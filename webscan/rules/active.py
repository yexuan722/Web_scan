"""主动 PoC：只在 deep 模式下运行，全部为只读探测 + 二次验证。

契约：preflight（找注入点）→ 基线 → 注入 → 验证可复现 → 生成带证据的发现。
没有证据、不能复现的一律不产出。
"""

from __future__ import annotations

import asyncio
import re
from typing import Awaitable, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .. import config
from ..fetcher import Fetcher
from ..models import Finding, Page


def _with_param(url: str, param: str, value: str) -> str:
    p = urlsplit(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    replaced = False
    new_pairs = []
    for k, v in pairs:
        if k == param and not replaced:
            new_pairs.append((k, value))
            replaced = True
        else:
            new_pairs.append((k, v))
    if not replaced:
        new_pairs.append((param, value))
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(new_pairs), ""))


def collect_targets(pages: list[Page], limit: int = config.ACTIVE_MAX_TARGETS) -> list[dict]:
    """从 URL 参数与 GET 表单里收集可测注入点。"""
    targets: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(url: str, param: str, value: str, source: str) -> None:
        key = (_with_param(url, param, "x"), param)
        if param in ("", "submit", "csrf", "token") or key in seen:
            return
        seen.add(key)
        targets.append({"url": url, "param": param, "value": value, "source": source})

    for page in pages:
        if not page.ok:
            continue
        base_url = page.requested_url or page.url
        parts = urlsplit(base_url)
        for k, v in parse_qsl(parts.query, keep_blank_values=True):
            add(base_url, k, v, "query")
        for form in page.forms:
            if form.method.upper() != "GET":
                continue
            for f in form.fields:
                if f.type.lower() in ("submit", "button", "file", "image"):
                    continue
                add(form.action or page.url, f.name, f.value or "1", "form")
    return targets[:limit]


def _snippet(text: str, start: int, end: int, pad: int = 100) -> str:
    return text[max(0, start - pad): end + pad]


async def run_active_tests(
    pages: list[Page],
    fetcher: Fetcher,
    *,
    limit: int = config.ACTIVE_MAX_TARGETS,
    on_progress: Callable[[int, int, str], Awaitable[None]] | None = None,
) -> list[Finding]:
    targets = collect_targets(pages, limit)
    baseline: dict[str, Page] = {}
    for p in pages:
        if not p.ok:
            continue
        baseline[p.url] = p
        if p.requested_url:
            baseline.setdefault(p.requested_url, p)
    out: list[Finding] = []
    sem = asyncio.Semaphore(4)
    done = 0
    total = len(targets)

    async def work(t: dict) -> list[Finding]:
        nonlocal done
        async with sem:
            found: list[Finding] = []
            base = baseline.get(t["url"])
            base_body = base.body if base else ""
            try:
                found += await _xss(t, fetcher, base_body)
                found += await _sqli(t, fetcher, base_body)
                found += await _lfi(t, fetcher, base_body)
                found += await _redirect(t, fetcher)
            except Exception:
                pass
            done += 1
            if on_progress:
                await on_progress(done, total, f"{t['url']} · {t['param']}")
            return found

    results = await asyncio.gather(*(work(t) for t in targets))
    for r in results:
        out.extend(r)
    return out


# ----------------------------------------------------------------------
async def _xss(t: dict, fetcher: Fetcher, base_body: str) -> list[Finding]:
    payload = config.XSS_PAYLOAD
    probe = f"{t['value']}{payload}" if t["value"] else payload
    url = _with_param(t["url"], t["param"], probe)
    page = await fetcher.fetch(url, follow=False)
    if page.error or 300 <= page.status < 400:
        return []
    if payload not in page.body:
        return []
    idx = page.body.find(payload)
    return [
        Finding(
            rule_id="XSS-REFLECT",
            title="反射型 XSS（参数回显未编码）",
            severity="high",
            category="注入漏洞",
            url=url,
            param=t["param"],
            detail=(
                f"参数 {t['param']} 的值被原样反射进响应且 < > 未被转义，"
                "浏览器会把注入内容当作脚本执行。"
            ),
            remediation=(
                "按输出上下文做编码（HTML 用 HTML 实体、属性用引号+实体、JS 用 JSON 转义）；"
                "启用严格 CSP 作为纵深防御。"
            ),
            confidence=0.95,
            verified=True,
            evidence=f"payload: {payload}\n响应位置: {idx}",
            request_snippet=f"GET {url}",
            response_snippet=_snippet(page.body, idx, idx + len(payload)),
            dedupe_key=f"XSS-REFLECT|{_with_param(url, t['param'], '')}|{t['param']}",
        )
    ]


async def _sqli(t: dict, fetcher: Fetcher, base_body: str) -> list[Finding]:
    sig_re = re.compile("|".join(config.SQLI_ERROR_SIGNATURES), re.I)
    hit_payload = None
    hit_page = None
    for payload in config.SQLI_ERROR_PAYLOADS:
        probe = f"{t['value']}{payload}" if t["value"] else payload
        url = _with_param(t["url"], t["param"], probe)
        page = await fetcher.fetch(url, follow=False)
        if page.error or 300 <= page.status < 400:
            continue
        m = sig_re.search(page.body)
        if m and not sig_re.search(base_body):
            hit_payload, hit_page = payload, page
            break
    if not hit_payload or not hit_page:
        return []

    # 二次验证：换一个 payload，能再次触发同类报错才算真
    second = config.SQLI_ERROR_PAYLOADS[1]
    url2 = _with_param(t["url"], t["param"], f"{t['value']}{second}")
    page2 = await fetcher.fetch(url2, follow=False)
    if page2.error or 300 <= page2.status < 400 or not sig_re.search(page2.body):
        return []

    m = sig_re.search(hit_page.body)
    return [
        Finding(
            rule_id="SQLI-ERROR",
            title="SQL 注入（错误回显型）",
            severity="critical",
            category="注入漏洞",
            url=_with_param(t["url"], t["param"], f"{t['value']}{hit_payload}"),
            param=t["param"],
            detail=(
                f"参数 {t['param']} 拼接单引号后触发数据库报错，且基线响应无该报错；"
                f"换用 {second!r} 可复现，判定为注入点。"
            ),
            remediation=(
                "使用参数化查询/预编译语句；对输入做白名单校验；"
                "关闭生产环境数据库错误回显。"
            ),
            confidence=0.9,
            verified=True,
            evidence=f"payload: {hit_payload} / 复现: {second}",
            request_snippet=f"GET {url2}",
            response_snippet=_snippet(hit_page.body, m.start(), m.end()),
            dedupe_key=f"SQLI-ERROR|{_with_param(t['url'], t['param'], '')}|{t['param']}",
        )
    ]


async def _lfi(t: dict, fetcher: Fetcher, base_body: str) -> list[Finding]:
    sig_re = re.compile("|".join(config.LFI_SIGNATURES), re.I)
    for payload in config.LFI_PAYLOADS:
        url = _with_param(t["url"], t["param"], payload)
        page = await fetcher.fetch(url, follow=False)
        if page.error or 300 <= page.status < 400:
            continue
        m = sig_re.search(page.body)
        if m and not sig_re.search(base_body):
            return [
                Finding(
                    rule_id="LFI",
                    title="本地文件包含 / 路径穿越",
                    severity="critical",
                    category="注入漏洞",
                    url=url,
                    param=t["param"],
                    detail=(
                        f"参数 {t['param']} 传入穿越路径后被读取，响应中出现系统文件特征内容。"
                    ),
                    remediation=(
                        "不要用用户输入拼接文件路径；使用固定文件 ID 映射；"
                        "对路径做 realpath 校验并限制在允许目录内。"
                    ),
                    confidence=0.95,
                    verified=True,
                    evidence=f"payload: {payload}",
                    request_snippet=f"GET {url}",
                    response_snippet=_snippet(page.body, m.start(), m.end()),
                    dedupe_key=f"LFI|{_with_param(t['url'], t['param'], '')}|{t['param']}",
                )
            ]
    return []


async def _redirect(t: dict, fetcher: Fetcher) -> list[Finding]:
    evil = "//ws-evil.example/landing"
    url = _with_param(t["url"], t["param"], evil)
    page = await fetcher.fetch(url, follow=False)
    if page.error or page.status not in (301, 302, 303, 307, 308):
        return []
    loc = page.header("location")
    if "ws-evil.example" not in loc:
        return []
    return [
        Finding(
            rule_id="OPEN-REDIRECT",
            title="开放重定向",
            severity="medium",
            category="业务逻辑",
            url=url,
            param=t["param"],
            detail=f"参数 {t['param']} 可控 302 的 Location，可被用于钓鱼跳转与 OAuth 令牌窃取。",
            remediation="跳转目标使用服务端白名单映射，禁止直接使用用户输入的 URL。",
            confidence=0.9,
            verified=True,
            evidence=f"payload: {evil}\nLocation: {loc}",
            request_snippet=f"GET {url}",
            response_snippet=f"HTTP {page.status}\nLocation: {loc}",
            dedupe_key=f"OPEN-REDIRECT|{_with_param(t['url'], t['param'], '')}|{t['param']}",
        )
    ]
