"""主动 PoC：只在 deep 模式下运行，全部为只读探测 + 二次验证。

契约：preflight（找注入点）→ 基线 → 注入 → 验证可复现 → 生成带证据的发现。
没有证据、不能复现的一律不产出。
"""

from __future__ import annotations

import asyncio
import re
import secrets
from typing import Awaitable, Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from .. import config
from ..crawler import dangerous_path, same_site
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
            action = form.action or page.url
            try:
                if form.method.upper() != "GET" or not same_site(page.url, action) or dangerous_path(action):
                    continue
            except ValueError:
                continue
            for f in form.fields:
                if f.type.lower() in ("submit", "button", "file", "image"):
                    continue
                add(action, f.name, f.value or "1", "form")
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
        if p.ok:
            baseline[p.url] = p
    out: list[Finding] = []
    sem = asyncio.Semaphore(4)
    done = 0
    total = len(targets)

    async def work(t: dict) -> list[Finding]:
        nonlocal done
        async with sem:
            found: list[Finding] = []
            try:
                baseline_url = _with_param(t["url"], t["param"], t["value"])
                base = baseline.get(baseline_url)
                if base is None:
                    base = await fetcher.fetch(baseline_url, follow=False)
                if base.ok and 200 <= base.status < 300:
                    found += await _xss(t, fetcher, base.body)
                    found += await _sqli(t, fetcher, base.body)
                    found += await _lfi(t, fetcher, base.body)
                if base.ok:
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
    for _ in range(2):
        payload = f"<script>alert('{secrets.token_hex(8)}')</script>"
        url = _with_param(t["url"], t["param"], t["value"] + payload)
        page = await fetcher.fetch(url, follow=False)
        media_type = page.content_type.partition(";")[0].strip().lower()
        if (not page.ok or not 200 <= page.status < 300
                or media_type not in ("text/html", "application/xhtml+xml")
                or payload in base_body or payload not in page.body):
            return []
    idx = page.body.find(payload)
    return [
        Finding(
            rule_id="XSS-REFLECT",
            title="疑似反射型 XSS（脚本标签原样回显）",
            severity="high",
            category="注入漏洞",
            url=url,
            param=t["param"],
            detail=(
                f"参数 {t['param']} 在两次测试中均将不同的脚本标签原样写入 HTML。"
                "需要结合页面上下文、安全策略和浏览器执行结果确认。"
            ),
            remediation=(
                "按输出上下文做编码（HTML 用 HTML 实体、属性用引号+实体、JS 用 JSON 转义）；"
                "启用严格 CSP 作为纵深防御。"
            ),
            confidence=0.65,
            verified=False,
            evidence=f"payload: {payload}\n响应位置: {idx}",
            request_snippet=f"GET {url}",
            response_snippet=_snippet(page.body, idx, idx + len(payload)),
            dedupe_key=f"XSS-REFLECT|{_with_param(url, t['param'], '')}|{t['param']}",
        )
    ]


async def _sqli(t: dict, fetcher: Fetcher, base_body: str) -> list[Finding]:
    signatures = [re.compile(pattern, re.I) for pattern in config.SQLI_ERROR_SIGNATURES]
    signatures = [sig for sig in signatures if not sig.search(base_body)]
    hits = {}
    for payload in dict.fromkeys(config.SQLI_ERROR_PAYLOADS):
        url = _with_param(t["url"], t["param"], t["value"] + payload)
        page = await fetcher.fetch(url, follow=False)
        if not page.ok or 300 <= page.status < 400:
            continue
        for sig in signatures:
            match = sig.search(page.body)
            if match is None:
                continue
            if sig in hits:
                return _sqli_finding(t, hits[sig], payload, page, match)
            hits[sig] = payload
    return []


def _sqli_finding(t: dict, first: str, second: str, page: Page, match: re.Match) -> list[Finding]:
    url = _with_param(t["url"], t["param"], t["value"] + second)
    return [
        Finding(
            rule_id="SQLI-ERROR",
            title="SQL 注入（错误回显型）",
            severity="critical",
            category="注入漏洞",
            url=url,
            param=t["param"],
            detail=(
                f"参数 {t['param']} 使用 {first!r} 后触发数据库报错，且基线响应无该报错；"
                f"换用 {second!r} 可复现，判定为注入点。"
            ),
            remediation=(
                "使用参数化查询/预编译语句；对输入做白名单校验；"
                "关闭生产环境数据库错误回显。"
            ),
            confidence=0.9,
            verified=True,
            evidence=f"payload: {first} / 复现: {second}",
            request_snippet=f"GET {url}",
            response_snippet=_snippet(page.body, match.start(), match.end()),
            dedupe_key=f"SQLI-ERROR|{_with_param(t['url'], t['param'], '')}|{t['param']}",
        )
    ]


async def _lfi(t: dict, fetcher: Fetcher, base_body: str) -> list[Finding]:
    sig_re = re.compile("|".join(config.LFI_SIGNATURES), re.I)
    first = None
    for payload in dict.fromkeys(config.LFI_PAYLOADS):
        url = _with_param(t["url"], t["param"], payload)
        page = await fetcher.fetch(url, follow=False)
        if page.error or 300 <= page.status < 400:
            continue
        m = sig_re.search(page.body)
        if m and not sig_re.search(base_body):
            if first is None:
                first = payload
                continue
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
                    evidence=f"payload: {first} / 复现: {payload}",
                    request_snippet=f"GET {url}",
                    response_snippet=_snippet(page.body, m.start(), m.end()),
                    dedupe_key=f"LFI|{_with_param(t['url'], t['param'], '')}|{t['param']}",
                )
            ]
    return []


async def _redirect(t: dict, fetcher: Fetcher) -> list[Finding]:
    for host in ("ws-evil.example", "ws-confirm.example"):
        evil = f"//{host}/landing"
        url = _with_param(t["url"], t["param"], evil)
        page = await fetcher.fetch(url, follow=False)
        if not page.ok or page.status not in (301, 302, 303, 307, 308):
            return []
        loc = page.header("location")
        try:
            destination = urlsplit(urljoin(url, loc))
        except ValueError:
            return []
        if destination.scheme not in ("http", "https") or destination.hostname != host:
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
