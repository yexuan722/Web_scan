"""只读探测：敏感文件、CORS 配置。全部是 GET，不改数据。"""

from __future__ import annotations

import asyncio

from .. import config
from ..fetcher import Fetcher
from ..models import Finding, Page


def _base(url: str) -> str:
    from urllib.parse import urlsplit

    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


async def probe_sensitive_paths(origin: str, fetcher: Fetcher) -> list[Finding]:
    """按指纹校验敏感文件是否真实存在，避免 404 页面误报。"""
    out: list[Finding] = []
    origin = origin.rstrip("/")
    sem = asyncio.Semaphore(6)

    async def one(entry: tuple[str, tuple[str, ...], tuple[str, ...], str, str]):
        path, all_of, any_of, desc, sev = entry
        async with sem:
            page = await fetcher.fetch(f"{origin}/{path}", follow=False)
        if page.error or page.status not in (200, 206):
            return None
        body = page.body
        if len(body) < 8:
            return None
        if all_of and not all(tok.lower() in body.lower() for tok in all_of):
            return None
        if any_of and not any(tok.lower() in body.lower() for tok in any_of):
            return None
        return Finding(
            rule_id="SENSITIVE-PATH",
            title=desc,
            severity=sev,
            category="信息泄露",
            url=f"{origin}/{path}",
            detail=f"该路径返回 HTTP {page.status}，且内容指纹匹配，判定为真实暴露。",
            remediation=(
                "删除或移出 Web 根目录；Web 服务器禁止访问隐藏文件与备份扩展名；"
                "发布流程中排除 .git/.env/*.bak/*.zip。"
            ),
            confidence=0.95,
            verified=True,
            evidence=f"HTTP {page.status}, {len(body)} bytes, ct={page.content_type or '-'}",
            response_snippet=body[:400],
            dedupe_key=f"SENSITIVE-PATH|{origin}/{path}",
        )

    results = await asyncio.gather(*(one(e) for e in config.SENSITIVE_PATHS))
    out.extend(r for r in results if r)
    return out


async def probe_cors(origin_url: str, fetcher: Fetcher) -> list[Finding]:
    """带伪造 Origin 发一次 GET，检查跨域策略是否过宽。"""
    out: list[Finding] = []
    evil = "https://ws-evil.example"
    page: Page = await fetcher.fetch(
        origin_url, follow=False, headers={"Origin": evil, "Accept": "*/*"}
    )
    if page.error:
        return out
    acao = page.header("access-control-allow-origin")
    acac = page.header("access-control-allow-credentials").lower() == "true"
    if not acao:
        return out

    if acao == evil:
        sev = "critical" if acac else "high"
        detail = (
            "服务端把请求的 Origin 原样回显到 Access-Control-Allow-Origin"
            + ("，且允许携带凭据（Allow-Credentials: true），任意站点可读取登录态数据。" if acac else "。")
        )
        out.append(
            Finding(
                rule_id="CORS-REFLECT",
                title="CORS 反射任意来源" + ("（含凭据）" if acac else ""),
                severity=sev,
                category="配置安全",
                url=origin_url,
                detail=detail,
                remediation=(
                    "改为严格白名单匹配：只允许固定域名，禁用 Origin 原样回显；"
                    "需要凭据时不要使用通配符。"
                ),
                confidence=1.0,
                verified=True,
                evidence=f"请求 Origin: {evil}\n响应 ACAO: {acao} / ACAC: {acac}",
                response_snippet=f"access-control-allow-origin: {acao}",
                dedupe_key=f"CORS-REFLECT|{origin_url}",
            )
        )
    elif acao == "*":
        out.append(
            Finding(
                rule_id="CORS-WILDCARD",
                title="CORS 允许任意来源（*）",
                severity="low" if not acac else "medium",
                category="配置安全",
                url=origin_url,
                detail="Access-Control-Allow-Origin 为通配符，若接口返回敏感数据则风险显著上升。",
                remediation="按业务需要收敛为固定来源白名单。",
                confidence=0.9,
                verified=True,
                evidence=f"响应 ACAO: {acao} / ACAC: {acac}",
                dedupe_key=f"CORS-WILDCARD|{origin_url}",
            )
        )
    return out
