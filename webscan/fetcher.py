"""HTTP 抓取层：并发控制、每主机限速、响应截断、错误兜底。"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from . import config
from .models import Page


class RateLimiter:
    """每主机令牌桶，保证扫描礼貌、不把自己打成 DoS。"""

    def __init__(self, rps: float) -> None:
        self.interval = 1.0 / rps if rps > 0 else 0.0
        self._next: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, host: str) -> None:
        if self.interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            allowed = self._next.get(host, 0.0)
            wait = max(0.0, allowed - now)
            self._next[host] = max(now, allowed) + self.interval
        if wait > 0:
            await asyncio.sleep(wait)


def _decode(content: bytes, content_type: str) -> str:
    charset = "utf-8"
    for part in content_type.split(";")[1:]:
        if "charset=" in part.lower():
            charset = part.split("=", 1)[1].strip().strip('"\'')
            break
    try:
        return content.decode(charset, errors="replace")
    except LookupError:
        return content.decode("utf-8", errors="replace")


class Fetcher:
    def __init__(
        self,
        concurrency: int = config.DEFAULT_CONCURRENCY,
        rps: float = config.DEFAULT_RPS,
        timeout: float = config.DEFAULT_TIMEOUT,
        user_agent: str = config.USER_AGENT,
    ) -> None:
        self._sem = asyncio.Semaphore(concurrency)
        self._limiter = RateLimiter(rps)
        self.requests = 0
        self._client = httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(timeout, connect=min(timeout, 6.0)),
            follow_redirects=True,
            headers={"User-Agent": user_agent, "Accept": "*/*"},
            limits=httpx.Limits(max_connections=concurrency + 4, max_keepalive_connections=concurrency),
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "Fetcher":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def fetch(
        self,
        url: str,
        method: str = "GET",
        *,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        follow: bool = True,
    ) -> Page:
        host = httpx.URL(url).host or ""
        page = Page(url=url, method=method, requested_url=url)
        async with self._sem:
            await self._limiter.acquire(host)
            self.requests += 1
            started = time.monotonic()
            try:
                resp = await self._client.request(
                    method,
                    url,
                    params=params,
                    data=data,
                    headers=headers,
                    follow_redirects=follow,
                )
                body = resp.content[: config.MAX_BODY_BYTES]
                page.status = resp.status_code
                page.headers = {k.lower(): v for k, v in resp.headers.items()}
                page.content_type = page.headers.get("content-type", "")
                page.body = _decode(body, page.content_type)
                page.length = len(resp.content)
                page.url = str(resp.url)
                page.set_cookies = resp.headers.get_list("set-cookie") if hasattr(
                    resp.headers, "get_list"
                ) else []
            except Exception as exc:  # 网络错误不能中断整次扫描
                page.error = f"{type(exc).__name__}: {exc}"
            page.elapsed_ms = int((time.monotonic() - started) * 1000)
        return page
