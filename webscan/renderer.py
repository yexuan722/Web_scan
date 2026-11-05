"""在隔离浏览器中提取 JavaScript 运行后出现的入口。"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from contextlib import AsyncExitStack
from pathlib import Path

from . import config
from .crawler import dangerous_path, same_site
from .models import Page

log = logging.getLogger(__name__)
MAX_RENDER_PAGES = 25
MAX_ASSET_REQUESTS = 24


class Renderer:
    def __init__(self) -> None:
        self._stack = AsyncExitStack()
        self._browser = None
        self.attempted = 0
        self.rendered = 0

    async def start(self) -> None:
        from playwright.async_api import async_playwright

        if getattr(sys, "frozen", False):
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(Path(sys._MEIPASS) / "pw-browsers")
        playwright = await self._stack.enter_async_context(async_playwright())
        self._browser = await playwright.chromium.launch(
            chromium_sandbox=True,
            args=[
                "--disable-background-networking",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                "--proxy-server=http://127.0.0.1:1",
                "--proxy-bypass-list=<-loopback>",
            ],
            timeout=15000,
        )
        self._stack.push_async_callback(self._browser.close)

    async def close(self) -> None:
        await self._stack.aclose()

    async def render(self, source: Page, fetcher) -> str | None:
        if self.attempted >= MAX_RENDER_PAGES or source.truncated:
            return None
        self.attempted += 1
        context = await self._browser.new_context(service_workers="block", accept_downloads=False)
        try:
            page = await context.new_page()
            document_served = False
            asset_requests = 0

            async def route_request(route):
                nonlocal document_served, asset_requests
                request = route.request
                if (request.method != "GET" or not same_site(source.url, request.url)
                        or dangerous_path(request.url)):
                    await route.abort()
                    return
                if request.is_navigation_request():
                    if document_served or request.url != source.url.split("#", 1)[0]:
                        await route.abort()
                        return
                    document_served = True
                    headers = {
                        key: value for key, value in source.headers.items()
                        if key in ("content-type", "content-security-policy", "x-content-type-options")
                    }
                    headers["content-type"] = source.content_type.split(";", 1)[0] + "; charset=utf-8"
                    await route.fulfill(status=source.status, headers=headers, body=source.body)
                    return
                if request.resource_type not in ("script", "fetch", "xhr") or asset_requests >= MAX_ASSET_REQUESTS:
                    await route.abort()
                    return
                asset_requests += 1
                response = await fetcher.fetch(request.url, follow=False, keep_bytes=True)
                if not response.ok or not 200 <= response.status < 300 or response.truncated:
                    await route.abort()
                    return
                headers = {
                    key: value for key, value in response.headers.items()
                    if key in ("content-type", "x-content-type-options")
                }
                await route.fulfill(status=response.status, headers=headers, body=response.raw_body)

            async def block_websocket(socket):
                await socket.close()

            await context.route("**/*", route_request)
            await context.route_web_socket("**/*", block_websocket)
            async with asyncio.timeout(10):
                await page.goto(source.url, wait_until="domcontentloaded", timeout=6000)
                await asyncio.sleep(0.8)
                markup = await page.evaluate(
                    "limit => document.documentElement.outerHTML.slice(0, limit)", config.MAX_BODY_BYTES
                )
            self.rendered += 1
            return markup
        except Exception:
            log.info("动态渲染失败，保留原始页面结果", exc_info=True)
            return None
        finally:
            await context.close()
