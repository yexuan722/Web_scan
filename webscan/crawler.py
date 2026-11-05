"""爬虫：同源 BFS、去重、深度/页数限制、破坏性路径排除。"""

from __future__ import annotations

import posixpath
import re
from html.parser import HTMLParser
from typing import Awaitable, Callable
from urllib.parse import parse_qsl, urljoin, urlencode, urlsplit, urlunsplit

from . import config
from .fetcher import Fetcher
from .models import Form, FormField, Page

# 不值得抓取的静态资源
SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tif",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".webm", ".flv",
    ".pdf", ".zip", ".rar", ".7z", ".gz", ".tar", ".exe", ".msi", ".dmg", ".apk",
    ".css", ".map",
}

_DANGEROUS = re.compile(config.DANGEROUS_PATH_PATTERN)


def normalize_url(url: str, base: str | None = None) -> str | None:
    """规范化 URL：小写主机、去默认端口、去 fragment、排序 query、合并多余斜杠。"""
    if base:
        url = urljoin(base, url)
    url = url.strip()
    if not url or url.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
        return None
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in config.ALLOWED_SCHEMES:
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    port = parts.port
    netloc = host if port in (None, 80, 443) else f"{host}:{port}"
    path = re.sub(r"/{2,}", "/", parts.path or "/")
    if not path.startswith("/"):
        path = "/" + path
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    query = ""
    if parts.query:
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        pairs.sort()
        query = urlencode(pairs)
    return urlunsplit((scheme, netloc, path, query, ""))


def same_site(a: str, b: str, allow_http_downgrade: bool = False) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    if pa.hostname != pb.hostname:
        return False
    if pa.port not in (None, 80, 443) or pb.port not in (None, 80, 443):
        return pa.port == pb.port
    if pa.scheme == pb.scheme:
        return True
    return pa.scheme == "http" and pb.scheme == "https"


def skipped_path(url: str) -> bool:
    path = urlsplit(url).path
    if _DANGEROUS.search(path):
        return True
    ext = posixpath.splitext(path)[1].lower()
    return ext in SKIP_EXT


class _Extractor(HTMLParser):
    def __init__(self, base: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base = base
        self.links: list[str] = []
        self.forms: list[Form] = []
        self._form: Form | None = None

    def _add(self, raw: str | None) -> None:
        if not raw:
            return
        abs_url = urljoin(self.base, raw.strip())
        if abs_url.startswith(("http://", "https://")):
            self.links.append(abs_url)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" or tag == "area":
            self._add(a.get("href"))
        elif tag in ("script", "iframe", "frame", "embed"):
            self._add(a.get("src"))
        elif tag == "link" and "stylesheet" not in a.get("rel", ""):
            self._add(a.get("href"))
        elif tag == "form":
            action = urljoin(self.base, a.get("action") or "")
            self._form = Form(
                action=action,
                method=(a.get("method") or "get").upper(),
            )
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None:
            name = a.get("name", "")
            if name:
                self._form.fields.append(
                    FormField(name=name, type=a.get("type", "text"), value=a.get("value", ""))
                )
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url=(.+)", a.get("content", ""), re.I)
            if m:
                self._add(m.group(1).strip(" '\""))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


def extract(page: Page) -> tuple[list[str], list[Form]]:
    """从 HTML 页里抽链接与表单。非 HTML 直接返回空。"""
    ctype = page.content_type
    if ctype and "html" not in ctype and "xml" not in ctype:
        return [], []
    if "<html" not in page.body[:2000].lower() and "<form" not in page.body[:2000].lower():
        return [], []
    parser = _Extractor(page.url)
    try:
        parser.feed(page.body)
    except Exception:
        return [], []
    return parser.links, parser.forms


async def crawl(
    start_url: str,
    fetcher: Fetcher,
    *,
    max_pages: int = config.DEFAULT_MAX_PAGES,
    max_depth: int = config.DEFAULT_MAX_DEPTH,
    on_page: Callable[[Page, int, int], Awaitable[None]] | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> tuple[list[Page], list[str]]:
    """广度优先抓取。返回 (页面列表, 被跳过的 URL 列表)。"""
    start = normalize_url(start_url) or start_url
    seen: set[str] = {start}
    skipped: list[str] = []
    pages: list[Page] = []
    frontier: list[tuple[str, int]] = [(start, 0)]
    batch = 12

    while frontier and len(pages) < max_pages:
        if should_stop and should_stop():
            break
        level, frontier = frontier, []
        while level and len(pages) < max_pages:
            chunk, level = level[:batch], level[batch:]
            results = await gather_pages(chunk, fetcher)
            for (url, depth), page in zip(chunk, results):
                pages.append(page)
                if on_page:
                    await on_page(page, len(pages), max_pages)
                if depth >= max_depth or not page.ok:
                    continue
                links, forms = extract(page)
                page.links = links
                page.forms = forms
                for raw in links:
                    nxt = normalize_url(raw, page.url)
                    if not nxt or nxt in seen:
                        continue
                    if not same_site(start, nxt):
                        continue
                    if skipped_path(nxt):
                        skipped.append(nxt)
                        continue
                    seen.add(nxt)
                    frontier.append((nxt, depth + 1))
    return pages, skipped


async def gather_pages(chunk: list[tuple[str, int]], fetcher: Fetcher) -> list[Page]:
    import asyncio

    return await asyncio.gather(*(fetcher.fetch(u) for u, _ in chunk))
