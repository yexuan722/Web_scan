"""单元测试：URL 规范化、评分模型、被动规则。运行：python -m unittest discover -s tests -v"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from webscan import config  # noqa: E402
from webscan.crawler import crawl, normalize_url, skipped_path  # noqa: E402
from webscan.fetcher import Fetcher  # noqa: E402
from webscan.models import Finding, Form, FormField, Page
from webscan.rules.active import _redirect, _sqli, _xss, collect_targets  # noqa: E402
from webscan.rules.passive import analyze_host, analyze_page  # noqa: E402
from webscan.scoring import compute_score  # noqa: E402


class TestNormalize(unittest.TestCase):
    def test_lowercase_and_default_port(self) -> None:
        self.assertEqual(
            normalize_url("HTTP://Example.COM:80/a//b#frag"), "http://example.com/a/b"
        )

    def test_query_sorted(self) -> None:
        self.assertEqual(
            normalize_url("https://a.com/x?b=2&a=1"), "https://a.com/x?a=1&b=2"
        )

    def test_reject_non_http(self) -> None:
        self.assertIsNone(normalize_url("javascript:alert(1)"))
        self.assertIsNone(normalize_url("ftp://a.com/x"))

    def test_relative_join(self) -> None:
        self.assertEqual(normalize_url("/x", "https://a.com/dir/p"), "https://a.com/x")

    def test_skip(self) -> None:
        self.assertTrue(skipped_path("https://a.com/logout.php"))
        self.assertTrue(skipped_path("https://a.com/img/a.png"))
        self.assertFalse(skipped_path("https://a.com/item?id=1"))


def _page(**kw) -> Page:
    base = dict(
        url="http://127.0.0.1:8899/",
        status=200,
        headers={"content-type": "text/html; charset=utf-8", "server": "ACME-Server/1.2.3"},
        body="<html><body>ok</body></html>",
        content_type="text/html; charset=utf-8",
    )
    base.update(kw)
    return Page(**base)


class TestScoring(unittest.TestCase):
    def test_clean_site_is_100(self) -> None:
        r = compute_score([])
        self.assertEqual(r["score"], 100)
        self.assertEqual(r["grade"], "good")

    def test_one_critical(self) -> None:
        f = Finding(rule_id="X", title="t", severity="critical", category="c", url="u",
                    detail="d", confidence=1.0)
        r = compute_score([f])
        self.assertEqual(r["score"], 65)  # 100 * (1 - 0.35)

    def test_more_findings_lower_score(self) -> None:
        mk = lambda s: Finding(rule_id="X", title="t", severity=s, category="c",
                               url="u", detail="d", confidence=1.0)
        a = compute_score([mk("high")])["score"]
        b = compute_score([mk("high"), mk("high")])["score"]
        self.assertLess(b, a)

    def test_info_does_not_deduct(self) -> None:
        f = Finding(rule_id="X", title="t", severity="info", category="c", url="u",
                    detail="d", confidence=1.0)
        self.assertEqual(compute_score([f])["score"], 100)


class TestPassiveRules(unittest.TestCase):
    def test_missing_headers_detected_once(self) -> None:
        pages = [_page(), _page(url="http://127.0.0.1:8899/a")]
        found = analyze_host("127.0.0.1:8899", pages)
        ids = [f.rule_id for f in found]
        self.assertEqual(ids.count("SEC-HEADERS"), 1)

    def test_cookie_flags(self) -> None:
        p = _page(set_cookies=["session=abc; Path=/"])
        ids = [f.rule_id for f in analyze_page(p, "h")]
        self.assertIn("COOKIE-FLAGS", ids)

    def test_error_disclosure(self) -> None:
        p = _page(body="<html>Traceback (most recent call last): boom</html>")
        found = [f for f in analyze_page(p, "h") if f.rule_id == "ERROR-DISCLOSURE"]
        self.assertTrue(found)

    def test_banner(self) -> None:
        found = [f for f in analyze_host("127.0.0.1:8899", [_page()]) if f.rule_id == "BANNER"]
        self.assertTrue(found)
        self.assertEqual(len(found), 1)  # 按主机聚合，多条头只报一次


class TestEvidenceInvariant(unittest.TestCase):
    def test_every_active_finding_has_evidence(self) -> None:
        """主动 PoC 的安全底线：没有证据就不产出（这里校验数据结构约束）。"""
        f = Finding(
            rule_id="XSS-REFLECT", title="t", severity="high", category="注入漏洞",
            url="http://a/?q=1", detail="d", verified=True, evidence="payload: x",
        )
        self.assertTrue(f.evidence)
        self.assertTrue(f.verified)


class TestScanBoundaries(unittest.IsolatedAsyncioTestCase):
    async def test_checks_each_redirect_before_sending(self) -> None:
        requests = []

        def respond(request):
            requests.append(str(request.url))
            destination = {
                "http://example.test/": "https://example.test/next",
                "https://example.test/next": "https://other.test/",
            }[str(request.url)]
            return httpx.Response(302, headers={"Location": destination})

        async with Fetcher("http://example.test/", rps=0) as fetcher:
            await fetcher._client.aclose()
            fetcher._client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
            self.assertFalse((await fetcher.fetch("http://example.test/")).ok)
            self.assertFalse((await fetcher.fetch("https://example.test:80/")).ok)
            self.assertFalse((await fetcher.fetch("https://example.test/%64elete")).ok)
            self.assertEqual(fetcher.requests, 2)
        self.assertEqual(requests, ["http://example.test/", "https://example.test/next"])

    async def test_body_limit_stops_reading_stream(self) -> None:
        class Body(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield b"x" * config.MAX_BODY_BYTES
                yield b"x"
                self.fail_if_read_past_limit()

            def fail_if_read_past_limit(self):
                raise AssertionError("stream was read past the limit")

        def respond(request):
            return httpx.Response(200, stream=Body())

        async with Fetcher("https://example.test/", rps=0) as fetcher:
            await fetcher._client.aclose()
            fetcher._client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
            page = await fetcher.fetch("https://example.test/")
        self.assertTrue(page.ok)
        self.assertTrue(page.truncated)
        self.assertEqual(page.length, config.MAX_BODY_BYTES)

    async def test_page_limit_and_forms_at_max_depth(self) -> None:
        class FakeFetcher:
            async def fetch(self, url):
                if url.endswith("/"):
                    links = "".join(f'<a href="/{i}">link</a>' for i in range(12))
                    return _page(url=url, body=f"<html>{links}</html>")
                return _page(url=url, body='<form action="/search"><input name="q"></form>')

        pages, _ = await crawl("https://example.test/", FakeFetcher(), max_pages=2, max_depth=1)
        self.assertEqual(len(pages), 2)
        self.assertEqual(pages[1].forms[0].fields[0].name, "q")

    def test_forms_outside_scope_are_not_queued(self) -> None:
        actions = (
            "https://other.test/search",
            "https://example.test:8443/search",
            "http://example.test/search",
            "https://example.test/delete",
            "https://example.test/search",
        )
        page = _page(url="https://example.test/", forms=[
            Form(action=action, fields=[FormField("q")]) for action in actions
        ])
        self.assertEqual([target["url"] for target in collect_targets([page])], [actions[-1]])


class TestActiveEvidence(unittest.IsolatedAsyncioTestCase):
    target = {"url": "https://example.test/?q=book", "param": "q", "value": "book"}

    async def test_only_html_reflection_is_reported_as_suspected(self) -> None:
        class Reflect:
            def __init__(self, content_type):
                self.content_type = content_type
                self.values = []

            async def fetch(self, url, *, follow):
                value = parse_qs(urlsplit(url).query)["q"][0]
                self.values.append(value)
                return _page(url=url, body=value, content_type=self.content_type)

        self.assertEqual(await _xss(self.target, Reflect("text/plain"), ""), [])
        html = Reflect("text/html; charset=utf-8")
        finding, = await _xss(self.target, html, "")
        self.assertFalse(finding.verified)
        self.assertEqual(len(set(html.values)), 2)

    async def test_sqli_requires_distinct_payloads_with_the_same_error(self) -> None:
        class Database:
            def __init__(self, accepted):
                self.accepted = accepted

            async def fetch(self, url, *, follow):
                suffix = parse_qs(urlsplit(url).query)["q"][0][len("book"):]
                if suffix in self.accepted:
                    return _page(url=url, body="SQLSTATE[42000]", status=500)
                return _page(url=url)

        second, third = config.SQLI_ERROR_PAYLOADS[1:]
        self.assertEqual(await _sqli(self.target, Database({second}), ""), [])
        finding, = await _sqli(self.target, Database({second, third}), "")
        self.assertTrue(finding.verified)
        self.assertEqual(await _sqli(self.target, Database({second, third}), "SQLSTATE[42000]"), [])

    async def test_redirect_checks_destination_host_not_path_text(self) -> None:
        class LocalRedirect:
            async def fetch(self, url, *, follow):
                value = parse_qs(urlsplit(url).query)["q"][0]
                return _page(url=url, status=302, headers={"location": "/next?url=" + value})

        self.assertEqual(await _redirect(self.target, LocalRedirect()), [])


if __name__ == "__main__":
    unittest.main()
