"""单元测试：URL 规范化、评分模型、被动规则。运行：python -m unittest discover -s tests -v"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from webscan.crawler import normalize_url, skipped_path  # noqa: E402
from webscan.models import Finding, Page  # noqa: E402
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


if __name__ == "__main__":
    unittest.main()
