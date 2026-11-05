"""工作台本地 API 的回归测试。"""

import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from webscan import api
from webscan.models import Finding, Form, FormField, Page, ScanResult
from webscan.storage import Store


class TestWorkbench(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        saved = api.store
        self.addCleanup(setattr, api, "store", saved)
        api.store = Store(Path(self.directory.name) / "workbench.db")
        server = ThreadingHTTPServer(("127.0.0.1", 0), api.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.base = f"http://127.0.0.1:{server.server_port}"
        self.scan = ScanResult.new("http://example.test/")
        api.store.create_scan(self.scan.id, self.scan.target, {})
        page = Page(
            url=self.scan.target, status=200, content_type="text/html",
            body="<script>example()</script>", rendered_html="<html>rendered</html>",
            forms=[Form("/search", fields=[FormField("q", value="not stored")])],
        )
        api.store.add_pages(self.scan.id, [page], save_snapshots=True)
        self.scan.status = "done"
        self.scan.findings = [
            Finding("XSS-REFLECT", "XSS", "high", "注入", page.url, "description",
                    request_snippet="GET /?q=test", response_snippet="test"),
        ]
        api.store.update_scan(self.scan)

    def request(self, path, body=None, *, token=True, host=None):
        headers = {"X-WebScan-Token": api._TOKEN} if token else {}
        if host:
            headers["Host"] = host
        data = None if body is None else json.dumps(body).encode()
        with urlopen(Request(self.base + path, data=data, headers=headers), timeout=5) as response:
            return json.load(response)

    def test_snapshots_are_separate_from_page_list_and_protected(self):
        path = f"/api/scans/{self.scan.id}/pages"
        page, = self.request(path)["items"]
        self.assertNotIn("source", page)
        self.assertNotIn("value", page["forms"][0]["fields"][0])
        self.assertTrue(page["has_rendered"])
        snapshot = path + f"/{page['id']}?kind=rendered"
        self.assertEqual(self.request(snapshot)["text"], "<html>rendered</html>")
        with self.assertRaises(HTTPError) as error:
            self.request(snapshot, token=False)
        self.assertEqual(error.exception.code, 403)

    def test_review_persists_and_cannot_update_other_scan(self):
        path = f"/api/scans/{self.scan.id}"
        finding, = self.request(path)["findings"]
        self.assertEqual(finding["request_snippet"], "GET /?q=test")
        body = {"finding_id": finding["id"], "scan_id": "other", "status": "误报"}
        with self.assertRaises(HTTPError) as error:
            self.request("/api/reviews", body)
        self.assertEqual(error.exception.code, 404)
        body["scan_id"] = self.scan.id
        self.assertTrue(self.request("/api/reviews", body)["ok"])
        reviewed, = self.request(path)["findings"]
        self.assertEqual(reviewed["review"], "误报")
        self.assertEqual(reviewed["assessment"], "疑似")

    def test_denies_external_host_and_unauthorized_checkup(self):
        with self.assertRaises(HTTPError) as error:
            self.request("/", host="remote.example")
        self.assertEqual(error.exception.code, 403)
        with self.assertRaises(HTTPError) as error:
            self.request("/api/checkup", {"url": "example.test"})
        self.assertEqual(error.exception.code, 403)
