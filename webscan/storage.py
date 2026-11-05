"""SQLite 持久化。连接短开短闭，WAL 模式，够用且不引第三方 ORM。"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from . import config
from .models import Page, ScanResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    status      TEXT NOT NULL,
    started_at  REAL NOT NULL,
    finished_at REAL,
    score       INTEGER DEFAULT 0,
    grade       TEXT DEFAULT '',
    grade_label TEXT DEFAULT '',
    options     TEXT DEFAULT '{}',
    stats       TEXT DEFAULT '{}',
    error       TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    category    TEXT NOT NULL,
    url         TEXT NOT NULL,
    param       TEXT DEFAULT '',
    detail      TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    confidence  REAL DEFAULT 0,
    verified    INTEGER DEFAULT 0,
    evidence    TEXT DEFAULT '',
    req         TEXT DEFAULT '',
    resp        TEXT DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
CREATE TABLE IF NOT EXISTS pages (
    scan_id    TEXT NOT NULL,
    url        TEXT NOT NULL,
    method     TEXT DEFAULT 'GET',
    status     INTEGER DEFAULT 0,
    length     INTEGER DEFAULT 0,
    elapsed_ms INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_pages_scan ON pages(scan_id);
CREATE TABLE IF NOT EXISTS page_details (
    page_id INTEGER PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    details TEXT NOT NULL,
    source TEXT,
    rendered TEXT
);
CREATE TABLE IF NOT EXISTS reviews (
    finding_id INTEGER PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    status TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path or config.DB_PATH)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as con:
            con.executescript(SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(self.path, timeout=30)
        con.row_factory = sqlite3.Row
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA foreign_keys=ON")
            yield con
            con.commit()
        finally:
            con.close()

    # ------------------------------------------------------------------
    def create_scan(self, scan_id: str, target: str, options: dict[str, Any]) -> None:
        with self._conn() as con:
            con.execute(
                "INSERT INTO scans (id, target, status, started_at, options) VALUES (?,?,?,?,?)",
                (scan_id, target, "pending", time.time(), json.dumps(options, ensure_ascii=False)),
            )

    def update_scan(self, scan: ScanResult, options: dict[str, Any] | None = None) -> None:
        with self._conn() as con:
            con.execute(
                "UPDATE scans SET status=?, finished_at=?, score=?, grade=?, grade_label=?,"
                " stats=?, error=? WHERE id=?",
                (
                    scan.status,
                    scan.finished_at,
                    scan.score,
                    scan.grade,
                    scan.grade_label,
                    json.dumps(scan.stats, ensure_ascii=False),
                    scan.error,
                    scan.id,
                ),
            )
            con.execute("DELETE FROM findings WHERE scan_id=?", (scan.id,))
            con.executemany(
                "INSERT INTO findings (scan_id, rule_id, title, severity, category, url, param,"
                " detail, remediation, confidence, verified, evidence, req, resp)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        scan.id, f.rule_id, f.title, f.severity, f.category, f.url, f.param,
                        f.detail, f.remediation, f.confidence, int(f.verified), f.evidence,
                        f.request_snippet, f.response_snippet,
                    )
                    for f in scan.findings
                ],
            )


    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self._conn() as con:
            row = con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            if not row:
                return None
            data = dict(row)
            data["options"] = json.loads(data.get("options") or "{}")
            data["stats"] = json.loads(data.get("stats") or "{}")
            frows = con.execute(
                "SELECT f.*, r.status AS review FROM findings AS f"
                " LEFT JOIN reviews AS r ON r.finding_id=f.id WHERE f.scan_id=?"
                " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
                " WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.id",
                (scan_id,),
            ).fetchall()
            data["findings"] = []
            for row in frows:
                finding = dict(row)
                finding["request_snippet"] = finding.pop("req")
                finding["response_snippet"] = finding.pop("resp")
                if finding["rule_id"] in {"SEC-HEADERS", "CSP-WEAK", "HSTS-MISSING",
                                         "COOKIE-FLAGS", "CORS-WILDCARD", "BANNER"}:
                    finding["assessment"] = "配置建议"
                else:
                    finding["assessment"] = "已验证" if finding["verified"] else "疑似"
                data["findings"].append(finding)
            return data

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._conn() as con:
            rows = con.execute(
                "SELECT id, target, status, started_at, finished_at, score, grade,"
                " grade_label, stats FROM scans ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["stats"] = json.loads(d.get("stats") or "{}")
                out.append(d)
            return out

    def delete_scan(self, scan_id: str) -> None:
        with self._conn() as con:
            con.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
            con.execute("DELETE FROM pages WHERE scan_id=?", (scan_id,))
            con.execute("DELETE FROM scans WHERE id=?", (scan_id,))

    def add_pages(self, scan_id: str, pages: list[Page], *, save_snapshots: bool = False) -> None:
        budget = 16 * 1024 * 1024
        with self._conn() as con:
            for page in pages:
                cursor = con.execute(
                    "INSERT INTO pages (scan_id, url, method, status, length, elapsed_ms)"
                    " VALUES (?,?,?,?,?,?)",
                    (scan_id, page.url, page.method, page.status, page.length, page.elapsed_ms),
                )
                details = {
                    "requested_url": page.requested_url, "error": page.error,
                    "truncated": page.truncated, "rendered": page.rendered_html is not None,
                    "forms": [
                        {"action": form.action, "method": form.method,
                         "fields": [{"name": field.name, "type": field.type} for field in form.fields]}
                        for form in page.forms
                    ],
                }
                source = rendered = None
                if save_snapshots and page.ok and page.content_type.split(";", 1)[0].strip().lower() in (
                    "text/html", "application/xhtml+xml"
                ):
                    source, rendered = page.body, page.rendered_html
                    size = len(source.encode("utf-8")) + len((rendered or "").encode("utf-8"))
                    if size <= budget:
                        budget -= size
                    else:
                        source = rendered = None
                con.execute(
                    "INSERT INTO page_details (page_id, scan_id, details, source, rendered)"
                    " VALUES (?,?,?,?,?)",
                    (cursor.lastrowid, scan_id, json.dumps(details, ensure_ascii=False), source, rendered),
                )

    def list_pages(self, scan_id: str) -> list[dict[str, Any]]:
        with self._conn() as con:
            rows = con.execute(
                "SELECT p.rowid AS id, p.*, d.details, d.source IS NOT NULL AS has_source,"
                " d.rendered IS NOT NULL AS has_rendered FROM pages AS p LEFT JOIN page_details AS d"
                " ON d.page_id=p.rowid AND d.scan_id=p.scan_id WHERE p.scan_id=? ORDER BY p.rowid",
                (scan_id,),
            )
            pages = []
            for row in rows:
                page = dict(row)
                page.update(json.loads(page.pop("details") or "{}"))
                pages.append(page)
            return pages

    def snapshot(self, scan_id: str, page_id: int, rendered: bool) -> str | None:
        column = "rendered" if rendered else "source"
        with self._conn() as con:
            row = con.execute(
                f"SELECT {column} FROM page_details WHERE scan_id=? AND page_id=?", (scan_id, page_id)
            ).fetchone()
            return row[0] if row else None

    def review_finding(self, scan_id: str, finding_id: int, status: str) -> bool:
        with self._conn() as con:
            cursor = con.execute(
                "INSERT INTO reviews (finding_id, status) SELECT id, ? FROM findings"
                " WHERE id=? AND scan_id=? ON CONFLICT(finding_id) DO UPDATE SET status=excluded.status",
                (status, finding_id, scan_id),
            )
            return cursor.rowcount == 1
