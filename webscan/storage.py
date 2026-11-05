"""SQLite 持久化。连接短开短闭，WAL 模式，够用且不引第三方 ORM。"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from . import config
from .models import Finding, ScanResult

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
                "SELECT * FROM findings WHERE scan_id=?" " ORDER BY CASE severity"
                " WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2"
                " WHEN 'low' THEN 3 ELSE 4 END, id",
                (scan_id,),
            ).fetchall()
            data["findings"] = [dict(r) for r in frows]
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

    def add_pages(self, scan_id: str, pages: list[tuple[str, str, int, int, int]]) -> None:
        with self._conn() as con:
            con.executemany(
                "INSERT INTO pages (scan_id, url, method, status, length, elapsed_ms)"
                " VALUES (?,?,?,?,?,?)",
                [(scan_id, *p) for p in pages],
            )
