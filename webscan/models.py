"""数据模型：页面、表单、发现项、扫描结果。"""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEV_LABEL = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
}


@dataclass
class FormField:
    name: str
    type: str = "text"
    value: str = ""


@dataclass
class Form:
    action: str
    method: str = "GET"
    fields: list[FormField] = field(default_factory=list)


@dataclass
class Page:
    """一次 HTTP 响应（已截断）。"""

    url: str
    method: str = "GET"
    status: int = 0
    requested_url: str = ""      # 跳转前请求的原始地址
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_type: str = ""
    elapsed_ms: int = 0
    length: int = 0             # 保留的正文大小（字节）
    truncated: bool = False
    error: str | None = None
    forms: list[Form] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    set_cookies: list[str] = field(default_factory=list)
    raw_body: bytes = b""
    rendered_html: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status > 0

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


@dataclass
class Finding:
    """一条漏洞发现。evidence 为原始报文片段，assertion 为判定依据。"""

    rule_id: str
    title: str
    severity: str
    category: str
    url: str
    detail: str
    remediation: str = ""
    param: str = ""
    confidence: float = 0.9
    verified: bool = False
    evidence: str = ""
    request_snippet: str = ""
    response_snippet: str = ""
    dedupe_key: str = ""

    def key(self) -> str:
        return self.dedupe_key or f"{self.rule_id}|{self.url}|{self.param}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    id: str
    target: str
    status: str = "pending"          # pending / running / done / failed / cancelled
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    error: str | None = None
    score: int = 0
    grade: str = ""
    grade_label: str = ""
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def new(target: str) -> "ScanResult":
        return ScanResult(id=uuid.uuid4().hex[:12], target=target)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


@dataclass
class ScanOptions:
    max_pages: int = 120
    max_depth: int = 3
    deep: bool = False              # 主动 PoC（需授权）
    probe_sensitive: bool = True    # 只读敏感路径探测
    dynamic: bool = False
    save_snapshots: bool = False
    concurrency: int = 8
    rps: float = 6.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
