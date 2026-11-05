"""全局配置与常量。所有可调参数集中在这里，方便写进报告。"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

APP_NAME = "WebScan"
APP_VERSION = "1.1.0"


def _writable(path: Path) -> bool:
    """真写一次再删，比权限位判断可靠（ACL / 只读 / 网络盘都适用）。"""
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".ws_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except Exception:
        return False


def _candidates() -> list[Path]:
    """按优先级给出候选数据目录：便携 → 用户目录 → 临时目录。"""
    if os.environ.get("WEBSCAN_DATA_DIR"):
        return [Path(os.environ["WEBSCAN_DATA_DIR"])]
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        local = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / APP_NAME / "data"
        tmp = Path(tempfile.gettempdir()) / APP_NAME / "data"
        # 便携模式优先：exe 旁边能写就写在旁边，符合"绿色软件"预期
        return [exe_dir / "data", local, tmp]
    return [Path.cwd() / "data"]


def _resolve_data_dir() -> Path:
    for candidate in _candidates():
        if _writable(candidate):
            return candidate
    # 全部不可写：返回首选，让上层报清晰的错误
    return _candidates()[0]


DATA_DIR = _resolve_data_dir()
DB_PATH = DATA_DIR / "webscan.db"
REPORT_DIR = DATA_DIR / "reports"


def set_data_dir(path: str | Path) -> None:
    """运行期覆盖数据目录（供 --data-dir 使用）。"""
    global DATA_DIR, DB_PATH, REPORT_DIR
    DATA_DIR = Path(path).resolve()
    DB_PATH = DATA_DIR / "webscan.db"
    REPORT_DIR = DATA_DIR / "reports"


# 默认监听端口（避开常见开发端口；Windows 上 SO_REUSEADDR 会让端口被静默抢占）
DEFAULT_PORT = 8770

# --------------------------------------------------------------------------
# 爬虫
# --------------------------------------------------------------------------
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 WebScan/1.0"
)

DEFAULT_MAX_PAGES = 120
DEFAULT_MAX_DEPTH = 3
DEFAULT_CONCURRENCY = 8
DEFAULT_RPS = 6.0              # 每主机请求速率上限
DEFAULT_TIMEOUT = 10.0
MAX_BODY_BYTES = 512 * 1024    # 单页最多保留 512 KiB 正文

# 绝不自动访问的路径（避免踢会话 / 删数据 / 下单）
DANGEROUS_PATH_PATTERN = (
    r"(?i)(logout|signout|sign-out|log-out|delete|remove|destroy|"
    r"unsubscribe|checkout|pay\b|payment|purchase|buy\b|order/cancel|"
    r"shutdown|reboot|reset-password|drop\b|truncate|install|setup/complete)"
)

ALLOWED_SCHEMES = ("http", "https")

# --------------------------------------------------------------------------
# 敏感文件探测（只读 GET，带内容指纹校验，避免把 404 页面当泄露）
# 结构：(路径, 必须全部出现的片段, 至少出现一个的片段, 说明, 严重度)
# --------------------------------------------------------------------------
SENSITIVE_PATHS: list[tuple[str, tuple[str, ...], tuple[str, ...], str, str]] = [
    (".git/config", ("[core]",), (), "Git 仓库配置泄露，可还原源码", "critical"),
    (".git/HEAD", ("ref: refs/",), (), "Git 目录可访问，可还原源码", "critical"),
    (".svn/entries", (), ("dir", "svn"), "SVN 元数据泄露", "high"),
    (".env", ("=",), ("APP_KEY", "DB_PASSWORD", "SECRET_KEY", "API_KEY", "MAIL_PASSWORD"),
     "环境变量文件泄露（可能含数据库口令）", "critical"),
    (".DS_Store", ("Bud1",), (), "macOS 目录索引泄露", "low"),
    ("web.config", ("<configuration",), (), "IIS 配置文件泄露", "high"),
    ("config.php.bak", ("<?php",), (), "PHP 配置备份文件泄露", "critical"),
    ("backup.zip", ("PK\x03\x04",), (), "站点备份压缩包可下载", "critical"),
    ("www.zip", ("PK\x03\x04",), (), "站点备份压缩包可下载", "critical"),
    ("package.json", ('"dependencies"',), (), "前端依赖清单泄露", "low"),
    ("composer.json", ('"require"',), (), "PHP 依赖清单泄露", "low"),
    ("phpinfo.php", (), ("phpinfo()", "PHP Version"), "phpinfo 调试页暴露", "high"),
    ("server-status", ("Apache Server Status",), (), "Apache 状态页暴露", "medium"),
    ("actuator/env", ('"propertySources"',), (), "Spring Actuator 环境变量暴露", "critical"),
    ("actuator/health", ('"status"',), (), "Spring Actuator 端点暴露", "low"),
    ("swagger-ui.html", ("Swagger UI",), (), "接口文档暴露（扩大攻击面）", "low"),
    ("crossdomain.xml", ("<cross-domain-policy",), ("*",), "宽松的跨域策略文件", "medium"),
]

# --------------------------------------------------------------------------
# 泄密特征（响应体正则）
# --------------------------------------------------------------------------
ERROR_SIGNATURES: list[tuple[str, str]] = [
    (r"Traceback \(most recent call last\)", "Python 堆栈信息泄露"),
    (r"<b>(Fatal error|Parse error|Warning)</b>:.{0,200}?on line \d+", "PHP 错误信息泄露"),
    (r"javax\.servlet\.ServletException|java\.lang\.NullPointerException", "Java 异常堆栈泄露"),
    (r"SQLSTATE\[\w+\]|You have an error in your SQL syntax|Unclosed quotation mark", "数据库错误信息泄露"),
    (r"Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver", "数据库错误信息泄露"),
    (r"at [\w.$]+\([\w.]+\.java:\d+\)", "Java 堆栈片段泄露"),
    (r"at Object\.<anonymous> \((.*?):\d+:\d+\)", "Node.js 堆栈信息泄露"),
]

# HTML 注释里值得警惕的内容
COMMENT_PATTERN = r"<!--(.*?)-->"
COMMENT_RISK: list[tuple[str, str]] = [
    (r"(?i)(password|passwd|pwd)\s*[:=]", "注释中出现口令线索"),
    (r"(?i)(todo|fixme|hack|backdoor)", "注释中残留开发标记"),
    (r"\b(10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "注释中暴露内网地址"),
    (r"(?i)api[_-]?key|secret[_-]?key|access[_-]?token", "注释中暴露密钥字段名"),
]

# 安全响应头定义：(header, 说明, 严重度)
SECURITY_HEADERS = [
    ("content-security-policy", "缺少 CSP（无法缓解 XSS / 内容注入）", "medium"),
    ("x-content-type-options", "缺少 X-Content-Type-Options: nosniff", "low"),
    ("x-frame-options", "缺少 X-Frame-Options（存在点击劫持风险）", "medium"),
    ("referrer-policy", "缺少 Referrer-Policy（可能泄露敏感 URL）", "low"),
    ("permissions-policy", "缺少 Permissions-Policy", "info"),
]

# --------------------------------------------------------------------------
# 评分模型（noisy-OR）
# --------------------------------------------------------------------------
SEVERITY_BASE = {
    "critical": 0.35,
    "high": 0.20,
    "medium": 0.08,
    "low": 0.02,
    "info": 0.0,
}

SEVERITY_WEIGHT = {  # 仅用于排序与展示
    "critical": 100,
    "high": 70,
    "medium": 40,
    "low": 15,
    "info": 0,
}

GRADE_BANDS = [
    (90, "良好", "good"),
    (75, "一般", "fair"),
    (50, "风险", "risky"),
    (0, "危险", "bad"),
]

# --------------------------------------------------------------------------
# 主动 PoC
# --------------------------------------------------------------------------

SQLI_ERROR_PAYLOADS = ("'", '"', "')")
SQLI_ERROR_SIGNATURES = (
    r"SQL syntax.{0,80}?MySQL",
    r"Unclosed quotation mark",
    r"SQLSTATE\[\w+\]",
    r"ORA-\d{5}",
    r"SQLite/JDBCDriver",
    r"pg_query\(\)",
    r"Microsoft OLE DB Provider",
    r"syntax error at or near",
)

LFI_PAYLOADS = (
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
)
LFI_SIGNATURES = (
    r"root:x:0:0:",
    r"\[fonts\]",
    r"\[extensions\]",
)

ACTIVE_MAX_TARGETS = 40        # 单次扫描最多测多少个参数
