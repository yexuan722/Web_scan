"""HTTP 服务层（纯标准库，零框架依赖）。

设计要点：
- 只监听 127.0.0.1，并校验 Host 头，防 DNS rebinding。
- 写操作需要本次运行随机生成的令牌（注入首页 meta），防本地跨站调用。
- 单实例：重复双击只打开已有窗口，不会起第二个服务。
- 端口被占用时自动向后找可用端口。
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import secrets
import socket
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from . import config
from .engine import run_scan
from .models import ScanOptions, ScanResult
from .report import write_report
from .storage import Store

log = logging.getLogger("webscan")

MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".json": "application/json; charset=utf-8",
}


def _web_dir() -> Path:
    """PyInstaller 打包后前端资源在 _MEIPASS 下，需要单独找。"""
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", "."))
        for candidate in (base / "webscan" / "web", base / "web"):
            if candidate.exists():
                return candidate
        return base / "web"
    return Path(__file__).parent / "web"


WEB_DIR = _web_dir()
STATIC_DIR = WEB_DIR / "static"

store: Store | None = None
_progress: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()
_tasks: list[threading.Thread] = []
MAX_CONCURRENT = 2

# 本次运行的一次性令牌，注入首页 meta；POST/DELETE 必须带上
_TOKEN = secrets.token_urlsafe(18)


def get_store() -> Store:
    """延迟创建：数据目录可能在启动时才被 --data-dir 改写。"""
    global store
    if store is None:
        store = Store()
    return store


def _instance_file() -> Path:
    return config.DATA_DIR / "instance.json"


def _setup_logging() -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    (config.DATA_DIR / "logs").mkdir(parents=True, exist_ok=True)
    handlers: list[logging.Handler] = [
        logging.FileHandler(config.DATA_DIR / "logs" / "webscan.log", encoding="utf-8")
    ]
    if sys.stdout is not None:  # --noconsole 打包后 stdout 为 None
        handlers.append(logging.StreamHandler())
    logging.basicConfig(
        level=logging.INFO,
        handlers=handlers,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        force=True,
    )
    # 第三方库的逐请求日志太吵，压到 WARNING
    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


# ----------------------------------------------------------------------
# 扫描任务
# ----------------------------------------------------------------------
def _start_scan(target: str, options: ScanOptions) -> str:
    scan = ScanResult.new(target)
    get_store().create_scan(scan.id, target, options.to_dict())
    with _lock:
        _progress[scan.id] = {"stage": "queued", "done": 0, "total": 0, "message": "排队中…"}

    def worker() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def emit(event: dict[str, Any]) -> None:
            with _lock:
                cur = _progress.setdefault(scan.id, {})
                if event.get("stage"):
                    cur["stage"] = event["stage"]
                for k in ("done", "total"):
                    if k in event:
                        cur[k] = event[k]
                if event.get("message"):
                    cur["message"] = event["message"]
                if event.get("type") in ("done", "error"):
                    cur["finished"] = True

        try:
            loop.run_until_complete(run_scan(store, scan, options, emit))
        except Exception:
            log.exception("扫描任务异常：%s", scan.id)
        finally:
            loop.close()

    th = threading.Thread(target=worker, name=f"scan-{scan.id}", daemon=True)
    _tasks.append(th)
    th.start()
    return scan.id


def _running_count() -> int:
    return sum(1 for t in _tasks if t.is_alive())


# ----------------------------------------------------------------------
# 路由
# ----------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "WebScan/1.0"
    protocol_version = "HTTP/1.1"

    # ---- 工具 ----
    def _send_json(self, obj: Any, status: int = 200) -> None:
        payload = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _send_file(self, path: Path, download: bool = False) -> None:
        if not path.exists() or not path.is_file():
            self._send_json({"detail": "文件不存在"}, 404)
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", MIME.get(path.suffix.lower(), "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
        self.end_headers()
        self.wfile.write(data)

    def _send_index(self) -> None:
        """首页注入本次运行的令牌。"""
        html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
        data = html.replace("__WEBSCAN_TOKEN__", _TOKEN).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            parsed = json.loads(raw.decode("utf-8"))
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    def _guard(self) -> bool:
        """本地访问保护：Host 白名单 + 写操作令牌。"""
        port = self.server.server_port
        host = (self.headers.get("Host") or "").lower()
        if host not in (f"127.0.0.1:{port}", f"localhost:{port}"):
            log.warning("拒绝非法 Host: %s", host)
            self._send_json({"detail": "非法访问来源"}, 403)
            return False
        token = self.headers.get("X-WebScan-Token", "")
        if not hmac.compare_digest(token, _TOKEN):
            self._send_json({"detail": "缺少访问令牌，请从界面操作"}, 403)
            return False
        return True

    def log_message(self, fmt: str, *args: Any) -> None:
        log.debug("%s - %s", self.address_string(), fmt % args)

    # ---- GET ----
    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        path = unquote(parts.path)
        query = parse_qs(parts.query)

        if path in ("/", "/index.html"):
            self._send_index()
            return
        if path.startswith("/static/"):
            rel = path[len("/static/"):]
            target = (STATIC_DIR / rel).resolve()
            if STATIC_DIR.resolve() not in target.parents and target != STATIC_DIR.resolve():
                self._send_json({"detail": "非法路径"}, 403)
                return
            self._send_file(target)
            return

        if path == "/api/health":
            self._send_json({"ok": True, "name": config.APP_NAME, "version": config.APP_VERSION})
            return

        if path == "/api/scans":
            self._send_json({"items": get_store().list_scans()})
            return

        if path.startswith("/api/scans/"):
            rest = path[len("/api/scans/"):]
            if rest.endswith("/export"):
                scan_id = rest[: -len("/export")].strip("/")
                self._export(scan_id, (query.get("fmt") or ["html"])[0])
                return
            scan_id = rest.strip("/")
            data = get_store().get_scan(scan_id)
            if not data:
                self._send_json({"detail": "扫描不存在"}, 404)
                return
            with _lock:
                data["progress"] = dict(_progress.get(scan_id, {}))
            self._send_json(data)
            return

        self._send_json({"detail": "Not Found"}, 404)

    # ---- POST ----
    def do_POST(self) -> None:
        if not self._guard():
            return
        if urlsplit(self.path).path != "/api/scans":
            self._send_json({"detail": "Not Found"}, 404)
            return
        body = self._body()
        if not body.get("authorized"):
            self._send_json({"detail": "必须确认对该目标拥有所有权或已获得授权"}, 403)
            return
        if _running_count() >= MAX_CONCURRENT:
            self._send_json({"detail": "同时运行的任务过多，请稍后再试"}, 429)
            return

        url = (body.get("url") or "").strip()
        if not url:
            self._send_json({"detail": "请输入目标地址"}, 400)
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urlsplit(url)
        if parsed.scheme not in config.ALLOWED_SCHEMES or not parsed.hostname:
            self._send_json({"detail": "目标地址格式不正确"}, 400)
            return

        options = ScanOptions(
            max_pages=max(1, min(500, int(body.get("max_pages") or config.DEFAULT_MAX_PAGES))),
            max_depth=max(1, min(6, int(body.get("max_depth") or config.DEFAULT_MAX_DEPTH))),
            deep=bool(body.get("deep")),
            probe_sensitive=bool(body.get("probe_sensitive", True)),
        )
        scan_id = _start_scan(url, options)
        log.info("新建扫描 %s -> %s (deep=%s)", scan_id, url, options.deep)
        self._send_json({"id": scan_id, "status": "running"})

    # ---- DELETE ----
    def do_DELETE(self) -> None:
        if not self._guard():
            return
        path = unquote(urlsplit(self.path).path)
        if not path.startswith("/api/scans/"):
            self._send_json({"detail": "Not Found"}, 404)
            return
        scan_id = path[len("/api/scans/"):].strip("/")
        get_store().delete_scan(scan_id)
        with _lock:
            _progress.pop(scan_id, None)
        self._send_json({"ok": True})

    # ---- 导出 ----
    def _export(self, scan_id: str, fmt: str) -> None:
        data = get_store().get_scan(scan_id)
        if not data:
            self._send_json({"detail": "扫描不存在"}, 404)
            return
        if data.get("status") != "done":
            self._send_json({"detail": "扫描尚未完成"}, 400)
            return
        fmt = (fmt or "html").lower()
        if fmt not in ("html", "md", "json"):
            self._send_json({"detail": "不支持的导出格式"}, 400)
            return
        data["id"] = scan_id
        data["started_at"] = data.get("started_at") or time.time()
        paths = write_report(data, config.REPORT_DIR)
        self._send_file(Path(paths[fmt]), download=True)


# ----------------------------------------------------------------------
# 实例管理
# ----------------------------------------------------------------------
def _port_in_use(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.4)
        return s.connect_ex((host, port)) == 0


def _read_instance() -> dict[str, Any] | None:
    try:
        data = json.loads(_instance_file().read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("port"):
            return data
    except Exception:
        return None
    return None


def _write_instance(host: str, port: int) -> None:
    try:
        _instance_file().parent.mkdir(parents=True, exist_ok=True)
        _instance_file().write_text(
            json.dumps(
                {"pid": os.getpid(), "host": host, "port": port,
                 "url": f"http://{host}:{port}/"}
            ),
            encoding="utf-8",
        )
    except Exception:
        log.exception("写实例文件失败")


def _clear_instance() -> None:
    try:
        _instance_file().unlink(missing_ok=True)
    except Exception:
        pass


def _alive(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=0.6) as r:
            data = json.loads(r.read().decode("utf-8"))
            return data.get("name") == config.APP_NAME
    except Exception:
        return False


# ----------------------------------------------------------------------
def serve(
    host: str = "127.0.0.1",
    port: int = config.DEFAULT_PORT,
    open_browser: bool = True,
    use_tray: bool = True,
    windowed: bool = True,
) -> None:
    _setup_logging()

    existing = _read_instance()
    if existing and _alive(int(existing["port"])):
        url = existing.get("url") or f"http://127.0.0.1:{existing['port']}/"
        log.info("已有实例在运行：%s", url)
        if open_browser:
            _bring_to_front(url, windowed)
        return

    httpd: ThreadingHTTPServer | None = None
    chosen = port
    for candidate in range(port, port + 20):
        if _port_in_use(host, candidate):
            continue
        try:
            httpd = ThreadingHTTPServer((host, candidate), Handler)
            chosen = candidate
            break
        except OSError:
            continue
    if httpd is None:
        log.error("端口 %s ~ %s 均被占用，无法启动", port, port + 19)
        return

    httpd.daemon_threads = True
    _write_instance(host, chosen)
    url = f"http://{host}:{chosen}/"
    log.info("WebScan %s 已启动：%s", config.APP_VERSION, url)
    log.info("数据目录：%s", config.DATA_DIR)

    closed = threading.Event()

    def shutdown() -> None:
        if closed.is_set():
            return
        log.info("正在退出…")
        _clear_instance()
        closed.set()
        try:
            httpd.shutdown()
        except Exception:
            pass

    server_thread = threading.Thread(target=httpd.serve_forever, name="http", daemon=True)
    server_thread.start()

    if use_tray:
        try:
            from .tray import start_tray

            start_tray(url=url, on_quit=shutdown)
        except Exception:
            log.exception("托盘启动失败，退化为无托盘模式")

    # 优先原生窗口（WebView2）；不可用则退到 app 模式窗口，再退到普通浏览器
    if windowed and _run_native_window(url):
        log.info("原生窗口已关闭")
        shutdown()
        httpd.server_close()
        return

    if open_browser:
        _bring_to_front(url, windowed)

    try:
        closed.wait()
    except KeyboardInterrupt:
        log.info("收到 Ctrl+C，退出")
    finally:
        shutdown()
        httpd.server_close()


def _run_native_window(url: str) -> bool:
    """用 WebView2 开一个真正的窗口。不可用时返回 False。"""
    try:
        from .window import run as run_window

        return run_window(url)
    except Exception:
        log.exception("原生窗口启动失败，回退浏览器")
        return False


def _bring_to_front(url: str, windowed: bool) -> None:
    if windowed and _open_app_window(url):
        return
    _open(url)


def _open_app_window(url: str) -> bool:
    """浏览器 --app 模式：独立窗口、任务栏图标，但没有标签栏和地址栏。"""
    if sys.platform != "win32":
        return False
    candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ]
    for exe in candidates:
        if not Path(exe).exists():
            continue
        try:
            import subprocess

            subprocess.Popen([exe, f"--app={url}", "--window-size=1280,860"])
            log.info("以 app 模式打开：%s", exe)
            return True
        except Exception:
            log.exception("app 模式启动失败：%s", exe)
    return False


def _is_elevated() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _notify_url(url: str, reason: str = "") -> None:
    """浏览器没能自动打开时的兜底：把地址明明白白摆给用户看。"""
    log.warning("未能自动打开浏览器：%s", url)
    if sys.platform != "win32":
        return
    try:
        import ctypes

        msg = (
            f"{reason}\n\n请手动在浏览器中打开：\n{url}"
            if reason
            else f"请手动在浏览器中打开：\n{url}"
        )
        ctypes.windll.user32.MessageBoxW(0, msg, "WebScan · 打开界面", 0x40)
    except Exception:
        pass


def _open(url: str) -> None:
    """打开浏览器。

    注意：Windows 上如果已有实例以管理员权限运行，普通权限进程调用默认浏览器会被
    拒绝并弹「现有实例正在以提升的权限运行」的对话框。这种情况下改用 explorer.exe
    交接给外壳（外壳始终跑在普通权限），或直接提示用户手动打开。
    """
    import webbrowser

    try:
        if sys.platform == "win32":
            if _is_elevated():
                # 提权进程直接拉浏览器会污染浏览器权限，交给 explorer 中转
                log.info("当前进程已提权，改用 explorer 打开界面")
                import subprocess

                subprocess.Popen(["explorer.exe", url])
                return
            if webbrowser.open(url):
                return
        else:
            if webbrowser.open(url):
                return
    except Exception:
        log.exception("打开浏览器异常")
        _notify_url(url, "自动打开浏览器失败。")
        return

    _notify_url(url)
