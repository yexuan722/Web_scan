"""原生窗口（Qt WebEngine / Chromium）。

相比浏览器标签页：
- 自己的窗口、任务栏图标、Alt+Tab 条目，关窗即退出；
- 没有地址栏、标签栏，不受浏览器插件/主题/缩放影响；
- 不经过浏览器进程交接，不会触发"管理员实例"冲突。

依赖：PySide6（含 QtWebEngine）。不可用时返回 False，调用方自动回退。
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

log = logging.getLogger("webscan.window")

TITLE = "WebScan · Web 漏洞扫描器"

# 必须在导入 QtWebEngine 之前设置。
# 打包后的程序里，Chromium 的沙箱子进程（QtWebEngineProcess.exe）无法启动，
# 表现为窗口一片空白、没有 QtWebEngineProcess 进程。
# 我们只加载本机 http://127.0.0.1 的自家页面，不渲染任意外部内容，
# 因此关闭该沙箱是可接受的风险折中。
os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")


def available() -> bool:
    try:
        import PySide6.QtWebEngineWidgets  # noqa: F401

        return True
    except Exception:
        return False


def _icon_path() -> str | None:
    candidates: list[Path] = []
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", "."))
        candidates += [base / "assets" / "webscan.ico", base / "webscan.ico"]
    candidates.append(Path(__file__).resolve().parent.parent / "assets" / "webscan.ico")
    for path in candidates:
        if path.exists():
            return str(path)
    return None


def run(url: str, width: int = 1400, height: int = 900) -> bool:
    """打开原生窗口并阻塞到窗口关闭。成功返回 True。"""
    if not available():
        log.info("未安装 PySide6，跳过原生窗口")
        return False

    try:
        from PySide6.QtCore import QCoreApplication, Qt, QUrl
        from PySide6.QtGui import QIcon
        from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineProfile
        from PySide6.QtWebEngineWidgets import QWebEngineView
        from PySide6.QtWidgets import QApplication, QFileDialog, QMainWindow
    except Exception:
        log.exception("Qt 组件导入失败")
        return False

    def _qt_message(mode, context, message):  # Qt 的诊断信息进日志，窗口版也有据可查
        log.warning("[qt] %s", message)

    try:
        from PySide6.QtCore import QLibraryInfo, qInstallMessageHandler

        qInstallMessageHandler(_qt_message)
    except Exception:
        pass

    try:
        QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts, True)
        app = QApplication.instance() or QApplication(sys.argv)
        app.setApplicationName("WebScan")
        app.setApplicationDisplayName(TITLE)
        try:
            log.info(
                "Qt 可执行目录：%s",
                QLibraryInfo.path(QLibraryInfo.LibraryPath.LibraryExecutablesPath),
            )
            log.info("Qt 数据目录：%s", QLibraryInfo.path(QLibraryInfo.LibraryPath.DataPath))
        except Exception:
            log.exception("读取 Qt 路径失败")

        icon_path = _icon_path()
        if icon_path:
            app.setWindowIcon(QIcon(icon_path))

        # 用匿名 profile：界面不需要 Cookie/缓存，也就不往磁盘写指纹数据
        profile = QWebEngineProfile()
        view = QWebEngineView()
        view.setPage(QWebEnginePage(profile, view))
        view.setUrl(QUrl(url))

        win = QMainWindow()
        win.setWindowTitle(TITLE)
        if icon_path:
            win.setWindowIcon(QIcon(icon_path))
        win.resize(width, height)
        win.setMinimumSize(1100, 700)
        win.setCentralWidget(view)

        def save_download(download):
            destination, _ = QFileDialog.getSaveFileName(
                win, "保存 WebScan 导出文件", str(Path.home() / download.suggestedFileName())
            )
            if not destination:
                download.cancel()
                return
            path = Path(destination)
            download.setDownloadDirectory(str(path.parent))
            download.setDownloadFileName(path.name)
            download.accept()

        profile.downloadRequested.connect(save_download)
        win.show()

        log.info("原生窗口已打开：%s", url)
        app.exec()
        return True
    except Exception:
        log.exception("原生窗口运行失败")
        return False
