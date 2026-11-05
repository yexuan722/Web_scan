"""系统托盘（可选）。依赖不到时静默降级，不影响主程序。"""

from __future__ import annotations

import logging
import threading
import webbrowser
from typing import Callable

log = logging.getLogger("webscan.tray")


def make_icon_image(size: int = 64):
    """画一个蓝底放大镜，作为窗口/托盘/exe 图标。"""
    from PIL import Image, ImageDraw

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    r = size * 0.22
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=r, fill=(37, 99, 235, 255))

    s = size / 64.0
    # 镜圈
    d.ellipse(
        [int(14 * s), int(12 * s), int(42 * s), int(40 * s)],
        outline=(255, 255, 255, 255),
        width=max(2, int(5 * s)),
    )
    # 手柄
    d.line(
        [int(40 * s), int(38 * s), int(52 * s), int(50 * s)],
        fill=(255, 255, 255, 255),
        width=max(2, int(6 * s)),
    )
    return img


def start_tray(url: str, on_quit: Callable[[], None]) -> bool:
    """启动托盘图标，成功返回 True。"""
    try:
        import pystray
    except Exception:
        log.info("未安装 pystray，跳过托盘")
        return False

    def _open(icon=None, item=None) -> None:
        # 走统一的打开逻辑（含提权检测与失败兜底）
        try:
            from .api import _open as open_url

            open_url(url)
        except Exception:
            webbrowser.open(url)

    def _quit(icon=None, item=None) -> None:
        try:
            if icon is not None:
                icon.stop()
        finally:
            on_quit()

    try:
        menu = pystray.Menu(
            pystray.MenuItem("打开界面", _open, default=True),
            pystray.MenuItem("退出", _quit),
        )
        title = f"WebScan · {url}"
        icon = pystray.Icon("webscan", make_icon_image(64), title, menu)
        threading.Thread(target=icon.run, daemon=True).start()
        log.info("托盘已启动：%s", url)
        return True
    except Exception:
        log.exception("托盘初始化失败")
        return False
