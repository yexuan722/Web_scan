"""命令行入口：`python -m webscan` / 双击 exe 启动本地服务并打开浏览器。"""

from __future__ import annotations

import argparse
import sys
import traceback

from . import config


def _fatal(title: str, message: str) -> None:
    """打包成窗口程序后没有控制台，出错必须弹窗，否则就是"双击没反应"。"""
    try:
        sys.stderr.write(f"[{title}] {message}\n")
    except Exception:
        pass
    if getattr(sys, "frozen", False) and sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(0, message, f"WebScan · {title}", 0x10)
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        prog="webscan",
        description="WebScan 1.0 —— Web 漏洞扫描器（仅限授权目标）",
    )
    parser.add_argument("--host", default="127.0.0.1", help="监听地址（默认仅本机）")
    parser.add_argument("--port", type=int, default=config.DEFAULT_PORT, help="监听端口")
    parser.add_argument("--no-browser", action="store_true", help="不自动打开界面")
    parser.add_argument(
        "--browser",
        action="store_true",
        help="用浏览器打开界面（默认优先使用原生窗口）",
    )
    parser.add_argument("--data-dir", help="数据目录（默认：程序旁 data / 用户目录）")
    parser.add_argument("--scan", metavar="URL", help="不开界面，直接命令行扫描并打印摘要")
    parser.add_argument("--deep", action="store_true", help="命令行扫描时启用主动 PoC")
    args = parser.parse_args(argv)

    if args.data_dir:
        config.set_data_dir(args.data_dir)

    if args.scan:
        try:
            return _cli_scan(args.scan, deep=args.deep)
        except Exception as exc:
            _fatal("扫描失败", f"{type(exc).__name__}: {exc}")
            traceback.print_exc()
            return 1

    try:
        from .api import serve

        serve(
            host=args.host,
            port=args.port,
            open_browser=not args.no_browser,
            windowed=not args.browser,
        )
    except Exception as exc:
        traceback.print_exc()
        _fatal(
            "启动失败",
            f"{type(exc).__name__}: {exc}\n\n"
            f"数据目录：{config.DATA_DIR}\n"
            "如果提示拒绝访问，可用 --data-dir 指定一个可写目录，"
            "或把程序放到有写权限的位置。",
        )
        return 1
    return 0


def _cli_scan(url: str, deep: bool) -> int:
    import asyncio

    from .engine import run_scan
    from .models import ScanOptions, ScanResult
    from .storage import Store

    store = Store()
    scan = ScanResult.new(url)
    store.create_scan(scan.id, url, {"deep": deep})
    options = ScanOptions(deep=deep)

    async def emit(event: dict) -> None:
        if event.get("message"):
            print(f"  · {event['message']}")

    async def run() -> ScanResult:
        return await run_scan(store, scan, options, emit)

    print(f"WebScan 1.0  |  目标: {url}\n")
    result = asyncio.run(run())
    if result.status != "done":
        print(f"\n扫描失败: {result.error}")
        return 1

    print(f"\n健康评分: {result.score}/100  ({result.grade_label})")
    print(f"共 {len(result.findings)} 条发现\n")
    for f in result.findings:
        print(f"[{f.severity.upper():8}] {f.title}")
        print(f"           {f.url}")
    print(f"\n详情: http://127.0.0.1:{config.DEFAULT_PORT}/#scan/{result.id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
