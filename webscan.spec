# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置：单目录、无控制台、带图标、内置 Qt WebEngine 窗口。

构建：python -m PyInstaller webscan.spec
产物：dist/WebScan/WebScan.exe
"""

from pathlib import Path
import os
import sys

from PyInstaller.utils.hooks import collect_submodules

hidden = []
datas = [
    ("webscan/web", "webscan/web"),
    ("assets/webscan.ico", "assets"),
]
binaries = []
browser_path = Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH", Path(SPECPATH) / "build" / "pw-browsers"))
browser_dirs = sorted(browser_path.glob("chromium_headless_shell-*"))
if not browser_dirs:
    raise SystemExit("Run scripts/build_exe.ps1 to install the Chromium headless shell first.")
for browser_dir in browser_dirs:
    datas.append((str(browser_dir), f"pw-browsers/{browser_dir.name}"))

# 托盘后端是运行时动态导入的
hidden += collect_submodules("pystray")
hidden += ["PIL.Image", "PIL.ImageDraw", "PIL.ImageFont"]

# Qt WebEngine 相关模块（其余由 PyInstaller 的 PySide6 hook 自动处理）
hidden += [
    "PySide6.QtCore",
    "PySide6.QtGui",
    "PySide6.QtWidgets",
    "PySide6.QtNetwork",
    "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineWidgets",
]

a = Analysis(
    ["run_webscan.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "numpy",
        "pandas",
        "pytest",
        # 瘦身：用不到的 Qt 模块
        "PySide6.Qt3DCore",
        "PySide6.QtCharts",
        "PySide6.QtDataVisualization",
        "PySide6.QtMultimedia",
        "PySide6.QtMultimediaWidgets",
        "PySide6.QtQuick3D",
        "PySide6.QtSql",
        "PySide6.QtTest",
        "PySide6.QtBluetooth",
        "PySide6.QtDesigner",
    ],
    noarchive=False,
)

# Qt 依赖 Windows 自带的 ICU 接口。PATH 上其他应用的 ICU 可能只有带版本后缀的符号。
if sys.platform == "win32":
    system_icu = {"icu.dll", "icuin.dll", "icuuc.dll"}
    a.binaries = [entry for entry in a.binaries if entry[0].lower() not in system_icu]

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="WebScan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="assets/webscan.ico",
)

# 单目录模式：不往 %TEMP% 解压，启动快、被杀软误报的概率低得多
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="WebScan",
)
