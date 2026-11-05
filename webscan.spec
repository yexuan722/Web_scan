# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置：单目录、无控制台、带图标、内置 Qt WebEngine 窗口。

构建：python -m PyInstaller webscan.spec
产物：dist/WebScan/WebScan.exe
"""

from PyInstaller.utils.hooks import collect_submodules

hidden = []
datas = [
    ("webscan/web", "webscan/web"),
    ("assets/webscan.ico", "assets"),
]
binaries = []

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
