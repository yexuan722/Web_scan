# 打包成可分发目录（onedir，比 onefile 稳定、杀软误报更少）
param(
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if (-not $SkipInstall) {
        python -m pip install --upgrade pyinstaller pystray pillow PySide6
    }

    # 图标（已存在则跳过）
    if (-not (Test-Path "assets/webscan.ico")) {
        python scripts/make_icon.py
    }

    python -m PyInstaller --noconfirm --clean webscan.spec

    Write-Host ""
    Write-Host "产物：$root\dist\WebScan\WebScan.exe" -ForegroundColor Green
    Write-Host "整个 dist\WebScan 目录就是绿色版，可直接压缩分发。"
    Write-Host "数据目录默认在 exe 同级的 data\，不可写时回落到 %LOCALAPPDATA%\WebScan\data。"
}
finally {
    Pop-Location
}
