# 启动 WebScan 本地服务
param(
    [int]$Port = 8770,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$env:PYTHONIOENCODING = "utf-8"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $pyArgs = @("-m", "webscan", "--port", $Port)
    if ($NoBrowser) { $pyArgs += "--no-browser" }
    & python @pyArgs
}
finally {
    Pop-Location
}
