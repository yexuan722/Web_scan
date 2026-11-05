# 启动本地漏洞靶站（仅测试用）
param(
    [int]$Port = 8899
)

$ErrorActionPreference = "Stop"
$env:PYTHONIOENCODING = "utf-8"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    & python "labs/vuln_app.py" $Port
}
finally {
    Pop-Location
}
