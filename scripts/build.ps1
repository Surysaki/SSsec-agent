# 构建 Windows 桌面应用
#
#   .\scripts\build.ps1
#
# 输出: dist\SSsec\SSsec.exe
#
# 注意：本文件必须保存为 UTF-8 with BOM。Windows PowerShell 5.1 在读取
# 无 BOM 的 .ps1 时会按系统 ANSI 代码页解析，导致中文字符串乱码。

param(
    [switch]$SkipInstall,
    [switch]$Clean
)

[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
try { chcp 65001 | Out-Null } catch {}

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Host "未找到 .venv，正在创建虚拟环境..." -ForegroundColor Cyan
    python -m venv .venv
    $python = Join-Path $root ".venv\Scripts\python.exe"
}

if (-not $SkipInstall) {
    Write-Host "安装运行与打包依赖..." -ForegroundColor Cyan
    & $python -m pip install -r requirements.txt -r requirements-dev.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Error "依赖安装失败（exit $LASTEXITCODE）"
        exit $LASTEXITCODE
    }
}

if ($Clean) {
    Write-Host "清理旧的 build/ 与 dist/..." -ForegroundColor Cyan
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue build, dist
}

$icon = Join-Path $root "sssec\assets\sssec.ico"
if (-not (Test-Path $icon)) {
    Write-Host "生成应用图标..." -ForegroundColor Cyan
    $env:QT_QPA_PLATFORM = "offscreen"
    & $python scripts\make_icon.py
}

Write-Host "执行 PyInstaller 打包（首次可能需要几分钟）..." -ForegroundColor Cyan
& $python -m PyInstaller --noconfirm --clean SSsec.spec
$buildExit = $LASTEXITCODE

$exe = Join-Path $root "dist\SSsec\SSsec.exe"
if ($buildExit -eq 0 -and (Test-Path $exe)) {
    Write-Host ""
    Write-Host "构建完成: $exe" -ForegroundColor Green
    Write-Host "运行: .\dist\SSsec\SSsec.exe" -ForegroundColor Green
    exit 0
} else {
    Write-Error "构建失败（PyInstaller exit $buildExit），未找到可用的 $exe"
    exit 1
}
