# 构建 Windows 桌面应用
#
#   .\scripts\build.ps1
#
# 输出: dist\SSsec\SSsec.exe

param(
    [switch]$SkipInstall,
    [switch]$Clean
)

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

$exe = Join-Path $root "dist\SSsec\SSsec.exe"
if (Test-Path $exe) {
    Write-Host ""
    Write-Host "构建完成: $exe" -ForegroundColor Green
    Write-Host "运行: .\dist\SSsec\SSsec.exe" -ForegroundColor Green
} else {
    Write-Error "构建失败，未找到 $exe"
}
