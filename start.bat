@echo off
chcp 65001 >nul
setlocal
set PYTHONUTF8=1
cd /d "%~dp0"
if exist "dist\SSsec\SSsec.exe" (
    start "" "dist\SSsec\SSsec.exe"
    exit /b 0
)
if exist ".venv\Scripts\pythonw.exe" (
    start "" ".venv\Scripts\pythonw.exe" -m sssec
    exit /b 0
)
echo.
echo 未找到虚拟环境或已构建的应用。
echo 请先在 PowerShell 中执行：
echo    python -m venv .venv
echo    .\.venv\Scripts\Activate.ps1
echo    pip install -r requirements.txt
echo    python -m sssec
echo.
pause
