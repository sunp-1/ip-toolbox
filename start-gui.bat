@echo off
chcp 65001 >nul
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
    echo [!] 未找到 python, 请安装 Python 3.7+ 并勾选 "Add Python to PATH"
    pause
    exit /b 1
)
start "IP Toolbox" /min python ip_tool.py
exit
