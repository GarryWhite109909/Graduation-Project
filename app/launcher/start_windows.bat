@echo off
chcp 65001 >nul
cd /d "%~dp0\.."
echo Starting AI Vulnerability Scanner...

REM 首次运行自动安装依赖
python -c "import fastapi, uvicorn" 2>nul
if errorlevel 1 (
    echo [Setup] First run: installing dependencies...
    pip install -r requirements.txt
    pip install -e .
    echo [Setup] Dependencies installed.
)

python -m app.launcher.bootstrap
pause
