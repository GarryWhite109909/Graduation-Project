@echo off
chcp 65001 >nul
cd /d "%~dp0\.."
echo Starting AI Vulnerability Scanner...

REM 首次运行自动安装依赖：检测核心 Web 层 + 分析引擎层 + tree-sitter 语言包 + 启动器硬件检测
python -c "import fastapi, uvicorn, pydantic, requests, tree_sitter, tree_sitter_python, tree_sitter_javascript, tree_sitter_java, tree_sitter_php, tree_sitter_typescript, chromadb, sentence_transformers, psutil" 2>nul
if errorlevel 1 (
    echo [Setup] First run: installing dependencies...
    pip install -r requirements.txt
    pip install -e .
    echo [Setup] Dependencies installed.
)

python -m app.launcher.bootstrap
pause
