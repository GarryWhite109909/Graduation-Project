@echo off
chcp 65001 >nul
cd /d "%~dp0\..\.."
echo Starting AI Vulnerability Scanner...

REM First-run auto-install: web layer + analysis engine + tree-sitter language packs + launcher hardware detection
python -c "import fastapi, uvicorn, pydantic, requests, tree_sitter, tree_sitter_python, tree_sitter_javascript, tree_sitter_java, tree_sitter_php, tree_sitter_typescript, chromadb, sentence_transformers, psutil" 2>nul
if errorlevel 1 (
    echo [Setup] First run: installing dependencies...
    REM Install CPU-only torch first to avoid pulling NVIDIA CUDA packages.
    REM LLM inference is handled by Ollama; Python side only needs torch for embeddings.
    pip install --index-url https://download.pytorch.org/whl/cpu torch
    REM Use Tsinghua TUNA mirror to speed up pip downloads in China
    pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
    pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .
    echo [Setup] Dependencies installed.
)

python -m app.launcher.bootstrap
pause
