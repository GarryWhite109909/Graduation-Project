@echo off
chcp 65001 >nul
cd /d "%~dp0\..\.."
echo Starting AI Vulnerability Scanner...

REM First-run auto-install: web layer + analysis engine + tree-sitter language packs + launcher hardware detection
python -c "import fastapi, uvicorn, pydantic, requests, tree_sitter, tree_sitter_python, tree_sitter_javascript, tree_sitter_java, tree_sitter_php, tree_sitter_typescript, chromadb, sentence_transformers, psutil" 2>nul
if errorlevel 1 (
    echo [Setup] First run: installing core dependencies...
    REM Default one-click backend is Ollama; Python side only needs CPU torch for embeddings.
    REM If transformers/llamacpp backend is chosen later, the launcher will reinstall torch per hardware.
    REM Use "python -m pip" instead of bare "pip" so it works even when pip is not on PATH.
    python -m pip install --index-url https://download.pytorch.org/whl/cpu torch
    REM Use Tsinghua TUNA mirror to speed up pip downloads in China
    python -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
    python -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .
    echo [Setup] Core dependencies installed.
)

REM If the user explicitly picked transformers/llamacpp backend, pre-install its deps (optional)
if not "%VULN_SCANNER_BACKEND%"=="" (
    if "%VULN_SCANNER_BACKEND%"=="transformers" python -m app.launcher.dependency_installer transformers
    if "%VULN_SCANNER_BACKEND%"=="llamacpp" python -m app.launcher.dependency_installer llamacpp
)

python -m app.launcher.bootstrap
pause
