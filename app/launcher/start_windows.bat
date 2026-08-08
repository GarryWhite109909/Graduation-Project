@echo off
chcp 65001 >nul
cd /d "%~dp0\..\.."
echo Starting AI Vulnerability Scanner...

REM =====================================================================
REM Decide the interpreter FIRST, then use it for the whole flow.
REM This way the torch-matched env (CUDA/ROCm) carries ALL deps
REM (web + analysis + tree-sitter + inference), avoiding split-env issues
REM (torch is right but tree_sitter_python is missing).
REM Falls back to plain "python" when no matching env is found.
REM =====================================================================
set "PY="
for /f "delims=" %%i in ('python -c "import sys; sys.path.insert(0,'.'); from app.launcher.dependency_installer import discover_best_python; b=discover_best_python(); print(b if b else sys.executable)" 2^>nul') do set "PY=%%i"
if "%PY%"=="" set "PY=python"
echo [Setup] Using interpreter: %PY%

REM ---------------------------------------------------------------------
REM First-run auto-install: web layer + analysis engine + tree-sitter + launcher detection
REM ---------------------------------------------------------------------
%PY% -c "import fastapi, uvicorn, pydantic, requests, tree_sitter, tree_sitter_python, tree_sitter_javascript, tree_sitter_java, tree_sitter_php, tree_sitter_typescript, chromadb, sentence_transformers, psutil" 2>nul
if errorlevel 1 (
    echo [Setup] First run: installing core dependencies...

    REM Install CPU torch for embeddings ONLY if this interpreter has no torch at all;
    REM skip when it already has a hardware-matched torch (CUDA/ROCm), to avoid
    REM overwriting the matching build with the CPU one.
    %PY% -c "import torch" 2>nul
    if errorlevel 1 (
        %PY% -m pip install --index-url https://download.pytorch.org/whl/cpu torch
    )

    REM Use Tsinghua TUNA mirror to speed up pip downloads in China
    %PY% -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
    %PY% -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .
    echo [Setup] Core dependencies installed.
)

REM New-framework legacy security tools (auto-install, latest stable)
if not "%VULN_SCANNER_SKIP_TOOLS%"=="1" (
    echo [Setup] Checking/installing security tools (latest stable)...
    %PY% -m app.launcher.dependency_installer tools
)

REM If the user explicitly picked transformers/llamacpp backend, pre-install its deps (optional)
if not "%VULN_SCANNER_BACKEND%"=="" (
    if "%VULN_SCANNER_BACKEND%"=="transformers" %PY% -m app.launcher.dependency_installer transformers
    if "%VULN_SCANNER_BACKEND%"=="llamacpp" %PY% -m app.launcher.dependency_installer llamacpp
)

%PY% -m app.launcher.bootstrap
pause
