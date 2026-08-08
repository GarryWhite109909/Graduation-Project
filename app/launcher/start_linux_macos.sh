#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/../.." || exit 1
echo "Starting AI Vulnerability Scanner..."

# 首次运行自动安装依赖：检测核心 Web 层 + 分析引擎层 + tree-sitter 语言包 + 启动器硬件检测
python3 -c "import fastapi, uvicorn, pydantic, requests, tree_sitter, tree_sitter_python, tree_sitter_javascript, tree_sitter_java, tree_sitter_php, tree_sitter_typescript, chromadb, sentence_transformers, psutil" 2>/dev/null || {
    echo "[Setup] First run: installing core dependencies..."

    # 默认一键启动后端的推理由 Ollama 负责，Python 侧 torch 仅用于 sentence-transformers embedding，
    # 先装 CPU 版保底。若后续选择 transformers/llamacpp 后端，启动器会按硬件自动重装对应版本。
    python3 -m pip install --index-url https://download.pytorch.org/whl/cpu torch || true

    # 使用清华 TUNA 镜像加速国内 pip 下载
    python3 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
    python3 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .
    echo "[Setup] Core dependencies installed."
}

# 若用户已显式指定 transformers/llamacpp 后端，提前预热安装对应依赖（可选）
if [ -n "${VULN_SCANNER_BACKEND:-}" ]; then
    if [ "$VULN_SCANNER_BACKEND" = "transformers" ]; then
        python3 -m app.launcher.dependency_installer transformers || true
    elif [ "$VULN_SCANNER_BACKEND" = "llamacpp" ]; then
        python3 -m app.launcher.dependency_installer llamacpp || true
    fi
fi

python3 -m app.launcher.bootstrap
