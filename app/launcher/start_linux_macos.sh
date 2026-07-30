#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.." || exit 1
echo "Starting AI Vulnerability Scanner..."

# 首次运行自动安装依赖：检测核心 Web 层 + 分析引擎层 + tree-sitter 语言包 + 启动器硬件检测
python3 -c "import fastapi, uvicorn, pydantic, requests, tree_sitter, tree_sitter_python, tree_sitter_javascript, tree_sitter_java, tree_sitter_php, tree_sitter_typescript, chromadb, sentence_transformers, psutil" 2>/dev/null || {
    echo "[Setup] First run: installing dependencies..."
    # 使用清华 TUNA 镜像加速国内 pip 下载
    pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
    pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .
    echo "[Setup] Dependencies installed."
}

python3 -m app.launcher.bootstrap
