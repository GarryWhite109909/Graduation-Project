#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.." || exit 1
echo "Starting AI Vulnerability Scanner..."

# 首次运行自动安装依赖
python3 -c "import fastapi, uvicorn" 2>/dev/null || {
    echo "[Setup] First run: installing dependencies..."
    pip3 install -r requirements.txt
    pip3 install -e .
    echo "[Setup] Dependencies installed."
}

python3 -m app.launcher.bootstrap
