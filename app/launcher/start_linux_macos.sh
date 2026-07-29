#!/usr/bin/env bash
cd "$(dirname "$0")/.." || exit 1
echo "Starting AI Vulnerability Scanner..."
python3 -m app.launcher.bootstrap
