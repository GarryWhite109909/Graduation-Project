#!/usr/bin/env python3
"""
模型下载脚本 —— 支持两种获取方式：

1. Ollama Registry（默认，最简单）
   python tools/download_model.py --source ollama --model graduation-vuln-scanner:v7

2. 直接下载 GGUF（适合无法访问 Ollama Registry 的环境）
   python tools/download_model.py \
       --source gguf \
       --url https://github.com/GarryWhite109909/Graduation-Project/releases/download/v1.0/merged_v7-q4_k_m.gguf \
       --model graduation-vuln-scanner:v7

8GB 显存用户：脚本默认使用 Q4_K_M 量化 + num_ctx=8192，可在 Modelfile 中再调低。
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.request import urlopen

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def run(cmd: list[str], **kwargs) -> int:
    print("$ " + " ".join(cmd))
    return subprocess.run(cmd, **kwargs).returncode


def download_gguf(url: str, out_path: Path) -> None:
    print(f"[下载] {url} -> {out_path}")
    with urlopen(url) as resp, open(out_path, "wb") as f:
        total = int(resp.headers.get("content-length", 0))
        downloaded = 0
        chunk_size = 1024 * 1024
        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            f.write(chunk)
            downloaded += len(chunk)
            if total:
                pct = downloaded / total * 100
                print(f"  {downloaded / 1e6:.1f}MB / {total / 1e6:.1f}MB ({pct:.1f}%)", end="\r")
    print()


def create_modelfile(gguf_path: Path, model_name: str) -> Path:
    modelfile = PROJECT_ROOT / f"outputs/Modelfile_{model_name.replace(':', '_')}"
    modelfile.parent.mkdir(parents=True, exist_ok=True)
    content = (
        f"FROM {gguf_path}\n\n"
        "# Qwen3 chat template（与训练时一致）\n"
        'TEMPLATE """{{- if .System }}<|im_start|>system\n'
        "{{ .System }}<|im_end|>\n"
        "{{- end }}<|im_start|>user\n"
        "{{ .Prompt }}<|im_end|>\n"
        "<|im_start|>assistant\n"
        '"""\n\n'
        'SYSTEM """你是一名资深的代码安全审计专家。请对给出的代码片段进行安全分析，判断其中是否存在安全漏洞。"""\n\n'
        "# 8GB 显存适配：Q4_K_M 约 4.7GB，num_ctx 8192 留足 activations 余量\n"
        "PARAMETER temperature 0.1\n"
        "PARAMETER num_ctx 8192\n"
        "PARAMETER num_predict 2048\n"
        'PARAMETER stop "<|im_end|>"\n'
        'PARAMETER stop "<|endoftext|>"\n'
    )
    modelfile.write_text(content, encoding="utf-8")
    return modelfile


def pull_ollama(model: str) -> int:
    if shutil.which("ollama") is None:
        print("[ERROR] 未找到 ollama 命令。请先安装：https://ollama.com/download")
        return 1
    return run(["ollama", "pull", model])


def create_from_gguf(url: str, model: str) -> int:
    if shutil.which("ollama") is None:
        print("[ERROR] 未找到 ollama 命令。请先安装：https://ollama.com/download")
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        gguf_path = Path(tmp) / "model.gguf"
        download_gguf(url, gguf_path)
        modelfile = create_modelfile(gguf_path, model)
        print(f"[创建] ollama create {model} -f {modelfile}")
        return run(["ollama", "create", model, "-f", str(modelfile)])


def main() -> int:
    parser = argparse.ArgumentParser(description="下载并安装漏洞扫描模型")
    parser.add_argument(
        "--source",
        choices=["ollama", "gguf"],
        default="ollama",
        help="模型来源：ollama registry 或直接下载 GGUF",
    )
    parser.add_argument("--model", default="graduation-vuln-scanner:v7", help="本地 Ollama 模型名")
    parser.add_argument("--url", help="GGUF 下载地址（source=gguf 时必填）")
    args = parser.parse_args()

    if args.source == "ollama":
        return pull_ollama(args.model)
    else:
        if not args.url:
            print("[ERROR] source=gguf 时必须指定 --url")
            return 1
        return create_from_gguf(args.url, args.model)


if __name__ == "__main__":
    sys.exit(main())
