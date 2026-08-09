#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把训练数据的 system prompt 统一替换为 v9max 消融最佳 prompt（combined）。

combined = SYSTEM_PROMPT 尾部替换为 CoT 步骤 + few-shot 示例（见 prompts.py
_build_combined_prompt）。evaluate.py 已默认 combined，训练数据同用以保证
训练/推理一致，避免 format shift。

用法:
  python _replace_sysprompt.py --in <file> --out <file> [--inplace]
"""
import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import build_system_prompt_variant

COMBINED = build_system_prompt_variant("combined")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    src = Path(args.inp)
    dst = Path(args.out)
    recs = [json.loads(l) for l in src.read_text(encoding="utf-8").splitlines() if l.strip()]
    changed = 0
    for rec in recs:
        msgs = rec.get("messages", [])
        if msgs and msgs[0].get("role") == "system":
            if msgs[0]["content"] != COMBINED:
                msgs[0]["content"] = COMBINED
                changed += 1
    with dst.open("w", encoding="utf-8") as f:
        for rec in recs:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"读取 {src.name}: {len(recs)} 条 | 替换 system prompt: {changed} 条")
    print(f"替换为 combined ({len(COMBINED)} 字符)")
    print(f"输出: {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())