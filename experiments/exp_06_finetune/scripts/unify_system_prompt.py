#!/usr/bin/env python3
"""统一所有训练数据的 system prompt 为 BASE_PROMPT。

exp_05 消融实验确定 BASE_PROMPT（482 字符）为最优 system prompt。
本脚本把所有已有训练数据的 messages[0].content 替换为 BASE_PROMPT，
其他字段（user/assistant/_meta）保持不变。

用法:
    python unify_system_prompt.py           # 统一所有文件（输出 _unified.jsonl）
    python unify_system_prompt.py --inplace  # 直接覆盖原文件
"""
import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import BASE_PROMPT

DATA_DIR = Path(__file__).resolve().parents[1] / "data"

# 所有训练数据文件
TRAIN_FILES = [
    "train_chatml_v9_augmented.jsonl",
    "distill_glm_cwe_cvss.jsonl",
    "distill_glm_web.jsonl",
    "distill_targeted_supplement.jsonl",
    "distill_cwe_boundary_supplement.jsonl",
    "combined_train_chatml.jsonl",
    "augmented_train_chatml.jsonl",
    "train_chatml.jsonl",
    "distill_corpus_annotated.jsonl",
    "supplement_chatml.jsonl",
]


def unify_file(fname: str, inplace: bool) -> tuple[int, int]:
    src = DATA_DIR / fname
    if not src.exists():
        return 0, 0
    dst = src if inplace else DATA_DIR / fname.replace(".jsonl", "_unified.jsonl")
    total = changed = 0
    lines_out = []
    with open(src, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            total += 1
            obj = json.loads(line)
            msgs = obj.get("messages", [])
            if msgs and msgs[0].get("role") == "system":
                old = msgs[0]["content"]
                if old != BASE_PROMPT:
                    msgs[0]["content"] = BASE_PROMPT
                    changed += 1
            lines_out.append(json.dumps(obj, ensure_ascii=False))
    with open(dst, "w", encoding="utf-8") as f:
        for line in lines_out:
            f.write(line + "\n")
    return total, changed


def main():
    parser = argparse.ArgumentParser(description="统一 system prompt 为 BASE_PROMPT")
    parser.add_argument("--inplace", action="store_true", help="直接覆盖原文件（默认输出 _unified.jsonl）")
    args = parser.parse_args()

    print(f"BASE_PROMPT 字符数: {len(BASE_PROMPT)}")
    print(f"数据目录: {DATA_DIR}\n")

    grand_total = grand_changed = 0
    for fname in TRAIN_FILES:
        total, changed = unify_file(fname, args.inplace)
        if total > 0:
            tag = "覆盖" if args.inplace else "新文件"
            print(f"  {fname:<45s} {total:>5d} 条  替换 {changed:>5d} 条  → {tag}")
            grand_total += total
            grand_changed += changed

    print(f"\n合计: {grand_total} 条  替换 {grand_changed} 条")
    print(f"未替换的 {grand_total - grand_changed} 条已经是 BASE_PROMPT")


if __name__ == "__main__":
    raise SystemExit(main())
