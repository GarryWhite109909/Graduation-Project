#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 supplement_low_cwe.jsonl 合并进 v3，并统一 system prompt 为 combined。

说明：新样本由模板脚本生成，system prompt 仍是 BASE 风格；合并后必须统一
替换为 v9max 消融最优 combined prompt，保证全数据集训练/推理一致。
"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))
from graduation_project.prompts import build_system_prompt_variant

COMBINED = build_system_prompt_variant("combined")
BASE = PROJECT_ROOT / "experiments" / "exp_06_finetune" / "data"
V3 = BASE / "final_train_chatml_v3.jsonl"
SUP = BASE / "supplement_low_cwe.jsonl"


def load(p):
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


v3 = load(V3)
sup = load(SUP)
before = len(v3)
v3 += sup  # 追加补充样本

# 统一替换 system prompt 为 combined
changed = 0
for rec in v3:
    msgs = rec.get("messages", [])
    if msgs and msgs[0].get("role") == "system" and msgs[0].get("content") != COMBINED:
        msgs[0]["content"] = COMBINED
        changed += 1

with V3.open("w", encoding="utf-8") as f:
    for rec in v3:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

print(f"合并前: {before} | 补充: {len(sup)} | 合并后: {len(v3)}")
print(f"system prompt 替换为 combined: {changed} 条")
print(f"输出: {V3}")