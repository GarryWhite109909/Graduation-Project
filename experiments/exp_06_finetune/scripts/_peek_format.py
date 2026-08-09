#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""查看前2条样本的 ChatML 结构。"""
import json
from pathlib import Path

import json
from pathlib import Path

recs = [json.loads(l) for l in Path(
    r"experiments/exp_06_finetune/data/final_train_chatml_quality_final_fix.jsonl"
).read_text(encoding="utf-8").splitlines() if l.strip()]

for i in range(2):
    r = recs[i]
    print(f"\n{'='*60}")
    print(f"样本 {i} | keys: {list(r.keys())}")
    for j, m in enumerate(r["messages"]):
        print(f"\n--- messages[{j}] role={m['role']} ---")
        print(m["content"][:600])