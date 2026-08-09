#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""输出 idx 0,1 完整样本，确认 fix_suggestion 到底是完整代码块还是 line N"""
import json, re
from pathlib import Path

BASE = Path(r"experiments/exp_06_finetune/data")
SRC = BASE / "final_train_chatml_v3.jsonl"
recs = [json.loads(l) for l in SRC.read_text(encoding="utf-8").splitlines() if l.strip()]

for idx in [0, 1]:
    rec = recs[idx]
    print("="*70)
    print(f"样本 idx={idx}")
    asst = rec["messages"][2]["content"]
    # 提取 JSON verdict
    m = re.search(r"```json\s*(\{.*?\})\s*```", asst, re.DOTALL)
    if m:
        try:
            v = json.loads(m.group(1))
            print("verdict fix_suggestion:")
            print(v.get("fix_suggestion", "<无>"))
            print("\n其余 verdict 字段:")
            for k in v:
                if k != "fix_suggestion":
                    print(f"  {k}: {str(v[k])[:120]}")
        except Exception as e:
            print("JSON 解析失败:", e)
    print("\n--- assistant 全文最后 400 字 ---")
    print(asst[-400:])