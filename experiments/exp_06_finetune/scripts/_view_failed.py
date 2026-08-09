#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""查看重蒸馏失败/残留的完整代码块 fix 样本（idx 157,413,566 及任何残留）。"""
import json, re
from pathlib import Path

BASE = Path(r"experiments/exp_06_finetune/data")
ORIG = BASE / "final_train_chatml_quality_final_fix.jsonl"
recs = [json.loads(l) for l in ORIG.read_text(encoding="utf-8").splitlines() if l.strip()]

_JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)
_FENCE_RE = re.compile(r"```[a-zA-Z0-9_+-]*\n(.*?)```", re.DOTALL)

def verdict_of(a):
    for r in reversed(_JSON_BLOCK_RE.findall(a or "")):
        try: return json.loads(r)
        except Exception: continue
    return None

# 所有残留完整代码块 fix
residual = []
for i, rec in enumerate(recs):
    v = verdict_of(rec["messages"][2].get("content", ""))
    if v and v.get("has_vulnerability") is True and "```" in (v.get("fix_suggestion") or ""):
        residual.append(i)
print(f"残留完整代码块 fix 的 idx: {residual}")

for idx in residual[:5]:
    rec = recs[idx]
    code = _FENCE_RE.findall(rec["messages"][1].get("content", ""))
    code = code[-1].strip() if code else ""
    v = verdict_of(rec["messages"][2].get("content", ""))
    print(f"\n{'='*70}\nidx={idx} | CWE={v.get('vulnerability_type')} | risk={v.get('risk_level')}")
    print("source:", v.get("source"))
    print("sink:", v.get("sink"))
    print("expl:", str(v.get("explanation"))[:200])
    print("\nCODE (带行号):")
    for n, line in enumerate(code.split("\n"), 1):
        print(f"{n:>3}| {line}")