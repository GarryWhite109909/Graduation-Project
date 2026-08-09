#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""质量抽查：抽取代表性样本，展示完整 user 代码 + verdict，供人工审查。"""
import json, re, sys
from pathlib import Path

BASE = Path(r"experiments/exp_06_finetune/data")
_JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)
_FENCE_RE = re.compile(r"```[a-zA-Z0-9_+-]*\n(.*?)```", re.DOTALL)

def show(path, idxs):
    recs = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    print(f"\n{'#'*70}\n文件: {path.name} ({len(recs)} 条)")
    for i in idxs:
        if i >= len(recs): continue
        r = recs[i]
        code = _FENCE_RE.findall(r["messages"][1].get("content","")) 
        code = code[-1].strip() if code else ""
        m = _JSON_BLOCK_RE.search(r["messages"][2].get("content",""))
        v = json.loads(m.group(1)) if m else None
        print(f"\n--- [{i}] verdict: {str(v.get('has_vulnerability')) if v else '?'} | CWE: {v.get('vulnerability_type') if v else '?'} | risk: {v.get('risk_level') if v else '?'} ---")
        print("CODE:")
        print(code[:600])
        if v:
            print("SOURCE:", v.get("source"))
            print("SINK:", v.get("sink"))
            print("EXPL:", (v.get("explanation") or "")[:150])
            print("FIX:", (v.get("fix_suggestion") or "")[:200])

show(BASE/"supplement_mode_a.jsonl", [0, 1, 2])
show(BASE/"supplement_mode_b.jsonl", [0, 1])
show(BASE/"supplement_mode_d.jsonl", [0, 1, 2])
show(BASE/"supplement_ssti_auth.jsonl", [0, 1])
show(BASE/"supplement_samples.jsonl", [0, 1])