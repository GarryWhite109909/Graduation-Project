#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""核查 ORIG 各 idx 是否带 fix_distill tag，DONE 文件实际内容。"""
import json, re
from pathlib import Path

BASE = Path(r"experiments/exp_06_finetune/data")
ORIG = BASE / "final_train_chatml_quality_final_fix.jsonl"
DONE = Path(str(ORIG) + ".done.jsonl")

recs = [json.loads(l) for l in ORIG.read_text(encoding="utf-8").splitlines() if l.strip()]

# 检查 fix_distill tag 分布
tagged = [i for i, r in enumerate(recs) if "fix_distill" in r]
print(f"ORIG 带 fix_distill tag 的样本数: {len(tagged)}")
print(f"  tag idx 范围: min={min(tagged) if tagged else None}, max={max(tagged) if tagged else None}")

# idx 0-570 中带 tag 的
tagged_early = [i for i in tagged if i < 600]
print(f"  idx<600 带 tag: {len(tagged_early)}")

# DONE 文件内容
done_lines = DONE.read_text(encoding="utf-8").splitlines() if DONE.exists() else []
done_idx = set()
for l in done_lines:
    if l.strip():
        try: done_idx.add(json.loads(l).get("idx"))
        except: pass
print(f"\nDONE 文件行数: {len(done_lines)}, 唯一 idx 数: {len(done_idx)}")
print(f"  0-599 在 done 中数量: {sum(1 for i in range(600) if i in done_idx)}")
print(f"  done idx 是否连续: min={min(done_idx) if done_idx else None}, max={max(done_idx) if done_idx else None}")

# 检查 idx 0 的完整用户和分析，看是否有 fix_distill
for idx in [0]:
    r = recs[idx]
    print(f"\nidx {idx}: keys={list(r.keys())}")
    print(f"  fix_distill={r.get('fix_distill')}")
    v = None
    m = re.search(r"```json\s*(\{.*?\})\s*```", r["messages"][2]["content"], re.DOTALL)
    if m:
        try:
            v = json.loads(m.group(1))
        except: pass
    print(f"  fix_suggestion 前60字: {str(v.get('fix_suggestion',''))[:60]!r}" if v else "  verdict 解析失败")