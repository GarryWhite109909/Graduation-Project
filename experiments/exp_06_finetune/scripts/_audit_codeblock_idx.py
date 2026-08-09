#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""导出 ORIG 中 fix_suggestion 为完整代码块(含```围栏)的漏洞样本 idx 列表。"""
import json, re
from pathlib import Path

BASE = Path(r"experiments/exp_06_finetune/data")
ORIG = BASE / "final_train_chatml_quality_final_fix.jsonl"
DONE = Path(str(ORIG) + ".done.jsonl")
FAILED = Path(str(ORIG) + ".failed.jsonl")

_JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)
def verdict_of(assistant):
    for r in reversed(_JSON_BLOCK_RE.findall(assistant or "")):
        try: return json.loads(r)
        except Exception: continue
    return None

recs = [json.loads(l) for l in ORIG.read_text(encoding="utf-8").splitlines() if l.strip()]
codeblock_idx = []
for i, rec in enumerate(recs):
    v = verdict_of(rec["messages"][2].get("content", ""))
    if v is None or v.get("has_vulnerability") is not True:
        continue
    sug = v.get("fix_suggestion") or ""
    if "```" in sug:
        codeblock_idx.append(i)

print(f"完整代码块 fix 的 idx 数: {len(codeblock_idx)}")
print(f"idx 列表: {codeblock_idx}")

# 检查这些 idx 是否都已在 DONE 中
if DONE.exists():
    done_idx = {json.loads(l).get("idx") for l in DONE.read_text(encoding="utf-8").splitlines() if l.strip()}
    in_done = [i for i in codeblock_idx if i in done_idx]
    not_in_done = [i for i in codeblock_idx if i not in done_idx]
    print(f"\n其中已在 DONE(会被跳过): {len(in_done)}")
    print(f"其中不在 DONE(可重跑): {len(not_in_done)} -> {not_in_done[:20]}")

# 检查这些 idx 是否在 FAILED
if FAILED.exists():
    failed_idx = {json.loads(l).get("idx") for l in FAILED.read_text(encoding="utf-8").splitlines() if l.strip()}
    in_failed = [i for i in codeblock_idx if i in failed_idx]
    print(f"\n其中在 FAILED: {len(in_failed)} -> {in_failed}")

# 保存列表
out = BASE / "_codeblock_fix_idx.json"
out.write_text(json.dumps(codeblock_idx, ensure_ascii=False), encoding="utf-8")
print(f"\n已保存到: {out}")