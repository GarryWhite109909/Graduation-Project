#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""核查：ORIG 源文件 idx0-456 的 fix_suggestion 是否完整代码块，蒸馏 done/failed 是否覆盖它们。"""
import json, re
from pathlib import Path

BASE = Path(r"experiments/exp_06_finetune/data")
ORIG = BASE / "final_train_chatml_quality_final_fix.jsonl"
RAW  = BASE / "final_train_chatml_quality_final.jsonl"
DONE = Path(str(ORIG) + ".done.jsonl")
FAILED = Path(str(ORIG) + ".failed.jsonl")

_JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)
def verdict_of(assistant):
    for r in reversed(_JSON_BLOCK_RE.findall(assistant or "")):
        try: return json.loads(r)
        except Exception: continue
    return None

recs = [json.loads(l) for l in ORIG.read_text(encoding="utf-8").splitlines() if l.strip()]
print(f"ORIG 总条数: {len(recs)}")

# 统计 ORIG 中漏洞样本的 fix_suggestion 格式
n_vuln = 0
n_codeblock = 0
n_linen = 0
codeblock_idx = []
for i, rec in enumerate(recs):
    v = verdict_of(rec["messages"][2].get("content", ""))
    if v is None or v.get("has_vulnerability") is not True:
        continue
    n_vuln += 1
    sug = v.get("fix_suggestion") or ""
    if "```" in sug:
        n_codeblock += 1
        codeblock_idx.append(i)
    elif re.search(r"line\s*\d+", sug, re.I):
        n_linen += 1
print(f"ORIG 漏洞样本: {n_vuln} | 完整代码块fix: {n_codeblock} | line N 形式fix: {n_linen}")
print(f"完整代码块 idx 范围: min={min(codeblock_idx) if codeblock_idx else None}, max={max(codeblock_idx) if codeblock_idx else None}, count={len(codeblock_idx)}")

# 检查 done / failed 是否覆盖 idx0-456
if DONE.exists():
    done_idx = {json.loads(l).get("idx") for l in DONE.read_text(encoding="utf-8").splitlines() if l.strip()}
    print(f"\nDONE 文件: {len(done_idx)} 条")
    missing = [i for i in range(0, 500) if i in done_idx]
    print(f"  idx 0-499 中已 done 的数量: {len(missing)}")
else:
    print(f"\nDONE 文件不存在: {DONE}")
if FAILED.exists():
    failed_idx = [json.loads(l).get("idx") for l in FAILED.read_text(encoding="utf-8").splitlines() if l.strip()]
    print(f"FAILED 文件: {len(failed_idx)} 条")
    print(f"  idx 0-499 中 failed: {[i for i in failed_idx if i < 500]}")
else:
    print(f"FAILED 文件不存在: {FAILED}")

# RAW 是否存在？对比
if RAW.exists():
    raw_recs = [json.loads(l) for l in RAW.read_text(encoding="utf-8").splitlines() if l.strip()]
    print(f"\nRAW(final_train_chatml_quality_final.jsonl) 总条数: {len(raw_recs)}")
    v0 = verdict_of(raw_recs[0]["messages"][2].get("content", "")) if raw_recs else None
    print(f"  RAW idx0 fix_suggestion 前100字: {(v0 or {}).get('fix_suggestion','<无>')[:100]!r}")