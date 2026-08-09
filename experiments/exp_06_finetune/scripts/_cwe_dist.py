#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""统计训练数据 CWE 分布，按数量排序，标记量级失衡方向。"""
import json, re, collections
from pathlib import Path

BASE = Path(r"experiments/exp_06_finetune/data")
_JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)

def verdict(a):
    for r in reversed(_JSON_BLOCK_RE.findall(a or "")):
        try:
            return json.loads(r)
        except json.JSONDecodeError:
            continue
    return None

def extract_cwe(v):
    """从 vulnerability_type 提取 CWE 编号。"""
    s = (v or {}).get("vulnerability_type", "") or ""
    m = re.search(r"CWE[-\s]?(\d+)", s, re.IGNORECASE)
    return f"CWE-{m.group(1)}" if m else s

recs = [json.loads(l) for l in (BASE / "final_train_chatml_quality_final_fix.jsonl")
        .read_text(encoding="utf-8").splitlines() if l.strip()]

safe = vuln = 0
cwe_counts = collections.Counter()
for rec in recs:
    v = verdict(rec["messages"][2].get("content", "")) if len(rec.get("messages", [])) >= 3 else None
    if not v:
        continue
    if v.get("has_vulnerability") is True:
        vuln += 1
        cwe = extract_cwe(v)
        cwe_counts[cwe] += 1
    else:
        safe += 1

print(f"总样本: {len(recs)} | 漏洞: {vuln} | 安全: {safe}\n")
print(f"{'CWE':<20} {'数量':>6} {'占比':>8}")
print("-" * 36)
for cwe, cnt in cwe_counts.most_common():
    pct = cnt / vuln * 100
    flag = " ← 量级偏低" if cnt < 30 else ""
    print(f"{cwe:<20} {cnt:>6} {pct:>7.1f}%{flag}")

print(f"\n共 {len(cwe_counts)} 种 CWE")
low = {c: n for c, n in cwe_counts.items() if n < 30}
print(f"量级偏低（<30条）: {len(low)} 种 → {', '.join(sorted(low.keys()))}")