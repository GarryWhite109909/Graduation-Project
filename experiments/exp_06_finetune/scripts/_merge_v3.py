#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""合并原始训练集 + 所有补充样本 → 最终训练集 v3，并统计 CWE 分布。"""
import json, re, collections
from pathlib import Path

BASE = Path(r"experiments/exp_06_finetune/data")
ORIG = BASE / "final_train_chatml_quality_final_fix.jsonl"
SUP1 = BASE / "supplement_samples.jsonl"       # 量级补充 654条
SUP2 = BASE / "supplement_ssti_auth.jsonl"      # SSTI/授权 75条
SUP3 = BASE / "supplement_mode_a.jsonl"         # 多候选主漏洞 60条
SUP4 = BASE / "supplement_mode_b.jsonl"         # 细粒度边界对 50条
SUP5 = BASE / "supplement_mode_d.jsonl"         # Spring/OGNL/SpEL 45条
OUT  = BASE / "final_train_chatml_v3.jsonl"

_JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)

def verdict(a):
    for r in reversed(_JSON_BLOCK_RE.findall(a or "")):
        try:
            return json.loads(r)
        except json.JSONDecodeError:
            continue
    return None

def extract_cwe(v):
    s = (v or {}).get("vulnerability_type", "") or ""
    m = re.search(r"CWE[-\s]?(\d+)", s, re.IGNORECASE)
    return f"CWE-{m.group(1)}" if m else s

def load(path):
    if not path.exists():
        print(f"  [WARN] 文件不存在: {path.name}")
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]

orig = load(ORIG)
sup1 = load(SUP1)
sup2 = load(SUP2)
sup3 = load(SUP3)
sup4 = load(SUP4)
sup5 = load(SUP5)

merged = orig + sup1 + sup2 + sup3 + sup4 + sup5
print(f"原始: {len(orig)}")
print(f"量级补充: {len(sup1)}")
print(f"SSTI/授权: {len(sup2)}")
print(f"模式A(多候选): {len(sup3)}")
print(f"模式B(边界对): {len(sup4)}")
print(f"模式D(CVE语料): {len(sup5)}")
print(f"合并后: {len(merged)}")

# 写入合并文件
with OUT.open("w", encoding="utf-8") as f:
    for rec in merged:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

# 统计
safe = vuln = 0
cwe_counts = collections.Counter()
for rec in merged:
    msgs = rec.get("messages", [])
    if len(msgs) < 3:
        continue
    v = verdict(msgs[2].get("content", ""))
    if not v:
        continue
    if v.get("has_vulnerability") is True:
        vuln += 1
        cwe_counts[extract_cwe(v)] += 1
    else:
        safe += 1

print(f"\n合并后: 总样本 {len(merged)} | 漏洞 {vuln} | 安全 {safe}")
print(f"\n{'CWE':<45} {'数量':>6} {'占比':>8}")
print("-" * 62)
low_count = 0
for cwe, cnt in cwe_counts.most_common():
    pct = cnt / vuln * 100
    flag = " ← 偏低" if cnt < 30 else ""
    if cnt < 30:
        low_count += 1
    print(f"{cwe:<45} {cnt:>6} {pct:>7.1f}%{flag}")

print(f"\n共 {len(cwe_counts)} 种 CWE | 偏低（<30条）: {low_count} 种")
print(f"\n输出: {OUT}")