#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""巡检 final_train_chatml_v3.jsonl：
1) 全库去重（按 user 代码去重 / 按整条 messages 去重 / 按代码块哈希去重）
2) fix_suggestion 落位排查（最小局部改正：必须有 line N 且 N 在代码行数范围内、
   无换行围栏、长度<=500）
3) system prompt 统一度（当前是否为 BASE_PROMPT）
4) assistant 是否含 JSON verdict、CWE 覆盖
"""
import json, re, collections, hashlib
from pathlib import Path

BASE = Path(r"experiments/exp_06_finetune/data")
SRC = BASE / "final_train_chatml_v3.jsonl"

recs = [json.loads(l) for l in SRC.read_text(encoding="utf-8").splitlines() if l.strip()]
print(f"总样本: {len(recs)}")

_JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)
_FENCE_RE = re.compile(r"```[a-zA-Z0-9_+-]*\n(.*?)```", re.DOTALL)
_REF_RE = re.compile(r"line\s*(\d+)", re.IGNORECASE)

def code_of(rec):
    b = _FENCE_RE.findall(rec["messages"][1].get("content", "") or "")
    return b[-1].strip() if b else None

def verdict_of(rec):
    a = rec["messages"][2].get("content", "") or ""
    for r in reversed(_JSON_BLOCK_RE.findall(a)):
        try:
            return json.loads(r)
        except json.JSONDecodeError:
            continue
    return None

# ---------- 1) 去重 ----------
print("\n=== 去重 ===")
code_hash = collections.Counter()
full_hash = collections.Counter()
for rec in recs:
    c = code_of(rec) or ""
    code_hash[hashlib.md5(c.encode()).hexdigest()] += 1
    full_hash[hashlib.md5(json.dumps(rec, ensure_ascii=False).encode()).hexdigest()] += 1
dup_code = sum(1 for v in code_hash.values() if v > 1)
dup_full = sum(1 for v in full_hash.values() if v > 1)
print(f"唯一代码块: {len(code_hash)} | 重复代码块数(去重后保留的重复源): {dup_code} | 涉及样本: {len(recs)-len(code_hash)}")
print(f"唯一完整样本: {len(full_hash)} | 完全重复样本: {len(recs)-len(full_hash)}")

# 展示重复代码的样本（按出现的重复次数降序，最多展示 5 组）
print("\n重复代码块示例（>1 次）:")
seen = set()
cnt = 0
for rec in recs:
    c = code_of(rec) or ""
    h = hashlib.md5(c.encode()).hexdigest()
    if code_hash[h] > 1 and h not in seen:
        seen.add(h)
        langs = []
        for r2 in recs:
            if hashlib.md5((code_of(r2) or "").encode()).hexdigest() == h:
                vt = (verdict_of(r2) or {}).get("vulnerability_type", "?")
                langs.append(vt.split()[-1] if vt else "?")
        first_line = c.splitlines()[0][:50] if c else "<空>"
        print(f"  x{code_hash[h]} | 首行: {first_line!r} | verdict类型: {collections.Counter(langs)}")
        cnt += 1
        if cnt >= 5:
            break

# ---------- 2) system prompt 统一度 ----------
print("\n=== system prompt ===")
sys_counter = collections.Counter()
for rec in recs:
    sys_counter[rec["messages"][0]["content"][:60]] += 1
for k, v in sys_counter.most_common(10):
    print(f"  [{v}条] {k!r}...")

# ---------- 3) fix_suggestion 落位 ----------
print("\n=== fix_suggestion 落位排查 ===")
n_vuln = 0
n_sug = 0
n_without_line = 0
n_out_of_range = 0
n_multiline = 0
n_too_long = 0
n_no_verdict = 0
n_verdict_no_vuln = 0
out_of_range_examples = []
for rec in recs:
    v = verdict_of(rec)
    if v is None:
        n_no_verdict += 1
        continue
    if v.get("has_vulnerability") is not True:
        n_verdict_no_vuln += 1
        continue
    n_vuln += 1
    sug = v.get("fix_suggestion") or ""
    if not sug:
        continue
    n_sug += 1
    c = code_of(rec) or ""
    total = len(c.split("\n"))
    refs = [int(x) for x in _REF_RE.findall(sug)]
    if not refs:
        n_without_line += 1
    if any(nx < 1 or nx > total for nx in refs):
        n_out_of_range += 1
        if len(out_of_range_examples) < 5:
            out_of_range_examples.append((sug, total, c.splitlines()[0][:40] if c else ""))
    if "\n" in sug or "```" in sug:
        n_multiline += 1
    if len(sug) > 500:
        n_too_long += 1
print(f"漏洞样本: {n_vuln}")
print(f"  → 无verdict: {n_no_verdict} | verdict标false: {n_verdict_no_vuln}")
print(f"  → 有fix_suggestion: {n_sug}/{n_vuln}")
print(f"  → 无行号: {n_without_line} | 行号越界: {n_out_of_range} | 含换行/围栏: {n_multiline} | 超长>500: {n_too_long}")
for sug, total, first in out_of_range_examples:
    print(f"  ⚠️ 越界示例 (code行数={total}, 首行={first!r}): {sug[:120]}")

# ---------- 4) CWE 分布 ----------
print("\n=== CWE 分布（漏洞样本）===")
cwe_counts = collections.Counter()
for rec in recs:
    v = verdict_of(rec)
    if v is None or v.get("has_vulnerability") is not True:
        continue
    s = v.get("vulnerability_type", "") or ""
    m = re.search(r"CWE[\s-]?(\d+)", s, re.IGNORECASE)
    cwe_counts[f"CWE-{m.group(1)}" if m else s] += 1
print(f"唯一 CWE 数: {len(cwe_counts)}")
low = {k: v for k, v in cwe_counts.items() if v < 30}
print(f"偏低(<30): {low if low else '无'}")