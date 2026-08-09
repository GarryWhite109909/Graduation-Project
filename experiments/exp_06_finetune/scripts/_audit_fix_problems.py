#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""查看 fix_suggestion 异常样本的具体内容与来源分布。"""
import json, re, collections, hashlib
from pathlib import Path

BASE = Path(r"experiments/exp_06_finetune/data")
SRC = BASE / "final_train_chatml_v3.jsonl"

recs = [json.loads(l) for l in SRC.read_text(encoding="utf-8").splitlines() if l.strip()]

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

# 找出异常样本：无行号 / 含换行围栏 / 超长
problems = []
for i, rec in enumerate(recs):
    v = verdict_of(rec)
    if v is None or v.get("has_vulnerability") is not True:
        continue
    sug = v.get("fix_suggestion") or ""
    if not sug:
        continue
    c = code_of(rec) or ""
    total = len(c.split("\n"))
    refs = [int(x) for x in _REF_RE.findall(sug)]
    flags = []
    if not refs:
        flags.append("无行号")
    if any(nx < 1 or nx > total for nx in refs):
        flags.append("越界")
    if "\n" in sug or "```" in sug:
        flags.append("换行/围栏")
    if len(sug) > 500:
        flags.append(f"超长{len(sug)}")
    if flags:
        problems.append((i, flags, sug, c.splitlines()[0][:40] if c else ""))

print(f"异常样本总数: {len(problems)}")
print(f"\n各异常类型组合分布:")
combo = collections.Counter()
for i, flags, sug, first in problems:
    combo["|".join(flags)] += 1
for k, v in combo.most_common():
    print(f"  {v:>4}  {k}")

# 展示前 15 个异常样本的 suggestion 原文
print(f"\n=== 异常样本 suggestion 原文（前 15 个）===")
for i, flags, sug, first in problems[:15]:
    print(f"\n[idx {i}] {flags} | code首行: {first!r}")
    print(f"  {sug[:200]}")

# 判断这些异常样本是否集中在后期的补充样本（按 idx 分布）
print(f"\n=== 异常样本 idx 分布（前30/后30）===")
idxs = [p[0] for p in problems]
print(f"  最小idx: {min(idxs)} | 最大idx: {max(idxs)} | 中位: {sorted(idxs)[len(idxs)//2]}")
print(f"  idx<7692(原始集) 的异常数: {sum(1 for x in idxs if x < 7692)}")
print(f"  idx>=7692(补充集) 的异常数: {sum(1 for x in idxs if x >= 7692)}")