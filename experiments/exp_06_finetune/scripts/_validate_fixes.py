#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""校验 75 条手动改写建议的格式合规性。"""
import json, re
from pathlib import Path

BASE = Path(r"experiments/exp_06_finetune/data")
_FENCE_RE = re.compile(r"```[a-zA-Z0-9_+-]*\n(.*?)```", re.DOTALL)
_JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)
_REF_RE = re.compile(r"line\s*(\d+)", re.IGNORECASE)

def code(t):
    b = _FENCE_RE.findall(t or "")
    return b[-1].strip() if b else None

def verdict(a):
    for r in reversed(_JSON_BLOCK_RE.findall(a or "")):
        try:
            return json.loads(r)
        except json.JSONDecodeError:
            continue
    return None

recs = [json.loads(l) for l in (BASE / "final_train_chatml_quality_final_fix.jsonl")
        .read_text(encoding="utf-8").splitlines() if l.strip()]
failed = [json.loads(l) for l in (BASE / "final_train_chatml_quality_final_fix.jsonl.failed.jsonl")
          .read_text(encoding="utf-8").splitlines() if l.strip()]

bad = 0
n = 0
for f in failed:
    idx = f["idx"]
    rec = recs[idx]
    c = code(rec["messages"][1].get("content", "")) or ""
    v = verdict(rec["messages"][2].get("content", ""))
    sug = (v or {}).get("fix_suggestion", "")
    total = len(c.split("\n"))
    refs = [int(x) for x in _REF_RE.findall(sug)]
    issues = []
    if not sug:
        issues.append("空建议")
    if "\n" in sug or "```" in sug:
        issues.append("含换行/围栏")
    if len(sug) > 500:
        issues.append(f"超长{len(sug)}")
    if not refs:
        issues.append("无行号")
    if any(nx < 1 or nx > total for nx in refs):
        issues.append(f"越界{refs} total{total} first={c.splitlines()[0][:40]!r}" if c else f"越界{refs} no-code")
    if issues:
        bad += 1
        print(f"idx {idx}: {'; '.join(issues)}")
    n += 1
print(f"校验 {n} 条 | 不合规 {bad}")