#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""提取 75 条失败样本的代码 + verdict，供人工逐个生成 fix_suggestion。"""
import json, re, sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1] / "data"
inp = BASE / "final_train_chatml_quality_final.jsonl"
failed = BASE / "final_train_chatml_quality_final_fix.jsonl.failed.jsonl"

_FENCE_RE = re.compile(r"```[a-zA-Z0-9_+-]*\n(.*?)```", re.DOTALL)
_JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)

def extract_code(text):
    blocks = _FENCE_RE.findall(text or "")
    return blocks[-1].strip() if blocks else None

def extract_verdict(assistant):
    for raw in reversed(_JSON_BLOCK_RE.findall(assistant or "")):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            continue
    return None

recs = [json.loads(l) for l in inp.read_text(encoding="utf-8").splitlines() if l.strip()]
fails = [json.loads(l) for l in failed.read_text(encoding="utf-8").splitlines() if l.strip()]

out = []
for f in fails:
    idx = f["idx"]
    rec = recs[idx]
    code = extract_code(rec["messages"][1].get("content", ""))
    v = extract_verdict(rec["messages"][2].get("content", ""))
    out.append({
        "idx": idx,
        "error": f["error"],
        "cwe": (v or {}).get("vulnerability_type"),
        "risk": (v or {}).get("risk_level"),
        "source": (v or {}).get("source"),
        "sink": (v or {}).get("sink"),
        "explanation": (v or {}).get("explanation"),
        "code": code,
    })

Path(BASE / "_failed_samples.json").write_text(
    json.dumps({"total": len(out), "samples": out}, ensure_ascii=False, indent=2),
    encoding="utf-8",
)
print(f"导出 {len(out)} 条 -> {BASE / '_failed_samples.json'}")