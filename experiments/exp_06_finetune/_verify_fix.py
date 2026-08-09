#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证 fix 蒸馏输出：统计改写/保留/失败情况，抽查格式。"""
import json, re, sys

FIX_FILE = r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\final_train_chatml_quality_final_fix.jsonl"
ORIG_FILE = r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\final_train_chatml_quality_final.jsonl"
pat = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)

def load(path):
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]

def get_verdict(msgs):
    m = pat.search((msgs[2].get("content","") if len(msgs) > 2 else ""))
    return json.loads(m.group(1)) if m else None

orig = load(ORIG_FILE)
fix = load(FIX_FILE)
print(f"原文件 {len(orig)} 条 | 蒸馏后 {len(fix)} 条")

# 对比哪些漏洞样本的 fix_suggestion 被改写
changed = 0
unchanged_vuln = 0
safe_kept = 0
for o, f in zip(orig, fix):
    ov = get_verdict(o.get("messages", []))
    fv = get_verdict(f.get("messages", []))
    if not ov or not fv:
        continue
    o_sug = ov.get("fix_suggestion", "")
    f_sug = fv.get("fix_suggestion", "")
    if ov.get("has_vulnerability") is True:
        if f_sug != o_sug:
            changed += 1
        else:
            unchanged_vuln += 1
    else:
        safe_kept += 1

print(f"漏洞样本 fix_suggestion 已改写: {changed} | 未改写(失败保留): {unchanged_vuln} | 安全样本保留: {safe_kept}")

# 校验改写的建议格式：都是 line N: 开头
bad_format = 0
no_fix_vuln = 0
for f in fix:
    fv = get_verdict(f.get("messages", []))
    if not fv or fv.get("has_vulnerability") is not True:
        continue
    sug = fv.get("fix_suggestion", "")
    if not sug or sug.lower() == "no fix needed":
        no_fix_vuln += 1
    if not re.match(r"^(line\s*\d+|第\s*\d+\s*行)", sug, re.IGNORECASE):
        bad_format += 1
print(f"漏洞样本无建议/错误: {no_fix_vuln} | 非 line 开头格式: {bad_format}")

# 抽查 3 条改写后的样本
print("\n=== 抽查改写后的 fix_suggestion ===")
count = 0
for f in fix:
    fv = get_verdict(f.get("messages", []))
    if not fv or fv.get("has_vulnerability") is not True:
        continue
    sug = fv.get("fix_suggestion", "")
    if re.match(r"^(line\s*\d+|第\s*\d+\s*行)", sug, re.IGNORECASE):
        print(f"  CWE={(fv.get('vulnerability_type') or '')[:25]} | {sug[:120]}")
        count += 1
        if count >= 3:
            break