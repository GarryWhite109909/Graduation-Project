#!/usr/bin/env python3
"""修复剩余 476 条不规范的 vulnerability_type。

两种问题：
1. "CWE-798: Use of Hard-coded Credentials" → "CWE-798 Hardcoded Credentials"
2. "CWE-798" → "CWE-798 Hardcoded Credentials"
"""
import json
import re
import sys
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
INPUT_FILE = DATA_DIR / "final_train_chatml_v2.jsonl"
OUTPUT_FILE = DATA_DIR / "final_train_chatml_v3.jsonl"

# CWE 编号 → 标准英文名
CWE_NAMES = {
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "XSS",
    "CWE-88": "Argument Injection",
    "CWE-89": "SQL Injection",
    "CWE-90": "LDAP Injection",
    "CWE-93": "Email Header Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Code Injection",
    "CWE-117": "Log Injection",
    "CWE-120": "Buffer Overflow",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-134": "Format String",
    "CWE-190": "Integer Overflow",
    "CWE-208": "Observable Timing Discrepancy",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication",
    "CWE-326": "Weak Cryptographic Algorithm",
    "CWE-327": "Weak Cryptographic Algorithm",
    "CWE-329": "Hardcoded IV",
    "CWE-330": "Weak Random Number",
    "CWE-347": "JWT Signature Verification",
    "CWE-352": "CSRF",
    "CWE-362": "Race Condition",
    "CWE-384": "Session Fixation",
    "CWE-401": "Memory Leak",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-441": "Untrusted Search Path",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity",
    "CWE-639": "IDOR",
    "CWE-643": "XPath Injection",
    "CWE-732": "Insecure File Permissions",
    "CWE-749": "OS Command Injection",
    "CWE-759": "Improper Restriction of Operations",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Hardcoded Credentials",
    "CWE-843": "Type Confusion",
    "CWE-862": "Missing Authorization",
    "CWE-912": "Backdoor",
    "CWE-915": "Mass Assignment",
    "CWE-917": "Expression Language Injection",
    "CWE-918": "SSRF",
    "CWE-943": "NoSQL Injection",
    "CWE-1188": "Insecure Default Permissions",
    "CWE-1321": "Prototype Pollution",
    "CWE-1336": "SSTI",
}


def normalize_vt(vt: str) -> str:
    """归一化 vulnerability_type。"""
    if not vt or vt == "none":
        return vt
    # 格式1: "CWE-XXX: Name" → "CWE-XXX Name"
    match = re.match(r"^(CWE-\d+)\s*:\s*(.+?)(?:\s*\(.*\))?$", vt)
    if match:
        cwe_id = match.group(1)
        name = match.group(2).strip()
        # 用标准名称替换
        if cwe_id in CWE_NAMES:
            return f"{cwe_id} {CWE_NAMES[cwe_id]}"
        return f"{cwe_id} {name}"
    # 格式2: "CWE-XXX" (无名称) → "CWE-XXX StandardName"
    match = re.match(r"^(CWE-\d+)$", vt)
    if match:
        cwe_id = match.group(1)
        if cwe_id in CWE_NAMES:
            return f"{cwe_id} {CWE_NAMES[cwe_id]}"
        return vt  # 未知 CWE，保留原值
    # 格式3: 已经是 "CWE-XXX Name" 但名称需要标准化
    match = re.match(r"^(CWE-\d+)\s+(.+?)(?:\s*\(.*\))?$", vt)
    if match:
        cwe_id = match.group(1)
        if cwe_id in CWE_NAMES:
            return f"{cwe_id} {CWE_NAMES[cwe_id]}"
        return vt
    return vt


def main():
    print("修复剩余不规范的 vulnerability_type...")
    samples = []
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            samples.append(json.loads(line))
    print(f"读取: {len(samples)} 条")

    fixed = 0
    for obj in samples:
        for m in obj["messages"]:
            if m["role"] != "assistant":
                continue
            json_match = re.search(r"```json\s*(\{.*?\})\s*```", m["content"], re.DOTALL)
            if not json_match:
                continue
            try:
                verdict = json.loads(json_match.group(1))
            except:
                continue
            if verdict.get("has_vulnerability") is not True:
                continue
            old_vt = verdict.get("vulnerability_type", "")
            if not old_vt or old_vt == "none":
                continue
            new_vt = normalize_vt(old_vt)
            if new_vt != old_vt:
                verdict["vulnerability_type"] = new_vt
                fixed += 1
                # 写回
                new_json = json.dumps(verdict, ensure_ascii=False)
                m["content"] = m["content"][:json_match.start(1)] + new_json + m["content"][json_match.end(1):]

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for obj in samples:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    print(f"修复: {fixed} 条")
    print(f"输出: {OUTPUT_FILE}")

    # 验证
    bad = 0
    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            obj = json.loads(line)
            for m in obj["messages"]:
                if m["role"] != "assistant":
                    continue
                json_match = re.search(r"```json\s*(\{.*?\})\s*```", m["content"], re.DOTALL)
                if not json_match:
                    continue
                try:
                    v = json.loads(json_match.group(1))
                except:
                    continue
                if v.get("has_vulnerability") is True:
                    vt = v.get("vulnerability_type", "")
                    if vt and vt != "none" and not re.match(r"^CWE-\d+\s+\S", vt):
                        bad += 1
    print(f"剩余不规范: {bad} 条")


if __name__ == "__main__":
    raise SystemExit(main())
