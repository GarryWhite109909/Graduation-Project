#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v9max 数据治理：归一化 vulnerability_type + 对齐 schema（去 cvss 字段）。

v9max 数据存在两类硬伤：
1. vulnerability_type 格式极度混乱（447 种不同值）：
   - 多种前缀/分隔符：`CWE-798: X` / `CWE-798 X` / `CWE-502` / `CWE-918-SSRF` / `CWE-78-OS命令注入`
   - 语言混杂：英文全名 / 中文 / 中英混合
   - 纯自然语言名（无 CWE 前缀）：`OS Command Injection` / `SQL注入` / `命令注入`
   小模型学不会 447 种标签，必须归一化到统一 `CWE-XXX 标准名` 格式。
2. 全量样本带 cvss_vector/cvss_score，但训练用 BASE_PROMPT 的 schema 不含这俩字段，
   → 训练/推理 schema 不一致，模型会学出 prompt 未要求的多余字段。需删除对齐。

用法：
  python3 fix_v9max_normalize.py --input data/distill_v2/train_chatml_v9max.jsonl \
      --output data/distill_v2/train_chatml_v9max_clean.jsonl
  python3 fix_v9max_normalize.py --dry-run   # 只报告，不写文件
"""
import argparse
import json
import re
from collections import Counter
from pathlib import Path

# CWE 编号 → 标准英文名（与 fix_vt_round2 / evaluate.extract_cwe 保持一致）
CWE_NAMES = {
    "CWE-22": "Path Traversal",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "XSS",
    "CWE-88": "Argument Injection",
    "CWE-89": "SQL Injection",
    "CWE-90": "LDAP Injection",
    "CWE-93": "Email Header Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Code Injection",
    "CWE-113": "HTTP Response Splitting",
    "CWE-117": "Log Injection",
    "CWE-120": "Buffer Overflow",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-134": "Format String",
    "CWE-190": "Integer Overflow",
    "CWE-200": "Information Disclosure",
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
    "CWE-367": "Time-of-check Time-of-use (TOCTOU)",
    "CWE-384": "Session Fixation",
    "CWE-401": "Memory Leak",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-441": "Unintended Proxy or Intermediary",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity",
    "CWE-639": "IDOR",
    "CWE-643": "XPath Injection",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-749": "Exposed Dangerous Method",
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

# 自然语言标签 → (CWE 编号, 标准名)。按匹配顺序（先长后短，避免误配）。
NATURAL_KEYWORDS = [
    ("Stack-based Buffer Overflow", "CWE-121", "Stack-based Buffer Overflow"),
    ("Heap-based Buffer Overflow", "CWE-122", "Heap-based Buffer Overflow"),
    ("Stack Overflow", "CWE-121", "Stack-based Buffer Overflow"),
    ("Heap Overflow", "CWE-122", "Heap-based Buffer Overflow"),
    ("Buffer Overflow", "CWE-120", "Buffer Overflow"),
    ("栈缓冲区溢出", "CWE-121", "Stack-based Buffer Overflow"),
    ("堆缓冲区溢出", "CWE-122", "Heap-based Buffer Overflow"),
    ("栈溢出", "CWE-121", "Stack-based Buffer Overflow"),
    ("堆溢出", "CWE-122", "Heap-based Buffer Overflow"),
    ("Out-of-bounds Write", "CWE-787", "Out-of-bounds Write"),
    ("Out-of-bounds Read", "CWE-125", "Out-of-bounds Read"),
    ("越界写", "CWE-787", "Out-of-bounds Write"),
    ("越界读", "CWE-125", "Out-of-bounds Read"),
    ("Use-After-Free", "CWE-416", "Use After Free"),
    ("Use After Free", "CWE-416", "Use After Free"),
    ("UAF", "CWE-416", "Use After Free"),
    ("Double Free", "CWE-415", "Double Free"),
    ("NULL Pointer Dereference", "CWE-476", "NULL Pointer Dereference"),
    ("Null Deref", "CWE-476", "NULL Pointer Dereference"),
    ("Integer Overflow", "CWE-190", "Integer Overflow"),
    ("Time-of-check Time-of-use", "CWE-367", "Time-of-check Time-of-use (TOCTOU)"),
    ("TOCTOU", "CWE-367", "Time-of-check Time-of-use (TOCTOU)"),
    ("Race Condition", "CWE-362", "Race Condition"),
    ("Mass Assignment", "CWE-915", "Mass Assignment"),
    ("Prototype Pollution", "CWE-1321", "Prototype Pollution"),
    ("Type Confusion", "CWE-843", "Type Confusion"),
    ("Hardcoded Credentials", "CWE-798", "Hardcoded Credentials"),
    ("Hard-coded Credentials", "CWE-798", "Hardcoded Credentials"),
    ("硬编码凭证", "CWE-798", "Hardcoded Credentials"),
    ("Inadequate Encryption", "CWE-326", "Weak Cryptographic Algorithm"),
    ("Weak Cryptographic", "CWE-326", "Weak Cryptographic Algorithm"),
    ("Weak Encryption", "CWE-326", "Weak Cryptographic Algorithm"),
    ("Weak Random", "CWE-330", "Weak Random Number"),
    ("Hardcoded IV", "CWE-329", "Hardcoded IV"),
    ("JWT", "CWE-347", "JWT Signature Verification"),
    ("Missing Authorization", "CWE-862", "Missing Authorization"),
    ("Missing Authentication", "CWE-306", "Missing Authentication"),
    ("Insecure Direct Object Reference", "CWE-639", "IDOR"),
    ("IDOR", "CWE-639", "IDOR"),
    ("Unintended Proxy", "CWE-441", "Unintended Proxy or Intermediary"),
    ("Session Fixation", "CWE-384", "Session Fixation"),
    ("Deserialization", "CWE-502", "Deserialization"),
    ("反序列化", "CWE-502", "Deserialization"),
    ("XML External Entity", "CWE-611", "XML External Entity"),
    ("XXE", "CWE-611", "XML External Entity"),
    ("Open Redirect", "CWE-601", "Open Redirect"),
    ("URL Redirection", "CWE-601", "Open Redirect"),
    ("URL Redirect", "CWE-601", "Open Redirect"),
    ("Path Traversal", "CWE-22", "Path Traversal"),
    ("路径穿越", "CWE-22", "Path Traversal"),
    ("路径遍历", "CWE-22", "Path Traversal"),
    ("Server-Side Request Forgery", "CWE-918", "SSRF"),
    ("SSRF", "CWE-918", "SSRF"),
    ("服务端请求伪造", "CWE-918", "SSRF"),
    ("Backdoor", "CWE-912", "Backdoor"),
    ("Hidden Functionality", "CWE-912", "Backdoor"),
    ("Exposed Dangerous Method", "CWE-749", "Exposed Dangerous Method"),
    ("Incorrect Default Permissions", "CWE-276", "Incorrect Default Permissions"),
    ("Insecure Default Permissions", "CWE-1188", "Insecure Default Permissions"),
    ("Insecure Default", "CWE-1188", "Insecure Default Permissions"),
    ("Incorrect Permission Assignment", "CWE-732", "Incorrect Permission Assignment"),
    ("Permission Assignment", "CWE-732", "Incorrect Permission Assignment"),
    ("Insecure Permissions", "CWE-732", "Incorrect Permission Assignment"),
    ("Memory Leak", "CWE-401", "Memory Leak"),
    ("Expression Language", "CWE-917", "Expression Language Injection"),
    ("Email Header", "CWE-93", "Email Header Injection"),
    ("Certificate Validation", "CWE-295", "Improper Certificate Validation"),
    ("Observable Timing", "CWE-208", "Observable Timing Discrepancy"),
    ("Log Injection", "CWE-117", "Log Injection"),
    ("日志注入", "CWE-117", "Log Injection"),
    ("Format String", "CWE-134", "Format String"),
    ("Code Injection", "CWE-94", "Code Injection"),
    ("SQL Injection", "CWE-89", "SQL Injection"),
    ("SQL 注入", "CWE-89", "SQL Injection"),
    ("SQL注入", "CWE-89", "SQL Injection"),
    ("LDAP Injection", "CWE-90", "LDAP Injection"),
    ("LDAP注入", "CWE-90", "LDAP Injection"),
    ("XPath Injection", "CWE-643", "XPath Injection"),
    ("XPath注入", "CWE-643", "XPath Injection"),
    ("NoSQL Injection", "CWE-943", "NoSQL Injection"),
    ("Template Injection", "CWE-1336", "SSTI"),
    ("SSTI", "CWE-1336", "SSTI"),
    ("模板注入", "CWE-1336", "SSTI"),
    ("Command Injection", "CWE-77", "Command Injection"),
    ("OS Command Injection", "CWE-78", "OS Command Injection"),
    ("命令注入", "CWE-78", "OS Command Injection"),
    ("Argument Injection", "CWE-88", "Argument Injection"),
    ("Cross-Site Scripting", "CWE-79", "XSS"),
    ("XSS", "CWE-79", "XSS"),
    ("Cross-Site Request Forgery", "CWE-352", "CSRF"),
    ("CSRF", "CWE-352", "CSRF"),
    ("跨站请求伪造", "CWE-352", "CSRF"),
    ("Information Disclosure", "CWE-200", "Information Disclosure"),
    ("信息泄露", "CWE-200", "Information Disclosure"),
    ("HTTP Response Splitting", "CWE-113", "HTTP Response Splitting"),
    # 补充长尾（dry-run 后人工复核结果）
    ("URL重定向到不可信站点", "CWE-601", "Open Redirect"),
    ("Authentication Bypass", "CWE-287", "Improper Authentication"),
    ("Unverified Password Change", "CWE-287", "Improper Authentication"),
    ("Uncontrolled File Path", "CWE-22", "Path Traversal"),
    ("文件路径不可信", "CWE-22", "Path Traversal"),
    ("代码注入", "CWE-94", "Code Injection"),
    ("SpEL表达式注入", "CWE-917", "Expression Language Injection"),
    ("Unintentional Proxy", "CWE-441", "Unintended Proxy or Intermediary"),
    ("容器默认权限配置不当", "CWE-1188", "Insecure Default Permissions"),
    ("Insecure Inherited Permissions", "CWE-732", "Incorrect Permission Assignment"),
    ("弱TLS", "CWE-326", "Weak Cryptographic Algorithm"),
    ("TLS协议", "CWE-326", "Weak Cryptographic Algorithm"),
]

# 分支：CWE 编号已在 CWE_NAMES 中，但标准名可能被误映射（如 CWE-749 在旧表里是
# OS Command Injection，这里按 v9max 语义取 Exposed Dangerous Method）。
_CWE_OVERRIDE = {"CWE-749": "Exposed Dangerous Method"}


def _canonical(cwe_id: str) -> str:
    """CWE 编号 → 'CWE-XXX 标准名'。"""
    name = _CWE_OVERRIDE.get(cwe_id) or CWE_NAMES.get(cwe_id)
    if name:
        return f"{cwe_id} {name}"
    return cwe_id


def normalize_vt(vt: str) -> str:
    """把任意 vulnerability_type 归一化为 'CWE-XXX 标准名'。"""
    if not vt or str(vt).strip().lower() == "none":
        return "none"
    s = str(vt).strip()

    # 情形1：含 CWE 编号（处理各种分隔符/括号/语言）
    m = re.search(r"CWE-(\d+)", s, re.IGNORECASE)
    if m:
        cwe_id = f"CWE-{m.group(1)}"
        return _canonical(cwe_id)

    # 情形2：纯自然语言名，关键字匹配
    for kw, cwe_id, name in NATURAL_KEYWORDS:
        if kw.lower() in s.lower():
            return f"{cwe_id} {name}"

    # 情形3：无法匹配，保留原样（由人工复核）
    return s


def extract_json(asst: str):
    """提取 assistant 中最后一个 ```json 块。"""
    blocks = re.findall(r"```json\s*(.*?)\s*```", asst, re.DOTALL)
    if not blocks:
        return None, None
    for b in reversed(blocks):
        try:
            return json.loads(b.strip()), b
        except Exception:
            continue
    return None, None


def main():
    parser = argparse.ArgumentParser(description="v9max 数据治理")
    parser.add_argument("--input", type=str,
                        default="experiments/exp_06_finetune/data/distill_v2/train_chatml_v9max.jsonl")
    parser.add_argument("--output", type=str,
                        default="experiments/exp_06_finetune/data/distill_v2/train_chatml_v9max_clean.jsonl")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    in_path = Path(args.input)
    records = [json.loads(l) for l in open(in_path, encoding="utf-8") if l.strip()]
    print(f"加载 {len(records)} 条 from {in_path}")

    vt_changed = 0
    cvss_dropped = 0
    unknown = Counter()
    out_records = []

    for r in records:
        msgs = r["messages"]
        if len(msgs) < 3:
            out_records.append(r)
            continue
        asst = msgs[2]["content"]
        j, raw = extract_json(asst)
        if j is None:
            out_records.append(r)
            continue

        changed = False
        # 1) 归一化 vulnerability_type
        vt = j.get("vulnerability_type")
        if j.get("has_vulnerability") is True and vt and str(vt).lower() != "none":
            new_vt = normalize_vt(vt)
            if new_vt != vt:
                j["vulnerability_type"] = new_vt
                vt_changed += 1
                changed = True
            if new_vt not in ("none",) and not re.match(r"^CWE-\d+\s+\S", new_vt):
                unknown[new_vt] += 1
        # 2) 删除 cvss 字段（对齐 BASE_PROMPT schema）
        for k in ("cvss_vector", "cvss_score"):
            if k in j:
                del j[k]
                cvss_dropped += 1
                changed = True

        if changed:
            raw = json.dumps(j, ensure_ascii=False)
            # 用新 JSON 替换最后一个 ```json 块
            new_asst = asst.rsplit("```json", 1)[0] + "```json\n" + raw + "\n```"
            msgs = [msgs[0], msgs[1], {"role": "assistant", "content": new_asst}]
            r = dict(r)
            r["messages"] = msgs

        out_records.append(r)

    print(f"vulnerability_type 归一化: {vt_changed} 条")
    print(f"cvss 字段删除: {cvss_dropped} 个字段")
    print(f"仍无法匹配的 vulnerability_type（需人工复核）: {len(unknown)} 种")
    for vt, c in unknown.most_common(30):
        print(f"   {c:5d}  {vt}")

    if args.dry_run:
        print("\n[dry-run] 未写入文件")
        return

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for r in out_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"\n输出: {out_path} ({len(out_records)} 条)")

    # 验证：剩余 distinct
    vt_after = Counter()
    for r in out_records:
        j, _ = extract_json(r["messages"][2]["content"])
        if j and j.get("has_vulnerability") is True:
            t = j.get("vulnerability_type", "")
            if t and t != "none":
                vt_after[t] += 1
    print(f"归一化后 distinct vulnerability_type: {len(vt_after)}")
    for t, c in vt_after.most_common(15):
        print(f"   {c:5d}  {t}")


if __name__ == "__main__":
    main()