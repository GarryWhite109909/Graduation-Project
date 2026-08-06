#!/usr/bin/env python3
"""归一化 vulnerability_type + 修复负样本字段 + 压缩超长样本。

修复内容：
1. vulnerability_type 归一化为 "CWE-XXX English Name" 格式（907 条）
2. 负样本 source/sink/explanation 设为 "N/A"，fix_suggestion 设为 "no fix needed"（1515 条）
3. 超长样本（>2048 tokens）压缩：去除代码冗余空行/注释
"""
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
INPUT_FILE = DATA_DIR / "final_train_chatml.jsonl"
OUTPUT_FILE = DATA_DIR / "final_train_chatml_v2.jsonl"

# ===========================================================================
# CWE 映射表：关键词 → (CWE编号, 英文名)
# ===========================================================================
# 按优先级排序（长的先匹配，避免 "SQL Injection" 被其他规则截断）
CWE_MAP = [
    # C/C++ 内存类
    (r"double.?free", "CWE-415 Double Free"),
    (r"use.?after.?free|uaf", "CWE-416 Use After Free"),
    (r"heap.?buffer.?overflow|堆缓冲区溢出|堆溢出", "CWE-122 Heap-based Buffer Overflow"),
    (r"stack.?buffer.?overflow|栈缓冲区溢出|栈溢出", "CWE-121 Stack-based Buffer Overflow"),
    (r"buffer.?overflow|缓冲区溢出|堆溢出写|堆越界写", "CWE-120 Buffer Copy without Checking Size"),
    (r"out.?of.?bounds.?read|越界读|堆越界读|堆缓冲区越界读", "CWE-125 Out-of-bounds Read"),
    (r"out.?of.?bounds.?write|越界写|堆越界写|堆缓冲区越界写", "CWE-787 Out-of-bounds Write"),
    (r"integer.?overflow|整数溢出", "CWE-190 Integer Overflow"),
    (r"null.?pointer.?deref|空指针", "CWE-476 NULL Pointer Dereference"),
    (r"toctou|race.?condition|数据竞争|竞态", "CWE-362 Race Condition"),
    (r"memory.?leak|内存泄漏", "CWE-401 Memory Leak"),
    (r"type.?confusion|类型混淆", "CWE-843 Type Confusion"),
    # Web 注入类
    (r"sql.?injection|sql注入|sql注入", "CWE-89 SQL Injection"),
    (r"nosql.?injection|nosql注入", "CWE-943 NoSQL Injection"),
    (r"command.?injection|命令注入|os命令注入|os command injection", "CWE-78 OS Command Injection"),
    (r"argument.?injection", "CWE-88 Argument Injection"),
    (r"code.?injection|代码注入|eval.?based|rce via eval", "CWE-94 Code Injection"),
    (r"format.?string|格式化字符串", "CWE-134 Format String"),
    (r"ldap.?injection|ldap注入", "CWE-90 LDAP Injection"),
    (r"xpath.?injection|xpath注入", "CWE-643 XPath Injection"),
    (r"expression.?language|spel|el表达式", "CWE-917 Expression Language Injection"),
    (r"log.?injection|日志注入|log.?forging", "CWE-117 Log Injection"),
    # Web 其他
    (r"xss|cross.?site.?scripting|跨站脚本", "CWE-79 XSS"),
    (r"csrf|cross.?site.?request.?forgery|跨站请求伪造", "CWE-352 CSRF"),
    (r"path.?traversal|路径穿越|path traversal|unintentional file write", "CWE-22 Path Traversal"),
    (r"xxe|xml.?external.?entity", "CWE-611 XML External Entity"),
    (r"deserialization|反序列化", "CWE-502 Deserialization"),
    (r"idor|insecure.?direct.?object", "CWE-639 IDOR"),
    (r"open.?redirect|url重定向|open redirect", "CWE-601 Open Redirect"),
    (r"missing.?auth|认证绕过|missing authentication", "CWE-306 Missing Authentication"),
    (r"missing.?author|越权|missing authorization", "CWE-862 Missing Authorization"),
    (r"hardcoded.?credential|硬编码凭证|硬编码密钥|hardcoded secret", "CWE-798 Hardcoded Credentials"),
    (r"hardcoded.?iv|硬编码iv", "CWE-329 Hardcoded IV"),
    (r"weak.?random|不安全随机|insufficiently random", "CWE-330 Weak Random Number"),
    (r"weak.?crypto|弱加密|weak tls|弱tls|weak algorithm", "CWE-327 Weak Cryptographic Algorithm"),
    (r"missing.?crypto|certificate.?verif|证书验证", "CWE-295 Improper Certificate Validation"),
    (r"missing.?salt|缺盐|no salt", "CWE-759 Improper Restriction of Operations"),
    (r"session.?fixation|会话固定", "CWE-384 Session Fixation"),
    (r"mass.?assignment", "CWE-915 Mass Assignment"),
    (r"ssti|server.?side.?template|模板注入", "CWE-1336 SSTI"),
    (r"ssrf|server.?side.?request.?forgery|unintended proxy|unintentional proxy", "CWE-918 SSRF"),
    (r"untrusted.?search.?path|uncontrolled search path|path hijacking", "CWE-441 Untrusted Search Path"),
    (r"insecure.?permission|insecure default permission|incorrect permission", "CWE-732 Insecure File Permissions"),
    (r"exposed.?dangerous.?method", "CWE-78 OS Command Injection"),
    (r"email.?header.?injection", "CWE-93 Email Header Injection"),
    (r"prototype.?pollution", "CWE-1321 Prototype Pollution"),
    (r"jwt", "CWE-347 JWT Signature Verification"),
]


def normalize_vt(vt: str) -> str:
    """归一化 vulnerability_type 为 CWE-XXX English Name 格式。"""
    if not vt or vt == "none":
        return vt
    # 已经是标准格式
    if re.match(r"^CWE-\d+\s+\S", vt):
        # 提取第一个 CWE 编号 + 名称
        match = re.match(r"^(CWE-\d+)\s+(.+?)(?:\s*\(.*\))?$", vt)
        if match:
            cwe_id = match.group(1)
            name = match.group(2).strip()
            # 标准化常见名称
            return f"{cwe_id} {name}"
        return vt
    # 按映射表匹配
    vt_lower = vt.lower()
    for pattern, replacement in CWE_MAP:
        if re.search(pattern, vt_lower):
            return replacement
    # 无法匹配，返回原值
    return vt


def fix_negative_fields(verdict: dict) -> dict:
    """修复负样本字段。"""
    if verdict.get("has_vulnerability") is False:
        verdict["source"] = "N/A"
        verdict["sink"] = "N/A"
        verdict["explanation"] = "N/A"
        verdict["fix_suggestion"] = "no fix needed"
    return verdict


def compress_code(code: str) -> str:
    """压缩代码：去除连续空行、冗余注释。"""
    lines = code.split("\n")
    out = []
    prev_blank = False
    for line in lines:
        stripped = line.strip()
        # 连续空行只保留一个
        if not stripped:
            if not prev_blank:
                out.append(line)
                prev_blank = True
            continue
        prev_blank = False
        # 去除纯注释行（# 或 // 开头，非 shebang）
        if re.match(r"^\s*(#|//)", line) and not stripped.startswith("#!"):
            continue
        out.append(line)
    # 去除尾部空行
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out)


def compress_sample(messages: list, target_tokens: int = 2048) -> list:
    """压缩样本以适合 target_tokens。"""
    for m in messages:
        if m["role"] != "user":
            continue
        content = m["content"]
        # 找代码块
        match = re.search(r"(```\w*\n)(.*?)(```)", content, re.DOTALL)
        if not match:
            continue
        code = match.group(2)
        compressed = compress_code(code)
        if compressed != code:
            new_content = content[:match.start(2)] + compressed + content[match.end(2):]
            m["content"] = new_content
    return messages


def main():
    print("=" * 70)
    print("修复训练数据：归一化 vulnerability_type + 修复负样本 + 压缩超长")
    print("=" * 70)

    # 读取所有样本
    samples = []
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            samples.append(json.loads(line))
    print(f"读取: {len(samples)} 条")

    # 统计
    vt_fixed = 0
    neg_fixed = 0
    compressed = 0

    for obj in samples:
        messages = obj["messages"]
        for m in messages:
            if m["role"] != "assistant":
                continue
            # 找 JSON 块
            json_match = re.search(r"```json\s*(\{.*?\})\s*```", m["content"], re.DOTALL)
            if not json_match:
                continue
            try:
                verdict = json.loads(json_match.group(1))
            except:
                continue

            # 1. 归一化 vulnerability_type
            old_vt = verdict.get("vulnerability_type", "")
            if verdict.get("has_vulnerability") is True and old_vt and old_vt != "none":
                new_vt = normalize_vt(old_vt)
                if new_vt != old_vt:
                    verdict["vulnerability_type"] = new_vt
                    vt_fixed += 1

            # 2. 修复负样本字段
            if verdict.get("has_vulnerability") is False:
                old_source = verdict.get("source", "")
                old_sink = verdict.get("sink", "")
                old_fix = verdict.get("fix_suggestion", "")
                if old_source != "N/A" or old_sink != "N/A" or old_fix != "no fix needed":
                    neg_fixed += 1
                verdict = fix_negative_fields(verdict)

            # 写回 JSON
            new_json = json.dumps(verdict, ensure_ascii=False)
            m["content"] = m["content"][:json_match.start(1)] + new_json + m["content"][json_match.end(1):]

    # 3. 压缩超长样本
    try:
        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained("Qwen/Qwen3-8B", trust_remote_code=True)
        for obj in samples:
            messages = obj["messages"]
            text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
            tokens = tokenizer.encode(text, add_special_tokens=False)
            if len(tokens) > 2048:
                obj["messages"] = compress_sample(messages)
                compressed += 1
        print(f"压缩超长样本: {compressed} 条")
    except ImportError:
        print("⚠️ transformers 不可用，跳过压缩")

    # 写入
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for obj in samples:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    print(f"\n修复完成:")
    print(f"  vulnerability_type 归一化: {vt_fixed} 条")
    print(f"  负样本字段修复: {neg_fixed} 条")
    print(f"  超长样本压缩: {compressed} 条")
    print(f"  输出: {OUTPUT_FILE}")

    # 验证
    print(f"\n=== 验证 ===")
    bad_vt = 0
    bad_neg = 0
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
                        bad_vt += 1
                elif v.get("has_vulnerability") is False:
                    if v.get("source") != "N/A" or v.get("sink") != "N/A" or v.get("fix_suggestion") != "no fix needed":
                        bad_neg += 1
    print(f"  剩余不规范 vulnerability_type: {bad_vt} 条")
    print(f"  剩余不规范负样本字段: {bad_neg} 条")


if __name__ == "__main__":
    raise SystemExit(main())
