"""精确泄露检测：用更长的指纹（前 300 字符）区分真泄露 vs 模板误判。"""
import json
import re
from pathlib import Path
from collections import defaultdict

CORPUS = Path(r"d:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\cpt_corpus.jsonl")
TESTSET_DIR = Path(r"d:\code\毕业设计\Graduation-Project\experiments\exp_04_hard_samples\samples")

# 加载测试集代码
testset_code = {}
for f in TESTSET_DIR.glob("*.py"):
    testset_code[f.name] = f.read_text(encoding="utf-8")

# 加载 CPT 语料
records = []
with open(CORPUS, encoding="utf-8") as fp:
    for i, line in enumerate(fp, 1):
        line = line.strip()
        if line:
            rec = json.loads(line)
            rec["_line"] = i
            records.append(rec)

# 用多个指纹长度做检测，看哪个长度下泄露信号稳定
print("=" * 70)
print("精确泄露检测（用 100/200/300 字符指纹 + 全文 substring 匹配）")
print("=" * 70)

# 先看模板指纹（flask 模板等）的命中数
template_patterns = [
    "from flask import Flask, request",
    "from flask import Flask, request, jsonify",
    "from flask import Flask, request, session",
    "app = Flask(__name__)",
    "@app.route",
    "import sqlite3",
    "import os",
    "import subprocess",
    "if __name__ == '__main__':",
    "import boto3",
    "from django",
]
template_hits = 0
for r in records:
    text = r.get("text", "")
    for pat in template_patterns:
        if pat in text:
            template_hits += 1
            break

print(f"\n含通用模板指纹的样本数: {template_hits}/{len(records)} "
      f"(这些不一定是泄露，是 boilerplate)")

# 真泄露检测：从 CPT 语料的代码块提取出来，与测试集做 substring 匹配
# 匹配长度 ≥ 200 字符才算泄露（避免 boilerplate 误判）
print(f"\n--- 严格泄露检测（代码片段 ≥200 字符 substring 命中）---")
real_leaks = []
for r in records:
    text = r.get("text", "")
    # 提取所有 ``` 代码块
    for m in re.finditer(r"```(?:\w+)?\n(.*?)```", text, re.DOTALL):
        frag = m.group(1).strip()
        if len(frag) < 200:
            continue
        # 取前 200 字符做指纹
        fingerprint = frag[:200]
        for fname, code in testset_code.items():
            if fingerprint in code:
                # 进一步确认：再取 frag 的后 200 字符
                back_print = frag[-200:]
                if back_print in code:
                    real_leaks.append({
                        "line": r["_line"],
                        "priority": r.get("priority"),
                        "test_file": fname,
                        "frag_len": len(frag),
                        "preview": fingerprint[:100].replace("\n", " "),
                    })
                    break

print(f"\n真泄露命中数（前后 200 字符都匹配）: {len(real_leaks)}")
if real_leaks:
    print(f"\nTop 10 真泄露:")
    for h in real_leaks[:10]:
        print(f"  L{h['line']} [{h['priority']}] ↔ {h['test_file']} "
              f"(片段长 {h['frag_len']} 字符)")
        print(f"    指纹: {h['preview']}...")

# 区分 Layer C 代码层（如果 prepare 重跑了应该有 layer=C 标签）vs 其他
print(f"\n--- 含 '### CVE/漏洞样本' 标记的样本（这些是测试集代码）---")
cve_samples = [r for r in records if "### CVE/漏洞样本" in r.get("text", "")]
print(f"含 '### CVE/漏洞样本' 标记: {len(cve_samples)} 条")
if cve_samples:
    print(f"Top 3 示例:")
    for r in cve_samples[:3]:
        preview = r.get("text", "")[:120].replace("\n", " ")
        print(f"  L{r['_line']} [{r.get('priority')}]: {preview}...")

# 检查 "### 漏洞示例" 标记（prepare_cpt_corpus.py 中 extract_labeled_code_samples 会生成这个标题）
print(f"\n--- 含 '### 漏洞示例' 或 '### 安全示例' 标记（Layer C 应有的标记）---")
layer_c_candidates = [r for r in records
                     if "### 漏洞示例" in r.get("text", "") or "### 安全示例" in r.get("text", "")]
print(f"含 Layer C 标记: {len(layer_c_candidates)} 条")

# 最终诊断
print(f"\n" + "=" * 70)
print(f"诊断结论")
print(f"=" * 70)
print(f"1. cpt_corpus.jsonl 是否为三层分离版: {'❌ 否（无 layer 字段）' if all('layer' not in r for r in records[:10]) else '✅ 是'}")
print(f"2. SYSTEM_PROMPT 重复次数: {sum(1 for r in records if '### SYSTEM' in r.get('text',''))}/{len(records)}")
print(f"3. 真实测试集泄露（≥200 字符匹配）: {len(real_leaks)} 处")
print(f"4. 含 '### CVE/漏洞样本' 标记: {len(cve_samples)} 条（说明测试集代码可能被纳入）")
print(f"5. 含 '### 漏洞示例' 标记: {len(layer_c_candidates)} 条（Layer C 三层版才应有）")
