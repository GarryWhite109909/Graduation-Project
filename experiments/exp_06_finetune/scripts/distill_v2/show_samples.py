"""临时脚本：打印代表性样本完整内容，供内容质量分析。"""
import json
from pathlib import Path

DATA_DIR = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\distill_v2")

def load(filename):
    path = DATA_DIR / filename
    return [json.loads(l) for l in path.read_text(encoding="utf-8").strip().split("\n") if l.strip()]

def show(obj, label):
    msgs = obj["messages"]
    meta = obj["_meta"]
    print(f"\n{'='*72}")
    print(f"{label}")
    print(f"task={meta['task_id']} | cwe={meta['cwe']} | lang={meta['lang']} | has_vuln={meta['has_vuln']}")
    print(f"{'='*72}")
    print(f"\n【USER 待测代码】")
    print(msgs[1]["content"])
    print(f"\n【ASSISTANT CoT+JSON】")
    print(msgs[2]["content"])

cc = load("deepseek_cc_memory.jsonl")
pt = load("deepseek_pentest.jsonl")

# 1. cc_memory UAF 漏洞（看漏洞推理链）
for s in cc:
    if s["_meta"]["has_vuln"] and "CWE-416" in s["_meta"]["cwe"]:
        show(s, "📌 cc_memory 漏洞：CWE-416 UAF")
        break

# 2. cc_memory 安全样本（看防御+否定推理，选中间位置的）
cc_safe = [s for s in cc if not s["_meta"]["has_vuln"]]
if cc_safe:
    show(cc_safe[len(cc_safe)//2], "📌 cc_memory 安全：防御+否定推理")

# 3. pentest 命令注入漏洞（看 source→sink 追踪）
for s in pt:
    if s["_meta"]["has_vuln"] and "CWE-78" in s["_meta"]["cwe"]:
        show(s, "📌 pentest 漏洞：CWE-78 命令注入")
        break

# 4. pentest 安全样本（看防御有效性）
pt_safe = [s for s in pt if not s["_meta"]["has_vuln"]]
if pt_safe:
    show(pt_safe[len(pt_safe)//2], "📌 pentest 安全：防御有效")
