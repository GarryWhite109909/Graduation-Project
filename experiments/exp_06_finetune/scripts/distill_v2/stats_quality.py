"""统计蒸馏数据的 CWE / 语言 / has_vuln / risk_level 分布，
以及检测模板化痕迹（重复短语、CoT 起始话术）。"""

import json
import re
from collections import Counter
from pathlib import Path

DATA_DIR = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\distill_v2")


def load_jsonl(path):
    samples = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def stats_pack(pack_name):
    path = DATA_DIR / f"{pack_name}.jsonl"
    if not path.exists():
        print(f"[跳过] {pack_name}")
        return

    samples = load_jsonl(path)
    print("\n" + "=" * 70)
    print(f"包: {pack_name} | 样本数: {len(samples)}")
    print("=" * 70)

    cwes = Counter()
    langs = Counter()
    has_vulns = Counter()
    risks = Counter()
    cot_openers = Counter()  # CoT 起始话术
    cot_step_counts = Counter()  # CoT 步数
    vuln_types = Counter()  # vulnerability_type 字段
    fix_suggestions = Counter()  # 安全样本的 fix_suggestion
    explanation_openers = Counter()  # explanation 起始词

    # 模板化检测：高频短语
    phrase_counter = Counter()
    PHRASES = [
        "防御缺失", "防御缺失点", "否定推理", "假设验证",
        "根因是", "根因：", "双重防御", "双重保险",
        "从源头阻断", "从源头杜绝", "彻底阻断",
        "数据流", "source→sink", "source → sink",
        "换句话说", "也就是说", "需要注意的是",
        "CWE-749", "CWE-78", "CWE-416", "CWE-476",
    ]

    for s in samples:
        meta = s.get("_meta", {})
        cwes[meta.get("cwe", "?")] += 1
        langs[meta.get("lang", "?")] += 1
        has_vulns[meta.get("has_vuln", "?")] += 1

        assistant = s["messages"][2]["content"]
        # 提取 JSON
        json_start = assistant.rfind("```json")
        cot = assistant[:json_start] if json_start != -1 else assistant
        try:
            j = json.loads(assistant[json_start:].replace("```json", "").replace("```", "").strip())
        except Exception:
            j = {}

        risks[j.get("risk_level", "?")] += 1
        vuln_types[j.get("vulnerability_type", "?")[:40]] += 1
        fix_suggestions[str(j.get("fix_suggestion", "?"))[:30]] += 1

        # CoT 起始话术（第一行非空）
        first_line = ""
        for ln in cot.split("\n"):
            ln = ln.strip()
            if ln:
                first_line = ln[:50]
                break
        cot_openers[first_line] += 1

        # CoT 步数
        steps = re.findall(r"(?:^|\n)\s*(\d+)[.)]\s*(.+)", cot)
        cot_step_counts[len(steps)] += 1

        # 短语统计
        for p in PHRASES:
            if p in assistant:
                phrase_counter[p] += 1

    print(f"\n--- CWE 分布 ---")
    for k, v in cwes.most_common():
        print(f"  {k:20s} {v:5d}  ({v/len(samples)*100:.1f}%)")

    print(f"\n--- 语言分布 ---")
    for k, v in langs.most_common():
        print(f"  {k:20s} {v:5d}  ({v/len(samples)*100:.1f}%)")

    print(f"\n--- has_vuln 分布 ---")
    for k, v in has_vulns.most_common():
        print(f"  {str(k):20s} {v:5d}  ({v/len(samples)*100:.1f}%)")

    print(f"\n--- risk_level 分布 ---")
    for k, v in risks.most_common():
        print(f"  {str(k):20s} {v:5d}  ({v/len(samples)*100:.1f}%)")

    print(f"\n--- CoT 步数分布 ---")
    for k in sorted(cot_step_counts.keys()):
        v = cot_step_counts[k]
        print(f"  {k} 步: {v:5d}  ({v/len(samples)*100:.1f}%)")

    print(f"\n--- CoT 起始话术 Top 8（检测模板化）---")
    for k, v in cot_openers.most_common(8):
        print(f"  [{v:4d}] {k}")

    print(f"\n--- vulnerability_type Top 10 ---")
    for k, v in vuln_types.most_common(10):
        print(f"  [{v:4d}] {k}")

    print(f"\n--- 安全样本 fix_suggestion Top 5 ---")
    for k, v in fix_suggestions.most_common(5):
        print(f"  [{v:4d}] {k}")

    print(f"\n--- 高频短语出现率（检测套话）---")
    for p, c in phrase_counter.most_common():
        if c > 0:
            print(f"  {p:20s} {c:5d}  ({c/len(samples)*100:.1f}%)")


for pack in ["deepseek_cc_memory", "deepseek_pentest"]:
    stats_pack(pack)
