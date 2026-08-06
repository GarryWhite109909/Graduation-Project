#!/usr/bin/env python3
"""全局合并所有训练数据 → final_train_chatml.jsonl。

数据源：
  1. distill_v2/train_chatml_v9max.jsonl    (7698)  DeepSeek 蒸馏
  2. train_chatml_v9_augmented_unified.jsonl (840)   v9 增强
  3. distill_glm_cwe_cvss_unified.jsonl      (676)   GLM 蒸馏
  4. distill_glm_web_unified.jsonl            (300)   GLM web
  5. distill_targeted_supplement_unified.jsonl(187)   针对性补充
  6. distill_cwe_boundary_supplement_unified (58)    CWE 边界对比
  7. distill_corpus_annotated_unified.jsonl  (400)   语料标注
  8. combined/augmented/train_chatml          (~2737) 早期数据（去重后保留独立部分）

处理：
  - 统一 system prompt 为 BASE_PROMPT
  - 按代码内容哈希去重
  - 统计正负比例、CWE 分布、语言分布
"""
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import BASE_PROMPT

DATA_DIR = Path(__file__).resolve().parents[1] / "data"

# 数据源（按优先级排序，先读的保留）
SOURCES = [
    ("distill_v2/train_chatml_v9max.jsonl",           "DeepSeek蒸馏"),
    ("train_chatml_v9_augmented_unified.jsonl",        "v9增强"),
    ("distill_glm_cwe_cvss_unified.jsonl",             "GLM cwe_cvss"),
    ("distill_glm_web_unified.jsonl",                   "GLM web"),
    ("distill_targeted_supplement_unified.jsonl",       "针对性补充"),
    ("distill_cwe_boundary_supplement_unified.jsonl",  "CWE边界对比"),
    ("distill_corpus_annotated_unified.jsonl",         "语料标注"),
    ("combined_train_chatml_unified.jsonl",             "早期合并"),
    ("augmented_train_chatml_unified.jsonl",            "早期增强"),
    ("train_chatml_unified.jsonl",                      "基础数据"),
    ("supplement_chatml_unified.jsonl",                 "补充数据"),
]

OUTPUT = DATA_DIR / "final_train_chatml.jsonl"


def extract_code(messages):
    """从 messages 中提取代码内容（用于去重）。"""
    for m in messages:
        if m.get("role") == "user":
            content = m.get("content", "")
            # 提取代码块
            match = re.search(r"```\w*\n(.*?)```", content, re.DOTALL)
            if match:
                return match.group(1).strip()
            return content.strip()
    return ""


def code_hash(messages):
    """代码内容的 MD5 哈希。"""
    code = extract_code(messages)
    return hashlib.md5(code.encode("utf-8")).hexdigest()


def extract_cwe(messages):
    """从 assistant 的 JSON 结论中提取 CWE。"""
    for m in messages:
        if m.get("role") != "assistant":
            continue
        match = re.search(r"```json\s*(\{.*?\})\s*```", m["content"], re.DOTALL)
        if not match:
            continue
        try:
            v = json.loads(match.group(1))
            vt = v.get("vulnerability_type", "")
            cwe_match = re.match(r"(CWE-\d+)", vt)
            if cwe_match:
                return cwe_match.group(1)
        except:
            pass
    return "unknown"


def extract_has_vuln(messages):
    """从 assistant 的 JSON 结论中提取 has_vulnerability。"""
    for m in messages:
        if m.get("role") != "assistant":
            continue
        match = re.search(r"```json\s*(\{.*?\})\s*```", m["content"], re.DOTALL)
        if not match:
            continue
        try:
            v = json.loads(match.group(1))
            return v.get("has_vulnerability", None)
        except:
            pass
    return None


def main():
    seen_hashes = set()
    all_samples = []
    stats_per_source = []

    print("=" * 80)
    print("全局合并所有训练数据")
    print("=" * 80)
    print(f"BASE_PROMPT: {len(BASE_PROMPT)} 字符\n")

    for fname, label in SOURCES:
        path = DATA_DIR / fname
        if not path.exists():
            continue
        samples = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    samples.append(json.loads(line))
                except:
                    continue

        # 统一 system prompt
        changed = 0
        for s in samples:
            msgs = s.get("messages", [])
            if msgs and msgs[0].get("role") == "system":
                if msgs[0]["content"] != BASE_PROMPT:
                    msgs[0]["content"] = BASE_PROMPT
                    changed += 1

        # 去重
        new_count = dup_count = 0
        for s in samples:
            msgs = s.get("messages", [])
            h = code_hash(msgs)
            if h in seen_hashes:
                dup_count += 1
                continue
            seen_hashes.add(h)
            # 剥离 _meta
            all_samples.append({"messages": msgs})
            new_count += 1

        stats_per_source.append({
            "label": label,
            "file": fname,
            "read": len(samples),
            "system_changed": changed,
            "new": new_count,
            "dup": dup_count,
        })
        print(f"  {label:<14s} 读 {len(samples):>5d}  新增 {new_count:>5d}  重复跳过 {dup_count:>5d}  system替换 {changed:>5d}")

    # 写入最终文件
    with open(OUTPUT, "w", encoding="utf-8") as f:
        for s in all_samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    # 统计
    print(f"\n{'=' * 80}")
    print(f"最终数据集: {OUTPUT.name}")
    print(f"{'=' * 80}")

    total = len(all_samples)
    vuln = safe = unknown = 0
    cwe_dist = Counter()
    for s in all_samples:
        hv = extract_has_vuln(s["messages"])
        if hv is True:
            vuln += 1
            cwe = extract_cwe(s["messages"])
            cwe_dist[cwe] += 1
        elif hv is False:
            safe += 1
        else:
            unknown += 1

    print(f"  总条数: {total}")
    print(f"  漏洞: {vuln}  安全: {safe}  未知: {unknown}")
    if vuln + safe > 0:
        ratio = safe / vuln if vuln > 0 else 0
        print(f"  正负比: 1:{ratio:.1f}")
    print(f"  CWE 种类: {len(cwe_dist)}")
    print(f"\n  CWE 分布 Top15:")
    for cwe, cnt in cwe_dist.most_common(15):
        print(f"    {cwe:<12s} {cnt:>5d}")

    print(f"\n  文件: {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
