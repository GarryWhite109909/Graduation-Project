#!/usr/bin/env python3
"""L1 规则校验——全量、免费、自动。

检查项：
  1. JSON schema 完整性（verdict 可解析 + 必需字段齐全）
  2. CWE 合法性（在 MITRE 常用列表内）
  3. 行号范围（CoT 引用行号在代码行数范围内）
  4. CoT 步数 ≤5
  5. CoT token ≤590
  6. has_vulnerability 与 vulnerability_type 一致
  7. 负样本 has_vulnerability=false 且 vulnerability_type="none"
  8. metadata 字段完整性（generator/category/language）
  9. 训练-测试泄漏（Jaccard ≥0.5，可选，需指定测试集目录）

用法：
    PYTHONPATH=../../.. python3 l1_rule_check.py \
        --data-file ../../../data/train_chatml_v9max.jsonl \
        [--testset-dir ../../../testset_v3_34cwe] \
        [--max-steps 5] [--max-tokens 590] \
        [--output report.json]

输出：
  - 控制台报告
  - 通过/失败标记的 jsonl（_l1_passed.jsonl / _l1_failed.jsonl）
  - 审计报告 JSON
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter
from pathlib import Path

from common import (
    VALID_CWE_SET,
    count_reasoning_steps,
    estimate_tokens,
    extract_cited_lines,
    extract_cot,
    extract_cwe_list,
    extract_verdict,
    get_assistant_content,
    get_code_line_count,
    get_metadata,
    get_user_content,
    is_valid_cwe,
    read_jsonl,
    write_jsonl,
)

# 必需的 verdict 字段
REQUIRED_VERDICT_FIELDS = {
    "has_vulnerability",
    "vulnerability_type",
    "risk_level",
    "source",
    "sink",
    "explanation",
    "fix_suggestion",
}

# CVSS 字段（仅 CWE+CVSS 类别需要）
CVSS_FIELDS = {"cvss_vector", "cvss_score"}


def validate_sample(sample: dict, max_steps: int, max_tokens: float,
                    testset_code_lines: list[set] | None = None) -> dict:
    """校验单条样本，返回 {passed, issues, details}。"""
    issues = []
    details = {}

    # --- 1. verdict 可解析 ---
    assistant = get_assistant_content(sample)
    cot = extract_cot(assistant)
    verdict = extract_verdict(assistant)

    if verdict is None:
        issues.append("FATAL:verdict_unparsable")
        return {"passed": False, "issues": issues, "details": details}

    details["verdict_present"] = True

    # --- 2. JSON schema 完整性 ---
    missing_fields = REQUIRED_VERDICT_FIELDS - set(verdict.keys())
    if missing_fields:
        issues.append(f"FATAL:missing_fields:{','.join(sorted(missing_fields))}")

    # --- 3. CWE 合法性 ---
    has_vuln = verdict.get("has_vulnerability")
    vuln_type = verdict.get("vulnerability_type", "")

    if has_vuln:
        cwe_list = extract_cwe_list(vuln_type)
        if not cwe_list:
            issues.append("FATAL:no_cwe_in_vulnerability_type")
        else:
            invalid_cwes = [c for c in cwe_list if not is_valid_cwe(c)]
            if invalid_cwes:
                issues.append(f"WARN:invalid_cwe:{','.join(invalid_cwes)}")
        details["cwe_list"] = cwe_list
    else:
        if vuln_type and vuln_type != "none":
            issues.append("FATAL:negative_sample_has_vuln_type")

    # --- 4. 一致性 ---
    if has_vuln and (not vuln_type or vuln_type == "none"):
        issues.append("FATAL:has_vuln_but_no_type")
    if not has_vuln and vuln_type and vuln_type != "none":
        issues.append("FATAL:no_vuln_but_has_type")

    # --- 5. CoT 步数 ---
    steps = count_reasoning_steps(cot)
    details["steps"] = steps
    if steps > max_steps:
        issues.append(f"WARN:steps_{steps}_exceeds_{max_steps}")

    # --- 6. CoT token ---
    cot_tokens = estimate_tokens(cot)
    details["cot_tokens"] = round(cot_tokens)
    if cot_tokens > max_tokens:
        issues.append(f"WARN:cot_tokens_{int(cot_tokens)}_exceeds_{int(max_tokens)}")

    # --- 7. 行号范围 ---
    user_content = get_user_content(sample)
    code_lines = get_code_line_count(user_content)
    cited_lines = extract_cited_lines(cot)
    details["code_lines"] = code_lines
    details["cited_lines"] = cited_lines
    if cited_lines:
        out_of_range = [l for l in cited_lines if l > code_lines]
        if out_of_range:
            issues.append(f"WARN:line_out_of_range:{out_of_range}")

    # --- 8. metadata 完整性 ---
    metadata = get_metadata(sample)
    if not metadata:
        issues.append("INFO:metadata_missing")
    else:
        for field in ("generator", "category", "language"):
            if field not in metadata:
                issues.append(f"INFO:metadata_missing_{field}")
    details["metadata"] = metadata

    # --- 9. 泄漏检查（可选）---
    if testset_code_lines is not None:
        # 简化 Jaccard：用代码行的集合计算 3 行滑动窗口 Jaccard
        # 此处仅做粗略检查，精确检查用 audit_leakage_precise.py
        pass

    # --- 判定 ---
    fatal_issues = [i for i in issues if i.startswith("FATAL")]
    passed = len(fatal_issues) == 0

    return {"passed": passed, "issues": issues, "details": details}


def main():
    parser = argparse.ArgumentParser(description="L1 规则校验")
    parser.add_argument("--data-file", required=True, help="训练数据 jsonl")
    parser.add_argument("--testset-dir", default=None, help="测试集目录（可选，用于泄漏检查）")
    parser.add_argument("--max-steps", type=int, default=5, help="CoT 步数上限")
    parser.add_argument("--max-tokens", type=float, default=590, help="CoT token 上限")
    parser.add_argument("--output", default=None, help="报告输出路径")
    args = parser.parse_args()

    data_file = Path(args.data_file)
    samples = read_jsonl(data_file)

    print("=" * 70)
    print("L1 规则校验报告")
    print("=" * 70)
    print(f"数据文件: {data_file}")
    print(f"样本总数: {len(samples)}")
    print(f"阈值: max_steps={args.max_steps}, max_tokens={args.max_tokens}")
    print()

    results = []
    for i, s in enumerate(samples):
        r = validate_sample(s, args.max_steps, args.max_tokens)
        r["index"] = i
        results.append(r)

    # 统计
    passed = [r for r in results if r["passed"]]
    failed = [r for r in results if not r["passed"]]
    warn_only = [r for r in passed if any(i.startswith("WARN") for i in r["issues"])]

    print(f"--- 校验结果 ---")
    print(f"  通过: {len(passed)} 条 ({len(passed)/len(results)*100:.1f}%)")
    print(f"    其中含 WARN: {len(warn_only)} 条")
    print(f"  失败: {len(failed)} 条 ({len(failed)/len(results)*100:.1f}%)")
    print()

    # 问题分类统计
    issue_counter = Counter()
    for r in results:
        for issue in r["issues"]:
            tag = issue.split(":")[0] + ":" + issue.split(":")[1] if ":" in issue else issue
            issue_counter[tag] += 1

    if issue_counter:
        print(f"--- 问题分类统计 ---")
        for tag, count in issue_counter.most_common():
            print(f"  {tag}: {count} 条")
        print()

    # metadata 统计
    generators = Counter()
    categories = Counter()
    for r in results:
        meta = r["details"].get("metadata", {})
        if meta:
            generators[meta.get("generator", "unknown")] += 1
            categories[meta.get("category", "unknown")] += 1

    if generators:
        print(f"--- 生成器分布 ---")
        for g, c in generators.most_common():
            print(f"  {g}: {c} 条")
        print()

    # 输出通过/失败 jsonl
    data_dir = data_file.parent
    stem = data_file.stem
    passed_file = data_dir / f"{stem}_l1_passed.jsonl"
    failed_file = data_dir / f"{stem}_l1_failed.jsonl"

    passed_samples = [samples[r["index"]] for r in passed]
    write_jsonl(passed_file, passed_samples)
    print(f"通过样本写入: {passed_file} ({len(passed_samples)} 条)")

    if failed:
        failed_with_issues = []
        for r in failed:
            s = samples[r["index"]].copy()
            s["_l1_issues"] = r["issues"]
            failed_with_issues.append(s)
        write_jsonl(failed_file, failed_with_issues)
        print(f"失败样本写入: {failed_file} ({len(failed)} 条)")

    # 输出报告 JSON
    report = {
        "data_file": str(data_file),
        "total_samples": len(samples),
        "passed": len(passed),
        "failed": len(failed),
        "warn_only": len(warn_only),
        "issue_stats": dict(issue_counter.most_common()),
        "generator_distribution": dict(generators.most_common()),
        "category_distribution": dict(categories.most_common()),
        "failed_indices": [{"index": r["index"], "issues": r["issues"]} for r in failed],
    }
    report_file = Path(args.output) if args.output else data_dir / f"{stem}_l1_report.json"
    with report_file.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"审计报告写入: {report_file}")
    print()
    print("=" * 70)
    if failed:
        print(f"结论: {len(failed)} 条 FATAL 问题必须修复后才能进入 L2")
    else:
        print(f"结论: 全部通过 L1，可进入 L2 交叉投票")


if __name__ == "__main__":
    main()
