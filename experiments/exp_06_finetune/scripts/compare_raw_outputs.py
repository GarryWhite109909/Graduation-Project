"""逐样本对比 7B baseline vs 3B finetuned 的原始输出。

生成两份 markdown：
  1. summary：指标对比（幻觉率 / CWE 错标率 / 输出长度 / 蒙题率 / 失误率）
  2. detail：每个样本的 7B vs 3B raw_output 并排展示，按问题类型分组

用法（在 AI 环境中或普通 python 中均可，不依赖 torch）：
    PYTHONPATH=. python experiments/exp_06_finetune/scripts/compare_raw_outputs.py \
        --baseline results/exp_06_eval.baseline.20260709_144644.json \
        --finetuned results/exp_06_eval.finetuned_custom.20260710_163901.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.schema import parse_verdict, normalize_has_vulnerability


_CWE_PATTERN = re.compile(r"(CWE-\d+)", re.IGNORECASE)


def extract_cwe(vulnerability_type: str) -> str:
    if not vulnerability_type:
        return ""
    m = _CWE_PATTERN.search(vulnerability_type)
    return m.group(1).upper() if m else ""


def cwe_matches(model_cwe: str, expected_cwe: str) -> bool:
    if not expected_cwe or expected_cwe.upper() == "N/A":
        return True
    if not model_cwe:
        return False
    expected = [c.strip().upper() for c in expected_cwe.split(";") if c.strip()]
    return model_cwe in expected


def analyze_sample(s: dict) -> dict:
    """对单个样本做问题诊断。"""
    raw = s.get("raw_output", "") or ""
    expected_present = s.get("expected_present")
    predicted = s.get("predicted")
    outcome = s.get("outcome", "")
    expected_cwe = s.get("expected_cwe", "")

    # 从结果字段或 raw_output 中提取 vulnerability_type
    vt = s.get("model_vulnerability_type", "")
    if not vt:
        verdict = parse_verdict(raw)
        vt = verdict.get("vulnerability_type", "") or ""
    model_cwe = extract_cwe(vt)

    issues = []
    # 1. CWE 错标（TP 但 CWE 不匹配）
    if outcome == "TP" and expected_cwe and expected_cwe.upper() != "N/A":
        if not cwe_matches(model_cwe, expected_cwe):
            issues.append("cwe_mismatch")
    # 2. has_vulnerability 字段缺失 / None
    verdict = parse_verdict(raw)
    hv = normalize_has_vulnerability(verdict.get("has_vulnerability"))
    if hv is None:
        issues.append("missing_verdict")
    # 3. 输出过短（可能截断）
    if len(raw) < 200:
        issues.append("too_short")
    # 4. 输出过长（可能啰嗦 / 重复）
    if len(raw) > 4000:
        issues.append("too_long")
    # 5. JSON 代码块缺失
    if "```json" not in raw and '"has_vulnerability"' not in raw:
        issues.append("no_json_block")
    # 6. CoT-JSON 不一致（CoT 提到"安全/无漏洞"但 JSON 标 True，或反之）
    cot_section = raw.split("```json")[0] if "```json" in raw else raw
    cot_lower = cot_section.lower()
    if hv is True and any(kw in cot_lower for kw in ["未发现漏洞", "不存在漏洞", "代码是安全的", "没有漏洞", "安全代码"]):
        issues.append("cot_json_inconsistent")
    if hv is False and any(kw in cot_lower for kw in ["存在漏洞", "存在安全", "容易导致", "可能导致", "风险"]):
        # 只在有明确"存在漏洞"表述时才标记，避免误报
        if any(kw in cot_lower for kw in ["存在漏洞", "存在安全漏洞", "这里存在"]):
            issues.append("cot_json_inconsistent")
    # 7. 重复文本（同一段话重复出现）
    if len(raw) > 500:
        # 简单检测：取中间 200 字符看是否在后面重复
        mid = raw[len(raw)//3:len(raw)//3+200]
        if mid and raw.count(mid[:80]) > 1:
            issues.append("repetition")
    # 8. 无漏洞样本但模型给出 CWE 编号（过度警觉）
    if expected_present is False and predicted is True and model_cwe:
        issues.append("fp_with_cwe")

    return {
        "issues": issues,
        "model_cwe": model_cwe,
        "model_vt": vt,
        "verdict_hv": hv,
        "raw_len": len(raw),
    }


def compute_summary(samples: list[dict]) -> dict:
    """汇总一个模型的统计指标。"""
    total = len(samples)
    tp = sum(1 for s in samples if s.get("outcome") == "TP")
    tn = sum(1 for s in samples if s.get("outcome") == "TN")
    fp = sum(1 for s in samples if s.get("outcome") == "FP")
    fn = sum(1 for s in samples if s.get("outcome") == "FN")

    # CWE 错标数（在 TP 中）
    cwe_mismatch = 0
    for s in samples:
        a = analyze_sample(s)
        if s.get("outcome") == "TP" and "cwe_mismatch" in a["issues"]:
            cwe_mismatch += 1

    # 各种问题计数
    issue_counts = {}
    for s in samples:
        a = analyze_sample(s)
        for iss in a["issues"]:
            issue_counts[iss] = issue_counts.get(iss, 0) + 1

    raw_lens = [len(s.get("raw_output", "") or "") for s in samples]
    avg_len = sum(raw_lens) / total if total else 0
    max_len = max(raw_lens) if raw_lens else 0
    min_len = min(raw_lens) if raw_lens else 0

    elapsed = [s.get("elapsed_seconds", 0) or 0 for s in samples]
    avg_elapsed = sum(elapsed) / total if total else 0

    # 严格 recall（CWE 也对才算）
    strict_tp = tp - cwe_mismatch
    vuln_total = tp + fn
    strict_recall = strict_tp / vuln_total if vuln_total else None

    return {
        "total": total,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "cwe_mismatch": cwe_mismatch,
        "strict_tp": strict_tp,
        "strict_recall": strict_recall,
        "issue_counts": issue_counts,
        "avg_raw_len": avg_len,
        "min_raw_len": min_len,
        "max_raw_len": max_len,
        "avg_elapsed": avg_elapsed,
    }


def render_summary(bl: dict, ft: dict) -> str:
    bl_m = compute_summary(bl["samples"])
    ft_m = compute_summary(ft["samples"])

    def pct(x):
        return "N/A" if x is None else f"{x*100:.2f}%"

    def delta(old, new):
        if old is None or new is None:
            return "N/A"
        d = new - old
        return f"{d:+.4f}"

    lines = []
    lines.append("# 7B vs 3B 原始输出对比 —— 汇总报告\n")
    lines.append(f"- 7B baseline: `{bl.get('source_path', '')}`")
    lines.append(f"- 3B finetuned: `{ft.get('source_path', '')}`")
    lines.append(f"- 7B model: {bl.get('model', '')}")
    lines.append(f"- 3B model: {ft.get('model', '')}  adapter: {ft.get('checkpoint', '')}")
    lines.append("")

    lines.append("## 1. 核心指标对比\n")
    lines.append("| 指标 | 7B baseline | 3B finetuned | 差值 |")
    lines.append("|------|------------|--------------|------|")
    lines.append(f"| TP | {bl_m['tp']} | {ft_m['tp']} | {ft_m['tp']-bl_m['tp']:+d} |")
    lines.append(f"| TN | {bl_m['tn']} | {ft_m['tn']} | {ft_m['tn']-bl_m['tn']:+d} |")
    lines.append(f"| FP | {bl_m['fp']} | {ft_m['fp']} | {ft_m['fp']-bl_m['fp']:+d} |")
    lines.append(f"| FN | {bl_m['fn']} | {ft_m['fn']} | {ft_m['fn']-bl_m['fn']:+d} |")
    lines.append(f"| CWE 错标数（TP 中） | {bl_m['cwe_mismatch']} | {ft_m['cwe_mismatch']} | {ft_m['cwe_mismatch']-bl_m['cwe_mismatch']:+d} |")
    lines.append(f"| 严格 TP（CWE 也对） | {bl_m['strict_tp']} | {ft_m['strict_tp']} | {ft_m['strict_tp']-bl_m['strict_tp']:+d} |")
    bl_vuln = bl_m['tp'] + bl_m['fn']
    ft_vuln = ft_m['tp'] + ft_m['fn']
    bl_recall = bl_m['tp']/bl_vuln if bl_vuln else None
    ft_recall = ft_m['tp']/ft_vuln if ft_vuln else None
    lines.append(f"| 宽松 recall | {pct(bl_recall)} | {pct(ft_recall)} | {delta(bl_recall, ft_recall) if bl_recall and ft_recall else 'N/A'} |")
    lines.append(f"| 严格 recall（CWE 对） | {pct(bl_m['strict_recall'])} | {pct(ft_m['strict_recall'])} | {delta(bl_m['strict_recall'], ft_m['strict_recall']) if bl_m['strict_recall'] and ft_m['strict_recall'] else 'N/A'} |")
    lines.append(f"| 平均输出字符数 | {bl_m['avg_raw_len']:.0f} | {ft_m['avg_raw_len']:.0f} | {ft_m['avg_raw_len']-bl_m['avg_raw_len']:+.0f} |")
    lines.append(f"| 最长输出 | {bl_m['max_raw_len']} | {ft_m['max_raw_len']} | {ft_m['max_raw_len']-bl_m['max_raw_len']:+d} |")
    lines.append(f"| 最短输出 | {bl_m['min_raw_len']} | {ft_m['min_raw_len']} | {ft_m['min_raw_len']-bl_m['min_raw_len']:+d} |")
    lines.append(f"| 平均耗时(s) | {bl_m['avg_elapsed']:.2f} | {ft_m['avg_elapsed']:.2f} | {ft_m['avg_elapsed']-bl_m['avg_elapsed']:+.2f} |")
    lines.append("")

    lines.append("## 2. 问题类型分布\n")
    all_issues = sorted(set(bl_m["issue_counts"]) | set(ft_m["issue_counts"]))
    issue_desc = {
        "cwe_mismatch": "CWE 错标（TP 但 CWE 不匹配）",
        "missing_verdict": "has_vulnerability 字段缺失",
        "too_short": "输出过短（<200 字符，可能截断）",
        "too_long": "输出过长（>4000 字符，可能啰嗦）",
        "no_json_block": "缺少 JSON 代码块",
        "cot_json_inconsistent": "CoT 与 JSON 结论不一致",
        "repetition": "文本重复",
        "fp_with_cwe": "安全样本误报且给出 CWE",
    }
    lines.append("| 问题类型 | 7B baseline | 3B finetuned | 说明 |")
    lines.append("|---------|------------|--------------|------|")
    for iss in all_issues:
        b = bl_m["issue_counts"].get(iss, 0)
        f = ft_m["issue_counts"].get(iss, 0)
        desc = issue_desc.get(iss, iss)
        lines.append(f"| {iss} | {b} | {f} | {desc} |")
    lines.append("")

    lines.append("## 3. 指标解读\n")
    lines.append("- **幻觉率**：CWE 错标数 / TP 总数。模型检测到漏洞但给了错误的 CWE 编号，属于「方向对但归因错」的幻觉。")
    lines.append("- **蒙题率**：CoT-JSON 不一致数 + missing_verdict 数。模型推理过程与结论脱节，说明结论可能是「蒙」的。")
    lines.append("- **失误率**：FP + FN。硬性错误判断。")
    lines.append("- **随机性**：确定性解码下不应有随机性；若两模型在同一样本上结论相反，反映的是模型能力差异而非随机。")
    lines.append("")

    return "\n".join(lines)


def render_detail(bl: dict, ft: dict) -> str:
    """逐样本并排展示 raw_output。"""
    bl_by_file = {s["file"]: s for s in bl["samples"]}
    ft_by_file = {s["file"]: s for s in ft["samples"]}
    all_files = sorted(set(bl_by_file) | set(ft_by_file))

    lines = []
    lines.append("# 7B vs 3B 原始输出对比 —— 逐样本详情\n")

    # 先按问题严重度分组
    groups = {
        "both_wrong": [],          # 两模型都错
        "7b_wrong_3b_right": [],   # 7B 错 3B 对
        "3b_wrong_7b_right": [],   # 3B 错 7B 对
        "both_right_diff_cwe": [], # 两模型都对但 CWE 不同
        "both_right_same": [],     # 两模型都对且 CWE 相同
    }

    for f in all_files:
        bl_s = bl_by_file.get(f, {})
        ft_s = ft_by_file.get(f, {})
        bl_out = bl_s.get("outcome", "")
        ft_out = ft_s.get("outcome", "")
        bl_correct = bl_out in ("TP", "TN")
        ft_correct = ft_out in ("TP", "TN")

        if not bl_correct and not ft_correct:
            groups["both_wrong"].append(f)
        elif not bl_correct and ft_correct:
            groups["7b_wrong_3b_right"].append(f)
        elif bl_correct and not ft_correct:
            groups["3b_wrong_7b_right"].append(f)
        else:
            # 两个都对，检查 CWE
            bl_a = analyze_sample(bl_s)
            ft_a = analyze_sample(ft_s)
            bl_cwe_ok = "cwe_mismatch" not in bl_a["issues"]
            ft_cwe_ok = "cwe_mismatch" not in ft_a["issues"]
            if bl_cwe_ok and ft_cwe_ok:
                groups["both_right_same"].append(f)
            else:
                groups["both_right_diff_cwe"].append(f)

    group_titles = {
        "both_wrong": "A. 两模型都错的样本（共性问题）",
        "7b_wrong_3b_right": "B. 7B 错 → 3B 对（微调改善）",
        "3b_wrong_7b_right": "C. 7B 对 → 3B 错（微调退化）",
        "both_right_diff_cwe": "D. 两模型都对但 CWE 归因有差异",
        "both_right_same": "E. 两模型完全一致（参考）",
    }

    for key in ["both_wrong", "7b_wrong_3b_right", "3b_wrong_7b_right",
                 "both_right_diff_cwe", "both_right_same"]:
        files = groups[key]
        if not files:
            continue
        lines.append(f"## {group_titles[key]}（{len(files)} 个样本）\n")
        for f in files:
            bl_s = bl_by_file.get(f, {})
            ft_s = ft_by_file.get(f, {})
            bl_raw = bl_s.get("raw_output", "") or "（无 7B 输出）"
            ft_raw = ft_s.get("raw_output", "") or "（无 3B 输出）"
            bl_a = analyze_sample(bl_s)
            ft_a = analyze_sample(ft_s)

            lines.append(f"### {f}")
            cat = bl_s.get("category") or ft_s.get("category", "")
            exp = "有漏洞" if bl_s.get("expected_present") else "安全"
            exp_cwe = bl_s.get("expected_cwe", "") or ft_s.get("expected_cwe", "")
            lines.append(f"- 类别: `{cat}` | 期望: {exp} | 期望 CWE: {exp_cwe}")
            lines.append(f"- 7B: outcome={bl_s.get('outcome','?')} CWE={bl_a['model_cwe'] or '—'} "
                         f"len={bl_a['raw_len']} issues={bl_a['issues'] or '无'}")
            lines.append(f"- 3B: outcome={ft_s.get('outcome','?')} CWE={ft_a['model_cwe'] or '—'} "
                         f"len={ft_a['raw_len']} issues={ft_a['issues'] or '无'}")
            lines.append(f"- 7B 耗时: {bl_s.get('elapsed_seconds', 0):.1f}s | 3B 耗时: {ft_s.get('elapsed_seconds', 0):.1f}s")
            lines.append("")
            lines.append("<details><summary>7B baseline 原始输出</summary>\n")
            lines.append("```\n" + bl_raw + "\n```\n")
            lines.append("</details>\n")
            lines.append("<details><summary>3B finetuned 原始输出</summary>\n")
            lines.append("```\n" + ft_raw + "\n```\n")
            lines.append("</details>\n")
            lines.append("---\n")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="对比 7B vs 3B 原始输出")
    parser.add_argument("--baseline", type=Path, required=True, help="7B baseline 结果 JSON")
    parser.add_argument("--finetuned", type=Path, required=True, help="3B finetuned 结果 JSON")
    parser.add_argument("--out-dir", type=Path, default=None, help="输出目录")
    args = parser.parse_args()

    bl = json.loads(args.baseline.read_text(encoding="utf-8"))
    ft = json.loads(args.finetuned.read_text(encoding="utf-8"))
    bl["source_path"] = str(args.baseline)
    ft["source_path"] = str(args.finetuned)

    out_dir = args.out_dir or args.finetuned.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    summary_md = render_summary(bl, ft)
    summary_path = out_dir / "compare_7b_3b_summary.md"
    summary_path.write_text(summary_md, encoding="utf-8")
    print(f"汇总报告: {summary_path}")

    detail_md = render_detail(bl, ft)
    detail_path = out_dir / "compare_7b_3b_detail.md"
    detail_path.write_text(detail_md, encoding="utf-8")
    print(f"详情报告: {detail_path}")

    print("\n=== 汇总预览 ===\n")
    print(summary_md)


if __name__ == "__main__":
    main()
