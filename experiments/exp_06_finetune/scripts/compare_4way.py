"""4 组对比：7B base vs 7B ft / 3B base vs 3B ft / 7B base vs 3B base / 7B ft vs 3B ft

生成：
  1. 一份综合汇总 markdown（4 组指标并排）
  2. 四份逐样本详情 markdown（每组一份）

用法：
    PYTHONPATH=. python experiments/exp_06_finetune/scripts/compare_4way.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.schema import parse_verdict, normalize_has_vulnerability

# ---------------------------------------------------------------------------
# 文件配置（最新版本）
# ---------------------------------------------------------------------------
RESULTS_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/results"

FILES = {
    "7b_base": RESULTS_DIR / "exp_06_eval.baseline.20260709_144644.json",
    "7b_ft":   RESULTS_DIR / "exp_06_eval.finetuned_custom.20260711_050855.json",
    "3b_base": RESULTS_DIR / "exp_06_eval.baseline.20260709_041420.json",
    "3b_ft":   RESULTS_DIR / "exp_06_eval.finetuned_custom.20260711_031127.json",
}

LABELS = {
    "7b_base": "7B base",
    "7b_ft":   "7B ft",
    "3b_base": "3B base",
    "3b_ft":   "3B ft",
}

# 4 组对比
PAIRS = [
    ("7b_base", "7b_ft",   "7B: base → finetune（微调效果）"),
    ("3b_base", "3b_ft",   "3B: base → finetune（微调效果）"),
    ("7b_base", "3b_base", "base 对比：7B vs 3B（模型规模）"),
    ("7b_ft",   "3b_ft",   "finetune 对比：7B vs 3B（微调后规模差异）"),
]

_CWE_PATTERN = re.compile(r"(CWE-\d+)", re.IGNORECASE)


def extract_cwe(vt: str) -> str:
    if not vt:
        return ""
    m = _CWE_PATTERN.search(vt)
    return m.group(1).upper() if m else ""


def cwe_matches(model_cwe: str, expected_cwe: str) -> bool:
    if not expected_cwe or expected_cwe.upper() == "N/A":
        return True
    if not model_cwe:
        return False
    expected = [c.strip().upper() for c in expected_cwe.split(";") if c.strip()]
    return model_cwe in expected


def analyze_sample(s: dict) -> dict:
    raw = s.get("raw_output", "") or ""
    expected_present = s.get("expected_present")
    predicted = s.get("predicted")
    outcome = s.get("outcome", "")
    expected_cwe = s.get("expected_cwe", "")

    vt = s.get("model_vulnerability_type", "")
    if not vt:
        verdict = parse_verdict(raw)
        vt = verdict.get("vulnerability_type", "") or ""
    model_cwe = extract_cwe(vt)

    issues = []
    if outcome == "TP" and expected_cwe and expected_cwe.upper() != "N/A":
        if not cwe_matches(model_cwe, expected_cwe):
            issues.append("cwe_mismatch")
    verdict = parse_verdict(raw)
    hv = normalize_has_vulnerability(verdict.get("has_vulnerability"))
    if hv is None:
        issues.append("missing_verdict")
    if len(raw) < 200:
        issues.append("too_short")
    if len(raw) > 4000:
        issues.append("too_long")
    if "```json" not in raw and '"has_vulnerability"' not in raw:
        issues.append("no_json_block")
    cot_section = raw.split("```json")[0] if "```json" in raw else raw
    cot_lower = cot_section.lower()
    if hv is True and any(kw in cot_lower for kw in ["未发现漏洞", "不存在漏洞", "代码是安全的", "没有漏洞", "安全代码"]):
        issues.append("cot_json_inconsistent")
    if hv is False and any(kw in cot_lower for kw in ["存在漏洞", "存在安全漏洞", "这里存在"]):
        issues.append("cot_json_inconsistent")
    if len(raw) > 500:
        mid = raw[len(raw)//3:len(raw)//3+80]
        if mid and raw.count(mid) > 1:
            issues.append("repetition")
    if expected_present is False and predicted is True and model_cwe:
        issues.append("fp_with_cwe")

    return {
        "issues": issues,
        "model_cwe": model_cwe,
        "model_vt": vt,
        "verdict_hv": hv,
        "raw_len": len(raw),
    }


def compute_metrics(samples: list[dict]) -> dict:
    total = len(samples)
    tp = sum(1 for s in samples if s.get("outcome") == "TP")
    tn = sum(1 for s in samples if s.get("outcome") == "TN")
    fp = sum(1 for s in samples if s.get("outcome") == "FP")
    fn = sum(1 for s in samples if s.get("outcome") == "FN")

    cwe_mismatch = 0
    for s in samples:
        a = analyze_sample(s)
        if s.get("outcome") == "TP" and "cwe_mismatch" in a["issues"]:
            cwe_mismatch += 1

    issue_counts = {}
    for s in samples:
        a = analyze_sample(s)
        for iss in a["issues"]:
            issue_counts[iss] = issue_counts.get(iss, 0) + 1

    raw_lens = [len(s.get("raw_output", "") or "") for s in samples]
    elapsed = [s.get("elapsed_seconds", 0) or 0 for s in samples]
    vuln_total = tp + fn
    safe_total = tn + fp
    recall = tp / vuln_total if vuln_total else None
    fpr = fp / safe_total if safe_total else None
    accuracy = (tp + tn) / total if total else None
    strict_tp = tp - cwe_mismatch
    strict_recall = strict_tp / vuln_total if vuln_total else None

    return {
        "total": total,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "vuln_total": vuln_total, "safe_total": safe_total,
        "recall": recall, "fpr": fpr, "accuracy": accuracy,
        "cwe_mismatch": cwe_mismatch,
        "strict_tp": strict_tp,
        "strict_recall": strict_recall,
        "hallucination_rate": cwe_mismatch / tp if tp else None,
        "error_rate": (fp + fn) / total if total else None,
        "issue_counts": issue_counts,
        "avg_raw_len": sum(raw_lens) / total if total else 0,
        "max_raw_len": max(raw_lens) if raw_lens else 0,
        "min_raw_len": min(raw_lens) if raw_lens else 0,
        "avg_elapsed": sum(elapsed) / total if total else 0,
    }


def pct(x):
    return "—" if x is None else f"{x*100:.1f}%"


def delta(old, new, fmt="+.1f"):
    if old is None or new is None:
        return "—"
    return f"{(new-old)*100:{fmt}}"


def render_combined_summary(metrics: dict) -> str:
    lines = []
    lines.append("# 4 组对比综合汇总\n")
    lines.append("## 模型文件\n")
    for key, path in FILES.items():
        lines.append(f"- **{LABELS[key]}**: `{path.name}`")
    lines.append("")

    # ---- 总览矩阵 ----
    lines.append("## 1. 四模型总览\n")
    lines.append("| 指标 | 7B base | 7B ft | 3B base | 3B ft |")
    lines.append("|------|---------|-------|---------|-------|")
    keys = ["7b_base", "7b_ft", "3b_base", "3b_ft"]
    m = {k: metrics[k] for k in keys}

    def row(label, getter, fmt=str):
        vals = [fmt(getter(m[k])) for k in keys]
        lines.append(f"| {label} | " + " | ".join(vals) + " |")

    row("TP", lambda x: x["tp"])
    row("TN", lambda x: x["tn"])
    row("FP", lambda x: x["fp"])
    row("FN", lambda x: x["fn"])
    row("宽松 recall", lambda x: x["recall"], pct)
    row("严格 recall（CWE对）", lambda x: x["strict_recall"], pct)
    row("FPR", lambda x: x["fpr"], pct)
    row("accuracy", lambda x: x["accuracy"], pct)
    row("CWE 错标数", lambda x: x["cwe_mismatch"])
    row("幻觉率（CWE错/TP）", lambda x: x["hallucination_rate"], pct)
    row("失误率（FP+FN）/total", lambda x: x["error_rate"], pct)
    row("CoT-JSON不一致", lambda x: x["issue_counts"].get("cot_json_inconsistent", 0))
    row("文本重复", lambda x: x["issue_counts"].get("repetition", 0))
    row("缺JSON块", lambda x: x["issue_counts"].get("no_json_block", 0))
    row("FP带CWE", lambda x: x["issue_counts"].get("fp_with_cwe", 0))
    row("平均输出字符", lambda x: x["avg_raw_len"], lambda v: f"{v:.0f}")
    row("最长输出", lambda x: x["max_raw_len"])
    row("平均耗时(s)", lambda x: x["avg_elapsed"], lambda v: f"{v:.1f}")
    lines.append("")

    # ---- 4 组对比 ----
    lines.append("## 2. 四组对比\n")
    for a_key, b_key, title in PAIRS:
        a = metrics[a_key]
        b = metrics[b_key]
        lines.append(f"### {title}\n")
        lines.append(f"| 指标 | {LABELS[a_key]} | {LABELS[b_key]} | 差值 |")
        lines.append("|------|------|------|------|")
        lines.append(f"| TP | {a['tp']} | {b['tp']} | {b['tp']-a['tp']:+d} |")
        lines.append(f"| TN | {a['tn']} | {b['tn']} | {b['tn']-a['tn']:+d} |")
        lines.append(f"| FP | {a['fp']} | {b['fp']} | {b['fp']-a['fp']:+d} |")
        lines.append(f"| FN | {a['fn']} | {b['fn']} | {b['fn']-a['fn']:+d} |")
        lines.append(f"| 宽松 recall | {pct(a['recall'])} | {pct(b['recall'])} | {delta(a['recall'], b['recall'])}pp |")
        lines.append(f"| 严格 recall | {pct(a['strict_recall'])} | {pct(b['strict_recall'])} | {delta(a['strict_recall'], b['strict_recall'])}pp |")
        lines.append(f"| FPR | {pct(a['fpr'])} | {pct(b['fpr'])} | {delta(a['fpr'], b['fpr'])}pp |")
        lines.append(f"| accuracy | {pct(a['accuracy'])} | {pct(b['accuracy'])} | {delta(a['accuracy'], b['accuracy'])}pp |")
        lines.append(f"| CWE 错标 | {a['cwe_mismatch']} | {b['cwe_mismatch']} | {b['cwe_mismatch']-a['cwe_mismatch']:+d} |")
        lines.append(f"| 幻觉率 | {pct(a['hallucination_rate'])} | {pct(b['hallucination_rate'])} | {delta(a['hallucination_rate'], b['hallucination_rate'])}pp |")
        lines.append(f"| 失误率 | {pct(a['error_rate'])} | {pct(b['error_rate'])} | {delta(a['error_rate'], b['error_rate'])}pp |")
        lines.append(f"| CoT-JSON不一致 | {a['issue_counts'].get('cot_json_inconsistent',0)} | {b['issue_counts'].get('cot_json_inconsistent',0)} | {b['issue_counts'].get('cot_json_inconsistent',0)-a['issue_counts'].get('cot_json_inconsistent',0):+d} |")
        lines.append(f"| 平均输出字符 | {a['avg_raw_len']:.0f} | {b['avg_raw_len']:.0f} | {b['avg_raw_len']-a['avg_raw_len']:+.0f} |")
        lines.append(f"| 平均耗时 | {a['avg_elapsed']:.1f}s | {b['avg_elapsed']:.1f}s | {b['avg_elapsed']-a['avg_elapsed']:+.1f}s |")
        lines.append("")

    # ---- 关键结论 ----
    lines.append("## 3. 关键结论\n")
    # 7B 微调效果
    r1 = metrics["7b_base"]
    r2 = metrics["7b_ft"]
    r3 = metrics["3b_base"]
    r4 = metrics["3b_ft"]
    lines.append("### 3.1 微调效果（7B vs 3B）\n")
    lines.append(f"- 7B 微调：recall {pct(r1['recall'])}→{pct(r2['recall'])}（{delta(r1['recall'],r2['recall'])}pp），"
                 f"FP {r1['fp']}→{r2['fp']}，FN {r1['fn']}→{r2['fn']}")
    lines.append(f"- 3B 微调：recall {pct(r3['recall'])}→{pct(r4['recall'])}（{delta(r3['recall'],r4['recall'])}pp），"
                 f"FP {r3['fp']}→{r4['fp']}，FN {r3['fn']}→{r4['fn']}")
    lines.append(f"- 7B 微调后幻觉率 {pct(r1['hallucination_rate'])}→{pct(r2['hallucination_rate'])}，"
                 f"3B 微调后幻觉率 {pct(r3['hallucination_rate'])}→{pct(r4['hallucination_rate'])}")
    lines.append("")

    lines.append("### 3.2 模型规模效果\n")
    lines.append(f"- base 对比：7B recall {pct(r1['recall'])} vs 3B {pct(r3['recall'])}（{delta(r3['recall'],r1['recall'])}pp），"
                 f"7B accuracy {pct(r1['accuracy'])} vs 3B {pct(r3['accuracy'])}")
    lines.append(f"- ft 对比：7B recall {pct(r2['recall'])} vs 3B {pct(r4['recall'])}（{delta(r4['recall'],r2['recall'])}pp），"
                 f"7B accuracy {pct(r2['accuracy'])} vs 3B {pct(r4['accuracy'])}")
    lines.append(f"- base 幻觉率：7B {pct(r1['hallucination_rate'])} vs 3B {pct(r3['hallucination_rate'])}")
    lines.append(f"- ft 幻觉率：7B {pct(r2['hallucination_rate'])} vs 3B {pct(r4['hallucination_rate'])}")
    lines.append("")

    return "\n".join(lines)


def render_detail(a_data: dict, b_data: dict, title: str) -> str:
    a_by = {s["file"]: s for s in a_data["samples"]}
    b_by = {s["file"]: s for s in b_data["samples"]}
    all_files = sorted(set(a_by) | set(b_by))

    lines = [f"# {title}\n"]

    groups = {
        "both_wrong": [],
        "a_wrong_b_right": [],
        "a_right_b_wrong": [],
        "both_right_diff_cwe": [],
        "both_right_same": [],
    }
    for f in all_files:
        a_s = a_by.get(f, {})
        b_s = b_by.get(f, {})
        a_out = a_s.get("outcome", "")
        b_out = b_s.get("outcome", "")
        a_ok = a_out in ("TP", "TN")
        b_ok = b_out in ("TP", "TN")
        if not a_ok and not b_ok:
            groups["both_wrong"].append(f)
        elif not a_ok and b_ok:
            groups["a_wrong_b_right"].append(f)
        elif a_ok and not b_ok:
            groups["a_right_b_wrong"].append(f)
        else:
            a_cwe_ok = "cwe_mismatch" not in analyze_sample(a_s)["issues"]
            b_cwe_ok = "cwe_mismatch" not in analyze_sample(b_s)["issues"]
            if a_cwe_ok and b_cwe_ok:
                groups["both_right_same"].append(f)
            else:
                groups["both_right_diff_cwe"].append(f)

    titles = {
        "both_wrong": f"A. 两模型都错（{len(groups['both_wrong'])}）",
        "a_wrong_b_right": f"B. {LABELS.get('a','A')}错→{LABELS.get('b','B')}对（{len(groups['a_wrong_b_right'])}）",
        "a_right_b_wrong": f"C. {LABELS.get('a','A')}对→{LABELS.get('b','B')}错（{len(groups['a_right_b_wrong'])}）",
        "both_right_diff_cwe": f"D. 都对但CWE有差异（{len(groups['both_right_diff_cwe'])}）",
        "both_right_same": f"E. 完全一致（{len(groups['both_right_same'])}）",
    }

    # 动态设置标签
    a_label = a_data.get("label", "A")
    b_label = b_data.get("label", "B")
    titles = {
        "both_wrong": f"A. 两模型都错（{len(groups['both_wrong'])}）",
        "a_wrong_b_right": f"B. {a_label}错→{b_label}对（{len(groups['a_wrong_b_right'])}）",
        "a_right_b_wrong": f"C. {a_label}对→{b_label}错（{len(groups['a_right_b_wrong'])}）",
        "both_right_diff_cwe": f"D. 都对但CWE有差异（{len(groups['both_right_diff_cwe'])}）",
        "both_right_same": f"E. 完全一致（{len(groups['both_right_same'])}）",
    }

    for key in ["both_wrong", "a_wrong_b_right", "a_right_b_wrong",
                 "both_right_diff_cwe", "both_right_same"]:
        files = groups[key]
        if not files:
            continue
        lines.append(f"## {titles[key]}\n")
        for f in files:
            a_s = a_by.get(f, {})
            b_s = b_by.get(f, {})
            a_raw = a_s.get("raw_output", "") or "（无输出）"
            b_raw = b_s.get("raw_output", "") or "（无输出）"
            a_a = analyze_sample(a_s)
            b_a = analyze_sample(b_s)
            cat = a_s.get("category") or b_s.get("category", "")
            exp = "有漏洞" if a_s.get("expected_present") else "安全"
            exp_cwe = a_s.get("expected_cwe", "") or b_s.get("expected_cwe", "")
            lines.append(f"### {f}")
            lines.append(f"- 类别: `{cat}` | 期望: {exp} | 期望CWE: {exp_cwe}")
            lines.append(f"- {a_label}: outcome={a_s.get('outcome','?')} CWE={a_a['model_cwe'] or '—'} "
                         f"len={a_a['raw_len']} issues={a_a['issues'] or '无'}")
            lines.append(f"- {b_label}: outcome={b_s.get('outcome','?')} CWE={b_a['model_cwe'] or '—'} "
                         f"len={b_a['raw_len']} issues={b_a['issues'] or '无'}")
            lines.append(f"- {a_label}耗时: {a_s.get('elapsed_seconds',0):.1f}s | {b_label}耗时: {b_s.get('elapsed_seconds',0):.1f}s")
            lines.append("")
            lines.append(f"<details><summary>{a_label} 原始输出</summary>\n")
            lines.append("```\n" + a_raw + "\n```\n")
            lines.append("</details>\n")
            lines.append(f"<details><summary>{b_label} 原始输出</summary>\n")
            lines.append("```\n" + b_raw + "\n```\n")
            lines.append("</details>\n")
            lines.append("---\n")

    return "\n".join(lines)


def main():
    # 加载全部 4 个文件
    data = {}
    for key, path in FILES.items():
        if not path.exists():
            print(f"警告: {path} 不存在，跳过 {key}")
            continue
        d = json.loads(path.read_text(encoding="utf-8"))
        d["label"] = LABELS[key]
        data[key] = d
        print(f"已加载 {key}: {path.name} ({len(d['samples'])} 样本)")

    if len(data) < 4:
        print(f"错误: 需要 4 个文件，只找到 {len(data)} 个")
        return

    metrics = {k: compute_metrics(d["samples"]) for k, d in data.items()}

    # 综合汇总
    summary = render_combined_summary(metrics)
    summary_path = RESULTS_DIR / "compare_4way_summary.md"
    summary_path.write_text(summary, encoding="utf-8")
    print(f"\n综合汇总: {summary_path}")

    # 4 份详情
    for a_key, b_key, title in PAIRS:
        data[a_key]["label"] = LABELS[a_key]
        data[b_key]["label"] = LABELS[b_key]
        detail = render_detail(data[a_key], data[b_key], title)
        fname = f"compare_4way_{a_key}_vs_{b_key}.md"
        dpath = RESULTS_DIR / fname
        dpath.write_text(detail, encoding="utf-8")
        print(f"详情: {dpath}")

    print("\n=== 综合汇总预览 ===\n")
    print(summary)


if __name__ == "__main__":
    main()
