"""对比 baseline vs finetuned 评估结果，生成 markdown 报告。

用法：
    PYTHONPATH=. python experiments/exp_06_finetune/scripts/compare_results.py \
        --baseline results/exp_06_eval.baseline.<ts>.json \
        --finetuned results/exp_06_eval.finetuned.<ts>.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from collections import defaultdict


def load_results(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def metrics_line(m: dict) -> str:
    def pct(x):
        return "N/A" if x is None else f"{x*100:.2f}%"
    return (
        f"TP={m['tp']} TN={m['tn']} FP={m['fp']} FN={m['fn']} | "
        f"recall={pct(m['recall'])} accuracy={pct(m['accuracy'])} FPR={pct(m['false_positive_rate'])}"
    )


def per_sample_diff(baseline: dict, finetuned: dict) -> dict:
    """逐样本对比，找出 improved / regressed / unchanged。"""
    bl_by_file = {s["file"]: s for s in baseline["samples"]}
    ft_by_file = {s["file"]: s for s in finetuned["samples"]}

    improved, regressed, unchanged_same, unchanged_diff = [], [], [], []
    for f, ft_s in ft_by_file.items():
        bl_s = bl_by_file.get(f)
        if bl_s is None:
            continue
        bl_out = bl_s["outcome"]
        ft_out = ft_s["outcome"]
        if bl_out == ft_out:
            unchanged_same.append(f)
        else:
            # 判定是 improved 还是 regressed
            correct = {"TP", "TN"}
            if ft_out in correct and bl_out not in correct:
                improved.append((f, bl_out, ft_out))
            elif bl_out in correct and ft_out not in correct:
                regressed.append((f, bl_out, ft_out))
            else:
                # FP -> FN 或 FN -> FP，都算"变化但不改善"
                unchanged_diff.append((f, bl_out, ft_out))
    return {
        "improved": improved,
        "regressed": regressed,
        "unchanged_same": unchanged_same,
        "unchanged_diff": unchanged_diff,
    }


def category_breakdown(baseline: dict, finetuned: dict) -> dict:
    """按 category 分组统计 baseline/finetuned 的 TP/FN/FP/TN。"""
    def tally(samples):
        out = defaultdict(lambda: {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "pf": 0, "total": 0})
        for s in samples:
            cat = s.get("category") or "unknown"
            out[cat]["total"] += 1
            o = s["outcome"].lower()  # 归一为小写
            if o in ("tp", "tn", "fp", "fn"):
                out[cat][o] += 1
            elif o == "parse_fail":
                out[cat]["pf"] += 1
        return dict(out)

    return {"baseline": tally(baseline["samples"]), "finetuned": tally(finetuned["samples"])}


def render_markdown(baseline: dict, finetuned: dict, out_path: Path) -> str:
    bl_m = baseline["metrics"]
    ft_m = finetuned["metrics"]

    diff = per_sample_diff(baseline, finetuned)
    cats = category_breakdown(baseline, finetuned)

    def pct(x):
        return "N/A" if x is None else f"{x*100:.2f}%"

    def delta(old, new):
        if old is None or new is None:
            return "N/A"
        d = (new - old) * 100
        sign = "+" if d >= 0 else ""
        return f"{sign}{d:.2f}pp"

    lines = []
    lines.append("# exp_06_finetune 微调效果对比报告\n")
    lines.append(f"- baseline 文件: `{baseline.get('source_path', '')}`")
    lines.append(f"- finetuned 文件: `{finetuned.get('source_path', '')}`")
    lines.append(f"- 模型: {baseline.get('model', '')}  vs  {finetuned.get('model', '')}")
    lines.append("")

    # 总体指标
    lines.append("## 1. 总体指标\n")
    lines.append("| 指标 | Baseline | Finetuned | 变化 |")
    lines.append("|------|----------|-----------|------|")
    lines.append(f"| TP | {bl_m['tp']} | {ft_m['tp']} | {ft_m['tp']-bl_m['tp']:+d} |")
    lines.append(f"| TN | {bl_m['tn']} | {ft_m['tn']} | {ft_m['tn']-bl_m['tn']:+d} |")
    lines.append(f"| FP | {bl_m['fp']} | {ft_m['fp']} | {ft_m['fp']-bl_m['fp']:+d} |")
    lines.append(f"| FN | {bl_m['fn']} | {ft_m['fn']} | {ft_m['fn']-bl_m['fn']:+d} |")
    lines.append(f"| 召回率 (recall) | {pct(bl_m['recall'])} | {pct(ft_m['recall'])} | {delta(bl_m['recall'], ft_m['recall'])} |")
    lines.append(f"| 准确率 (accuracy) | {pct(bl_m['accuracy'])} | {pct(ft_m['accuracy'])} | {delta(bl_m['accuracy'], ft_m['accuracy'])} |")
    lines.append(f"| 误报率 (FPR) | {pct(bl_m['false_positive_rate'])} | {pct(ft_m['false_positive_rate'])} | {delta(bl_m['false_positive_rate'], ft_m['false_positive_rate'])} |")
    bl_es = bl_m["elapsed_stats"]
    ft_es = ft_m["elapsed_stats"]
    lines.append(f"| 平均耗时 | {bl_es['avg']}s | {ft_es['avg']}s | {ft_es['avg']-bl_es['avg']:+.2f}s |")
    lines.append("")

    # 逐样本变化
    lines.append("## 2. 逐样本变化\n")
    lines.append(f"- 改善样本数（错误→正确）: **{len(diff['improved'])}**")
    lines.append(f"- 退化样本数（正确→错误）: **{len(diff['regressed'])}**")
    lines.append(f"- 同类错误变化（FP↔FN）: {len(diff['unchanged_diff'])}")
    lines.append(f"- 保持不变: {len(diff['unchanged_same'])}")
    lines.append("")

    if diff["improved"]:
        lines.append("### 2.1 改善的样本（错误 → 正确）\n")
        lines.append("| 文件 | Baseline | Finetuned |")
        lines.append("|------|----------|-----------|")
        for f, bo, fo in sorted(diff["improved"]):
            lines.append(f"| {f} | {bo} | {fo} |")
        lines.append("")

    if diff["regressed"]:
        lines.append("### 2.2 退化的样本（正确 → 错误）\n")
        lines.append("| 文件 | Baseline | Finetuned |")
        lines.append("|------|----------|-----------|")
        for f, bo, fo in sorted(diff["regressed"]):
            lines.append(f"| {f} | {bo} | {fo} |")
        lines.append("")

    if diff["unchanged_diff"]:
        lines.append("### 2.3 同类错误变化（FP↔FN，仍错误）\n")
        lines.append("| 文件 | Baseline | Finetuned |")
        lines.append("|------|----------|-----------|")
        for f, bo, fo in sorted(diff["unchanged_diff"]):
            lines.append(f"| {f} | {bo} | {fo} |")
        lines.append("")

    # 分类别统计
    lines.append("## 3. 分类别统计\n")
    lines.append("| 类别 | Baseline (TP/TN/FP/FN/PF) | Finetuned (TP/TN/FP/FN/PF) |")
    lines.append("|------|---------------------------|----------------------------|")
    all_cats = sorted(set(cats["baseline"].keys()) | set(cats["finetuned"].keys()))
    for c in all_cats:
        b = cats["baseline"].get(c, {"tp":0,"tn":0,"fp":0,"fn":0,"pf":0,"total":0})
        f = cats["finetuned"].get(c, {"tp":0,"tn":0,"fp":0,"fn":0,"pf":0,"total":0})
        b_str = f"{b['tp']}/{b['tn']}/{b['fp']}/{b['fn']}/{b['pf']} (n={b['total']})"
        f_str = f"{f['tp']}/{f['tn']}/{f['fp']}/{f['fn']}/{f['pf']} (n={f['total']})"
        lines.append(f"| {c} | {b_str} | {f_str} |")
    lines.append("")

    # 仍然失败的样本
    lines.append("## 4. Finetuned 仍然失败的样本\n")
    ft_fails = [s for s in finetuned["samples"] if s["outcome"] in ("FN", "FP", "parse_fail")]
    if ft_fails:
        lines.append("| 文件 | 期望 | 预测 | 结果 | 类别 | CWE |")
        lines.append("|------|------|------|------|------|-----|")
        for s in sorted(ft_fails, key=lambda x: (x["outcome"], x["file"])):
            exp = "有漏洞" if s["expected_present"] else "安全"
            pred = str(s.get("model_has_vulnerability"))
            lines.append(f"| {s['file']} | {exp} | {pred} | {s['outcome']} | {s.get('category','')} | {s.get('expected_cwe','')} |")
    else:
        lines.append("无失败样本。")
    lines.append("")

    text = "\n".join(lines)
    out_path.write_text(text, encoding="utf-8")
    return text


def main():
    parser = argparse.ArgumentParser(description="对比 baseline vs finetuned 评估结果")
    parser.add_argument("--baseline", type=Path, required=True, help="baseline 结果 JSON")
    parser.add_argument("--finetuned", type=Path, required=True, help="finetuned 结果 JSON")
    parser.add_argument("--out", type=Path, default=None, help="输出 markdown 路径（默认与 finetuned 同目录）")
    args = parser.parse_args()

    bl = load_results(args.baseline)
    ft = load_results(args.finetuned)
    bl["source_path"] = str(args.baseline)
    ft["source_path"] = str(args.finetuned)

    out = args.out or args.finetuned.with_suffix(".compare.md")
    text = render_markdown(bl, ft, out)
    print(f"对比报告已生成: {out}")
    print("\n=== 预览 ===\n")
    print(text[:2000])


if __name__ == "__main__":
    main()
