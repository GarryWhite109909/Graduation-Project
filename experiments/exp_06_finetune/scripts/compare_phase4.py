"""Phase 4 对比：Prompt Distillation vs Phase 1/2/3

自动发现 results/exp_06_eval.phase4_*.json，与 Phase 1/2/3 结果对比，
判断 Prompt Distillation 是否进一步提升。

用法：
    PYTHONPATH=. /home/zane/miniconda3/envs/AI/bin/python \
        experiments/exp_06_finetune/scripts/compare_phase4.py

输出：
    experiments/exp_06_finetune/results/phase4_summary.md
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

sys.path.insert(0, str(Path(__file__).parent))
from compare_phase1_sweep import (
    compute_metrics,
    discover_eval_files,
    pct,
)

RESULTS_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/results"
LOGS_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/logs"
OUTPUT_MD = RESULTS_DIR / "phase4_summary.md"

BASELINE_TAG = "lr1e-5_base"


def discover_phase4_eval_files() -> dict[str, Path]:
    """发现所有 exp_06_eval.phase4_*.json"""
    found = {}
    for p in sorted(RESULTS_DIR.glob("exp_06_eval.phase4_*.json")):
        m = re.match(r"exp_06_eval\.phase4_(.+?)\.\d{8}_\d{6}\.json", p.name)
        if m:
            tag = m.group(1)
            found[tag] = p
    return found


def discover_phase3_eval_files() -> dict[str, Path]:
    """发现 Phase 3 评估结果"""
    found = {}
    for p in sorted(RESULTS_DIR.glob("exp_06_eval.knitlm_merged.*.json")):
        found["knitlm_merged"] = p
    return found


def discover_phase2_eval_files() -> dict[str, Path]:
    """发现 Phase 2 评估结果"""
    found = {}
    for p in sorted(RESULTS_DIR.glob("exp_06_eval.phase2_*.json")):
        m = re.match(r"exp_06_eval\.phase2_(.+?)\.\d{8}_\d{6}\.json", p.name)
        if m:
            found[m.group(1)] = p
    return found


def discover_phase4_train_logs() -> dict[str, dict]:
    """从 Phase 4 训练日志提取 dev_loss/train_loss"""
    results = {}
    for p in LOGS_DIR.glob("train_log_pd_*.json"):
        try:
            data = json.loads(p.read_text())
        except Exception:
            continue
        metrics = data.get("metrics", {})
        dev_loss = None
        for entry in data.get("log_history", []):
            if "eval_loss" in entry:
                dev_loss = entry["eval_loss"]
        results["ollama30b"] = {
            "dev_loss": dev_loss,
            "train_loss": metrics.get("train_loss"),
            "train_runtime": metrics.get("train_runtime"),
        }
    return results


def main():
    phase4_evals = discover_phase4_eval_files()
    phase3_evals = discover_phase3_eval_files()
    phase2_evals = discover_phase2_eval_files()
    phase1_evals = discover_eval_files()
    phase4_logs = discover_phase4_train_logs()

    print("发现的 Phase 4 评估结果：")
    for tag, path in phase4_evals.items():
        print(f"  {tag}: {path.name}")

    if not phase4_evals:
        print("\n⚠️ 未发现 Phase 4 评估结果。请先运行：")
        print("   bash experiments/exp_06_finetune/scripts/run_phase4_prompt_distillation.sh all")
        return

    # 计算各阶段指标
    all_metrics = []

    # Phase 1 baseline
    if BASELINE_TAG in phase1_evals:
        data = json.loads(phase1_evals[BASELINE_TAG].read_text())
        m = compute_metrics(data.get("samples", []))
        m["label"] = "Phase 1 baseline (r=8, e=1)"
        m["phase"] = "phase1"
        all_metrics.append(m)

    # Phase 2
    for tag, path in phase2_evals.items():
        data = json.loads(path.read_text())
        m = compute_metrics(data.get("samples", []))
        m["label"] = f"Phase 2 ({tag})"
        m["phase"] = "phase2"
        all_metrics.append(m)

    # Phase 3
    if "knitlm_merged" in phase3_evals:
        data = json.loads(phase3_evals["knitlm_merged"].read_text())
        m = compute_metrics(data.get("samples", []))
        m["label"] = "Phase 3 KnItLM"
        m["phase"] = "phase3"
        all_metrics.append(m)

    # Phase 4
    base_metrics = next((x for x in all_metrics if x["phase"] == "phase1"), None)
    phase3_metrics = next((x for x in all_metrics if x["phase"] == "phase3"), None)
    for tag, path in phase4_evals.items():
        data = json.loads(path.read_text())
        m = compute_metrics(data.get("samples", []))
        m["label"] = f"Phase 4 PD ({tag})"
        m["phase"] = "phase4"
        if tag in phase4_logs:
            m.update(phase4_logs[tag])
        all_metrics.append(m)

    # ---- 生成 markdown ----
    lines = []
    lines.append("# Phase 4 对比：Prompt Distillation vs Phase 1/2/3\n")
    lines.append("> 目标：验证 Prompt Distillation 自蒸馏是否在 Phase 3 基础上进一步提升。\n")
    lines.append("- Student: Phase 3 KnItLM 合并模型（路线 B：知识注入 + 蒸馏叠加）")
    lines.append("- Teacher: qwen3-coder:30b (Ollama)")
    lines.append("- Loss: (1-α)×CE + α×KL, α=0.5, T=2.0")
    lines.append("- 测试集：exp_04_hard_samples 87 段\n")

    # 评估侧对比
    lines.append("## 1. 评估侧：exp_04 87 段测试集指标\n")
    lines.append("| 配置 | TP | TN | FP | FN | 宽松 recall | 严格 recall | FPR | accuracy | CWE错标 | 幻觉率 |")
    lines.append("|------|----|----|----|----|-------------|-------------|-----|----------|---------|--------|")
    for m in all_metrics:
        lines.append(
            f"| {m['label']} | {m.get('tp','—')} | {m.get('tn','—')} | {m.get('fp','—')} | "
            f"{m.get('fn','—')} | {pct(m.get('recall'))} | {pct(m.get('strict_recall'))} | "
            f"{pct(m.get('fpr'))} | {pct(m.get('accuracy'))} | {m.get('cwe_mismatch','—')} | "
            f"{pct(m.get('hallucination_rate'))} |"
        )
    lines.append("")

    # 与 Phase 3 的差值（因为 Phase 4 基于 Phase 3）
    if phase3_metrics:
        lines.append("## 2. 与 Phase 3 的差值（Phase 4 基于 Phase 3）\n")
        lines.append("| 配置 | Δrecall | Δstrict_recall | ΔFPR | Δaccuracy | ΔCWE错标 |")
        lines.append("|------|---------|----------------|------|-----------|---------|")
        for m in all_metrics:
            if m["phase"] != "phase4":
                continue
            def delta(key):
                b = phase3_metrics.get(key)
                c = m.get(key)
                if b is None or c is None:
                    return "—"
                return f"{(c-b)*100:+.1f}pp"
            def delta_int(key):
                b = phase3_metrics.get(key, 0) or 0
                c = m.get(key, 0) or 0
                return f"{c-b:+d}"
            lines.append(
                f"| {m['label']} | {delta('recall')} | {delta('strict_recall')} | "
                f"{delta('fpr')} | {delta('accuracy')} | {delta_int('cwe_mismatch')} |"
            )
        lines.append("")

    # 与 Phase 1 baseline 的总差值
    if base_metrics:
        lines.append("## 3. 与 Phase 1 baseline 的总差值\n")
        lines.append("| 配置 | Δrecall | Δstrict_recall | ΔFPR | Δaccuracy | ΔCWE错标 |")
        lines.append("|------|---------|----------------|------|-----------|---------|")
        for m in all_metrics:
            if m["phase"] == "phase1":
                continue
            def delta(key):
                b = base_metrics.get(key)
                c = m.get(key)
                if b is None or c is None:
                    return "—"
                return f"{(c-b)*100:+.1f}pp"
            def delta_int(key):
                b = base_metrics.get(key, 0) or 0
                c = m.get(key, 0) or 0
                return f"{c-b:+d}"
            lines.append(
                f"| {m['label']} | {delta('recall')} | {delta('strict_recall')} | "
                f"{delta('fpr')} | {delta('accuracy')} | {delta_int('cwe_mismatch')} |"
            )
        lines.append("")

    # 结论
    lines.append("## 4. 结论\n")
    phase4_metrics = [m for m in all_metrics if m["phase"] == "phase4"]
    if phase4_metrics and phase3_metrics:
        p4 = phase4_metrics[0]
        d_strict_vs_p3 = (p4.get("strict_recall", 0) or 0) - (phase3_metrics.get("strict_recall", 0) or 0)
        d_fpr_vs_p3 = (p4.get("fpr", 0) or 0) - (phase3_metrics.get("fpr", 0) or 0)
        d_hallu_vs_p3 = (p4.get("hallucination_rate", 0) or 0) - (phase3_metrics.get("hallucination_rate", 0) or 0)
        d_strict_vs_p1 = (p4.get("strict_recall", 0) or 0) - (base_metrics.get("strict_recall", 0) or 0)

        lines.append(f"- **Phase 4 vs Phase 3**：严格 recall {d_strict_vs_p3*100:+.1f}pp, FPR {d_fpr_vs_p3*100:+.1f}pp, 幻觉率 {d_hallu_vs_p3*100:+.1f}pp")
        lines.append(f"- **Phase 4 vs Phase 1**：严格 recall {d_strict_vs_p1*100:+.1f}pp")
        lines.append("")

        # 多维判定（2026-07-19 修订）：
        # 1. strict_recall 阈值 +1pp（原 +2pp 对 Phase 3 已大幅突破后的增量优化过高）
        # 2. FPR 守门：Phase 3 已压到 3.8%，不允许反弹超过 +3pp
        # 3. 幻觉率守门：Phase 3 已压到 29.1%，不允许反弹超过 +5pp
        STRICT_RECALL_GAIN_THRESHOLD = 0.01
        FPR_GUARD_THRESHOLD = 0.03
        HALLU_GUARD_THRESHOLD = 0.05

        fpr_ok = d_fpr_vs_p3 <= FPR_GUARD_THRESHOLD
        hallu_ok = d_hallu_vs_p3 <= HALLU_GUARD_THRESHOLD
        guards_ok = fpr_ok and hallu_ok
        strict_gain = d_strict_vs_p3 > STRICT_RECALL_GAIN_THRESHOLD
        strict_flat = d_strict_vs_p3 > 0

        if strict_gain and guards_ok:
            lines.append(
                f"**判定**：✅ **Phase 4 PD 有效**：strict_recall {d_strict_vs_p3*100:+.1f}pp "
                f"(>+{STRICT_RECALL_GAIN_THRESHOLD*100:.0f}pp 阈值)，FPR {d_fpr_vs_p3*100:+.1f}pp、"
                f"幻觉率 {d_hallu_vs_p3*100:+.1f}pp 均守门通过。"
            )
        elif strict_flat and guards_ok:
            lines.append(
                f"**判定**：⚠️ **Phase 4 PD 小幅提升**：strict_recall {d_strict_vs_p3*100:+.1f}pp "
                f"(<+{STRICT_RECALL_GAIN_THRESHOLD*100:.0f}pp 阈值)，FPR/幻觉率未恶化。"
                f"建议多种子验证稳定性后再下结论。"
            )
        elif not guards_ok:
            failed = []
            if not fpr_ok:
                failed.append(f"FPR 反弹 {d_fpr_vs_p3*100:+.1f}pp > +{FPR_GUARD_THRESHOLD*100:.0f}pp")
            if not hallu_ok:
                failed.append(f"幻觉率反弹 {d_hallu_vs_p3*100:+.1f}pp > +{HALLU_GUARD_THRESHOLD*100:.0f}pp")
            lines.append(
                f"**判定**：❌ **Phase 4 PD 精度退化**：{ '；'.join(failed) }。"
                f"即使 strict_recall {d_strict_vs_p3*100:+.1f}pp 也不可接受——"
                f"Phase 3 KnItLM 的精度优势被蒸馏破坏。建议：① 降低 α（0.5→0.2）减弱 KL 主导；"
                f"② 降 lr（1e-4→5e-5）；③ 提高 T（2.0→4.0）放宽 teacher 软标签分布。"
            )
        else:
            lines.append(
                f"**判定**：⚠️ **Phase 4 PD 未带来提升**：strict_recall {d_strict_vs_p3*100:+.1f}pp，"
                f"FPR {d_fpr_vs_p3*100:+.1f}pp。可能需要调整 α/T 或换 teacher 模型。"
            )
        lines.append("")
        lines.append(
            f"> **判定标准**（2026-07-19 修订）：strict_recall 阈值 +{STRICT_RECALL_GAIN_THRESHOLD*100:.0f}pp "
            f"（原 +2pp 对 Phase 3 已大幅突破后的增量优化过高），"
            f"FPR 守门 ≤+{FPR_GUARD_THRESHOLD*100:.0f}pp（Phase 3 已压到 3.8%，不允许反弹太多），"
            f"幻觉率守门 ≤+{HALLU_GUARD_THRESHOLD*100:.0f}pp（Phase 3 已压到 29.1%）。"
            f"三维中任一不过即视为退化。"
        )
        lines.append("")

    OUTPUT_MD.write_text("\n".join(lines))
    print(f"\n✅ 对比报告已生成：{OUTPUT_MD}")


if __name__ == "__main__":
    main()
