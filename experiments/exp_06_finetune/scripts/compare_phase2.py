"""Phase 2 对比：r=32 + rsLoRA + e=2 vs Phase 1 baseline (r=8, e=1)

自动发现 results/exp_06_eval.phase2_*.json 和 phase1_lr1e-5_base.*.json，
生成对比表，判断 Phase 2 是否带来严格 recall 提升。

用法：
    PYTHONPATH=. /home/zane/miniconda3/envs/AI/bin/python \
        experiments/exp_06_finetune/scripts/compare_phase2.py

输出：
    experiments/exp_06_finetune/results/phase2_summary.md
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

# 复用 compare_phase1_sweep.py 的指标计算逻辑
sys.path.insert(0, str(Path(__file__).parent))
from compare_phase1_sweep import (
    compute_metrics,
    discover_eval_files,
    pct,
)

RESULTS_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/results"
LOGS_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/logs"
OUTPUT_MD = RESULTS_DIR / "phase2_summary.md"

# Phase 2 配置（run_phase2_eval.sh 中定义）
PHASE2_CONFIGS = [
    "phase2_r32_lr1e-5_rslora_e2",
    "phase2_r32_lr1e-5_rslora_dora_e2",
]

PHASE2_LABELS = {
    "phase2_r32_lr1e-5_rslora_e2": "Phase 2: r=32 + rsLoRA + e=2",
    "phase2_r32_lr1e-5_rslora_dora_e2": "Phase 2: r=32 + rsLoRA + DoRA + e=2",
}

# Phase 1 baseline（最优配置，作为对比基准）
BASELINE_TAG = "lr1e-5_base"


def discover_phase2_eval_files() -> dict[str, Path]:
    """发现所有 exp_06_eval.phase2_*.json，返回 {tag: path}。"""
    found = {}
    for p in sorted(RESULTS_DIR.glob("exp_06_eval.phase2_*.json")):
        m = re.match(r"exp_06_eval\.phase2_(.+?)\.\d{8}_\d{6}\.json", p.name)
        if m:
            tag = m.group(1)
            found[tag] = p
    return found


def discover_phase2_train_logs() -> dict[str, dict]:
    """从训练日志提取 Phase 2 的 dev_loss。"""
    results = {}
    for p in LOGS_DIR.glob("train_log_r32_e2_lr1e-05*.json"):
        try:
            data = json.loads(p.read_text())
        except Exception:
            continue
        args = data.get("args", {})
        suffix = args.get("output_suffix", "")
        if "phase2" not in suffix:
            continue
        # 区分 run1 (rsLoRA only) 和 run2 (+ DoRA)
        if "dora" in suffix:
            tag = "r32_lr1e-5_rslora_dora_e2"
        else:
            tag = "r32_lr1e-5_rslora_e2"

        metrics = data.get("metrics", {})
        train_loss = metrics.get("train_loss", 0)
        train_runtime = metrics.get("train_runtime", 0)

        # dev_loss 在 log_history 里，取最小值（best metric）
        dev_loss = None
        for entry in data.get("log_history", []):
            if "eval_loss" in entry:
                if dev_loss is None or entry["eval_loss"] < dev_loss:
                    dev_loss = entry["eval_loss"]

        results[tag] = {
            "dev_loss": dev_loss,
            "train_loss": train_loss,
            "train_runtime": train_runtime,
            "lr": args.get("lr", 1e-5),
            "use_rslora": args.get("use_rslora", True),
            "use_dora": args.get("use_dora", False),
        }
    return results


def discover_phase1_baseline() -> dict | None:
    """加载 Phase 1 baseline (lr=1e-5) 的评估结果。"""
    eval_files = discover_eval_files()
    if BASELINE_TAG in eval_files:
        data = json.loads(eval_files[BASELINE_TAG].read_text())
        samples = data.get("samples", [])
        m = compute_metrics(samples)
        m["tag"] = BASELINE_TAG
        m["label"] = "Phase 1 baseline (r=8, e=1, lr=1e-5)"
        m["has_eval"] = True
        return m
    return None


def main():
    phase2_evals = discover_phase2_eval_files()
    phase2_logs = discover_phase2_train_logs()
    baseline = discover_phase1_baseline()

    print("发现的 Phase 2 评估结果：")
    for tag, path in phase2_evals.items():
        print(f"  {tag}: {path.name}")
    if not phase2_evals:
        print("  (无)")
    print(f"\n发现的 Phase 2 训练日志：")
    for tag, info in phase2_logs.items():
        print(f"  {tag}: dev_loss={info['dev_loss']}, train_loss={info['train_loss']:.4f}")
    if not phase2_logs:
        print("  (无)")

    if not phase2_evals and not phase2_logs:
        print("\n⚠️ 未发现任何 Phase 2 结果。")
        print("   请先运行：bash experiments/exp_06_finetune/scripts/run_phase2_sft.sh run1")
        print("   然后：bash experiments/exp_06_finetune/scripts/run_phase2_eval.sh")
        return

    # 计算 Phase 2 指标
    phase2_metrics = {}
    for tag in PHASE2_CONFIGS:
        # tag 格式: phase2_r32_lr1e-5_rslora_e2
        # eval 文件 tag 不含 phase2_ 前缀（discover 从文件名提取）
        eval_tag = tag.replace("phase2_", "")
        m = {"tag": tag, "label": PHASE2_LABELS.get(tag, tag), "has_eval": False}
        if eval_tag in phase2_evals:
            data = json.loads(phase2_evals[eval_tag].read_text())
            samples = data.get("samples", [])
            m.update(compute_metrics(samples))
            m["has_eval"] = True
        # 匹配训练日志（tag 去掉 phase2_ 前缀）
        log_tag = tag.replace("phase2_", "")
        if log_tag in phase2_logs:
            m.update(phase2_logs[log_tag])
        phase2_metrics[tag] = m

    # ---- 生成 markdown ----
    lines = []
    lines.append("# Phase 2 对比：r=32 + rsLoRA + e=2 vs Phase 1 baseline\n")
    lines.append("> 目标：验证增大 LoRA rank (r=8→32) + rsLoRA + 双 epoch 是否提升严格 recall。\n")
    lines.append("- 基座：Qwen2.5-Coder-7B-Instruct (4bit QLoRA)")
    lines.append("- Phase 1 baseline: r=8, alpha=16, e=1, lr=1e-5")
    lines.append("- Phase 2: r=32, alpha=64, rsLoRA, e=2, lr=1e-5")
    lines.append(f"- 训练数据：train_chatml_v2.jsonl (700 train + 123 dev)")
    lines.append(f"- 测试集：exp_04_hard_samples 87 段")
    lines.append(f"- RDNA4 优化：AOTRITON attention + 部分 TunableOp (46/1104 GEMM)\n")

    # 训练侧对比
    lines.append("## 1. 训练侧：dev_loss / train_loss 对比\n")
    lines.append("| 配置 | r | rsLoRA | DoRA | epochs | dev_loss | train_loss | 训练耗时 | step time |")
    lines.append("|------|---|--------|------|--------|----------|------------|----------|-----------|")
    if baseline:
        lines.append(f"| {baseline['label']} | 8 | | | 1 | — | — | — | 73-76s |")
    for tag in PHASE2_CONFIGS:
        m = phase2_metrics[tag]
        dev_loss = f"{m['dev_loss']:.4f}" if m.get("dev_loss") else "—"
        train_loss = f"{m['train_loss']:.4f}" if m.get("train_loss") else "—"
        runtime = f"{m['train_runtime']/60:.1f}min" if m.get("train_runtime") else "—"
        lines.append(f"| {m['label']} | 32 | ✓ | {'✓' if m.get('use_dora') else ''} | 2 | {dev_loss} | {train_loss} | {runtime} | ~31s |")
    lines.append("")

    # 评估侧对比
    lines.append("## 2. 评估侧：exp_04 87 段测试集指标\n")
    eval_tags = [t for t in PHASE2_CONFIGS if phase2_metrics[t].get("has_eval")]
    if not eval_tags:
        lines.append("⚠️ 暂无 Phase 2 评估结果。请运行 `run_phase2_eval.sh`。\n")
    else:
        lines.append("| 配置 | TP | TN | FP | FN | 宽松 recall | 严格 recall | FPR | accuracy | CWE错标 | 幻觉率 | CoT不一致 | 平均耗时 |")
        lines.append("|------|----|----|----|----|-------------|-------------|-----|----------|---------|--------|-----------|----------|")
        if baseline:
            m = baseline
            lines.append(
                f"| **{m['label']}** | {m.get('tp','—')} | {m.get('tn','—')} | {m.get('fp','—')} | {m.get('fn','—')} | "
                f"**{pct(m.get('recall'))}** | **{pct(m.get('strict_recall'))}** | **{pct(m.get('fpr'))}** | "
                f"**{pct(m.get('accuracy'))}** | {m.get('cwe_mismatch','—')} | {pct(m.get('hallucination_rate'))} | "
                f"{m.get('issue_counts',{}).get('cot_json_inconsistent', 0)} | "
                f"{m.get('avg_elapsed',0):.1f}s |"
            )
        for tag in eval_tags:
            m = phase2_metrics[tag]
            lines.append(
                f"| {m['label']} | {m.get('tp','—')} | {m.get('tn','—')} | {m.get('fp','—')} | {m.get('fn','—')} | "
                f"{pct(m.get('recall'))} | {pct(m.get('strict_recall'))} | {pct(m.get('fpr'))} | "
                f"{pct(m.get('accuracy'))} | {m.get('cwe_mismatch','—')} | {pct(m.get('hallucination_rate'))} | "
                f"{m.get('issue_counts',{}).get('cot_json_inconsistent', 0)} | "
                f"{m.get('avg_elapsed',0):.1f}s |"
            )
        lines.append("")

        # 与 baseline 的差值
        if baseline:
            lines.append("## 3. 与 Phase 1 baseline 的差值\n")
            lines.append("| 配置 | Δrecall | Δstrict_recall | ΔFPR | Δaccuracy | ΔCWE错标 | Δ幻觉率 |")
            lines.append("|------|---------|----------------|------|-----------|---------|---------|")
            for tag in eval_tags:
                m = phase2_metrics[tag]
                dr = (m.get('recall', 0) - baseline.get('recall', 0)) * 100 if m.get('recall') and baseline.get('recall') else 0
                dsr = (m.get('strict_recall', 0) - baseline.get('strict_recall', 0)) * 100 if m.get('strict_recall') and baseline.get('strict_recall') else 0
                dfpr = (m.get('fpr', 0) - baseline.get('fpr', 0)) * 100 if m.get('fpr') and baseline.get('fpr') else 0
                dacc = (m.get('accuracy', 0) - baseline.get('accuracy', 0)) * 100 if m.get('accuracy') and baseline.get('accuracy') else 0
                dcwe = (m.get('cwe_mismatch', 0) - baseline.get('cwe_mismatch', 0))
                dhall = ((m.get('hallucination_rate', 0) - baseline.get('hallucination_rate', 0)) * 100) if m.get('hallucination_rate') is not None and baseline.get('hallucination_rate') is not None else 0
                lines.append(
                    f"| {m['label']} | {dr:+.1f}pp | {dsr:+.1f}pp | {dfpr:+.1f}pp | {dacc:+.1f}pp | {dcwe:+d} | {dhall:+.1f}pp |"
                )
            lines.append("")

    # 结论与下一步
    lines.append("## 4. 结论与下一步建议\n")
    if eval_tags and baseline:
        best_tag = max(eval_tags, key=lambda t: phase2_metrics[t].get('strict_recall', 0) or 0)
        best = phase2_metrics[best_tag]
        delta_sr = (best.get('strict_recall', 0) - baseline.get('strict_recall', 0)) * 100
        delta_fpr = (best.get('fpr', 0) - baseline.get('fpr', 0)) * 100

        if delta_sr > 2 and delta_fpr <= 5:
            verdict = "✅ **Phase 2 有效**：严格 recall 提升 >2pp 且 FPR 未显著增加"
            next_step = "继续 Phase 3（KnItLM 知识注入）"
        elif delta_sr > 0:
            verdict = "⚠️ **Phase 2 提升有限**：严格 recall 有小幅提升但不显著"
            next_step = "考虑跳过 Phase 2 run2 (DoRA)，直接进 Phase 3"
        else:
            verdict = "❌ **Phase 2 无提升**：r=32 + rsLoRA + e=2 未能提升严格 recall"
            next_step = "分析失败原因（数据质量？过拟合？）再决定是否进 Phase 3"

        lines.append(f"- 最佳配置：{best['label']}")
        lines.append(f"- 严格 recall 差值：{delta_sr:+.1f}pp")
        lines.append(f"- FPR 差值：{delta_fpr:+.1f}pp")
        lines.append(f"- 判定：{verdict}")
        lines.append(f"- 下一步：{next_step}")
    else:
        lines.append("- 待 Phase 2 评估完成后自动生成结论")

    OUTPUT_MD.write_text("\n".join(lines))
    print(f"\n✅ 对比报告已生成：{OUTPUT_MD}")
    print("\n摘要：")
    print("".join(lines[-10:]))


if __name__ == "__main__":
    main()
