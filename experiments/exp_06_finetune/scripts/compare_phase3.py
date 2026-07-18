"""Phase 3 对比：KnItLM 知识注入 vs Phase 1/2 baseline

自动发现 results/exp_06_eval.knitlm_merged.*.json，与 Phase 1 baseline 和 Phase 2 结果对比，
判断 KnItLM CPT 是否带来严格 recall 提升（CWE 错标减少）。

用法：
    PYTHONPATH=. /home/zane/miniconda3/envs/AI/bin/python \
        experiments/exp_06_finetune/scripts/compare_phase3.py

输出：
    experiments/exp_06_finetune/results/phase3_summary.md
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
OUTPUT_MD = RESULTS_DIR / "phase3_summary.md"

# Phase 1 baseline（最优配置，作为对比基准）
BASELINE_TAG = "lr1e-5_base"


def discover_phase3_eval_files() -> dict[str, Path]:
    """发现所有 exp_06_eval.knitlm_merged.*.json，返回 {tag: path}。"""
    found = {}
    for p in sorted(RESULTS_DIR.glob("exp_06_eval.knitlm_merged.*.json")):
        found["knitlm_merged"] = p
    return found


def discover_phase3_train_logs() -> dict[str, dict]:
    """从 CPT 训练日志提取 Phase 3 的 dev_loss/train_loss。"""
    results = {}
    for p in LOGS_DIR.glob("phase3_knitlm_cpt_*.json"):
        try:
            data = json.loads(p.read_text())
        except Exception:
            continue
        metrics = data.get("metrics", {})
        dev_loss = None
        for entry in data.get("log_history", []):
            if "eval_loss" in entry:
                dev_loss = entry["eval_loss"]
        results["knitlm_merged"] = {
            "dev_loss": dev_loss,
            "train_loss": metrics.get("train_loss"),
            "train_runtime": metrics.get("train_runtime"),
        }
    # 如果没有 json 日志，从 run_knitlm_cpt.sh 的文本日志解析
    if "knitlm_merged" not in results:
        for p in LOGS_DIR.glob("phase3_knitlm_cpt_*.log"):
            try:
                text = p.read_text(errors="ignore")
            except Exception:
                continue
            # 解析 "{'train_runtime': '5273', ... 'train_loss': '0.5132', ...}"
            m = re.search(r"\{'train_runtime':\s*'([\d.]+)'.*?'train_loss':\s*'([\d.]+)'", text)
            if m:
                results["knitlm_merged"] = {
                    "dev_loss": None,
                    "train_loss": float(m.group(2)),
                    "train_runtime": float(m.group(1)),
                }
                # 解析 eval_loss
                m2 = re.search(r"'eval_loss':\s*'([\d.]+)'", text)
                if m2:
                    results["knitlm_merged"]["dev_loss"] = float(m2.group(1))
                break
    return results


def main():
    phase3_evals = discover_phase3_eval_files()
    phase3_logs = discover_phase3_train_logs()
    phase1_evals = discover_eval_files()

    print("发现的 Phase 3 评估结果：")
    for tag, path in phase3_evals.items():
        print(f"  {tag}: {path.name}")
    print(f"\n发现的 Phase 3 训练日志：")
    for tag, info in phase3_logs.items():
        print(f"  {tag}: dev_loss={info.get('dev_loss')}, train_loss={info.get('train_loss')}")

    if not phase3_evals:
        print("\n⚠️ 未发现 Phase 3 评估结果。请先运行：")
        print("   bash experiments/exp_06_finetune/scripts/run_knitlm_cpt.sh eval")
        return

    # 计算 Phase 3 指标
    phase3_metrics = {}
    for tag, path in phase3_evals.items():
        data = json.loads(path.read_text())
        samples = data.get("samples", [])
        m = compute_metrics(samples)
        m["tag"] = f"phase3_{tag}"
        m["label"] = "Phase 3: KnItLM (CPT + merge)"
        m["has_eval"] = True
        if tag in phase3_logs:
            m.update(phase3_logs[tag])
        phase3_metrics[tag] = m

    # Phase 1 baseline
    base_tag = BASELINE_TAG
    base_metrics = {}
    if base_tag in phase1_evals:
        data = json.loads(phase1_evals[base_tag].read_text())
        samples = data.get("samples", [])
        base_metrics = compute_metrics(samples)
        base_metrics["tag"] = base_tag
        base_metrics["label"] = "Phase 1 baseline (r=8, e=1, lr=1e-5)"
        base_metrics["has_eval"] = True

    # Phase 2（如果存在）
    phase2_metrics = {}
    for p in sorted(RESULTS_DIR.glob("exp_06_eval.phase2_*.json")):
        m = re.match(r"exp_06_eval\.phase2_(.+?)\.\d{8}_\d{6}\.json", p.name)
        if m:
            tag = m.group(1)
            data = json.loads(p.read_text())
            samples = data.get("samples", [])
            phase2_metrics[tag] = compute_metrics(samples)
            phase2_metrics[tag]["tag"] = f"phase2_{tag}"
            phase2_metrics[tag]["label"] = f"Phase 2: {tag}"
            phase2_metrics[tag]["has_eval"] = True

    # ---- 生成 markdown ----
    lines = []
    lines.append("# Phase 3 对比：KnItLM 知识注入 vs Phase 1/2\n")
    lines.append("> 目标：验证 CPT 知识注入是否提升严格 recall（CWE 错标减少）。\n")
    lines.append("- 基座：Qwen2.5-Coder-7B-Base → CPT (r=64, rsLoRA, e=1, lr=2e-5) → merge to Instruct")
    lines.append("- 训练数据：cpt_corpus.jsonl (1400 样本, 5.06 MB)")
    lines.append("- 测试集：exp_04_hard_samples 87 段")
    lines.append("- RDNA4 优化：AOTRITON attention + 部分 TunableOp + device_map={\"\": 0}\n")

    # 训练侧
    lines.append("## 1. 训练侧：CPT 训练指标\n")
    lines.append("| 配置 | 方法 | r | epochs | dev_loss | train_loss | 训练耗时 |")
    lines.append("|------|------|---|--------|----------|------------|----------|")
    if phase3_logs:
        for tag, info in phase3_logs.items():
            dev = f"{info['dev_loss']:.4f}" if info.get("dev_loss") else "—"
            tl = f"{info['train_loss']:.4f}" if info.get("train_loss") else "—"
            rt = f"{info['train_runtime']:.0f}s" if info.get("train_runtime") else "—"
            lines.append(f"| Phase 3 KnItLM | CPT | 64 | 1 | {dev} | {tl} | {rt} |")
    lines.append("")

    # 评估侧对比
    lines.append("## 2. 评估侧：exp_04 87 段测试集指标\n")
    lines.append("| 配置 | TP | TN | FP | FN | 宽松 recall | 严格 recall | FPR | accuracy | CWE错标 | 幻觉率 |")
    lines.append("|------|----|----|----|----|-------------|-------------|-----|----------|---------|--------|")

    all_configs = []
    if base_metrics:
        all_configs.append(("phase1", base_metrics))
    for tag, m in phase2_metrics.items():
        all_configs.append(("phase2", m))
    for tag, m in phase3_metrics.items():
        all_configs.append(("phase3", m))

    for phase, m in all_configs:
        lines.append(
            f"| {m['label']} | {m.get('tp','—')} | {m.get('tn','—')} | {m.get('fp','—')} | "
            f"{m.get('fn','—')} | {pct(m.get('recall'))} | {pct(m.get('strict_recall'))} | "
            f"{pct(m.get('fpr'))} | {pct(m.get('accuracy'))} | {m.get('cwe_mismatch','—')} | "
            f"{pct(m.get('hallucination_rate'))} |"
        )
    lines.append("")

    # 与 Phase 1 baseline 的差值
    if base_metrics:
        lines.append("## 3. 与 Phase 1 baseline 的差值\n")
        lines.append("| 配置 | Δrecall | Δstrict_recall | ΔFPR | Δaccuracy | ΔCWE错标 |")
        lines.append("|------|---------|----------------|------|-----------|---------|")

        def delta(cur, key):
            b = base_metrics.get(key)
            c = cur.get(key)
            if b is None or c is None:
                return "—"
            return f"{(c-b)*100:+.1f}pp"

        def delta_int(cur, key):
            b = base_metrics.get(key, 0) or 0
            c = cur.get(key, 0) or 0
            return f"{c-b:+d}"

        for phase, m in all_configs:
            if phase == "phase1":
                continue
            lines.append(
                f"| {m['label']} | {delta(m, 'recall')} | {delta(m, 'strict_recall')} | "
                f"{delta(m, 'fpr')} | {delta(m, 'accuracy')} | {delta_int(m, 'cwe_mismatch')} |"
            )
        lines.append("")

    # 结论
    lines.append("## 4. 结论与下一步建议\n")
    if base_metrics and phase3_metrics:
        p3 = list(phase3_metrics.values())[0]
        d_strict = (p3.get("strict_recall", 0) or 0) - (base_metrics.get("strict_recall", 0) or 0)
        d_fpr = (p3.get("fpr", 0) or 0) - (base_metrics.get("fpr", 0) or 0)
        d_cwe = (p3.get("cwe_mismatch", 0) or 0) - (base_metrics.get("cwe_mismatch", 0) or 0)

        lines.append(f"- **Phase 3 严格 recall 差值**: {d_strict*100:+.1f}pp")
        lines.append(f"- **Phase 3 FPR 差值**: {d_fpr*100:+.1f}pp")
        lines.append(f"- **Phase 3 CWE 错标差值**: {d_cwe:+d}")
        lines.append("")

        if d_strict > 0.03 and d_fpr <= 0.05:
            lines.append("**判定**：✅ **Phase 3 KnItLM 有效**：严格 recall 显著提升，FPR 未恶化。")
            lines.append("**下一步**：Phase 4 Prompt Distillation（自蒸馏进一步提升）")
        elif d_strict > 0 and d_fpr <= 0.10:
            lines.append("**判定**：⚠️ **Phase 3 有小幅提升**：严格 recall 有提升但有限。")
            lines.append("**下一步**：可继续 Phase 4，或回到 Phase 2 最优配置 + KnItLM base 重训 SFT")
        elif d_fpr > 0.10:
            lines.append("**判定**：❌ **Phase 3 FPR 恶化**：CPT 可能引入噪音导致误报增加。")
            lines.append("**下一步**：检查 CPT 语料质量，或降低 CPT lr/epochs 重训")
        else:
            lines.append("**判定**：⚠️ **Phase 3 提升不明显**：CPT 知识注入效果有限。")
            lines.append("**下一步**：直接进 Phase 4 Prompt Distillation")
        lines.append("")

    # 写入文件
    OUTPUT_MD.write_text("\n".join(lines))
    print(f"\n✅ 对比报告已生成：{OUTPUT_MD}")
    print("\n摘要：")
    # 打印关键差值
    if base_metrics and phase3_metrics:
        p3 = list(phase3_metrics.values())[0]
        print(f"| 配置 | Δrecall | Δstrict_recall | ΔFPR | Δaccuracy | ΔCWE错标 |")
        print(f"|------|---------|----------------|------|-----------|---------|")
        for phase, m in all_configs:
            if phase == "phase1":
                continue
            dr = (m.get("recall", 0) or 0) - (base_metrics.get("recall", 0) or 0)
            dsr = (m.get("strict_recall", 0) or 0) - (base_metrics.get("strict_recall", 0) or 0)
            dfpr = (m.get("fpr", 0) or 0) - (base_metrics.get("fpr", 0) or 0)
            dacc = (m.get("accuracy", 0) or 0) - (base_metrics.get("accuracy", 0) or 0)
            dcwe = (m.get("cwe_mismatch", 0) or 0) - (base_metrics.get("cwe_mismatch", 0) or 0)
            print(f"| {m['label']} | {dr*100:+.1f}pp | {dsr*100:+.1f}pp | {dfpr*100:+.1f}pp | {dacc*100:+.1f}pp | {dcwe:+d} |")


if __name__ == "__main__":
    main()
