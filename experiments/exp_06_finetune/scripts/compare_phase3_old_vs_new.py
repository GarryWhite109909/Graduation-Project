"""Phase 3 语料清洗前后对比：旧版扁平语料 vs 新版三层分离+清洗语料

用于量化测试集泄露和 SYSTEM 重复污染对 Phase 3 指标的影响。

用法：
    python experiments/exp_06_finetune/scripts/compare_phase3_old_vs_new.py
    python experiments/exp_06_finetune/scripts/compare_phase3_old_vs_new.py \
        --old results/exp_06_eval.knitlm_merged.20260719_120000.json \
        --new results/exp_06_eval.knitlm_merged_cleaned.20260719_180000.json

输出：
    experiments/exp_06_finetune/results/phase3_old_vs_new_summary.md
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).parent))

from compare_phase1_sweep import compute_metrics, pct

RESULTS_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/results"
OUTPUT_MD = RESULTS_DIR / "phase3_old_vs_new_summary.md"


def discover_old_phase3() -> Path | None:
    """发现旧版 Phase 3 评估结果（exp_06_eval.knitlm_merged.*.json）。"""
    files = sorted(RESULTS_DIR.glob("exp_06_eval.knitlm_merged.*.json"))
    if not files:
        return None
    return files[-1]  # 取最新的


def discover_new_phase3() -> Path | None:
    """发现新版 Phase 3 评估结果（exp_06_eval.knitlm_merged_cleaned.*.json）。"""
    patterns = [
        "exp_06_eval.knitlm_merged_cleaned.*.json",
        "exp_06_eval.knitlm_merged_v2.*.json",
        "exp_06_eval.knitlm_merged_new.*.json",
    ]
    for pat in patterns:
        files = sorted(RESULTS_DIR.glob(pat))
        if files:
            return files[-1]
    return None


def discover_training_log() -> Path | None:
    """发现新版 Phase 3 训练日志（knitlm_cpt）。"""
    files = sorted(
        (PROJECT_ROOT / "experiments/exp_06_finetune/logs").glob("train_log_knitlm_cpt_*.json")
    )
    return files[-1] if files else None


def extract_train_info(log_path: Path | None) -> dict:
    """从训练日志提取 dev_loss / train_loss / train_runtime。"""
    info = {"dev_loss": None, "train_loss": None, "train_runtime": None}
    if not log_path:
        return info
    try:
        data = json.loads(log_path.read_text())
    except Exception:
        return info

    metrics = data.get("metrics", {})
    info["train_loss"] = metrics.get("train_loss")
    info["train_runtime"] = metrics.get("train_runtime")

    # eval_loss 取最后一条
    for entry in reversed(data.get("log_history", [])):
        if "eval_loss" in entry:
            info["dev_loss"] = entry["eval_loss"]
            break
    return info


def regression_table(old_samples: list[dict], new_samples: list[dict]) -> list[dict]:
    """对比单条样本的 outcome/CWE，输出回归/修复清单。"""
    old_map = {s["file"]: s for s in old_samples}
    new_map = {s["file"]: s for s in new_samples}

    rows = []
    for fname in sorted(set(old_map) | set(new_map)):
        old = old_map.get(fname)
        new = new_map.get(fname)
        if not old or not new:
            continue
        old_outcome = old.get("outcome", "")
        new_outcome = new.get("outcome", "")
        if old_outcome == new_outcome:
            continue
        rows.append({
            "file": fname,
            "expected_present": old.get("expected_present"),
            "old_outcome": old_outcome,
            "new_outcome": new_outcome,
            "old_cwe": old.get("model_vulnerability_type", ""),
            "new_cwe": new.get("model_vulnerability_type", ""),
            "change": "修复" if new_outcome in ("TP", "TN") and old_outcome not in ("TP", "TN")
                      else "回归" if old_outcome in ("TP", "TN") and new_outcome not in ("TP", "TN")
                      else "变化",
        })
    return rows


def main():
    parser = argparse.ArgumentParser(description="Phase 3 语料清洗前后对比")
    parser.add_argument("--old", type=Path, help="旧 Phase 3 评估结果文件")
    parser.add_argument("--new", type=Path, help="新 Phase 3 评估结果文件")
    args = parser.parse_args()

    old_path = args.old or discover_old_phase3()
    new_path = args.new or discover_new_phase3()

    print("=" * 60)
    print("Phase 3 语料清洗前后对比")
    print("=" * 60)

    if not old_path or not old_path.exists():
        print(f"\n⚠️ 未找到旧 Phase 3 评估结果 ({old_path})")
        print("   请在台式机跑完旧版 CPT 后，将 results/exp_06_eval.knitlm_merged.*.json 回传至此目录")
        return

    if not new_path or not new_path.exists():
        print(f"\n⚠️ 未找到新 Phase 3 评估结果 ({new_path})")
        print("   请先使用清洗后的语料重跑 Phase 3 CPT 与评估：")
        print("     python experiments/exp_06_finetune/scripts/train_knitlm_cpt.py")
        print("     python experiments/exp_06_finetune/scripts/merge_lora_to_instruct.py")
        print("     python evaluate.py --model .../knitlm_merged_cleaned --mode ...")
        return

    print(f"旧结果: {old_path.name}")
    print(f"新结果: {new_path.name}")

    old_data = json.loads(old_path.read_text())
    new_data = json.loads(new_path.read_text())

    old_metrics = compute_metrics(old_data.get("samples", []))
    new_metrics = compute_metrics(new_data.get("samples", []))

    old_metrics["label"] = "Phase 3 旧版 (扁平语料 + SYSTEM 重复 + 测试集泄露)"
    new_metrics["label"] = "Phase 3 新版 (三层分离 + 清洗后语料)"

    # 训练侧信息
    train_log = discover_training_log()
    if train_log:
        new_metrics.update(extract_train_info(train_log))

    lines = []
    lines.append("# Phase 3 语料清洗前后对比\n")
    lines.append(
        "> 目标：量化测试集泄露和 SYSTEM_PROMPT 重复污染对 Phase 3 指标的贡献，"
        "验证清洗后的三层分离语料是否仍能保持知识注入效果。\n"
    )
    lines.append(f"- 旧结果：`{old_path.name}`")
    lines.append(f"- 新结果：`{new_path.name}`")
    lines.append(f"- 新版训练日志：`{train_log.name if train_log else '未找到'}`\n")

    # 表 1：评估侧指标
    lines.append("## 1. 87 段测试集指标对比\n")
    lines.append("| 配置 | TP | TN | FP | FN | 宽松 recall | 严格 recall | FPR | accuracy | CWE 错标 | 幻觉率 |")
    lines.append("|------|----|----|----|----|-------------|-------------|-----|----------|---------|--------|")
    for m in (old_metrics, new_metrics):
        lines.append(
            f"| {m['label']} | {m.get('tp', '—')} | {m.get('tn', '—')} | {m.get('fp', '—')} | "
            f"{m.get('fn', '—')} | {pct(m.get('recall'))} | {pct(m.get('strict_recall'))} | "
            f"{pct(m.get('fpr'))} | {pct(m.get('accuracy'))} | {m.get('cwe_mismatch', '—')} | "
            f"{pct(m.get('hallucination_rate'))} |"
        )
    lines.append("")

    # 表 2：差值
    lines.append("## 2. 新版 vs 旧版差值\n")
    lines.append("| 指标 | 差值（新版 - 旧版）|")
    lines.append("|------|------------------|")
    for key in ("recall", "strict_recall", "fpr", "accuracy", "hallucination_rate"):
        old_v = old_metrics.get(key)
        new_v = new_metrics.get(key)
        if old_v is None or new_v is None:
            delta = "—"
        else:
            delta = f"{(new_v - old_v) * 100:+.1f}pp"
        lines.append(f"| {key} | {delta} |")
    # CWE 错标是整数
    old_cwe = old_metrics.get("cwe_mismatch", 0) or 0
    new_cwe = new_metrics.get("cwe_mismatch", 0) or 0
    lines.append(f"| CWE 错标 | {new_cwe - old_cwe:+d} |")
    lines.append("")

    # 表 3：训练侧指标
    lines.append("## 3. 新版训练侧指标\n")
    lines.append("| dev_loss | train_loss | train_runtime(s) |")
    lines.append("|----------|------------|------------------|")
    lines.append(
        f"| {new_metrics.get('dev_loss', '—')} | "
        f"{new_metrics.get('train_loss', '—')} | "
        f"{new_metrics.get('train_runtime', '—')} |"
    )
    lines.append("")

    # 表 4：回归/修复清单
    rows = regression_table(old_data.get("samples", []), new_data.get("samples", []))
    lines.append("## 4. 单样本变化（回归 / 修复）\n")
    lines.append(f"> 共 {len(rows)} 个样本 outcome 发生变化。\n")
    if rows:
        lines.append("| 文件 | expected | 旧 outcome | 新 outcome | 变化 | 旧 CWE | 新 CWE |")
        lines.append("|------|----------|-----------|-----------|------|--------|--------|")
        for r in rows:
            lines.append(
                f"| {r['file']} | {r['expected_present']} | {r['old_outcome']} | "
                f"{r['new_outcome']} | {r['change']} | {r['old_cwe']} | {r['new_cwe']} |"
            )
    else:
        lines.append("两版评估在 87 段测试集上的单样本 outcome 完全一致。")
    lines.append("")

    # 结论
    lines.append("## 5. 结论\n")
    d_strict = (new_metrics.get("strict_recall", 0) or 0) - (old_metrics.get("strict_recall", 0) or 0)
    d_fpr = (new_metrics.get("fpr", 0) or 0) - (old_metrics.get("fpr", 0) or 0)
    d_hallu = (new_metrics.get("hallucination_rate", 0) or 0) - (old_metrics.get("hallucination_rate", 0) or 0)

    lines.append(f"- **严格 recall 变化**：{d_strict * 100:+.1f}pp")
    lines.append(f"- **FPR 变化**：{d_fpr * 100:+.1f}pp")
    lines.append(f"- **幻觉率变化**：{d_hallu * 100:+.1f}pp")
    lines.append(f"- **CWE 错标变化**：{(new_metrics.get('cwe_mismatch', 0) or 0) - (old_metrics.get('cwe_mismatch', 0) or 0):+d}")
    lines.append(f"- **单样本 outcome 变化数**：{len(rows)}")
    lines.append("")

    if d_strict >= -0.02 and d_fpr <= 0.05 and d_hallu <= 0.05:
        lines.append(
            "**判定**：✅ **清洗后的三层分离语料保留了 Phase 3 核心突破**。"
            "严格 recall 未大幅倒退，FPR 和幻觉率未显著恶化，"
            "说明旧版指标的提升并非主要由测试集泄露/ SYSTEM 重复驱动。"
        )
    else:
        failed = []
        if d_strict < -0.02:
            failed.append(f"严格 recall 倒退 {abs(d_strict) * 100:.1f}pp")
        if d_fpr > 0.05:
            failed.append(f"FPR 上升 {d_fpr * 100:+.1f}pp")
        if d_hallu > 0.05:
            failed.append(f"幻觉率上升 {d_hallu * 100:+.1f}pp")
        lines.append(
            "**判定**：❌ **清洗后的语料性能显著退化**。"
            f"{'；'.join(failed)}。"
            "这说明旧版 Phase 3 的指标突破可能部分依赖测试集泄露或 SYSTEM 重复污染，"
            "需要进一步扩增清洗后的语料规模或调整训练配置。"
        )
    lines.append("")

    # 写入
    OUTPUT_MD.write_text("\n".join(lines))
    print(f"\n✅ 对比报告已生成：{OUTPUT_MD}")


if __name__ == "__main__":
    main()
