"""Phase 1 sweep 对比：lr × rsLoRA 网格搜索结果汇总

自动发现 results/exp_06_eval.phase1_*.json，结合 logs/train_log_*.json 的 dev_loss，
生成对比表，选出最佳配置。

用法：
    PYTHONPATH=. /home/zane/miniconda3/envs/AI/bin/python \
        experiments/exp_06_finetune/scripts/compare_phase1_sweep.py

输出：
    experiments/exp_06_finetune/results/phase1_sweep_summary.md
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.schema import parse_verdict, normalize_has_vulnerability

RESULTS_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/results"
LOGS_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/logs"
OUTPUT_MD = RESULTS_DIR / "phase1_sweep_summary.md"

# 配置展示顺序（与 run_phase1_eval.sh 一致）
CONFIG_ORDER = [
    "lr1e-5_base",
    "lr5e-5",
    "lr1e-4",
    "lr5e-5_rslora",
    "lr1e-4_rslora",
    "lr5e-5_rslora_dora",
]

CONFIG_LABELS = {
    "lr1e-5_base": "lr=1e-5 (baseline)",
    "lr5e-5": "lr=5e-5",
    "lr1e-4": "lr=1e-4",
    "lr5e-5_rslora": "lr=5e-5 + rsLoRA",
    "lr1e-4_rslora": "lr=1e-4 + rsLoRA",
    "lr5e-5_rslora_dora": "lr=5e-5 + rsLoRA + DoRA",
}

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
    if total == 0:
        return {}
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
        "avg_elapsed": sum(elapsed) / total if total else 0,
    }


def discover_eval_files() -> dict[str, Path]:
    """发现所有 exp_06_eval.phase1_{tag}.*.json，返回 {tag: path}。
    同一 tag 多个时间戳时取最新。"""
    found = {}
    for p in sorted(RESULTS_DIR.glob("exp_06_eval.phase1_*.json")):
        m = re.match(r"exp_06_eval\.phase1_(.+?)\.\d{8}_\d{6}\.json", p.name)
        if m:
            tag = m.group(1)
            found[tag] = p  # sorted 已按时间戳升序，后者覆盖前者
    return found


def discover_train_dev_loss() -> dict[str, dict]:
    """从训练日志提取 dev_loss 和 train_loss。
    返回 {tag: {dev_loss, train_loss, train_runtime, lr, rslora, dora}}。
    """
    results = {}
    # 匹配新旧两种日志命名：
    #   旧: train_log_r8_e1_s42_7b.json
    #   新: train_log_r8_e1_lr{X}_s42{...}_7b.json
    for p in LOGS_DIR.glob("train_log_r8_e1_*s42*.json"):
        try:
            data = json.loads(p.read_text())
        except Exception:
            continue
        args = data.get("args", {})
        lr = args.get("lr", 0)
        use_rslora = args.get("use_rslora", False)
        use_dora = args.get("use_dora", False)
        suffix = args.get("output_suffix", "")

        # 构造 tag（与 CONFIG_ORDER 一致）
        if lr == 1e-05 and not use_rslora and suffix == "_7b":
            tag = "lr1e-5_base"
        elif lr == 5e-05 and not use_rslora and not use_dora and suffix == "_7b":
            tag = "lr5e-5"
        elif lr == 1e-04 and not use_rslora and not use_dora and suffix == "_7b":
            tag = "lr1e-4"
        elif lr == 5e-05 and use_rslora and not use_dora and suffix == "_7b":
            tag = "lr5e-5_rslora"
        elif lr == 1e-04 and use_rslora and not use_dora and suffix == "_7b":
            tag = "lr1e-4_rslora"
        elif lr == 5e-05 and use_rslora and use_dora and suffix == "_7b":
            tag = "lr5e-5_rslora_dora"
        else:
            continue

        dev_loss = None
        train_loss = data.get("metrics", {}).get("train_loss")
        train_runtime = data.get("metrics", {}).get("train_runtime")
        for entry in data.get("log_history", []):
            if "eval_loss" in entry:
                dev_loss = entry["eval_loss"]
        results[tag] = {
            "dev_loss": dev_loss,
            "train_loss": train_loss,
            "train_runtime": train_runtime,
            "lr": lr,
            "use_rslora": use_rslora,
            "use_dora": use_dora,
        }
    return results


def pct(x):
    return "—" if x is None else f"{x*100:.1f}%"


def main():
    eval_files = discover_eval_files()
    train_logs = discover_train_dev_loss()

    print("发现的评估结果：")
    for tag, path in eval_files.items():
        print(f"  {tag}: {path.name}")
    print(f"\n发现的训练日志：")
    for tag, info in train_logs.items():
        print(f"  {tag}: dev_loss={info['dev_loss']}, train_loss={info['train_loss']:.4f}")

    # 计算每个配置的指标
    all_tags = sorted(set(list(eval_files.keys()) + list(train_logs.keys())),
                      key=lambda t: CONFIG_ORDER.index(t) if t in CONFIG_ORDER else 99)

    if not all_tags:
        print("\n⚠️ 未发现任何 phase1 评估结果或训练日志。")
        print("   请先运行：bash experiments/exp_06_finetune/scripts/run_phase1_sweep.sh")
        print("   然后：bash experiments/exp_06_finetune/scripts/run_phase1_eval.sh")
        return

    metrics = {}
    for tag in all_tags:
        m = {}
        if tag in eval_files:
            data = json.loads(eval_files[tag].read_text())
            samples = data.get("samples", [])
            m = compute_metrics(samples)
        if tag in train_logs:
            m.update(train_logs[tag])
        m["tag"] = tag
        m["label"] = CONFIG_LABELS.get(tag, tag)
        m["has_eval"] = tag in eval_files
        metrics[tag] = m

    # ---- 生成 markdown ----
    lines = []
    lines.append("# Phase 1 Sweep 对比：lr × rsLoRA 网格搜索\n")
    lines.append("> 目标：验证 lr 调优 + rsLoRA 对 7B r=8 e=1 的影响，选出最佳配置进入 Phase 2/3。\n")
    lines.append(f"- 基座：Qwen2.5-Coder-7B-Instruct (4bit QLoRA)")
    lines.append(f"- 训练数据：train_chatml_v2.jsonl (700 train + 123 dev)")
    lines.append(f"- 测试集：exp_04_hard_samples 87 段\n")

    # 训练侧对比（dev_loss）
    lines.append("## 1. 训练侧：dev_loss / train_loss 对比\n")
    lines.append("| 配置 | lr | rsLoRA | DoRA | dev_loss | train_loss | 训练耗时(s) |")
    lines.append("|------|-----|--------|------|----------|------------|-------------|")
    for tag in all_tags:
        m = metrics[tag]
        lr_val = m.get("lr")
        lr_str = f"{lr_val:g}" if isinstance(lr_val, (int, float)) else "—"
        rslora = "✓" if m.get("use_rslora") else ""
        dora = "✓" if m.get("use_dora") else ""
        dev_loss = f"{m['dev_loss']:.4f}" if m.get("dev_loss") else "—"
        train_loss = f"{m['train_loss']:.4f}" if m.get("train_loss") else "—"
        runtime = f"{m['train_runtime']:.0f}" if m.get("train_runtime") else "—"
        lines.append(f"| {m['label']} | {lr_str} | {rslora} | {dora} | {dev_loss} | {train_loss} | {runtime} |")
    lines.append("")

    # 评估侧对比
    lines.append("## 2. 评估侧：exp_04 87 段测试集指标\n")
    eval_tags = [t for t in all_tags if metrics[t].get("has_eval")]
    if not eval_tags:
        lines.append("⚠️ 暂无评估结果。请运行 `run_phase1_eval.sh`。\n")
    else:
        lines.append("| 配置 | TP | TN | FP | FN | 宽松 recall | 严格 recall | FPR | accuracy | CWE错标 | 幻觉率 | CoT不一致 | 平均耗时 |")
        lines.append("|------|----|----|----|----|-------------|-------------|-----|----------|---------|--------|-----------|----------|")
        for tag in eval_tags:
            m = metrics[tag]
            lines.append(
                f"| {m['label']} | {m.get('tp','—')} | {m.get('tn','—')} | {m.get('fp','—')} | {m.get('fn','—')} | "
                f"{pct(m.get('recall'))} | {pct(m.get('strict_recall'))} | {pct(m.get('fpr'))} | "
                f"{pct(m.get('accuracy'))} | {m.get('cwe_mismatch','—')} | {pct(m.get('hallucination_rate'))} | "
                f"{m.get('issue_counts',{}).get('cot_json_inconsistent', 0)} | "
                f"{m.get('avg_elapsed',0):.1f}s |"
            )
        lines.append("")

        # 与 baseline 的差值
        base_tag = "lr1e-5_base"
        if base_tag in metrics and metrics[base_tag].get("has_eval"):
            lines.append("## 3. 与 baseline (lr=1e-5) 的差值\n")
            base = metrics[base_tag]
            lines.append("| 配置 | Δrecall | Δstrict_recall | ΔFPR | Δaccuracy | ΔCWE错标 | Δ幻觉率 |")
            lines.append("|------|---------|----------------|------|-----------|---------|---------|")
            for tag in eval_tags:
                if tag == base_tag:
                    continue
                m = metrics[tag]
                def delta(key):
                    b = base.get(key)
                    cur = m.get(key)
                    if b is None or cur is None:
                        return "—"
                    return f"{(cur-b)*100:+.1f}pp"
                def delta_int(key):
                    b = base.get(key, 0) or 0
                    cur = m.get(key, 0) or 0
                    return f"{cur-b:+d}"
                lines.append(
                    f"| {m['label']} | {delta('recall')} | {delta('strict_recall')} | {delta('fpr')} | "
                    f"{delta('accuracy')} | {delta_int('cwe_mismatch')} | {delta('hallucination_rate')} |"
                )
            lines.append("")

    # 结论与推荐
    lines.append("## 4. 选型建议\n")
    lines.append("**选型标准**（按优先级）：")
    lines.append("1. 严格 recall 最高（CWE 也对，反映真实技能提升）")
    lines.append("2. FPR 不恶化（FP 不增加）")
    lines.append("3. dev_loss 最低（训练侧泛化最好）")
    lines.append("4. CoT-JSON 不一致为 0\n")

    # 自动推荐
    best_tag = None
    best_score = None
    for tag in eval_tags:
        m = metrics[tag]
        if not m.get("strict_recall") or m.get("fpr") is None:
            continue
        # 评分：严格 recall - FPR 惩罚 - dev_loss 归一化
        score = m["strict_recall"] - 2 * m["fpr"]
        if m.get("dev_loss"):
            score -= 0.01 * m["dev_loss"]  # 小惩罚，仅打破平局
        if best_score is None or score > best_score:
            best_score = score
            best_tag = tag

    if best_tag:
        lines.append(f"**自动推荐**：`{metrics[best_tag]['label']}`（综合评分最高）")
        lines.append("")
        lines.append("**下一步**：")
        lines.append(f"- 若推荐配置的严格 recall 显著高于 baseline（>3pp），直接进入 Phase 3（DPO）")
        lines.append(f"- 若提升有限（<2pp），进入 Phase 2：r=32 + rsLoRA + e=2 + lr=1e-4")
        lines.append(f"- 若 FPR 恶化，回到 baseline lr=1e-5 + rsLoRA 作为 Phase 2 起点")
    else:
        lines.append("⚠️ 数据不足，无法自动推荐。请确保至少有 baseline + 2 个 sweep 配置的评估结果。")

    OUTPUT_MD.write_text("\n".join(lines))
    print(f"\n对比报告已生成：{OUTPUT_MD}")
    print(f"\n摘要：")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
