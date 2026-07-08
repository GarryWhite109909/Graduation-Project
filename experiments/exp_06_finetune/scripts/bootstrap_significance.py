"""
Bootstrap 显著性检验 —— 比较基线 vs 微调的检测指标差异是否显著。

输入：两个 evaluate.py 产生的 JSON 结果文件（--baseline / --finetuned）。
方法：配对 Bootstrap 重采样（同一测试集，按样本配对），N=10000 次。
  - 每次有放回抽取 N 个样本（N=测试样本数）
  - 计算两组在本次重采样下的 recall / accuracy / fpr
  - 累计差值分布
输出：
  - 各指标的均值差、95% 置信区间、p 值（双尾：H0: 差值=0）
  - 是否显著（p < 0.05）

用法：
  python bootstrap_significance.py \
      --baseline results/exp_06_eval.baseline.20260707_120000.json \
      --finetuned results/exp_06_eval.finetuned_final.20260707_130000.json

  # 多种子聚合结果：默认取 all_runs 展开后所有 (sample, seed) 对作配对
  python bootstrap_significance.py \
      --baseline results/exp_06_eval.baseline_seeds3.*.json \
      --finetuned results/exp_06_eval.finetuned_final_seeds3.*.json \
      --n-bootstrap 10000
"""

import argparse
import json
import random
import sys
from pathlib import Path


def load_samples(path: Path) -> list[dict]:
    """从 evaluate.py 的结果文件加载样本列表。

    优先使用 all_runs（多种子），否则退回 samples（单种子）。
    每条样本带 run_seed 字段，便于配对。
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if data.get("all_runs"):
        # 多种子：展平所有 (sample, seed) 对
        flat = []
        for run in data["all_runs"]:
            for s in run:
                flat.append(s)
        return flat
    return data.get("samples", [])


def compute_metrics(samples: list[dict]) -> dict:
    """从样本列表计算 recall/accuracy/fpr。

    parse_fail 不计入分母（按惯例视为模型失效，单列统计）。
    """
    tp = sum(1 for s in samples if s["outcome"] == "TP")
    fp = sum(1 for s in samples if s["outcome"] == "FP")
    fn = sum(1 for s in samples if s["outcome"] == "FN")
    tn = sum(1 for s in samples if s["outcome"] == "TN")
    pf = sum(1 for s in samples if s["outcome"] == "parse_fail")

    pos = tp + fn  # 真实正例
    neg = fp + tn  # 真实负例
    total = pos + neg  # 不含 parse_fail

    recall = tp / pos if pos > 0 else None
    accuracy = (tp + tn) / total if total > 0 else None
    fpr = fp / neg if neg > 0 else None
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn, "parse_fail": pf,
        "recall": recall, "accuracy": accuracy, "fpr": fpr,
    }


def bootstrap_paired(
    baseline_samples: list[dict],
    finetuned_samples: list[dict],
    n_bootstrap: int,
    seed: int = 42,
) -> dict:
    """配对 Bootstrap：以样本为重采样单元，比较两组指标差。

    要求两组样本数量相等且顺序对应（同一测试集）。若为多种子结果，
    则按 (file, run_seed) 配对；若不匹配则报错。

    返回各指标的差值分布统计：
      {
        metric: {
          "baseline_mean": float,
          "finetuned_mean": float,
          "diff_mean": float,
          "ci_low": float, "ci_high": float,  # 95% CI
          "p_value": float,                    # 双尾
          "significant": bool,                 # p < 0.05
          "n_bootstrap": int,
        }
      }
    """
    n = len(baseline_samples)
    if n != len(finetuned_samples):
        raise ValueError(
            f"样本数不匹配：baseline={n}, finetuned={len(finetuned_samples)}。"
            "请确保两个评估文件使用同一测试集且种子一致。"
        )

    # 配对索引（按 file + run_seed 匹配，确保对应同一观测）
    base_key = [(s["file"], s.get("run_seed", 0)) for s in baseline_samples]
    fine_key = [(s["file"], s.get("run_seed", 0)) for s in finetuned_samples]
    if base_key != fine_key:
        # 尝试按 file 配对（单种子场景 run_seed 不同无所谓）
        base_files = [s["file"] for s in baseline_samples]
        fine_files = [s["file"] for s in finetuned_samples]
        if base_files == fine_files:
            # 配对正确，继续
            pass
        else:
            raise ValueError(
                "样本顺序/集合不匹配，无法配对。请确保两组评估跑的是同一测试集。\n"
                f"baseline 前 5: {base_files[:5]}\n"
                f"finetuned 前 5: {fine_files[:5]}"
            )

    rng = random.Random(seed)
    metrics_list = ["recall", "accuracy", "fpr"]
    diff_dist = {m: [] for m in metrics_list}

    base_m = compute_metrics(baseline_samples)
    fine_m = compute_metrics(finetuned_samples)

    for _ in range(n_bootstrap):
        idx = [rng.randrange(n) for _ in range(n)]
        b_sub = [baseline_samples[i] for i in idx]
        f_sub = [finetuned_samples[i] for i in idx]
        b_metrics = compute_metrics(b_sub)
        f_metrics = compute_metrics(f_sub)
        for m in metrics_list:
            if b_metrics[m] is None or f_metrics[m] is None:
                continue
            # recall/accuracy: 微调 - 基线（>0 表示微调更好）
            # fpr: 基线 - 微调（>0 表示微调更好，因为 fpr 下降）
            if m == "fpr":
                diff_dist[m].append(b_metrics[m] - f_metrics[m])
            else:
                diff_dist[m].append(f_metrics[m] - b_metrics[m])

    summary = {}
    for m in metrics_list:
        diffs = diff_dist[m]
        if not diffs:
            summary[m] = None
            continue
        diffs_sorted = sorted(diffs)
        n_diff = len(diffs)
        # 95% CI: 第 2.5 和 97.5 百分位
        ci_low_idx = int(0.025 * n_diff)
        ci_high_idx = int(0.975 * n_diff)
        ci_low = diffs_sorted[ci_low_idx]
        ci_high = diffs_sorted[min(ci_high_idx, n_diff - 1)]

        # 双尾 p 值：|mean_diff| 在 0 的两侧各占多少
        # 等价于：H0 下 diff=0，看观测差值偏离 0 的概率
        # 用 bootstrap 分布中 ≤0 和 ≥0 的比例的两倍（取较小者）
        n_le_zero = sum(1 for d in diffs if d <= 0)
        n_ge_zero = sum(1 for d in diffs if d >= 0)
        # 单侧 p = min(P(diff<=0), P(diff>=0))；双尾 = 2 * 单侧
        p_one_side = min(n_le_zero, n_ge_zero) / n_diff
        p_value = min(1.0, 2 * p_one_side)

        # 微调更好的方向：recall/accuracy 差>0 好，fpr 差>0 好（已转换）
        base_val = base_m[m]
        fine_val = fine_m[m]
        if m == "fpr":
            diff_point = base_val - fine_val if base_val is not None and fine_val is not None else None
            better = (diff_point is not None and diff_point > 0)
        else:
            diff_point = fine_val - base_val if base_val is not None and fine_val is not None else None
            better = (diff_point is not None and diff_point > 0)

        summary[m] = {
            "baseline_mean": round(base_val, 4) if base_val is not None else None,
            "finetuned_mean": round(fine_val, 4) if fine_val is not None else None,
            "diff_mean": round(sum(diffs) / n_diff, 4),
            "ci_low": round(ci_low, 4),
            "ci_high": round(ci_high, 4),
            "p_value": round(p_value, 4),
            "significant": p_value < 0.05,
            "direction": "finetuned_better" if better else (
                "finetuned_worse" if diff_point is not None and diff_point < 0 else "tie"
            ),
            "n_bootstrap": n_diff,
        }
    return summary


def main():
    parser = argparse.ArgumentParser(description="Bootstrap 显著性检验：baseline vs finetuned")
    parser.add_argument("--baseline", type=str, required=True,
                        help="基线评估结果 JSON 文件")
    parser.add_argument("--finetuned", type=str, required=True,
                        help="微调评估结果 JSON 文件")
    parser.add_argument("--n-bootstrap", type=int, default=10000,
                        help="Bootstrap 迭代次数（默认 10000）")
    parser.add_argument("--seed", type=int, default=42, help="随机种子")
    parser.add_argument("--output", type=str, default=None,
                        help="可选：将结果保存到 JSON 文件")
    args = parser.parse_args()

    baseline_path = Path(args.baseline)
    finetuned_path = Path(args.finetuned)
    if not baseline_path.exists():
        print(f"错误：基线文件不存在: {baseline_path}")
        sys.exit(1)
    if not finetuned_path.exists():
        print(f"错误：微调文件不存在: {finetuned_path}")
        sys.exit(1)

    print(f"加载基线样本: {baseline_path}")
    baseline_samples = load_samples(baseline_path)
    print(f"  样本数: {len(baseline_samples)}")
    print(f"加载微调样本: {finetuned_path}")
    finetuned_samples = load_samples(finetuned_path)
    print(f"  样本数: {len(finetuned_samples)}")

    print(f"\n开始 Bootstrap 检验（n={args.n_bootstrap}, seed={args.seed}）...")
    summary = bootstrap_paired(
        baseline_samples, finetuned_samples,
        n_bootstrap=args.n_bootstrap, seed=args.seed,
    )

    print("\n" + "=" * 72)
    print("Bootstrap 显著性检验结果（配对，双尾）")
    print("=" * 72)
    print(f"{'指标':<12} {'基线':>8} {'微调':>8} {'差值':>8} "
          f"{'95% CI':>22} {'p值':>8} {'显著?':>8}")
    print("-" * 72)
    for m in ["recall", "accuracy", "fpr"]:
        s = summary[m]
        if s is None:
            print(f"{m:<12}  (无数据)")
            continue
        ci_str = f"[{s['ci_low']:+.4f}, {s['ci_high']:+.4f}]"
        sig_str = "✓" if s["significant"] else "✗"
        # 方向标注：finetuned_better 标 +，worse 标 -
        dir_mark = ""
        if s["direction"] == "finetuned_better":
            dir_mark = " ▲"
        elif s["direction"] == "finetuned_worse":
            dir_mark = " ▼"
        print(f"{m:<12} {s['baseline_mean']:>8.4f} {s['finetuned_mean']:>8.4f} "
              f"{s['diff_mean']:>+8.4f} {ci_str:>22} {s['p_value']:>8.4f} "
              f"{sig_str:>8}{dir_mark}")

    print("\n说明：")
    print("  - 差值 = 微调 - 基线（recall/accuracy 越大越好，fpr 越小越好）")
    print("  - 95% CI 不含 0 ⇒ p < 0.05 ⇒ 显著")
    print("  - ▲ 微调更好，▼ 微调更差")

    # 整体结论
    recall_sig = summary.get("recall", {}).get("significant", False) if summary.get("recall") else False
    acc_sig = summary.get("accuracy", {}).get("significant", False) if summary.get("accuracy") else False
    fpr_sig = summary.get("fpr", {}).get("significant", False) if summary.get("fpr") else False
    n_sig = sum([recall_sig, acc_sig, fpr_sig])
    print(f"\n整体：{n_sig}/3 项指标显著（p<0.05）")

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump({
                "baseline_file": str(baseline_path),
                "finetuned_file": str(finetuned_path),
                "n_bootstrap": args.n_bootstrap,
                "seed": args.seed,
                "baseline_n_samples": len(baseline_samples),
                "finetuned_n_samples": len(finetuned_samples),
                "baseline_metrics": compute_metrics(baseline_samples),
                "finetuned_metrics": compute_metrics(finetuned_samples),
                "bootstrap_summary": summary,
            }, f, indent=2, ensure_ascii=False)
        print(f"\n结果已保存: {out_path}")


if __name__ == "__main__":
    main()
