"""
多种子训练编排脚本（P0.4 改造）—— 串行跑 3 个种子的训练 + 评估，聚合均值±标准差。

流程：
  1. 对每个 seed 调用 train_qlora.py 训练（产出 .../lora_r{r}_a{a}_e{e}_s{seed}/best）
  2. 对每个 seed 的 best checkpoint 调用 evaluate.py 评估（确定性解码）
  3. 聚合 3 个种子的 recall/accuracy/fpr，输出 mean±std
  4. 生成 bootstrap 显著性检验所需的两方结果文件（baseline vs finetuned）

用法（在 AI conda 环境中运行）：
  /home/zane/miniconda3/envs/AI/bin/python run_multiseed.py --seeds 3 --epochs 5

注意：本脚本通过 subprocess 调用 train_qlora.py 与 evaluate.py，
     不会重复加载模型，每个子进程独立运行后退出释放显存。
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/outputs"
RESULTS_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/results"


def run_train(seed: int, epochs: int, lr: float, lora_r: int, lora_alpha: int,
              dev_ratio: float, patience: int, extra_args: list[str]) -> bool:
    """调用 train_qlora.py 训练单个种子，返回是否成功。"""
    cmd = [
        sys.executable, str(SCRIPTS_DIR / "train_qlora.py"),
        "--seed", str(seed),
        "--epochs", str(epochs),
        "--lr", str(lr),
        "--lora-r", str(lora_r),
        "--lora-alpha", str(lora_alpha),
        "--dev-ratio", str(dev_ratio),
        "--early-stopping-patience", str(patience),
    ] + extra_args
    print(f"\n{'='*60}")
    print(f"训练 seed={seed}")
    print(f"命令: {' '.join(cmd)}")
    print(f"{'='*60}")
    t0 = time.time()
    ret = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    elapsed = time.time() - t0
    print(f"\n训练 seed={seed} 完成，耗时 {elapsed:.0f}s，退出码 {ret.returncode}")
    return ret.returncode == 0


def run_evaluate(seed: int, adapter_path: str, tag: str) -> Path | None:
    """调用 evaluate.py 评估单个种子的 best checkpoint，返回结果文件路径。"""
    cmd = [
        sys.executable, str(SCRIPTS_DIR / "evaluate.py"),
        "--mode", "finetuned",
        "--adapter-path", adapter_path,
        # 确定性解码，单种子（训练种子已不同，评估用贪心即可）
    ]
    print(f"\n评估 seed={seed}: {' '.join(cmd)}")
    t0 = time.time()
    ret = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    elapsed = time.time() - t0
    print(f"评估 seed={seed} 完成，耗时 {elapsed:.0f}s，退出码 {ret.returncode}")
    if ret.returncode != 0:
        return None
    # 找最新的结果文件
    files = sorted(RESULTS_DIR.glob(f"exp_06_eval.finetuned_custom.*.json"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def run_baseline_eval() -> Path | None:
    """评估基座模型（对照组）。"""
    cmd = [
        sys.executable, str(SCRIPTS_DIR / "evaluate.py"),
        "--mode", "baseline",
    ]
    print(f"\n评估 baseline: {' '.join(cmd)}")
    ret = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    if ret.returncode != 0:
        return None
    files = sorted(RESULTS_DIR.glob("exp_06_eval.baseline.*.json"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def aggregate_results(result_files: list[Path]) -> dict:
    """从多个评估结果文件聚合指标。"""
    import statistics
    per_seed = []
    recall_list, acc_list, fpr_list = [], [], []
    for rf in result_files:
        if rf is None or not rf.exists():
            continue
        data = json.loads(rf.read_text(encoding="utf-8"))
        m = data.get("metrics", {})
        per_seed.append({"file": str(rf), "metrics": m})
        if m.get("recall") is not None:
            recall_list.append(m["recall"])
        if m.get("accuracy") is not None:
            acc_list.append(m["accuracy"])
        if m.get("false_positive_rate") is not None:
            fpr_list.append(m["false_positive_rate"])

    def stats(vals):
        if not vals:
            return None
        if len(vals) == 1:
            return {"mean": round(vals[0], 4), "std": 0.0, "values": vals}
        return {"mean": round(statistics.mean(vals), 4),
                "std": round(statistics.stdev(vals), 4),
                "values": vals}

    return {
        "n_seeds": len(per_seed),
        "per_seed": per_seed,
        "recall_mean_std": stats(recall_list),
        "accuracy_mean_std": stats(acc_list),
        "fpr_mean_std": stats(fpr_list),
    }


def main():
    parser = argparse.ArgumentParser(description="多种子训练 + 评估编排")
    parser.add_argument("--seeds", type=int, default=3, help="种子数（默认 3）")
    parser.add_argument("--epochs", type=int, default=5, help="每轮训练 epoch 数")
    parser.add_argument("--lr", type=float, default=2e-4)
    parser.add_argument("--lora-r", type=int, default=16)
    parser.add_argument("--lora-alpha", type=int, default=32)
    parser.add_argument("--dev-ratio", type=float, default=0.15)
    parser.add_argument("--early-stopping-patience", type=int, default=2)
    parser.add_argument("--skip-train", action="store_true",
                        help="跳过训练，只评估已有 checkpoint")
    parser.add_argument("--skip-baseline", action="store_true",
                        help="跳过 baseline 评估")
    parser.add_argument("--extra-train-args", nargs="*", default=[],
                        help="传给 train_qlora.py 的额外参数")
    args = parser.parse_args()

    seed_list = [42 + i * 1000 for i in range(args.seeds)]  # 42, 1042, 2042
    print(f"多种子训练：seeds={seed_list}, epochs={args.epochs}")

    # 1. 训练每个种子
    adapter_paths = []
    for seed in seed_list:
        if args.skip_train:
            adapter_path = str(OUTPUT_DIR / f"lora_r{args.lora_r}_a{args.lora_alpha}_e{args.epochs}_s{seed}/best")
            print(f"跳过训练 seed={seed}，使用已有: {adapter_path}")
        else:
            ok = run_train(seed, args.epochs, args.lr, args.lora_r, args.lora_alpha,
                           args.dev_ratio, args.early_stopping_patience, args.extra_train_args)
            if not ok:
                print(f"训练 seed={seed} 失败，跳过")
                continue
        adapter_path = str(OUTPUT_DIR / f"lora_r{args.lora_r}_a{args.lora_alpha}_e{args.epochs}_s{seed}/best")
        adapter_paths.append((seed, adapter_path))

    # 2. 评估每个种子的 best checkpoint
    finetuned_result_files = []
    for seed, adapter_path in adapter_paths:
        if not Path(adapter_path).exists():
            print(f"checkpoint 不存在: {adapter_path}，跳过评估")
            continue
        rf = run_evaluate(seed, adapter_path, f"seed{seed}")
        finetuned_result_files.append(rf)

    # 3. 评估 baseline
    baseline_result_file = None
    if not args.skip_baseline:
        baseline_result_file = run_baseline_eval()

    # 4. 聚合
    print(f"\n{'='*60}")
    print("多种子聚合结果")
    print(f"{'='*60}")
    finetuned_agg = aggregate_results(finetuned_result_files)
    print(f"\nFinetuned ({finetuned_agg['n_seeds']} seeds):")
    for ps in finetuned_agg["per_seed"]:
        m = ps["metrics"]
        print(f"  recall={m.get('recall')}, accuracy={m.get('accuracy')}, fpr={m.get('false_positive_rate')}")
    print(f"  recall   mean±std: {finetuned_agg['recall_mean_std']}")
    print(f"  accuracy mean±std: {finetuned_agg['accuracy_mean_std']}")
    print(f"  fpr      mean±std: {finetuned_agg['fpr_mean_std']}")

    if baseline_result_file:
        print(f"\nBaseline: {baseline_result_file}")
        baseline_data = json.loads(baseline_result_file.read_text(encoding="utf-8"))
        bm = baseline_data.get("metrics", {})
        print(f"  recall={bm.get('recall')}, accuracy={bm.get('accuracy')}, fpr={bm.get('false_positive_rate')}")

    # 5. 保存聚合结果
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    summary_file = RESULTS_DIR / f"exp_06_multiseed_summary.{ts}.json"
    summary_file.write_text(json.dumps({
        "seeds": seed_list,
        "finetuned_aggregate": finetuned_agg,
        "baseline_file": str(baseline_result_file) if baseline_result_file else None,
        "finetuned_files": [str(f) for f in finetuned_result_files],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n聚合结果已保存: {summary_file}")

    # 6. 提示跑显著性检验
    if baseline_result_file and finetuned_result_files:
        print(f"\n跑 bootstrap 显著性检验：")
        print(f"  /home/zane/miniconda3/envs/graproj/bin/python3 {SCRIPTS_DIR / 'bootstrap_significance.py'} \\")
        print(f"    --baseline {baseline_result_file} \\")
        print(f"    --finetuned {finetuned_result_files[0]}")
        print(f"  （或对所有种子分别跑）")


if __name__ == "__main__":
    main()
