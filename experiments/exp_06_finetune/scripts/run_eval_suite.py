"""
exp_06_finetune 完整评估套件 —— 一键跑 baseline / finetuned / 多种子 / CVE-fix / bootstrap。

用法：
  cd /home/zane/文档/code/毕业设计
  PYTHONPATH=/home/zane/文档/code/毕业设计 \
  /home/zane/miniconda3/envs/AI/bin/python experiments/exp_06_finetune/scripts/run_eval_suite.py \
      --adapter-dir experiments/exp_06_finetune/outputs/lora_r16_a32_e5_s42/best \
      --seeds 3

可选：
  --cve-fix-dir experiments/exp_06_finetune/testset_cve_fix
  --multiseed-only    只跑多种子评估
  --single-only       只跑单种子评估
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
AI_PYTHON = "/home/zane/miniconda3/envs/AI/bin/python"
GRAPROJ_PYTHON = "/home/zane/miniconda3/envs/graproj/bin/python3"
RESULTS_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/results"
EXP04_MANIFEST = PROJECT_ROOT / "experiments/exp_04_hard_samples/samples/manifest.json"
CVE_MANIFEST = PROJECT_ROOT / "experiments/exp_06_finetune/testset_cve_fix/manifest_eval.json"


def run(cmd: list[str], desc: str):
    print("\n" + "=" * 60)
    print(desc)
    print("=" * 60)
    print(" ".join(cmd))
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    env["CUDA_VISIBLE_DEVICES"] = "0"
    env["HIP_VISIBLE_DEVICES"] = "0"
    result = subprocess.run(cmd, cwd=PROJECT_ROOT, env=env)
    if result.returncode != 0:
        print(f"[错误] {desc} 失败，退出码 {result.returncode}", file=sys.stderr)
        sys.exit(result.returncode)


def latest_result(prefix: str) -> Path:
    """按文件名时间戳找最新的结果文件。"""
    candidates = sorted(RESULTS_DIR.glob(f"{prefix}.*.json"), key=lambda p: p.name)
    if not candidates:
        raise FileNotFoundError(f"未找到 {prefix}.*.json 结果文件")
    return candidates[-1]


def main():
    parser = argparse.ArgumentParser(description="exp_06_finetune 完整评估套件")
    parser.add_argument("--adapter-dir", type=str, required=True,
                        help="finetuned 模型 best adapter 目录")
    parser.add_argument("--seeds", type=int, default=3,
                        help="多种子评估的种子数（默认 3）")
    parser.add_argument("--cve-fix-dir", type=str, default=None,
                        help="CVE-fix 测试集目录（含 manifest_eval.json 和代码文件）")
    parser.add_argument("--multiseed-only", action="store_true",
                        help="只跑多种子评估")
    parser.add_argument("--single-only", action="store_true",
                        help="只跑单种子评估")
    args = parser.parse_args()

    adapter_dir = Path(args.adapter_dir)
    if not adapter_dir.exists():
        print(f"错误：adapter 目录不存在: {adapter_dir}", file=sys.stderr)
        sys.exit(1)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # 1. 单种子 baseline（确定性解码）
    # ------------------------------------------------------------------
    if not args.multiseed_only:
        run([
            AI_PYTHON, "experiments/exp_06_finetune/scripts/evaluate.py",
            "--mode", "baseline",
        ], "单种子 baseline 评估（temperature=0.0）")
        baseline_single = latest_result("exp_06_eval.baseline")
        print(f"baseline 单种子结果: {baseline_single}")

    # ------------------------------------------------------------------
    # 2. 单种子 finetuned
    # ------------------------------------------------------------------
    if not args.multiseed_only:
        run([
            AI_PYTHON, "experiments/exp_06_finetune/scripts/evaluate.py",
            "--mode", "finetuned",
            "--adapter-path", str(adapter_dir),
        ], "单种子 finetuned 评估（best checkpoint, temperature=0.0）")
        finetuned_single = latest_result("exp_06_eval.finetuned")
        print(f"finetuned 单种子结果: {finetuned_single}")

    # ------------------------------------------------------------------
    # 3. 多种子 baseline
    # ------------------------------------------------------------------
    if not args.single_only:
        run([
            AI_PYTHON, "experiments/exp_06_finetune/scripts/evaluate.py",
            "--mode", "baseline",
            "--seeds", str(args.seeds),
        ], f"多种子 baseline 评估（{args.seeds} seeds）")
        baseline_multi = latest_result("exp_06_eval.baseline_seeds")
        print(f"baseline 多种子结果: {baseline_multi}")

    # ------------------------------------------------------------------
    # 4. 多种子 finetuned
    # ------------------------------------------------------------------
    if not args.single_only:
        run([
            AI_PYTHON, "experiments/exp_06_finetune/scripts/evaluate.py",
            "--mode", "finetuned",
            "--adapter-path", str(adapter_dir),
            "--seeds", str(args.seeds),
        ], f"多种子 finetuned 评估（{args.seeds} seeds）")
        finetuned_multi = latest_result("exp_06_eval.finetuned")
        print(f"finetuned 多种子结果: {finetuned_multi}")

    # ------------------------------------------------------------------
    # 5. Bootstrap 显著性检验（单种子 + 多种子）
    # ------------------------------------------------------------------
    if not args.multiseed_only:
        run([
            GRAPROJ_PYTHON, "experiments/exp_06_finetune/scripts/bootstrap_significance.py",
            "--baseline", str(baseline_single),
            "--finetuned", str(finetuned_single),
            "--n-bootstrap", "10000",
        ], "Bootstrap 显著性检验（单种子）")

    if not args.single_only:
        run([
            GRAPROJ_PYTHON, "experiments/exp_06_finetune/scripts/bootstrap_significance.py",
            "--baseline", str(baseline_multi),
            "--finetuned", str(finetuned_multi),
            "--n-bootstrap", "10000",
        ], "Bootstrap 显著性检验（多种子）")

    # ------------------------------------------------------------------
    # 6. CVE-fix held-out 测试集评估
    # ------------------------------------------------------------------
    if args.cve_fix_dir:
        cve_dir = Path(args.cve_fix_dir)
        cve_manifest = cve_dir / "manifest_eval.json"
        if not cve_manifest.exists():
            print(f"错误：CVE-fix manifest_eval.json 不存在: {cve_manifest}", file=sys.stderr)
            print("请先运行 adapter_cve_fix_manifest.py 转换", file=sys.stderr)
            sys.exit(1)

        run([
            AI_PYTHON, "experiments/exp_06_finetune/scripts/evaluate.py",
            "--mode", "finetuned",
            "--adapter-path", str(adapter_dir),
            "--manifest-path", str(cve_manifest),
            "--samples-dir", str(cve_dir),
        ], "CVE-fix held-out 测试集评估（finetuned）")

        run([
            AI_PYTHON, "experiments/exp_06_finetune/scripts/evaluate.py",
            "--mode", "baseline",
            "--manifest-path", str(cve_manifest),
            "--samples-dir", str(cve_dir),
        ], "CVE-fix held-out 测试集评估（baseline）")

    print("\n" + "=" * 60)
    print("评估套件完成")
    print("=" * 60)
    print(f"结果目录: {RESULTS_DIR}")
    for f in sorted(RESULTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime)[-10:]:
        print(f"  {f.name}")


if __name__ == "__main__":
    main()
