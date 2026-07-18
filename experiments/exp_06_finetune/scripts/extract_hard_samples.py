"""
Phase 6 - Hard sample 提取脚本 —— 从 evaluate.py 输出中提取错题，
用于复习机制闭环（hard sample mining）。

对应 docs/方法.md §9 Phase 6。

输入：evaluate.py 生成的 JSON 文件（含 samples 数组）
  results/exp_06_eval.*.json

输出：错题清单
  results/hard_samples_{source_tag}.json
    {
      "summary": {...},
      "fn_samples": [...],          # 漏报（最严重，模型该报但漏了）
      "fp_samples": [...],          # 误报（FPR 来源）
      "cwe_mismatch_samples": [...], # TP 但 CWE 标错
      "slow_samples": [...],        # 响应慢（>阈值秒）
      "all_hard_samples": [...]     # 所有合并，便于增强
    }

后续用法：
  1. 把 hard_samples 喂给 Qwen3-30B 重生成 CoT
  2. 用 augment_data.py 做数据增强
  3. 合并回 train_chatml_v2.jsonl 重训

用法：
  /home/zane/miniconda3/envs/AI/bin/python extract_hard_samples.py \\
      --eval-json results/exp_06_eval.phase1_lr1e-4_rslora.{ts}.json \\
      --source-tag lr1e-4_rslora

  # 批量处理所有 phase1 评估结果
  /home/zane/miniconda3/envs/AI/bin/python extract_hard_samples.py --batch phase1
"""

import argparse
import glob
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
RESULTS_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/results"

# 默认慢响应阈值（秒）
DEFAULT_SLOW_THRESHOLD = 30.0

# CWE 匹配正则
_CWE_PATTERN = re.compile(r"(CWE-\d+)", re.IGNORECASE)


def extract_cwe(text: str) -> str:
    if not text:
        return ""
    m = _CWE_PATTERN.search(text)
    return m.group(1).upper() if m else ""


def cwe_matches(model_cwe: str, expected_cwe: str) -> bool:
    if not expected_cwe or expected_cwe.upper() == "N/A":
        return True
    if not model_cwe:
        return False
    expected_cwes = [c.strip().upper() for c in expected_cwe.split(";") if c.strip()]
    return model_cwe in expected_cwes


def extract_sample_info(sample: dict) -> dict:
    """提取关键信息（去掉 raw_output，节省空间；但保留便于后续增强）。"""
    return {
        "file": sample.get("file", ""),
        "language": sample.get("language", ""),
        "category": sample.get("category", ""),
        "difficulty": sample.get("difficulty", ""),
        "expected_present": sample.get("expected_present"),
        "model_has_vulnerability": sample.get("model_has_vulnerability"),
        "predicted": sample.get("predicted"),
        "outcome": sample.get("outcome", ""),
        "expected_vulnerability": sample.get("expected_vulnerability", ""),
        "expected_cwe": sample.get("expected_cwe", ""),
        "elapsed_seconds": sample.get("elapsed_seconds", 0),
        "raw_output": sample.get("raw_output", ""),  # 保留，用于增强
    }


def process_eval(eval_path: Path, source_tag: str, slow_threshold: float) -> dict:
    """处理单个 evaluate 输出文件。"""
    with open(eval_path, "r", encoding="utf-8") as fp:
        data = json.load(fp)

    samples = data.get("samples", [])
    if not samples:
        print(f"⚠️ {eval_path.name} 无 samples 字段", file=sys.stderr)
        return {}

    # 按 outcome 分类
    fn_samples = []           # 漏报
    fp_samples = []            # 误报
    cwe_mismatch_samples = []  # TP 但 CWE 标错
    slow_samples = []          # 慢响应

    for s in samples:
        outcome = s.get("outcome", "")
        info = extract_sample_info(s)

        # 漏报
        if outcome == "FN":
            fn_samples.append(info)
        # 误报
        elif outcome == "FP":
            fp_samples.append(info)
        # TP 但 CWE 标错
        elif outcome == "TP":
            model_cwe = extract_cwe(s.get("raw_output", ""))
            expected_cwe = s.get("expected_cwe", "")
            if not cwe_matches(model_cwe, expected_cwe):
                info["model_cwe"] = model_cwe
                cwe_mismatch_samples.append(info)

        # 慢响应
        if s.get("elapsed_seconds", 0) > slow_threshold:
            slow_samples.append(info)

    # 统计
    total = len(samples)
    summary = {
        "source_file": str(eval_path.relative_to(PROJECT_ROOT)),
        "source_tag": source_tag,
        "total_samples": total,
        "TP": sum(1 for s in samples if s.get("outcome") == "TP"),
        "FP": len(fp_samples),
        "FN": len(fn_samples),
        "TN": sum(1 for s in samples if s.get("outcome") == "TN"),
        "cwe_mismatch": len(cwe_mismatch_samples),
        "slow_samples": len(slow_samples),
        "slow_threshold_sec": slow_threshold,
        "accuracy": sum(1 for s in samples if s.get("outcome") in ("TP", "TN")) / total if total else 0,
        "recall": len([s for s in samples if s.get("outcome") == "TP"]) /
                  max(1, sum(1 for s in samples if s.get("expected_present"))),
        "fpr": len(fp_samples) /
               max(1, sum(1 for s in samples if not s.get("expected_present"))),
    }

    return {
        "summary": summary,
        "fn_samples": fn_samples,
        "fp_samples": fp_samples,
        "cwe_mismatch_samples": cwe_mismatch_samples,
        "slow_samples": slow_samples,
        "all_hard_samples": fn_samples + fp_samples + cwe_mismatch_samples,
    }


def main():
    parser = argparse.ArgumentParser(description="提取 hard samples")
    parser.add_argument("--eval-json", type=Path, help="单个 evaluate 输出文件")
    parser.add_argument("--source-tag", type=str, default="",
                        help="结果标识（默认用文件名）")
    parser.add_argument("--batch", type=str, default="",
                        help="批量模式：phase1 / phase2 / all")
    parser.add_argument("--slow-threshold", type=float, default=DEFAULT_SLOW_THRESHOLD,
                        help=f"慢响应阈值（默认 {DEFAULT_SLOW_THRESHOLD}s）")
    parser.add_argument("--output-dir", type=Path, default=RESULTS_DIR)
    args = parser.parse_args()

    print("=" * 60)
    print("Phase 6 - Hard Sample 提取")
    print("=" * 60)

    # 决定要处理的文件列表
    if args.batch:
        # 批量模式
        pattern = {
            "phase1": "exp_06_eval.phase1_*.json",
            "phase2": "exp_06_eval.phase2_*.json",
            "all": "exp_06_eval.*.json",
        }.get(args.batch, f"exp_06_eval.{args.batch}_*.json")
        eval_files = sorted(Path(args.output_dir).glob(pattern))
        if not eval_files:
            print(f"❌ 未找到匹配 {pattern} 的文件")
            sys.exit(1)
        print(f"批量模式 [{args.batch}]: 找到 {len(eval_files)} 个文件")
    else:
        if not args.eval_json:
            print("❌ 必须指定 --eval-json 或 --batch")
            sys.exit(1)
        eval_files = [args.eval_json]

    # 处理每个文件
    all_summaries = []
    for eval_path in eval_files:
        # 从文件名提取 tag
        if not args.source_tag:
            # exp_06_eval.phase1_lr1e-4_rslora.{ts}.json → lr1e-4_rslora
            m = re.search(r"exp_06_eval\.(?:phase\d+_)?(.+?)\.\d{8}_\d{6}\.json", eval_path.name)
            tag = m.group(1) if m else eval_path.stem
        else:
            tag = args.source_tag

        print(f"\n--- 处理 {eval_path.name} (tag={tag}) ---")
        result = process_eval(eval_path, tag, args.slow_threshold)

        if not result:
            continue

        # 打印摘要
        s = result["summary"]
        print(f"  总样本: {s['total_samples']}")
        print(f"  TP={s['TP']} FP={s['FP']} FN={s['FN']} TN={s['TN']}")
        print(f"  accuracy={s['accuracy']*100:.1f}% recall={s['recall']*100:.1f}% FPR={s['fpr']*100:.1f}%")
        print(f"  CWE 错配: {s['cwe_mismatch']}  慢响应(>{s['slow_threshold_sec']}s): {s['slow_samples']}")
        print(f"  FN 样本: {len(result['fn_samples'])}  FP 样本: {len(result['fp_samples'])}")

        # 写出
        out_path = args.output_dir / f"hard_samples_{tag}.json"
        with open(out_path, "w", encoding="utf-8") as fp:
            json.dump(result, fp, ensure_ascii=False, indent=2)
        print(f"  输出: {out_path}")

        all_summaries.append(s)

    # 汇总
    if len(all_summaries) > 1:
        print("\n" + "=" * 60)
        print("批量汇总")
        print("=" * 60)
        print(f"{'Tag':<25} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} {'Acc':>6} {'Recall':>8} {'FPR':>6} {'CWE误':>5}")
        for s in all_summaries:
            print(f"{s['source_tag']:<25} {s['TP']:>4} {s['FP']:>4} {s['FN']:>4} {s['TN']:>4} "
                  f"{s['accuracy']*100:>5.1f}% {s['recall']*100:>7.1f}% {s['fpr']*100:>5.1f}% {s['cwe_mismatch']:>5}")

        # 找最差 tag（FN 最多）作为后续增强目标
        worst = max(all_summaries, key=lambda x: x["FN"])
        print(f"\n最需改进（FN 最多）: {worst['source_tag']} FN={worst['FN']}")

    print(f"\n✅ 提取完成")
    print(f"   下一步：用 augment_data.py 增强这些 hard samples")


if __name__ == "__main__":
    main()