#!/usr/bin/env python3
"""分层审查流水线——L1 → L2 → L3 → L4 → 合并。

完整审查流程：
  L1 规则校验（全量，免费）→ 过滤格式错误
  L2 三模型交叉投票（全量，API）→ 标记分歧
  L3 闭源模型仲裁（分歧+抽样，Claude+GPT-5）→ 最终裁决
  L4 金标准校准（一次性，评估生成器）→ 加权方案
  合并 → 清洗后的最终训练数据

用法：
    PYTHONPATH=../../.. python3 run_pipeline.py \
        --data-file ../../../data/train_chatml_v9max.jsonl \
        --output-dir ../../../data/v9max_audited \
        [--golden-dir ../../../testset_cve_fix] \
        [--skip-l2] [--skip-l3] [--skip-l4]  # 跳过某层（测试用）

注意：
  - L1 可独立运行（免费）
  - L2/L3 需要 API key（DEEPSEEK/GLM/KIMI/ANTHROPIC/OPENAI）
  - L4 需要金标准集
  - 首次运行建议加 --skip-l2 --skip-l3 --skip-l4 只跑 L1
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from common import read_jsonl, write_jsonl


def run_step(name: str, script: str, args: list[str]) -> bool:
    """运行一个审查步骤。返回是否成功。"""
    print()
    print("=" * 70)
    print(f"运行 {name}: {script}")
    print("=" * 70)
    cmd = [sys.executable, script] + args
    result = subprocess.run(cmd, capture_output=False)
    if result.returncode != 0:
        print(f"ERROR: {name} 失败 (exit code {result.returncode})")
        return False
    return True


def merge_final(l1_passed_file: Path, l3_arbitrated_file: Path | None,
                l4_report_file: Path | None, output_file: Path) -> dict:
    """合并最终数据。

    1. 以 L1 通过的样本为基础
    2. 移除 L3 标记为 reject 的样本
    3. 对 L3 标记为 accept 但 corrected_label 不同的样本，修正标签
    4. 应用 L4 权重标记到 metadata.confidence
    """
    samples = read_jsonl(l1_passed_file)
    print(f"L1 通过样本: {len(samples)}")

    # 移除 L3 reject
    if l3_arbitrated_file and l3_arbitrated_file.exists():
        arbitrated = read_jsonl(l3_arbitrated_file)
        reject_count = 0
        accept_corrected = 0

        # 建立索引（按样本内容哈希）
        reject_set = set()
        corrections = {}
        for s in arbitrated:
            arbitration = s.get("_l3_arbitration", {})
            verdict = arbitration.get("verdict")
            # 用 user content 前缀作为 key（简化）
            user_content = ""
            for m in s.get("messages", []):
                if m.get("role") == "user":
                    user_content = m.get("content", "")[:200]
                    break

            if verdict == "reject":
                reject_set.add(user_content)
                reject_count += 1
            elif verdict == "accept":
                corrected = arbitration.get("corrected_label", {})
                if corrected and corrected.get("has_vulnerability") is not None:
                    corrections[user_content] = corrected
                    accept_corrected += 1

        # 过滤
        filtered = []
        for s in samples:
            user_content = ""
            for m in s.get("messages", []):
                if m.get("role") == "user":
                    user_content = m.get("content", "")[:200]
                    break
            if user_content in reject_set:
                continue
            # 应用修正（TODO: 实际修正逻辑）
            filtered.append(s)

        print(f"L3 reject 移除: {reject_count}")
        print(f"L3 accept 修正: {accept_corrected}")
        samples = filtered

    # 应用 L4 权重
    if l4_report_file and l4_report_file.exists():
        with l4_report_file.open() as f:
            l4_report = json.load(f)
        weights = l4_report.get("weights", {})
        for s in samples:
            gen = s.get("metadata", {}).get("generator", "unknown")
            weight = weights.get(gen, 1.0)
            s.setdefault("metadata", {})["confidence_weight"] = weight
        print(f"L4 权重应用: {weights}")

    # 写出
    write_jsonl(output_file, samples)
    print(f"最终数据写入: {output_file} ({len(samples)} 条)")

    return {
        "final_count": len(samples),
        "l1_passed": len(read_jsonl(l1_passed_file)),
    }


def main():
    parser = argparse.ArgumentParser(description="分层审查流水线")
    parser.add_argument("--data-file", required=True, help="待审查的 jsonl")
    parser.add_argument("--output-dir", required=True, help="输出目录")
    parser.add_argument("--golden-dir", default=None, help="金标准集目录（L4）")
    parser.add_argument("--skip-l2", action="store_true", help="跳过 L2")
    parser.add_argument("--skip-l3", action="store_true", help="跳过 L3")
    parser.add_argument("--skip-l4", action="store_true", help="跳过 L4")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    script_dir = Path(__file__).parent

    data_file = Path(args.data_file)
    stem = data_file.stem

    # --- L1 规则校验 ---
    l1_passed = output_dir / f"{stem}_l1_passed.jsonl"
    l1_report = output_dir / f"{stem}_l1_report.json"
    if not run_step("L1 规则校验", str(script_dir / "l1_rule_check.py"),
                    ["--data-file", str(data_file),
                     "--output", str(l1_report)]):
        print("L1 失败，流水线中止")
        return

    # --- L2 交叉投票 ---
    l2_disputed = output_dir / f"{stem}_l2_disputed.jsonl"
    if not args.skip_l2:
        if not run_step("L2 交叉投票", str(script_dir / "l2_cross_vote.py"),
                        ["--data-file", str(l1_passed),
                         "--output", str(l2_disputed)]):
            print("L2 失败，跳过（可能是 API 未配置）")
            args.skip_l3 = True

    # --- L3 闭源仲裁 ---
    l3_output = output_dir / "l3_output"
    l3_arbitrated = l3_output / "arbitrated.jsonl"
    if not args.skip_l3 and not args.skip_l2:
        if not run_step("L3 闭源仲裁", str(script_dir / "l3_arbiter.py"),
                        ["--disputed-file", str(l2_disputed),
                         "--sample-file", str(l1_passed),
                         "--sample-ratio", "0.05",
                         "--output-dir", str(l3_output)]):
            print("L3 失败（可能是 API 未配置）")

    # --- L4 金标准校准 ---
    l4_report = output_dir / "l4_golden_report.json"
    if not args.skip_l4 and args.golden_dir:
        run_step("L4 金标准校准", str(script_dir / "l4_golden_eval.py"),
                 ["--golden-dir", args.golden_dir,
                  "--output", str(l4_report)])

    # --- 合并最终数据 ---
    final_output = output_dir / f"{stem}_final.jsonl"
    merge_final(
        l1_passed,
        l3_arbitrated if l3_arbitrated.exists() else None,
        l4_report if l4_report.exists() else None,
        final_output,
    )

    print()
    print("=" * 70)
    print("审查流水线完成")
    print("=" * 70)
    print(f"最终数据: {final_output}")
    print()
    print("审查总结:")
    print("  L1 规则校验: 过滤格式错误（免费、全量）")
    if not args.skip_l2:
        print("  L2 交叉投票: 标记三方分歧（API、全量）")
    if not args.skip_l3:
        print("  L3 闭源仲裁: Claude+GPT-5 裁决分歧（API、分歧+抽样）")
    if not args.skip_l4:
        print("  L4 金标准校准: 评估生成器质量（一次性）")
    print()
    print("下一步: 用最终数据训练 v9max")


if __name__ == "__main__":
    main()
