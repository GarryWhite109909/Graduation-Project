#!/usr/bin/env python3
"""L3 闭源模型仲裁——分歧样本 + 抽样校准。

主审：Claude Opus 4.1（推理最强、安全对齐成熟、长上下文 200K）
副审：GPT-5（交叉验证 Claude 判断，防 Claude 过度保守）
审查 prompt 用英文（避免中文语料偏置）

为什么必须用闭源模型：
  - 三大开源模型（DeepSeek/GLM/K3）都是中国模型，预训练语料重叠，存在共同盲区
  - 三大模型各有偏置，互审会产生"同行放水"效应
  - 审查比生成容易，闭源模型的判断显著更可靠
  - 闭源模型安全对齐不同，提供独立第三方视角

为什么不全量审查：
  - 成本：11500 条 × Claude API 单价，可能几百到上千元
  - 没必要：L1 规则 + L2 投票已解决 80% 问题
  - 闭源模型也有偏置（Claude 过度保守），全量审查可能引入新偏差

输入：
  - L2 分歧样本（l2_disputed.jsonl）
  - 每个生成模型抽样 5-10%（用于质量校准）

输出：
  - 仲裁结果（arbitrated.jsonl）：采纳/驳回/需人工
  - 质量评分报告（quality_report.json）

用法：
    PYTHONPATH=../../.. python3 l3_arbiter.py \
        --disputed-file ../../../data/train_chatml_v9max_l2_disputed.jsonl \
        --sample-file ../../../data/train_chatml_v9max_l1_passed.jsonl \
        --sample-ratio 0.05 \
        --output-dir ../../../data/l3_output

环境变量：
    ANTHROPIC_API_KEY=sk-ant-xxx
    OPENAI_API_KEY=sk-xxx
"""

from __future__ import annotations

import argparse
import json
import os
import random
from pathlib import Path

from common import (
    extract_cwe_list,
    extract_verdict,
    get_assistant_content,
    get_metadata,
    get_user_content,
    read_jsonl,
    write_jsonl,
)


# ============================================================
# Claude Opus 4.1 审查 prompt（英文，反偏置）
# ============================================================
CLAUDE_REVIEW_PROMPT = """You are a senior security reviewer auditing training samples for a code vulnerability detection model. Your judgment is final arbitration—be rigorous but fair.

You will receive:
1. A code snippet
2. The original label (has_vulnerability / CWE / cited lines / CoT reasoning / fix)
3. Two reviewer judgments (from other models) that disagreed with the original

Audit criteria (rate each 1-5):
1. label_correctness: Is the vulnerability/safety label accurate?
2. cwe_accuracy: Is the CWE attribution correct per MITRE definition?
3. reasoning_quality: Is the CoT grounded in specific code lines? No hallucination? ≤5 steps?
4. fix_validity: Does the fix actually resolve the vulnerability without introducing new issues?
5. format_compliance: Does it follow the 3-section format (code → reasoning → JSON verdict)?

CRITICAL — Anti-bias instructions:
- Do NOT be overly conservative: safe code with effective defenses (parameterized queries, shlex.quote, PreparedStatement, RAII, etc.) should be judged SAFE. Do not mark safe code as vulnerable just because it looks suspicious.
- Do NOT be overly permissive: weak defenses (replace("'", ""), startswith without normalization, partial encoding) do NOT make code safe. Be strict about incomplete defenses.
- Ground your judgment in specific code lines, not general suspicion.

Output JSON (wrapped in ```json):
```json
{
  "label_correct": true/false,
  "corrected_label": {
    "has_vulnerability": true/false,
    "cwe": "CWE-XXX or none",
    "cited_lines": [line numbers]
  },
  "cwe_correct": true/false,
  "reasoning_quality": 1-5,
  "fix_valid": true/false,
  "format_compliant": true/false,
  "overall_score": 1-5,
  "issues": ["specific problem 1", "specific problem 2"],
  "reason": "1-2 sentence explanation"
}
```

If the original label is correct, set label_correct=true and corrected_label=original.
If the original label is wrong, set label_correct=false and provide corrected_label."""


# ============================================================
# GPT-5 副审 prompt（英文，交叉验证）
# ============================================================
GPT5_REVIEW_PROMPT = """You are a security expert reviewing a code vulnerability training sample. Provide an independent judgment.

You will receive a code snippet and its label. Judge independently:
1. Is the label (vulnerable/safe) correct?
2. Is the CWE attribution accurate?
3. Are the cited line numbers correct?

Be balanced: neither overly conservative (marking safe code as vulnerable) nor overly permissive (accepting weak defenses as safe).

Output JSON (wrapped in ```json):
```json
{
  "label_correct": true/false,
  "corrected_label": {
    "has_vulnerability": true/false,
    "cwe": "CWE-XXX or none"
  },
  "confidence": "high/medium/low",
  "reason": "1 sentence explanation"
}
```"""


def build_review_input(sample: dict) -> str:
    """构建送审输入（代码 + 原标注 + 复审分歧）。"""
    code = get_user_content(sample)
    assistant = get_assistant_content(sample)
    verdict = extract_verdict(assistant)
    metadata = get_metadata(sample)

    dispute_info = sample.get("_l2_dispute", {})

    return f"""Code:
{code}

Original label:
- has_vulnerability: {verdict.get('has_vulnerability') if verdict else 'N/A'}
- vulnerability_type: {verdict.get('vulnerability_type', 'N/A') if verdict else 'N/A'}
- generator: {metadata.get('generator', 'unknown')}
- category: {metadata.get('category', 'unknown')}

Reviewer disagreements:
{json.dumps(dispute_info, ensure_ascii=False, indent=2) if dispute_info else 'No disagreement info (quality sampling)'}"""


# ============================================================
# API 调用（需填充 API key）
# ============================================================
def call_claude(sample: dict) -> dict:
    """调用 Claude Opus 4.1 主审。

    TODO: 实现实际 API 调用。伪代码：

    import anthropic
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    response = client.messages.create(
        model="claude-opus-4-1-20250805",
        max_tokens=1024,
        system=CLAUDE_REVIEW_PROMPT,
        messages=[
            {"role": "user", "content": build_review_input(sample)}
        ],
        temperature=0.0,  # 仲裁要确定性
    )
    # 解析 response.content → JSON dict
    """
    raise NotImplementedError(
        "请实现 Claude API 调用。需要 anthropic 包和 ANTHROPIC_API_KEY。"
    )


def call_gpt5(sample: dict) -> dict:
    """调用 GPT-5 副审。

    TODO: 实现实际 API 调用。伪代码：

    import openai
    client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])

    response = client.chat.completions.create(
        model="gpt-5",
        messages=[
            {"role": "system", "content": GPT5_REVIEW_PROMPT},
            {"role": "user", "content": build_review_input(sample)}
        ],
        temperature=0.0,
        max_tokens=512,
    )
    # 解析 response → JSON dict
    """
    raise NotImplementedError(
        "请实现 GPT-5 API 调用。需要 openai 包和 OPENAI_API_KEY。"
    )


# ============================================================
# 仲裁逻辑
# ============================================================
def arbitrate(claude_result: dict, gpt5_result: dict) -> dict:
    """仲裁逻辑。

    - Claude 与 GPT-5 一致 → 采纳（accept/reject 基于 label_correct）
    - Claude 与 GPT-5 分歧 → 标记"需人工"（manual_review）
    """
    claude_label_correct = claude_result.get("label_correct")
    gpt5_label_correct = gpt5_result.get("label_correct")

    if claude_label_correct == gpt5_label_correct:
        # 一致
        if claude_label_correct:
            verdict = "accept"  # 原标注正确，采纳
        else:
            verdict = "reject"  # 原标注错误，驳回
        confidence = "high"
    else:
        # 分歧
        verdict = "manual_review"
        confidence = "low"

    return {
        "verdict": verdict,
        "confidence": confidence,
        "claude": claude_result,
        "gpt5": gpt5_result,
        "corrected_label": claude_result.get("corrected_label", {}),
        "overall_score": claude_result.get("overall_score", 0),
        "issues": claude_result.get("issues", []),
    }


# ============================================================
# 主流程
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="L3 闭源模型仲裁")
    parser.add_argument("--disputed-file", required=True, help="L2 分歧样本 jsonl")
    parser.add_argument("--sample-file", default=None,
                        help="L1 通过的全量样本（用于抽样校准）")
    parser.add_argument("--sample-ratio", type=float, default=0.05,
                        help="抽样校准比例（0.05=每个生成器抽 5%）")
    parser.add_argument("--output-dir", required=True, help="输出目录")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # --- 1. 仲裁分歧样本 ---
    disputed = read_jsonl(args.disputed_file)
    print(f"读取 {len(disputed)} 条分歧样本")

    arbitrated = []
    for i, sample in enumerate(disputed):
        print(f"[#{i}] 仲裁中...")
        try:
            claude_result = call_claude(sample)
            gpt5_result = call_gpt5(sample)
        except NotImplementedError as e:
            print(f"  [跳过] {e}")
            continue

        result = arbitrate(claude_result, gpt5_result)
        sample["_l3_arbitration"] = result
        arbitrated.append(sample)

    # --- 2. 抽样校准（每个生成器抽 5-10%）---
    calibration_samples = []
    if args.sample_file:
        all_samples = read_jsonl(args.sample_file)
        # 按生成器分组
        by_generator = {}
        for s in all_samples:
            gen = get_metadata(s).get("generator", "unknown")
            by_generator.setdefault(gen, []).append(s)

        random.seed(42)
        for gen, gen_samples in by_generator.items():
            n = max(1, int(len(gen_samples) * args.sample_ratio))
            sampled = random.sample(gen_samples, min(n, len(gen_samples)))
            print(f"生成器 {gen}: 抽样 {len(sampled)} 条校准")
            for s in sampled:
                s["_l3_calibration"] = True
                calibration_samples.append(s)

        print(f"抽样校准 {len(calibration_samples)} 条")

        for i, sample in enumerate(calibration_samples):
            print(f"[校准 #{i}] 评估生成器质量...")
            try:
                claude_result = call_claude(sample)
                # 抽样校准只需 Claude，不需 GPT-5
                sample["_l3_quality_score"] = claude_result
            except NotImplementedError as e:
                print(f"  [跳过] {e}")
                continue

    # --- 3. 输出 ---
    arbitrated_file = output_dir / "arbitrated.jsonl"
    write_jsonl(arbitrated_file, arbitrated)

    if calibration_samples:
        calibration_file = output_dir / "calibration.jsonl"
        write_jsonl(calibration_file, calibration_samples)

    # 生成报告
    report = {
        "disputed_count": len(disputed),
        "arbitrated_count": len(arbitrated),
        "calibration_count": len(calibration_samples),
        "verdict_stats": {},
    }

    for s in arbitrated:
        v = s.get("_l3_arbitration", {}).get("verdict", "unknown")
        report["verdict_stats"][v] = report["verdict_stats"].get(v, 0) + 1

    # 质量评分汇总
    if calibration_samples:
        quality_by_gen = {}
        for s in calibration_samples:
            gen = get_metadata(s).get("generator", "unknown")
            score = s.get("_l3_quality_score", {}).get("overall_score", 0)
            quality_by_gen.setdefault(gen, []).append(score)
        report["quality_by_generator"] = {
            gen: {
                "mean_score": sum(scores) / len(scores),
                "count": len(scores),
            }
            for gen, scores in quality_by_gen.items()
        }

    report_file = output_dir / "l3_report.json"
    with report_file.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print()
    print("=" * 70)
    print("L3 闭源仲裁结果")
    print("=" * 70)
    print(f"分歧样本: {len(disputed)}")
    print(f"已仲裁: {len(arbitrated)}")
    for v, c in report["verdict_stats"].items():
        print(f"  {v}: {c}")
    if "quality_by_generator" in report:
        print(f"\n生成器质量评分（抽样校准）:")
        for gen, stats in report["quality_by_generator"].items():
            print(f"  {gen}: 均分 {stats['mean_score']:.2f} ({stats['count']} 条)")
    print(f"\n输出目录: {output_dir}")
    print()
    print("仲裁结论:")
    print("  - accept: 原标注正确，保留")
    print("  - reject: 原标注错误，需修正或删除")
    print("  - manual_review: Claude 与 GPT-5 分歧，需人工确认（预计 <5%）")


if __name__ == "__main__":
    main()
