#!/usr/bin/env python3
"""L2 三模型交叉投票——全量，API 调用。

策略：
  - DeepSeek 生成的样本 → GLM + K3 复审
  - GLM 生成的样本 → DeepSeek + K3 复审
  - K3 生成的样本 → DeepSeek + GLM 复审
  - 三方在 {漏洞/安全, CWE, 行号} 任一不一致 → 标记分歧

复审只要求判断 {has_vulnerability, cwe, cited_lines}，不重新生成完整 CoT。
这样成本低、速度快，分歧样本才送 L3 闭源仲裁。

为什么三模型互审不能作为最终裁决：
  - 三大模型都是中国模型，预训练语料重叠，存在共同盲区
  - 三大模型各有偏置（DeepSeek 高误报、K3 保守、GLM 格式好但推理慢）
  - 互审会产生"同行放水"效应
  → 三模型互审的价值在于"标记分歧"，最终裁决由 L3 闭源模型完成

用法：
    PYTHONPATH=../../.. python3 l2_cross_vote.py \
        --data-file ../../../data/train_chatml_v9max_l1_passed.jsonl \
        --output ../../../data/train_chatml_v9max_l2_disputed.jsonl

环境变量：
    DEEPSEEK_API_KEY=sk-xxx
    GLM_API_KEY=xxx
    KIMI_API_KEY=xxx
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from common import (
    extract_cited_lines,
    extract_cot,
    extract_cwe_list,
    extract_verdict,
    get_assistant_content,
    get_metadata,
    get_user_content,
    read_jsonl,
    write_jsonl,
)

# ============================================================
# 复审 prompt（让复审模型独立判断标签是否正确）
# ============================================================
REVIEW_SYSTEM_PROMPT = """你是一名资深安全审计专家。你的任务是审查一个训练样本的标签是否正确。

你会收到：
1. 代码片段
2. 原标注（has_vulnerability / vulnerability_type / 关键行号）

请独立判断：
1. 这段代码是否真的有漏洞？（不要受原标注影响）
2. 如果有漏洞，CWE 编号是什么？
3. 关键行号是否正确指向漏洞位置？

输出 JSON（用 ```json 包裹）：
```json
{
  "has_vulnerability": true/false,
  "cwe": "CWE-XXX 或 none",
  "cited_lines": [行号列表],
  "confidence": "high/medium/low",
  "reason": "1 句话理由"
}
```

注意：
- 独立判断，不要默认原标注是对的
- 如果代码有有效防御措施，应该判为无漏洞
- 如果原标注的 CWE 错误，给出你认为正确的 CWE
"""

REVIEW_USER_TEMPLATE = """代码片段：
```
{code}
```

原标注：
- has_vulnerability: {has_vuln}
- vulnerability_type: {vuln_type}
- 关键行号: {cited_lines}

请独立审查上述标注是否正确。输出 JSON。"""


# ============================================================
# API 客户端配置（需填充 API key）
# ============================================================
def get_reviewers(generator: str) -> list[str]:
    """根据生成方确定两个复审方。"""
    all_models = {"deepseek", "glm", "kimi"}
    return [m for m in all_models if m != generator]


def call_reviewer(reviewer: str, code: str, original_label: dict) -> dict:
    """调用复审模型，返回 {has_vulnerability, cwe, cited_lines, confidence, reason}。

    TODO: 实现实际 API 调用。以下是伪代码框架：

    if reviewer == "deepseek":
        import openai
        client = openai.OpenAI(
            api_key=os.environ["DEEPSEEK_API_KEY"],
            base_url="https://api.deepseek.com/v1"
        )
        model = "deepseek-chat"
    elif reviewer == "glm":
        import zhipuai
        client = zhipuai.ZhipuAI(api_key=os.environ["GLM_API_KEY"])
        model = "glm-5.2"
    elif reviewer == "kimi":
        import openai
        client = openai.OpenAI(
            api_key=os.environ["KIMI_API_KEY"],
            base_url="https://api.moonshot.cn/v1"
        )
        model = "kimi-k3"

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": REVIEW_SYSTEM_PROMPT},
            {"role": "user", "content": REVIEW_USER_TEMPLATE.format(...)}
        ],
        temperature=0.0,  # 复审要确定性
        max_tokens=512,
    )
    # 解析 response → dict
    """
    raise NotImplementedError(
        f"请实现 {reviewer} API 调用。参考 docs/v9max_数据生成提示词.md §7 API 调用示例。"
    )


# ============================================================
# 共识检查
# ============================================================
def check_consensus(original: dict, review1: dict, review2: dict) -> dict:
    """检查三方共识。

    判定维度：
      1. has_vulnerability（漏洞/安全）—— 最重要
      2. CWE 编号（至少一个匹配）
      3. 行号（交集非空）

    返回:
      {
        "consensus": bool,  # 三方完全一致
        "disagreement_dims": [...],  # 分歧维度
        "original": original,
        "review1": review1,
        "review2": review2,
      }
    """
    disagreements = []

    # 维度 1: has_vulnerability
    orig_hv = original.get("has_vulnerability")
    r1_hv = review1.get("has_vulnerability")
    r2_hv = review2.get("has_vulnerability")
    if not (orig_hv == r1_hv == r2_hv):
        disagreements.append("has_vulnerability")

    # 维度 2: CWE（至少一个匹配）
    orig_cwe = set(original.get("cwe_list", []))
    r1_cwe = set(extract_cwe_list(review1.get("cwe", "")))
    r2_cwe = set(extract_cwe_list(review2.get("cwe", "")))
    if orig_cwe and r1_cwe and r2_cwe:
        if not (orig_cwe & r1_cwe) and not (orig_cwe & r2_cwe):
            disagreements.append("cwe")
    elif orig_hv:  # 有漏洞但 CWE 缺失
        disagreements.append("cwe")

    # 维度 3: 行号（交集非空，仅当有漏洞时检查）
    if orig_hv:
        orig_lines = set(original.get("cited_lines", []))
        r1_lines = set(review1.get("cited_lines", []))
        r2_lines = set(review2.get("cited_lines", []))
        if orig_lines and r1_lines and r2_lines:
            if not (orig_lines & r1_lines) and not (orig_lines & r2_lines):
                disagreements.append("cited_lines")

    return {
        "consensus": len(disagreements) == 0,
        "disagreement_dims": disagreements,
        "original": original,
        "review1": review1,
        "review2": review2,
    }


# ============================================================
# 主流程
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="L2 三模型交叉投票")
    parser.add_argument("--data-file", required=True, help="L1 通过的 jsonl")
    parser.add_argument("--output", required=True, help="分歧样本输出 jsonl")
    parser.add_argument("--sample-ratio", type=float, default=1.0,
                        help="抽样比例（1.0=全量，0.1=10% 抽样，用于测试）")
    args = parser.parse_args()

    samples = read_jsonl(args.data_file)
    print(f"读取 {len(samples)} 条 L1 通过样本")

    # 抽样（用于测试流程）
    if args.sample_ratio < 1.0:
        import random
        random.seed(42)
        n = int(len(samples) * args.sample_ratio)
        samples = random.sample(samples, n)
        print(f"抽样 {n} 条用于测试")

    disputed = []
    consensus_count = 0

    for i, sample in enumerate(samples):
        metadata = get_metadata(sample)
        generator = metadata.get("generator", "unknown")

        if generator == "unknown":
            print(f"[#{i}] 跳过：无 generator 标记")
            continue

        reviewers = get_reviewers(generator)
        print(f"[#{i}] generator={generator}, reviewers={reviewers}")

        # 提取原标注
        assistant = get_assistant_content(sample)
        verdict = extract_verdict(assistant)
        cot = extract_cot(assistant)
        original_label = {
            "has_vulnerability": verdict.get("has_vulnerability") if verdict else None,
            "cwe_list": extract_cwe_list(verdict.get("vulnerability_type", "")) if verdict else [],
            "cited_lines": extract_cited_lines(cot),
        }

        # 调用两个复审方
        code = get_user_content(sample)
        try:
            review1 = call_reviewer(reviewers[0], code, original_label)
            review2 = call_reviewer(reviewers[1], code, original_label)
        except NotImplementedError as e:
            print(f"  [跳过] {e}")
            continue

        # 检查共识
        result = check_consensus(original_label, review1, review2)

        if result["consensus"]:
            consensus_count += 1
        else:
            sample["_l2_dispute"] = {
                "generator": generator,
                "disagreement_dims": result["disagreement_dims"],
                "original": original_label,
                "review1": review1,
                "review2": review2,
            }
            disputed.append(sample)

    # 输出
    write_jsonl(args.output, disputed)
    print()
    print(f"=" * 70)
    print(f"L2 交叉投票结果")
    print(f"=" * 70)
    print(f"总样本: {len(samples)}")
    print(f"三方共识: {consensus_count} ({consensus_count/len(samples)*100:.1f}%)")
    print(f"有分歧: {len(disputed)} ({len(disputed)/len(samples)*100:.1f}%)")
    print(f"分歧样本写入: {args.output}")
    print()
    print(f"下一步: 将分歧样本送 L3 闭源模型仲裁（l3_arbiter.py）")


if __name__ == "__main__":
    main()
