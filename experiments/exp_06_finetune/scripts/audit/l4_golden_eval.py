#!/usr/bin/env python3
"""L4 金标准集校准——评估生成模型本身的质量。

用 50-100 条金标准（已知 CVE + 人工确认无漏洞代码）评估每个生成模型，
按准确率给该模型输出加权，用于最终数据合并时的置信度调整。

金标准集来源：
  - 已知 CVE-fix 样本（项目已有 20 条 cve_fix，答案来自 NVD）
  - 人工确认无漏洞的安全代码（项目已有 18 条 safe_*）
  - 可补充 OWASP benchmark / SARD 样本

加权方案：
  - 准确率 >= 0.85: 权重 1.0（高置信，样本全量保留）
  - 准确率 0.70-0.85: 权重 0.8（中置信，样本保留但 L3 优先审查）
  - 准确率 < 0.70: 权重 0.5（低置信，样本降权或考虑弃用该生成器）

为什么需要 L4：
  - L1-L3 审查的是"单条样本对不对"，L4 审查的是"生成器本身可靠不可靠"
  - 如果 DeepSeek 在金标准上准确率只有 60%，那它生成的 7700 条都需要加强审查
  - L4 结果指导 L2/L3 的审查力度分配（低质量生成器抽样比例提高）

用法：
    PYTHONPATH=../../.. python3 l4_golden_eval.py \
        --golden-dir ../../../testset_cve_fix \
        --generators deepseek glm kimi \
        --output ../../../data/l4_golden_report.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from common import read_jsonl, write_jsonl


# 金标准集样本格式
GOLDEN_SAMPLE_SCHEMA = {
    "code": "代码片段",
    "language": "python/java/javascript/c/php",
    "has_vulnerability": True,
    "cwe": "CWE-89",
    "cited_lines": [42, 45],
    "source": "CVE-2019-12419 或 safe_01 或 owasp-benchmark",
}


def load_golden_set(golden_dir: Path | str) -> list[dict]:
    """加载金标准集。

    支持两种格式：
    1. jsonl 文件（每条含 code/language/has_vulnerability/cwe/cited_lines）
    2. 代码文件 + manifest.json（如 testset_cve_fix 的结构）

    TODO: 根据实际金标准集格式实现
    """
    golden_dir = Path(golden_dir)
    golden = []

    # 方式 1: jsonl 文件
    golden_jsonl = golden_dir / "golden_set.jsonl"
    if golden_jsonl.exists():
        golden = read_jsonl(golden_jsonl)
        return golden

    # 方式 2: 代码文件 + manifest
    manifest = golden_dir / "manifest.json"
    if manifest.exists():
        with manifest.open() as f:
            manifest_data = json.load(f)
        for item in manifest_data.get("samples", []):
            code_file = golden_dir / item["file"]
            if code_file.exists():
                golden.append({
                    "code": code_file.read_text(encoding="utf-8"),
                    "language": item.get("language", "unknown"),
                    "has_vulnerability": item.get("has_vulnerability", True),
                    "cwe": item.get("cwe", ""),
                    "cited_lines": item.get("cited_lines", []),
                    "source": item.get("source", ""),
                })

    return golden


def evaluate_generator(generator: str, golden_set: list[dict]) -> dict:
    """让生成模型在金标准集上跑，计算准确率。

    TODO: 实现实际 API 调用。让生成模型对每条金标准生成判断，
    然后对比金标准答案。

    伪代码：
    correct = 0
    cwe_correct = 0
    for golden in golden_set:
        # 调用生成模型判断
        prediction = call_generator(generator, golden["code"])
        if prediction["has_vulnerability"] == golden["has_vulnerability"]:
            correct += 1
            if prediction.get("cwe") == golden["cwe"]:
                cwe_correct += 1

    return {
        "generator": generator,
        "total": len(golden_set),
        "correct": correct,
        "accuracy": correct / len(golden_set),
        "cwe_accuracy": cwe_correct / len(golden_set),
    }
    """
    raise NotImplementedError(
        f"请实现 {generator} 在金标准集上的评估调用。"
    )


def compute_weights(accuracies: dict[str, float]) -> dict[str, float]:
    """根据准确率计算加权方案。

    >= 0.85: 权重 1.0（高置信）
    0.70-0.85: 权重 0.8（中置信）
    < 0.70: 权重 0.5（低置信）
    """
    weights = {}
    for gen, acc in accuracies.items():
        if acc >= 0.85:
            weights[gen] = 1.0
        elif acc >= 0.70:
            weights[gen] = 0.8
        else:
            weights[gen] = 0.5
    return weights


def main():
    parser = argparse.ArgumentParser(description="L4 金标准集校准")
    parser.add_argument("--golden-dir", required=True, help="金标准集目录")
    parser.add_argument("--generators", nargs="+", default=["deepseek", "glm", "kimi"],
                        help="要评估的生成器列表")
    parser.add_argument("--output", required=True, help="报告输出路径")
    args = parser.parse_args()

    # 加载金标准集
    golden_set = load_golden_set(args.golden_dir)
    print(f"加载金标准集: {len(golden_set)} 条")
    if not golden_set:
        print("ERROR: 金标准集为空，请检查 --golden-dir")
        return

    # 评估每个生成器
    results = {}
    for gen in args.generators:
        print(f"\n评估生成器: {gen}")
        try:
            result = evaluate_generator(gen, golden_set)
            results[gen] = result
            print(f"  accuracy: {result['accuracy']:.2%}")
            print(f"  cwe_accuracy: {result['cwe_accuracy']:.2%}")
        except NotImplementedError as e:
            print(f"  [跳过] {e}")

    # 计算权重
    accuracies = {gen: r["accuracy"] for gen, r in results.items()}
    weights = compute_weights(accuracies)

    # 输出报告
    report = {
        "golden_set_size": len(golden_set),
        "evaluations": results,
        "weights": weights,
        "recommendations": [],
    }

    # 生成建议
    for gen, acc in accuracies.items():
        if acc < 0.70:
            report["recommendations"].append(
                f"{gen} 准确率 {acc:.2%} < 70%，建议提高 L3 抽样比例至 15-20%，"
                f"或考虑弃用该生成器的输出"
            )
        elif acc < 0.85:
            report["recommendations"].append(
                f"{gen} 准确率 {acc:.2%}，建议 L3 抽样比例保持 10%"
            )
        else:
            report["recommendations"].append(
                f"{gen} 准确率 {acc:.2%}，置信度高，L3 抽样比例可降至 5%"
            )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print()
    print("=" * 70)
    print("L4 金标准校准结果")
    print("=" * 70)
    print(f"金标准集: {len(golden_set)} 条")
    for gen, r in results.items():
        print(f"  {gen}: accuracy={r['accuracy']:.2%}, cwe_accuracy={r['cwe_accuracy']:.2%}, "
              f"weight={weights[gen]}")
    print()
    print("建议:")
    for rec in report["recommendations"]:
        print(f"  - {rec}")
    print(f"\n报告写入: {output_path}")


if __name__ == "__main__":
    main()
