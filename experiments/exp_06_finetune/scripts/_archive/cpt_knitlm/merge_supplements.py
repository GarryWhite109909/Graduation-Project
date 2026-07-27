"""增强数据合并脚本 —— 将基础训练数据与选中的增强数据合并，对错误相关样本加权。

依据 docs/对话.md 的"错题闭环"范式：evaluate → extract errors → augment → retrain。
本脚本负责 augment → retrain 之间的数据准备环节。

核心逻辑：
1. 加载基础 ChatML 训练数据
2. 加载 select_supplements.py 选中的增强文件
3. 对增强数据标记 weight（错误相关样本权重提升，默认 2.0x）
4. 合并并去重（基于 messages 内容的 hash）
5. 输出合并后的 jsonl，供 SFT 训练使用

权重设计：
  - 基础数据 weight=1.0
  - 错题相关增强数据 weight=supplement_weight（默认 2.0）
  - probe_report 中 fuzzy/error CWE 相关增强 weight=1.5
  - 其他增强数据 weight=1.0

输出格式：每行 {"messages": [...], "weight": float, "source": str}
  供 WeightedTrainer / train_qlora.py 的加权采样使用。

用法：
  # 基本用法：合并基础数据与增强数据
  python3 merge_supplements.py \\
      --supplement-config data/selected_supplements.json

  # 自定义基础数据和权重
  python3 merge_supplements.py \\
      --base-data data/train_chatml_v2.jsonl \\
      --supplement-config data/selected_supplements.json \\
      --supplement-weight 2.0 \\
      --output data/merged_error_driven.jsonl

  # 指定每类增强的最大样本数（防止单类过大）
  python3 merge_supplements.py \\
      --supplement-config data/selected_supplements.json \\
      --max-samples-per-category 100
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"

# 默认基础训练数据
DEFAULT_BASE_DATA = DATA_DIR / "train_chatml_v2.jsonl"


def compute_messages_hash(messages: list[dict]) -> str:
    """计算 messages 内容的 hash，用于去重。

    只取 user 和 assistant 的 content 做 hash（忽略 system，因为 system prompt 可能
    因版本不同而略有差异，但 user+assistant 相同即为重复样本）。

    # 注意：忽略 system prompt 是为了允许 system prompt 版本差异，
    # 但可能导致 SYSTEM_PROMPT 被降级为 SYSTEM_PROMPT_LITE。
    # 建议在合并前确保所有 supplement 使用统一的 SYSTEM_PROMPT_LITE。
    """
    parts = []
    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "")
        if role in ("user", "assistant"):
            parts.append(f"{role}:{content}")
    text = "\n".join(parts)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def load_jsonl(path: Path, source_name: str, weight: float = 1.0,
               max_samples: int | None = None) -> list[dict]:
    """加载 jsonl 文件，为每条记录添加 weight 和 source 标记。"""
    records = []
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            if max_samples and i >= max_samples:
                break
            try:
                rec = json.loads(line)
                rec["weight"] = weight
                # 用 _source 内部字段，避免覆盖记录本身可能存在的 source 字段
                rec["_source"] = source_name
                # 计算 hash 用于去重 + 格式标记
                if "messages" in rec:
                    rec["_format"] = "chatml"
                    rec["_hash"] = compute_messages_hash(rec["messages"])
                elif "text" in rec:
                    # CPT 格式（纯文本），用 text 的 hash
                    rec["_format"] = "cpt"
                    rec["_hash"] = hashlib.sha256(
                        rec["text"].encode("utf-8")
                    ).hexdigest()[:16]
                else:
                    # 无 messages 或 text 字段，下游可能崩溃，跳过并告警
                    print(f"⚠️ 警告：记录无 messages 或 text 字段，跳过: {rec.get('_source', 'unknown')}")
                    continue
                records.append(rec)
            except json.JSONDecodeError:
                continue
    return records


def merge_and_deduplicate(
    base_records: list[dict],
    supplement_records: list[dict],
) -> list[dict]:
    """合并基础数据和增强数据，去重。

    去重策略：基于 _hash，保留先出现的记录（基础数据优先）。
    如果增强数据与基础数据重复，保留增强版本（因为权重可能更高）。
    """
    seen_hashes = set()
    merged = []

    # 先添加基础数据
    for rec in base_records:
        h = rec.get("_hash", "")
        if h and h in seen_hashes:
            continue
        if h:
            seen_hashes.add(h)
        merged.append(rec)

    # 再添加增强数据（如果 hash 冲突，用增强版本替换——权重更高）
    supplement_by_hash = {}
    for rec in supplement_records:
        h = rec.get("_hash", "")
        if h:
            # 记录权重最高的版本
            if h not in supplement_by_hash or rec.get("weight", 1.0) > supplement_by_hash[h].get("weight", 1.0):
                supplement_by_hash[h] = rec

    for h, rec in supplement_by_hash.items():
        if h in seen_hashes:
            # 替换基础数据中对应的记录（用增强版本，权重更高）
            for i, existing in enumerate(merged):
                if existing.get("_hash") == h:
                    merged[i] = rec
                    break
        else:
            seen_hashes.add(h)
            merged.append(rec)

    return merged


def clean_record(rec: dict) -> dict:
    """清理记录：移除内部字段（_hash/_source/_format），保留 weight 和 source。"""
    cleaned = {k: v for k, v in rec.items() if not k.startswith("_")}
    # 从内部 _source 字段恢复 source 输出字段（若原记录本身已有 source 则保留原值）
    if "source" not in cleaned and rec.get("_source"):
        cleaned["source"] = rec["_source"]
    return cleaned


def main():
    parser = argparse.ArgumentParser(
        description="增强数据合并：将基础训练数据与选中的增强数据合并，对错误相关样本加权",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--base-data",
        type=Path,
        default=DEFAULT_BASE_DATA,
        help=f"基础训练数据路径（默认 {DEFAULT_BASE_DATA}）",
    )
    parser.add_argument(
        "--supplement-config",
        type=Path,
        default=DATA_DIR / "selected_supplements.json",
        help=f"select_supplements.py 的输出配置（默认 {DATA_DIR / 'selected_supplements.json'}）",
    )
    parser.add_argument(
        "--supplement-weight",
        type=float,
        default=2.0,
        help="错误相关增强数据的权重（默认 2.0，基础数据为 1.0）",
    )
    parser.add_argument(
        "--probe-weight",
        type=float,
        default=1.5,
        help="探测报告 fuzzy/error CWE 相关增强的权重（默认 1.5）",
    )
    parser.add_argument(
        "--max-samples-per-category",
        type=int,
        default=None,
        help="每个增强文件的最大样本数（防止单类过大，默认不限）",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DATA_DIR / "merged_error_driven.jsonl",
        help=f"输出路径（默认 {DATA_DIR / 'merged_error_driven.jsonl'}）",
    )

    args = parser.parse_args()

    # 1. 加载基础数据
    print(f"加载基础数据: {args.base_data}")
    if not args.base_data.exists():
        print(f"❌ 基础数据不存在: {args.base_data}", file=sys.stderr)
        sys.exit(1)
    base_records = load_jsonl(args.base_data, "base", weight=1.0)
    print(f"  基础数据: {len(base_records)} 条")

    # 2. 加载增强配置
    print(f"\n加载增强配置: {args.supplement_config}")
    if not args.supplement_config.exists():
        print(f"❌ 增强配置不存在: {args.supplement_config}", file=sys.stderr)
        print(f"   先运行: python3 select_supplements.py")
        sys.exit(1)

    with open(args.supplement_config, encoding="utf-8") as f:
        config = json.load(f)

    # 3. 收集增强文件及其权重
    # 错题相关增强文件 → supplement_weight
    error_files = set()
    for cat, info in config.get("error_categories", {}).items():
        f = info.get("supplement_file", "")
        if f and info.get("exists", False):
            error_files.add(f)

    # 额外增强文件 → supplement_weight
    for f in config.get("extra_supplements", []):
        error_files.add(f)

    # probe_report 相关增强文件 → probe_weight
    probe_files = set()
    probe_info = config.get("probe_supplements")
    if probe_info:
        for f in probe_info.get("supplement_hints", []):
            probe_files.add(f)

    # 最终选中的文件（去重，probe 文件从 error_files 中排除以避免权重覆盖）
    all_supplement_files = {}
    for f in error_files:
        all_supplement_files[f] = args.supplement_weight
    for f in probe_files:
        if f not in all_supplement_files:
            all_supplement_files[f] = args.probe_weight

    # selected_files 是最终确认存在的文件列表
    selected_files = config.get("selected_files", [])
    # 只加载 selected_files 中实际存在的
    files_to_load = {}
    for f in selected_files:
        data_path = DATA_DIR / f
        if data_path.exists():
            weight = all_supplement_files.get(f, 1.0)
            files_to_load[f] = weight

    # 4. 加载所有增强数据
    print(f"\n加载增强数据：")
    all_supplement_records = []
    for f, weight in sorted(files_to_load.items()):
        path = DATA_DIR / f
        max_samples = args.max_samples_per_category
        records = load_jsonl(path, f, weight=weight, max_samples=max_samples)
        all_supplement_records.extend(records)
        print(f"  {f}: {len(records)} 条 (weight={weight})")

    # 5. 合并并去重
    print(f"\n合并数据...")
    print(f"  基础: {len(base_records)} 条")
    print(f"  增强: {len(all_supplement_records)} 条")
    merged = merge_and_deduplicate(base_records, all_supplement_records)
    print(f"  合并后（去重）: {len(merged)} 条")

    # 6. 统计权重分布
    weight_counts = {}
    for rec in merged:
        w = rec.get("weight", 1.0)
        weight_counts[w] = weight_counts.get(w, 0) + 1
    print(f"\n权重分布：")
    for w, count in sorted(weight_counts.items()):
        print(f"  weight={w}: {count} 条")

    # 7. 保存
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        for rec in merged:
            cleaned = clean_record(rec)
            f.write(json.dumps(cleaned, ensure_ascii=False) + "\n")

    print(f"\n✅ 合并数据已保存: {args.output}")
    print(f"   总计 {len(merged)} 条")
    print(f"\n下一步：用合并数据训练 SFT")
    print(f"  python3 train_qlora.py \\")
    print(f"      --data-file {args.output} --epochs 1")


if __name__ == "__main__":
    main()
