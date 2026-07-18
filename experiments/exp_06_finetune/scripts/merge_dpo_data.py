"""
DPO 数据合并脚本 —— 合并三个 DPO 偏好对文件为统一训练集。

Phase 5 准备工作（DPO 当前硬件死机，等 5070 Super 升级后使用）。
对应 docs/方法.md §9 Phase 5。

输入：
  data/dpo_preference_pairs.jsonl       (62 条) - 原始 DPO v1
  data/dpo_preference_pairs_v3.jsonl    (98 条) - DPO v3 改进版
  data/dpo_v3_expansion.jsonl           (36 条) - v3 扩展

输出：
  data/dpo_merged.jsonl                 (196 条) - 合并 + 去重 + 打乱

去重策略：按 prompt 内容哈希去重（保留最新 v3 版本，覆盖 v1）
打乱策略：固定 seed=42 打乱，避免 epoch 内顺序偏差

用法：
  /home/zane/miniconda3/envs/AI/bin/python merge_dpo_data.py
  /home/zane/miniconda3/envs/AI/bin/python merge_dpo_data.py --dry-run  # 仅统计
"""

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# 三个 DPO 文件，按优先级从低到高排列（后者覆盖前者的重复 prompt）
DPO_FILES = [
    ("v1", DATA_DIR / "dpo_preference_pairs.jsonl"),
    ("v3", DATA_DIR / "dpo_preference_pairs_v3.jsonl"),
    ("v3_expansion", DATA_DIR / "dpo_v3_expansion.jsonl"),
]

OUTPUT_FILE = DATA_DIR / "dpo_merged.jsonl"


def prompt_hash(prompt: str) -> str:
    """对 prompt 内容做哈希，用于去重。"""
    # 去除首尾空白后哈希，避免微小差异导致重复
    return hashlib.md5(prompt.strip().encode("utf-8")).hexdigest()


def load_jsonl(path: Path) -> list[dict]:
    records = []
    with open(path, "r", encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"  ⚠️ 跳过无效行 ({path.name}): {e}", file=sys.stderr)
    return records


def main():
    parser = argparse.ArgumentParser(description="合并 DPO 数据文件")
    parser.add_argument("--dry-run", action="store_true", help="仅统计，不写文件")
    parser.add_argument("--seed", type=int, default=42, help="打乱 seed（默认 42）")
    args = parser.parse_args()

    print("=" * 60)
    print("DPO 数据合并")
    print("=" * 60)

    # 按优先级从低到高加载，后加载的覆盖前面的重复 prompt
    merged: dict[str, dict] = {}  # prompt_hash -> record
    source_count: dict[str, int] = {}

    for tag, path in DPO_FILES:
        if not path.exists():
            print(f"⚠️ 文件不存在，跳过: {path}")
            continue
        records = load_jsonl(path)
        source_count[tag] = len(records)
        print(f"\n[{tag}] {path.name}")
        print(f"  加载: {len(records)} 条")

        new_count = 0
        overwrite_count = 0
        for r in records:
            # 验证格式
            if not all(k in r for k in ("prompt", "chosen", "rejected")):
                print(f"  ⚠️ 跳过格式异常记录（缺 prompt/chosen/rejected）", file=sys.stderr)
                continue
            h = prompt_hash(r["prompt"])
            if h in merged:
                overwrite_count += 1
            else:
                new_count += 1
            # 标记来源，便于追溯
            r_with_src = {**r, "_source": tag}
            merged[h] = r_with_src

        print(f"  新增: {new_count}  覆盖: {overwrite_count}")

    # 去除 _source 字段（不写入输出）
    final_records = []
    for r in merged.values():
        clean = {k: v for k, v in r.items() if k != "_source"}
        final_records.append(clean)

    # 固定 seed 打乱
    rng = random.Random(args.seed)
    rng.shuffle(final_records)

    print("\n" + "=" * 60)
    print("合并结果")
    print("=" * 60)
    print(f"源文件统计: {source_count}")
    print(f"合计: {sum(source_count.values())} 条")
    print(f"去重后: {len(final_records)} 条")
    print(f"输出: {OUTPUT_FILE}")

    if args.dry_run:
        print("\n[dry-run] 不写文件")
        return

    with open(OUTPUT_FILE, "w", encoding="utf-8") as fp:
        for r in final_records:
            fp.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"\n✅ 已写入 {len(final_records)} 条到 {OUTPUT_FILE}")
    print(f"   Phase 5 DPO 训练时直接用此文件即可")


if __name__ == "__main__":
    main()
