"""
合并 7 个 pack 的蒸馏产物 → train_chatml_v9max.jsonl。

功能：
  1. 读取 data/distill_v2/{pack}.jsonl 7 个文件
  2. 去重（按 _meta.task_id）
  3. 剥离 _meta 字段（训练时不消费）
  4. 可选合并现有 train_chatml_v9_augmented.jsonl（914 条）
  5. 统计正负样本比例、CWE 分布、语言分布
  6. 输出 train_chatml_v9max.jsonl

用法：
  python merge_to_chatml.py                          # 只合并蒸馏 v2 数据
  python merge_to_chatml.py --with-v9                # 合并 v9_augmented（914 条）
  python merge_to_chatml.py --with-v9 --stats        # 打印详细统计
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from config import DATA_DIR, FINAL_OUTPUT
from task_specs import PACKS

# 现有 v9 数据（exp_06_finetune/data/train_chatml_v9_augmented.jsonl）
V9_PATH = DATA_DIR / "train_chatml_v9_augmented.jsonl"


def load_pack(pack_id: str, filename: str) -> list:
    """读取单个 pack 的 jsonl，返回样本列表。"""
    path = DATA_DIR / filename
    if not path.exists():
        print(f"  ⚠️  {filename} 不存在，跳过")
        return []
    samples = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                samples.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    print(f"  {pack_id:<24} {len(samples):>6} 条  ← {filename}")
    return samples


def strip_meta(sample: dict) -> dict:
    """剥离 _meta 字段，保留纯 ChatML messages 格式。"""
    return {
        "messages": sample["messages"]
    }


def dedup(samples: list) -> list:
    """按 _meta.task_id 去重（保留第一条）。"""
    seen = set()
    result = []
    for s in samples:
        tid = s.get("_meta", {}).get("task_id", "")
        if tid and tid in seen:
            continue
        if tid:
            seen.add(tid)
        result.append(s)
    return result


def print_stats(samples: list, title: str = ""):
    """打印样本统计。"""
    if not samples:
        print(f"  {title}: 0 条")
        return

    vuln = sum(1 for s in samples if s.get("_meta", {}).get("has_vuln", False))
    safe = len(samples) - vuln

    cwes = Counter(s.get("_meta", {}).get("cwe", "?") for s in samples)
    langs = Counter(s.get("_meta", {}).get("lang", "?") for s in samples)
    models = Counter(s.get("_meta", {}).get("model", "?") for s in samples)

    print(f"\n  {title} 统计（{len(samples)} 条）:")
    print(f"    正负比: 漏洞 {vuln} : 安全 {safe} = 1:{safe/vuln:.1f}" if vuln else f"    正负比: 全安全")
    print(f"    模型分布: {dict(models)}")
    print(f"    语言 Top5: {dict(langs.most_common(5))}")
    print(f"    CWE Top5: {dict(cwes.most_common(5))}")


def main():
    parser = argparse.ArgumentParser(description="合并蒸馏数据 → v9max")
    parser.add_argument("--with-v9", action="store_true",
                        help="合并现有 train_chatml_v9_augmented.jsonl（914 条）")
    parser.add_argument("--stats", action="store_true",
                        help="打印详细统计")
    parser.add_argument("--output", type=str, default=str(FINAL_OUTPUT),
                        help=f"输出路径（默认 {FINAL_OUTPUT}）")
    args = parser.parse_args()

    print("=" * 70)
    print("合并蒸馏 v2 数据")
    print("=" * 70)

    # 1. 读取 7 个 pack
    print("\n[1] 读取各 pack 产物:")
    all_samples = []
    for pack in PACKS:
        samples = load_pack(pack.pack_id, pack.output_file)
        all_samples.extend(samples)

    print(f"\n  合计读取: {len(all_samples)} 条")

    # 2. 去重
    before = len(all_samples)
    all_samples = dedup(all_samples)
    print(f"  去重后: {len(all_samples)} 条（移除 {before - len(all_samples)} 条重复）")

    # 3. 可选合并 v9
    if args.with_v9 and V9_PATH.exists():
        print(f"\n[2] 合并 v9_augmented:")
        v9_samples = []
        with open(V9_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    s = json.loads(line)
                    # v9 没有 _meta，补一个占位
                    if "_meta" not in s:
                        s["_meta"] = {"task_id": f"v9-{len(v9_samples):04d}", "model": "v9", "has_vuln": None}
                    v9_samples.append(s)
                except json.JSONDecodeError:
                    continue
        print(f"  v9_augmented: {len(v9_samples)} 条 ← {V9_PATH.name}")
        all_samples = v9_samples + all_samples
        print(f"  合并后: {len(all_samples)} 条")

    # 4. 统计
    if args.stats:
        print_stats(all_samples, "合并后")

    # 5. 剥离 _meta，写最终文件
    output_path = Path(args.output)
    with open(output_path, "w", encoding="utf-8") as f:
        for s in all_samples:
            clean = strip_meta(s)
            f.write(json.dumps(clean, ensure_ascii=False) + "\n")

    print(f"\n[{'3' if args.with_v9 else '2'}] 写入最终文件:")
    print(f"  {output_path}")
    print(f"  {len(all_samples)} 条")

    # 6. 泄漏审计提醒
    print(f"\n⚠️  训练前请跑泄漏审计:")
    print(f"  python experiments/exp_06_finetune/scripts/audit_leakage_precise.py "
          f"--train {output_path.name}")


if __name__ == "__main__":
    main()
