"""
GLM 教师模型 CoT 合并脚本。

工作流程：
  1. GLM 在对话中分批生成 CoT，写入 data/glm_cot_map.jsonl（每行一条 filename→cot_analysis 映射）
  2. 本脚本读取 distill_corpus_annotated.jsonl（400 条原始标注）
  3. 用 glm_cot_map.jsonl 中的 CoT 替换原始 cot_analysis 字段
  4. 输出 distill_corpus_annotated_v2.jsonl（高质量多样化 CoT 版）

用法：
  cd /home/zane/文档/code/毕业设计
  PYTHONPATH=. /home/zane/miniconda3/envs/graproj/bin/python3 \
      experiments/exp_06_finetune/scripts/apply_glm_cot.py

  # 查看进度（不写文件）
  PYTHONPATH=. python experiments/exp_06_finetune/scripts/apply_glm_cot.py --check
"""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"
INPUT_FILE = DATA_DIR / "distill_corpus_annotated.jsonl"
COT_MAP_FILE = DATA_DIR / "glm_cot_map.jsonl"
OUTPUT_FILE = DATA_DIR / "distill_corpus_annotated_v2.jsonl"


def load_cot_map() -> dict:
    """加载 GLM 生成的 CoT 映射。"""
    if not COT_MAP_FILE.exists():
        return {}
    mapping = {}
    with open(COT_MAP_FILE, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                d = json.loads(line)
                mapping[d["filename"]] = d["cot_analysis"]
    return mapping


def main():
    parser = argparse.ArgumentParser(description="合并 GLM 生成的 CoT 到 v2 蒸馏数据")
    parser.add_argument("--check", action="store_true",
                        help="只检查进度，不写输出文件")
    args = parser.parse_args()

    # 加载原始数据
    if not INPUT_FILE.exists():
        print(f"错误：输入文件不存在: {INPUT_FILE}", file=sys.stderr)
        sys.exit(1)
    with open(INPUT_FILE, encoding="utf-8") as f:
        samples = [json.loads(l) for l in f if l.strip()]
    print(f"原始样本: {len(samples)} 条")

    # 加载 CoT 映射
    cot_map = load_cot_map()
    print(f"GLM CoT 映射: {len(cot_map)} 条")

    # 统计覆盖情况
    covered = sum(1 for s in samples if s["filename"] in cot_map)
    missing = [s["filename"] for s in samples if s["filename"] not in cot_map]
    print(f"已覆盖: {covered}/{len(samples)}  缺失: {len(missing)}")

    if missing:
        print(f"缺失的前10个: {missing[:10]}")

    if args.check:
        print("\n仅检查模式，不写文件。")
        if len(missing) == 0:
            print("✅ 所有样本已覆盖，可以生成 v2 文件")
        else:
            print(f"⏳ 还需生成 {len(missing)} 条 CoT")
        return

    if len(missing) > 0:
        print(f"\n警告：仍有 {len(missing)} 条未覆盖，将保留原始 CoT")

    # 合并：用 GLM CoT 替换原始 cot_analysis
    output_samples = []
    replaced = 0
    for rec in samples:
        new_rec = dict(rec)
        if rec["filename"] in cot_map:
            new_cot = cot_map[rec["filename"]]
            if new_cot and len(new_cot) > 20:
                new_rec["cot_analysis"] = new_cot
                replaced += 1
        output_samples.append(new_rec)

    # 写入
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for rec in output_samples:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"\n已写入: {OUTPUT_FILE}")
    print(f"替换 CoT: {replaced}/{len(output_samples)} 条")

    # 统计 CoT 多样性
    cot_texts = [s.get("cot_analysis", "") for s in output_samples]
    unique_texts = len(set(cot_texts))
    print(f"CoT 多样性: {unique_texts}/{len(cot_texts)} 条唯一文本")

    # 安全样本 explanation 多样性
    safe_samples = [s for s in output_samples if not s.get("has_vulnerability")]
    safe_expls = [s.get("taint_path", "") for s in safe_samples]
    unique_expls = len(set(safe_expls))
    print(f"安全样本 taint_path 多样性: {unique_expls}/{len(safe_samples)} 条唯一")


if __name__ == "__main__":
    main()
