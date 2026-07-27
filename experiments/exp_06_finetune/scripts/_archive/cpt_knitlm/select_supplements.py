"""错题驱动增强选择脚本 —— 根据错误类别自动选择对应的增强数据。

依据 docs/对话.md 的"错题闭环"范式：evaluate → extract errors → augment → retrain。
本脚本负责 extract errors → augment 之间的映射环节。

核心逻辑：
1. 读取 extract_phase3_errors.py 输出的错题分析 JSON
2. 统计各类别的错题数量
3. 按映射规则选择对应的 supplement_*.jsonl 或 supplement_*.py 脚本
4. 可选：读取 probe_report.json 获取 fuzzy/error CWE 列表，追加对应增强

映射规则（基于 extract_phase3_errors.py 的 CATEGORY_KEYWORDS）：
  shell偏见       → supplement_ccot_contrastive_v2.jsonl（shell=True 对比推理）
  SSTI概念混淆   → supplement_cwe_attribution_ssti.jsonl（SSTI 归因专项）
  CWE-89错标SSTI → supplement_cwe_attribution_ssti.jsonl（SSTI/CWE-89 区分）
  结论漂移        → supplement_ccot_contrastive.jsonl（CoT→结论对比纠偏）
  跨文件认知      → supplement_longfile_defense.jsonl（跨函数推理）
  missing_feature → supplement_hard_samples.py（需动态生成）
  未分类          → supplement_blindspot_cwe.jsonl（盲区兜底）

用法：
  # 基本用法：根据错题分析选择增强数据
  python3 select_supplements.py \\
      --error-json results/phase3_vs_phase1_regression.json

  # 结合探测报告：追加 fuzzy/error CWE 对应的增强数据
  python3 select_supplements.py \\
      --error-json results/phase3_vs_phase1_regression.json \\
      --probe-report data/probe_report.json

  # 指定输出路径
  python3 select_supplements.py \\
      --error-json results/phase3_vs_phase1_regression.json \\
      --output data/selected_supplements.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"
RESULTS_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/results"
SCRIPTS_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# 错误类别 → 增强文件映射
# ---------------------------------------------------------------------------

ERROR_SUPPLEMENT_MAP: dict[str, str] = {
    "shell偏见": "supplement_ccot_contrastive_v2.jsonl",
    "SSTI概念混淆": "supplement_cwe_attribution_ssti.jsonl",
    "CWE-89错标SSTI": "supplement_cwe_attribution_ssti.jsonl",
    "结论漂移": "supplement_ccot_contrastive.jsonl",
    "跨文件认知": "supplement_longfile_defense.jsonl",
    "missing_feature": "supplement_hard_samples.jsonl",
    "未分类": "supplement_blindspot_cwe.jsonl",
}

# 额外的类别→增强映射（当某些类别需要多个增强源时）
ERROR_SUPPLEMENT_EXTRA: dict[str, list[str]] = {
    "shell偏见": ["supplement_cwe_attribution_nosql.jsonl"],
    "结论漂移": ["supplement_ccot_contrastive_v2.jsonl"],
    "missing_feature": ["supplement_longtail_cwe.jsonl"],
}

# CWE → 可能相关的增强文件（用于 probe_report 补充）
CWE_SUPPLEMENT_HINTS: dict[str, list[str]] = {
    # CWE-89 SQL 注入：无专门 SQL 补充，原误配到 shell 偏见补充不合理，改为盲区兜底
    "CWE-89": ["supplement_blindspot_cwe.jsonl"],
    "CWE-78": ["supplement_ccot_contrastive_v2.jsonl", "supplement_cwe_attribution_nosql.jsonl"],
    "CWE-79": ["supplement_ccot_contrastive_v2.jsonl"],
    "CWE-22": ["supplement_longfile_defense.jsonl"],
    # CWE-502 反序列化：项目无专门反序列化补充，原误配到 SSTI（CWE-94/1336），改为盲区兜底
    "CWE-502": ["supplement_blindspot_cwe.jsonl"],
    "CWE-1336": ["supplement_cwe_attribution_ssti.jsonl"],
    "CWE-352": ["supplement_hard_samples.jsonl", "supplement_longtail_cwe.jsonl"],
    "CWE-798": ["supplement_blindspot_cwe.jsonl"],
    "CWE-611": ["supplement_blindspot_cwe.jsonl", "supplement_longtail_cwe.jsonl"],
    "CWE-639": ["supplement_hard_samples.jsonl"],
    "CWE-200": ["supplement_blindspot_cwe.jsonl"],
    "CWE-190": ["supplement_longtail_cwe.jsonl"],
    "CWE-94": ["supplement_cwe_attribution_ssti.jsonl", "supplement_cwe_attribution_spel.jsonl"],
}


def count_records_in_jsonl(path: Path) -> int:
    """统计 jsonl 文件的行数（即记录数）。"""
    if not path.exists():
        return 0
    count = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def load_error_json(path: Path) -> dict:
    """加载 extract_phase3_errors.py 输出的错题分析 JSON。"""
    if not path.exists():
        print(f"❌ 错题分析文件不存在: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_probe_report(path: Path) -> dict:
    """加载 probe_model.py 的探测报告。"""
    if not path.exists():
        print(f"⚠️ 探测报告不存在: {path}", file=sys.stderr)
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def select_from_errors(error_json: dict) -> dict[str, dict]:
    """根据错题分析 JSON 选择增强数据。

    Returns: {category: {"count": int, "supplement_file": str, "record_count": int}}
    """
    # 统计各类别的错题数量
    category_counts: Counter = Counter()

    # Phase 3 残留错题
    for error in error_json.get("p3_errors", []):
        for cat in error.get("category_hints", []):
            category_counts[cat] += 1

    # Phase 1→3 回归（也是错题，且更关键）
    for reg in error_json.get("regressions", []):
        for cat in reg.get("category_hints", []):
            category_counts[cat] += 1

    # 为每个类别选择增强文件
    result = {}
    for cat, count in category_counts.most_common():
        supplement_file = ERROR_SUPPLEMENT_MAP.get(cat)
        if not supplement_file:
            # 尝试模糊匹配
            for key, val in ERROR_SUPPLEMENT_MAP.items():
                if key in cat or cat in key:
                    supplement_file = val
                    break
        if not supplement_file:
            supplement_file = ERROR_SUPPLEMENT_MAP["未分类"]

        data_path = DATA_DIR / supplement_file
        script_path = SCRIPTS_DIR / supplement_file.replace(".jsonl", ".py")

        record_count = count_records_in_jsonl(data_path)
        if record_count == 0 and script_path.exists():
            # .py 脚本需动态生成，标记为 -1
            record_count = -1

        result[cat] = {
            "count": count,
            "supplement_file": supplement_file,
            "record_count": record_count,
            "data_path": str(data_path),
            "exists": data_path.exists() or script_path.exists(),
        }

    return result


def get_extra_supplements(category_result: dict[str, dict]) -> list[str]:
    """获取额外的增强文件（某些类别需要多个增强源）。"""
    extra_files = set()
    for cat in category_result:
        for extra in ERROR_SUPPLEMENT_EXTRA.get(cat, []):
            extra_files.add(extra)
    return sorted(extra_files)


def select_from_probe(probe_report: dict) -> dict:
    """根据探测报告选择额外增强数据（fuzzy/error CWE 的补充）。

    Returns: {"fuzzy_cwes": [...], "error_cwes": [...], "supplement_hints": [...]}
    """
    summary = probe_report.get("summary", {})
    fuzzy_cwes = summary.get("fuzzy_cwes", [])
    error_cwes = summary.get("error_cwes", [])

    # 收集 fuzzy/error CWE 对应的增强提示
    supplement_hints = set()
    for cwe in fuzzy_cwes + error_cwes:
        for hint in CWE_SUPPLEMENT_HINTS.get(cwe, []):
            supplement_hints.add(hint)

    return {
        "fuzzy_cwes": fuzzy_cwes,
        "fuzzy_count": len(fuzzy_cwes),
        "error_cwes": error_cwes,
        "error_count": len(error_cwes),
        "supplement_hints": sorted(supplement_hints),
    }


def main():
    parser = argparse.ArgumentParser(
        description="错题驱动增强选择：根据错误类别自动选择对应的增强数据",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--error-json",
        type=Path,
        default=RESULTS_DIR / "phase3_vs_phase1_regression.json",
        help=f"错题分析 JSON 路径（默认 {RESULTS_DIR / 'phase3_vs_phase1_regression.json'}）",
    )
    parser.add_argument(
        "--probe-report",
        type=Path,
        default=None,
        help="探测报告 JSON 路径（可选，追加 fuzzy/error CWE 增强）",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DATA_DIR / "selected_supplements.json",
        help=f"输出路径（默认 {DATA_DIR / 'selected_supplements.json'}）",
    )

    args = parser.parse_args()

    # 1. 加载错题分析
    print(f"加载错题分析: {args.error_json}")
    error_json = load_error_json(args.error_json)

    p3_errors = error_json.get("p3_errors", [])
    regressions = error_json.get("regressions", [])
    print(f"  Phase 3 残留错题: {len(p3_errors)} 个")
    print(f"  Phase 1→3 回归: {len(regressions)} 个")

    # 2. 根据错题选择增强
    category_result = select_from_errors(error_json)

    print(f"\n错题类别分布与增强选择：")
    print(f"{'类别':<20} {'错题数':>6} {'增强文件':<45} {'记录数':>6} {'存在':>4}")
    print("-" * 90)
    for cat, info in category_result.items():
        rec_str = str(info["record_count"]) if info["record_count"] >= 0 else "需生成"
        exists_str = "✅" if info["exists"] else "❌"
        print(f"{cat:<20} {info['count']:>6} {info['supplement_file']:<45} {rec_str:>6} {exists_str:>4}")

    # 3. 收集额外增强文件
    extra_files = get_extra_supplements(category_result)
    if extra_files:
        print(f"\n额外增强文件：")
        for f in extra_files:
            path = DATA_DIR / f
            count = count_records_in_jsonl(path)
            print(f"  {f} ({count} 条)")

    # 4. 可选：根据探测报告补充
    probe_result = {}
    if args.probe_report:
        print(f"\n加载探测报告: {args.probe_report}")
        probe_report = load_probe_report(args.probe_report)
        if probe_report:
            probe_result = select_from_probe(probe_report)
            print(f"  fuzzy CWE: {probe_result['fuzzy_cwes']} ({probe_result['fuzzy_count']} 个)")
            print(f"  error CWE: {probe_result['error_cwes']} ({probe_result['error_count']} 个)")
            if probe_result["supplement_hints"]:
                print(f"  补充增强: {probe_result['supplement_hints']}")

    # 5. 构建输出
    # 收集所有选中的文件（去重）
    selected_files = set()
    for info in category_result.values():
        if info["exists"]:
            selected_files.add(info["supplement_file"])
    for f in extra_files:
        if (DATA_DIR / f).exists():
            selected_files.add(f)
    if probe_result:
        for hint in probe_result.get("supplement_hints", []):
            if (DATA_DIR / hint).exists():
                selected_files.add(hint)

    output = {
        "source": str(args.error_json),
        "p3_errors_count": len(p3_errors),
        "regressions_count": len(regressions),
        "error_categories": category_result,
        "extra_supplements": extra_files,
        "selected_files": sorted(selected_files),
        "probe_supplements": probe_result if probe_result else None,
    }

    # 6. 保存
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"\n✅ 增强选择结果已保存: {args.output}")
    print(f"   选中 {len(selected_files)} 个增强文件")
    print(f"\n下一步：运行 merge_supplements.py 合并基础数据与增强数据")
    print(f"  python3 merge_supplements.py \\")
    print(f"      --supplement-config {args.output}")


if __name__ == "__main__":
    main()
