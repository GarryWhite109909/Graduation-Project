"""
实验公共工具函数 —— 供 exp_01 / exp_02 / exp_03 共享。

抽取 manifest 加载、样本读取、结果落盘、检出指标统计等通用逻辑，
避免每个实验脚本重复实现。所有实验脚本统一使用本模块的函数，
确保结果格式与统计口径一致。

典型用法（exp_01 / exp_02）:
    from experiments.utils import (
        load_manifest, read_sample_code, save_results_json,
        compute_detection_metrics, print_summary,
    )
"""

import json
import sys
import time
from pathlib import Path
from typing import Any, Optional


def load_manifest(manifest_path: Path) -> tuple[dict, list[dict]]:
    """加载样本清单 manifest.json。

    Args:
        manifest_path: manifest.json 的路径

    Returns:
        (manifest_dict, samples_list)

    Raises:
        FileNotFoundError: manifest 不存在
        KeyError: manifest 缺少 samples 字段
    """
    if not manifest_path.exists():
        raise FileNotFoundError(f"找不到 manifest: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if "samples" not in manifest:
        raise KeyError(f"manifest 缺少 samples 字段: {manifest_path}")
    return manifest, manifest["samples"]


def read_sample_code(samples_dir: Path, filename: str) -> Optional[str]:
    """读取样本代码文件内容。文件不存在时返回 None 并打印警告。"""
    path = samples_dir / filename
    if not path.exists():
        print(f"[跳过] 样本文件不存在: {path}", file=sys.stderr)
        return None
    return path.read_text(encoding="utf-8")


def save_results_json(results_path: Path, results: dict) -> None:
    """把结果 dict 写入 JSON（增量落盘，UTF-8，缩进 2）。"""
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def new_results_envelope(experiment: str, **extra) -> dict:
    """创建结果文件的外层信封（统一字段：experiment/started_at/samples + extra）。"""
    env = {
        "experiment": experiment,
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "samples": [],
    }
    env.update(extra)
    return env


def compute_detection_metrics(
    records: list[dict],
    expected_field: str = "expected_present",
    predicted_field: str = "model_has_vulnerability",
) -> dict:
    """从结果记录列表计算检出指标。

    要求每条 record 含 expected_field（真值）与 predicted_field（模型判定）字段。
    缺字段或值为 None 的样本计入 invalid，不参与 TP/FP/FN/TN。

    Returns:
        {
            "total": int, "valid": int, "invalid": int,
            "tp": int, "tn": int, "fp": int, "fn": int,
            "vuln_total": int, "safe_total": int,
            "recall": float|None,       # 漏洞样本召回率 = tp/(tp+fn)
            "false_positive_rate": float|None,  # 安全样本误报率 = fp/(fp+tn)
            "accuracy": float|None,     # 总体准确率 = (tp+tn)/valid
            "elapsed_stats": {"avg": float, "max": float, "min": float, "sum": float, "count": int},
        }
    """
    tp = tn = fp = fn = 0
    elapsed_list: list[float] = []
    invalid = 0

    for r in records:
        exp = r.get(expected_field)
        pred = r.get(predicted_field)
        # 收集耗时（若有）
        el = r.get("elapsed_seconds")
        if isinstance(el, (int, float)):
            elapsed_list.append(el)

        if exp is None or pred is None:
            invalid += 1
            continue
        if exp and pred:
            tp += 1
        elif (not exp) and (not pred):
            tn += 1
        elif exp and (not pred):
            fn += 1
        else:
            fp += 1

    valid = tp + tn + fp + fn
    vuln_total = tp + fn
    safe_total = tn + fp

    recall = (tp / vuln_total) if vuln_total else None
    fpr = (fp / safe_total) if safe_total else None
    accuracy = (tp + tn) / valid if valid else None

    elapsed_stats = {
        "avg": round(sum(elapsed_list) / len(elapsed_list), 2) if elapsed_list else None,
        "max": round(max(elapsed_list), 2) if elapsed_list else None,
        "min": round(min(elapsed_list), 2) if elapsed_list else None,
        "sum": round(sum(elapsed_list), 2) if elapsed_list else None,
        "count": len(elapsed_list),
    }

    return {
        "total": len(records),
        "valid": valid,
        "invalid": invalid,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "vuln_total": vuln_total, "safe_total": safe_total,
        "recall": recall,
        "false_positive_rate": fpr,
        "accuracy": accuracy,
        "elapsed_stats": elapsed_stats,
    }


def format_metrics_text(metrics: dict) -> str:
    """把指标格式化为可读文本（用于打印 / 写入报告）。"""
    def pct(x):
        return "N/A" if x is None else f"{x*100:.1f}%"

    m = metrics
    lines = [
        f"样本总数: {m['total']}（有效 {m['valid']}，无效 {m['invalid']}）",
        f"TP={m['tp']}  TN={m['tn']}  FP={m['fp']}  FN={m['fn']}",
        f"漏洞样本召回率 = {m['tp']}/{m['vuln_total']} = {pct(m['recall'])}",
        f"安全样本误报率 = {m['fp']}/{m['safe_total']} = {pct(m['false_positive_rate'])}",
        f"总体准确率 = {m['tp']+m['tn']}/{m['valid']} = {pct(m['accuracy'])}",
    ]
    es = m["elapsed_stats"]
    if es["count"]:
        lines.append(
            f"耗时: 平均 {es['avg']}s  最长 {es['max']}s  最短 {es['min']}s  总和 {es['sum']}s"
        )
    return "\n".join(lines)


def print_summary(metrics: dict) -> None:
    """打印汇总指标到 stdout。"""
    print(format_metrics_text(metrics))


if __name__ == "__main__":
    # 自检：用构造数据测试指标计算
    demo = [
        {"expected_present": True, "model_has_vulnerability": True, "elapsed_seconds": 50.0},
        {"expected_present": True, "model_has_vulnerability": False, "elapsed_seconds": 55.0},
        {"expected_present": False, "model_has_vulnerability": False, "elapsed_seconds": 40.0},
        {"expected_present": False, "model_has_vulnerability": True, "elapsed_seconds": 60.0},
        {"expected_present": True, "model_has_vulnerability": None, "elapsed_seconds": None},
    ]
    m = compute_detection_metrics(demo)
    print_summary(m)
