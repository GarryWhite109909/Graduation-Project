"""rerun_p15_fix - 修复 P1-5 消融对照实验的 2 个无判定样本

修复内容：
1. B 组 (pure) safe_06_csp_header.py：旧 schema 解析失败（输出 markdown 列表格式），
   用新 schema 重新解析可救回（None -> False）。无需重跑 LLM。
2. D 组 (irrelevant) typical_33_php_type_juggling.php：raw_output 在 533 字符处被截断
   （没有 ### 结论 部分），无法用 schema 救回，需重跑 LLM（D 组 irrelevant 模式）。

修复后 4 组实验分母一致（87/60/27），可比性恢复。

用法:
    python rerun_p15_fix.py                  # 重新解析 safe_06 + 重跑 typical_33
    python rerun_p15_fix.py --dry-run        # 只重新解析 safe_06，不重跑 LLM
    python rerun_p15_fix.py --keep-loaded     # 跑完后保持模型在显存中
"""

import argparse
import json
import sys
import time
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from graduation_project.llm_client import OllamaClient
from graduation_project.prompts import SYSTEM_PROMPT, build_user_prompt
from graduation_project.schema import parse_verdict, normalize_has_vulnerability
from experiments.utils import (
    load_manifest,
    save_results_json,
    compute_detection_metrics,
    print_summary,
)

SCRIPT_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = SCRIPT_DIR / "samples"
RESULTS_DIR = SCRIPT_DIR / "results"
MANIFEST_PATH = SAMPLES_DIR / "manifest.json"


# D 组无关文本块（与 run_rag_experiment.py 保持一致，避免 import 副作用）
IRRELEVANT_TEXT_BLOCK = """【参考资料 1】（数据结构 / 链表）
链表是一种线性数据结构，其中的元素通过指针连接。与数组不同，链表的元素在内存中不必连续存储。
单链表每个节点包含数据域和指向下一个节点的指针域。插入和删除操作在已知位置时为 O(1)，
但随机访问需要 O(n)。Python 中可手动实现 ListNode 类。

【参考资料 2】（算法 / 二分查找）
二分查找要求数组已排序，时间复杂度 O(log n)。基本思路：取中间元素与目标比较，
若目标更小则在左半部分递归，更大则在右半部分递归。注意边界处理：
- 左闭右开 [lo, hi) 写法：循环条件 lo < hi，中点 mid = (lo + hi) // 2
- 左闭右闭 [lo, hi] 写法：循环条件 lo <= hi，更新 hi = mid - 1 / lo = mid + 1

【参考资料 3】（设计模式 / 工厂方法）
工厂方法模式定义一个创建对象的接口，让子类决定实例化哪个类。
优点：客户端不需要知道具体类名，只需知道工厂；新增产品类型时无需修改现有工厂代码。
示例：ShapeFactory.get_shape("circle") 返回 Circle 实例。"""


def build_irrelevant_context(target_chars: int = 1500) -> tuple[str, list[dict]]:
    """D 组：注入与漏洞无关但长度相近的说明文字（与 run_rag_experiment.py 保持一致）。"""
    block = IRRELEVANT_TEXT_BLOCK
    repeats = max(1, target_chars // len(block) + 1)
    text = (block + "\n\n") * repeats
    text = text[:target_chars]
    retrieval_records = [{
        "rank": 1,
        "id": "irrelevant_text",
        "type": "无关参考资料",
        "cwe": "N/A",
        "distance": None,
        "note": "irrelevant_text_injection",
        "chars": len(text),
    }]
    return text, retrieval_records

# P1-5 4 组结果文件
ABLATION_FILES = {
    "A_rag":         "results.ablation.rag.topk3.qwen7b.v3.json",
    "B_pure":        "results.ablation.pure.topk3.qwen7b.v3.json",
    "C_random":      "results.ablation.random.topk3.qwen7b.v3.json",
    "D_irrelevant":  "results.ablation.irrelevant.topk3.qwen7b.v3.json",
}

# 需要重新解析的样本（B 组，schema 修复）
REPARSE_SAMPLE = "safe_06_csp_header.py"
# 需要重跑的样本（D 组，输出截断）
RERUN_SAMPLE = "typical_33_php_type_juggling.php"

MODEL = "qwen2.5-coder:7b"


def reparse_sample(results: dict, target_file: str) -> bool:
    """用新 schema 重新解析指定样本的 raw_output。

    返回是否有变化（None -> 有判定）。
    """
    for s in results.get("samples", []):
        if s.get("file") != target_file:
            continue
        changed = False
        for run in s.get("runs", []):
            raw = run.get("raw_output")
            if not raw:
                continue
            old_has_vuln = run.get("model_has_vulnerability")
            new_verdict = parse_verdict(raw)
            new_has_vuln = (
                normalize_has_vulnerability(new_verdict.get("has_vulnerability"))
                if new_verdict else None
            )
            if new_verdict and new_has_vuln is not None and old_has_vuln is None:
                run["parsed_verdict"] = new_verdict
                run["model_has_vulnerability"] = new_has_vuln
                run["rerun_reason"] = "schema_fix_reparse"
                changed = True
                print(f"    [重新解析] {target_file}: None -> {new_has_vuln}")
        # 重新计算多数表决
        if changed:
            verdicts = [r.get("model_has_vulnerability") for r in s.get("runs", [])]
            valid = [v for v in verdicts if v is not None]
            if valid:
                true_count = sum(1 for v in valid if v)
                s["majority_verdict"] = true_count >= len(valid) / 2
                s["agreement_rate"] = round(
                    max(true_count, len(valid) - true_count) / len(valid), 4
                )
        return changed
    return False


def rerun_sample(client: OllamaClient, sample_meta: dict, temperature: float) -> dict:
    """用 D 组（irrelevant）模式重跑单个样本，返回 run_record。"""
    filename = sample_meta["file"]
    path = SAMPLES_DIR / filename
    code = path.read_text(encoding="utf-8")
    language = sample_meta.get("language", "text")

    # D 组：注入 1500 字符无关文本
    rag_context, retrieval_records = build_irrelevant_context(target_chars=1500)
    print(f"        注入无关文本 {len(rag_context)} 字符")

    prompt = build_user_prompt(
        code=code, language=language, filename=filename, rag_context=rag_context,
    )
    print(f"        推理中...", end="", flush=True)
    t0 = time.time()
    result = client.generate(
        prompt=prompt, system_prompt=SYSTEM_PROMPT,
        temperature=temperature, max_tokens=None,
        keep_alive=-1, timeout=900,
    )
    elapsed = round(result["duration"], 2)

    run_record = {
        "run_index": 1,
        "rag_retrieval": retrieval_records,
        "rag_context_chars": len(rag_context) if rag_context else 0,
        "elapsed_seconds": elapsed,
        "raw_output": None,
        "parsed_verdict": {},
        "model_has_vulnerability": None,
        "error": None,
        "rerun_reason": "output_truncated_rerun",
    }

    if result["error"]:
        run_record["error"] = result["error"]
        print(f" [错误] {result['error']}", file=sys.stderr)
    else:
        text = result["text"]
        run_record["raw_output"] = text
        run_record["meta"] = result["meta"]
        verdict = parse_verdict(text)
        run_record["parsed_verdict"] = verdict
        if verdict:
            run_record["model_has_vulnerability"] = normalize_has_vulnerability(
                verdict.get("has_vulnerability")
            )
        print(f" -> 用时 {elapsed}s, 判定={run_record['model_has_vulnerability']}", flush=True)
        # 提示 raw_output 长度，便于确认未截断
        has_conclusion = "### 结论" in text or "has_vulnerability" in text
        print(f"        raw_output 长度={len(text)}, has_conclusion={has_conclusion}")

    return run_record


def recompute_metrics(results: dict) -> None:
    """重新计算 metrics_single_run（4 组都是 repeat=1，无多数表决口径）。"""
    flat_records = []
    for s in results["samples"]:
        for run in s["runs"]:
            flat_records.append({
                "file": s["file"],
                "expected_present": s["expected_present"],
                "model_has_vulnerability": run.get("model_has_vulnerability"),
                "elapsed_seconds": run.get("elapsed_seconds"),
            })
    results["metrics_single_run"] = compute_detection_metrics(flat_records)


def main() -> int:
    parser = argparse.ArgumentParser(description="修复 P1-5 消融对照实验的 2 个无判定样本")
    parser.add_argument("--host", default="http://localhost:11434")
    parser.add_argument("--temperature", type=float, default=0.1)
    parser.add_argument("--dry-run", action="store_true",
                        help="只重新解析 safe_06，不重跑 typical_33")
    parser.add_argument("--keep-loaded", action="store_true",
                        help="跑完后保持模型在显存中（默认卸载）")
    args = parser.parse_args()

    try:
        manifest, samples = load_manifest(MANIFEST_PATH)
    except (FileNotFoundError, KeyError) as e:
        print(f"[错误] {e}", file=sys.stderr)
        return 1

    # 找到 typical_33 的 meta
    rerun_meta = next((s for s in samples if s["file"] == RERUN_SAMPLE), None)
    if rerun_meta is None:
        print(f"[错误] 未找到样本 {RERUN_SAMPLE}", file=sys.stderr)
        return 1

    # Step 1: 重新解析 B 组 safe_06
    print("=== Step 1: 重新解析 B 组 safe_06_csp_header.py（schema 修复）===")
    b_path = RESULTS_DIR / ABLATION_FILES["B_pure"]
    if not b_path.exists():
        print(f"[错误] 结果文件不存在: {b_path}", file=sys.stderr)
        return 1
    b_results = json.loads(b_path.read_text(encoding="utf-8"))
    changed = reparse_sample(b_results, REPARSE_SAMPLE)
    if changed:
        recompute_metrics(b_results)
        b_results["schema_fix_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        save_results_json(b_path, b_results)
        print(f"  [完成] B 组 safe_06 已重新解析并保存")
    else:
        print(f"  [跳过] B 组 safe_06 无需重新解析")

    # 打印 B 组修正后指标
    print(f"\n  === B 组 (pure) 修正后指标 ===")
    print_summary(b_results["metrics_single_run"])

    if args.dry_run:
        print("\n[dry-run] 不重跑 LLM，退出")
        return 0

    # Step 2: 重跑 D 组 typical_33
    print("\n=== Step 2: 重跑 D 组 typical_33_php_type_juggling.php（输出截断）===")
    d_path = RESULTS_DIR / ABLATION_FILES["D_irrelevant"]
    if not d_path.exists():
        print(f"[错误] 结果文件不存在: {d_path}", file=sys.stderr)
        return 1

    client = OllamaClient(base_url=args.host, model=MODEL)
    if not client.check_connection():
        print(f"[错误] 无法连接 Ollama", file=sys.stderr)
        return 1

    print(f"  重跑 {RERUN_SAMPLE}...")
    run_record = rerun_sample(client, rerun_meta, args.temperature)

    # 更新 D 组结果中的对应样本
    d_results = json.loads(d_path.read_text(encoding="utf-8"))
    for s in d_results["samples"]:
        if s["file"] == RERUN_SAMPLE:
            s["runs"] = [run_record]
            verdicts = [run_record.get("model_has_vulnerability")]
            valid = [v for v in verdicts if v is not None]
            if valid:
                true_count = sum(1 for v in valid if v)
                s["majority_verdict"] = true_count >= len(valid) / 2
                s["agreement_rate"] = round(
                    max(true_count, len(valid) - true_count) / len(valid), 4
                )
            break

    recompute_metrics(d_results)
    d_results["rerun_fixed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    save_results_json(d_path, d_results)

    print(f"\n  === D 组 (irrelevant) 修正后指标 ===")
    print_summary(d_results["metrics_single_run"])

    # 卸载模型
    if not args.keep_loaded:
        if client.unload_model():
            print(f"\n  [信息] 模型 {MODEL} 已从显存卸载")

    # Step 3: 汇总 4 组修正后指标
    print("\n=== Step 3: P1-5 4 组修正后指标汇总 ===")
    print(f"{'组别':<20} {'准确率':>8} {'召回率':>8} {'误报率':>8} {'TP/FP/FN/TN':>20}")
    for name, f in ABLATION_FILES.items():
        d = json.loads((RESULTS_DIR / f).read_text(encoding="utf-8"))
        m = d.get("metrics_single_run", {})
        tp, fp, fn, tn = m.get("tp", 0), m.get("fp", 0), m.get("fn", 0), m.get("tn", 0)
        acc = m.get("accuracy", 0) or 0
        rec = m.get("recall", 0) or 0
        fpr = m.get("false_positive_rate", 0) or 0
        print(f"{name:<20} {acc*100:>7.2f}% {rec*100:>7.2f}% {fpr*100:>7.2f}% {f'{tp}/{fp}/{fn}/{tn}':>20}")

    print("\n=== 全部完成 ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
