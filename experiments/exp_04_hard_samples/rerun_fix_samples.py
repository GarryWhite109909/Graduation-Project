"""
rerun_fix_samples - 修复后重跑受影响样本

修复内容：
1. safe_11_bcrypt_password.py：增加 html.escape 输出转义（修复反射型 XSS）
2. safe_13_csrf_token.py：增加 html.escape 输出转义（修复反射型 XSS）
3. safe_18_java_prepared_stmt.java：凭证改从环境变量读取（修复硬编码凭证）
4. schema.py：增加 markdown 格式解析兜底（修复 safe_07 解析失败）

本脚本只重跑上述 3 个修改样本 × 6 模型 = 18 次推理，
并对 qwen2.5-coder_14b 的 safe_07 用新 schema 重新解析 raw_output（无需重跑 LLM），
最后重新计算所有模型的指标。

用法:
    python rerun_fix_samples.py                    # 重跑 3 样本 × 6 模型
    python rerun_fix_samples.py --dry-run          # 只重新解析 safe_07，不重跑 LLM
    python rerun_fix_samples.py --models qwen2.5-coder:7b  # 只跑指定模型
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
    upsert_sample,
    compute_detection_metrics,
    compute_repeat_metrics,
    print_summary,
)

SCRIPT_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = SCRIPT_DIR / "samples"
RESULTS_DIR = SCRIPT_DIR / "results"
MANIFEST_PATH = SAMPLES_DIR / "manifest.json"

# 需要重跑的样本（代码已修复）
FIXED_SAMPLES = ["safe_11_bcrypt_password.py", "safe_13_csrf_token.py", "safe_18_java_prepared_stmt.java"]

# 6 个模型及其结果文件
MODELS = [
    ("qwen2.5-coder:7b", "results.pure.qwen2.5-coder_7b.v3.multi_model.json"),
    ("qwen2.5-coder:14b", "results.pure.qwen2.5-coder_14b.v3.multi_model.json"),
    ("gemma4:12b", "results.pure.gemma4_12b.v3.multi_model.json"),
    ("deepseek-coder-v2:16b", "results.pure.deepseek-coder-v2_16b.v3.multi_model.json"),
    ("gpt-oss:20b", "results.pure.gpt-oss_20b.v3.multi_model.json"),
    ("gemma4:26b", "results.pure.gemma4_26b.v3.multi_model.json"),
]


def rerun_sample(client: OllamaClient, sample_meta: dict, temperature: float) -> dict:
    """重跑单个样本，返回 run_record。"""
    filename = sample_meta["file"]
    path = SAMPLES_DIR / filename
    code = path.read_text(encoding="utf-8")
    language = sample_meta.get("language", "text")

    prompt = build_user_prompt(code=code, language=language, filename=filename, rag_context="")
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
        "rag_retrieval": [],
        "rag_context_chars": 0,
        "elapsed_seconds": elapsed,
        "raw_output": None,
        "parsed_verdict": {},
        "model_has_vulnerability": None,
        "error": None,
        "rerun_reason": "sample_code_fixed",
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

    return run_record


def reparse_safe_07(results: dict) -> bool:
    """对 safe_07_input_validation.py 用新 schema 重新解析 raw_output。

    返回是否有变化。
    """
    for s in results.get("samples", []):
        if s.get("file") != "safe_07_input_validation.py":
            continue
        changed = False
        for run in s.get("runs", []):
            raw = run.get("raw_output")
            if not raw:
                continue
            old_verdict = run.get("parsed_verdict", {})
            old_has_vuln = run.get("model_has_vulnerability")
            new_verdict = parse_verdict(raw)
            new_has_vuln = normalize_has_vulnerability(new_verdict.get("has_vulnerability")) if new_verdict else None
            if new_verdict and new_has_vuln is not None and old_has_vuln is None:
                run["parsed_verdict"] = new_verdict
                run["model_has_vulnerability"] = new_has_vuln
                run["rerun_reason"] = "schema_fix_reparse"
                changed = True
                print(f"    [重新解析] safe_07: None -> {new_has_vuln}")
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


def recompute_metrics(results: dict) -> None:
    """重新计算 metrics_single_run 和 metrics_majority_vote。"""
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
    results["metrics_majority_vote"] = compute_repeat_metrics(flat_records)


def main() -> int:
    parser = argparse.ArgumentParser(description="修复后重跑受影响样本")
    parser.add_argument("--host", default="http://localhost:11434")
    parser.add_argument("--temperature", type=float, default=0.1)
    parser.add_argument("--models", nargs="*", default=None,
                        help="只跑指定模型（默认全部 6 个）")
    parser.add_argument("--dry-run", action="store_true",
                        help="只重新解析 safe_07，不重跑 LLM")
    parser.add_argument("--keep-loaded", action="store_true",
                        help="跑完后保持模型在显存中（默认卸载）")
    args = parser.parse_args()

    try:
        manifest, samples = load_manifest(MANIFEST_PATH)
    except (FileNotFoundError, KeyError) as e:
        print(f"[错误] {e}", file=sys.stderr)
        return 1

    # 筛选要跑的样本
    fixed_sample_metas = [s for s in samples if s["file"] in FIXED_SAMPLES]
    if len(fixed_sample_metas) != len(FIXED_SAMPLES):
        print(f"[错误] 未找到所有修复样本，期望 {len(FIXED_SAMPLES)}，找到 {len(fixed_sample_metas)}", file=sys.stderr)
        return 1

    # 筛选要跑的模型
    models_to_run = MODELS
    if args.models:
        models_to_run = [(m, f) for m, f in MODELS if m in args.models]
        if not models_to_run:
            print(f"[错误] 未找到指定模型", file=sys.stderr)
            return 1

    print(f"[信息] 修复样本: {FIXED_SAMPLES}")
    print(f"[信息] 模型列表: {[m for m, _ in models_to_run]}")
    print(f"[信息] dry-run={args.dry_run}")

    # Step 1: 对所有模型先重新解析 safe_07（无需 LLM）
    print("\n=== Step 1: 重新解析 safe_07（schema 修复）===")
    for model_name, result_file in models_to_run:
        result_path = RESULTS_DIR / result_file
        if not result_path.exists():
            print(f"  [跳过] {model_name}: 结果文件不存在 {result_file}")
            continue
        results = json.loads(result_path.read_text(encoding="utf-8"))
        changed = reparse_safe_07(results)
        if changed:
            recompute_metrics(results)
            results["schema_fix_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            save_results_json(result_path, results)
            print(f"  [完成] {model_name}: safe_07 已重新解析并保存")
        else:
            print(f"  [跳过] {model_name}: safe_07 无需重新解析")

    if args.dry_run:
        print("\n[dry-run] 不重跑 LLM，退出")
        return 0

    # Step 2: 重跑 3 个修复样本 × 各模型
    print("\n=== Step 2: 重跑 3 个修复样本 × 各模型 ===")
    for model_idx, (model_name, result_file) in enumerate(models_to_run, 1):
        result_path = RESULTS_DIR / result_file
        if not result_path.exists():
            print(f"\n[跳过] {model_name}: 结果文件不存在")
            continue

        print(f"\n[{model_idx}/{len(models_to_run)}] 模型 {model_name}")
        results = json.loads(result_path.read_text(encoding="utf-8"))

        client = OllamaClient(base_url=args.host, model=model_name)
        if not client.check_connection():
            print(f"  [错误] 无法连接 Ollama，跳过 {model_name}", file=sys.stderr)
            continue

        for sample_meta in fixed_sample_metas:
            filename = sample_meta["file"]
            print(f"  重跑 {filename}...")

            run_record = rerun_sample(client, sample_meta, args.temperature)

            # 更新结果中的对应样本
            for s in results["samples"]:
                if s["file"] == filename:
                    # 替换 runs 为新的单次结果
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

            # 增量落盘
            save_results_json(result_path, results)

        # 重新计算指标
        recompute_metrics(results)
        results["rerun_fixed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        save_results_json(result_path, results)

        # 打印该模型的汇总
        print(f"\n  === {model_name} 修正后指标 ===")
        print_summary(results["metrics_single_run"])

        # 卸载模型（除非 --keep-loaded 或还有后续模型）
        if not args.keep_loaded:
            if client.unload_model():
                print(f"  [信息] 模型 {model_name} 已从显存卸载")

    print("\n=== 全部完成 ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
