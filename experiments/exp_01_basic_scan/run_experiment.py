"""
exp_01_basic_scan - 批量漏洞检测摸底测试脚本

读取 samples/manifest.json 中登记的代码样本，依次调用本地 Ollama API
（默认模型 gemma4:26b）进行漏洞分析，将每次推理的原始输出、耗时、解析
后的判定结果统一写入 results/results.json，便于后续人工复核与统计。

用法:
    python run_experiment.py                          # 使用默认配置运行全部样本
    python run_experiment.py --model gemma4:26b       # 指定模型
    python run_experiment.py --limit 3                # 只跑前 3 个样本（调试用）
    python run_experiment.py --host http://localhost:11434
"""

import argparse
import sys
import time
from pathlib import Path

# 把项目根加入 sys.path，保证可从任意目录运行
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.llm_client import OllamaClient
from src.prompts import build_full_prompt
from src.schema import parse_verdict, normalize_has_vulnerability
from experiments.utils import (
    load_manifest,
    read_sample_code,
    save_results_json,
    new_results_envelope,
    compute_detection_metrics,
    print_summary,
)

# ---------------------------------------------------------------------------
# 路径常量
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = SCRIPT_DIR / "samples"
RESULTS_DIR = SCRIPT_DIR / "results"
MANIFEST_PATH = SAMPLES_DIR / "manifest.json"
RESULTS_PATH = RESULTS_DIR / "results.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="批量漏洞检测摸底测试")
    parser.add_argument("--host", default="http://localhost:11434",
                        help="Ollama 服务地址（默认 http://localhost:11434）")
    parser.add_argument("--model", default="qwen2.5-coder:14b",
                        help="Ollama 中模型名（默认 qwen2.5-coder:14b）")
    parser.add_argument("--temperature", type=float, default=0.1,
                        help="采样温度（默认 0.1，更稳定）")
    parser.add_argument("--limit", type=int, default=0,
                        help="只跑前 N 个样本，0 表示全部")
    parser.add_argument("--timeout", type=int, default=600,
                        help="单次请求超时秒数（默认 600）")
    parser.add_argument("--keep-loaded", action="store_true",
                        help="跑完后保持模型在显存中（默认卸载，多模型场景避免爆显存）")
    args = parser.parse_args()

    try:
        manifest, samples = load_manifest(MANIFEST_PATH)
    except (FileNotFoundError, KeyError) as e:
        print(f"[错误] {e}", file=sys.stderr)
        return 1
    if args.limit > 0:
        samples = samples[: args.limit]

    results = new_results_envelope(
        experiment=manifest.get("experiment", "exp_01_basic_scan"),
        model=args.model,
        host=args.host,
        temperature=args.temperature,
    )

    total = len(samples)
    print(f"[信息] 共 {total} 个样本，模型 {args.model}，host {args.host}")

    client = OllamaClient(base_url=args.host, model=args.model)

    for idx, sample_meta in enumerate(samples, 1):
        filename = sample_meta["file"]
        code = read_sample_code(SAMPLES_DIR, filename)
        if code is None:
            continue
        language = sample_meta.get("language", "text")

        prompt = build_full_prompt(code=code, language=language, filename=filename)
        print(f"[{idx}/{total}] 分析 {filename} ({language}, expected_present={sample_meta['expected_present']}) ...", flush=True)

        record = {
            "file": filename,
            "language": language,
            "category": sample_meta.get("category"),
            "expected_present": sample_meta.get("expected_present"),
            "expected_vulnerability": sample_meta.get("expected_vulnerability"),
            "prompt_chars": len(prompt),
            "elapsed_seconds": None,
            "raw_output": None,
            "parsed_verdict": {},
            "model_has_vulnerability": None,
            "error": None,
        }

        # keep_alive=-1 让模型在批量跑期间常驻显存，跑完统一卸载
        result = client.generate(
            prompt=prompt,
            temperature=args.temperature,
            max_tokens=None,
            keep_alive=-1,
            timeout=args.timeout,
        )
        elapsed = round(result["duration"], 2)
        record["elapsed_seconds"] = elapsed

        if result["error"]:
            record["error"] = result["error"]
            print(f"        [错误] {result['error']}", file=sys.stderr)
        else:
            text = result["text"]
            record["raw_output"] = text
            record["meta"] = result["meta"]
            verdict = parse_verdict(text)
            record["parsed_verdict"] = verdict
            if verdict:
                record["model_has_vulnerability"] = normalize_has_vulnerability(
                    verdict.get("has_vulnerability")
                )
            print(f"        -> 用时 {elapsed}s, 判定={record['model_has_vulnerability']}")

        results["samples"].append(record)
        # 每跑完一个样本立即落盘，避免中途崩溃丢失结果
        save_results_json(RESULTS_PATH, results)

    results["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    # 汇总指标并写入结果文件
    metrics = compute_detection_metrics(results["samples"])
    results["metrics"] = metrics
    save_results_json(RESULTS_PATH, results)
    print(f"[完成] 结果已写入 {RESULTS_PATH}")
    print("\n=== 汇总指标 ===")
    print_summary(metrics)

    # 默认跑完立即从显存卸载模型，多模型场景下避免爆显存
    if args.keep_loaded:
        print(f"[信息] --keep-loaded 已启用，模型 {args.model} 保留在显存中")
    else:
        if client.unload_model():
            print(f"[信息] 模型 {args.model} 已从显存卸载（如需保留请加 --keep-loaded）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
