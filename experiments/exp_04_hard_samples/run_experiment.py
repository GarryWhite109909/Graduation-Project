"""
exp_04_hard_samples - 难样本压力测试：纯 LLM 漏洞检测（含重复实验 + 置信区间）

读取 samples/manifest.json 中登记的 42 段样本（含典型/安全/难/噪音），
对每个样本调用本地 Ollama API 进行漏洞分析。支持：

- --repeat N：对每个样本连续调用 N 次，记录每次原始输出
- 多数表决作为最终判定，计算 Wilson 95% 置信区间
- 耗时统计含均值/标准差/中位数/p95
- 跨文件样本自动注入对应 _input.py 作为上下文
- 长文件按原样送入（不切片）

用法:
    python run_experiment.py                              # 默认 --repeat 3
    python run_experiment.py --repeat 1                   # 单次（与 exp_01 等价）
    python run_experiment.py --limit 3 --repeat 2         # 只跑前 3 个样本，每个 2 次
    python run_experiment.py --model gemma4:12b
    python run_experiment.py --keep-loaded                # 跑完保留模型在显存
"""

import argparse
import re
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
    save_results_json,
    new_results_envelope,
    compute_detection_metrics,
    compute_repeat_metrics,
    print_summary,
    print_repeat_summary,
)

# ---------------------------------------------------------------------------
# 路径常量
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = SCRIPT_DIR / "samples"
RESULTS_DIR = SCRIPT_DIR / "results"
MANIFEST_PATH = SAMPLES_DIR / "manifest.json"
RESULTS_PATH = RESULTS_DIR / "results.json"


# ---------------------------------------------------------------------------
# 跨文件样本处理
# ---------------------------------------------------------------------------
# 跨文件样本配对：sink 文件 → 对应的 input 文件
# 当分析 sink 时，把 input 内容作为「相关代码上下文」注入 prompt，模拟跨文件分析
def _crossfile_pair(sink_filename: str) -> str | None:
    """根据 sink 文件名推断对应的 input 文件名。无配对返回 None。"""
    # hard_crossfile_01_sink.py → hard_crossfile_01_input.py
    m = re.match(r"^(hard_crossfile_\d+)_sink\.(py|js|java|php)$", sink_filename)
    if m:
        return f"{m.group(1)}_input.{m.group(2)}"
    return None


def read_sample_code(samples_dir: Path, filename: str) -> str | None:
    """读取样本代码。文件不存在时返回 None。"""
    path = samples_dir / filename
    if not path.exists():
        print(f"[跳过] 样本文件不存在: {path}", file=sys.stderr)
        return None
    return path.read_text(encoding="utf-8")


def build_prompt_for_sample(samples_dir: Path, sample_meta: dict) -> str:
    """为单个样本构建 prompt，自动处理跨文件样本。

    跨文件样本（hard_crossfile_*_sink.*）会把对应的 _input.* 文件作为
    「相关代码上下文」注入 prompt，让模型能模拟跨文件污点分析。
    """
    filename = sample_meta["file"]
    language = sample_meta.get("language", "text")
    code = read_sample_code(samples_dir, filename)
    if code is None:
        return None

    pair = _crossfile_pair(filename)
    if pair:
        input_code = read_sample_code(samples_dir, pair)
        if input_code:
            # 把 input 文件作为相关上下文注入
            code = (
                f"# === 相关代码上下文（同项目另一文件：{pair}） ===\n"
                f"{input_code}\n\n"
                f"# === 待分析的目标文件：{filename} ===\n"
                f"{code}"
            )
            print(f"        [跨文件] 注入相关上下文 {pair}（{len(input_code)} 字符）")

    return build_full_prompt(code=code, language=language, filename=filename)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="exp_04 难样本压力测试（纯 LLM，含重复实验）")
    parser.add_argument("--host", default="http://localhost:11434",
                        help="Ollama 服务地址（默认 http://localhost:11434）")
    parser.add_argument("--model", default="qwen2.5-coder:14b",
                        help="Ollama 模型名（默认 qwen2.5-coder:14b）")
    parser.add_argument("--temperature", type=float, default=0.1,
                        help="采样温度（默认 0.1）")
    parser.add_argument("--limit", type=int, default=0,
                        help="只跑前 N 个样本，0 表示全部")
    parser.add_argument("--repeat", type=int, default=3,
                        help="每个样本重复跑 N 次（默认 3，用于多数表决与置信区间）")
    parser.add_argument("--timeout", type=int, default=900,
                        help="单次请求超时秒数（默认 900，长文件需更久）")
    parser.add_argument("--keep-loaded", action="store_true",
                        help="跑完后保持模型在显存中（默认卸载）")
    parser.add_argument("--output", default=str(RESULTS_PATH),
                        help="结果输出路径（默认 results/results.json）")
    parser.add_argument("--resume", action="store_true",
                        help="断点续跑：加载已有结果，跳过已完成的样本（majority_verdict "
                             "不为 None），只重跑未完成的。适合中断后恢复。")
    args = parser.parse_args()

    try:
        manifest, samples = load_manifest(MANIFEST_PATH)
    except (FileNotFoundError, KeyError) as e:
        print(f"[错误] {e}", file=sys.stderr)
        return 1
    if args.limit > 0:
        samples = samples[: args.limit]

    repeat = max(1, args.repeat)
    total = len(samples)
    total_runs = total * repeat
    print(f"[信息] 共 {total} 个样本，每样本重复 {repeat} 次，共 {total_runs} 次推理")
    print(f"[信息] 模型 {args.model}，host {args.host}，温度 {args.temperature}")
    print(f"[信息] 预计耗时约 {total_runs * 45 / 60:.1f} 分钟（按 45s/次估算）")

    client = OllamaClient(base_url=args.host, model=args.model)
    if not client.check_connection():
        print(f"[错误] 无法连接 Ollama（{args.host}），请先运行 ollama serve", file=sys.stderr)
        return 1

    # --resume: 加载已有结果，跳过已完成的样本
    output_path = Path(args.output)
    if args.resume and output_path.exists():
        import json as _json
        results = _json.loads(output_path.read_text(encoding="utf-8"))
        existing_samples = results.get("samples", [])
        finished = sum(1 for s in existing_samples
                       if s.get("majority_verdict") is not None)
        pending = total - finished
        print(f"[信息] --resume: 已完成 {finished}/{total}，待重跑 {pending} 个样本")
        results["samples"] = existing_samples
        results["resumed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    else:
        results = new_results_envelope(
            experiment="exp_04_hard_samples",
            model=args.model,
            host=args.host,
            temperature=args.temperature,
            repeat=repeat,
            sample_count=total,
            total_runs=total_runs,
        )

    run_idx = 0
    skipped = 0
    for idx, sample_meta in enumerate(samples, 1):
        filename = sample_meta["file"]
        language = sample_meta.get("language", "text")

        # --resume: 跳过已完成的样本
        if args.resume:
            existing = next((s for s in results["samples"]
                             if s["file"] == filename), None)
            if existing and existing.get("majority_verdict") is not None:
                skipped += 1
                print(f"[{idx}/{total}] {filename} 已完成，跳过", flush=True)
                continue

        prompt = build_prompt_for_sample(SAMPLES_DIR, sample_meta)
        if prompt is None:
            continue

        print(f"\n[{idx}/{total}] {filename} ({language}, expected_present={sample_meta['expected_present']})", flush=True)

        sample_record = {
            "file": filename,
            "language": language,
            "category": sample_meta.get("category"),
            "difficulty": sample_meta.get("difficulty"),
            "expected_present": sample_meta.get("expected_present"),
            "expected_vulnerability": sample_meta.get("expected_vulnerability"),
            "expected_cwe": sample_meta.get("expected_cwe"),
            "expected_risk_level": sample_meta.get("expected_risk_level"),
            "prompt_chars": len(prompt),
            "runs": [],
            # 多数表决后填充：
            "majority_verdict": None,
            "agreement_rate": None,
        }

        for r in range(repeat):
            run_idx += 1
            print(f"  [{r+1}/{repeat}] 推理中...", end="", flush=True)
            t0 = time.time()
            result = client.generate(
                prompt=prompt,
                temperature=args.temperature,
                max_tokens=None,
                keep_alive=-1,  # 批量期间常驻，跑完统一卸载
                timeout=args.timeout,
            )
            elapsed = round(result["duration"], 2)
            print(f" 用时 {elapsed}s", end="")

            run_record = {
                "run_index": r + 1,
                "elapsed_seconds": elapsed,
                "raw_output": None,
                "parsed_verdict": {},
                "model_has_vulnerability": None,
                "error": None,
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
                print(f" -> 判定={run_record['model_has_vulnerability']}", flush=True)

            sample_record["runs"].append(run_record)
            # 每跑完一次落盘，避免崩溃丢失
            # 替换或追加当前 sample_record
            _upsert_sample(results["samples"], sample_record)
            save_results_json(Path(args.output), results)

        # 多数表决
        verdicts = [r.get("model_has_vulnerability") for r in sample_record["runs"]]
        valid = [v for v in verdicts if v is not None]
        if valid:
            true_count = sum(1 for v in valid if v)
            sample_record["majority_verdict"] = true_count >= len(valid) / 2
            sample_record["agreement_rate"] = round(
                max(true_count, len(valid) - true_count) / len(valid), 4
            )
        save_results_json(Path(args.output), results)

    results["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    # 1. 单次实验口径指标（所有 run 拉平统计，便于和 exp_01 对比）
    flat_records = []
    for s in results["samples"]:
        for run in s["runs"]:
            flat_records.append({
                "file": s["file"],
                "expected_present": s["expected_present"],
                "model_has_vulnerability": run.get("model_has_vulnerability"),
                "elapsed_seconds": run.get("elapsed_seconds"),
            })
    single_metrics = compute_detection_metrics(flat_records)
    results["metrics_single_run"] = single_metrics

    # 2. 多数表决口径指标（含 Wilson 95% CI）
    repeat_metrics = compute_repeat_metrics(flat_records)
    results["metrics_majority_vote"] = repeat_metrics

    save_results_json(Path(args.output), results)

    print(f"\n[完成] 结果已写入 {args.output}")
    print("\n=== 单次实验口径指标（所有 run 拉平）===")
    print_summary(single_metrics)
    print("\n=== 多数表决口径指标（含 95% 置信区间）===")
    print_repeat_summary(repeat_metrics)

    # 卸载模型
    if args.keep_loaded:
        print(f"\n[信息] --keep-loaded 已启用，模型 {args.model} 保留在显存中")
    else:
        if client.unload_model():
            print(f"[信息] 模型 {args.model} 已从显存卸载（如需保留请加 --keep-loaded）")
    return 0


def _upsert_sample(samples_list: list, sample_record: dict) -> None:
    """把 sample_record 按 file 字段 upsert 到 samples_list。"""
    for i, s in enumerate(samples_list):
        if s["file"] == sample_record["file"]:
            samples_list[i] = sample_record
            return
    samples_list.append(sample_record)


if __name__ == "__main__":
    raise SystemExit(main())
