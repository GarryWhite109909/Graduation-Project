"""
exp_04_hard_samples - 难样本压力测试：纯 LLM 漏洞检测（含重复实验 + 置信区间）

读取 samples/manifest.json 中登记的 87 段样本（含典型/安全/难/噪音），
对每个样本调用本地 Ollama API 进行漏洞分析。支持：

- --repeat N：对每个样本连续调用 N 次，记录每次原始输出
- 多数表决作为最终判定，计算 Wilson 95% 置信区间
- 耗时统计含均值/标准差/中位数/p95
- 跨文件样本自动注入对应 _input.py 作为上下文
- --slice：启用 AST 切片（tree-sitter 按函数切分长文件），解决长上下文注意力衰减

用法:
    python run_experiment.py                              # 默认 --repeat 3
    python run_experiment.py --repeat 1                   # 单次（与 exp_01 等价）
    python run_experiment.py --limit 3 --repeat 2         # 只跑前 3 个样本，每个 2 次
    python run_experiment.py --model deepseek-coder-v2:16b  # 切换对照模型
    python run_experiment.py --keep-loaded                # 跑完保留模型在显存
    python run_experiment.py --slice                      # 启用 AST 切片（长文件按函数切分）
    python run_experiment.py --slice --min-lines 150      # 自定义切片阈值
    python run_experiment.py --slice --only longfile      # 仅对 hard_longfile_* 应用切片
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

from graduation_project.llm_client import OllamaClient
from graduation_project.prompts import build_full_prompt
from graduation_project.schema import parse_verdict, normalize_has_vulnerability
from graduation_project.code_slicer import CodeSlicer, SliceResult
from experiments.utils import (
    load_manifest,
    read_sample_code,
    save_results_json,
    new_results_envelope,
    upsert_sample,
    default_results_path,
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


def build_prompt_for_chunk(chunk_code: str, language: str, filename: str, chunk_name: str) -> str:
    """为单个切片构建 prompt。

    与 build_prompt_for_sample 类似，但 prompt 头部明确告知模型这是从长文件中切出的函数片段，
    需要重点关注当前函数本身的安全问题。
    """
    code_with_header = (
        f"# === 切片说明 ===\n"
        f"# 以下是从长文件 {filename} 中按 AST 函数切分得到的代码片段。\n"
        f"# 当前分析目标：函数 {chunk_name}\n"
        f"# 文件级上下文（imports / 全局常量 / 类骨架）已保留在上方，供参考。\n"
        f"# === 代码片段 ===\n"
        f"{chunk_code}"
    )
    return build_full_prompt(code=code_with_header, language=language, filename=filename)


def should_slice_sample(filename: str, only_mode: str) -> bool:
    """根据 --only 参数判断是否对该样本应用切片。"""
    if not only_mode or only_mode == "all":
        return True
    if only_mode == "longfile":
        return "longfile" in filename
    if only_mode == "hard":
        return filename.startswith("hard_")
    return True


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="exp_04 难样本压力测试（纯 LLM，含重复实验）")
    parser.add_argument("--host", default="http://localhost:11434",
                        help="Ollama 服务地址（默认 http://localhost:11434）")
    parser.add_argument("--model", default="qwen2.5-coder:7b",
                        help="Ollama 模型名（默认 qwen2.5-coder:7b）")
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
    parser.add_argument("--output", default=None,
                        help="结果输出路径（默认 results/exp_04_hard_samples.<model>.repeat<N>.<timestamp>.json）")
    parser.add_argument("--resume", action="store_true",
                        help="断点续跑：加载已有结果，跳过已完成的样本（majority_verdict "
                             "不为 None），只重跑未完成的。适合中断后恢复。")
    parser.add_argument("--slice", action="store_true",
                        help="启用 AST 切片模式（tree-sitter 按函数切分长文件）。"
                             "切片后每个函数片段单独送入 LLM，结果按 OR 合并"
                             "（任一片段判 True 则整体判 True，保守策略宁误报不漏报）。")
    parser.add_argument("--min-lines", type=int, default=150,
                        help="AST 切片的最小文件行数阈值（默认 150，文件 < 此值不切片）。"
                             "仅 --slice 启用时生效。")
    parser.add_argument("--only", choices=["all", "longfile", "hard"], default="all",
                        help="切片范围：all=全部样本 / longfile=仅 hard_longfile_* / hard=仅 hard_*。"
                             "默认 all。仅 --slice 启用时生效。")
    parser.add_argument("--filter", default=None,
                        help="只跑文件名包含此子串的样本（如 --filter longfile）。默认 None=全部。")
    args = parser.parse_args()

    repeat = max(1, args.repeat)
    slice_tag = ""
    if args.slice:
        slice_tag = f"slice-min{args.min_lines}-{args.only}"
    extra_tag = f"repeat{repeat}" + (f".{slice_tag}" if slice_tag else "")
    results_path = Path(args.output) if args.output else default_results_path(
        RESULTS_DIR,
        experiment="exp_04_hard_samples",
        model=args.model,
        extra_tag=extra_tag,
    )

    try:
        manifest, samples = load_manifest(MANIFEST_PATH)
    except (FileNotFoundError, KeyError) as e:
        print(f"[错误] {e}", file=sys.stderr)
        return 1
    if args.limit > 0:
        samples = samples[: args.limit]
    if args.filter:
        samples = [s for s in samples if args.filter in s["file"]]

    total = len(samples)
    total_runs = total * repeat
    print(f"[信息] 共 {total} 个样本，每样本重复 {repeat} 次，共 {total_runs} 次推理")
    print(f"[信息] 模型 {args.model}，host {args.host}，温度 {args.temperature}")
    if args.slice:
        print(f"[信息] AST 切片已启用：min_lines={args.min_lines}, only={args.only}")
    print(f"[信息] 预计耗时约 {total_runs * 45 / 60:.1f} 分钟（按 45s/次估算）")

    client = OllamaClient(base_url=args.host, model=args.model)
    if not client.check_connection():
        print(f"[错误] 无法连接 Ollama（{args.host}），请先运行 ollama serve", file=sys.stderr)
        return 1

    # 切片器（仅 --slice 启用时使用）
    slicer = CodeSlicer(min_lines=args.min_lines) if args.slice else None

    # --resume: 加载已有结果，跳过已完成的样本
    if args.resume and results_path.exists():
        import json as _json
        results = _json.loads(results_path.read_text(encoding="utf-8"))
        existing_samples = results.get("samples", [])
        finished = sum(1 for s in existing_samples
                       if s.get("majority_verdict") is not None)
        pending = total - finished
        print(f"[信息] --resume: 已完成 {finished}/{total}，待重跑 {pending} 个样本")
        results["samples"] = existing_samples
        results["resumed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        results["resumed_from"] = str(results_path)
    else:
        results = new_results_envelope(
            experiment="exp_04_hard_samples",
            model=args.model,
            host=args.host,
            temperature=args.temperature,
            repeat=repeat,
            sample_count=total,
            total_runs=total_runs,
            slice_enabled=args.slice,
            slice_min_lines=args.min_lines if args.slice else None,
            slice_only=args.only if args.slice else None,
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

        # 判断是否需要切片
        apply_slice = False
        slice_result: SliceResult | None = None
        if slicer and should_slice_sample(filename, args.only):
            code = read_sample_code(SAMPLES_DIR, filename)
            if code is not None:
                slice_result = slicer.slice(code, language=language, filename=filename)
                apply_slice = slice_result.sliced

        if apply_slice and slice_result is not None:
            sample_record = run_sample_with_slice(
                client=client,
                sample_meta=sample_meta,
                slice_result=slice_result,
                repeat=repeat,
                temperature=args.temperature,
                timeout=args.timeout,
                idx=idx,
                total=total,
            )
        else:
            prompt = build_prompt_for_sample(SAMPLES_DIR, sample_meta)
            if prompt is None:
                continue
            print(f"\n[{idx}/{total}] {filename} ({language}, expected_present={sample_meta['expected_present']})", flush=True)
            sample_record = run_sample_whole(
                client=client,
                sample_meta=sample_meta,
                prompt=prompt,
                repeat=repeat,
                temperature=args.temperature,
                timeout=args.timeout,
                idx=idx,
                total=total,
            )

        upsert_sample(results["samples"], sample_record)
        save_results_json(results_path, results)

    results["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    # 统计指标：切片模式用 sample 级别（majority_verdict），非切片模式用 run 级别拉平
    has_slice = any(s.get("slice_mode") for s in results["samples"])
    if has_slice:
        # 切片模式：每个 sample 一条 record，用 majority_verdict（chunk 间 OR 合并结果）
        flat_records = []
        for s in results["samples"]:
            flat_records.append({
                "file": s["file"],
                "expected_present": s["expected_present"],
                "model_has_vulnerability": s.get("majority_verdict"),
                "elapsed_seconds": sum(
                    r.get("elapsed_seconds", 0) for r in s.get("runs", [])
                ) if s.get("runs") else None,
            })
        single_metrics = compute_detection_metrics(flat_records)
        results["metrics_single_run"] = single_metrics

        # 多数表决口径：切片模式下与 single 等价（sample 级别已合并）
        # 但仍用 compute_repeat_metrics 获得 per_sample 一致率等明细
        repeat_metrics = compute_repeat_metrics(flat_records)
        results["metrics_majority_vote"] = repeat_metrics
        # 切片模式额外：chunk 级别指标（参考）
        chunk_records = []
        for s in results["samples"]:
            for chunk in s.get("chunks", []):
                for run in chunk.get("runs", []):
                    chunk_records.append({
                        "file": f"{s['file']}#{chunk['name']}",
                        "expected_present": s["expected_present"],  # 注意：用 sample 级真值，仅供参考
                        "model_has_vulnerability": run.get("model_has_vulnerability"),
                        "elapsed_seconds": run.get("elapsed_seconds"),
                    })
        results["metrics_chunk_level"] = compute_detection_metrics(chunk_records)
    else:
        # 非切片模式：保持原逻辑，所有 run 拉平
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
        repeat_metrics = compute_repeat_metrics(flat_records)
        results["metrics_majority_vote"] = repeat_metrics

    save_results_json(results_path, results)

    print(f"\n[完成] 结果已写入 {results_path}")
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


# ---------------------------------------------------------------------------
# 单样本执行：整文件模式（原逻辑）
# ---------------------------------------------------------------------------
def run_sample_whole(
    client: OllamaClient,
    sample_meta: dict,
    prompt: str,
    repeat: int,
    temperature: float,
    timeout: int,
    idx: int,
    total: int,
) -> dict:
    """整文件模式：对单个样本连续跑 N 次，多数表决。"""
    filename = sample_meta["file"]
    language = sample_meta.get("language", "text")
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
        "slice_mode": False,
        "runs": [],
        "majority_verdict": None,
        "agreement_rate": None,
    }

    for r in range(repeat):
        print(f"  [{r+1}/{repeat}] 推理中...", end="", flush=True)
        result = client.generate(
            prompt=prompt,
            temperature=temperature,
            max_tokens=None,
            keep_alive=-1,
            timeout=timeout,
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

    # 多数表决
    verdicts = [r.get("model_has_vulnerability") for r in sample_record["runs"]]
    valid = [v for v in verdicts if v is not None]
    if valid:
        true_count = sum(1 for v in valid if v)
        sample_record["majority_verdict"] = true_count >= len(valid) / 2
        sample_record["agreement_rate"] = round(
            max(true_count, len(valid) - true_count) / len(valid), 4
        )

    return sample_record


# ---------------------------------------------------------------------------
# 单样本执行：切片模式
# ---------------------------------------------------------------------------
def run_sample_with_slice(
    client: OllamaClient,
    sample_meta: dict,
    slice_result: SliceResult,
    repeat: int,
    temperature: float,
    timeout: int,
    idx: int,
    total: int,
) -> dict:
    """切片模式：对每个 chunk 连续跑 N 次，chunk 内多数表决，chunk 间 OR 合并。

    合并策略（保守，宁误报不漏报）：
    - 任一 chunk 多数表决为 True → 整体 majority_verdict = True
    - 所有 chunk 多数表决为 False → 整体 majority_verdict = False
    - 所有 chunk 都无有效判定 → None
    """
    filename = sample_meta["file"]
    language = sample_meta.get("language", "text")
    chunk_count = slice_result.chunk_count
    print(f"\n[{idx}/{total}] {filename} ({language}, expected_present={sample_meta['expected_present']})", flush=True)
    print(f"  [切片] 共 {chunk_count} 个 chunk，每 chunk 重复 {repeat} 次，共 {chunk_count * repeat} 次推理", flush=True)

    sample_record = {
        "file": filename,
        "language": language,
        "category": sample_meta.get("category"),
        "difficulty": sample_meta.get("difficulty"),
        "expected_present": sample_meta.get("expected_present"),
        "expected_vulnerability": sample_meta.get("expected_vulnerability"),
        "expected_cwe": sample_meta.get("expected_cwe"),
        "expected_risk_level": sample_meta.get("expected_risk_level"),
        "slice_mode": True,
        "slice_chunk_count": chunk_count,
        "slice_total_lines": slice_result.total_lines,
        "chunks": [],
        "runs": [],  # 兼容统计：把每个 chunk 的每次 run 平铺
        "majority_verdict": None,
        "agreement_rate": None,
    }

    overall_true_count = 0  # chunk 多数表决为 True 的数量
    overall_valid_chunks = 0

    for chunk in slice_result.chunks:
        chunk_prompt = build_prompt_for_chunk(
            chunk_code=chunk.code,
            language=language,
            filename=filename,
            chunk_name=chunk.name,
        )
        print(f"  [chunk {chunk.chunk_id}/{chunk_count}] {chunk.name} (L{chunk.start_line}-L{chunk.end_line})", flush=True)

        chunk_record = {
            "chunk_id": chunk.chunk_id,
            "name": chunk.name,
            "start_line": chunk.start_line,
            "end_line": chunk.end_line,
            "node_type": chunk.node_type,
            "char_count": chunk.char_count,
            "prompt_chars": len(chunk_prompt),
            "runs": [],
            "majority_verdict": None,
            "agreement_rate": None,
        }

        for r in range(repeat):
            print(f"    [{r+1}/{repeat}] 推理中...", end="", flush=True)
            result = client.generate(
                prompt=chunk_prompt,
                temperature=temperature,
                max_tokens=None,
                keep_alive=-1,
                timeout=timeout,
            )
            elapsed = round(result["duration"], 2)
            print(f" 用时 {elapsed}s", end="")

            run_record = {
                "run_index": r + 1,
                "chunk_id": chunk.chunk_id,
                "chunk_name": chunk.name,
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

            chunk_record["runs"].append(run_record)
            # 平铺到 sample 级别 runs，便于统计函数复用
            sample_record["runs"].append({
                "run_index": len(sample_record["runs"]) + 1,
                "chunk_id": chunk.chunk_id,
                "chunk_name": chunk.name,
                "elapsed_seconds": elapsed,
                "raw_output": run_record["raw_output"],
                "parsed_verdict": run_record["parsed_verdict"],
                "model_has_vulnerability": run_record["model_has_vulnerability"],
                "error": run_record["error"],
            })

        # chunk 内多数表决
        verdicts = [r.get("model_has_vulnerability") for r in chunk_record["runs"]]
        valid = [v for v in verdicts if v is not None]
        if valid:
            true_count = sum(1 for v in valid if v)
            chunk_record["majority_verdict"] = true_count >= len(valid) / 2
            chunk_record["agreement_rate"] = round(
                max(true_count, len(valid) - true_count) / len(valid), 4
            )
            overall_valid_chunks += 1
            if chunk_record["majority_verdict"]:
                overall_true_count += 1

        sample_record["chunks"].append(chunk_record)

    # 整体合并：任一 chunk True → 整体 True（保守策略）
    if overall_valid_chunks > 0:
        sample_record["majority_verdict"] = overall_true_count > 0
        sample_record["agreement_rate"] = round(overall_true_count / overall_valid_chunks, 4)
        # 记录哪些 chunk 判了 True
        true_chunks = [c["name"] for c in sample_record["chunks"]
                       if c.get("majority_verdict") is True]
        sample_record["true_chunks"] = true_chunks
        print(f"  [合并] {overall_true_count}/{overall_valid_chunks} chunk 判 True → 整体 {sample_record['majority_verdict']}", flush=True)
        if true_chunks:
            print(f"  [触发] 判 True 的 chunks: {true_chunks}", flush=True)

    return sample_record


if __name__ == "__main__":
    raise SystemExit(main())
