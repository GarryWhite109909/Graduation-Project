"""
exp_05_prompt_ablation - Prompt 工程消融对比

在 qwen2.5-coder:7b 上系统对比 5 种 Prompt 策略对漏洞检测召回与误报的影响：
  1. zero_shot      当前完整版 SYSTEM_PROMPT（含白名单+硬编码规则+多条要求+schema）
  2. whitelist_only 仅角色 + SAFE_PATTERN_WHITELIST + schema（去掉其他规则）
  3. few_shot       在 zero_shot 基础上加 3 组示例（漏洞/安全/漏洞）
  4. cot            在 zero_shot 基础上显式要求按 5 步思维链分析
  5. combined       zero_shot + few_shot + cot 三合一

复用 exp_04_hard_samples 的 87 段样本（含典型/安全/难/噪音），保证横向对比公平。
跨文件样本自动注入对应 _input.py 作为上下文（与 exp_04 一致）。

用法:
    python run_ablation.py                                   # 默认跑全部 5 变体 × 87 样本
    python run_ablation.py --variants zero_shot,cot          # 只跑指定变体
    python run_ablation.py --limit 5                         # 只跑前 5 个样本（调试）
    python run_ablation.py --repeat 3                        # 每变体每样本重复 3 次（多数表决）
    python run_ablation.py --filter safe                     # 只跑文件名含 safe 的样本
    python run_ablation.py --resume                          # 断点续跑
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
from graduation_project.prompts import (
    PROMPT_VARIANTS,
    build_user_prompt,
    build_system_prompt_variant,
)
from graduation_project.schema import parse_verdict, normalize_has_vulnerability
from experiments.utils import (
    load_manifest,
    read_sample_code,
    save_results_json,
    new_results_envelope,
    compute_detection_metrics,
    compute_repeat_metrics,
    print_summary,
    print_repeat_summary,
    default_results_path,
)


def upsert_sample_variant(samples_list: list[dict], sample_record: dict) -> None:
    """按 (variant, file) 联合 key upsert 样本记录。

    与通用 upsert_sample 不同：本实验同一 file 会有 5 个变体的记录，
    不能只按 file 替换，否则前一个变体的记录会被后一个变体覆盖。
    """
    key_variant = sample_record.get("variant")
    key_file = sample_record.get("file")
    for i, s in enumerate(samples_list):
        if s.get("variant") == key_variant and s.get("file") == key_file:
            samples_list[i] = sample_record
            return
    samples_list.append(sample_record)

# ---------------------------------------------------------------------------
# 路径常量
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
# 复用 exp_04 的样本集，保证与难样本实验对比公平
SAMPLES_DIR = SCRIPT_DIR.parent / "exp_04_hard_samples" / "samples"
MANIFEST_PATH = SAMPLES_DIR / "manifest.json"
RESULTS_DIR = SCRIPT_DIR / "results"


# ---------------------------------------------------------------------------
# 跨文件样本处理（与 exp_04 一致）
# ---------------------------------------------------------------------------
def _crossfile_pair(sink_filename: str) -> str | None:
    """根据 sink 文件名推断对应的 input 文件名。无配对返回 None。"""
    m = re.match(r"^(hard_crossfile_\d+)_sink\.(py|js|java|php)$", sink_filename)
    if m:
        return f"{m.group(1)}_input.{m.group(2)}"
    return None


def build_user_prompt_for_sample(samples_dir: Path, sample_meta: dict) -> str:
    """为单个样本构建 user prompt，自动处理跨文件样本。

    返回 user prompt 字符串（不含 system prompt，system prompt 由变体决定）。
    若样本文件不存在返回 None。
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
            code = (
                f"# === 相关代码上下文（同项目另一文件：{pair}） ===\n"
                f"{input_code}\n\n"
                f"# === 待分析的目标文件：{filename} ===\n"
                f"{code}"
            )
            print(f"        [跨文件] 注入相关上下文 {pair}（{len(input_code)} 字符）")

    return build_user_prompt(code=code, language=language, filename=filename)


# ---------------------------------------------------------------------------
# 单变体单样本执行
# ---------------------------------------------------------------------------
def run_sample_with_variant(
    client: OllamaClient,
    variant: str,
    system_prompt: str,
    user_prompt: str,
    sample_meta: dict,
    repeat: int,
    temperature: float,
    timeout: int,
    idx: int,
    total: int,
) -> dict:
    """对单个样本用指定变体跑 N 次，多数表决。"""
    filename = sample_meta["file"]
    language = sample_meta.get("language", "text")
    print(f"\n[{idx}/{total}] [{variant}] {filename} ({language}, expected_present={sample_meta['expected_present']})", flush=True)

    full_prompt = system_prompt + "\n\n" + user_prompt

    sample_record = {
        "file": filename,
        "language": language,
        "category": sample_meta.get("category"),
        "difficulty": sample_meta.get("difficulty"),
        "expected_present": sample_meta.get("expected_present"),
        "expected_vulnerability": sample_meta.get("expected_vulnerability"),
        "expected_cwe": sample_meta.get("expected_cwe"),
        "expected_risk_level": sample_meta.get("expected_risk_level"),
        "variant": variant,
        "prompt_chars": len(full_prompt),
        "system_prompt_chars": len(system_prompt),
        "user_prompt_chars": len(user_prompt),
        "runs": [],
        "majority_verdict": None,
        "agreement_rate": None,
    }

    for r in range(repeat):
        print(f"  [{variant} {r+1}/{repeat}] 推理中...", end="", flush=True)
        result = client.generate(
            prompt=user_prompt,
            system_prompt=system_prompt,
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
# 主流程
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="exp_05 Prompt 工程消融对比")
    parser.add_argument("--host", default="http://localhost:11434",
                        help="Ollama 服务地址（默认 http://localhost:11434）")
    parser.add_argument("--model", default="qwen2.5-coder:7b",
                        help="Ollama 模型名（默认 qwen2.5-coder:7b）")
    parser.add_argument("--temperature", type=float, default=0.1,
                        help="采样温度（默认 0.1）")
    parser.add_argument("--limit", type=int, default=0,
                        help="只跑前 N 个样本，0 表示全部")
    parser.add_argument("--repeat", type=int, default=1,
                        help="每变体每样本重复 N 次（默认 1，快速验证；3 用于多数表决与置信区间）")
    parser.add_argument("--timeout", type=int, default=900,
                        help="单次请求超时秒数（默认 900）")
    parser.add_argument("--keep-loaded", action="store_true",
                        help="跑完后保持模型在显存中（默认卸载）")
    parser.add_argument("--variants", default=",".join(PROMPT_VARIANTS),
                        help=f"逗号分隔的变体名，默认全部（{','.join(PROMPT_VARIANTS)}）")
    parser.add_argument("--filter", default=None,
                        help="只跑文件名包含此子串的样本（如 --filter safe）")
    parser.add_argument("--resume", action="store_true",
                        help="断点续跑：加载已有结果，跳过已完成的 (variant,file) 组合")
    parser.add_argument("--output", default=None,
                        help="结果输出路径（默认自动生成）")
    args = parser.parse_args()

    # 解析变体列表
    variants = [v.strip() for v in args.variants.split(",") if v.strip()]
    for v in variants:
        if v not in PROMPT_VARIANTS:
            print(f"[错误] 未知变体: {v}（合法值: {PROMPT_VARIANTS}）", file=sys.stderr)
            return 1
    if not variants:
        print("[错误] 至少指定一个变体", file=sys.stderr)
        return 1

    repeat = max(1, args.repeat)
    extra_tag = f"ablation.repeat{repeat}"
    results_path = Path(args.output) if args.output else default_results_path(
        RESULTS_DIR,
        experiment="exp_05_prompt_ablation",
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

    total_samples = len(samples)
    total_runs = total_samples * len(variants) * repeat
    print(f"[信息] 共 {total_samples} 个样本 × {len(variants)} 个变体 × {repeat} 次 = {total_runs} 次推理")
    print(f"[信息] 模型 {args.model}，host {args.host}，温度 {args.temperature}")
    print(f"[信息] 变体: {variants}")
    print(f"[信息] 预计耗时约 {total_runs * 8 / 60:.1f} 分钟（按 8s/次估算）")

    client = OllamaClient(base_url=args.host, model=args.model)
    if not client.check_connection():
        print(f"[错误] 无法连接 Ollama（{args.host}），请先运行 ollama serve", file=sys.stderr)
        return 1

    # 预构建每个变体的 system prompt（避免循环内重复构建）
    variant_system_prompts = {v: build_system_prompt_variant(v) for v in variants}
    print("\n[信息] 变体 system prompt 长度:")
    for v, sp in variant_system_prompts.items():
        print(f"  {v:15s}: {len(sp):5d} 字符")

    # --resume: 加载已有结果
    if args.resume and results_path.exists():
        import json as _json
        results = _json.loads(results_path.read_text(encoding="utf-8"))
        existing_samples = results.get("samples", [])
        finished_keys = {
            (s.get("variant"), s.get("file"))
            for s in existing_samples
            if s.get("majority_verdict") is not None
        }
        print(f"[信息] --resume: 已完成 {len(finished_keys)} 个 (variant,file) 组合")
        results["samples"] = existing_samples
        results["resumed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        results["resumed_from"] = str(results_path)
    else:
        results = new_results_envelope(
            experiment="exp_05_prompt_ablation",
            model=args.model,
            host=args.host,
            temperature=args.temperature,
            repeat=repeat,
            variants=variants,
            sample_count=total_samples,
            total_runs=total_runs,
            samples_source=str(SAMPLES_DIR.relative_to(SCRIPT_DIR.parent)),
        )

    # 主循环：外层变体，内层样本（便于 --resume 按变体粒度续跑）
    run_idx = 0
    for variant in variants:
        system_prompt = variant_system_prompts[variant]
        print(f"\n{'='*60}\n[变体] {variant}（system prompt {len(system_prompt)} 字符）\n{'='*60}")

        for idx, sample_meta in enumerate(samples, 1):
            filename = sample_meta["file"]

            # --resume 跳过已完成
            if args.resume and (variant, filename) in finished_keys:
                run_idx += 1
                print(f"[{run_idx}/{total_runs}] [{variant}] {filename} 已完成，跳过")
                continue
            run_idx += 1

            user_prompt = build_user_prompt_for_sample(SAMPLES_DIR, sample_meta)
            if user_prompt is None:
                continue

            sample_record = run_sample_with_variant(
                client=client,
                variant=variant,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                sample_meta=sample_meta,
                repeat=repeat,
                temperature=args.temperature,
                timeout=args.timeout,
                idx=idx,
                total=total_samples,
            )
            upsert_sample_variant(results["samples"], sample_record)
            save_results_json(results_path, results)

    results["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    # 统计指标：按变体分组
    metrics_by_variant = {}
    for variant in variants:
        variant_records = []
        for s in results["samples"]:
            if s.get("variant") != variant:
                continue
            for run in s.get("runs", []):
                variant_records.append({
                    "file": s["file"],
                    "expected_present": s["expected_present"],
                    "model_has_vulnerability": run.get("model_has_vulnerability"),
                    "elapsed_seconds": run.get("elapsed_seconds"),
                })
        if not variant_records:
            continue
        single = compute_detection_metrics(variant_records)
        repeat_metrics = compute_repeat_metrics(variant_records)
        metrics_by_variant[variant] = {
            "metrics_single_run": single,
            "metrics_majority_vote": repeat_metrics,
        }

    results["metrics_by_variant"] = metrics_by_variant
    save_results_json(results_path, results)

    print(f"\n[完成] 结果已写入 {results_path}")
    for variant in variants:
        if variant not in metrics_by_variant:
            continue
        print(f"\n{'='*60}\n[变体] {variant}\n{'='*60}")
        print("=== 单次实验口径指标（所有 run 拉平）===")
        print_summary(metrics_by_variant[variant]["metrics_single_run"])
        print("\n=== 多数表决口径指标（含 95% 置信区间）===")
        print_repeat_summary(metrics_by_variant[variant]["metrics_majority_vote"])

    # 卸载模型
    if args.keep_loaded:
        print(f"\n[信息] --keep-loaded 已启用，模型 {args.model} 保留在显存中")
    else:
        if client.unload_model():
            print(f"[信息] 模型 {args.model} 已从显存卸载（如需保留请加 --keep-loaded）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
