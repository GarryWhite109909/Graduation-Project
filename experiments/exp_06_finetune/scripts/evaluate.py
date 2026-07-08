"""
微调效果评估脚本 —— 在 exp_04 87 段测试集上对比微调前后模型表现。

支持两种模式：
  --mode baseline   评估未微调的 Qwen2.5-Coder-3B-Instruct（对照组）
  --mode finetuned  评估加载了 LoRA adapter 的微调模型

P0 改造（glm 建议）：
  - 默认 temperature=0.0, do_sample=False（确定性解码），消除采样随机性
  - --seeds N 跑 N 个种子取均值±标准差（多种子显著性检验）
  - --checkpoint 指定评估哪个 checkpoint（checkpoint-36 / checkpoint-45 / final）

用法（在 AI conda 环境中运行，需 GPU）：
  # 评估基座（对照组，确定性解码）
  /home/zane/miniconda3/envs/AI/bin/python evaluate.py --mode baseline

  # 评估微调后（默认 final adapter，确定性解码）
  /home/zane/miniconda3/envs/AI/bin/python evaluate.py --mode finetuned

  # 对比 checkpoint-36 vs checkpoint-45 vs final，各跑 3 个种子
  /home/zane/miniconda3/envs/AI/bin/python evaluate.py --mode finetuned \
      --checkpoint checkpoint-36 --seeds 3
  /home/zane/miniconda3/envs/AI/bin/python evaluate.py --mode finetuned \
      --checkpoint checkpoint-45 --seeds 3
  /home/zane/miniconda3/envs/AI/bin/python evaluate.py --mode finetuned \
      --checkpoint final --seeds 3
"""

import argparse
import json
import os
import statistics
import sys
import time
from pathlib import Path

# ROCm 多设备保护：在 import torch 前强制只用 GPU 0
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0")
os.environ.setdefault("HIP_VISIBLE_DEVICES", "0")

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import SYSTEM_PROMPT, build_user_prompt
from graduation_project.schema import parse_verdict, normalize_has_vulnerability
from experiments.utils import (
    load_manifest, read_sample_code, compute_detection_metrics,
    compute_repeat_metrics, save_results_json,
)

MODEL_ID = "Qwen/Qwen2.5-Coder-3B-Instruct"  # 与训练脚本一致
MANIFEST_PATH = PROJECT_ROOT / "experiments/exp_04_hard_samples/samples/manifest.json"
SAMPLES_DIR = PROJECT_ROOT / "experiments/exp_04_hard_samples/samples"
OUTPUT_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/results"
# 默认 LoRA 输出根目录，用于 --checkpoint 简写解析
DEFAULT_LORA_ROOT = PROJECT_ROOT / "experiments/exp_06_finetune/outputs/lora_r16_a32_e2_s42/best"


def resolve_adapter_path(checkpoint: str | None, adapter_path: str | None) -> str | None:
    """把 --checkpoint 简写（如 checkpoint-36）解析为完整路径。

    优先级：--adapter-path 显式路径 > --checkpoint 简写 > None
    """
    if adapter_path:
        return adapter_path
    if checkpoint:
        # checkpoint=final → .../lora_r16_a32_e3/final
        # checkpoint=checkpoint-36 → .../lora_r16_a32_e3/checkpoint-36
        return str(DEFAULT_LORA_ROOT / checkpoint)
    return None


def load_model(mode: str, adapter_path: str | None, quantize_4bit: bool):
    """加载模型 + tokenizer。"""
    print(f"加载 tokenizer: {MODEL_ID}")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    dtype = torch.float16
    print(f"加载模型: {MODEL_ID} (mode={mode})")
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_ID,
        device_map={"": 0},
        trust_remote_code=True,
        torch_dtype=dtype,
        attn_implementation="sdpa",  # 推理用 sdpa 比 eager 快很多
    )

    if mode == "finetuned" and adapter_path:
        print(f"加载 LoRA adapter: {adapter_path}")
        model = PeftModel.from_pretrained(model, adapter_path)
        model = model.merge_and_unload()  # 合并 LoRA 权重加速推理
        print("LoRA 已合并")

    model.eval()
    return model, tokenizer


def generate_response(
    model, tokenizer, messages,
    max_new_tokens=1024,
    temperature=0.0,
    do_sample=False,
) -> str:
    """用 ChatML 模板生成回复。

    P0 改造：默认 temperature=0.0, do_sample=False（确定性贪心解码），
    消除采样随机性，使评估结果可复现。多种子评估通过 --seeds 重复跑实现。

    max_new_tokens=1024：与 exp_04 Ollama 实测对齐（7B 模型在部分样本上需要 500-650
    token 才能写完分析+JSON，384 会截断 JSON 导致 parse_fail）。

    若 do_sample=True，需配合 temperature>0 / top_p，否则回退到贪心。
    """
    text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(text, return_tensors="pt").to(model.device)
    gen_kwargs = {
        "max_new_tokens": max_new_tokens,
        "pad_token_id": tokenizer.pad_token_id,
    }
    if do_sample and temperature > 0:
        gen_kwargs["do_sample"] = True
        gen_kwargs["temperature"] = temperature
        gen_kwargs["top_p"] = 0.9
    else:
        gen_kwargs["do_sample"] = False  # 确定性贪心解码
    with torch.no_grad():
        outputs = model.generate(**inputs, **gen_kwargs)
    # 只取新生成的部分
    input_len = inputs["input_ids"].shape[1]
    response = tokenizer.decode(outputs[0][input_len:], skip_special_tokens=True)
    return response


def evaluate(model, tokenizer, samples, manifest_records,
             temperature=0.0, do_sample=False, run_seed=0, samples_dir=None):
    """在样本集上评估，返回结果列表。

    P0 改造：接受 temperature / do_sample / run_seed 参数。
    run_seed 用于在多种子评估时设置 torch 随机种子（仅对 do_sample=True 有效）。
    """
    if do_sample and run_seed:
        torch.manual_seed(run_seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(run_seed)

    results = []
    for i, rec in enumerate(manifest_records):
        filename = rec["file"]
        language = rec["language"]
        expected_present = rec["expected_present"]

        # 读取代码
        code_samples_dir = samples_dir if samples_dir is not None else SAMPLES_DIR
        code = read_sample_code(code_samples_dir, filename)
        if code is None:
            print(f"[{i+1}/{len(manifest_records)}] 跳过 {filename}（代码不存在）")
            continue

        # 跨文件样本处理
        if "crossfile" in filename and filename.endswith("_sink.py"):
            input_file = filename.replace("_sink.py", "_input.py")
            input_code = read_sample_code(code_samples_dir, input_file)
            if input_code:
                code = f"# 配套输入层文件 {input_file}\n{input_code}\n\n# 当前 sink 文件\n{code}"

        # 构造消息
        user_prompt = build_user_prompt(code=code, language=language, filename=filename)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        # 推理
        t0 = time.time()
        try:
            raw_output = generate_response(
                model, tokenizer, messages,
                temperature=temperature, do_sample=do_sample,
            )
            elapsed = time.time() - t0
            verdict = parse_verdict(raw_output)
            predicted = normalize_has_vulnerability(verdict.get("has_vulnerability") if verdict else None)
        except Exception as e:
            elapsed = time.time() - t0
            raw_output = f"ERROR: {e}"
            verdict = None
            predicted = None

        # 判定
        if predicted is None:
            outcome = "parse_fail"
        elif predicted == expected_present:
            outcome = "TP" if expected_present else "TN"
        else:
            outcome = "FP" if not expected_present else "FN"

        result = {
            "file": filename,
            "language": language,
            "category": rec.get("category", ""),
            "difficulty": rec.get("difficulty", ""),
            "expected_present": expected_present,
            "model_has_vulnerability": predicted,  # 与 utils.compute_detection_metrics 默认字段对齐
            "predicted": predicted,  # 保留兼容字段
            "outcome": outcome,
            "expected_vulnerability": rec.get("expected_vulnerability", ""),
            "expected_cwe": rec.get("expected_cwe", ""),
            "raw_output": raw_output,
            "elapsed_seconds": round(elapsed, 2),  # 与 utils 期望字段对齐
            "elapsed": round(elapsed, 2),
            "run_seed": run_seed,  # 标记本次评估的种子（多种子聚合用）
        }
        results.append(result)
        print(f"[{i+1}/{len(manifest_records)}] {filename} → {outcome} ({elapsed:.1f}s)", flush=True)

    return results


def aggregate_multiseed(all_runs: list[list[dict]]) -> dict:
    """聚合多种子评估结果，返回每个种子的单次指标 + 总体均值±标准差。

    all_runs: 每个 run 是一次完整 evaluate() 的结果列表。
    返回:
        {
            "per_seed": [{seed, metrics}, ...],
            "mean": {recall, accuracy, fpr},
            "std":  {recall, accuracy, fpr},
        }
    """
    per_seed = []
    recall_list, acc_list, fpr_list = [], [], []
    for run_results in all_runs:
        m = compute_detection_metrics(run_results)
        seed = run_results[0].get("run_seed", 0) if run_results else 0
        per_seed.append({"seed": seed, "metrics": m})
        if m["recall"] is not None:
            recall_list.append(m["recall"])
        if m["accuracy"] is not None:
            acc_list.append(m["accuracy"])
        if m["false_positive_rate"] is not None:
            fpr_list.append(m["false_positive_rate"])

    def stats(vals):
        if not vals:
            return None
        if len(vals) == 1:
            return {"mean": round(vals[0], 4), "std": 0.0}
        return {"mean": round(statistics.mean(vals), 4),
                "std": round(statistics.stdev(vals), 4)}

    return {
        "per_seed": per_seed,
        "mean_recall": stats(recall_list),
        "mean_accuracy": stats(acc_list),
        "mean_fpr": stats(fpr_list),
    }


def main():
    parser = argparse.ArgumentParser(description="评估微调前后模型")
    parser.add_argument("--mode", choices=["baseline", "finetuned"], required=True)
    parser.add_argument("--adapter-path", type=str, default=None,
                        help="LoRA adapter 路径（finetuned 模式必填，与 --checkpoint 二选一）")
    parser.add_argument("--checkpoint", type=str, default=None,
                        help="checkpoint 简写：checkpoint-36 / checkpoint-45 / final（自动解析路径）")
    parser.add_argument("--quantize-4bit", action="store_true", help="用 4bit 量化加载（省显存）")
    parser.add_argument("--limit", type=int, default=0, help="只评估前 N 个样本（0=全部）")
    parser.add_argument("--manifest-path", type=str, default=None,
                        help="指定测试集 manifest 路径（默认 exp_04_hard_samples，可改为 CVE-fix）")
    parser.add_argument("--samples-dir", type=str, default=None,
                        help="指定代码样本目录（默认与 manifest 同目录）")
    # P0 改造：确定性解码 + 多种子
    parser.add_argument("--temperature", type=float, default=0.0,
                        help="采样温度（默认 0.0 确定性贪心解码）")
    parser.add_argument("--do-sample", action="store_true",
                        help="启用采样（默认 False 确定性；启用时需 temperature>0）")
    parser.add_argument("--seeds", type=int, default=1,
                        help="跑 N 个种子取均值±标准差（默认 1；>1 时自动启用 do_sample）")
    args = parser.parse_args()

    # 解析 adapter 路径
    adapter_path = resolve_adapter_path(args.checkpoint, args.adapter_path)
    if args.mode == "finetuned" and not adapter_path:
        print("错误：finetuned 模式需要 --adapter-path 或 --checkpoint")
        sys.exit(1)
    if args.mode == "finetuned" and not Path(adapter_path).exists():
        print(f"错误：adapter 路径不存在: {adapter_path}")
        sys.exit(1)

    # 多种子评估时强制启用采样（确定性解码下多种子无意义）
    do_sample = args.do_sample
    if args.seeds > 1:
        do_sample = True
        if args.temperature == 0.0:
            args.temperature = 0.1  # 多种子需要采样，默认 0.1
        print(f"多种子评估({args.seeds})：自动启用 do_sample, temperature={args.temperature}")

    # 检查 GPU
    if not torch.cuda.is_available():
        print("错误：未检测到 GPU。请在真实终端运行（非 IDE 沙箱）。")
        sys.exit(1)

    # 加载测试集（支持自定义 manifest 路径，用于 CVE-fix held-out 测试集）
    manifest_path = Path(args.manifest_path) if args.manifest_path else MANIFEST_PATH
    samples_dir = Path(args.samples_dir) if args.samples_dir else None
    print(f"测试集 manifest: {manifest_path}")
    manifest, records = load_manifest(manifest_path)
    if args.limit > 0:
        records = records[:args.limit]
    print(f"测试样本: {len(records)} 段")

    # 加载模型
    model, tokenizer = load_model(args.mode, adapter_path, args.quantize_4bit)

    # 多种子评估
    all_runs = []
    seed_list = [42 + i * 1000 for i in range(args.seeds)]  # 42, 1042, 2042 ...
    print(f"\n开始评估（mode={args.mode}, seeds={seed_list}, do_sample={do_sample}, temp={args.temperature}）...")
    for run_idx, seed in enumerate(seed_list):
        print(f"\n===== Run {run_idx+1}/{args.seeds} (seed={seed}) =====")
        run_results = evaluate(
            model, tokenizer, None, records,
            temperature=args.temperature, do_sample=do_sample, run_seed=seed,
            samples_dir=samples_dir,
        )
        all_runs.append(run_results)

    # 用第一个 run 的结果作为"代表"保存（单种子时就是唯一结果）
    representative_results = all_runs[0]
    metrics = compute_detection_metrics(representative_results)
    print("\n=== 单次指标（run 1, seed={}）===".format(seed_list[0]))
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    # 多种子聚合
    multi_summary = None
    if args.seeds > 1:
        multi_summary = aggregate_multiseed(all_runs)
        print("\n=== 多种子聚合（{} seeds）===".format(args.seeds))
        for ps in multi_summary["per_seed"]:
            m = ps["metrics"]
            print(f"  seed={ps['seed']}: recall={m['recall']}, accuracy={m['accuracy']}, fpr={m['false_positive_rate']}")
        print(f"  recall   均值±std: {multi_summary['mean_recall']}")
        print(f"  accuracy 均值±std: {multi_summary['mean_accuracy']}")
        print(f"  fpr      均值±std: {multi_summary['mean_fpr']}")

    # 保存结果
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    tag = args.mode
    if args.mode == "finetuned":
        ck_tag = args.checkpoint or "custom"
        tag = f"finetuned_{ck_tag}"
    if args.seeds > 1:
        tag += f"_seeds{args.seeds}"
    out_file = OUTPUT_DIR / f"exp_06_eval.{tag}.{ts}.json"
    save_results_json(
        out_file,
        {
            "experiment": "exp_06_finetune_eval",
            "model": f"qwen2.5-coder-3b-instruct-{args.mode}",
            "checkpoint": args.checkpoint or (args.adapter_path or ""),
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "decoding": {"temperature": args.temperature, "do_sample": do_sample, "seeds": seed_list},
            "samples": representative_results,
            "all_runs": all_runs if args.seeds > 1 else None,
            "metrics": metrics,
            "multiseed_summary": multi_summary,
        },
    )
    print(f"\n结果已保存: {out_file}")

    # 打印混淆矩阵（基于第一个 run）
    tp = sum(1 for r in representative_results if r["outcome"] == "TP")
    fp = sum(1 for r in representative_results if r["outcome"] == "FP")
    fn = sum(1 for r in representative_results if r["outcome"] == "FN")
    tn = sum(1 for r in representative_results if r["outcome"] == "TN")
    pf = sum(1 for r in representative_results if r["outcome"] == "parse_fail")
    print(f"\n混淆矩阵(run1): TP={tp} FP={fp} FN={fn} TN={tn} (parse_fail={pf})")


if __name__ == "__main__":
    main()
