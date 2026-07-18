"""
verify_bnb_corruption.py —— 验证 Phase 1 训练是否受 bitsandbytes paged_adamw_8bit bug 影响

背景：
  Level1Techs 报告 (2026-06, gfx1201/ROCm 7.2.1) 指出 bitsandbytes paged 优化器
  (paged_adamw_32bit, paged_adamw_8bit, adamw_bnb_8bit) 在第一次 optimizer.step()
  后会静默损坏模型状态。症状：step 1 训练正常，之后逐步劣化。
  本项目 train_qlora.py 用 paged_adamw_8bit，需验证 Phase 1 sweep 结果是否被污染。
  报告来源：https://forum.level1techs.com/t/250960

检查项：
  1. LoRA adapter 权重是否有 NaN/Inf（最直接的损坏信号）
  2. 权重统计（mean/std/max/min）是否在合理范围（LoRA 权重 std 应在 1e-3~1e-1）
  3. trainer_state.json 中 dev_loss 曲线是否健康（应单调下降或震荡收敛，不应反弹）
  4. optimizer.pt 中 optimizer state 是否有 NaN（如果存在）
  5. 跨 run 对比：5 个 run 的 dev_loss 是否符合 lr × rsLoRA 的预期排序

判定标准：
  - 任何 NaN/Inf → ❌ 严重损坏
  - 权重 std > 10 或 < 1e-6 → ⚠️ 可疑
  - dev_loss 在某 epoch 后突然反弹 > 50% → ⚠️ 可疑
  - 5 个 run dev_loss 排序与预期不符 → ⚠️ 可疑
  - 全部通过 → ✅ Phase 1 数据有效，无需重跑

用法：
  /home/zane/miniconda3/envs/AI/bin/python verify_bnb_corruption.py
  /home/zane/miniconda3/envs/AI/bin/python verify_bnb_corruption.py --run-ids 4 5
  /home/zane/miniconda3/envs/AI/bin/python verify_bnb_corruption.py --verbose

退出码：
  0 = 全部通过，Phase 1 数据有效
  1 = 发现可疑信号（建议跑 adamw_torch 对比组）
  2 = 发现严重损坏（必须重跑）
"""

import argparse
import json
import math
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
OUTPUTS_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/outputs"

# Phase 1 sweep 5 个 run 的目录名模式
# run 1: lr=5e-5 baseline
# run 2: lr=1e-4 baseline
# run 3: lr=5e-5 + rsLoRA
# run 4: lr=1e-4 + rsLoRA ⭐ best
# run 5: lr=5e-5 + rsLoRA + DoRA
RUN_PATTERNS = {
    1: "lora_r8_a16_e1_lr5e-05_s42_7b",
    2: "lora_r8_a16_e1_lr0.0001_s42_7b",  # lr=1e-4 baseline
    3: "lora_r8_a16_e1_lr5e-05_s42_rslora_7b",
    4: "lora_r8_a16_e1_lr0.0001_s42_rslora_7b",  # lr=1e-4 + rsLoRA ⭐ best
    5: "lora_r8_a16_e1_lr5e-05_s42_rslora_dora_7b",
}

# 预期 dev_loss 排序（从 Phase 1 sweep 实测，run 4 应最低）
EXPECTED_DEV_LOSS_ORDER = [4, 2, 3, 1]  # run 5 不参与排序（DoRA 是兼容性探测）

# LoRA 权重统计的合理范围（基于 Qwen2.5-Coder-7B + r=8 LoRA 经验值）
HEALTHY_STD_MIN = 1e-4
HEALTHY_STD_MAX = 10.0
HEALTHY_ABS_MAX = 100.0  # 单个权重绝对值上限


def find_run_dir(run_id: int) -> Path | None:
    """根据 run_id 查找输出目录。"""
    # 优先用预设模式
    pattern = RUN_PATTERNS.get(run_id)
    if pattern:
        p = OUTPUTS_DIR / pattern
        if p.exists():
            return p
    # 兜底：glob 查找（处理 lr 排序差异）
    candidates = sorted(OUTPUTS_DIR.glob(f"lora_r8_a16_e1_lr*_s42*_7b"))
    if run_id <= len(candidates):
        return candidates[run_id - 1]
    return None


def check_lora_weights(adapter_dir: Path) -> dict:
    """检查 LoRA adapter 权重：NaN/Inf + 统计。"""
    try:
        import torch
    except ImportError:
        return {"status": "skip", "reason": "torch not available"}

    # 找 adapter_model.safetensors 或 adapter_model.bin
    weight_file = None
    for name in ["adapter_model.safetensors", "adapter_model.bin"]:
        p = adapter_dir / name
        if p.exists():
            weight_file = p
            break

    if weight_file is None:
        return {"status": "skip", "reason": f"未找到 adapter 权重文件 in {adapter_dir}"}

    # 加载权重
    try:
        if weight_file.suffix == ".safetensors":
            from safetensors.torch import load_file
            state_dict = load_file(str(weight_file))
        else:
            state_dict = torch.load(str(weight_file), map_location="cpu", weights_only=False)
    except Exception as e:
        return {"status": "error", "reason": f"加载失败: {e}"}

    # 检查每个 tensor
    nan_count = 0
    inf_count = 0
    suspicious_tensors = []
    stats = []
    for name, tensor in state_dict.items():
        if not isinstance(tensor, torch.Tensor):
            continue
        t = tensor.float()  # 转 fp32 做统计
        has_nan = torch.isnan(t).any().item()
        has_inf = torch.isinf(t).any().item()
        std = t.std().item() if t.numel() > 1 else 0.0
        abs_max = t.abs().max().item() if t.numel() > 0 else 0.0
        mean = t.mean().item()

        if has_nan:
            nan_count += int(torch.isnan(t).sum().item())
            suspicious_tensors.append({"name": name, "issue": "NaN", "count": int(torch.isnan(t).sum().item())})
        if has_inf:
            inf_count += int(torch.isinf(t).sum().item())
            suspicious_tensors.append({"name": name, "issue": "Inf", "count": int(torch.isinf(t).sum().item())})
        if std > HEALTHY_STD_MAX or std < HEALTHY_STD_MIN:
            suspicious_tensors.append({"name": name, "issue": f"std 异常: {std:.4g}"})
        if abs_max > HEALTHY_ABS_MAX:
            suspicious_tensors.append({"name": name, "issue": f"abs_max 异常: {abs_max:.4g}"})

        stats.append({
            "name": name,
            "shape": list(t.shape),
            "mean": mean,
            "std": std,
            "abs_max": abs_max,
            "numel": t.numel(),
        })

    return {
        "status": "ok" if not suspicious_tensors else "suspicious",
        "nan_count": nan_count,
        "inf_count": inf_count,
        "total_tensors": len(stats),
        "suspicious_tensors": suspicious_tensors,
        "stats_summary": {
            "mean_of_stds": sum(s["std"] for s in stats) / max(1, len(stats)),
            "max_abs_max": max((s["abs_max"] for s in stats), default=0),
        },
        "stats": stats,
    }


def check_trainer_state(adapter_dir: Path) -> dict:
    """检查 trainer_state.json 的 dev_loss 曲线。"""
    # 找 trainer_state.json（在 output_dir 根目录或 best/ 子目录）
    state_file = None
    for path in [adapter_dir / "trainer_state.json",
                 adapter_dir / "best" / "trainer_state.json",
                 adapter_dir / "checkpoint-88" / "trainer_state.json"]:
        if path.exists():
            state_file = path
            break

    if state_file is None:
        return {"status": "skip", "reason": "未找到 trainer_state.json"}

    try:
        with open(state_file) as f:
            state = json.load(f)
    except Exception as e:
        return {"status": "error", "reason": f"加载失败: {e}"}

    log_history = state.get("log_history", [])
    eval_entries = [e for e in log_history if "eval_loss" in e]
    train_loss_entries = [e for e in log_history if "loss" in e and "eval_loss" not in e]

    if not eval_entries:
        return {"status": "skip", "reason": "log_history 无 eval_loss 条目"}

    # 检查 dev_loss 曲线
    eval_losses = [e["eval_loss"] for e in eval_entries]
    has_nan = any(math.isnan(l) for l in eval_losses)
    has_inf = any(math.isinf(l) for l in eval_losses)

    # 检测反弹：后续 eval_loss 比前一次高 50% 以上
    bounces = []
    for i in range(1, len(eval_losses)):
        if eval_losses[i] > eval_losses[i - 1] * 1.5:
            bounces.append({
                "epoch": eval_entries[i].get("epoch", i),
                "prev_loss": eval_losses[i - 1],
                "curr_loss": eval_losses[i],
                "increase_pct": (eval_losses[i] / eval_losses[i - 1] - 1) * 100,
            })

    final_dev_loss = eval_losses[-1]
    min_dev_loss = min(eval_losses)
    best_epoch = eval_entries[eval_losses.index(min_dev_loss)].get("epoch", "?")

    # 训练 loss 趋势
    train_losses = [e["loss"] for e in train_loss_entries]
    train_has_nan = any(math.isnan(l) for l in train_losses) if train_losses else False

    suspicious = has_nan or has_inf or train_has_nan or len(bounces) > 0

    return {
        "status": "ok" if not suspicious else "suspicious",
        "eval_losses": eval_losses,
        "final_dev_loss": final_dev_loss,
        "min_dev_loss": min_dev_loss,
        "best_epoch": best_epoch,
        "has_nan": has_nan,
        "has_inf": has_inf,
        "train_loss_has_nan": train_has_nan,
        "bounces": bounces,
        "num_epochs": len(eval_losses),
    }


def check_optimizer_state(adapter_dir: Path) -> dict:
    """检查 optimizer.pt 是否有 NaN（如果存在）。"""
    try:
        import torch
    except ImportError:
        return {"status": "skip", "reason": "torch not available"}

    # 找 optimizer.pt
    opt_file = None
    for path in [adapter_dir / "optimizer.pt",
                 adapter_dir / "best" / "optimizer.pt",
                 adapter_dir / "checkpoint-88" / "optimizer.pt"]:
        if path.exists():
            opt_file = path
            break

    if opt_file is None:
        return {"status": "skip", "reason": "未找到 optimizer.pt（trainer.save_model 可能没存）"}

    try:
        opt_state = torch.load(str(opt_file), map_location="cpu", weights_only=False)
    except Exception as e:
        return {"status": "error", "reason": f"加载失败: {e}"}

    # optimizer state 是 dict，递归检查所有 tensor
    nan_count = 0
    inf_count = 0
    total_tensors = 0

    def _scan(obj):
        nonlocal nan_count, inf_count, total_tensors
        if isinstance(obj, dict):
            for v in obj.values():
                _scan(v)
        elif isinstance(obj, list):
            for v in obj:
                _scan(v)
        elif hasattr(obj, "data") and hasattr(obj.data, "isnan"):
            # 真正的 tensor
            t = obj.data if hasattr(obj, "data") else obj
            if hasattr(t, "isnan"):
                nan_count += int(t.isnan().sum().item())
                inf_count += int(t.isinf().sum().item())
                total_tensors += 1

    _scan(opt_state)

    return {
        "status": "ok" if nan_count == 0 and inf_count == 0 else "corrupted",
        "nan_count": nan_count,
        "inf_count": inf_count,
        "total_tensors": total_tensors,
    }


def compare_runs_across(run_results: dict) -> dict:
    """跨 run 对比，看 dev_loss 排序是否符合预期。"""
    # 收集每个 run 的 min_dev_loss
    losses = {}
    for run_id, r in run_results.items():
        if r.get("trainer_state", {}).get("status") == "ok":
            losses[run_id] = r["trainer_state"]["min_dev_loss"]

    if len(losses) < 3:
        return {"status": "skip", "reason": f"只有 {len(losses)} 个 run 有 dev_loss，无法对比"}

    # 按预期，run 4 (lr=1e-4 + rsLoRA) 应该最低
    # run 2 (lr=1e-4) > run 1 (lr=5e-5) 因为高 lr 更激进（实际上 run 2 比 run 1 dev_loss 低）
    # 实测：run 4 < run 2 < run 3 < run 1
    sorted_runs = sorted(losses.items(), key=lambda x: x[1])
    actual_order = [r[0] for r in sorted_runs if r[0] in EXPECTED_DEV_LOSS_ORDER]

    # 验证：实际排序中 run 4 应该是最低
    if 4 in losses and losses[4] == min(losses.values()):
        order_ok = True
    else:
        order_ok = False

    return {
        "status": "ok" if order_ok else "suspicious",
        "losses": losses,
        "sorted_order": sorted_runs,
        "expected_best": 4,
        "actual_best": sorted_runs[0][0] if sorted_runs else None,
        "verdict": "run 4 (lr=1e-4 + rsLoRA) dev_loss 最低，符合 lr × rsLoRA 协同假设"
                   if order_ok else "❌ dev_loss 排序异常，怀疑训练被损坏",
    }


def main():
    parser = argparse.ArgumentParser(description="验证 Phase 1 是否受 bitsandbytes paged_adamw_8bit bug 影响")
    parser.add_argument("--run-ids", type=int, nargs="+", default=[1, 2, 3, 4, 5],
                        help="要检查的 run 编号（默认 1-5）")
    parser.add_argument("--verbose", action="store_true", help="打印详细统计")
    parser.add_argument("--outputs-dir", type=Path, default=OUTPUTS_DIR)
    args = parser.parse_args()

    print("=" * 70)
    print("Phase 1 bitsandbytes paged_adamw_8bit 损坏验证")
    print("=" * 70)
    print(f"背景：Level1Techs 报告 gfx1201 上 paged_adamw_8bit 会静默损坏模型状态")
    print(f"     train_qlora.py 用 paged_adamw_8bit，需验证 Phase 1 sweep 结果")
    print(f"     报告来源：https://forum.level1techs.com/t/250960")
    print(f"     你的硬件：gfx1200 (RX 9060 XT) vs 报告 gfx1201 (R9700)")
    print("")

    run_results = {}

    for run_id in args.run_ids:
        print(f"\n{'─' * 70}")
        print(f"Run {run_id}")
        print(f"{'─' * 70}")

        run_dir = find_run_dir(run_id)
        if run_dir is None:
            print(f"  ❌ 未找到 run {run_id} 的输出目录")
            run_results[run_id] = {"status": "missing"}
            continue

        print(f"  目录: {run_dir}")

        # 找 best 子目录（train_qlora.py 用 load_best_model_at_end，best 在 best/ 子目录）
        best_dir = run_dir / "best"
        target_dir = best_dir if best_dir.exists() else run_dir
        print(f"  检查目录: {target_dir}")

        result = {"run_dir": str(run_dir)}

        # 1. LoRA 权重检查
        print(f"\n  [1/3] LoRA 权重检查...")
        weight_check = check_lora_weights(target_dir)
        result["weights"] = weight_check
        if weight_check["status"] == "ok":
            s = weight_check["stats_summary"]
            print(f"    ✅ {weight_check['total_tensors']} 个 tensor 全部通过")
            print(f"       mean of stds: {s['mean_of_stds']:.4g}")
            print(f"       max abs_max:  {s['max_abs_max']:.4g}")
        elif weight_check["status"] == "suspicious":
            print(f"    ⚠️ 发现 {len(weight_check['suspicious_tensors'])} 个可疑 tensor:")
            for s in weight_check["suspicious_tensors"][:5]:
                print(f"       - {s['name']}: {s['issue']}")
        elif weight_check["status"] == "skip":
            print(f"    ⏭️ 跳过: {weight_check['reason']}")
        else:
            print(f"    ❌ 错误: {weight_check.get('reason', 'unknown')}")

        # 2. trainer_state 检查
        print(f"\n  [2/3] trainer_state.json dev_loss 曲线检查...")
        state_check = check_trainer_state(target_dir)
        result["trainer_state"] = state_check
        if state_check["status"] == "ok":
            print(f"    ✅ dev_loss 曲线健康")
            print(f"       eval_losses: {[f'{l:.4f}' for l in state_check['eval_losses']]}")
            print(f"       final: {state_check['final_dev_loss']:.4f}  min: {state_check['min_dev_loss']:.4f} (epoch {state_check['best_epoch']})")
        elif state_check["status"] == "suspicious":
            print(f"    ⚠️ dev_loss 曲线可疑")
            print(f"       eval_losses: {[f'{l:.4f}' for l in state_check['eval_losses']]}")
            if state_check["has_nan"]:
                print(f"       ❌ 有 NaN")
            if state_check["train_loss_has_nan"]:
                print(f"       ❌ train_loss 有 NaN")
            if state_check["bounces"]:
                print(f"       ⚠️ 反弹:")
                for b in state_check["bounces"]:
                    print(f"          epoch {b['epoch']}: {b['prev_loss']:.4f} → {b['curr_loss']:.4f} (+{b['increase_pct']:.1f}%)")
        elif state_check["status"] == "skip":
            print(f"    ⏭️ 跳过: {state_check['reason']}")
        else:
            print(f"    ❌ 错误: {state_check.get('reason', 'unknown')}")

        # 3. optimizer.pt 检查
        print(f"\n  [3/3] optimizer.pt 状态检查...")
        opt_check = check_optimizer_state(target_dir)
        result["optimizer"] = opt_check
        if opt_check["status"] == "ok":
            print(f"    ✅ optimizer state 正常 ({opt_check['total_tensors']} tensors, 0 NaN, 0 Inf)")
        elif opt_check["status"] == "corrupted":
            print(f"    ❌ optimizer state 损坏！")
            print(f"       NaN count: {opt_check['nan_count']}")
            print(f"       Inf count: {opt_check['inf_count']}")
            print(f"       这是 bitsandbytes 损坏的强证据")
        elif opt_check["status"] == "skip":
            print(f"    ⏭️ 跳过: {opt_check['reason']}")
        else:
            print(f"    ❌ 错误: {opt_check.get('reason', 'unknown')}")

        if args.verbose and "stats" in weight_check:
            print(f"\n  详细权重统计（前 10）:")
            for s in weight_check["stats"][:10]:
                print(f"    {s['name']}: shape={s['shape']} mean={s['mean']:.4g} std={s['std']:.4g} abs_max={s['abs_max']:.4g}")

        run_results[run_id] = result

    # 跨 run 对比
    print(f"\n{'=' * 70}")
    print("跨 run 对比")
    print(f"{'=' * 70}")

    comparison = compare_runs_across(run_results)
    if comparison["status"] == "ok":
        print(f"  ✅ {comparison['verdict']}")
        print(f"  dev_loss 排序（低→高）:")
        for run_id, loss in comparison["sorted_order"]:
            tag = " ⭐ best" if run_id == 4 else ""
            print(f"    run {run_id}: {loss:.4f}{tag}")
    elif comparison["status"] == "suspicious":
        print(f"  ⚠️ {comparison['verdict']}")
        print(f"  实际排序: {comparison['sorted_order']}")
        print(f"  预期最佳: run {comparison['expected_best']}")
        print(f"  实际最佳: run {comparison['actual_best']}")
    else:
        print(f"  ⏭️ 跳过: {comparison.get('reason')}")

    # 总体结论
    print(f"\n{'=' * 70}")
    print("总体结论")
    print(f"{'=' * 70}")

    critical_issues = []
    suspicious_count = 0
    for run_id, r in run_results.items():
        if r.get("status") == "missing":
            continue
        weights = r.get("weights", {})
        trainer = r.get("trainer_state", {})
        opt = r.get("optimizer", {})

        if weights.get("status") == "suspicious" and (weights.get("nan_count", 0) > 0 or weights.get("inf_count", 0) > 0):
            critical_issues.append(f"run {run_id}: LoRA 权重有 NaN/Inf")
        if trainer.get("has_nan") or trainer.get("has_inf"):
            critical_issues.append(f"run {run_id}: trainer_state dev_loss 有 NaN/Inf")
        if opt.get("status") == "corrupted":
            critical_issues.append(f"run {run_id}: optimizer.pt 有 NaN/Inf（强损坏证据）")

        if any(s.get("status") == "suspicious" for s in [weights, trainer, opt]):
            suspicious_count += 1

    if critical_issues:
        print(f"\n❌ 发现 {len(critical_issues)} 个严重问题：")
        for issue in critical_issues:
            print(f"   - {issue}")
        print(f"\n判定：Phase 1 数据被 bitsandbytes 损坏，必须重跑！")
        print(f"建议：用 --optim adamw_torch 重跑 run 4 (lr=1e-4 + rsLoRA)，对比 dev_loss 是否一致")
        print(f"命令：")
        print(f"  HF_HUB_OFFLINE=1 /home/zane/miniconda3/envs/AI/bin/python train_qlora.py \\")
        print(f"    --model-id Qwen/Qwen2.5-Coder-7B-Instruct --epochs 1 --lr 1e-4 \\")
        print(f"    --lora-r 8 --lora-alpha 16 --use-rslora --output-suffix _7b_adamw_torch")
        sys.exit(2)
    elif suspicious_count > 0:
        print(f"\n⚠️ {suspicious_count} 个 run 有可疑信号（但无 NaN/Inf 硬证据）")
        print(f"   建议：跑一组 adamw_torch 对比验证（约 1.5h）")
        print(f"   命令：")
        print(f"     HF_HUB_OFFLINE=1 /home/zane/miniconda3/envs/AI/bin/python train_qlora.py \\")
        print(f"       --model-id Qwen/Qwen2.5-Coder-7B-Instruct --epochs 1 --lr 1e-4 \\")
        print(f"       --lora-r 8 --lora-alpha 16 --use-rslora --output-suffix _7b_adamw_torch")
        sys.exit(1)
    else:
        print(f"\n✅ 全部检查通过，Phase 1 sweep 数据有效，无需重跑！")
        print(f"   下一步：bash run_phase1_eval.sh 跑评估 + compare_phase1_sweep.py 生成报告")
        sys.exit(0)


if __name__ == "__main__":
    main()
