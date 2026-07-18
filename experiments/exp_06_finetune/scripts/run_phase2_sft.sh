#!/bin/bash
# ============================================================================
# Phase 2: SFT 强化训练（r=32 + rsLoRA + e=2 + lr=1e-5）
#
# 设计依据（Phase 1 sweep 关键发现）：
#   - lr=1e-5 baseline: FPR=11.5%, accuracy=92.0% ⭐
#   - lr=5e-5/1e-4:     FPR=23.1%, accuracy=86-88% ❌
#   高 lr 让模型变成"看见代码就说有漏洞"，FPR 翻倍
#   所以 Phase 2 必须用 lr=1e-5，靠 r=32 + epochs=2 增加容量，不靠 lr
#
# 网格（顺序跑，每组 ~3.2h，7B 4bit QLoRA）：
#   run 1 (主): lr=1e-5, r=32, alpha=64, rsLoRA, epochs=2
#   run 2 (备): lr=1e-5, r=32, alpha=64, rsLoRA + DoRA, epochs=2
#              （DoRA 在 r=32 时可能比 r=8 更有价值，因为 magnitude 也能学到东西）
#
# 用法：
#   bash experiments/exp_06_finetune/scripts/run_phase2_sft.sh
#   bash experiments/exp_06_finetune/scripts/run_phase2_sft.sh run1   # 只跑 run 1
# ============================================================================

set -e

PROJECT_ROOT="/home/zane/文档/code/毕业设计"
AI_PYTHON="/home/zane/miniconda3/envs/AI/bin/python"
SCRIPT_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/scripts"
LOG_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/logs"

# RDNA4 优化（参考 docs/方法.md §12）
export HF_HUB_OFFLINE=1
export TOKENIZERS_PARALLELISM=false
export TORCH_ROCM_AOTRITON_ENABLE_EXPERIMENTAL=1

# TunableOp（如果离线调优已生成 tuned 表，自动启用）
TUNABLEOP_CSV="${PROJECT_ROOT}/experiments/exp_06_finetune/configs/tunableop_tuned.csv"
if [ -f "${TUNABLEOP_CSV}" ]; then
    export PYTORCH_TUNABLEOP_ENABLED=1
    export PYTORCH_TUNABLEOP_TUNING=0
    export PYTORCH_TUNABLEOP_FILE_NAME="${TUNABLEOP_CSV}"
    echo "[Phase 2] TunableOp 已启用: ${TUNABLEOP_CSV}"
fi

RUN="${1:-all}"

# ----------------------------------------------------------------------------
# Run 1: 主配置（lr=1e-5 + r=32 + rsLoRA + epochs=2）
# ----------------------------------------------------------------------------
run1() {
    local ts=$(date +%Y%m%d_%H%M%S)
    local log="${LOG_DIR}/phase2_run1_lr1e-5_r32_rslora_e2_${ts}.log"
    echo ""
    echo "========== Phase 2 Run 1 =========="
    echo "  lr=1e-5, r=32, alpha=64, rsLoRA, epochs=2"
    echo "  Log: ${log}"
    echo "===================================="

    ${AI_PYTHON} "${SCRIPT_DIR}/train_qlora.py" \
        --model-id Qwen/Qwen2.5-Coder-7B-Instruct \
        --epochs 2 \
        --batch-size 1 \
        --grad-accum 8 \
        --lr 1e-5 \
        --lora-r 32 \
        --lora-alpha 64 \
        --lora-dropout 0.05 \
        --use-rslora \
        --seed 42 \
        --output-suffix _phase2_r32_lr1e-5_rslora_e2_7b \
        2>&1 | tee "${log}"
}

# ----------------------------------------------------------------------------
# Run 2: 加 DoRA（r=32 时 DoRA 价值更明显）
# ----------------------------------------------------------------------------
run2() {
    local ts=$(date +%Y%m%d_%H%M%S)
    local log="${LOG_DIR}/phase2_run2_lr1e-5_r32_rslora_dora_e2_${ts}.log"
    echo ""
    echo "========== Phase 2 Run 2 =========="
    echo "  lr=1e-5, r=32, alpha=64, rsLoRA + DoRA, epochs=2"
    echo "  Log: ${log}"
    echo "===================================="

    ${AI_PYTHON} "${SCRIPT_DIR}/train_qlora.py" \
        --model-id Qwen/Qwen2.5-Coder-7B-Instruct \
        --epochs 2 \
        --batch-size 1 \
        --grad-accum 8 \
        --lr 1e-5 \
        --lora-r 32 \
        --lora-alpha 64 \
        --lora-dropout 0.05 \
        --use-rslora \
        --use-dora \
        --seed 42 \
        --output-suffix _phase2_r32_lr1e-5_rslora_dora_e2_7b \
        2>&1 | tee "${log}"
}

case "${RUN}" in
    run1) run1 ;;
    run2) run2 ;;
    all)
        run1
        echo ""
        read -p "Run 1 完成。继续跑 Run 2 (DoRA)？[y/N] " ans
        if [[ "${ans}" == "y" || "${ans}" == "Y" ]]; then
            run2
        fi
        ;;
    *)
        echo "用法: bash $0 [run1|run2|all]"
        exit 1
        ;;
esac

echo ""
echo "✅ Phase 2 训练完成"
echo "下一步："
echo "  1. 评估: bash experiments/exp_06_finetune/scripts/run_phase2_eval.sh"
echo "  2. 对比: /home/zane/miniconda3/envs/AI/bin/python experiments/exp_06_finetune/scripts/compare_phase1_sweep.py"
