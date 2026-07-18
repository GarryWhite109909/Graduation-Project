#!/bin/bash
# ============================================================================
# Phase 1: P0 零成本验证 —— 7B 上 lr × rsLoRA 小网格搜索
#
# 目标：验证 docs/方法.md §9 P0 的两个假设
#   1. lr 1e-5 → 更高 lr 是否提升严格 recall（修正文档"直接跳 2e-4"的激进建议）
#   2. rsLoRA 是否带来零成本提升
#
# 网格（每组 r=8 e=1，~54min/组，7B 4bit QLoRA）：
#   run 0 (baseline, 已存在): lr=1e-5, rslora=off           → lora_r8_a16_e1_lr1e-05_s42_7b
#   run 1:                    lr=5e-5, rslora=off
#   run 2:                    lr=1e-4, rslora=off
#   run 3:                    lr=5e-5, rslora=on
#   run 4:                    lr=1e-4, rslora=on
#   run 5 (兼容性探测):        lr=5e-5, rslora=on, dora=on   ← 验证 DoRA+4bit 在 ROCm 上是否跑通
#
# 用法（在真实终端运行，非 IDE 沙箱）：
#   cd /home/zane/文档/code/毕业设计
#   bash experiments/exp_06_finetune/scripts/run_phase1_sweep.sh
#
# 可选环境变量：
#   SKIP_DORA=1       跳过 run 5（DoRA 兼容性探测）
#   START_FROM=3      从指定 run 编号开始（断点续跑）
#   EPOCHS=1          训练轮数（默认 1）
#
# 输出：experiments/exp_06_finetune/outputs/lora_r8_a16_e1_lr{X}_s42[_rslora][_dora]_7b/
#       experiments/exp_06_finetune/logs/train_log_r8_e1_s42{...}_7b.json
# ============================================================================

set -e

PROJECT_ROOT="/home/zane/文档/code/毕业设计"
AI_PYTHON="/home/zane/miniconda3/envs/AI/bin/python"
SCRIPT_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/scripts"
OUTPUTS_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/outputs"

# 离线模式（项目 memory 约定：网络不可达时用 HF_HUB_OFFLINE=1）
export HF_HUB_OFFLINE=1
export TOKENIZERS_PARALLELISM=false

# ============================================================================
# RDNA4 训练优化（参考 docs/方法.md §12）
# 这些 env vars 只在脚本启动时生效，对当前正在运行的 bash 进程无影响
# （bash 已读过这部分，改这里只影响"下次"运行）
# ============================================================================

# 1. AOTRITON attention（PyTorch 2.11+ 实验性，日志中反复 warning 推荐开启）
#    vLLM 社区实测 gfx1201 推理 +63%，训练侧 attention kernel 同路径，预期 +20-40%
export TORCH_ROCM_AOTRITON_ENABLE_EXPERIMENTAL=1

# 2. PyTorch TunableOp 离线调优结果加载（仅当 tuned CSV 存在时启用）
#    跑 tunableop_offline_tune.sh 生成 tuned CSV，AMD 官方实测 +15% 端到端
TUNABLEOP_CSV="${PROJECT_ROOT}/experiments/exp_06_finetune/configs/tunableop_tuned.csv"
if [ -f "${TUNABLEOP_CSV}" ]; then
    export PYTORCH_TUNABLEOP_ENABLED=1
    export PYTORCH_TUNABLEOP_TUNING=0          # 0=只读取已 tuned 结果，不 online tune
    export PYTORCH_TUNABLEOP_FILE_NAME="${TUNABLEOP_CSV}"
    echo "[RDNA4 opt] TunableOp: 加载 tuned CSV (${TUNABLEOP_CSV})"
else
    echo "[RDNA4 opt] TunableOp: 未找到 tuned CSV，跳过（Phase 2 前建议先跑 tunableop_offline_tune.sh）"
fi

# 3. hipBLASLt 离线调优结果加载（同上，仅当 tuning file 存在时启用）
#    ROCm 7.2 重点增强，GEMM 密集场景 +10-20%
HIPBLASLT_FILE="${PROJECT_ROOT}/experiments/exp_06_finetune/configs/hipblaslt_tuning.txt"
if [ -f "${HIPBLASLT_FILE}" ]; then
    export HIPBLASLT_TUNING_FILE="${HIPBLASLT_FILE}"
    echo "[RDNA4 opt] hipBLASLt: 加载 tuning file (${HIPBLASLT_FILE})"
fi

EPOCHS="${EPOCHS:-1}"
LORA_R=8
LORA_ALPHA=16
SEED=42
START_FROM="${START_FROM:-1}"
SKIP_DORA="${SKIP_DORA:-0}"

echo "=========================================="
echo "Phase 1 Sweep: 7B lr × rsLoRA 网格搜索"
echo "  EPOCHS=${EPOCHS}  LORA_R=${LORA_R}  LORA_ALPHA=${LORA_ALPHA}  SEED=${SEED}"
echo "  START_FROM=${START_FROM}  SKIP_DORA=${SKIP_DORA}"
echo "=========================================="

run_train() {
    local run_id=$1
    local lr=$2
    local extra_flags=$3
    local desc=$4
    echo ""
    echo "------ run ${run_id}: ${desc} ------"
    echo "  lr=${lr}  flags=${extra_flags:-none}"
    local extra_args=()
    if [ -n "$extra_flags" ]; then
        extra_args=($extra_flags)
    fi
    ${AI_PYTHON} "${SCRIPT_DIR}/train_qlora.py" \
        --model-id Qwen/Qwen2.5-Coder-7B-Instruct \
        --epochs ${EPOCHS} \
        --batch-size 1 \
        --grad-accum 8 \
        --lr ${lr} \
        --lora-r ${LORA_R} \
        --lora-alpha ${LORA_ALPHA} \
        --seed ${SEED} \
        --output-suffix _7b \
        "${extra_args[@]}"
    echo "------ run ${run_id} 完成 ------"
}

# run 1: lr=5e-5, 无 rslora
if [ "${START_FROM}" -le 1 ]; then
    run_train 1 5e-5 "" "lr=5e-5 baseline-rslora"
fi

# run 2: lr=1e-4, 无 rslora
if [ "${START_FROM}" -le 2 ]; then
    run_train 2 1e-4 "" "lr=1e-4 baseline-rslora"
fi

# run 3: lr=5e-5 + rsLoRA
if [ "${START_FROM}" -le 3 ]; then
    run_train 3 5e-5 "--use-rslora" "lr=5e-5 + rsLoRA"
fi

# run 4: lr=1e-4 + rsLoRA
if [ "${START_FROM}" -le 4 ]; then
    run_train 4 1e-4 "--use-rslora" "lr=1e-4 + rsLoRA"
fi

# run 5: DoRA 兼容性探测（独立，失败不影响前 4 组）
if [ "${SKIP_DORA}" != "1" ] && [ "${START_FROM}" -le 5 ]; then
    echo ""
    echo "------ run 5: DoRA + 4bit QLoRA 兼容性探测 ------"
    echo "  若段错误/OOM，说明 DoRA+4bit 在 ROCm 上不兼容，Phase 2 改用 fp16 + DoRA 或放弃 DoRA"
    set +e
    run_train 5 5e-5 "--use-rslora --use-dora" "lr=5e-5 + rsLoRA + DoRA (兼容性探测)"
    dora_rc=$?
    set -e
    if [ ${dora_rc} -ne 0 ]; then
        echo "⚠️ run 5 DoRA 失败 (rc=${dora_rc})，DoRA+4bit QLoRA 在 ROCm 上不兼容"
        echo "   Phase 2 将放弃 DoRA，仅用 rsLoRA"
    fi
fi

echo ""
echo "=========================================="
echo "Phase 1 训练全部完成"
echo "=========================================="
echo ""
echo "输出目录："
ls -1d "${OUTPUTS_DIR}"/lora_r8_a16_e1_lr*_s42*_7b 2>/dev/null || echo "  (无匹配目录)"
echo ""
echo "下一步：运行评估 + 对比"
echo "  bash ${SCRIPT_DIR}/run_phase1_eval.sh"
echo "  ${AI_PYTHON} ${SCRIPT_DIR}/compare_phase1_sweep.py"
echo ""
echo "可选：验证 Phase 1 是否受 bitsandbytes paged_adamw_8bit bug 影响"
echo "  ${AI_PYTHON} ${SCRIPT_DIR}/verify_bnb_corruption.py"