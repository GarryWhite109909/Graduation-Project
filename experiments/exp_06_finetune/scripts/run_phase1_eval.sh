#!/bin/bash
# ============================================================================
# Phase 1 评估：在 exp_04 87 段测试集上评估每个 sweep checkpoint
#
# 对每个 outputs/lora_r8_a16_e1_lr*_s42*_7b/best 目录跑 evaluate.py，
# 然后把输出重命名为 exp_06_eval.phase1_{tag}.{ts}.json 以便对比脚本识别。
#
# 用法：
#   cd /home/zane/文档/code/毕业设计
#   bash experiments/exp_06_finetune/scripts/run_phase1_eval.sh
#
# 可选环境变量：
#   SKIP_EXISTING=1   跳过已有 phase1 评估结果的配置（断点续跑）
#   LIMIT=0           只评估前 N 个样本（默认 0=全部，调试时可设小值）
# ============================================================================

set -e

PROJECT_ROOT="/home/zane/文档/code/毕业设计"
AI_PYTHON="/home/zane/miniconda3/envs/AI/bin/python"
SCRIPT_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/scripts"
OUTPUTS_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/outputs"
RESULTS_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/results"

export HF_HUB_OFFLINE=1
export TOKENIZERS_PARALLELISM=false

SKIP_EXISTING="${SKIP_EXISTING:-0}"
LIMIT="${LIMIT:-0}"

echo "=========================================="
echo "Phase 1 评估：sweep checkpoints on exp_04 87 段测试集"
echo "  SKIP_EXISTING=${SKIP_EXISTING}  LIMIT=${LIMIT}"
echo "=========================================="

# 配置列表：tag | adapter 目录名
# 注意：baseline 用旧命名（train_qlora.py 改造前已训练完成，目录无 lr 前缀）；
#       sweep 各组用新命名（改造后 output_dir 含 lr{lr:g} 前缀）。
declare -a CONFIGS=(
    "lr1e-5_base|lora_r8_a16_e1_s42_7b"
    "lr5e-5|lora_r8_a16_e1_lr5e-05_s42_7b"
    "lr1e-4|lora_r8_a16_e1_lr0.0001_s42_7b"
    "lr5e-5_rslora|lora_r8_a16_e1_lr5e-05_s42_rslora_7b"
    "lr1e-4_rslora|lora_r8_a16_e1_lr0.0001_s42_rslora_7b"
    "lr5e-5_rslora_dora|lora_r8_a16_e1_lr5e-05_s42_rslora_dora_7b"
)

for entry in "${CONFIGS[@]}"; do
    tag="${entry%%|*}"
    adapter_dirname="${entry##*|}"
    adapter_path="${OUTPUTS_DIR}/${adapter_dirname}/best"

    echo ""
    echo "------ 评估 ${tag} ------"
    echo "  adapter: ${adapter_path}"

    if [ ! -d "${adapter_path}" ]; then
        echo "  ⚠️ adapter 目录不存在，跳过（训练未完成或失败）"
        continue
    fi

    # 断点续跑：检查是否已有该 tag 的评估结果
    if [ "${SKIP_EXISTING}" = "1" ]; then
        existing=$(ls -1 "${RESULTS_DIR}"/exp_06_eval.phase1_${tag}.*.json 2>/dev/null | head -1 || true)
        if [ -n "${existing}" ]; then
            echo "  ✓ 已有评估结果 ${existing}，跳过（SKIP_EXISTING=1）"
            continue
        fi
    fi

    # 运行评估（确定性解码 temperature=0.0）
    limit_args=()
    if [ "${LIMIT}" != "0" ]; then
        limit_args=(--limit "${LIMIT}")
    fi

    ${AI_PYTHON} "${SCRIPT_DIR}/evaluate.py" \
        --mode finetuned \
        --adapter-path "${adapter_path}" \
        --model-id Qwen/Qwen2.5-Coder-7B-Instruct \
        --temperature 0.0 \
        "${limit_args[@]}"

    # 找到最新生成的 exp_06_eval.finetuned_custom.*.json，重命名为带 tag 的文件
    latest=$(ls -1t "${RESULTS_DIR}"/exp_06_eval.finetuned_custom.*.json 2>/dev/null | head -1 || true)
    if [ -z "${latest}" ]; then
        echo "  ⚠️ 未找到 evaluate.py 输出文件，跳过重命名"
        continue
    fi
    ts=$(date +%Y%m%d_%H%M%S)
    new_name="${RESULTS_DIR}/exp_06_eval.phase1_${tag}.${ts}.json"
    mv "${latest}" "${new_name}"
    echo "  → ${new_name}"
done

echo