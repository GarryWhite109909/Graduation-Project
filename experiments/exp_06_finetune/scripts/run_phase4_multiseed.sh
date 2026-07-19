#!/bin/bash
# ============================================================================
# Phase 4 多种子评估包装脚本
#
# 用途：Phase 4 训练完成后，对 best adapter 用多个 seed 跑 eval，
#       验证 PD（KL 蒸馏）训练的稳定性。
#
# 动机：compare_phase4.py 单次 eval 判定可能受 LLM 推理随机性影响
#       （即使 temperature=0，batch 内 attention 也可能有微小数值差异）。
#       PD 训练对 KL loss 敏感，必须多种子验证。
#
# 用法：
#   bash experiments/exp_06_finetune/scripts/run_phase4_multiseed.sh [adapter_dir]
#
# 参数：
#   adapter_dir：可选，默认自动找最新 pd_r32_*_phase4_ollama30b*/best
#
# 环境变量：
#   SEEDS="42 7 123"：评估用 seed 列表（默认 3 个）
#   STUDENT_MODEL：与 run_phase4_prompt_distillation.sh 一致
# ============================================================================

set -e

PROJECT_ROOT="/home/zane/文档/code/毕业设计"
AI_PYTHON="/home/zane/miniconda3/envs/AI/bin/python"
SCRIPT_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/scripts"
OUTPUTS_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/outputs"
RESULTS_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/results"

# Student：默认基于 Phase 3 KnItLM 合并模型
PHASE3_MERGED="${OUTPUTS_DIR}/knitlm_merged_7b_instruct"
STUDENT_MODEL="${STUDENT_MODEL:-${PHASE3_MERGED}}"

# 多种子列表
SEEDS="${SEEDS:-42 7 123}"

# 找 Phase 4 adapter
ADAPTER_DIR="${1:-}"
if [ -z "${ADAPTER_DIR}" ]; then
    ADAPTER_DIR=$(ls -dt ${OUTPUTS_DIR}/pd_r32_*_phase4_ollama30b*/best 2>/dev/null | head -1)
    if [ -z "${ADAPTER_DIR}" ]; then
        ADAPTER_DIR=$(ls -dt ${OUTPUTS_DIR}/pd_r32_*/best 2>/dev/null | head -1)
    fi
fi
if [ -z "${ADAPTER_DIR}" ] || [ ! -d "${ADAPTER_DIR}" ]; then
    echo "❌ 未找到 Phase 4 adapter 目录：${ADAPTER_DIR}"
    echo "   用法: bash $0 [adapter_dir]"
    exit 1
fi

echo "=========================================="
echo "Phase 4 多种子评估"
echo "  Adapter: ${ADAPTER_DIR}"
echo "  Student: ${STUDENT_MODEL}"
echo "  Seeds: ${SEEDS}"
echo "=========================================="

export HF_HUB_OFFLINE=1
export TOKENIZERS_PARALLELISM=false

for seed in ${SEEDS}; do
    echo ""
    echo "------ Seed ${seed} ------"
    ${AI_PYTHON} "${SCRIPT_DIR}/evaluate.py" \
        --mode finetuned \
        --adapter-path "${ADAPTER_DIR}" \
        --model-id "${STUDENT_MODEL}" \
        --temperature 0.0 \
        --seed ${seed}

    # 重命名为带 seed 的文件
    latest=$(ls -1t ${RESULTS_DIR}/exp_06_eval.finetuned_custom.*.json 2>/dev/null | head -1)
    if [ -n "${latest}" ]; then
        ts=$(date +%Y%m%d_%H%M%S)
        new_name="${RESULTS_DIR}/exp_06_eval.phase4_ollama30b_seed${seed}.${ts}.json"
        mv "${latest}" "${new_name}"
        echo "  → ${new_name}"
    fi
done

echo ""
echo "✅ 多种子评估完成"
echo ""
echo "下一步：用 compare_phase4.py 自动汇总（脚本会拾取所有 phase4_*.json）"
echo "  ${AI_PYTHON} ${SCRIPT_DIR}/compare_phase4.py"
echo ""
echo "或手动对比 seed 间稳定性："
echo "  ${AI_PYTHON} -c \"import json; \\"
echo "  import pathlib; \\"
echo "  d=list(pathlib.Path('${RESULTS_DIR}').glob('exp_06_eval.phase4_ollama30b_seed*.json')); \\"
echo "  [print(f.name, json.load(open(f))['samples'][:5]) for f in sorted(d)]\""
