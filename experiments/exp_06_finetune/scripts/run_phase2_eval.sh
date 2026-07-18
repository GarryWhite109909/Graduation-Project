#!/bin/bash
# ============================================================================
# Phase 2 评估：在 exp_04 87 段测试集上评估 r=32 checkpoints
#
# 对每个 outputs/lora_r32_*_phase2_*/best 目录跑 evaluate.py，
# 然后把输出重命名为 exp_06_eval.phase2_{tag}.{ts}.json
#
# 用法：
#   cd /home/zane/文档/code/毕业设计
#   bash experiments/exp_06_finetune/scripts/run_phase2_eval.sh
#
# 可选环境变量：
#   SKIP_EXISTING=1   跳过已有 phase2 评估结果的配置
#   LIMIT=0           只评估前 N 个样本（默认 0=全部）
#   RAG=1             启用 RAG 检索（CWE 知识库注入）
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
RAG="${RAG:-0}"

echo "=========================================="
echo "Phase 2 评估：r=32 checkpoints on exp_04 87 段测试集"
echo "  SKIP_EXISTING=${SKIP_EXISTING}  LIMIT=${LIMIT}  RAG=${RAG}"
echo "=========================================="

# 配置列表：tag | adapter 目录名
# 注意：目录名包含 peft_tag（_rslora / _rslora_dora），由 train_qlora.py 自动生成
declare -a CONFIGS=(
    "phase2_r32_lr1e-5_rslora_e2|lora_r32_a64_e2_lr1e-05_s42_rslora_phase2_r32_lr1e-5_rslora_e2_7b"
    "phase2_r32_lr1e-5_rslora_dora_e2|lora_r32_a64_e2_lr1e-05_s42_rslora_dora_phase2_r32_lr1e-5_rslora_dora_e2_7b"
)

# 可选 RAG 后缀
RAG_SUFFIX=""
RAG_ARGS=()
if [ "${RAG}" = "1" ]; then
    RAG_SUFFIX="_rag"
    RAG_ARGS=(--rag)
    echo "[Phase 2] RAG 已启用"
fi

for entry in "${CONFIGS[@]}"; do
    tag="${entry%%|*}"
    adapter_dirname="${entry##*|}"
    adapter_path="${OUTPUTS_DIR}/${adapter_dirname}/best"

    echo ""
    echo "------ 评估 ${tag}${RAG_SUFFIX} ------"
    echo "  adapter: ${adapter_path}"

    if [ ! -d "${adapter_path}" ]; then
        echo "  ⚠️ adapter 目录不存在，跳过"
        continue
    fi

    # 断点续跑
    if [ "${SKIP_EXISTING}" = "1" ]; then
        existing=$(ls -1 "${RESULTS_DIR}"/exp_06_eval.${tag}${RAG_SUFFIX}.*.json 2>/dev/null | head -1 || true)
        if [ -n "${existing}" ]; then
            echo "  ✓ 已有评估结果，跳过"
            continue
        fi
    fi

    limit_args=()
    if [ "${LIMIT}" != "0" ]; then
        limit_args=(--limit "${LIMIT}")
    fi

    ${AI_PYTHON} "${SCRIPT_DIR}/evaluate.py" \
        --mode finetuned \
        --adapter-path "${adapter_path}" \
        --model-id Qwen/Qwen2.5-Coder-7B-Instruct \
        --temperature 0.0 \
        "${limit_args[@]}" \
        "${RAG_ARGS[@]}"

    latest=$(ls -1t "${RESULTS_DIR}"/exp_06_eval.finetuned_custom.*.json 2>/dev/null | head -1 || true)
    if [ -z "${latest}" ]; then
        echo "  ⚠️ 未找到输出文件"
        continue
    fi
    ts=$(date +%Y%m%d_%H%M%S)
    new_name="${RESULTS_DIR}/exp_06_eval.${tag}${RAG_SUFFIX}.${ts}.json"
    mv "${latest}" "${new_name}"
    echo "  → ${new_name}"
done

echo ""
echo "✅ Phase 2 评估完成"
echo "下一步：/home/zane/miniconda3/envs/AI/bin/python experiments/exp_06_finetune/scripts/compare_phase2.py"
