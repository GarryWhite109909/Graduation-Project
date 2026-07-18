#!/bin/bash
# ============================================================================
# Phase 4: Prompt Distillation 一键运行脚本
#
# 完整流程：
#   Step 1: 起 Ollama 服务 + 拉模型（前置，仅首次）
#   Step 2: precompute teacher logits（823 样本，~4h）
#   Step 3: 训练 student（Prompt Distillation loss = CE + KL）
#   Step 4: 评估
#
# 对应 docs/方法.md §9 Phase 4
#
# 用法：
#   bash experiments/exp_06_finetune/scripts/run_phase4_prompt_distillation.sh [step]
#
# 参数：
#   无参数/step=all   跑完整流程（step 2-4，假设 step 1 已完成）
#   step=precompute   只跑 precompute
#   step=train         只跑训练
#   step=eval          只跑评估
#   step=test          测试模式（limit=5 验证脚本能跑通）
#
# 环境变量：
#   OLLAMA_MODEL=qwen3-coder:30b   teacher 模型
#   SKIP_PRECOMPUTE=0              跳过 precompute（已有数据时设 1）
#   ALPHA=0.5                       KL loss 权重
#   TEMPERATURE=2.0                 KL softmax 温度
# ============================================================================

set -e

PROJECT_ROOT="/home/zane/文档/code/毕业设计"
AI_PYTHON="/home/zane/miniconda3/envs/AI/bin/python"
SCRIPT_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/scripts"
DATA_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/data"
OUTPUTS_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/outputs"
RESULTS_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/results"

# 配置
OLLAMA_MODEL="${OLLAMA_MODEL:-qwen3-coder:30b}"
OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
ALPHA="${ALPHA:-0.5}"
TEMPERATURE="${TEMPERATURE:-2.0}"
TOP_K=20  # Ollama 后端上限 20

TEACHER_LOGITS_DIR="${DATA_DIR}/teacher_logits"

# Student 模型：默认基于 Phase 3 KnItLM 合并模型（路线 B：知识注入 + 蒸馏叠加）
# 设为 Qwen/Qwen2.5-Coder-7B-Instruct 可回到路线 A（独立对比）
PHASE3_MERGED="${OUTPUTS_DIR}/knitlm_merged_7b_instruct"
STUDENT_MODEL="${STUDENT_MODEL:-${PHASE3_MERGED}}"

STEP="${1:-all}"

echo "=========================================="
echo "Phase 4: Prompt Distillation"
echo "  Teacher: ${OLLAMA_MODEL} (Ollama, MoE offload)"
echo "  Student: ${STUDENT_MODEL}"
if [ -d "${STUDENT_MODEL}" ]; then
    echo "  路线 B: 基于 Phase 3 KnItLM 合并模型（知识注入 + 蒸馏叠加）"
else
    echo "  路线 A: 原始 Instruct（独立对比）"
fi
echo "  Step: ${STEP}"
echo "  Alpha=${ALPHA} T=${TEMPERATURE}"
echo "=========================================="

# ============================================================================
# Step 1: 检查 Ollama 服务（不自动启动，仅检查）
# ============================================================================
check_ollama() {
    echo ""
    echo "------ 检查 Ollama 服务 ------"
    if ! curl -s --max-time 5 "${OLLAMA_URL}/api/tags" > /dev/null 2>&1; then
        echo "❌ Ollama 服务未启动: ${OLLAMA_URL}"
        echo "   请先运行: ollama serve &"
        exit 1
    fi
    echo "  ✅ Ollama 服务在线"

    # 检查模型是否已拉取
    if ! curl -s "${OLLAMA_URL}/api/tags" | grep -q "\"${OLLAMA_MODEL}\""; then
        echo "❌ 模型 ${OLLAMA_MODEL} 未拉取"
        echo "   请先运行: ollama pull ${OLLAMA_MODEL}"
        exit 1
    fi
    echo "  ✅ 模型 ${OLLAMA_MODEL} 已就绪"
}

# ============================================================================
# Step 2: precompute teacher logits
# ============================================================================
run_precompute() {
    local limit_arg=""
    if [ "${STEP}" = "test" ]; then
        limit_arg="--limit 5"
        echo ""
        echo "------ Step 2: precompute（测试模式，5 样本）------"
        local out_dir="${DATA_DIR}/teacher_logits_test"
        rm -rf "${out_dir}"
    else
        echo ""
        echo "------ Step 2: precompute teacher logits（823 样本，~4h）------"
        local out_dir="${TEACHER_LOGITS_DIR}"
        if [ "${SKIP_PRECOMPUTE:-0}" = "1" ] && [ -f "${out_dir}/index.json" ]; then
            echo "  ⏭️  SKIP_PRECOMPUTE=1 且已有 index.json，跳过"
            return
        fi
        rm -rf "${out_dir}"
    fi

    ${AI_PYTHON} "${SCRIPT_DIR}/precompute_teacher_logits.py" \
        --backend ollama \
        --ollama-url "${OLLAMA_URL}" \
        --ollama-model "${OLLAMA_MODEL}" \
        --ollama-keepalive 300 \
        --ollama-max-tokens 1024 \
        --top-k ${TOP_K} \
        --output-dir "${out_dir}" \
        --resume \
        ${limit_arg}

    echo "  ✅ precompute 完成: ${out_dir}"
    if [ "${STEP}" = "test" ]; then
        echo ""
        echo "  验证 teacher answer 质量："
        ${AI_PYTHON} -c "
import torch
data = torch.load('${out_dir}/sample_0000.pt', weights_only=False)
print('=== Teacher answer 预览 ===')
print(data['teacher_answer'][:500])
print(f'\\n总 tokens: {data[\"indices\"].shape[0]}, K: {data[\"indices\"].shape[1]}')
print(f'前 3 位置 top-5 logprobs:')
for i in range(3):
    vals = data['values'][i][:5].tolist()
    print(f'  pos {i}: {[round(v,3) for v in vals]}')
"
    fi
}

# ============================================================================
# Step 3: 训练 student
# ============================================================================
run_train() {
    local limit_arg=""
    local suffix=""
    if [ "${STEP}" = "test" ]; then
        limit_arg="--limit 5"
        suffix="_test"
        local teacher_dir="${DATA_DIR}/teacher_logits_test"
    else
        local teacher_dir="${TEACHER_LOGITS_DIR}"
    fi

    if [ ! -f "${teacher_dir}/index.json" ]; then
        echo "❌ teacher_logits 索引不存在: ${teacher_dir}/index.json"
        echo "   先运行: bash $0 precompute"
        exit 1
    fi

    echo ""
    echo "------ Step 3: 训练 student（Prompt Distillation）------"
    echo "  Teacher logits: ${teacher_dir}"
    echo "  Loss: (1-α)×CE + α×KL, α=${ALPHA}, T=${TEMPERATURE}"

    export HF_HUB_OFFLINE=1
    export TOKENIZERS_PARALLELISM=false
    # RDNA4 优化（参考 docs/方法.md §12）
    export TORCH_ROCM_AOTRITON_ENABLE_EXPERIMENTAL=1

    # TunableOp（如果离线调优已生成 tuned 表，自动启用）
    TUNABLEOP_CSV="${PROJECT_ROOT}/experiments/exp_06_finetune/configs/tunableop_tuned.csv"
    if [ -f "${TUNABLEOP_CSV}" ]; then
        export PYTORCH_TUNABLEOP_ENABLED=1
        export PYTORCH_TUNABLEOP_TUNING=0
        export PYTORCH_TUNABLEOP_FILE_NAME="${TUNABLEOP_CSV}"
        echo "[Phase 4] TunableOp 已启用: ${TUNABLEOP_CSV}"
    fi

    ${AI_PYTHON} "${SCRIPT_DIR}/train_prompt_distillation.py" \
        --teacher-logits "${teacher_dir}" \
        --model "${STUDENT_MODEL}" \
        --alpha ${ALPHA} \
        --temperature ${TEMPERATURE} \
        --epochs 1 \
        --lr 1e-4 \
        --lora-r 32 --lora-alpha 64 \
        --use-rslora \
        --batch-size 1 --grad-accum 8 \
        --output-suffix "_phase4_ollama30b${suffix}" \
        ${limit_arg}
}

# ============================================================================
# Step 4: 评估
# ============================================================================
run_eval() {
    # 找最新的 phase4 adapter
    local adapter_dir=$(ls -dt ${OUTPUTS_DIR}/pd_r32_*_phase4_ollama30b*/best 2>/dev/null | head -1)
    if [ -z "${adapter_dir}" ]; then
        # 兜底：找最新的 pd_r32 目录
        adapter_dir=$(ls -dt ${OUTPUTS_DIR}/pd_r32_*/best 2>/dev/null | head -1)
    fi
    if [ -z "${adapter_dir}" ]; then
        echo "❌ 未找到 Phase 4 adapter 目录"
        exit 1
    fi

    echo ""
    echo "------ Step 4: 评估 Phase 4 adapter ------"
    echo "  adapter: ${adapter_dir}"
    echo "  base model: ${STUDENT_MODEL}"

    export HF_HUB_OFFLINE=1
    export TOKENIZERS_PARALLELISM=false

    ${AI_PYTHON} "${SCRIPT_DIR}/evaluate.py" \
        --mode finetuned \
        --adapter-path "${adapter_dir}" \
        --model-id "${STUDENT_MODEL}" \
        --temperature 0.0

    # 重命名为带 tag 的文件
    local latest=$(ls -1t ${RESULTS_DIR}/exp_06_eval.finetuned_custom.*.json 2>/dev/null | head -1)
    if [ -n "${latest}" ]; then
        local ts=$(date +%Y%m%d_%H%M%S)
        local new_name="${RESULTS_DIR}/exp_06_eval.phase4_ollama30b.${ts}.json"
        mv "${latest}" "${new_name}"
        echo "  → ${new_name}"
    fi
}

# ============================================================================
# 主流程
# ============================================================================
case "${STEP}" in
    test)
        check_ollama
        run_precompute
        # test 模式不跑完整训练，只验证脚本能跑通
        echo ""
        echo "✅ 测试模式完成（未跑完整训练）"
        echo "   要跑完整流程: bash $0 all"
        ;;
    precompute)
        check_ollama
        run_precompute
        ;;
    train)
        run_train
        ;;
    eval)
        run_eval
        ;;
    all)
        check_ollama
        run_precompute
        run_train
        run_eval
        ;;
    *)
        echo "未知 step: ${STEP}"
        echo "用法: bash $0 [test|precompute|train|eval|all]"
        exit 1
        ;;
esac

echo ""
echo "✅ Phase 4 流程完成"
