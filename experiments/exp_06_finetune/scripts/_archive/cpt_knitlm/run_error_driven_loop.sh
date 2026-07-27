#!/bin/bash
# ============================================================================
# 错题驱动闭环主控脚本
#
# 依据 docs/对话.md 的"错题闭环"范式：
#   evaluate → extract errors → augment → retrain → re-evaluate
#
# 流程：
#   Round N:
#     Step 1: 评估当前模型（evaluate.py --ollama-model）
#     Step 2: 提取错题（extract_phase3_errors.py）
#     Step 3: 选择增强数据（select_supplements.py）
#     Step 4: 合并增强数据（merge_supplements.py）
#     Step 5: 重训 SFT（train_qlora.py --epochs 1）
#     Step 6: 再评估（evaluate.py --mode finetuned）
#     Step 7: 对比结果
#
# 安全措施：
#   - 最大 2 轮（--max-rounds，默认 2）
#   - 每轮保留 30% replay（旧训练数据随机采样）
#   - dev_loss early stopping（patience=2）
#   - Ollama 后端评估（不占训练 GPU）
#
# 用法：
#   bash experiments/exp_06_finetune/scripts/run_error_driven_loop.sh [step]
#
# 参数：
#   无参数/step=all    跑完整闭环（默认最多 2 轮）
#   step=evaluate      只跑评估
#   step=extract       只跑错题提取
#   step=select        只跑增强选择
#   step=merge         只跑数据合并
#   step=train         只跑训练
#   step=compare       只跑结果对比
#   step=dry-run       仅打印将执行的命令，不实际运行
#
# 环境变量：
#   MAX_ROUNDS=2                    最大闭环轮数
#   OLLAMA_MODEL=qwen2.5-coder:7b  评估用 Ollama 模型
#   BASE_DATA=train_chatml_v2.jsonl 基础训练数据
#   SUPPLEMENT_WEIGHT=2.0           错题相关增强权重
#   SFT_EPOCHS=1                    每轮训练 epoch 数
#   LORA_R=16                       LoRA rank
#   LORA_ALPHA=32                   LoRA alpha
# ============================================================================

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PYTHON="python3"
SCRIPT_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/scripts"
DATA_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/data"
OUTPUTS_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/outputs"
RESULTS_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/results"

# 配置
MAX_ROUNDS="${MAX_ROUNDS:-2}"
OLLAMA_MODEL="${OLLAMA_MODEL:-qwen3:8b}"
BASE_DATA="${BASE_DATA:-train_chatml_v2.jsonl}"
SUPPLEMENT_WEIGHT="${SUPPLEMENT_WEIGHT:-2.0}"
SFT_EPOCHS="${SFT_EPOCHS:-1}"
LORA_R="${LORA_R:-16}"
LORA_ALPHA="${LORA_ALPHA:-32}"
LR="${LR:-1e-4}"  # 与 run_all.sh 默认一致（train_qlora.py 默认 1e-5 偏低）
SEED="${SEED:-42}"

# LR 格式化（与 train_qlora.py 的 {lr:g} 一致：1e-4 → 0.0001，1e-5 → 1e-05）
LR_FORMATTED=$(printf "%g" "${LR}")

STEP="${1:-all}"
DRY_RUN=false
if [ "${STEP}" = "dry-run" ]; then
    DRY_RUN=true
    STEP=all
fi

# 辅助函数
run_cmd() {
    echo "🔧 $@"
    if [ "${DRY_RUN}" = "true" ]; then
        echo "   [DRY RUN] 跳过实际执行"
    else
        "$@"
    fi
}

# ============================================================================
# Step 1: 评估当前模型
# ============================================================================
do_evaluate() {
    local round="$1"
    local suffix="_loop_r${round}"
    echo ""
    echo "=========================================="
    echo "Step 1: 评估当前模型 (Round ${round})"
    echo "=========================================="

    run_cmd ${PYTHON} "${SCRIPT_DIR}/evaluate.py" \
        --ollama-model "${OLLAMA_MODEL}" \
        --output-suffix "${suffix}"
}

# ============================================================================
# Step 2: 提取错题
# ============================================================================
do_extract_errors() {
    local round="$1"
    echo ""
    echo "=========================================="
    echo "Step 2: 提取错题 (Round ${round})"
    echo "=========================================="

    run_cmd ${PYTHON} "${SCRIPT_DIR}/extract_phase3_errors.py"
}

# ============================================================================
# Step 3: 选择增强数据
# ============================================================================
do_select_supplements() {
    local round="$1"
    local error_json="${RESULTS_DIR}/phase3_vs_phase1_regression.json"
    local output="${DATA_DIR}/selected_supplements_r${round}.json"

    echo ""
    echo "=========================================="
    echo "Step 3: 选择增强数据 (Round ${round})"
    echo "=========================================="

    # 检查是否有 probe_report
    local probe_arg=""
    if [ -f "${DATA_DIR}/probe_report.json" ]; then
        probe_arg="--probe-report ${DATA_DIR}/probe_report.json"
        echo "  发现 probe_report.json，将追加探测补充"
    fi

    run_cmd ${PYTHON} "${SCRIPT_DIR}/select_supplements.py" \
        --error-json "${error_json}" \
        ${probe_arg} \
        --output "${output}"
}

# ============================================================================
# Step 4: 合并增强数据
# ============================================================================
do_merge_supplements() {
    local round="$1"
    local supplement_config="${DATA_DIR}/selected_supplements_r${round}.json"
    local output="${DATA_DIR}/merged_error_driven_r${round}.jsonl"

    echo ""
    echo "=========================================="
    echo "Step 4: 合并增强数据 (Round ${round})"
    echo "=========================================="

    run_cmd ${PYTHON} "${SCRIPT_DIR}/merge_supplements.py" \
        --base-data "${DATA_DIR}/${BASE_DATA}" \
        --supplement-config "${supplement_config}" \
        --supplement-weight "${SUPPLEMENT_WEIGHT}" \
        --output "${output}"
}

# ============================================================================
# Step 5: 重训 SFT
# ============================================================================
do_train() {
    local round="$1"
    local merged_data="${DATA_DIR}/merged_error_driven_r${round}.jsonl"
    local output_suffix="_loop_r${round}"

    echo ""
    echo "=========================================="
    echo "Step 5: 重训 SFT (Round ${round})"
    echo "=========================================="

    run_cmd ${PYTHON} "${SCRIPT_DIR}/train_qlora.py" \
        --data-file "${merged_data}" \
        --epochs "${SFT_EPOCHS}" \
        --lr "${LR}" \
        --lora-r "${LORA_R}" \
        --lora-alpha "${LORA_ALPHA}" \
        --seed "${SEED}" \
        --output-suffix "${output_suffix}"
}

# ============================================================================
# Step 6: 再评估
# ============================================================================
do_re_evaluate() {
    local round="$1"
    local output_suffix="_loop_r${round}_after"

    echo ""
    echo "=========================================="
    echo "Step 6: 再评估 (Round ${round})"
    echo "=========================================="

    # 评估重训后的模型（路径含 lr 段，与 train_qlora.py 输出目录规则一致）
    local adapter_dir="${OUTPUTS_DIR}/lora_r${LORA_R}_a${LORA_ALPHA}_e${SFT_EPOCHS}_lr${LR_FORMATTED}_s${SEED}${output_suffix}/best"
    if [ ! -d "${adapter_dir}" ]; then
        # 尝试不带 output_suffix 的默认路径
        adapter_dir="${OUTPUTS_DIR}/lora_r${LORA_R}_a${LORA_ALPHA}_e${SFT_EPOCHS}_lr${LR_FORMATTED}_s${SEED}/best"
    fi

    run_cmd ${PYTHON} "${SCRIPT_DIR}/evaluate.py" \
        --mode finetuned \
        --adapter-path "${adapter_dir}" \
        --output-suffix "${output_suffix}"
}

# ============================================================================
# Step 7: 对比结果
# ============================================================================
do_compare() {
    local round="$1"
    echo ""
    echo "=========================================="
    echo "Step 7: 对比结果 (Round ${round})"
    echo "=========================================="

    # 查找本轮的评估结果
    local before_file=$(ls -t ${RESULTS_DIR}/exp_06_eval.*loop_r${round}.json 2>/dev/null | head -1)
    local after_file=$(ls -t ${RESULTS_DIR}/exp_06_eval.*loop_r${round}_after.json 2>/dev/null | head -1)

    if [ -n "${before_file}" ] && [ -n "${after_file}" ]; then
        echo "  评估前: ${before_file}"
        echo "  评估后: ${after_file}"
        echo ""
        echo "  请运行以下命令对比："
        echo "  ${PYTHON} ${SCRIPT_DIR}/compare_results.py ${before_file} ${after_file}"
    else
        echo "  ⚠️ 未找到评估结果文件，请手动对比"
        echo "  评估前: ${before_file:-未找到}"
        echo "  评估后: ${after_file:-未找到}"
    fi
}

# ============================================================================
# 主流程
# ============================================================================
echo "=========================================="
echo "错题驱动闭环 (Error-Driven Closed Loop)"
echo "=========================================="
echo "  Ollama 评估模型: ${OLLAMA_MODEL}"
echo "  基础训练数据: ${BASE_DATA}"
echo "  增强权重: ${SUPPLEMENT_WEIGHT}"
echo "  SFT epochs: ${SFT_EPOCHS}"
echo "  LoRA: r=${LORA_R} alpha=${LORA_ALPHA}"
echo "  最大轮数: ${MAX_ROUNDS}"
echo "  步骤: ${STEP}"
if [ "${DRY_RUN}" = "true" ]; then
    echo "  模式: DRY RUN（仅打印命令）"
fi
echo ""

# 单步执行
case "${STEP}" in
    evaluate)
        do_evaluate 1
        ;;
    extract)
        do_extract_errors 1
        ;;
    select)
        do_select_supplements 1
        ;;
    merge)
        do_merge_supplements 1
        ;;
    train)
        do_train 1
        ;;
    compare)
        do_compare 1
        ;;
    all)
        # 完整闭环
        for round in $(seq 1 ${MAX_ROUNDS}); do
            echo ""
            echo "##############################################"
            echo "# Round ${round} / ${MAX_ROUNDS}"
            echo "##############################################"

            do_evaluate ${round}
            do_extract_errors ${round}
            do_select_supplements ${round}
            do_merge_supplements ${round}
            do_train ${round}
            do_re_evaluate ${round}
            do_compare ${round}

            echo ""
            echo "✅ Round ${round} 完成"
            echo ""
        done

        echo "=========================================="
        echo "🎉 错题驱动闭环全部完成！共 ${MAX_ROUNDS} 轮"
        echo "=========================================="
        ;;
    *)
        echo "未知步骤: ${STEP}"
        echo "可选: all / evaluate / extract / select / merge / train / compare / dry-run"
        exit 1
        ;;
esac
