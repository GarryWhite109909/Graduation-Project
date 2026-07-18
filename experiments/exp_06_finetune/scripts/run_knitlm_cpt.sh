#!/bin/bash
# ============================================================================
# Phase 3: KnItLM 知识注入一键运行脚本
#
# 对应 docs/方法.md §9 Phase 3，原理见 §8.3 KnItLM
# 论文：KnItLM (ICLR 2026 投稿, https://openreview.net/forum?id=2uctT30vTS)
#
# 三阶段流程：
#   Step 1 (CPT, ~3-4h):    在 Qwen2.5-Coder-7B（base）上做 CPT with LoRA
#                           语料: data/cpt_corpus.jsonl (4.88MB, CVE/CWE/OWASP)
#                           得到注入漏洞知识的 LoRA adapter
#   Step 2 (Merge, ~10min): 把 CPT LoRA 合并到 Qwen2.5-Coder-7B-Instruct
#                           在 CPU 上 merge（省 GPU 显存），输出完整 fp16 模型
#   Step 3 (Eval, ~30min):  在 exp_04 87 段测试集上评估合并后的模型
#                           对比 Phase 1 baseline（未注入知识的 7B-Instruct）
#
# 设计要点：
#   - 必须用 base 模型做 CPT，避免破坏 Instruct 的对话能力（KnItLM 核心思想）
#   - CPT 用 causal LM loss，不是 SFT loss
#   - LoRA rank=64（CPT 容量需求高，比 SFT 的 r=8/32 大）
#   - merge 在 CPU 上做，避免 GPU 显存不足（7B fp16 ~14GB）
#
# 前置条件：
#   - data/cpt_corpus.jsonl 已存在（prepare_cpt_corpus.py 已运行）
#   - Qwen/Qwen2.5-Coder-7B 已下载（HF 本地缓存）
#   - GPU 空闲（VRAM > 12GB 可用）
#
# 用法：
#   bash experiments/exp_06_finetune/scripts/run_knitlm_cpt.sh [step]
#
# 参数：
#   无参数/step=all   跑完整流程（Step 1-3）
#   step=cpt          只跑 Step 1（CPT 训练）
#   step=merge        只跑 Step 2（LoRA 合并）
#   step=eval         只跑 Step 3（评估）
#   step=test         测试模式（CPT max_steps=5 验证脚本能跑通）
#
# 可选环境变量：
#   LORA_R=64          CPT LoRA rank
#   LORA_ALPHA=128     CPT LoRA alpha
#   EPOCHS=1           CPT 训练轮数
#   LR=2e-5            CPT 学习率（比 SFT 低）
#   SKIP_MERGE=0       跳过 Step 2（已有合并模型时设 1）
# ============================================================================

set -e

PROJECT_ROOT="/home/zane/文档/code/毕业设计"
AI_PYTHON="/home/zane/miniconda3/envs/AI/bin/python"
SCRIPT_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/scripts"
OUTPUTS_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/outputs"
LOG_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/logs"
DATA_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/data"
RESULTS_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/results"

# 配置（默认值对应 §9 Phase 3 推荐配置）
LORA_R="${LORA_R:-64}"
LORA_ALPHA="${LORA_ALPHA:-128}"
EPOCHS="${EPOCHS:-1}"
LR="${LR:-2e-5}"
BASE_MODEL="Qwen/Qwen2.5-Coder-7B"

# CPT adapter 输出目录（与 train_knitlm_cpt.py 的命名规则一致）
CPT_SUBDIR="knitlm_cpt_r${LORA_R}_a${LORA_ALPHA}_e${EPOCHS}_lr${LR}_rslora"
CPT_ADAPTER_DIR="${OUTPUTS_DIR}/${CPT_SUBDIR}/best"
MERGED_MODEL_DIR="${OUTPUTS_DIR}/knitlm_merged_7b_instruct"

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
    echo "[Phase 3] TunableOp 已启用: ${TUNABLEOP_CSV}"
fi

STEP="${1:-all}"
TEST_MODE=0
if [ "${STEP}" = "test" ]; then
    TEST_MODE=1
    STEP="cpt"
    EPOCHS=1
    echo "⚠️ 测试模式：CPT 只跑 5 step 验证脚本"
fi

echo "=========================================="
echo "Phase 3: KnItLM 知识注入"
echo "  Base 模型: ${BASE_MODEL}"
echo "  语料: ${DATA_DIR}/cpt_corpus.jsonl"
echo "  LoRA: r=${LORA_R} alpha=${LORA_ALPHA} rsLoRA=on"
echo "  训练: epochs=${EPOCHS} lr=${LR}"
echo "  CPT adapter: ${CPT_ADAPTER_DIR}"
echo "  合并模型: ${MERGED_MODEL_DIR}"
echo "  Step: ${STEP}"
echo "=========================================="

# 前置检查
if [ ! -f "${DATA_DIR}/cpt_corpus.jsonl" ]; then
    echo "❌ 语料文件不存在: ${DATA_DIR}/cpt_corpus.jsonl"
    echo "   先运行: ${AI_PYTHON} ${SCRIPT_DIR}/prepare_cpt_corpus.py"
    exit 1
fi

# ----------------------------------------------------------------------------
# Step 1: CPT 训练（base model + causal LM + LoRA）
# ----------------------------------------------------------------------------
run_cpt() {
    local ts=$(date +%Y%m%d_%H%M%S)
    local log="${LOG_DIR}/phase3_knitlm_cpt_${CPT_SUBDIR}_${ts}.log"
    echo ""
    echo "========== Step 1/3: CPT 训练 =========="
    echo "  在 ${BASE_MODEL} 上做 CPT with LoRA"
    echo "  预计耗时：3-4 小时（7B 4bit + r=64 + e=1）"
    echo "  Log: ${log}"
    echo "========================================="

    local extra_args=()
    if [ "${TEST_MODE}" = "1" ]; then
        # 测试模式：用 --no-early-stopping + 极小 dev ratio + 不存盘
        extra_args=(--no-early-stopping --dev-ratio 0.02 --save-steps 9999 --logging-steps 1)
    fi

    ${AI_PYTHON} "${SCRIPT_DIR}/train_knitlm_cpt.py" \
        --model "${BASE_MODEL}" \
        --corpus "${DATA_DIR}/cpt_corpus.jsonl" \
        --epochs ${EPOCHS} \
        --lr ${LR} \
        --batch-size 1 \
        --grad-accum 16 \
        --lora-r ${LORA_R} \
        --lora-alpha ${LORA_ALPHA} \
        --lora-dropout 0.05 \
        --use-rslora \
        --seed 42 \
        "${extra_args[@]}" \
        2>&1 | tee "${log}"

    if [ ! -d "${CPT_ADAPTER_DIR}" ]; then
        echo "❌ CPT 训练失败，adapter 未保存到 ${CPT_ADAPTER_DIR}"
        exit 1
    fi
    echo ""
    echo "✅ Step 1 完成：CPT adapter 已保存到 ${CPT_ADAPTER_DIR}"
}

# ----------------------------------------------------------------------------
# Step 2: LoRA 合并到 Instruct（CPU 上做，省 GPU 显存）
# ----------------------------------------------------------------------------
run_merge() {
    local ts=$(date +%Y%m%d_%H%M%S)
    local log="${LOG_DIR}/phase3_knitlm_merge_${ts}.log"
    echo ""
    echo "========== Step 2/3: LoRA 合并到 Instruct =========="
    echo "  把 CPT adapter 合并到 Qwen2.5-Coder-7B-Instruct"
    echo "  在 CPU 上 merge（7B fp16 ~14GB，CPU 32GB 内存足够）"
    echo "  预计耗时：~10 分钟"
    echo "  Log: ${log}"
    echo "===================================================="

    if [ ! -d "${CPT_ADAPTER_DIR}" ]; then
        echo "❌ CPT adapter 不存在: ${CPT_ADAPTER_DIR}"
        echo "   先跑 Step 1: bash $0 cpt"
        exit 1
    fi

    ${AI_PYTHON} "${SCRIPT_DIR}/merge_lora_to_instruct.py" \
        --cpt-adapter "${CPT_ADAPTER_DIR}" \
        --instruct-model "Qwen/Qwen2.5-Coder-7B-Instruct" \
        --output "${MERGED_MODEL_DIR}" \
        --dtype fp16 \
        2>&1 | tee "${log}"

    if [ ! -f "${MERGED_MODEL_DIR}/config.json" ]; then
        echo "❌ 合并失败，模型未保存到 ${MERGED_MODEL_DIR}"
        exit 1
    fi
    echo ""
    echo "✅ Step 2 完成：合并后的模型已保存到 ${MERGED_MODEL_DIR}"
}

# ----------------------------------------------------------------------------
# Step 3: 评估（在 exp_04 87 段测试集上）
# ----------------------------------------------------------------------------
run_eval() {
    local ts=$(date +%Y%m%d_%H%M%S)
    local result_json="${RESULTS_DIR}/exp_06_eval.knitlm_merged.${ts}.json"
    local log="${LOG_DIR}/phase3_knitlm_eval_${ts}.log"
    echo ""
    echo "========== Step 3/3: 评估合并后的模型 =========="
    echo "  测试集: exp_04_hard_samples 87 段"
    echo "  模型: ${MERGED_MODEL_DIR}"
    echo "  结果: ${result_json}"
    echo "  预计耗时：~30 分钟"
    echo "================================================"

    if [ ! -f "${MERGED_MODEL_DIR}/config.json" ]; then
        echo "❌ 合并模型不存在: ${MERGED_MODEL_DIR}"
        echo "   先跑 Step 2: bash $0 merge"
        exit 1
    fi

    ${AI_PYTHON} "${SCRIPT_DIR}/evaluate.py" \
        --mode baseline \
        --model-id "${MERGED_MODEL_DIR}" \
        --temperature 0.0 \
        2>&1 | tee "${log}"

    # evaluate.py 默认输出 exp_06_eval.baseline.*.json，重命名为 phase3 tag
    local latest=$(ls -1t ${RESULTS_DIR}/exp_06_eval.baseline.*.json 2>/dev/null | head -1)
    if [ -n "${latest}" ] && [ "${latest}" != "${result_json}" ]; then
        mv "${latest}" "${result_json}"
    fi

    echo ""
    echo "✅ Step 3 完成：评估结果已保存到 ${result_json}"
    echo ""
    echo "对比基准："
    echo "  Phase 1 baseline (7B-Instruct, lr=1e-5): 严格 recall=41.0%, FPR=11.5%, accuracy=92.0%"
    echo "  KnItLM 期望：注入漏洞领域知识后，严格 recall 提升（CWE 错标减少）"
}

case "${STEP}" in
    cpt)
        run_cpt
        ;;
    merge)
        run_merge
        ;;
    eval)
        run_eval
        ;;
    all)
        run_cpt
        echo ""
        echo "--------------------------------------------"
        echo "Step 1 完成，按 Enter 继续 Step 2 (merge)..."
        read -r
        run_merge
        echo ""
        echo "--------------------------------------------"
        echo "Step 2 完成，按 Enter 继续 Step 3 (eval)..."
        read -r
        run_eval
        ;;
    test)
        run_cpt
        ;;
    *)
        echo "用法: bash $0 [cpt|merge|eval|all|test]"
        exit 1
        ;;
esac

echo ""
echo "=========================================="
echo "Phase 3 KnItLM 流程结束"
echo "=========================================="
echo ""
echo "后续可选："
echo "  1. 用合并后的模型作为 SFT 基座（Phase 2 配置 + KnItLM base）"
echo "     ${AI_PYTHON} ${SCRIPT_DIR}/train_qlora.py \\"
echo "         --model-id ${MERGED_MODEL_DIR} \\"
echo "         --lora-r 32 --lora-alpha 64 --use-rslora --epochs 2 --lr 1e-5"
echo "  2. 跑 RAG 对照评估（看 KnItLM + RAG 是否进一步提升）"
echo "     RAG=1 bash ${SCRIPT_DIR}/run_phase2_eval.sh"