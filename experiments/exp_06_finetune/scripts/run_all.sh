#!/bin/bash
# ============================================================================
# exp_06_finetune 完整运行脚本
#
# 数据流：
#   build_dataset.py          → train_chatml.jsonl              (222 手写样本)
#   generate_distill_data.py  → distill_corpus_annotated.jsonl  (400 蒸馏 v1)
#   regenerate_cot_with_teacher.py → distill_corpus_annotated_v2.jsonl (400 v2, 教师CoT)
#   supplement_hard_samples.py → supplement_chatml.jsonl        (49 对抗补充)
#   combine_and_augment.py    → train_chatml_v2.jsonl           (671 最终训练集)
#
# 流程：
#   0. 环境检查
#   1. 构建训练数据集（222 原始 + 400 蒸馏v2 + 49 补充 → 671 条）
#   2. 单种子训练（LoRA + early stopping + dev split + best checkpoint）
#   3. 评估基座（确定性解码，temperature=0.0）
#   4. 评估微调后模型（用 best checkpoint）
#   5. Bootstrap 显著性检验（baseline vs finetuned）
#   6. （可选）多种子训练 + 评估
#   7. （可选）CVE-fix held-out 独立测试集评估
#
# 用法：
#   cd /home/zane/文档/code/毕业设计
#   bash experiments/exp_06_finetune/scripts/run_all.sh
#
# 可选标志（环境变量）：
#   SKIP_TRAIN=1      跳过训练，只评估现有 checkpoint
#   MULTISEED=1       启用多种子训练 + 评估
#   CVE_FIX=1         启用 CVE-fix held-out 测试集评估
#   SEED=42           单种子训练的种子（默认 42）
#   EPOCHS=3          训练轮数（默认 3，上次 5 轮在 epoch 3 后严重过拟合）
#   LR=5e-5           学习率（默认 5e-5，2e-4 对 LoRA r=16 偏高）
#
# 注意：在真实终端运行（非 IDE 沙箱），需 GPU + 网络访问。
# ============================================================================

set -e

PROJECT_ROOT="/home/zane/文档/code/毕业设计"
AI_PYTHON="/home/zane/miniconda3/envs/AI/bin/python"
GRAFROJ_PYTHON="/home/zane/miniconda3/envs/graproj/bin/python3"
MODEL_ID="Qwen/Qwen2.5-Coder-3B-Instruct"

# 训练超参（默认值已根据上次 trainer_state.json 过拟合分析调整）
EPOCHS="${EPOCHS:-3}"
LORA_R="${LORA_R:-16}"
LORA_ALPHA="${LORA_ALPHA:-32}"
SEED="${SEED:-42}"
BATCH_SIZE="${BATCH_SIZE:-1}"
GRAD_ACCUM="${GRAD_ACCUM:-8}"
LR="${LR:-1e-4}"

# 训练数据文件（train_chatml_v2.jsonl = 222 原始 + 400 蒸馏v2 + 49 补充 + 35 长尾CWE = 706 条）
DATA_FILE="${PROJECT_ROOT}/experiments/exp_06_finetune/data/train_chatml_v2.jsonl"

# Checkpoint 路径（与 train_qlora.py 输出目录规则一致）
ADAPTER_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/outputs/lora_r${LORA_R}_a${LORA_ALPHA}_e${EPOCHS}_s${SEED}/best"

# 环境变量（ROCm + HF 离线）
export HF_ENDPOINT="https://hf-mirror.com"
export HF_HUB_ENABLE_HF_TRANSFER="0"
export TOKENIZERS_PARALLELISM="false"
export HF_HUB_OFFLINE="1"
export TRANSFORMERS_OFFLINE="1"
export OLLAMA_FLASH_ATTENTION="true"
# ROCm 可能报告多个 GPU 设备，强制只用第一个，防止 DataParallel 跨不存在设备
export CUDA_VISIBLE_DEVICES="0"
export HIP_VISIBLE_DEVICES="0"

cd "${PROJECT_ROOT}"

echo "============================================================"
echo "exp_06_finetune 完整流程"
echo "============================================================"
echo "模型: ${MODEL_ID}"
echo "训练数据: ${DATA_FILE}"
echo "LoRA: r=${LORA_R} alpha=${LORA_ALPHA} epochs=${EPOCHS} seed=${SEED} lr=${LR}"
echo "适配器输出: ${ADAPTER_DIR}"
echo ""

# ----------------------------------------------------------------------------
# 阶段 0：环境检查
# ----------------------------------------------------------------------------
echo "============================================================"
echo "阶段 0：环境检查"
echo "============================================================"
${AI_PYTHON} -c "
import torch
print('PyTorch:', torch.__version__)
print('HIP:', torch.version.hip)
print('GPU available:', torch.cuda.is_available())
if torch.cuda.is_available():
    print('GPU:', torch.cuda.get_device_name(0))
    print('VRAM:', round(torch.cuda.get_device_properties(0).total_memory/1e9, 2), 'GB')
import peft, trl, transformers
print('peft:', peft.__version__, 'trl:', trl.__version__, 'transformers:', transformers.__version__)
"

# ----------------------------------------------------------------------------
# 阶段 1：构建训练数据集（222 原始 + 400 蒸馏v2 + 49 补充 → 671 条）
# ----------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "阶段 1：构建训练数据集"
echo "============================================================"
# 1a. 原始手写样本（222 条，42 CWE，9 语言）
PYTHONPATH=${PROJECT_ROOT} ${GRAFROJ_PYTHON} experiments/exp_06_finetune/scripts/build_dataset.py
# 1b. 蒸馏标注样本 v1（400 条，模板 CoT，作为 regenerate_cot_with_teacher.py 的输入）
PYTHONPATH=${PROJECT_ROOT} ${GRAFROJ_PYTHON} experiments/exp_06_finetune/scripts/generate_distill_data.py
# 1c. 合并所有数据源 → train_chatml_v2.jsonl（671 条）
#     注：distill_corpus_annotated_v2.jsonl 和 supplement_chatml.jsonl 为预生成资产，
#     若需重新生成，手动运行：
#       regenerate_cot_with_teacher.py（需 Ollama qwen2.5-coder:7b 教师模型）
#       supplement_hard_samples.py
PYTHONPATH=${PROJECT_ROOT} ${GRAFROJ_PYTHON} experiments/exp_06_finetune/scripts/combine_and_augment.py

# ----------------------------------------------------------------------------
# 阶段 2：单种子训练
# ----------------------------------------------------------------------------
if [ -z "$SKIP_TRAIN" ]; then
    echo ""
    echo "============================================================"
    echo "阶段 2：单种子训练（seed=${SEED}, epochs=${EPOCHS}, lr=${LR}）"
    echo "============================================================"
    PYTHONPATH=${PROJECT_ROOT} ${AI_PYTHON} experiments/exp_06_finetune/scripts/train_qlora.py \
        --epochs ${EPOCHS} \
        --batch-size ${BATCH_SIZE} \
        --grad-accum ${GRAD_ACCUM} \
        --lr ${LR} \
        --lora-r ${LORA_R} \
        --lora-alpha ${LORA_ALPHA} \
        --max-seq-length 2048 \
        --seed ${SEED} \
        --dev-ratio 0.15 \
        --early-stopping-patience 2 \
        --data-file "${DATA_FILE}"
else
    echo ""
    echo "阶段 2：跳过训练（SKIP_TRAIN=1）"
fi

# ----------------------------------------------------------------------------
# 阶段 3：评估基座（对照组，确定性解码）
# ----------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "阶段 3：评估基座（temperature=0.0 确定性解码）"
echo "============================================================"
PYTHONPATH=${PROJECT_ROOT} ${AI_PYTHON} experiments/exp_06_finetune/scripts/evaluate.py \
    --mode baseline

BASELINE_RESULT=$(ls -t ${PROJECT_ROOT}/experiments/exp_06_finetune/results/exp_06_eval.baseline.*.json | head -1)
echo "基线结果: ${BASELINE_RESULT}"

# ----------------------------------------------------------------------------
# 阶段 4：评估微调后模型（best checkpoint，确定性解码）
# ----------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "阶段 4：评估微调后模型（best checkpoint, temperature=0.0）"
echo "============================================================"
if [ ! -d "${ADAPTER_DIR}" ]; then
    echo "错误：适配器目录不存在: ${ADAPTER_DIR}"
    echo "请先运行训练，或检查 SEED/EPOCHS 环境变量是否与训练时一致"
    exit 1
fi
PYTHONPATH=${PROJECT_ROOT} ${AI_PYTHON} experiments/exp_06_finetune/scripts/evaluate.py \
    --mode finetuned \
    --adapter-path "${ADAPTER_DIR}"

FINETUNED_RESULT=$(ls -t ${PROJECT_ROOT}/experiments/exp_06_finetune/results/exp_06_eval.finetuned_*.json | head -1)
echo "微调结果: ${FINETUNED_RESULT}"

# ----------------------------------------------------------------------------
# 阶段 5：Bootstrap 显著性检验
# ----------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "阶段 5：Bootstrap 显著性检验（baseline vs finetuned）"
echo "============================================================"
PYTHONPATH=${PROJECT_ROOT} ${GRAFROJ_PYTHON} experiments/exp_06_finetune/scripts/bootstrap_significance.py \
    --baseline "${BASELINE_RESULT}" \
    --finetuned "${FINETUNED_RESULT}" \
    --n-bootstrap 10000

# ----------------------------------------------------------------------------
# 阶段 6：（可选）多种子训练 + 评估
# ----------------------------------------------------------------------------
if [ "$MULTISEED" = "1" ]; then
    echo ""
    echo "============================================================"
    echo "阶段 6：多种子训练 + 评估（seeds=42,1042,2042）"
    echo "============================================================"
    PYTHONPATH=${PROJECT_ROOT} ${AI_PYTHON} experiments/exp_06_finetune/scripts/run_multiseed.py \
        --epochs ${EPOCHS} \
        --lora-r ${LORA_R} \
        --lora-alpha ${LORA_ALPHA} \
        --data-file "${DATA_FILE}"
else
    echo ""
    echo "阶段 6：跳过多种子训练（MULTISEED=1 启用）"
fi

# ----------------------------------------------------------------------------
# 阶段 7：（可选）CVE-fix held-out 独立测试集评估
# ----------------------------------------------------------------------------
if [ "$CVE_FIX" = "1" ]; then
    echo ""
    echo "============================================================"
    echo "阶段 7：CVE-fix held-out 独立测试集评估"
    echo "============================================================"
    TESTSET_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/testset_cve_fix"
    if [ ! -d "${TESTSET_DIR}" ]; then
        echo "测试集不存在，先抓取（需 GITHUB_TOKEN 环境变量）..."
        PYTHONPATH=${PROJECT_ROOT} ${GRAFROJ_PYTHON} experiments/exp_06_finetune/scripts/prepare_cve_fix_testset.py \
            --max-samples 30 --language python
    fi
    echo "CVE-fix 测试集 manifest 格式与 exp_04 不同，需手动适配 evaluate.py："
    echo "  - manifest 路径: ${TESTSET_DIR}/manifest.json"
    echo "  - 适配器: ${ADAPTER_DIR}"
    echo "  - 参考 evaluate.py 的 MANIFEST_PATH 常量做临时修改后运行"
else
    echo ""
    echo "阶段 7：跳过 CVE-fix 测试集（CVE_FIX=1 启用）"
fi

# ----------------------------------------------------------------------------
# 汇总
# ----------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "完成！结果文件："
echo "============================================================"
ls -lt ${PROJECT_ROOT}/experiments/exp_06_finetune/results/ | head -10
echo ""
echo "关键指标对比："
echo "  1. 看 baseline vs finetuned 的 recall/accuracy/fpr"
echo "  2. 看 bootstrap_significance 的 p 值（<0.05 为显著）"
echo "  3. 若启用多种子，看 mean±std 是否稳定"
