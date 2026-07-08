#!/bin/bash
# ============================================================================
# exp_06_finetune 完整运行脚本（P0+P1 改造版）
#
# 流程：
#   0. 环境检查
#   1. 构建训练数据集（222 样本，42 CWE，9 语言）
#   2. 数据增强（变量重命名 + 日志注入 + 注释混淆，222→666 样本）
#   3. 单种子训练（5 epochs + early stopping + dev split + best checkpoint）
#   4. 评估基座（确定性解码，temperature=0.0）
#   5. 评估微调后模型（用 best checkpoint）
#   6. Bootstrap 显著性检验（baseline vs finetuned）
#   7. （可选）多种子训练 + 评估（更严格的显著性检验）
#   8. （可选）CVE-fix held-out 独立测试集评估
#
# 用法：
#   cd /home/zane/文档/code/毕业设计
#   bash experiments/exp_06_finetune/scripts/run_all.sh
#
# 可选标志（环境变量）：
#   SKIP_TRAIN=1            跳过训练，只评估现有 checkpoint
#   SKIP_MULTISEED=1        跳过多种子训练（默认跳过，需 --multiseed 启用）
#   MULTISEED=1             启用多种子训练 + 评估
#   CVE_FIX=1               启用 CVE-fix held-out 测试集评估
#   USE_AUGMENTED=0         不用增强数据训练（默认 1 用增强数据）
#   SEED=42                 单种子训练的种子（默认 42）
#
# 注意：在真实终端运行（非 IDE 沙箱），需 GPU + 网络访问。
# ============================================================================

set -e

PROJECT_ROOT="/home/zane/文档/code/毕业设计"
AI_PYTHON="/home/zane/miniconda3/envs/AI/bin/python"
GRAFROJ_PYTHON="/home/zane/miniconda3/envs/graproj/bin/python3"
MODEL_ID="Qwen/Qwen2.5-Coder-3B-Instruct"

# 训练超参
EPOCHS="${EPOCHS:-5}"
LORA_R="${LORA_R:-16}"
LORA_ALPHA="${LORA_ALPHA:-32}"
SEED="${SEED:-42}"
BATCH_SIZE="${BATCH_SIZE:-1}"
GRAD_ACCUM="${GRAD_ACCUM:-8}"
LR="${LR:-2e-4}"

# 数据文件选择
#   USE_COMBINED=1（默认）：用合并数据（原始增强 666 + 蒸馏 400 + 蒸馏增强 800 = 1866 条）
#   USE_AUGMENTED=1       ：仅用原始增强数据（666 条）
#   都不设                ：仅用原始数据（222 条）
USE_COMBINED="${USE_COMBINED:-1}"
USE_AUGMENTED="${USE_AUGMENTED:-0}"
if [ "$USE_COMBINED" = "1" ]; then
    DATA_FILE="${PROJECT_ROOT}/experiments/exp_06_finetune/data/combined_train_chatml.jsonl"
elif [ "$USE_AUGMENTED" = "1" ]; then
    DATA_FILE="${PROJECT_ROOT}/experiments/exp_06_finetune/data/augmented_train_chatml.jsonl"
else
    DATA_FILE="${PROJECT_ROOT}/experiments/exp_06_finetune/data/train_chatml.jsonl"
fi

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
echo "exp_06_finetune 完整流程（P0+P1 改造版）"
echo "============================================================"
echo "模型: ${MODEL_ID}"
echo "训练数据: ${DATA_FILE}"
echo "LoRA: r=${LORA_R} alpha=${LORA_ALPHA} epochs=${EPOCHS} seed=${SEED}"
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
# 阶段 1：构建训练数据集（原始 222 条 + 蒸馏 400 条 + 增强合并到 1866 条）
# ----------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "阶段 1：构建训练数据集"
echo "============================================================"
# 1a. 原始手写样本（222 条）
PYTHONPATH=${PROJECT_ROOT} ${GRAFROJ_PYTHON} experiments/exp_06_finetune/scripts/build_dataset.py
# 1b. 蒸馏标注样本（400 条，由 GLM-5.2 生成 CoT）
PYTHONPATH=${PROJECT_ROOT} ${GRAFROJ_PYTHON} experiments/exp_06_finetune/scripts/generate_distill_data.py
# 1c. 蒸馏 → ChatML 格式转换
PYTHONPATH=${PROJECT_ROOT} ${GRAFROJ_PYTHON} experiments/exp_06_finetune/scripts/format_distilled.py \
    --input experiments/exp_06_finetune/data/distill_corpus_annotated.jsonl \
    --output experiments/exp_06_finetune/data/train_chatml_distilled.jsonl

# ----------------------------------------------------------------------------
# 阶段 2：数据增强 + 合并（666 增强 + 400 蒸馏 + 800 蒸馏增强 = 1866 条）
# ----------------------------------------------------------------------------
if [ "$USE_COMBINED" = "1" ] || [ "$USE_AUGMENTED" = "1" ]; then
    echo ""
    echo "============================================================"
    echo "阶段 2：数据增强 + 合并"
    echo "============================================================"
    # 先对原始数据做增强
    PYTHONPATH=${PROJECT_ROOT} ${GRAFROJ_PYTHON} experiments/exp_06_finetune/scripts/augment_data.py \
        --variants 2 --append
    # 如果用合并模式，再合并蒸馏数据 + 蒸馏增强
    if [ "$USE_COMBINED" = "1" ]; then
        PYTHONPATH=${PROJECT_ROOT} ${GRAFROJ_PYTHON} experiments/exp_06_finetune/scripts/combine_and_augment.py
    fi
else
    echo ""
    echo "阶段 2：跳过数据增强（USE_COMBINED=0 USE_AUGMENTED=0）"
fi

# ----------------------------------------------------------------------------
# 阶段 3：单种子训练
# ----------------------------------------------------------------------------
if [ -z "$SKIP_TRAIN" ]; then
    echo ""
    echo "============================================================"
    echo "阶段 3：单种子训练（seed=${SEED}, epochs=${EPOCHS} + early stopping）"
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
    echo "阶段 3：跳过训练（SKIP_TRAIN=1）"
fi

# ----------------------------------------------------------------------------
# 阶段 4：评估基座（对照组，确定性解码）
# ----------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "阶段 4：评估基座（temperature=0.0 确定性解码）"
echo "============================================================"
PYTHONPATH=${PROJECT_ROOT} ${AI_PYTHON} experiments/exp_06_finetune/scripts/evaluate.py \
    --mode baseline

BASELINE_RESULT=$(ls -t ${PROJECT_ROOT}/experiments/exp_06_finetune/results/exp_06_eval.baseline.*.json | head -1)
echo "基线结果: ${BASELINE_RESULT}"

# ----------------------------------------------------------------------------
# 阶段 5：评估微调后模型（best checkpoint，确定性解码）
# ----------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "阶段 5：评估微调后模型（best checkpoint, temperature=0.0）"
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
# 阶段 6：Bootstrap 显著性检验
# ----------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "阶段 6：Bootstrap 显著性检验（baseline vs finetuned）"
echo "============================================================"
PYTHONPATH=${PROJECT_ROOT} ${GRAFROJ_PYTHON} experiments/exp_06_finetune/scripts/bootstrap_significance.py \
    --baseline "${BASELINE_RESULT}" \
    --finetuned "${FINETUNED_RESULT}" \
    --n-bootstrap 10000

# ----------------------------------------------------------------------------
# 阶段 7：（可选）多种子训练 + 评估
# ----------------------------------------------------------------------------
if [ "$MULTISEED" = "1" ]; then
    echo ""
    echo "============================================================"
    echo "阶段 7：多种子训练 + 评估（seeds=42,1042,2042）"
    echo "============================================================"
    PYTHONPATH=${PROJECT_ROOT} ${AI_PYTHON} experiments/exp_06_finetune/scripts/run_multiseed.py \
        --epochs ${EPOCHS} \
        --lora-r ${LORA_R} \
        --lora-alpha ${LORA_ALPHA} \
        --data-file "${DATA_FILE}"
else
    echo ""
    echo "阶段 7：跳过多种子训练（MULTISEED=1 启用）"
fi

# ----------------------------------------------------------------------------
# 阶段 8：（可选）CVE-fix held-out 独立测试集评估
# ----------------------------------------------------------------------------
if [ "$CVE_FIX" = "1" ]; then
    echo ""
    echo "============================================================"
    echo "阶段 8：CVE-fix held-out 独立测试集评估"
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
    echo "阶段 8：跳过 CVE-fix 测试集（CVE_FIX=1 启用）"
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
