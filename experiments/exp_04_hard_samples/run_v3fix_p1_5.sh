#!/usr/bin/env bash
# exp_04 P1-5 修复后重跑（A/C/D 三组）
# 修复内容：knowledge.json 4 处事实错误 + 3 处代码示例语法 + prompts.py RAG 引导语中性化 + build_rag_context 区分 safe/danger 标签
# B 组（pure）不传 rag_context，prompt 改动不影响，无需重跑。

set -e
cd "$(dirname "$0")"
mkdir -p results

PY=/home/zane/miniconda3/envs/graproj/bin/python3
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
MODEL=qwen2.5-coder:7b

echo "============================================================"
echo "[v3 fix] P1-5 修复后重跑 A/C/D 三组, 模型 $MODEL, 开始 $(date +'%F %T')"
echo "============================================================"
$PY -c "import chromadb; print(f'[info] chromadb {chromadb.__version__} ok')"

echo
echo ">>> [1/3] A 组 RAG+LLM (top-k=3) - 修复后"
date +"开始: %F %T"
$PY -u run_rag_experiment.py --mode rag --top-k 3 --model $MODEL \
    --output results/results.ablation.rag.topk3.qwen7b.v3fix.json
date +"完成: %F %T"

echo
echo ">>> [2/3] C 组 随机知识 - 修复后"
date +"开始: %F %T"
$PY -u run_rag_experiment.py --mode random --top-k 3 --model $MODEL \
    --output results/results.ablation.random.topk3.qwen7b.v3fix.json
date +"完成: %F %T"

echo
echo ">>> [3/3] D 组 等长无关文本 - 修复后"
date +"开始: %F %T"
$PY -u run_rag_experiment.py --mode irrelevant --model $MODEL \
    --output results/results.ablation.irrelevant.topk3.qwen7b.v3fix.json
date +"完成: %F %T"

echo
echo "============================================================"
echo "[完成] 三组重跑结束 $(date +'%F %T')"
echo "============================================================"
