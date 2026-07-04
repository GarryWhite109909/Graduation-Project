#!/usr/bin/env bash
# exp_04 v2 消融实验重跑：prompt + RAG 修复后，4 组 × 87 样本
#
# 用法：
#   nohup bash run_ablation_v2_rerun.sh > results/ablation_v2_rerun.log 2>&1 &
#
# 完成后结果落在 results/results.ablation.*.qwen7b.v2.json，由 generate_report.py 汇总。

set -e
cd "$(dirname "$0")"
mkdir -p results

PY=/home/zane/miniconda3/envs/graproj/bin/python3
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
MODEL=qwen2.5-coder:7b

echo "============================================================"
echo "[消融重跑] prompt+RAG 修复后, 模型 $MODEL, 87 样本 × 4 组"
echo "开始: $(date +'%F %T')"
echo "============================================================"
$PY -c "import chromadb; print(f'[信息] chromadb {chromadb.__version__} 可用')"

echo
echo ">>> [1/4] A 组 RAG+LLM (top-k=3)"
date +"开始: %F %T"
$PY -u run_rag_experiment.py --mode rag --top-k 3 --model $MODEL \
    --output results/results.ablation.rag.topk3.qwen7b.v2.json
date +"完成: %F %T"

echo
echo ">>> [2/4] B 组 纯 LLM"
date +"开始: %F %T"
$PY -u run_rag_experiment.py --mode pure --model $MODEL \
    --output results/results.ablation.pure.topk3.qwen7b.v2.json
date +"完成: %F %T"

echo
echo ">>> [3/4] C 组 随机知识"
date +"开始: %F %T"
$PY -u run_rag_experiment.py --mode random --top-k 3 --model $MODEL \
    --output results/results.ablation.random.topk3.qwen7b.v2.json
date +"完成: %F %T"

echo
echo ">>> [4/4] D 组 等长无关文本"
date +"开始: %F %T"
$PY -u run_rag_experiment.py --mode irrelevant --model $MODEL \
    --output results/results.ablation.irrelevant.topk3.qwen7b.v2.json
date +"完成: %F %T"

echo
echo "============================================================"
echo "[全部完成] 调用 generate_report.py 生成报告"
echo "============================================================"
date +"开始: %F %T"
$PY -u generate_report.py
date +"全部结束: %F %T"
