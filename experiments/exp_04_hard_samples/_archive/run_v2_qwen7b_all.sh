#!/usr/bin/env bash
# exp_04 v2 87 段：qwen2.5-coder:7b 全量重跑（P1-4 + P1-5 + P2-8）
#
# 用法：
#   nohup bash run_v2_qwen7b_all.sh > results/v2_qwen7b.run.log 2>&1 &
#
# 前置：RAG 知识库已重建（72 条），manifest v2 (87 段) 就位。
# 完成后所有结果落在 results/，由 generate_report.py 汇总成 exp_04_report.md。

set -e
cd "$(dirname "$0")"
mkdir -p results

PY=/home/zane/miniconda3/envs/graproj/bin/python3
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
MODEL=qwen2.5-coder:7b

echo "============================================================"
echo "[v2 qwen7b 全量] 模型 $MODEL, 样本 87 段, 开始 $(date +'%F %T')"
echo "============================================================"
$PY -c "import chromadb; print(f'[信息] chromadb {chromadb.__version__} 可用')"

echo
echo "============================================================"
echo "[1/8] P1-4 重复性 + 95% CI (repeat=3, 约 70 min)"
echo "============================================================"
date +"开始: %F %T"
$PY -u run_experiment.py --model $MODEL --repeat 3 \
    --output results/results.p1-4.repeat3.qwen2.5-coder-7b.v2.json
date +"完成: %F %T"

echo
echo "============================================================"
echo "[P1-5] RAG 消融对照 4 组 (repeat=1, 每组约 23 min)"
echo "============================================================"

echo
echo ">>> [2/8] A 组 RAG+LLM (top-k=3)"
date +"开始: %F %T"
$PY -u run_rag_experiment.py --mode rag --top-k 3 --model $MODEL \
    --output results/results.ablation.rag.topk3.qwen7b.v2.json
date +"完成: %F %T"

echo
echo ">>> [3/8] B 组 纯 LLM"
date +"开始: %F %T"
$PY -u run_rag_experiment.py --mode pure --model $MODEL \
    --output results/results.ablation.pure.topk3.qwen7b.v2.json
date +"完成: %F %T"

echo
echo ">>> [4/8] C 组 随机知识"
date +"开始: %F %T"
$PY -u run_rag_experiment.py --mode random --top-k 3 --model $MODEL \
    --output results/results.ablation.random.topk3.qwen7b.v2.json
date +"完成: %F %T"

echo
echo ">>> [5/8] D 组 等长无关文本"
date +"开始: %F %T"
$PY -u run_rag_experiment.py --mode irrelevant --model $MODEL \
    --output results/results.ablation.irrelevant.topk3.qwen7b.v2.json
date +"完成: %F %T"

echo
echo "============================================================"
echo "[P2-8] Top-K 对比 K=1/5/10 (K=3 复用 P1-5 A 组)"
echo "============================================================"

IDX=5
for K in 1 5 10; do
    IDX=$((IDX + 1))
    echo
    echo ">>> [$IDX/8] Top-K = $K"
    date +"开始: %F %T"
    $PY -u run_rag_experiment.py --mode rag --top-k $K --model $MODEL \
        --output "results/results.ablation.rag.topk${K}.qwen7b.v2.json"
    date +"完成: %F %T"
done

echo
echo "============================================================"
echo "[全部完成] 调用 generate_report.py 生成最终报告"
echo "============================================================"
date +"开始: %F %T"
$PY -u generate_report.py
date +"全部结束: %F %T"
