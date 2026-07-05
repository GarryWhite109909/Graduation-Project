#!/usr/bin/env bash
# exp_04 P1-5 + P2-8 实验运行脚本（顺序执行，避免 GPU 抢占）
#
# 用法：
#   cd experiments/exp_04_hard_samples
#   nohup bash run_ablation_and_topk.sh > results/ablation_topk.run.log 2>&1 &
#
# 前置：P1-4（run_experiment.py --repeat 3）必须先跑完释放显存。
# 完成后所有结果文件落在 results/，由 generate_report.py 统一汇总成 exp_04_report.md。

set -e
cd "$(dirname "$0")"
mkdir -p results

# 必须使用 conda env graproj 的 python3：默认 /usr/bin/python3 (3.14) 没有 chromadb
PY=/home/zane/miniconda3/envs/graproj/bin/python3
# 强制离线模式：sentence-transformers 会尝试联网检查 embedding 模型更新，
# 但模型已缓存本地，关闭联网可避免 "Network is unreachable" 错误
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
echo "[信息] 使用 Python: $PY"
echo "[信息] HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1"
$PY -c "import chromadb; print(f'[信息] chromadb {chromadb.__version__} 可用')" || { echo "[错误] chromadb 不可用"; exit 1; }

echo "============================================================"
echo "[P1-4] 难样本压力测试：42 样本 × 3 次（含 num_ctx=16384 修复）"
echo "============================================================"
date +"开始时间: %Y-%m-%d %H:%M:%S"
echo
echo ">>> P1-4 重复实验 + 多数表决 + Wilson CI（--resume 续跑）"
$PY -u run_experiment.py --repeat 3 --resume \
    --output results/results.p1-4.repeat3.gemma4-12b.json
echo
date +"P1-4 完成时间: %Y-%m-%d %H:%M:%S"

echo
echo "============================================================"
echo "[P1-5] RAG 消融对照实验：4 组 × 42 样本 × 1 次"
echo "============================================================"
date +"开始时间: %Y-%m-%d %H:%M:%S"

# A 组：RAG+LLM（K=3，复用 P2-8 的 K=3 结果以避免重复跑）
echo
echo ">>> [A 组] RAG+LLM (top-k=3)"
$PY -u run_rag_experiment.py --mode rag --top-k 3 --repeat 1 \
    --output results/results.ablation.rag.topk3.json

# B 组：纯 LLM
echo
echo ">>> [B 组] 纯 LLM（无 RAG）"
$PY -u run_rag_experiment.py --mode pure --repeat 1 \
    --output results/results.ablation.pure.topk3.json

# C 组：随机知识注入
echo
echo ">>> [C 组] 随机知识注入"
$PY -u run_rag_experiment.py --mode random --top-k 3 --repeat 1 \
    --output results/results.ablation.random.topk3.json

# D 组：等长无关文本注入
echo
echo ">>> [D 组] 等长无关文本注入"
$PY -u run_rag_experiment.py --mode irrelevant --repeat 1 \
    --output results/results.ablation.irrelevant.topk3.json

echo
date +"P1-5 完成时间: %Y-%m-%d %H:%M:%S"

echo
echo "============================================================"
echo "[P2-8] RAG Top-K 对比：K=1,5,10（K=3 已在 P1-5 完成）"
echo "============================================================"
date +"开始时间: %Y-%m-%d %H:%M:%S"

for K in 1 5 10; do
    echo
    echo ">>> Top-K = $K"
    $PY -u run_rag_experiment.py --mode rag --top-k "$K" --repeat 1 \
        --output "results/results.ablation.rag.topk${K}.json"
done

echo
date +"P2-8 完成时间: %Y-%m-%d %H:%M:%S"
echo
echo "============================================================"
echo "[全部完成] 调用 generate_report.py 生成最终报告"
echo "============================================================"
$PY -u generate_report.py
date +"全部结束: %Y-%m-%d %H:%M:%S"
