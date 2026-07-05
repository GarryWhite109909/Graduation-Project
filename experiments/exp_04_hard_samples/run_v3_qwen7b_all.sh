#!/usr/bin/env bash
# exp_04 v3 87 段：qwen2.5-coder:7b 全量重跑（修复答案泄露后）
#
# 用法：
#   nohup bash run_v3_qwen7b_all.sh > results/v3_qwen7b.run.log 2>&1 &
#
# 可调环境变量：
#   REST_SEC=600   每批之间休息秒数（默认 600=10分钟）
#   MODEL=qwen2.5-coder:7b
#
# 前置：RAG 知识库已重建（72 条，示例代码已去重），manifest v3 (87 段，泄露注释已清理) 就位。
# 完成后所有结果落在 results/，由 generate_report.py 汇总成 exp_04_report.md。
#
# 设计：8 批实验，每批跑完休息 REST_SEC 秒让显卡风扇降速，减少震颤疲劳。
#       休息期间打印倒计时，Ctrl+C 可跳过当前休息（不影响下一批）。

set -e
cd "$(dirname "$0")"
mkdir -p results

PY=/home/zane/miniconda3/envs/graproj/bin/python3
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
MODEL=${MODEL:-qwen2.5-coder:7b}
REST_SEC=${REST_SEC:-600}
SUFFIX=v3   # 输出文件后缀，区分 v2/v3

# ---- 工具函数 ----

print_banner() {
    echo
    echo "============================================================"
    echo "$1"
    echo "============================================================"
    date +"时间: %F %T"
}

# 休息倒计时：Ctrl+C 可跳过当前休息，不影响后续批次
rest_countdown() {
    local sec=$1
    echo
    echo ">>> 显卡休息 ${sec}s（约 $((sec/60)) 分钟），Ctrl+C 可跳过"
    local i=$sec
    while [ $i -gt 0 ]; do
        # 打印剩余时间（每 60 秒打印一次，最后 60 秒每秒打印）
        if [ $i -le 60 ] || [ $((i % 60)) -eq 0 ]; then
            echo "    休息剩余: ${i}s ($((i/60))m$((i%60))s)"
        fi
        sleep 1
        i=$((i - 1))
    done
    echo "    休息结束，继续下一批"
}

# 打印显卡状态（AMD 用 rocm-smi，无则跳过）
gpu_status() {
    if command -v rocm-smi >/dev/null 2>&1; then
        echo "[显卡] $(rocm-smi --showtemp --showuse --showfan 2>/dev/null | grep -E 'GPU|temp|fan|use' | head -3 | tr '\n' ' ')"
    elif command -v nvidia-smi >/dev/null 2>&1; then
        echo "[显卡] $(nvidia-smi --query-gpu=temperature.gpu,fan.speed,utilization.gpu --format=csv,noheader 2>/dev/null)"
    else
        echo "[显卡] (无监控工具，跳过)"
    fi
}

# ---- 主流程开始 ----

print_banner "[v3 qwen7b 全量] 模型 $MODEL, 样本 87 段 (修复后), 休息 ${REST_SEC}s/批"
$PY -c "import chromadb; print(f'[信息] chromadb {chromadb.__version__} 可用')"
gpu_status

# ===== 批次 1/8：P1-4 重复性（repeat=3，约 30 分钟）=====
print_banner "[1/8] P1-4 重复性 + 95% CI (repeat=3, 约 30 min)"
$PY -u run_experiment.py --model $MODEL --repeat 3 \
    --output results/results.p1-4.repeat3.qwen2.5-coder-7b.${SUFFIX}.json
gpu_status
rest_countdown $REST_SEC || true

# ===== 批次 2/8：P1-5 A 组 RAG+LLM (top-k=3，也是 P2-8 K=3) =====
print_banner "[2/8] P1-5 A 组 RAG+LLM (top-k=3, 约 10 min)"
$PY -u run_rag_experiment.py --mode rag --top-k 3 --model $MODEL \
    --output results/results.ablation.rag.topk3.qwen7b.${SUFFIX}.json
gpu_status
rest_countdown $REST_SEC || true

# ===== 批次 3/8：P1-5 B 组 纯 LLM =====
print_banner "[3/8] P1-5 B 组 纯 LLM (约 10 min)"
$PY -u run_rag_experiment.py --mode pure --model $MODEL \
    --output results/results.ablation.pure.topk3.qwen7b.${SUFFIX}.json
gpu_status
rest_countdown $REST_SEC || true

# ===== 批次 4/8：P1-5 C 组 随机知识 =====
print_banner "[4/8] P1-5 C 组 随机知识 (约 10 min)"
$PY -u run_rag_experiment.py --mode random --top-k 3 --model $MODEL \
    --output results/results.ablation.random.topk3.qwen7b.${SUFFIX}.json
gpu_status
rest_countdown $REST_SEC || true

# ===== 批次 5/8：P1-5 D 组 等长无关文本 =====
print_banner "[5/8] P1-5 D 组 等长无关文本 (约 10 min)"
$PY -u run_rag_experiment.py --mode irrelevant --model $MODEL \
    --output results/results.ablation.irrelevant.topk3.qwen7b.${SUFFIX}.json
gpu_status
rest_countdown $REST_SEC || true

# ===== 批次 6/8：P2-8 Top-K=1 =====
print_banner "[6/8] P2-8 Top-K = 1 (约 10 min)"
$PY -u run_rag_experiment.py --mode rag --top-k 1 --model $MODEL \
    --output results/results.ablation.rag.topk1.qwen7b.${SUFFIX}.json
gpu_status
rest_countdown $REST_SEC || true

# ===== 批次 7/8：P2-8 Top-K=5 =====
print_banner "[7/8] P2-8 Top-K = 5 (约 10 min)"
$PY -u run_rag_experiment.py --mode rag --top-k 5 --model $MODEL \
    --output results/results.ablation.rag.topk5.qwen7b.${SUFFIX}.json
gpu_status
rest_countdown $REST_SEC || true

# ===== 批次 8/8：P2-8 Top-K=10 =====
print_banner "[8/8] P2-8 Top-K = 10 (约 10 min)"
$PY -u run_rag_experiment.py --mode rag --top-k 10 --model $MODEL \
    --output results/results.ablation.rag.topk10.qwen7b.${SUFFIX}.json
gpu_status

# ===== 全部完成，生成报告 =====
print_banner "[全部完成] 调用 generate_report.py 生成最终报告"
$PY -u generate_report.py
date +"全部结束: %F %T"
gpu_status
echo
echo "结果文件清单:"
ls -la results/results.*.${SUFFIX}.json
