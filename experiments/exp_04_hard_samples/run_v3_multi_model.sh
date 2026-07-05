#!/usr/bin/env bash
# exp_04 v3 多模型对比：在修复后的 87 段难样本上横向对比各模型零样本能力
#
# 用法：
#   nohup bash run_v3_multi_model.sh > results/v3_multi_model.run.log 2>&1 &
#
# 可调环境变量：
#   REST_SEC=600      每模型之间休息秒数（默认 600=10分钟）
#   MODE=pure         实验模式：pure（纯 LLM）或 rag（RAG+LLM，默认 K=5）
#   TOP_K=5           MODE=rag 时的 Top-K
#
# 对比模型（按显存占用从小到大排列）：
#   qwen2.5-coder:7b
#   qwen2.5-coder:14b
#   gemma4:12b
#   deepseek-coder-v2:16b
#   gpt-oss:20b
#   gemma4:26b

set -e
cd "$(dirname "$0")"
mkdir -p results

PY=/home/zane/miniconda3/envs/graproj/bin/python3
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
REST_SEC=${REST_SEC:-600}
MODE=${MODE:-pure}
TOP_K=${TOP_K:-5}
SUFFIX=v3.multi_model

# 模型列表（按推荐运行顺序：小 → 大）
MODELS=(
    "qwen2.5-coder:7b"
    "qwen2.5-coder:14b"
    "gemma4:12b"
    "deepseek-coder-v2:16b"
    "gpt-oss:20b"
    "gemma4:26b"
)

print_banner() {
    echo
    echo "============================================================"
    echo "$1"
    echo "============================================================"
    date +"时间: %F %T"
}

rest_countdown() {
    local sec=$1
    echo
    echo ">>> 显卡休息 ${sec}s（约 $((sec/60)) 分钟），Ctrl+C 可跳过"
    local i=$sec
    while [ $i -gt 0 ]; do
        if [ $i -le 60 ] || [ $((i % 60)) -eq 0 ]; then
            echo "    休息剩余: ${i}s ($((i/60))m$((i%60))s)"
        fi
        sleep 1
        i=$((i - 1))
    done
    echo "    休息结束，继续下一模型"
}

gpu_status() {
    if command -v rocm-smi >/dev/null 2>&1; then
        echo "[显卡] $(rocm-smi --showtemp --showuse --showfan 2>/dev/null | grep -E 'GPU|temp|fan|use' | head -3 | tr '\n' ' ')"
    elif command -v nvidia-smi >/dev/null 2>&1; then
        echo "[显卡] $(nvidia-smi --query-gpu=temperature.gpu,fan.speed,utilization.gpu --format=csv,noheader 2>/dev/null)"
    else
        echo "[显卡] (无监控工具，跳过)"
    fi
}

# 主流程
print_banner "[v3 多模型对比] 模式=$MODE, 样本 87 段, 模型数=${#MODELS[@]}, 休息 ${REST_SEC}s/模型"
$PY -c "import chromadb; print(f'[信息] chromadb {chromadb.__version__} 可用')"
gpu_status

TOTAL=${#MODELS[@]}
IDX=0
for MODEL in "${MODELS[@]}"; do
    IDX=$((IDX + 1))

    # 构建安全文件名：把冒号替换为下划线
    SAFE_NAME=$(echo "$MODEL" | tr ':/' '__')
    OUTPUT="results/results.${MODE}.${SAFE_NAME}.${SUFFIX}.json"

    print_banner "[$IDX/$TOTAL] 模型 $MODEL (模式 $MODE)"

    if [ "$MODE" = "rag" ]; then
        $PY -u run_rag_experiment.py --mode rag --top-k $TOP_K --model "$MODEL" \
            --output "$OUTPUT"
    else
        $PY -u run_rag_experiment.py --mode pure --model "$MODEL" \
            --output "$OUTPUT"
    fi

    gpu_status

    # 最后一模型后不休息
    if [ $IDX -lt $TOTAL ]; then
        rest_countdown $REST_SEC || true
    fi
done

print_banner "[全部完成] 多模型对比结束"
date +"全部结束: %F %T"
gpu_status
echo
echo "结果文件清单:"
ls -la results/results.${MODE}.*.${SUFFIX}.json
