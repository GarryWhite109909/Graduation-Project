#!/bin/bash
# ============================================================================
# PyTorch TunableOp 离线调优 —— 为 Phase 2/3 训练预先生成 GEMM kernel 选择表
#
# 原理：PyTorch TunableOp 自动从 rocBLAS/hipBLASLt 中挑选最优 GEMM kernel
#       AMD 官方实测 gfx1100 上 +15% 端到端加速，RDNA4 同样可用
#       参考：https://rocm.blogs.amd.com/artificial-intelligence/pytorch-tunableop-offline/
#
# PyTorch 2.11+ 正确工作流（三步）：
#   Step 1 (Recording, ~5min):  跑极短训练，记录所有 GEMM shape 到 untuned csv
#                                关键 env: PYTORCH_TUNABLEOP_RECORD_UNTUNED=1
#                                输出: configs/tunableop_untuned0.csv
#   Step 2 (Tuning, 30-60min):  调用 tune_gemm_in_file() API 离线调优所有 GEMM
#                                输出: configs/tunableop_tuned.csv
#   Step 3 (Deploy, 自动):       run_phase2_sft.sh 等脚本自动加载 tuned csv
#
# ⚠️ 关键点（PyTorch 2.11 实测）：
#   - 仅设 PYTORCH_TUNABLEOP_ENABLED=1 不够，必须显式 enable + record_untuned_enable
#   - untuned csv 在程序退出时由 atexit handler 写入 cwd，文件名固定为 tunableop_untuned0.csv
#   - 必须在 train_qlora.py 里调用 Python API（环境变量 PYTORCH_TUNABLEOP_FILE_NAME 不生效）
#
# 何时跑：Phase 2 启动前跑一次即可
# 前置条件：Phase 1 sweep 已结束（GPU 空闲）
# 输出：experiments/exp_06_finetune/configs/tunableop_tuned.csv
#
# 用法（真实终端运行）：
#   bash experiments/exp_06_finetune/scripts/tunableop_offline_tune.sh
#
# 可选环境变量：
#   SKIP_RECORD=1   跳过 Step 1（已有 untuned csv 时复用）
#   SKIP_TUNE=1     跳过 Step 2（只录制不调优）
# ============================================================================

set -e

PROJECT_ROOT="/home/zane/文档/code/毕业设计"
AI_PYTHON="/home/zane/miniconda3/envs/AI/bin/python"
SCRIPT_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/scripts"
CONFIGS_DIR="${PROJECT_ROOT}/experiments/exp_06_finetune/configs"

# untuned csv 由 PyTorch 自动写入 cwd（文件名固定 tunableop_untuned0.csv）
# 所以录制时 cd 到 configs 目录，确保 csv 落在正确位置
UNTUNED_CSV="${CONFIGS_DIR}/tunableop_untuned0.csv"
TUNED_CSV="${CONFIGS_DIR}/tunableop_tuned.csv"

mkdir -p "${CONFIGS_DIR}"

# 离线模式 + RDNA4 优化
export HF_HUB_OFFLINE=1
export TOKENIZERS_PARALLELISM=false
export TORCH_ROCM_AOTRITON_ENABLE_EXPERIMENTAL=1

echo "=========================================="
echo "TunableOp 离线调优"
echo "  GPU: $(rocminfo 2>/dev/null | grep 'Marketing Name' | head -1 | awk -F': ' '{print $2}' || echo 'unknown')"
echo "  PyTorch: $(${AI_PYTHON} -c 'import torch; print(torch.__version__)' 2>/dev/null)"
echo "  Untuned CSV: ${UNTUNED_CSV}"
echo "  Tuned CSV:   ${TUNED_CSV}"
echo "=========================================="

# ----------------------------------------------------------------------------
# Step 1: Recording —— 用极短训练记录所有 GEMM shape
# ----------------------------------------------------------------------------
if [ "${SKIP_RECORD:-0}" != "1" ]; then
    if [ -f "${UNTUNED_CSV}" ]; then
        echo ""
        echo "[Step 1/3] 已存在 ${UNTUNED_CSV}，备份后重新生成"
        mv "${UNTUNED_CSV}" "${UNTUNED_CSV}.bak.$(date +%s)"
    fi

    echo ""
    echo "[Step 1/3] Recording GEMM shapes（用 5 step 训练采集）..."
    echo "  预计耗时：3-5 分钟（含模型加载）"

    # 启用 TunableOp recording 模式（关键三个 env var）
    export PYTORCH_TUNABLEOP_ENABLED=1
    export PYTORCH_TUNABLEOP_TUNING=0              # 不调优，只记录
    export PYTORCH_TUNABLEOP_RECORD_UNTUNED=1      # 关键：录制 untuned shapes

    # cd 到 configs 目录，让 PyTorch 把 untuned csv 写在这里
    # train_qlora.py 里的 Python API 会自动处理 enable + record_untuned_enable
    cd "${CONFIGS_DIR}"
    ${AI_PYTHON} "${SCRIPT_DIR}/train_qlora.py" \
        --model-id Qwen/Qwen2.5-Coder-7B-Instruct \
        --epochs 1 \
        --max-steps 5 \
        --batch-size 1 \
        --grad-accum 8 \
        --lr 5e-5 \
        --lora-r 8 \
        --lora-alpha 16 \
        --seed 42 \
        --dev-ratio 0.02 \
        --no-early-stopping \
        --output-suffix _tunableop_record \
        --save-steps 9999 \
        --logging-steps 1 \
        2>&1 | tee "${CONFIGS_DIR}/tunableop_record.log"
    cd "${PROJECT_ROOT}"

    echo ""
    echo "[Step 1/3] Recording 完成。GEMM shape 数量："
    if [ -f "${UNTUNED_CSV}" ]; then
        wc -l "${UNTUNED_CSV}"
        echo "  前 5 行预览："
        head -5 "${UNTUNED_CSV}" | sed 's/^/    /'
    else
        echo "  ❌ CSV 未生成！检查 tunableop_record.log"
        exit 1
    fi
else
    echo ""
    echo "[Step 1/3] 跳过（SKIP_RECORD=1），使用已有 ${UNTUNED_CSV}"
fi

# ----------------------------------------------------------------------------
# Step 2: Offline Tuning —— 调用 tune_gemm_in_file() API 调优所有 GEMM
# ----------------------------------------------------------------------------
if [ "${SKIP_TUNE:-0}" != "1" ] && [ -f "${UNTUNED_CSV}" ]; then
    echo ""
    echo "[Step 2/3] Offline tuning GEMM kernels..."
    echo "  预计耗时：10-30 分钟（取决于 GEMM shape 数量，每个 shape ~30s）"
    echo "  Untuned: ${UNTUNED_CSV}"
    echo "  Tuned:   ${TUNED_CSV}"

    # 用 Python API 调优（不是 CLI 工具）
    ${AI_PYTHON} - <<PYEOF 2>&1 | tee "${CONFIGS_DIR}/tunableop_tune.log"
import os
import sys
import time

# 配置 TunableOp 为 tuning 模式
os.environ["PYTORCH_TUNABLEOP_ENABLED"] = "1"
os.environ["PYTORCH_TUNABLEOP_TUNING"] = "1"
os.environ["PYTORCH_TUNABLEOP_RECORD_UNTUNED"] = "0"

import torch
from torch.cuda import tunable

tunable.enable(True)
tunable.tuning_enable(True)
tunable.record_untuned_enable(False)
tunable.set_filename("${TUNED_CSV}")

# 减少调优迭代次数以加速（默认 100 iters / 30ms，实测每 GEMM ~30s）
# 设为 10 iters / 3ms 后每 GEMM ~3-5s，1104 个 GEMM 约 1-1.5h
# 准确度损失可接受（最优 kernel 通常在前几次迭代就能确定）
tunable.set_max_tuning_iterations(10)
tunable.set_max_tuning_duration(3)

enabled = tunable.is_enabled()
tuning_on = tunable.tuning_is_enabled()
record_on = tunable.record_untuned_is_enabled()
max_iter = tunable.get_max_tuning_iterations()
max_dur = tunable.get_max_tuning_duration()
print(f"TunableOp state: enabled={enabled} tuning={tuning_on} record_untuned={record_on}")
print(f"  max_tuning_iterations={max_iter} (default 100, reduced for speed)")
print(f"  max_tuning_duration={max_dur}ms (default 30ms, reduced for speed)")
print(f"Output file: {tunable.get_filename()}")
print(f"Input untuned: ${UNTUNED_CSV}")
print()

# 读取 untuned 文件中的 GEMM 数量
with open("${UNTUNED_CSV}") as f:
    gemm_lines = [l for l in f if l.startswith(("Gemm", "ScaledGemm"))]
print(f"待调优 GEMM 数量: {len(gemm_lines)}")
print()

# 调优（每个 GEMM ~30s，总共可能 5-30 分钟）
print("开始调优...")
start = time.time()
tunable.tune_gemm_in_file("${UNTUNED_CSV}")
torch.cuda.synchronize()
elapsed = time.time() - start

print(f"\n✅ 调优完成，耗时 {elapsed/60:.1f} 分钟")
print(f"调优结果写入: ${TUNED_CSV}")

# 验证
if os.path.exists("${TUNED_CSV}"):
    with open("${TUNED_CSV}") as f:
        lines = f.readlines()
    tuned_gemm_count = sum(1 for l in lines if l.startswith(("Gemm", "ScaledGemm")))
    print(f"Tuned CSV 行数: {len(lines)} (其中 GEMM 调优结果 {tuned_gemm_count} 条)")
else:
    print(f"❌ Tuned CSV 未生成！")
    sys.exit(1)
PYEOF

    echo ""
    echo "[Step 2/3] Tuning 完成。Tuned CSV："
    wc -l "${TUNED_CSV}" 2>/dev/null
else
    echo ""
    echo "[Step 2/3] 跳过（SKIP_TUNE=1 或 untuned csv 不存在）"
fi

# ----------------------------------------------------------------------------
# Step 3: Deploy —— 下次训练自动加载
# ----------------------------------------------------------------------------
echo ""
echo "[Step 3/3] Deploy 提示"
echo "  run_phase2_sft.sh / run_knitlm_cpt.sh 等训练脚本已配置自动加载："
echo "    if [ -f tunableop_tuned.csv ]; then export PYTORCH_TUNABLEOP_ENABLED=1 ..."
echo ""
echo "  下次运行训练脚本时会看到："
echo "    TunableOp 已启用: enabled=True tuning=False record_untuned=False file=.../tunableop_tuned.csv"
echo ""
echo "✅ TunableOp 离线调优流程结束"
echo ""
echo "验证（可选）：对比启用前后的 step time"
echo "  启用前：~73-76 s/step（参考 Phase 1 sweep log）"
echo "  启用后：预期