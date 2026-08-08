#!/usr/bin/env bash
# release_model.sh —— 将训练好的 LoRA adapter 打包为 Ollama 模型
#
# 全流程：merge LoRA → HF 格式 → GGUF f16 → Q4_K_M 量化 → ollama create → 可选 push
#
# 用法：
#   bash tools/release_model.sh \
#       --version v5 \
#       --adapter experiments/exp_06_finetune/outputs/lora_r8_a16_e3_lr0.0001_s42_rslora_v5/best \
#       --base Qwen/Qwen3-8B \
#       --ollama-name garrywhite109909/graduation-vuln-scanner:v5
#
# 前置：
#   - conda activate AI（含 peft/transformers/torch）
#   - 已安装 Ollama 并能执行 ollama create/push
#   - 网络可访问 HuggingFace（base 模型权重）

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="v5"
ADAPTER=""
BASE_MODEL="Qwen/Qwen3-8B"
OLLAMA_NAME="garrywhite109909/graduation-vuln-scanner:v5"
PUSH=0
LLAMA_CPP_DIR="${PROJECT_ROOT}/.cache/llama.cpp"

usage() {
    echo "用法: $0 --version v5 --adapter <adapter_path> [--base Qwen/Qwen3-8B] [--ollama-name garrywhite109909/graduation-vuln-scanner:v5] [--push]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --adapter) ADAPTER="$2"; shift 2 ;;
        --base) BASE_MODEL="$2"; shift 2 ;;
        --ollama-name) OLLAMA_NAME="$2"; shift 2 ;;
        --push) PUSH=1; shift ;;
        -h|--help) usage ;;
        *) echo "未知参数: $1"; usage ;;
    esac
done

if [[ -z "${ADAPTER}" ]]; then
    # 未指定 adapter 时自动探测项目约定目录
    ADAPTER=$(PYTHONPATH="${PROJECT_ROOT}" python3 -c "from graduation_project.paths import resolve_adapter_path; print(resolve_adapter_path(), end='')" 2>/dev/null || true)
    if [[ -z "${ADAPTER}" ]]; then
        echo "[ERROR] 未指定 --adapter，且无法在 ${PROJECT_ROOT}/models 或训练输出目录中探测到合法 adapter"
        usage
    fi
    echo "[INFO] 自动探测到 adapter: ${ADAPTER}"
fi

echo "=================================================="
echo "发布模型 ${OLLAMA_NAME}"
echo "版本: ${VERSION}"
echo "基座: ${BASE_MODEL}"
echo "Adapter: ${ADAPTER}"
echo "=================================================="

# 1. 合并 LoRA
MERGED_DIR="${PROJECT_ROOT}/outputs/merged_${VERSION}"
echo "[1/6] 合并 LoRA adapter 到 base 模型 -> ${MERGED_DIR}"
python3 "${PROJECT_ROOT}/tools/merge_lora.py" \
    --base "${BASE_MODEL}" \
    --adapter "${ADAPTER}" \
    --out "${MERGED_DIR}"

# 2. 准备 llama.cpp
echo "[2/6] 检查 llama.cpp"
if [[ ! -f "${LLAMA_CPP_DIR}/build/bin/llama-quantize" || ! -f "${LLAMA_CPP_DIR}/convert_hf_to_gguf.py" ]]; then
    echo "  llama.cpp 未找到，自动克隆并编译（约 2-5 分钟）..."
    mkdir -p "${LLAMA_CPP_DIR}"
    git clone --depth 1 https://github.com/ggerganov/llama.cpp.git "${LLAMA_CPP_DIR}"
    cd "${LLAMA_CPP_DIR}"
    cmake -B build
    cmake --build build --config Release -j "$(nproc)"
    cd "${PROJECT_ROOT}"
fi

# 3. 转换为 GGUF f16
GGUF_F16="${PROJECT_ROOT}/outputs/merged_${VERSION}-f16.gguf"
echo "[3/6] 转换为 GGUF f16 -> ${GGUF_F16}"
python3 "${LLAMA_CPP_DIR}/convert_hf_to_gguf.py" "${MERGED_DIR}" \
    --outtype f16 \
    --outfile "${GGUF_F16}"

# 4. 量化为 Q4_K_M（8GB 显存可跑）
GGUF_Q4="${PROJECT_ROOT}/outputs/merged_${VERSION}-q4_k_m.gguf"
echo "[4/6] 量化为 Q4_K_M（约 4.7GB，适配 8GB 显存）-> ${GGUF_Q4}"
"${LLAMA_CPP_DIR}/build/bin/llama-quantize" "${GGUF_F16}" "${GGUF_Q4}" q4_k_m

# 5. 生成 Modelfile 并创建 Ollama 模型
#    SYSTEM prompt 从 graduation_project.prompts.BASE_PROMPT 动态获取，
#    确保与训练/评估时一致（schema 变更后自动同步）。
MODELFILE="${PROJECT_ROOT}/outputs/Modelfile_${VERSION}"
echo "[5/6] 创建 Ollama 模型 ${OLLAMA_NAME}"

SYSTEM_PROMPT_FILE=$(mktemp)
PYTHONPATH="${PROJECT_ROOT}" python3 -c "
from graduation_project.prompts import BASE_PROMPT
print(BASE_PROMPT, end='')
" > "${SYSTEM_PROMPT_FILE}" || {
    echo "[ERROR] 无法从 graduation_project.prompts 导出 BASE_PROMPT"
    exit 1
}

cat > "${MODELFILE}" <<EOF
FROM ${GGUF_Q4}

# Qwen3 chat template（与训练时一致）
TEMPLATE """{{- if .System }}<|im_start|>system
{{ .System }}<|im_end|>
{{- end }}<|im_start|>user
{{ .Prompt }}<|im_end|>
<|im_start|>assistant
"""

SYSTEM """$(cat "${SYSTEM_PROMPT_FILE}")"""

PARAMETER temperature 0.0
PARAMETER num_ctx 8192
PARAMETER num_predict 2048
PARAMETER stop "<|im_end|>"
PARAMETER stop "<|endoftext|>"
EOF

rm -f "${SYSTEM_PROMPT_FILE}"
echo "  Modelfile 已生成: ${MODELFILE}"
ollama create "${OLLAMA_NAME}" -f "${MODELFILE}"

# 6. 可选 push
if [[ ${PUSH} -eq 1 ]]; then
    echo "[6/6] 推送到 Ollama Registry..."
    ollama push "${OLLAMA_NAME}"
else
    echo "[6/6] 本地模型已创建。如需发布，请执行："
    echo "      ollama push ${OLLAMA_NAME}"
fi

echo ""
echo "=================================================="
echo "发布完成"
echo "  Ollama 模型: ${OLLAMA_NAME}"
echo "  GGUF Q4_K_M: ${GGUF_Q4}"
echo "  用户侧运行: VULN_SCANNER_MODEL=${OLLAMA_NAME} python -m app.launcher.bootstrap"
echo "=================================================="
