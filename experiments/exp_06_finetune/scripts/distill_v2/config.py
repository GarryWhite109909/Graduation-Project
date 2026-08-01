"""
蒸馏 v2 全局配置。

API Key 通过环境变量传入（与 docs/prompts/*.md 约定一致）：
  - DEEPSEEK_API_KEY   : DeepSeek V4-Flash
  - MOONSHOT_API_KEY   : Kimi K3

数据输出根目录：experiments/exp_06_finetune/data/distill_v2/
"""

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# 路径
# ---------------------------------------------------------------------------
# 本文件：scripts/distill_v2/config.py
# parents[0]=distill_v2, parents[1]=scripts, parents[2]=exp_06_finetune
BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data" / "distill_v2"
PROGRESS_DIR = DATA_DIR / "_progress"
DATA_DIR.mkdir(parents=True, exist_ok=True)
PROGRESS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# DeepSeek V4-Flash
#   文档：docs/prompts/deepseek_prompt.md 第 196-204 行
# ---------------------------------------------------------------------------
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL = "https://api.deepseek.com"          # OpenAI 兼容
DEEPSEEK_MODEL = "deepseek-v4-flash"                    # V4-Flash-0731 正式版
DEEPSEEK_CHAT_URL = f"{DEEPSEEK_BASE_URL}/v1/chat/completions"
DEEPSEEK_CONCURRENCY = 8
# thinking 关闭：实测 V4-Flash 思考链 4096+ token 仍吃满 max_tokens，content 为空。
# system prompt 已规定推理路径（A/B/C）+ ≤5步约束，模型按指令执行即可，不需要自己"想"。
# 关闭后 temperature 生效（0.7 增加输出多样性），max_tokens 2048 足够三段式输出。
DEEPSEEK_THINKING = "disabled"
DEEPSEEK_TEMPERATURE = 0.7
DEEPSEEK_MAX_TOKENS = 2048

# ---------------------------------------------------------------------------
# Kimi K3（Moonshot）
#   文档：docs/prompts/kimi_prompt.md 第 196-206 行
#   注：K3 思考模式始终开启（架构决定，无法关闭），message.reasoning_content 为思考链
#       （不计入训练），message.content 为最终输出（训练只取这个）。
#       reasoning_effort 可调 low/high/max（默认 max），调低可省 token 但伤质量。
#       run_distill.py 当前未传 reasoning_effort，即走默认 max。
# ---------------------------------------------------------------------------
MOONSHOT_API_KEY = os.environ.get("MOONSHOT_API_KEY", "")
MOONSHOT_BASE_URL = "https://api.moonshot.ai/v1"
KIMI_MODEL = "kimi-k3"
KIMI_CHAT_URL = f"{MOONSHOT_BASE_URL}/chat/completions"
KIMI_CONCURRENCY = 2                                    # 思考模式贵且慢，保守
KIMI_TEMPERATURE = 0.5
KIMI_MAX_TOKENS = 1024

# ---------------------------------------------------------------------------
# 通用
# ---------------------------------------------------------------------------
MAX_RETRIES = 2                  # 三段式校验失败后重试次数
REQUEST_TIMEOUT = 180            # K3 思考链可能较长，给 3 分钟
RETRY_BACKOFF = 4                # 重试间隔（秒），指数退避基数

# 最终合并产物
FINAL_OUTPUT = DATA_DIR / "train_chatml_v9max.jsonl"


def check_api_keys(models=None):
    """启动时按需校验环境变量，缺失则提示并退出。

    Args:
        models: 需要校验的模型集合，如 {"deepseek"} 或 {"deepseek", "kimi"}。
                None 表示全部校验（向后兼容）。
    """
    if models is None:
        models = {"deepseek", "kimi"}
    missing = []
    if "deepseek" in models and not DEEPSEEK_API_KEY:
        missing.append("DEEPSEEK_API_KEY")
    if "kimi" in models and not MOONSHOT_API_KEY:
        missing.append("MOONSHOT_API_KEY")
    if missing:
        raise SystemExit(
            "[config] 缺少环境变量: " + ", ".join(missing) +
            "\n  Windows PowerShell:  $env:DEEPSEEK_API_KEY='sk-xxx'; $env:MOONSHOT_API_KEY='sk-yyy'\n"
            "  Linux/Mac:           export DEEPSEEK_API_KEY=sk-xxx MOONSHOT_API_KEY=sk-yyy"
        )
