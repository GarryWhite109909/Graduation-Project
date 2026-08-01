"""提示词包：从 docs/prompts/*.md 同步为程序化调用。"""

from .deepseek import DEEPSEEK_SYSTEM, build_deepseek_user
from .kimi import KIMI_SYSTEM, build_kimi_user

__all__ = [
    "DEEPSEEK_SYSTEM",
    "build_deepseek_user",
    "KIMI_SYSTEM",
    "build_kimi_user",
]
