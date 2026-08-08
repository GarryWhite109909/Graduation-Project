"""
项目路径解析工具 —— 统一处理模型、adapter、配置文件等路径。

设计原则：
- 优先尊重用户显式配置（环境变量 / 构造函数参数）
- 其次按项目内约定目录自动探测（models/、outputs/ 等）
- 所有路径解析都返回绝对路径或空字符串，避免相对路径在不同 cwd 下歧义
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


def find_project_root(anchor: Optional[Path] = None) -> Path:
    """定位项目根目录（Graduation-Project/）。

    策略：
        1. 已设置 VULN_SCANNER_ROOT 环境变量时直接采用
        2. 从 anchor 文件所在目录向上查找 pyproject.toml / .git 标记
        3. 以上都失败时回退到当前工作目录

    在常规 uvicorn / python -m 启动方式下，anchor 默认指向 graduation_project/paths.py，
    向上两级即可得到项目根目录。
    """
    env_root = os.environ.get("VULN_SCANNER_ROOT", "").strip()
    if env_root:
        p = Path(env_root)
        if p.is_dir():
            return p.resolve()

    start = anchor or Path(__file__).resolve()
    cur = start if start.is_dir() else start.parent
    for _ in range(5):
        if (cur / "pyproject.toml").exists() or (cur / ".git").is_dir():
            return cur
        parent = cur.parent
        if parent == cur:
            break
        cur = parent

    return Path.cwd().resolve()


def is_valid_adapter_dir(path: Path) -> bool:
    """检查目录是否是合法的 LoRA adapter 目录（含权重文件）。"""
    if not path.is_dir():
        return False
    weight_names = (
        "adapter_model.safetensors",
        "adapter_model.bin",
        "adapter_model.gguf",
    )
    return any((path / name).is_file() for name in weight_names)


def discover_adapter_dir(project_root: Optional[Path] = None) -> Optional[Path]:
    """在项目约定目录中自动探测 LoRA adapter。

    搜索范围（按优先级）：
        1. project_root / "models" 下的直接子目录
        2. project_root / "models" 本身（adapter 文件直接放 models/ 下）
        3. project_root / "experiments" / "exp_06_finetune" / "outputs" / ** / "best"

    若 models/ 下存在多个合法 adapter 目录，优先选择包含 "v9max" / "best" / "adapter"
    字样的目录；仍无法确定时返回找到的第一个。
    """
    root = (project_root or find_project_root()).resolve()

    candidates: list[Path] = []

    # 1) models/ 子目录
    models_dir = root / "models"
    if models_dir.is_dir():
        for child in sorted(models_dir.iterdir()):
            if child.is_dir() and is_valid_adapter_dir(child):
                candidates.append(child)
        # models/ 本身也可能直接放权重
        if is_valid_adapter_dir(models_dir):
            candidates.append(models_dir)

    # 2) 训练输出目录兜底（兼容旧路径）
    outputs_dir = root / "experiments" / "exp_06_finetune" / "outputs"
    if outputs_dir.is_dir():
        for best_dir in sorted(outputs_dir.rglob("best")):
            if is_valid_adapter_dir(best_dir):
                candidates.append(best_dir)

    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]

    # 启发式排序：优先包含版本/标识关键字的目录
    score_map = {"v9max": 3, "best": 2, "adapter": 1}

    def _score(p: Path) -> int:
        lowered = p.name.lower()
        return max((score_map.get(k, 0) for k in score_map if k in lowered), default=0)

    candidates.sort(key=_score, reverse=True)
    return candidates[0]


def resolve_adapter_path(
    explicit: str = "",
    project_root: Optional[Path] = None,
) -> str:
    """解析 LoRA adapter 目录路径。

    解析优先级：
        1. explicit 参数（非空且目录存在）
        2. VULN_SCANNER_ADAPTER 环境变量（非空且目录存在）
        3. 项目根目录下 models/ 等约定位置自动探测

    Returns:
        adapter 目录的绝对路径字符串；未找到时返回空字符串。
    """
    # 1. explicit
    if explicit:
        p = Path(explicit).expanduser()
        if not p.is_absolute():
            p = (project_root or find_project_root()) / p
        if is_valid_adapter_dir(p):
            return str(p.resolve())

    # 2. 环境变量
    env_val = os.environ.get("VULN_SCANNER_ADAPTER", "").strip()
    if env_val:
        p = Path(env_val).expanduser()
        if not p.is_absolute():
            p = (project_root or find_project_root()) / p
        if is_valid_adapter_dir(p):
            return str(p.resolve())

    # 3. 自动探测
    found = discover_adapter_dir(project_root)
    if found:
        return str(found.resolve())

    return ""


def resolve_base_model_path(explicit: str = "") -> str:
    """解析基座模型路径（HF id 或本地目录）。

    解析优先级：
        1. explicit 参数（非空）
        2. VULN_SCANNER_MODEL_ID 环境变量（用户显式指定，可为 HF id 或本地路径）
        3. 项目本地缓存 models/hf_models/Qwen3-8B（存在时优先本地，离线可用）
        4. 回退官方 HF id Qwen/Qwen3-8B
    """
    if explicit:
        return explicit

    env_id = os.environ.get("VULN_SCANNER_MODEL_ID", "").strip()
    if env_id:
        return env_id

    local = find_project_root() / "models" / "hf_models" / "Qwen3-8B"
    if (local / "config.json").is_file():
        return str(local)

    return "Qwen/Qwen3-8B"
