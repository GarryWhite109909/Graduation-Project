"""
跨平台推理后端依赖自动安装器。

职责：
    1. 检测操作系统、CPU 架构、GPU 厂商（NVIDIA / AMD / Apple Silicon / CPU）。
    2. 根据所选推理后端（transformers / llamacpp）和硬件组合，生成正确的 pip 安装命令。
    3. 检查依赖是否已安装；缺失时自动下载安装（支持 dry-run、超时、进度回调）。
    4. 对预览/慢速组合（如 ROCm / Apple Silicon / CPU-only + bitsandbytes）给出明确警告。

使用方式（由 bootstrap.py 调用）：
    from app.launcher.dependency_installer import install_backend_dependencies
    ok = install_backend_dependencies("transformers", dry_run=False)

环境变量：
    VULN_SCANNER_AUTO_INSTALL_DEPS
        0 — 禁用自动安装（仅检测并打印手动命令）
        1 — 强制自动安装（即使依赖已存在也重新检查/升级）
        未设置 — 缺省时对缺失依赖自动安装
    VULN_SCANNER_PIP_INDEX
        覆盖 pip 镜像源，例如 https://pypi.tuna.tsinghua.edu.cn/simple
    VULN_SCANNER_TORCH_INDEX
        覆盖 PyTorch 专用 index-url（高级用户）
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

# Windows 默认 GBK 控制台：任何会 print 非 GBK 字符的脚本必须重新配置 stdout/stderr
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class PlatformInfo:
    """操作系统与架构信息。"""

    os_name: str  # windows / linux / darwin
    arch: str     # amd64 / arm64 / x86 / etc.
    is_64bit: bool


@dataclass
class GPUInfo:
    """GPU 信息。"""

    vendor: Optional[str]  # nvidia / amd / apple / None
    name: Optional[str]
    vram_mb: Optional[int]


@dataclass
class InstallSpec:
    """一条 pip 安装指令。"""

    description: str
    packages: List[str]
    index_url: Optional[str] = None
    extra_index_url: Optional[str] = None
    env: dict = field(default_factory=dict)
    required: bool = True
    warning: Optional[str] = None
    # 安装成功后需要能 import 的模块名（用于二次校验）
    check_modules: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 平台 / 硬件检测
# ---------------------------------------------------------------------------

def detect_platform() -> PlatformInfo:
    """检测操作系统与架构。"""
    system = platform.system().lower()
    if system == "windows":
        os_name = "windows"
    elif system == "linux":
        os_name = "linux"
    elif system == "darwin":
        os_name = "darwin"
    else:
        os_name = system

    machine = platform.machine().lower()
    # 统一常见架构名
    if machine in ("amd64", "x86_64", "x64"):
        arch = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        arch = machine

    return PlatformInfo(os_name=os_name, arch=arch, is_64bit=platform.architecture()[0] == "64bit")


def _run_quiet(cmd: List[str], timeout: float = 5.0) -> tuple[int, str]:
    """运行命令并返回 (returncode, stdout)。忽略异常。"""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return result.returncode, result.stdout
    except Exception:
        return -1, ""


def _detect_nvidia() -> tuple[Optional[str], Optional[int]]:
    """优先 nvidia-smi，再尝试 torch.cuda。"""
    try:
        code, out = _run_quiet(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
            timeout=5.0,
        )
        if code == 0 and out.strip():
            line = out.strip().splitlines()[0]
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2 and parts[0]:
                name = parts[0]
                try:
                    vram = int(parts[1])
                except ValueError:
                    vram = None
                return name, vram
    except Exception:
        pass

    try:
        import torch  # type: ignore
        if torch.cuda.is_available():
            name = torch.cuda.get_device_name(0)
            props = torch.cuda.get_device_properties(0)
            vram = int(props.total_memory // 1024 // 1024)
            return name, vram
    except Exception:
        pass
    return None, None


def _detect_amd_windows() -> tuple[Optional[str], Optional[int]]:
    try:
        code, out = _run_quiet(
            ["wmic", "path", "win32_VideoController", "get", "Name,AdapterRAM", "/format:csv"],
            timeout=5.0,
        )
        if code == 0 and out.strip():
            for line in out.strip().splitlines()[1:]:
                if "AMD" in line or "Radeon" in line:
                    parts = line.split(",")
                    if len(parts) >= 3:
                        name = parts[-2].strip().strip('"')
                        try:
                            vram = int(parts[-1].strip().strip('"')) // 1024 // 1024
                        except ValueError:
                            vram = None
                        return name, vram
    except Exception:
        pass
    return None, None


def _detect_amd_linux() -> tuple[Optional[str], Optional[int]]:
    # 1) rocm-smi
    try:
        code, out = _run_quiet(["rocm-smi", "--showproductname"], timeout=5.0)
        if code == 0 and out.strip():
            name = None
            for line in out.strip().splitlines():
                line = line.strip()
                if "Card Series" in line:
                    parts = line.split(":", 2)
                    if len(parts) >= 3 and parts[2].strip():
                        name = parts[2].strip()
                        break
            vram = None
            if name:
                try:
                    _, mem_out = _run_quiet(["rocm-smi", "--showmeminfo", "vram"], timeout=5.0)
                    if mem_out:
                        for line in mem_out.strip().splitlines():
                            if "Total Memory" in line:
                                parts = line.split(":", 2)
                                if len(parts) >= 3:
                                    vram = int(parts[2].strip()) // 1024 // 1024
                                break
                except Exception:
                    pass
            return name, vram
    except Exception:
        pass

    # 2) sysfs kfd
    try:
        kfd_nodes = Path("/sys/class/kfd/kfd/topology/nodes")
        if kfd_nodes.is_dir():
            for node_dir in sorted(kfd_nodes.iterdir()):
                props_path = node_dir / "properties"
                if not props_path.is_file():
                    continue
                props = props_path.read_text(encoding="utf-8", errors="ignore")
                if "vendor_id 0x1002" in props or "vendor_id 4098" in props:
                    vram = None
                    mem_props_path = node_dir / "mem_banks" / "0" / "properties"
                    if mem_props_path.is_file():
                        try:
                            mem_props = mem_props_path.read_text(encoding="utf-8", errors="ignore")
                            for p in mem_props.splitlines():
                                if p.startswith("size_in_bytes "):
                                    vram = int(p.split(" ", 1)[1].strip()) // 1024 // 1024
                                    break
                        except Exception:
                            pass
                    return "AMD GPU", vram
    except Exception:
        pass

    # 3) lspci fallback
    try:
        code, out = _run_quiet(["lspci", "-nn"], timeout=5.0)
        if code == 0 and out.strip():
            for line in out.strip().splitlines():
                if "VGA" in line and ("AMD" in line or "Radeon" in line or "ATI" in line):
                    desc = line.split(":", 2)[-1].strip()
                    desc = desc.split(" [1002:")[0].strip()
                    return desc, None
    except Exception:
        pass
    return None, None


def _detect_amd(platform_info: PlatformInfo) -> tuple[Optional[str], Optional[int]]:
    if platform_info.os_name == "windows":
        return _detect_amd_windows()
    if platform_info.os_name == "linux":
        return _detect_amd_linux()
    return None, None


def _detect_apple() -> Optional[str]:
    try:
        code, out = _run_quiet(["sysctl", "-n", "machdep.cpu.brand_string"], timeout=3.0)
        if code == 0 and out.strip():
            brand = out.strip()
            if "Apple M" in brand:
                return brand
    except Exception:
        pass
    return None


def detect_gpu(platform_info: Optional[PlatformInfo] = None) -> GPUInfo:
    """检测 GPU 厂商与显存。"""
    if platform_info is None:
        platform_info = detect_platform()

    # NVIDIA
    nvidia_name, nvidia_vram = _detect_nvidia()
    if nvidia_name:
        return GPUInfo(vendor="nvidia", name=nvidia_name, vram_mb=nvidia_vram)

    # Apple Silicon
    if platform_info.os_name == "darwin":
        apple_name = _detect_apple()
        if apple_name:
            return GPUInfo(vendor="apple", name=apple_name, vram_mb=None)

    # AMD
    amd_name, amd_vram = _detect_amd(platform_info)
    if amd_name:
        return GPUInfo(vendor="amd", name=amd_name, vram_mb=amd_vram)

    return GPUInfo(vendor=None, name=None, vram_mb=None)


# ---------------------------------------------------------------------------
# 依赖规格生成
# ---------------------------------------------------------------------------

def _pip_base_cmd(python_executable: str) -> List[str]:
    return [python_executable, "-m", "pip", "install", "--upgrade"]


def _pip_index_args(spec: InstallSpec) -> List[str]:
    args: List[str] = []
    # 允许用户通过环境变量覆盖镜像源
    global_index = os.environ.get("VULN_SCANNER_PIP_INDEX", "").strip()
    torch_index = os.environ.get("VULN_SCANNER_TORCH_INDEX", "").strip()

    # torch 专用 index 优先级：显式 TORCH_INDEX > spec.index_url > 全局 PIP_INDEX
    if spec.index_url and "pytorch.org" in spec.index_url:
        if torch_index:
            args.extend(["--index-url", torch_index])
        else:
            args.extend(["--index-url", spec.index_url])
        if spec.extra_index_url:
            args.extend(["--extra-index-url", spec.extra_index_url])
    else:
        if global_index:
            args.extend(["--index-url", global_index])
        elif spec.index_url:
            args.extend(["--index-url", spec.index_url])
        if spec.extra_index_url:
            args.extend(["--extra-index-url", spec.extra_index_url])
    return args


def _torch_spec(platform_info: PlatformInfo, gpu: GPUInfo, python_executable: str) -> InstallSpec:
    """生成 PyTorch 安装规格。"""
    # 项目只需要 torch；不安装 torchvision/torchaudio，避免与 torch 版本/index 不匹配。
    base_pkgs = ["torch"]

    if gpu.vendor == "nvidia":
        # RTX 20/30/40/50 + A/H 系列均支持 CUDA 12.6；旧卡 Maxwell/Pascal 也兼容。
        # cu126 是最新稳定、兼容性最广的 CUDA 分支（覆盖 RTX 20~50 全系）。
        # 需要 Blackwell（RTX 50）原生 CUDA 13 时可改 cu130，但驱动要求更高。
        return InstallSpec(
            description="PyTorch (CUDA 12.6)",
            packages=base_pkgs,
            index_url="https://download.pytorch.org/whl/cu126",
            check_modules=["torch"],
        )

    if gpu.vendor == "amd":
        if platform_info.os_name == "linux":
            return InstallSpec(
                description="PyTorch (ROCm 7.2)",
                packages=base_pkgs,
                index_url="https://download.pytorch.org/whl/rocm7.2",
                check_modules=["torch"],
                warning="ROCm 7.2 需要兼容的 Linux 内核与 ROCm 驱动；安装失败时请改回 Ollama 后端。",
            )
        # AMD on Windows/macOS：PyTorch 无官方 ROCm  wheel，只能走 CPU
        return InstallSpec(
            description="PyTorch (CPU-only，Windows/macOS AMD GPU 无官方 ROCm 支持)",
            packages=base_pkgs,
            index_url="https://download.pytorch.org/whl/cpu",
            check_modules=["torch"],
            warning="Windows/macOS 上的 AMD GPU 暂不支持 ROCm 加速，PyTorch 将使用 CPU。",
        )

    if gpu.vendor == "apple":
        # 默认 PyPI wheel 在 Apple Silicon 上启用 Metal Performance Shaders
        return InstallSpec(
            description="PyTorch (Apple Metal)",
            packages=base_pkgs,
            check_modules=["torch"],
        )

    # CPU-only
    return InstallSpec(
        description="PyTorch (CPU-only)",
        packages=base_pkgs,
        index_url="https://download.pytorch.org/whl/cpu",
        check_modules=["torch"],
    )


def _bitsandbytes_spec(platform_info: PlatformInfo, gpu: GPUInfo) -> InstallSpec:
    """生成 bitsandbytes 安装规格。

    bitsandbytes 官方当前支持：
      - NVIDIA CUDA（Windows/Linux）
      - AMD ROCm（Linux 预览轮；Windows 预览需 ROCm SDK，见官方文档）
      - CPU-only（Windows/Linux/macOS，慢但可用）
      - Apple Silicon（macOS arm64，通过 CPU 路径慢速运行）

    因此除明确禁用的场景外，一律安装 bitsandbytes，让用户在对应平台获得
    4bit/8bit 量化能力；不支持的组合会在运行时由 transformers_client 回退到
    CPU 或非量化路径。
    """
    platform_label = {
        "windows": "Windows", "linux": "Linux", "darwin": "macOS"
    }.get(platform_info.os_name, platform_info.os_name)
    gpu_label = gpu.vendor.upper() if gpu.vendor else "CPU"

    warning: Optional[str] = None
    if gpu.vendor == "amd":
        warning = (
            f"{platform_label} + ROCm 的 bitsandbytes 支持仍处于预览阶段，"
            "需兼容的 ROCm PyTorch 环境；安装失败时可设置 VULN_SCANNER_QUANTIZE=0 关闭量化。"
        )
    elif gpu.vendor == "apple":
        warning = (
            "Apple Silicon 上的 bitsandbytes 走 CPU 路径，4bit 推理速度较慢；"
            "追求速度请改用 Ollama 后端。"
        )
    elif gpu.vendor is None:
        warning = (
            "CPU-only 模式下 bitsandbytes 4bit 可用但速度显著慢于 GPU；"
            "大模型建议改用 Ollama 后端。"
        )

    return InstallSpec(
        description=f"bitsandbytes ({platform_label} {gpu_label})",
        packages=["bitsandbytes>=0.50.0"],
        check_modules=["bitsandbytes"],
        warning=warning,
    )


def _transformers_specs(platform_info: PlatformInfo, gpu: GPUInfo, python_executable: str) -> List[InstallSpec]:
    """transformers 后端：torch + transformers + peft + accelerate + bitsandbytes。"""
    specs: List[InstallSpec] = []

    specs.append(_torch_spec(platform_info, gpu, python_executable))
    specs.append(InstallSpec(
        description="Transformers / PEFT / Accelerate",
        packages=["transformers>=4.46.0", "peft>=0.20.0", "accelerate>=1.14.0"],
        check_modules=["transformers", "peft", "accelerate"],
    ))
    specs.append(_bitsandbytes_spec(platform_info, gpu))
    return specs


def _llamacpp_specs(platform_info: PlatformInfo, gpu: GPUInfo, python_executable: str) -> List[InstallSpec]:
    """llamacpp 后端：llama-cpp-python（按硬件加 CMAKE_ARGS）。"""
    env: dict = {}
    description = "llama-cpp-python"

    if gpu.vendor == "nvidia":
        env = {"CMAKE_ARGS": "-DLLAMA_CUDA=on"}
        description = "llama-cpp-python (CUDA)"
    elif gpu.vendor == "apple":
        env = {"CMAKE_ARGS": "-DLLAMA_METAL=on"}
        description = "llama-cpp-python (Metal)"
    elif gpu.vendor == "amd" and platform_info.os_name == "linux":
        env = {"CMAKE_ARGS": "-DGGML_HIP=ON"}
        description = "llama-cpp-python (ROCm)"

    # Windows AMD / CPU：使用 PyPI 预编译 wheel，不额外传 CMAKE_ARGS
    return [InstallSpec(
        description=description,
        packages=["llama-cpp-python"],
        env=env,
        check_modules=["llama_cpp"],
    )]


def get_backend_requirements(
    backend: str,
    platform_info: Optional[PlatformInfo] = None,
    gpu: Optional[GPUInfo] = None,
    python_executable: Optional[str] = None,
) -> List[InstallSpec]:
    """获取指定后端在当【前平台的全部安装规格。"""
    if platform_info is None:
        platform_info = detect_platform()
    if gpu is None:
        gpu = detect_gpu(platform_info)
    python_executable = python_executable or sys.executable

    backend = backend.strip().lower()
    if backend == "transformers":
        return _transformers_specs(platform_info, gpu, python_executable)
    if backend in ("llamacpp", "llama-cpp", "llama_cpp", "gguf"):
        return _llamacpp_specs(platform_info, gpu, python_executable)
    raise ValueError(f"不支持自动安装的后端: {backend}")


# ---------------------------------------------------------------------------
# 安装 / 检测
# ---------------------------------------------------------------------------

def _module_import_name(package: str) -> str:
    """pip 包名 -> import 时模块名。"""
    mapping = {
        "llama-cpp-python": "llama_cpp",
    }
    return mapping.get(package, package.replace("-", "_"))


def check_module_installed(module: str) -> bool:
    """检查模块是否已安装（通过 import）。安装新包后调用会刷新 importlib 缓存。"""
    try:
        import importlib
        importlib.invalidate_caches()
        __import__(module)
        return True
    except Exception:
        return False


def get_missing_modules(backend: str) -> List[str]:
    """获取某后端缺失的必须模块。"""
    backend = backend.strip().lower()
    if backend == "transformers":
        required = ["torch", "transformers", "peft", "accelerate", "bitsandbytes"]
    elif backend in ("llamacpp", "llama-cpp", "llama_cpp", "gguf"):
        required = ["llama_cpp"]
    else:
        return []
    return [m for m in required if not check_module_installed(m)]


def _is_auto_install_enabled() -> bool:
    val = os.environ.get("VULN_SCANNER_AUTO_INSTALL_DEPS", "").strip().lower()
    return val not in ("0", "false", "no", "off")


def _force_reinstall() -> bool:
    val = os.environ.get("VULN_SCANNER_AUTO_INSTALL_DEPS", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def _build_pip_cmd(spec: InstallSpec, python_executable: str) -> List[str]:
    cmd = _pip_base_cmd(python_executable)
    cmd.extend(_pip_index_args(spec))
    cmd.extend(spec.packages)
    return cmd


def install_backend_dependencies(
    backend: str,
    python_executable: Optional[str] = None,
    dry_run: bool = False,
    auto_confirm: Optional[bool] = None,
    callback: Optional[Callable[[str], None]] = None,
) -> bool:
    """自动安装指定后端的依赖。

    Args:
        backend: "transformers" 或 "llamacpp"
        python_executable: 目标 Python 解释器（默认 sys.executable）
        dry_run: 为 True 时只打印安装命令，不执行
        auto_confirm: True 不询问；False 只检测不安装；None 按环境变量/默认自动安装
        callback: 进度回调函数，接收字符串消息

    Returns:
        True 表示依赖已就绪；False 表示有缺失且安装失败/被取消。
    """
    if auto_confirm is False:
        # 仅检测模式
        missing = get_missing_modules(backend)
        if missing:
            _emit(f"[检测] {backend} 后端缺少依赖: {', '.join(missing)}", callback)
            return False
        _emit(f"[检测] {backend} 后端依赖已就绪", callback)
        return True

    python_executable = python_executable or sys.executable
    platform_info = detect_platform()
    gpu = detect_gpu(platform_info)

    _emit(f"[依赖安装] 后端: {backend} | 系统: {platform_info.os_name}/{platform_info.arch} | GPU: {gpu.vendor or '无'}", callback)

    specs = get_backend_requirements(backend, platform_info, gpu, python_executable)

    # 先检查必须 spec 是否已全部就绪
    if not _force_reinstall():
        all_ready = True
        for spec in specs:
            if not spec.required:
                continue
            missing = [m for m in spec.check_modules if not check_module_installed(m)]
            if missing:
                all_ready = False
                break
        if all_ready:
            _emit(f"[依赖安装] {backend} 后端依赖已就绪，跳过安装", callback)
            return True

    if dry_run:
        _emit("[依赖安装] DRY-RUN 模式，仅展示命令：", callback)
        for spec in specs:
            if spec.warning:
                _emit(f"  ⚠️ {spec.warning}", callback)
            if not spec.packages:
                continue
            cmd = _build_pip_cmd(spec, python_executable)
            env_repr = " ".join(f'{k}="{v}"' for k, v in spec.env.items()) if spec.env else ""
            _emit(f"  [{spec.description}]", callback)
            _emit(f"    {env_repr + ' ' if env_repr else ''}{' '.join(cmd)}", callback)
        return True

    # 实际安装
    if not _is_auto_install_enabled():
        _emit("[依赖安装] 已禁用自动安装（VULN_SCANNER_AUTO_INSTALL_DEPS=0）", callback)
        _emit("[依赖安装] 请手动执行以下命令：", callback)
        for spec in specs:
            if not spec.packages:
                continue
            cmd = _build_pip_cmd(spec, python_executable)
            env_repr = " ".join(f'{k}="{v}"' for k, v in spec.env.items()) if spec.env else ""
            _emit(f"  {env_repr + ' ' if env_repr else ''}{' '.join(cmd)}", callback)
        return False

    auto = auto_confirm if auto_confirm is not None else True
    if not auto:
        answer = input(f"[依赖安装] 将为 {backend} 后端安装依赖（可能下载数 GB），是否继续？[Y/n]: ").strip().lower()
        if answer and answer not in ("y", "yes"):
            _emit("[依赖安装] 用户取消安装", callback)
            return False

    overall_ok = True
    for spec in specs:
        if spec.warning:
            _emit(f"[依赖安装] ⚠️ {spec.warning}", callback)
        if not spec.packages:
            continue

        # 若该 spec 的校验模块已全部就绪且未强制重装，则跳过（避免重复下载 torch 等大包）
        if not _force_reinstall():
            already_ok = all(check_module_installed(m) for m in spec.check_modules)
            if already_ok:
                _emit(f"[依赖安装] {spec.description} 已就绪，跳过", callback)
                continue

        cmd = _build_pip_cmd(spec, python_executable)
        env = os.environ.copy()
        env.update(spec.env)

        _emit(f"[依赖安装] 正在安装: {spec.description}...", callback)
        _emit(f"[依赖安装] 命令: {' '.join(cmd)}", callback)

        try:
            # 长超时：大型 wheel（torch ~2GB）下载+安装可能很慢
            result = subprocess.run(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=3600,  # 60 分钟
            )
            if result.returncode != 0:
                _emit(f"[依赖安装] ❌ {spec.description} 安装失败（退出码 {result.returncode}）", callback)
                # 打印最后 800 字符帮助诊断
                tail = result.stdout.strip()[-800:] if result.stdout else ""
                if tail:
                    _emit(f"[依赖安装] 日志尾部:\n{tail}", callback)
                overall_ok = False
                if spec.required:
                    break
            else:
                _emit(f"[依赖安装] ✅ {spec.description} 安装完成", callback)
        except subprocess.TimeoutExpired:
            _emit(f"[依赖安装] ❌ {spec.description} 安装超时（60 分钟）", callback)
            overall_ok = False
            if spec.required:
                break
        except Exception as e:
            _emit(f"[依赖安装] ❌ {spec.description} 安装异常: {e}", callback)
            overall_ok = False
            if spec.required:
                break

    # 二次校验
    if overall_ok:
        missing = get_missing_modules(backend)
        if missing:
            _emit(f"[依赖安装] ❌ 安装后仍无法导入: {', '.join(missing)}", callback)
            overall_ok = False
        else:
            _emit(f"[依赖安装] ✅ {backend} 后端依赖全部就绪", callback)
    else:
        _emit(f"[依赖安装] 部分依赖安装失败，可尝试：", callback)
        _emit(f"  1. 设置 VULN_SCANNER_AUTO_INSTALL_DEPS=0 后手动安装", callback)
        _emit(f"  2. 或设置 VULN_SCANNER_BACKEND=ollama 改用 Ollama 后端", callback)

    return overall_ok


# ---------------------------------------------------------------------------
# 安全工具安装（新框架：两阶段/外部扫描所需的传统 SAST/SCA/Secret 工具）
# ---------------------------------------------------------------------------

# pip 可安装的 CLI 工具（跨平台可靠，用于 external_scanner / two_stage Stage 1）。
# 键为可执行名（用于 PATH 探测），值为安装时的版本下限（自动装到最新稳定版）。
SECURITY_TOOLS_PIP: list[str] = ["bandit", "semgrep", "pip-audit", "detect-secrets"]
# 各 pip 工具的“最新稳定版本”下限（2026-08 核实的最新发布版本）：
#   bandit          1.9.4
#   semgrep         1.172.0
#   pip-audit       2.10.1
#   detect-secrets  1.5.0
SECURITY_TOOLS_PIP_SPEC: dict[str, str] = {
    "bandit": "bandit>=1.9.4",
    "semgrep": "semgrep>=1.172.0",
    "pip-audit": "pip-audit>=2.10.1",
    "detect-secrets": "detect-secrets>=1.5.0",
}
# 独立二进制工具（经系统包管理器安装，最佳努力：失败仅告警不阻断）
SECURITY_TOOLS_BIN: dict[str, str] = {
    "gitleaks": "Gitleaks.Gitleaks",   # winget 包 ID（最新稳定：8.30.1）
    "trivy": "AquaSecurity.Trivy",     # winget 包 ID（最新稳定：0.73.0）
}
# 全部安全工具（供安装/卸载/状态汇总共用）
SECURITY_TOOLS_ALL: list[str] = SECURITY_TOOLS_PIP + list(SECURITY_TOOLS_BIN.keys())


def _tool_installed(name: str) -> bool:
    """判断命令行工具是否已安装（在 PATH 中）。"""
    return shutil.which(name) is not None


def _find_winget_install(tool: str) -> bool:
    """Windows 下在 winget 常见安装目录探测工具可执行文件。

    winget 安装的便携工具通常落在：
      %LOCALAPPDATA%\\Microsoft\\WinGet\\Packages\\<Publisher>\\<Pkg>\\<ver>\\
    gitleaks/trivy 的可执行文件位于其中某个子目录。此函数在用户级与系统级
    WinGet 目录里递归查找 <tool>.exe，命中即返回 True（不依赖 PATH）。
    """
    if sys.platform != "win32":
        return False
    exe_name = f"{tool}.exe"
    bases = []
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        bases.append(Path(local_app_data) / "Microsoft" / "WinGet" / "Packages")
    program_data = os.environ.get("ProgramData")
    if program_data:
        bases.append(Path(program_data) / "Microsoft" / "WinGet" / "Packages")
    for base in bases:
        if not base.is_dir():
            continue
        try:
            for candidate in base.rglob(exe_name):
                if candidate.is_file():
                    return True
        except Exception:
            continue
    return False


def _refresh_process_path() -> None:
    """Windows 下从注册表重新读取 PATH，刷新生效到当前进程。

    winget / 安装器写完系统/用户 PATH 后，当前进程的 os.environ["PATH"] 不会自动
    更新，导致 shutil.which() 找不到刚装好的工具。此函数把注册表中的 PATH 合并回
    当前进程，使安装结果立即可见（无需重启终端）。
    """
    if sys.platform != "win32":
        return
    try:
        import winreg
    except Exception:
        return

    new_paths: list[str] = []
    # 系统级 + 用户级 PATH，按序读取（系统在前、用户在后，与 Windows 解析顺序一致）
    for root, subkey in (
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
        (winreg.HKEY_CURRENT_USER, r"Environment"),
    ):
        try:
            with winreg.OpenKey(root, subkey) as key:
                value, _ = winreg.QueryValueEx(key, "Path")
                new_paths.append(value or "")
        except Exception:
            continue

    registry_path = os.pathsep.join(p for p in new_paths if p)
    if not registry_path:
        return
    # 保留当前进程已有的、注册表里没有的条目（如虚拟环境），避免丢失
    current = os.environ.get("PATH", "")
    merged = registry_path
    for item in current.split(os.pathsep):
        if item and item not in merged.split(os.pathsep):
            merged += os.pathsep + item
    os.environ["PATH"] = merged
    # 让 shutil 重新解析
    try:
        import importlib
        importlib.reload(shutil)
    except Exception:
        pass


def _try_install_binary_tool(
    tool: str,
    platform_info: PlatformInfo,
    dry_run: bool,
    callback: Optional[Callable[[str], None]] = None,
) -> None:
    """最佳努力安装独立二进制工具（gitleaks / trivy），失败仅告警。
    经系统包管理器安装；无法自动安装时给出手动指引。
    """
    if dry_run:
        _emit(f"[安全工具] DRY-RUN: 将安装二进制工具 {tool}", callback)
        return

    if platform_info.os_name == "windows":
        if shutil.which("winget"):
            pkg = SECURITY_TOOLS_BIN[tool]
            _emit(f"[安全工具] 使用 winget 安装 {tool}...", callback)
            cmd = ["winget", "install", pkg, "--silent",
                   "--accept-source-agreements", "--accept-package-agreements",
                   "--disable-interactivity"]
            try:
                r = _run_quiet(cmd, timeout=1800)
                # winget 退出码 0 = 安装成功，但新目录可能不在当前进程 PATH：
                # 先刷新注册表 PATH，再探测常见 winget Links / Packages 目录
                _refresh_process_path()
                found = _tool_installed(tool) or _find_winget_install(tool)
                if r[0] == 0 and found:
                    _emit(f"[安全工具] ✅ {tool} 安装完成", callback)
                elif r[0] == 0 and not found:
                    _emit(f"[安全工具] ✓ {tool} 已安装（退出码 0），但未加入 PATH，"
                          f"请重启终端后再使用", callback)
                else:
                    _emit(f"[安全工具] ⚠ {tool} winget 安装未成功（退出码 {r[0]}），可手动安装", callback)
            except Exception as e:
                _emit(f"[安全工具] ⚠ {tool} 安装异常: {e}", callback)
        else:
            _emit(f"[安全工具] 未检测到 winget，请手动安装 {tool}（GitHub Releases）", callback)

    elif platform_info.os_name == "darwin":
        if shutil.which("brew"):
            _emit(f"[安全工具] 使用 Homebrew 安装 {tool}...", callback)
            cmd = ["brew", "install", tool]
            try:
                r = _run_quiet(cmd, timeout=1800)
                if r[0] == 0 and _tool_installed(tool):
                    _emit(f"[安全工具] ✅ {tool} 安装完成", callback)
                else:
                    _emit(f"[安全工具] ⚠ {tool} brew 安装未成功，可手动安装", callback)
            except Exception as e:
                _emit(f"[安全工具] ⚠ {tool} 安装异常: {e}", callback)
        else:
            _emit(f"[安全工具] 未检测到 brew，请手动安装 {tool}（GitHub Releases）", callback)

    else:
        # Linux：尝试常见包管理器，否则提示手动安装
        pm_cmds = [
            ["apt-get", "install", "-y", tool],
            ["dnf", "install", "-y", tool],
            ["pacman", "-S", "--noconfirm", tool],
            ["zypper", "install", "-y", tool],
        ]
        installed = False
        for cmd in pm_cmds:
            if shutil.which(cmd[0]):
                _emit(f"[安全工具] 使用 {cmd[0]} 安装 {tool}...", callback)
                try:
                    r = _run_quiet([c for c in cmd], timeout=1800)
                    if r[0] == 0 and _tool_installed(tool):
                        _emit(f"[安全工具] ✅ {tool} 安装完成", callback)
                        installed = True
                        break
                except Exception:
                    pass
        if not installed:
            _emit(f"[安全工具] 请手动安装 {tool}（GitHub Releases / 系统包管理器）", callback)


def install_security_tools(
    python_executable: Optional[str] = None,
    dry_run: bool = False,
    auto_confirm: Optional[bool] = None,
    callback: Optional[Callable[[str], None]] = None,
) -> bool:
    """启动前自动下载新框架所需的传统安全工具。

    - pip 工具（bandit / semgrep / pip-audit / detect-secrets）：缺失即 pip 安装
    - 二进制工具（gitleaks / trivy）：经系统包管理器最佳努力安装，失败不阻断

    返回 True 表示核心 pip 工具已就绪（二进制工具缺失仅告警，不影响核心两阶段扫描）。
    """
    python_executable = python_executable or sys.executable
    platform_info = detect_platform()

    _emit("[安全工具] 检查新框架所需传统工具 "
          f"({', '.join(SECURITY_TOOLS_ALL)})...", callback)

    # 1) pip 可安装工具
    missing_pip = [t for t in SECURITY_TOOLS_PIP if not _tool_installed(t)]
    missing_pip_spec = [SECURITY_TOOLS_PIP_SPEC.get(t, t) for t in missing_pip]
    if missing_pip:
        _emit(f"[安全工具] 缺失 pip 工具: {', '.join(missing_pip_spec)}", callback)
        if dry_run:
            _emit(f"[安全工具] DRY-RUN: pip install {' '.join(missing_pip_spec)}", callback)
        elif _is_auto_install_enabled():
            cmd = _pip_base_cmd(python_executable) + missing_pip_spec
            global_index = os.environ.get("VULN_SCANNER_PIP_INDEX", "").strip()
            if global_index:
                cmd.extend(["--index-url", global_index])
            _emit(f"[安全工具] 正在安装: {' '.join(cmd)}", callback)
            try:
                r = subprocess.run(
                    cmd, env=os.environ.copy(),
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding="utf-8", errors="replace",
                    timeout=1200,  # 20 分钟
                )
                if r.returncode == 0:
                    _emit("[安全工具] ✅ pip 工具安装完成", callback)
                else:
                    _emit(f"[安全工具] ❌ pip 工具安装失败（退出码 {r.returncode}）", callback)
                    tail = r.stdout.strip()[-800:] if r.stdout else ""
                    if tail:
                        _emit(f"[安全工具] 日志尾部:\n{tail}", callback)
            except subprocess.TimeoutExpired:
                _emit("[安全工具] ❌ pip 工具安装超时（20 分钟）", callback)
        else:
            _emit("[安全工具] 自动安装已禁用，请手动: "
                  f"pip install {' '.join(missing_pip_spec)}", callback)
    else:
        _emit("[安全工具] pip 工具已就绪", callback)

    # 2) 独立二进制工具（最佳努力）
    for tool in SECURITY_TOOLS_BIN:
        if _tool_installed(tool):
            _emit(f"[安全工具] {tool} 已就绪", callback)
        else:
            _try_install_binary_tool(tool, platform_info, dry_run, callback)

    # 汇总：核心（pip）工具必须就绪；二进制缺失仅告警
    missing_pip = [t for t in SECURITY_TOOLS_PIP if not _tool_installed(t)]
    if missing_pip:
        _emit(f"[安全工具] ⚠ 核心工具仍缺失: {', '.join(missing_pip)}（外部工具扫描会静默跳过）", callback)
        return False
    _emit("[安全工具] ✅ 核心安全工具就绪", callback)
    return True


def _emit(message: str, callback: Optional[Callable[[str], None]] = None) -> None:
    """输出消息，同时调用回调。"""
    print(message)
    if callback is not None:
        try:
            callback(message)
        except Exception:
            pass


def print_manual_install_commands(backend: str, python_executable: Optional[str] = None) -> None:
    """打印手动安装命令（用于失败后的回退提示）。"""
    python_executable = python_executable or sys.executable
    platform_info = detect_platform()
    gpu = detect_gpu(platform_info)
    specs = get_backend_requirements(backend, platform_info, gpu, python_executable)
    print(f"# 手动安装 {backend} 后端依赖（{platform_info.os_name}/{platform_info.arch}, GPU={gpu.vendor or '无'}）")
    for spec in specs:
        if spec.warning:
            print(f"# ⚠️ {spec.warning}")
        if not spec.packages:
            continue
        cmd = _build_pip_cmd(spec, python_executable)
        env_repr = " ".join(f'{k}="{v}"' for k, v in spec.env.items()) if spec.env else ""
        print(f"{env_repr + ' ' if env_repr else ''}{' '.join(cmd)}")


if __name__ == "__main__":
    # 命令行入口：python -m app.launcher.dependency_installer [transformers|llamacpp|tools] [--dry-run]
    import argparse

    parser = argparse.ArgumentParser(description="推理后端 / 安全工具依赖自动安装器")
    parser.add_argument("target", choices=["transformers", "llamacpp", "tools"], help="安装目标：推理后端或安全工具")
    parser.add_argument("--dry-run", action="store_true", help="仅打印安装命令")
    parser.add_argument("--python", default=sys.executable, help="目标 Python 解释器")
    args = parser.parse_args()

    if args.target == "tools":
        ok = install_security_tools(python_executable=args.python, dry_run=args.dry_run)
    else:
        ok = install_backend_dependencies(args.target, python_executable=args.python, dry_run=args.dry_run)
    sys.exit(0 if ok else 1)
