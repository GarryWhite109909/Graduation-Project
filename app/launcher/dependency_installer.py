"""
跨平台推理后端依赖自动安装器。

职责：
    1. 检测操作系统、CPU 架构、GPU 厂商（NVIDIA / AMD / Apple Silicon / CPU）。
    2. 根据所选推理后端（transformers / llamacpp）和硬件组合，生成正确的 pip 安装命令。
    3. 检查依赖是否已安装；缺失时自动下载安装（支持 dry-run、超时、进度回调）。
    4. 对不支持的组合（如 Apple Silicon / ROCm + bitsandbytes）给出明确警告和回退方案。

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
        # RTX 20/30/40/50 + A/H 系列均支持 CUDA 12.1；旧卡 Maxwell/Pascal 也兼容。
        # 如需匹配驱动 CUDA 版本，可后续扩展 nvidia-smi 读取 cuda_version。
        return InstallSpec(
            description="PyTorch (CUDA 12.1)",
            packages=base_pkgs,
            index_url="https://download.pytorch.org/whl/cu121",
            check_modules=["torch"],
        )

    if gpu.vendor == "amd":
        if platform_info.os_name == "linux":
            return InstallSpec(
                description="PyTorch (ROCm 6.0)",
                packages=base_pkgs,
                index_url="https://download.pytorch.org/whl/rocm6.0",
                check_modules=["torch"],
                warning="ROCm 6.0 需要兼容的 Linux 内核与 ROCm 驱动；安装失败时请改回 Ollama 后端。",
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


def _bitsandbytes_spec(platform_info: PlatformInfo, gpu: GPUInfo) -> Optional[InstallSpec]:
    """bitsandbytes 目前仅官方支持 Windows/Linux + NVIDIA CUDA。"""
    if gpu.vendor == "nvidia" and platform_info.os_name in ("windows", "linux"):
        return InstallSpec(
            description="bitsandbytes (Windows/Linux CUDA)",
            packages=["bitsandbytes>=0.43.0"],
            check_modules=["bitsandbytes"],
        )
    return None


def _transformers_specs(platform_info: PlatformInfo, gpu: GPUInfo, python_executable: str) -> List[InstallSpec]:
    """transformers 后端：torch + transformers + peft + accelerate + bitsandbytes（如支持）。"""
    specs: List[InstallSpec] = []

    specs.append(_torch_spec(platform_info, gpu, python_executable))
    specs.append(InstallSpec(
        description="Transformers / PEFT / Accelerate",
        packages=["transformers>=4.45.0", "peft>=0.13.0", "accelerate>=1.0.0"],
        check_modules=["transformers", "peft", "accelerate"],
    ))

    bnb = _bitsandbytes_spec(platform_info, gpu)
    if bnb:
        specs.append(bnb)
    else:
        # 占位 spec，用于打印警告，不执行安装
        platform_label = {
            "windows": "Windows", "linux": "Linux", "darwin": "macOS"
        }.get(platform_info.os_name, platform_info.os_name)
        gpu_label = gpu.vendor.upper() if gpu.vendor else "CPU-only"
        specs.append(InstallSpec(
            description="bitsandbytes（当前硬件/OS不支持，跳过）",
            packages=[],
            check_modules=["bitsandbytes"],
            required=False,
            warning=(
                f"bitsandbytes 不支持 {gpu_label} + {platform_label} 组合，"
                "transformers 后端加载时将无法使用 4bit 量化（NF4）。"
                "Apple Silicon / ROCm 用户建议改用 Ollama 后端；"
                "如仍想用 transformers，请设置 VULN_SCANNER_QUANTIZE=0 并确保内存/显存足够。"
            ),
        ))
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
    # 命令行入口：python -m app.launcher.dependency_installer [transformers|llamacpp] [--dry-run]
    import argparse

    parser = argparse.ArgumentParser(description="推理后端依赖自动安装器")
    parser.add_argument("backend", choices=["transformers", "llamacpp"], help="推理后端")
    parser.add_argument("--dry-run", action="store_true", help="仅打印安装命令")
    parser.add_argument("--python", default=sys.executable, help="目标 Python 解释器")
    args = parser.parse_args()

    ok = install_backend_dependencies(args.backend, python_executable=args.python, dry_run=args.dry_run)
    sys.exit(0 if ok else 1)
