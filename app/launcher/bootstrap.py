"""
启动器 —— 首次使用检测 Ollama + 模型，后续直接启动后端 + 打开浏览器。

跨平台入口：
    python -m app.launcher.bootstrap

启动脚本：
    Windows: 双击 start_windows.bat
    Linux/macOS: bash start_linux_macos.sh
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

import requests

# 项目根目录（Graduation-Project/）
PROJECT_ROOT = Path(__file__).resolve().parents[2]
# 默认模型（发布到 Ollama Registry 的 SFT，可通过环境变量切换版本）
DEFAULT_MODEL = os.environ.get("VULN_SCANNER_MODEL", "garrywhite109909/graduation-vuln-scanner:v5")
# 回退模型（官方 Qwen3-8B，未微调）
FALLBACK_MODEL = os.environ.get("VULN_SCANNER_FALLBACK_MODEL", "qwen3:8b")
# 后端端口
PORT = 8765


def check_ollama_installed() -> bool:
    """检测系统是否安装 Ollama。"""
    return shutil.which("ollama") is not None


def try_install_ollama() -> bool:
    """尝试自动安装 Ollama。成功返回 True，失败回退到打开下载页。"""
    print("[启动器] 未检测到 Ollama，尝试自动安装...")

    if sys.platform == "win32":
        # Windows: 优先 winget
        if shutil.which("winget"):
            print("[启动器] 使用 winget 安装 Ollama...")
            try:
                result = subprocess.run(
                    ["winget", "install", "Ollama.Ollama",
                     "--accept-source-agreements", "--accept-package-agreements"],
                    timeout=600,
                )
                if result.returncode == 0 and check_ollama_installed():
                    print("[启动器] Ollama 安装完成。")
                    return True
                print(f"[启动器] winget 退出码 {result.returncode}。")
            except subprocess.TimeoutExpired:
                print("[启动器] winget 安装超时。")
        else:
            print("[启动器] 未检测到 winget，无法自动安装。")
        webbrowser.open("https://ollama.com/download")
        return False

    elif sys.platform == "darwin":
        # macOS: 优先 Homebrew
        if shutil.which("brew"):
            print("[启动器] 使用 Homebrew 安装 Ollama...")
            try:
                result = subprocess.run(
                    ["brew", "install", "ollama"],
                    timeout=600,
                )
                if result.returncode == 0 and check_ollama_installed():
                    print("[启动器] Ollama 安装完成。")
                    return True
                print(f"[启动器] brew 退出码 {result.returncode}。")
            except subprocess.TimeoutExpired:
                print("[启动器] brew 安装超时。")
        else:
            print("[启动器] 未检测到 brew，无法自动安装。")
        webbrowser.open("https://ollama.com/download")
        return False

    else:
        # Linux: 官方一键脚本（可能需要 sudo 密码）
        print("[启动器] 使用官方脚本安装 Ollama（如提示请输入 sudo 密码）...")
        try:
            result = subprocess.run(
                ["bash", "-c", "curl -fsSL https://ollama.com/install.sh | sh"],
                timeout=600,
            )
            if result.returncode == 0 and check_ollama_installed():
                print("[启动器] Ollama 安装完成。")
                return True
            print(f"[启动器] 安装脚本退出码 {result.returncode}。")
        except subprocess.TimeoutExpired:
            print("[启动器] 安装超时。")
        webbrowser.open("https://ollama.com/download")
        return False


def ensure_ollama_running() -> bool:
    """确保 Ollama 服务在运行。未运行则尝试启动。"""
    try:
        resp = requests.get("http://localhost:11434/api/tags", timeout=3)
        return resp.status_code == 200
    except Exception:
        # 尝试后台启动 ollama serve
        print("[启动器] Ollama 服务未运行，尝试启动...")
        try:
            if sys.platform == "win32":
                subprocess.Popen(
                    ["ollama", "serve"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.Popen(
                    ["ollama", "serve"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            time.sleep(3)
            resp = requests.get("http://localhost:11434/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception as e:
            print(f"[启动器] 启动 Ollama 失败: {e}")
            return False


def list_ollama_models() -> list[str]:
    """列出已 pull 的模型。"""
    try:
        resp = requests.get("http://localhost:11434/api/tags", timeout=5)
        data = resp.json()
        return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []


def ensure_model_available(model: str) -> bool:
    """确保模型已 pull。未 pull 则自动下载。"""
    models = list_ollama_models()
    # 精确匹配（Ollama 模型名含 tag，不需要模糊匹配）
    if model in models:
        return True

    print(f"[启动器] 首次使用，正在下载模型 {model}（约 5GB，请耐心等待）...")
    print(f"[启动器] 下载过程中可以关闭此窗口，下次启动会继续。")
    try:
        result = subprocess.run(
            ["ollama", "pull", model],
            timeout=1800,  # 30 分钟超时
        )
        if result.returncode == 0:
            print(f"[启动器] 模型 {model} 下载完成。")
            return True
        print(f"[启动器] 模型下载失败（退出码 {result.returncode}）。")
        return False
    except subprocess.TimeoutExpired:
        print("[启动器] 模型下载超时。")
        return False


def start_backend(port: int = PORT) -> subprocess.Popen:
    """启动 FastAPI 后端。"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)

    cmd = [
        sys.executable, "-m", "uvicorn",
        "app.backend.main:app",
        "--host", "127.0.0.1",
        "--port", str(port),
    ]
    print(f"[启动器] 启动后端：http://127.0.0.1:{port}")
    proc = subprocess.Popen(cmd, env=env, cwd=str(PROJECT_ROOT))
    return proc


def wait_for_backend(port: int, timeout: int = 30) -> bool:
    """等待后端就绪。"""
    for _ in range(timeout):
        try:
            resp = requests.get(f"http://127.0.0.1:{port}/api/health", timeout=2)
            if resp.status_code == 200:
                return True
        except Exception:
            time.sleep(1)
    return False


def main():
    print("=" * 60)
    print("  AI 漏洞扫描器 —— 启动中")
    print("=" * 60)

    # 1. 检测 Ollama
    if not check_ollama_installed():
        # 尝试自动安装
        if not try_install_ollama():
            print("\n[错误] Ollama 自动安装失败。请手动安装：")
            print("  下载地址：https://ollama.com/download")
            print("  安装后重新运行本启动器。")
            input("\n按回车键退出...")
            return
        # 安装后重新检查 PATH
        if not check_ollama_installed():
            print("\n[错误] Ollama 已安装但不在 PATH 中。")
            print("  请重启终端后重新运行本启动器，或手动将 ollama 加入 PATH。")
            input("\n按回车键退出...")
            return

    print("[1/4] Ollama 已安装")

    # 2. 确保 Ollama 服务运行
    if not ensure_ollama_running():
        print("\n[错误] Ollama 服务无法启动。请手动运行 `ollama serve` 后重试。")
        input("\n按回车键退出...")
        return

    print("[2/4] Ollama 服务已运行")

    # 3. 确保模型可用
    model = os.environ.get("VULN_SCANNER_MODEL", DEFAULT_MODEL)
    if not ensure_model_available(model):
        # 回退到官方 Qwen3-8B
        print(f"[启动器] {model} 不可用，尝试回退模型 {FALLBACK_MODEL}")
        if not ensure_model_available(FALLBACK_MODEL):
            print(f"\n[错误] 无法获取任何可用模型。请手动运行：")
            print(f"  ollama pull {model}")
            input("\n按回车键退出...")
            return
        os.environ["VULN_SCANNER_MODEL"] = FALLBACK_MODEL

    print(f"[3/4] 模型就绪")

    # 4. 启动后端
    backend_proc = start_backend(PORT)
    if not wait_for_backend(PORT):
        print(f"\n[错误] 后端启动超时。请检查端口 {PORT} 是否被占用。")
        backend_proc.terminate()
        input("\n按回车键退出...")
        return

    print(f"[4/4] 后端就绪，正在打开浏览器...")

    # 5. 打开浏览器
    webbrowser.open(f"http://localhost:{PORT}")

    print(f"\n{'=' * 60}")
    print(f"  AI 漏洞扫描器已启动")
    print(f"  访问地址：http://localhost:{PORT}")
    print(f"  API 文档：http://localhost:{PORT}/docs")
    print(f"  按 Ctrl+C 停止服务")
    print(f"{'=' * 60}\n")

    # 保持运行
    try:
        backend_proc.wait()
    except KeyboardInterrupt:
        print("\n[启动器] 正在停止服务...")
        backend_proc.terminate()
        backend_proc.wait()


if __name__ == "__main__":
    main()
