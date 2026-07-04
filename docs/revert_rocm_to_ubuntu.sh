#!/usr/bin/env bash
set -euo pipefail

# 回退到 Ubuntu 官方仓库的 ROCm（当前是 7.1.x）

echo "==> 1. 移除 AMD ROCm 7.2.4 元包及其依赖"
sudo apt-get remove --purge -y rocm
sudo apt-get autoremove --purge -y

# 如果还有带 70204 版本号的 AMD 包残留，继续清理
echo "==> 2. 清理可能残留的 AMD ROCm 7.2.4 包"
remaining=$(dpkg -l | grep -E '70204|repo.radeon.com' | awk '{print $2}' || true)
if [ -n "$remaining" ]; then
    echo "$remaining" | xargs -r sudo apt-get remove --purge -y
fi

echo "==> 3. 移除 AMD 源和 apt 优先级配置"
sudo rm -f /etc/apt/sources.list.d/rocm.list
sudo rm -f /etc/apt/preferences.d/99-rocm
sudo rm -f /etc/apt/keyrings/rocm.gpg

echo "==> 4. 更新 apt 缓存"
sudo apt-get update

echo "==> 5. 安装 Ubuntu 官方仓库的 ROCm"
sudo apt-get install -y rocm rocm-smi rocminfo

echo "==> 6. 将当前用户加入 render/video 组"
sudo usermod -a -G render,video "$USER"

echo "==> 完成。请重启系统或重新登录，然后运行："
echo "    rocminfo | head -20"
echo "    rocm-smi"
echo "如果 Ollama 仍在运行，建议重启 Ollama 服务：sudo systemctl restart ollama"
