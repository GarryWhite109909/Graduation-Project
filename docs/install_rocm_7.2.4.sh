#!/usr/bin/env bash
set -euo pipefail

# 安装 ROCm 7.2.4（使用 noble/24.04 源）到 Ubuntu 26.04
# 注意：Ubuntu 26.04 不是 ROCm 7.2.4 官方列出的支持版本，使用 noble 源属于强制安装。

echo "==> 1. 清理旧的 ROCm apt 配置（如果存在）"
sudo rm -f /etc/apt/keyrings/rocm.gpg
sudo rm -f /etc/apt/sources.list.d/rocm.list
sudo rm -f /etc/apt/sources.list.d/amdgpu.list

echo "==> 2. 移除 Ubuntu 自带的旧 rocm-smi，避免与 AMD 源包冲突"
sudo apt-get remove -y rocm-smi librocm-smi64-7 || true

echo "==> 3. 导入 ROCm GPG key 并添加 7.2.4 noble 源"
sudo mkdir -p --mode=0755 /etc/apt/keyrings
wget -q -O - https://repo.radeon.com/rocm/rocm.gpg.key \
    | sudo gpg --dearmor -o /etc/apt/keyrings/rocm.gpg

echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/rocm.gpg] https://repo.radeon.com/rocm/apt/7.2.4 noble main" \
    | sudo tee /etc/apt/sources.list.d/rocm.list

echo "==> 4. 设置 apt 优先级，优先使用 AMD 官方源的所有包"
printf 'Package: *\nPin: origin repo.radeon.com\nPin-Priority: 1001\n' \
    | sudo tee /etc/apt/preferences.d/99-rocm

echo "==> 5. 更新 apt 缓存"
sudo apt-get update

echo "==> 6. 安装 ROCm 7.2.4（元包 rocm 包含运行时与开发库）"
sudo apt-get install -y rocm

echo "==> 7. 将当前用户加入 render/video 组（使用 GPU 需要）"
sudo usermod -a -G render,video "$USER"

echo "==> 安装完成。请退出当前登录会话并重新登录，或执行 'newgrp render' 使组权限生效。"
echo "==> 验证命令：rocminfo | head -20  或  hipcc --version"
