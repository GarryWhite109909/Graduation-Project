#!/usr/bin/env python3
"""绘制 Qwen3-8B SFT v2~v6 训练趋势图。"""

import json
import pathlib
import sys

import matplotlib.pyplot as plt
import matplotlib as mpl

mpl.rcParams['font.sans-serif'] = ['DejaVu Sans', 'WenQuanYi Micro Hei', 'SimHei']
mpl.rcParams['axes.unicode_minus'] = False

BASE = pathlib.Path(__file__).resolve().parent.parent
LOG_DIR = BASE / 'logs'
OUT_DIR = BASE / 'results' / 'figures'
OUT_DIR.mkdir(parents=True, exist_ok=True)

LOGS = {
    'v2': 'train_log_r8_e3_lr0.0001_s42_rsloraqwen3_8b_sft_p2.json',
    'v3': 'train_log_r8_e3_lr0.0001_s42_rsloraqwen3_8b_sft_p2_v3.json',
    'v4': 'train_log_r8_e3_lr0.0001_s42_rsloraqwen3_8b_sft_p2_v4.json',
    'v5': 'train_log_r8_e3_lr0.0001_s42_rslora_v5.json',
    'v6': 'train_log_r8_e3_lr0.0001_s42_rslora_v6_hard_neg.json',
}


def load_log(name):
    path = LOG_DIR / name
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def extract_curves(log):
    train_steps, train_loss = [], []
    eval_epochs, eval_loss = [], []
    for entry in log.get('log_history', []):
        if 'loss' in entry and 'eval_loss' not in entry:
            train_steps.append(entry['step'])
            train_loss.append(entry['loss'])
        elif 'eval_loss' in entry:
            eval_epochs.append(entry['epoch'])
            eval_loss.append(entry['eval_loss'])
    return train_steps, train_loss, eval_epochs, eval_loss


def plot_loss_curves():
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    colors = {'v2': '#1f77b4', 'v3': '#ff7f0e', 'v4': '#2ca02c',
              'v5': '#d62728', 'v6': '#9467bd'}

    for version, filename in LOGS.items():
        log = load_log(filename)
        steps, tloss, epochs, eloss = extract_curves(log)
        axes[0].plot(steps, tloss, label=f'{version}', color=colors[version], alpha=0.9, linewidth=1.5)
        axes[1].plot(epochs, eloss, marker='o', label=f'{version}', color=colors[version], linewidth=1.5)

    axes[0].set_xlabel('Step')
    axes[0].set_ylabel('Training Loss')
    axes[0].set_title('Qwen3-8B SFT v2~v6 Training Loss')
    axes[0].legend()
    axes[0].grid(True, alpha=0.3)

    axes[1].set_xlabel('Epoch')
    axes[1].set_ylabel('Eval Loss')
    axes[1].set_title('Qwen3-8B SFT v2~v6 Eval Loss')
    axes[1].legend()
    axes[1].grid(True, alpha=0.3)

    plt.tight_layout()
    out = OUT_DIR / 'sft_v2_v6_loss_trends.png'
    fig.savefig(out, dpi=150, bbox_inches='tight')
    fig.savefig(out.with_suffix('.svg'), bbox_inches='tight')
    print(f'Saved: {out}')
    return out


def plot_metric_trends():
    # 从台账提取的关键指标，按版本顺序
    versions = ['baseline', 'v2', 'v3', 'v5', 'v6']
    synthetic_recall = [0.967, 0.967, 0.984, 1.000, 0.984]
    synthetic_fpr = [0.269, 0.231, 0.192, 0.231, 0.192]
    synthetic_strict_recall = [0.459, 0.623, 0.607, 0.590, 0.557]
    cve_recall = [0.375, 0.625, 0.500, 0.571, 0.429]

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    x = range(len(versions))

    axes[0].plot(x, synthetic_recall, marker='o', label='synthetic recall', linewidth=2)
    axes[0].plot(x, synthetic_strict_recall, marker='s', label='synthetic strict_recall', linewidth=2)
    axes[0].plot(x, synthetic_fpr, marker='^', label='synthetic FPR', linewidth=2)
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(versions)
    axes[0].set_ylim(0, 1.05)
    axes[0].set_ylabel('Score')
    axes[0].set_title('Synthetic Set Metrics Across Versions')
    axes[0].legend()
    axes[0].grid(True, alpha=0.3)

    axes[1].plot(x, cve_recall, marker='o', color='#d62728', label='CVE-fix recall', linewidth=2)
    axes[1].set_xticks(x)
    axes[1].set_xticklabels(versions)
    axes[1].set_ylim(0, 0.7)
    axes[1].set_ylabel('Recall')
    axes[1].set_title('CVE-fix Real Set Recall Across Versions')
    axes[1].legend()
    axes[1].grid(True, alpha=0.3)

    plt.tight_layout()
    out = OUT_DIR / 'sft_v2_v6_metric_trends.png'
    fig.savefig(out, dpi=150, bbox_inches='tight')
    fig.savefig(out.with_suffix('.svg'), bbox_inches='tight')
    print(f'Saved: {out}')
    return out


if __name__ == '__main__':
    plot_loss_curves()
    plot_metric_trends()
