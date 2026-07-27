"""
修复训练数据质量（v3 → v4）——2026-07-25

修复内容：
  1. 更新所有 system 消息为新的 SYSTEM_PROMPT_LITE（数据流导向 + 反清单式指令）
  2. 修复 24 条不坚定安全 CoT（移除 hedge 短语，改为防御有效判定）
  3. 修复 1 条事实错误 CoT（L8: 列表参数 subprocess 被误判为"缺乏有效防御"）

输出：train_chatml_v4.jsonl

用法：
  python3 fix_cot_quality.py
  # 或用 Ollama 重写不坚定 CoT：
  python3 fix_cot_quality.py --use-ollama
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

# 导入新的 SYSTEM_PROMPT_LITE
PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))
from graduation_project.prompts import SYSTEM_PROMPT_LITE

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
INPUT_FILE = DATA_DIR / "train_chatml_v3_fixed.jsonl"
OUTPUT_FILE = DATA_DIR / "train_chatml_v4.jsonl"
FIX_REPORT = DATA_DIR / "cot_quality_fix_report.json"

# Hedge 短语模式（安全样本中的不坚定措辞）
HEDGE_PATTERNS = [
    (r'潜在风险[，。]?', ''),
    (r'潜在的安全隐患[，。]?', ''),
    (r'仍存在潜在的安全隐患[，。]?', ''),
    (r'仍存在潜在风险[，。]?', ''),
    (r'仍存在.*?隐患[，。]?', ''),
    (r'防御力度仍可加强[，。]?', ''),
    (r'可能存在.*?隐患[，。]?', ''),
    (r'未能完全防止.*?[，。]?', ''),
    (r'不能完全防止.*?[，。]?', ''),
    (r'并非绝对.*?[，。]?', ''),
    (r'建议对.*?进行.*?(?:校验|过滤|白名单|控制).*?[，。]?', ''),
    (r'建议.*?(?:校验|过滤|白名单|转义).*?以.*?安全性[，。]?', ''),
    (r'尽管.*?但.*?存在.*?风险[，。]?', ''),
    (r'虽然.*?但.*?仍.*?风险[，。]?', ''),
]

# 事实错误修复（L8: 列表参数 subprocess）
FACTUAL_FIXES = {
    8: {
        # 原文错误："缺乏有效的防御措施" → 应为"列表形式是有效防御"
        "old_snippets": [
            "代码中未对 `host` 进行白名单校验或参数化处理，也未对输入进行转义，缺乏有效的防御措施。",
            "尽管未发现明显漏洞，但代码存在潜在风险，建议对 `host` 进行严格的输入校验和白名单控制以提升安全性。",
            "若输入未经过验证，可能导致命令注入漏洞。",
            "未经过任何过滤或校验，存在直接拼接命令的风险。",
        ],
        "new_snippets": [
            "代码使用 `subprocess.run(['ping', host])` 列表形式传参，shell 默认 False，列表参数不触发 shell 解释，是命令注入的有效防御。",
            "列表形式确保 `host` 作为独立参数传递给 ping 进程，不会被 shell 解析为元字符，防御有效，无漏洞。",
            "列表形式不触发 shell 解释，不存在命令注入风险。",
            "`host` 作为列表元素传递给 subprocess.run，不经过 shell 解析，数据流安全。",
        ],
    },
}

# 安全样本结论的坚定版本（替换含糊结论）
CONFIDENT_CONCLUSIONS = [
    (r'综合判断，代码未发现明显.*?漏洞.*?因此无漏洞[。]?',
     '综合判断，防御措施有效，无漏洞。'),
    (r'综合来看，.*?未发现可利用的漏洞[。]?',
     '综合判断，防御措施有效，无漏洞。'),
    (r'综合来看，.*?未构成实际漏洞[。]?',
     '综合判断，防御措施有效，无漏洞。'),
    (r'尽管.*?但.*?未.*?漏洞.*?[。]?',
     '防御措施有效，无漏洞。'),
]


def apply_hedge_fixes(cot: str) -> tuple[str, int]:
    """对安全 CoT 应用 hedge 短语移除。返回 (修复后 CoT, 修复数)。"""
    fix_count = 0
    for pattern, replacement in HEDGE_PATTERNS:
        new_cot, n = re.subn(pattern, replacement, cot)
        if n > 0:
            cot = new_cot
            fix_count += n
    
    # 应用结论修复
    for pattern, replacement in CONFIDENT_CONCLUSIONS:
        new_cot, n = re.subn(pattern, replacement, cot)
        if n > 0:
            cot = new_cot
            fix_count += n
    
    # 清理多余空格和空行
    cot = re.sub(r'  +', ' ', cot)
    cot = re.sub(r'\n\n+', '\n', cot)
    
    return cot, fix_count


def apply_factual_fixes(line_no: int, cot: str) -> tuple[str, bool]:
    """对特定行号的事实错误 CoT 应用定向修复。"""
    if line_no not in FACTUAL_FIXES:
        return cot, False
    
    fixes = FACTUAL_FIXES[line_no]
    changed = False
    for old, new in zip(fixes["old_snippets"], fixes["new_snippets"]):
        if old in cot:
            cot = cot.replace(old, new)
            changed = True
    
    return cot, changed


def rewrite_with_ollama(cot: str, code: str, is_vuln: bool) -> str:
    """用 Ollama 重写不坚定 CoT 为坚定版本。"""
    import urllib.request
    
    verdict = "有漏洞" if is_vuln else "无漏洞"
    prompt = f"""请重写以下安全分析 CoT，使其对防御措施的判定更加坚定。

要求：
1. 保留数据流推理结构（输入点 → 数据流 → sink → 防御评估 → 结论）
2. 移除所有含糊措辞：不要出现"潜在风险""防御力度仍可加强""仍存在隐患"等
3. 若防御措施有效，明确判定"防御有效，无漏洞"
4. 若确实有漏洞，明确说明漏洞类型和攻击方式
5. 不要逐项列举漏洞类型检查
6. 保持简洁，不要超过 300 字
7. 不要包含 JSON 块，只输出分析过程

原 CoT：
{cot}

代码：
{code[:2000]}

正确结论：{verdict}

重写后的 CoT（只输出分析过程，不要 JSON）："""

    data = json.dumps({
        "model": "qwen3:8b",
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "options": {"temperature": 0.3, "num_ctx": 8192},
    }).encode()
    
    req = urllib.request.Request(
        "http://localhost:11434/api/chat",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read())
            return result["message"]["content"].strip()
    except Exception as e:
        print(f"  Ollama 重写失败: {e}", file=sys.stderr)
        return cot  # 返回原文


def main():
    parser = argparse.ArgumentParser(description="修复训练数据 CoT 质量（v3→v4）")
    parser.add_argument("--use-ollama", action="store_true",
                        help="用 Ollama 重写不坚定 CoT（更慢但质量更好）")
    args = parser.parse_args()

    print(f"输入: {INPUT_FILE}")
    print(f"输出: {OUTPUT_FILE}")
    print()

    # 读取所有样本
    samples = []
    with open(INPUT_FILE) as f:
        for line in f:
            samples.append(json.loads(line))
    print(f"读取 {len(samples)} 条样本")

    # 统计
    stats = {
        "system_updated": 0,
        "hedge_fixed": 0,
        "factual_fixed": 0,
        "ollama_rewritten": 0,
    }
    fix_details = []

    # 1. 更新所有 system 消息
    new_system = SYSTEM_PROMPT_LITE
    for i, obj in enumerate(samples, 1):
        old_system = obj["messages"][0]["content"]
        if old_system != new_system:
            obj["messages"][0]["content"] = new_system
            stats["system_updated"] += 1
    
    print(f"✓ 更新 {stats['system_updated']} 条 system 消息")

    # 2. 修复不坚定安全 CoT
    hedge_phrases = [
        r'潜在风险', r'潜在的安全', r'仍存在.*风险', r'仍可加强',
        r'建议.*校验', r'建议.*过滤', r'建议.*白名单', r'建议.*转义',
        r'防御力度', r'进一步提升', r'仍存在.*隐患', r'可能存在.*隐患',
        r'未能完全', r'不能完全', r'并非绝对',
    ]

    for i, obj in enumerate(samples, 1):
        for msg in obj["messages"]:
            if msg["role"] != "assistant":
                continue
            content = msg["content"]
            cot = content.split("```json")[0]
            json_part = content[len(cot):]
            
            is_vuln = '"has_vulnerability": true' in content
            
            # 只修复安全样本
            if is_vuln:
                continue
            
            # 检查是否有 hedge 短语
            has_hedge = any(re.search(pat, cot) for pat in hedge_phrases)
            if not has_hedge:
                continue

            # 先应用事实修复
            cot, factual_changed = apply_factual_fixes(i, cot)
            if factual_changed:
                stats["factual_fixed"] += 1
                fix_details.append({"line": i, "type": "factual", "changed": factual_changed})

            # 再应用 hedge 修复
            cot, hedge_count = apply_hedge_fixes(cot)
            if hedge_count > 0:
                stats["hedge_fixed"] += 1
                fix_details.append({"line": i, "type": "hedge", "count": hedge_count})

            # 如果用了 Ollama，进一步重写
            if args.use_ollama and (hedge_count > 0 or factual_changed):
                # 获取代码
                code = ""
                for m in obj["messages"]:
                    if m["role"] == "user":
                        code = m["content"]
                        break
                print(f"  L{i}: Ollama 重写中...", end="", flush=True)
                new_cot = rewrite_with_ollama(cot, code, is_vuln)
                if new_cot != cot:
                    cot = new_cot
                    stats["ollama_rewritten"] += 1
                    print(" ✓")
                else:
                    print(" (未变)")
                time.sleep(0.5)

            # 重新组装
            msg["content"] = cot + json_part
            break

    print(f"✓ 修复 {stats['hedge_fixed']} 条 hedge CoT")
    print(f"✓ 修复 {stats['factual_fixed']} 条事实错误 CoT")
    if args.use_ollama:
        print(f"✓ Ollama 重写 {stats['ollama_rewritten']} 条 CoT")

    # 3. 写出
    with open(OUTPUT_FILE, "w") as f:
        for obj in samples:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    print(f"\n✓ 写出 {len(samples)} 条到 {OUTPUT_FILE}")

    # 4. 保存修复报告
    with open(FIX_REPORT, "w") as f:
        json.dump({"stats": stats, "fix_details": fix_details}, f, ensure_ascii=False, indent=2)
    print(f"✓ 修复报告: {FIX_REPORT}")


if __name__ == "__main__":
    main()
