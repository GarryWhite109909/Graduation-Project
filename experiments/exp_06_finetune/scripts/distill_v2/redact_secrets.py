"""扫描并替换蒸馏数据里的示例密钥，绕过 GitHub Push Protection。

蒸馏生成的"硬编码凭证漏洞"示例代码里含形似真实的密钥字符串，
GitHub Push Protection 不区分真假会拦截。本脚本把密钥 body 替换成 REDACTED，
保留类型前缀（sk_live_/hooks.slack.com 等）维持教学语义，但破坏密钥格式使其不触发扫描。

处理范围：deepseek_cc_memory.jsonl / deepseek_pentest.jsonl 及其 _progress failed 文件。
"""
import json
import re
from pathlib import Path

DATA_DIR = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\distill_v2")

# 密钥格式正则 → 替换规则（保留语义前缀，body 改 REDACTED）
SECRET_PATTERNS = [
    # Slack Incoming Webhook URL: https://hooks.slack.com/services/T.../B.../...
    (re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{10,}"),
     "https://hooks.slack.com/services/REDACTED"),
    # Stripe live/test/restricted key: sk_live_xxx / sk_test_xxx / rk_live_xxx
    (re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b"),
     "sk_live_REDACTED"),
    # AWS Access Key ID: AKIA + 16 位
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "AKIA_REDACTED_PLACEHOLDER"),
    # GitHub token: ghp_/gho_/ghu_/ghs_/ghr_ + 36 位
    (re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b"),
     "ghp_REDACTED"),
    # Google API key: AIza + 35 位
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
     "AIza_REDACTED"),
    # GCP OAuth token: ya29.xxx
    (re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}\b"),
     "ya29.REDACTED"),
    # JWT (eyJ 开头，3 段 base64): 只匹配足够长的
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b"),
     "eyJREDACTED.REDACTED.REDACTED"),
]


def scan_and_replace(text: str):
    """返回 (替换后文本, 命中数, 命中详情列表)。"""
    hits = []
    new_text = text
    for pat, repl in SECRET_PATTERNS:
        for m in pat.finditer(new_text):
            hits.append((m.group(0)[:60], repl))
        new_text = pat.sub(repl, new_text)
    return new_text, len(hits), hits


def process_file(path: Path):
    if not path.exists():
        print(f"[跳过] {path.name} 不存在")
        return 0

    lines = path.read_text(encoding="utf-8").splitlines()
    total_hits = 0
    all_hits = []
    new_lines = []
    changed = False

    for i, line in enumerate(lines, 1):
        new_line, hits, details = scan_and_replace(line)
        if hits > 0:
            total_hits += hits
            all_hits.append((i, details))
            changed = True
        new_lines.append(new_line)

    if changed:
        path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        print(f"\n[{path.name}] 替换 {total_hits} 处:")
        for lineno, details in all_hits:
            for orig, repl in details:
                print(f"  行 {lineno}: {orig}... → {repl}")
    else:
        print(f"[{path.name}] 无密钥命中 ✅")
    return total_hits


total = 0
for name in [
    "deepseek_cc_memory.jsonl",
    "deepseek_pentest.jsonl",
    "_progress/deepseek_cc_memory_failed.jsonl",
    "_progress/deepseek_pentest_failed.jsonl",
]:
    total += process_file(DATA_DIR / name)

print(f"\n=== 总计替换 {total} 处密钥 ===")
