"""
合并训练数据 —— 高质量版（去除换皮增强）。

输入：
  1. data/train_chatml.jsonl           （build_dataset.py 产出，222 条）
  2. data/distill_corpus_annotated.jsonl 或 v2（generate_distill_data.py 产出，400 条标注）
  3. data/supplement_chatml.jsonl       （supplement_hard_samples.py 产出，对抗性补充样本）

流程：
  1. 读取原始训练数据（222 条 ChatML）
  2. 读取蒸馏标注数据（400 条，优先用 v2 版本——教师模型生成的多样化 CoT）
  3. 转为 ChatML 格式
  4. 合并 → data/train_chatml_v2.jsonl（622 条，无换皮复制）
  5. 应用 SYSTEM_PROMPT_LITE（精简版 system prompt，~600 字符）
  6. 规范化 vuln_type 命名（去括号变体 + 统一中英文）

设计原则：
  - 质量优先：622 条高质量样本 > 1866 条换皮复制
  - 不做变量重命名增强（不改语义，只增加模板记忆）
  - 不做日志注入（纯噪声，不增加推理能力）
  - 安全样本的 explanation 必须描述具体防御措施，不使用统一模板
  - system prompt 精简化：去掉规则条文，让模型从 CoT 样本中学习判断

用法：
  cd /home/zane/文档/code/毕业设计
  PYTHONPATH=. /home/zane/miniconda3/envs/AI/bin/python \
      experiments/exp_06_finetune/scripts/combine_and_augment.py

  # 指定使用 v1（模板版）而非 v2（教师模型版）
  PYTHONPATH=. python experiments/exp_06_finetune/scripts/combine_and_augment.py --use-v1
"""

import argparse
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import SYSTEM_PROMPT_LITE, build_user_prompt
from experiments.exp_06_finetune.scripts.format_distilled import build_messages, build_json_verdict

DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"
ORIGINAL_FILE = DATA_DIR / "train_chatml.jsonl"
DISTILL_V2 = DATA_DIR / "distill_corpus_annotated_v2.jsonl"
DISTILL_V1 = DATA_DIR / "distill_corpus_annotated.jsonl"
SUPPLEMENT_FILE = DATA_DIR / "supplement_chatml.jsonl"
SUPPLEMENT_LONGTAIL_FILE = DATA_DIR / "supplement_longtail_cwe.jsonl"
SUPPLEMENT_CRYPTO_NOISE_FILE = DATA_DIR / "supplement_crypto_noise.jsonl"
SUPPLEMENT_LONGFILE_DEFENSE_FILE = DATA_DIR / "supplement_longfile_defense.jsonl"
SUPPLEMENT_7B_WEAKNESS_FILE = DATA_DIR / "supplement_7b_weakness.jsonl"
SUPPLEMENT_BLINDSPOT_FILE = DATA_DIR / "supplement_blindspot_cwe.jsonl"
SUPPLEMENT_CWE_ATTR_SSTI_FILE = DATA_DIR / "supplement_cwe_attribution_ssti.jsonl"
SUPPLEMENT_CWE_ATTR_NOSQL_FILE = DATA_DIR / "supplement_cwe_attribution_nosql.jsonl"
SUPPLEMENT_CWE_ATTR_SPEL_FILE = DATA_DIR / "supplement_cwe_attribution_spel.jsonl"
SUPPLEMENT_CCOT_CONTRASTIVE_FILE = DATA_DIR / "supplement_ccot_contrastive.jsonl"
OUTPUT_FILE = DATA_DIR / "train_chatml_v2.jsonl"


# ---------------------------------------------------------------------------
# vuln_type 规范化映射 —— 同一 CWE 编号内的变体合并到主名
# ---------------------------------------------------------------------------
# 设计原则：
#   - 按 CWE 编号归并，去掉括号变体（如 XSS(DOM) → XSS）
#   - 统一中英文（如 "会话固定" → "Session Fixation"）
#   - 不同 CWE 编号的小类保留（如 CWE-601 开放重定向 ≠ CWE-22 路径穿越）
#   - 主名优先选用样本量最大的命名
# ---------------------------------------------------------------------------
VTYPE_NORMALIZE = {
    # CWE-22 路径穿越（7 个变体 → 1 个主名）
    "CWE-22 路径穿越(tar)": "CWE-22 路径穿越",
    "CWE-22 路径穿越(Zip Slip)": "CWE-22 路径穿越",
    "CWE-22 路径穿越(Null Byte)": "CWE-22 路径穿越",
    "CWE-22 路径穿越(Symlink)": "CWE-22 路径穿越",
    "CWE-22 路径穿越(Windows)": "CWE-22 路径穿越",
    "CWE-22 路径穿越(编码绕过)": "CWE-22 路径穿越",
    # CWE-79 XSS（4 个变体 → 1 个主名）
    "CWE-79 XSS(DOM)": "CWE-79 XSS",
    "CWE-79 XSS(存储型)": "CWE-79 XSS",
    "CWE-79 XSS(反射型)": "CWE-79 XSS",
    "CWE-79 XSS(JavaScript URL)": "CWE-79 XSS",
    # CWE-89 SQL注入
    "CWE-89 SQL注入(二次)": "CWE-89 SQL注入",
    # CWE-78 命令注入
    "CWE-78 命令注入(环境变量)": "CWE-78 命令注入",
    # CWE-94 代码注入（含 SSTI 归并）
    "CWE-94 代码注入(跨文件)": "CWE-94 代码注入",
    "CWE-94 代码注入(SSTI)": "CWE-94 代码注入",
    "CWE-94 SSTI": "CWE-94 代码注入",
    "CWE-1336 SSTI": "CWE-94 代码注入",
    # CWE-95 eval 注入（4 个变体）
    "CWE-95 preg_replace /e 注入": "CWE-95 eval 注入",
    "CWE-95 assert 代码执行": "CWE-95 eval 注入",
    "CWE-95 Function 构造器注入": "CWE-95 eval 注入",
    "CWE-95 exec 注入": "CWE-95 eval 注入",
    # CWE-98 文件包含（4 个变体）
    "CWE-98 SSTI/模板注入": "CWE-94 代码注入",  # 实际是 SSTI，归到代码注入
    "CWE-98 路径穿越/模板注入": "CWE-94 代码注入",  # 实际是 SSTI
    "CWE-98 文件包含(LFI)空字节绕过": "CWE-98 文件包含(LFI)",
    "CWE-98 服务端包含(LFI)": "CWE-98 文件包含(LFI)",
    # CWE-123 任意地址写（5 个变体）
    "CWE-123 栈缓冲区写越界": "CWE-123 任意地址写",
    "CWE-123 数组越界写(Write-What-Where)": "CWE-123 任意地址写",
    "CWE-123 数组越界写": "CWE-123 任意地址写",
    "CWE-123 任意地址写(unsafe)": "CWE-123 任意地址写",
    "CWE-123 内核任意地址写(CVE风格)": "CWE-123 任意地址写",
    # CWE-134 格式化字符串（6 个变体）
    "CWE-134 Python format 注入": "CWE-134 格式化字符串",
    "CWE-134 Java 格式化字符串": "CWE-134 格式化字符串",
    "CWE-134 syslog 格式化字符串": "CWE-134 格式化字符串",
    "CWE-134 格式串拼接": "CWE-134 格式化字符串",
    "CWE-134 Python % 格式化注入": "CWE-134 格式化字符串",
    "CWE-134 CVE风格格式串(sudo)": "CWE-134 格式化字符串",
    # CWE-209 信息泄露
    "CWE-209 错误信息泄露": "CWE-209 信息泄露",
    # CWE-327 弱密码学
    "CWE-327 弱哈希": "CWE-327 弱密码学",
    # CWE-347 JWT
    "CWE-347 JWT签名未校验": "CWE-347 JWT none 算法绕过",
    # CWE-384 Session Fixation（统一中英文）
    "CWE-384 会话固定": "CWE-384 Session Fixation",
    # CWE-409 解压炸弹（6 个变体）
    "CWE-409 解压炸弹(zip bomb)": "CWE-409 解压炸弹",
    "CWE-409 解压炸弹(Java)": "CWE-409 解压炸弹",
    "CWE-409 gzip 炸弹": "CWE-409 解压炸弹",
    "CWE-409 XML 实体爆炸(Billion Laughs)": "CWE-409 解压炸弹",
    "CWE-409 XML 实体爆炸": "CWE-409 解压炸弹",
    "CWE-409 Node.js gzip 炸弹": "CWE-409 解压炸弹",
    # CWE-434 任意文件上传（5 个变体）
    "CWE-434 Content-Type 绕过": "CWE-434 任意文件上传",
    "CWE-434 双扩展名绕过": "CWE-434 任意文件上传",
    "CWE-434 路径穿越上传": "CWE-434 任意文件上传",
    "CWE-434 CVE风格上传": "CWE-434 任意文件上传",
    "CWE-434 文件上传": "CWE-434 任意文件上传",
    # CWE-502 不安全反序列化
    "CWE-502 反序列化": "CWE-502 不安全反序列化",
    # CWE-613 会话不过期
    "CWE-613 会话过期失效": "CWE-613 会话不过期",
    # CWE-915 批量赋值
    "CWE-915 批量赋值(Spring4Shell)": "CWE-915 批量赋值",
    # CWE-917 表达式注入（JNDI 注入 ≠ SpEL，保持区分）
    "CWE-917 表达式注入(JNDI)": "CWE-917 JNDI注入",
    # CWE-943 NoSQL 注入
    "CWE-943 NoSQL注入": "CWE-943 NoSQL 注入",
}


def normalize_vuln_type(vtype: str) -> str:
    """规范化 vuln_type 命名。

    1. 查 VTYPE_NORMALIZE 映射表
    2. 若未命中，去掉常见括号变体后缀（如 "XXX(某变体)" → "XXX"）
    3. 其他保持原样
    """
    if not vtype or vtype == "none":
        return vtype
    # 1. 精确匹配映射表
    if vtype in VTYPE_NORMALIZE:
        return VTYPE_NORMALIZE[vtype]
    # 2. 兜底：去掉括号变体（如 "CWE-XX 某类型(变体)" → "CWE-XX 某类型"）
    m = re.match(r'^(CWE-\d+\s+[^()（）]+)[（(].*$', vtype)
    if m:
        base = m.group(1).strip()
        # 再查一次映射表（防止去括号后仍需映射）
        return VTYPE_NORMALIZE.get(base, base)
    return vtype


def apply_system_prompt_lite(sample: dict) -> dict:
    """把样本的 system message 替换为 SYSTEM_PROMPT_LITE。"""
    msgs = sample["messages"]
    if msgs and msgs[0].get("role") == "system":
        msgs[0]["content"] = SYSTEM_PROMPT_LITE
    return sample


def normalize_sample_vtype(sample: dict) -> tuple[dict, str]:
    """规范化样本 assistant message 中的 vulnerability_type 字段。

    返回 (处理后的样本, 原始vuln_type) 便于统计。
    """
    msgs = sample["messages"]
    for m in msgs:
        if m.get("role") != "assistant":
            continue
        content = m["content"]
        # 匹配 ```json ... ``` 块
        json_block_match = re.search(r'(```json\s*\{.*?\}\s*```)', content, re.DOTALL)
        if not json_block_match:
            continue
        json_block = json_block_match.group(1)
        # 提取内层 JSON
        inner_match = re.search(r'```json\s*(\{.*?\})\s*```', json_block, re.DOTALL)
        if not inner_match:
            continue
        try:
            verdict = json.loads(inner_match.group(1))
        except json.JSONDecodeError:
            continue
        orig_vtype = verdict.get("vulnerability_type", "")
        new_vtype = normalize_vuln_type(orig_vtype)
        if new_vtype != orig_vtype:
            verdict["vulnerability_type"] = new_vtype
            # 重新序列化 JSON 块
            new_json_str = json.dumps(verdict, ensure_ascii=False, indent=2)
            new_json_block = f"```json\n{new_json_str}\n```"
            m["content"] = content.replace(json_block, new_json_block)
        return sample, orig_vtype
    return sample, ""


def main():
    parser = argparse.ArgumentParser(description="合并高质量训练数据（无换皮增强）")
    parser.add_argument("--use-v1", action="store_true",
                        help="使用 v1（模板版）蒸馏数据而非 v2（教师模型版）")
    args = parser.parse_args()

    print("=" * 60)
    print("合并训练数据：原始 + 蒸馏（高质量版，无换皮增强）")
    print("=" * 60)

    # 1. 读取原始训练数据
    print(f"\n[1] 读取 {ORIGINAL_FILE.name}...")
    original_samples = []
    with open(ORIGINAL_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                original_samples.append(json.loads(line))
    print(f"    {len(original_samples)} 条")

    # 2. 读取蒸馏标注数据（优先 v2）
    distill_file = DISTILL_V1 if args.use_v1 else DISTILL_V2
    if not distill_file.exists():
        if not args.use_v1:
            print(f"\n[!] v2 蒸馏数据不存在: {distill_file}")
            print(f"    回退到 v1: {DISTILL_V1}")
            distill_file = DISTILL_V1
        else:
            print(f"\n错误：蒸馏数据不存在: {distill_file}")
            sys.exit(1)

    print(f"\n[2] 读取 {distill_file.name}...")
    distill_samples = []
    with open(distill_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                distill_samples.append(json.loads(line))
    print(f"    {len(distill_samples)} 条")

    # 3. 转换蒸馏数据为 ChatML
    print(f"\n[3] 转换蒸馏数据为 ChatML...")
    distill_chatml = []
    for rec in distill_samples:
        messages = build_messages(rec)
        distill_chatml.append(messages)
    print(f"    {len(distill_chatml)} 条 ChatML")

    # 3.5 读取补充对抗性样本
    supplement_samples = []
    if SUPPLEMENT_FILE.exists():
        print(f"\n[3.5] 读取 {SUPPLEMENT_FILE.name}...")
        with open(SUPPLEMENT_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    supplement_samples.append(json.loads(line))
        print(f"    {len(supplement_samples)} 条")
    else:
        print(f"\n[3.5] 补充样本文件不存在: {SUPPLEMENT_FILE}（跳过）")
        print("       提示：运行 supplement_hard_samples.py 生成")

    # 3.6 读取长尾 CWE 补充样本
    if SUPPLEMENT_LONGTAIL_FILE.exists():
        print(f"\n[3.6] 读取 {SUPPLEMENT_LONGTAIL_FILE.name}...")
        with open(SUPPLEMENT_LONGTAIL_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    supplement_samples.append(json.loads(line))
        print(f"    长尾 CWE 补充已加入，supplement 总计: {len(supplement_samples)} 条")

    # 3.7 读取 Crypto + Noise 补充样本
    if SUPPLEMENT_CRYPTO_NOISE_FILE.exists():
        print(f"\n[3.7] 读取 {SUPPLEMENT_CRYPTO_NOISE_FILE.name}...")
        cn_count = 0
        with open(SUPPLEMENT_CRYPTO_NOISE_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    supplement_samples.append(json.loads(line))
                    cn_count += 1
        print(f"    Crypto+Noise 补充 {cn_count} 条，supplement 总计: {len(supplement_samples)} 条")

    # 3.8 读取长文件 + 伪防御 + 跨文件补充样本
    if SUPPLEMENT_LONGFILE_DEFENSE_FILE.exists():
        print(f"\n[3.8] 读取 {SUPPLEMENT_LONGFILE_DEFENSE_FILE.name}...")
        ld_count = 0
        with open(SUPPLEMENT_LONGFILE_DEFENSE_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    supplement_samples.append(json.loads(line))
                    ld_count += 1
        print(f"    长文件+伪防御+跨文件 补充 {ld_count} 条，supplement 总计: {len(supplement_samples)} 条")

    # 3.9 读取 7B 薄弱点补充样本（crossfile input 安全、shlex/session 安全、漏报漏洞补充）
    if SUPPLEMENT_7B_WEAKNESS_FILE.exists():
        print(f"\n[3.9] 读取 {SUPPLEMENT_7B_WEAKNESS_FILE.name}...")
        w7_count = 0
        with open(SUPPLEMENT_7B_WEAKNESS_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    supplement_samples.append(json.loads(line))
                    w7_count += 1
        print(f"    7B 薄弱点 补充 {w7_count} 条，supplement 总计: {len(supplement_samples)} 条")

    # 3.10 读取盲区 CWE 补充样本（日志注入/弱随机数/弱密码学，补齐分类法盲区）
    if SUPPLEMENT_BLINDSPOT_FILE.exists():
        print(f"\n[3.10] 读取 {SUPPLEMENT_BLINDSPOT_FILE.name}...")
        bs_count = 0
        with open(SUPPLEMENT_BLINDSPOT_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    supplement_samples.append(json.loads(line))
                    bs_count += 1
        print(f"    盲区 CWE 补充 {bs_count} 条，supplement 总计: {len(supplement_samples)} 条")

    # 3.11 读取 CWE 归因补充样本（SSTI/NoSQL/SpEL，教模型区分 CWE 编号）
    for cwe_attr_file, label in [
        (SUPPLEMENT_CWE_ATTR_SSTI_FILE, "CWE-94 SSTI"),
        (SUPPLEMENT_CWE_ATTR_NOSQL_FILE, "CWE-643 NoSQL"),
        (SUPPLEMENT_CWE_ATTR_SPEL_FILE, "CWE-917 SpEL"),
    ]:
        if cwe_attr_file.exists():
            print(f"\n[3.11] 读取 {cwe_attr_file.name}...")
            attr_count = 0
            with open(cwe_attr_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        supplement_samples.append(json.loads(line))
                        attr_count += 1
            print(f"    {label} 归因补充 {attr_count} 条，supplement 总计: {len(supplement_samples)} 条")

    # 3.12 读取 CCoT 对比样本（shell=True 偏见 / SSTI 概念混淆 / 结论漂移）
    if SUPPLEMENT_CCOT_CONTRASTIVE_FILE.exists():
        print(f"\n[3.12] 读取 {SUPPLEMENT_CCOT_CONTRASTIVE_FILE.name}...")
        ccot_count = 0
        with open(SUPPLEMENT_CCOT_CONTRASTIVE_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    supplement_samples.append(json.loads(line))
                    ccot_count += 1
        print(f"    CCoT 对比样本 {ccot_count} 条，supplement 总计: {len(supplement_samples)} 条")
    else:
        print(f"\n[3.12] CCoT 对比样本文件不存在: {SUPPLEMENT_CCOT_CONTRASTIVE_FILE}（跳过）")

    # 4. 合并
    print(f"\n[4] 合并所有数据...")
    all_samples = original_samples + distill_chatml + supplement_samples
    print(f"    总计: {len(all_samples)} 条")

    # 5. 应用 SYSTEM_PROMPT_LITE（精简版 system prompt）
    print(f"\n[5] 应用 SYSTEM_PROMPT_LITE（精简版 system prompt, {len(SYSTEM_PROMPT_LITE)} 字符）...")
    for s in all_samples:
        apply_system_prompt_lite(s)
    print(f"    已替换 {len(all_samples)} 条样本的 system prompt")

    # 6. 规范化 vuln_type 命名
    print(f"\n[6] 规范化 vuln_type 命名...")
    normalize_count = 0
    vtype_changes = {}
    for s in all_samples:
        s, orig_vtype = normalize_sample_vtype(s)
        if orig_vtype:
            new_vtype = normalize_vuln_type(orig_vtype)
            if new_vtype != orig_vtype:
                normalize_count += 1
                vtype_changes[orig_vtype] = new_vtype
    print(f"    规范化 {normalize_count} 条样本的 vuln_type")
    if vtype_changes:
        print(f"    映射变化（共 {len(vtype_changes)} 种）:")
        for old, new in sorted(vtype_changes.items()):
            print(f"      {old!r} → {new!r}")

    # 7. 统计
    vuln = 0
    safe = 0
    for s in all_samples:
        assistant_msg = s["messages"][-1]["content"]
        if '"has_vulnerability": true' in assistant_msg:
            vuln += 1
        elif '"has_vulnerability": false' in assistant_msg:
            safe += 1
    print(f"\n[7] 标签分布: 漏洞: {vuln}  安全: {safe}")

    # 统计 vuln_type 分布
    from collections import Counter
    vtype_counter = Counter()
    for s in all_samples:
        _, orig_vtype = normalize_sample_vtype(s)
        if orig_vtype:
            vtype_counter[normalize_vuln_type(orig_vtype)] += 1
    print(f"    vuln_type 分布（规范化后）:")
    for t, c in vtype_counter.most_common(20):
        print(f"      {c:4d}  {t}")

    # 检查安全样本 explanation 多样性
    safe_explanations = set()
    for s in all_samples:
        assistant_msg = s["messages"][-1]["content"]
        if '"has_vulnerability": false' in assistant_msg:
            m = re.search(r'"explanation"\s*:\s*"([^"]*)"', assistant_msg)
            if m:
                safe_explanations.add(m.group(1))
    print(f"    安全样本 explanation 唯一值: {len(safe_explanations)} 种")
    if len(safe_explanations) <= 3:
        print("    ⚠️  警告：安全样本 explanation 过于单一！")
        for expl in list(safe_explanations)[:5]:
            print(f"      '{expl}'")

    # 8. 写入
    print(f"\n[8] 写入 {OUTPUT_FILE.name}...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for s in all_samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"    完成: {OUTPUT_FILE}")

    # 9. 估计 token 数
    total_chars = 0
    for s in all_samples:
        for msg in s["messages"]:
            total_chars += len(msg["content"])
    print(f"    总字符数: {total_chars}  估计 token: ~{total_chars // 4}")


if __name__ == "__main__":
    main()
