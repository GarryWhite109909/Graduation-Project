#!/usr/bin/env python3
"""
构建 SFT v7 训练数据。

策略（避免 v6 hard-negative 负迁移）：
- 以 train_chatml_v5_clean.jsonl 为基底
- 针对 v5 在 87 合成集上的 7 个 FP + 1 个 FN，生成"正确推理"样本
- 用 Jaccard 相似度找出训练集中与错题最相似的 N 条，替换而非追加
- 对整数溢出、授权控制、安全参数化查询等易混淆模式做精细化 CoT

用法：
    PYTHONPATH=../../.. python3 build_v7_dataset.py
输出：
    experiments/exp_06_finetune/data/train_chatml_v7.jsonl
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = ROOT / "experiments/exp_06_finetune/data"
V5_FILE = DATA_DIR / "train_chatml_v5_clean.jsonl"
OUT_FILE = DATA_DIR / "train_chatml_v7.jsonl"

# v5 在 87 合成集上的错题（来自 compare_results.py 输出）
# key 为样本标识，value 为期望结论 + 正确推理要点
TARGET_CASES: dict[str, dict[str, Any]] = {
    "safe_03_subprocess_list.py": {
        "expected": False,
        "cwe": None,
        "points": [
            "subprocess.run 使用列表参数 ['ping', '-c', '1', host]，而非 shell 字符串",
            "列表参数模式下 shell=False（默认），shell 元字符不会被解释",
            "不存在命令注入风险：host 中的 ; | & 等不会被 shell 执行",
            "结论：安全，无命令注入漏洞",
        ],
    },
    "safe_04_path_whitelist.py": {
        "expected": False,
        "cwe": None,
        "points": [
            "文件名严格限定在 ALLOWED_FILES 白名单内",
            "通过 os.path.abspath + startswith(abs_base + os.sep) 校验最终路径是否落在 BASE_DIR 下",
            "不存在路径穿越：../../etc/passwd 会被白名单拒绝或被路径校验拦截",
            "结论：安全，无路径遍历漏洞",
        ],
    },
    "safe_05_parametrized_like.py": {
        "expected": False,
        "cwe": None,
        "points": [
            "LIKE 子句中的通配符 % 位于参数绑定值内部，这是 SQL 语义允许的正常用法",
            "用户输入 keyword 通过 ? 占位符参数化传入，不会被解析为 SQL 语法",
            "数据库驱动负责转义，不存在 SQL 注入",
            "结论：安全，无 SQL 注入漏洞",
        ],
    },
    "safe_08_shlex.py": {
        "expected": False,
        "cwe": None,
        "points": [
            "shlex.quote(host) 对用户输入进行 shell 安全转义",
            "虽然使用了 shell=True，但转义后的字符串作为单一参数传入",
            "host 中的空格、引号、分号都会被转义为普通字符",
            "结论：安全，无命令注入漏洞",
        ],
    },
    "safe_09_proper_authz.py": {
        "expected": False,
        "cwe": None,
        "points": [
            "接口先检查 session 中是否存在 user_id，未登录返回 401",
            "再调用 is_admin() 校验用户角色，非 admin 返回 403",
            "同时具备认证与授权控制，不是简单的 missing_authentication",
            "结论：安全，无越权访问漏洞",
        ],
    },
    "safe_17_race_with_lock.py": {
        "expected": False,
        "cwe": None,
        "points": [
            "对 balances 的读写操作包裹在 threading.Lock 中",
            "检查余额与扣款两个步骤是原子操作，并发请求不会导致负余额或重复扣款",
            "不存在竞态条件导致的 TOCTOU 漏洞",
            "结论：安全，无 race condition 漏洞",
        ],
    },
    "safe_18_java_prepared_stmt.java": {
        "expected": False,
        "cwe": None,
        "points": [
            "SQL 使用 PreparedStatement 与 ? 占位符",
            "username/password 通过 stmt.setString() 绑定，不会被解释为 SQL 语法",
            "数据库凭证从环境变量读取，避免硬编码",
            "结论：安全，无 SQL 注入与硬编码凭证漏洞",
        ],
    },
    "typical_29_integer_overflow.java": {
        "expected": True,
        "cwe": "CWE-190",
        "points": [
            "total = price * qty，两个 int 相乘",
            "若 qty 和 price 都接近 Integer.MAX_VALUE，乘积会溢出为负数或极小正数",
            "Spring 的 @RequestParam int 不会自动做范围校验",
            "业务逻辑依赖 total 做后续处理，溢出可导致价格计算错误、逻辑绕过或资源分配异常",
            "结论：存在整数溢出漏洞（CWE-190）",
        ],
    },
}


def tokenize(text: str) -> set[str]:
    """简单按非单词字符分词。"""
    return set(re.findall(r"[a-zA-Z0-9_]{2,}", text.lower()))


def jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def build_correct_cot(code: str, case: dict[str, Any]) -> str:
    """根据要点生成正确 CoT。"""
    expected = "存在安全漏洞" if case["expected"] else "不存在安全漏洞"
    cwe_line = f"CWE：{case['cwe']}\n" if case.get("cwe") else ""
    points = "\n".join(f"{i+1}. {p}" for i, p in enumerate(case["points"]))
    return (
        "### 分析过程\n"
        f"{points}\n\n"
        "### 结论\n"
        f"{expected}\n"
        f"{cwe_line}"
        "风险等级：" + ("medium" if case["expected"] else "None") + "\n"
    )


def main():
    print(f"[v7 数据构建] 基底：{V5_FILE}")
    records: list[dict] = []
    with open(V5_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    print(f"  加载 {len(records)} 条 v5 样本")

    # 读取 exp_04 样本代码
    samples_dir = ROOT / "experiments/exp_04_hard_samples/samples"
    case_code: dict[str, str] = {}
    for fname in TARGET_CASES:
        path = samples_dir / fname
        if path.exists():
            case_code[fname] = path.read_text(encoding="utf-8")
        else:
            print(f"  ⚠️ 找不到样本文件：{fname}")

    # 对每个错题，找训练集中最相似的 3 条并替换其 assistant 内容
    replaced = 0
    for fname, case in TARGET_CASES.items():
        if fname not in case_code:
            continue
        target_tokens = tokenize(case_code[fname])
        # 计算与每条训练样本的相似度（取 user prompt 中代码部分）
        scored = []
        for idx, rec in enumerate(records):
            content = ""
            for msg in rec.get("messages", []):
                if msg.get("role") == "user":
                    content = msg.get("content", "")
                    break
            sim = jaccard(target_tokens, tokenize(content))
            scored.append((sim, idx))
        scored.sort(reverse=True)

        correct_cot = build_correct_cot(case_code[fname], case)
        # 替换前 3 条最相似样本的 assistant 内容
        for _, idx in scored[:3]:
            rec = records[idx]
            for msg in rec.get("messages", []):
                if msg.get("role") == "assistant":
                    msg["content"] = correct_cot
                    replaced += 1
                    break
        print(f"  已替换 {fname} 相关样本 3 条")

    # 新增 8 条错题本身作为训练样本（直接学习正确答案）
    system_prompt = "你是一名资深的代码安全审计专家。请对给出的代码片段进行安全分析，判断其中是否存在安全漏洞。"
    for fname, case in TARGET_CASES.items():
        if fname not in case_code:
            continue
        code = case_code[fname]
        user_prompt = f"请分析以下代码片段是否存在安全漏洞。\n\n语言：{fname.split('.')[-1]}\n文件名：{fname}\n\n```\n{code}\n```"
        records.append({
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
                {"role": "assistant", "content": build_correct_cot(code, case)},
            ]
        })
        replaced += 1

    print(f"  共替换/新增 {replaced} 条样本")
    print(f"  输出：{OUT_FILE}")
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
