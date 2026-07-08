"""
数据增强脚本 —— 通过变量重命名 / 日志注入 / 注释混淆生成增强训练样本。

目标：让模型不依赖具体变量名/函数名识别漏洞，提升对真实代码的泛化能力。
  - 同一漏洞样本的不同写法应被识别为同一漏洞
  - 同一安全样本的不同写法应保持安全判定

工作方式：
  1. 从 build_dataset 导入 SAMPLES（含元数据），在样本层做增强
  2. 对每个样本生成 N 个增强变体（默认 1-2 个）
  3. 变换：标识符重命名（一致映射） + 日志注入 + 顶部注释混淆
  4. 同步更新 source/sink/taint_path/fix_idea 字段，使 CoT 引用新名称
  5. 用 build_messages() 重新生成 ChatML，保证 CoT 与代码一致

输出：
  data/augmented_train_chatml.jsonl
  （可选 --append 合并原 train_chatml.jsonl 写到同一文件）

用法：
  PYTHONPATH=/home/zane/文档/code/毕业设计 \\
  /home/zane/miniconda3/envs/graproj/bin/python3 augment_data.py \\
      --variants 2 --append

  # 仅看增强统计，不写文件
  PYTHONPATH=/home/zane/文档/code/毕业设计 \\
  /home/zane/miniconda3/envs/graproj/bin/python3 augment_data.py --dry-run

注：增强变换是文本级，保留代码语义安全性（漏洞仍漏洞，安全仍安全）。
    不做控制流改写（可能引入 bug），不做字符串内部替换（避免误伤）。
"""

import argparse
import json
import os
import random
import re
import sys
from pathlib import Path

# 复用 build_dataset 的样本与 ChatML 构造逻辑
PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from experiments.exp_06_finetune.scripts.build_dataset import (
    SAMPLES, build_messages,
)

DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"
OUTPUT_FILE = DATA_DIR / "augmented_train_chatml.jsonl"
ORIG_FILE = DATA_DIR / "train_chatml.jsonl"


# ---------------------------------------------------------------------------
# 标识符重命名映射
# 这些是常见的用户自定义变量/参数名，重命名不会影响框架 API 语义。
# 框架 API（request/db/cursor/app/session 等）不在此表，保留原样。
# ---------------------------------------------------------------------------

RENAME_MAP = {
    # 通用变量
    "keyword": ["search_term", "query_str", "search_text"],
    "host": ["target_host", "remote_host", "server_addr"],
    "filename": ["file_name", "fname", "target_file"],
    "url": ["target_url", "remote_url", "endpoint_url"],
    "data": ["payload", "body_content", "input_data"],
    "query": ["sql_query", "db_query", "stmt_text"],
    "result": ["output", "response_data", "ret_val"],
    "token": ["auth_token", "session_tok", "cred_token"],
    "name": ["identifier", "label", "tag_name"],
    "value": ["val", "input_val", "raw_value"],
    "user": ["account", "user_obj", "current_account"],
    "username": ["login_name", "user_id_str", "account_name"],
    "password": ["pwd", "secret", "credential"],
    "order": ["sort_field", "order_col", "sort_key"],
    "table": ["tbl_name", "target_table", "relation"],
    "expr": ["expression", "formula", "eval_str"],
    "input": ["user_input", "raw_input", "src_data"],
    "output": ["result_data", "ret_val", "response_body"],
    "amount": ["qty", "transfer_amount", "sum_value"],
    "id": ["record_id", "entity_id", "obj_id"],
    "uid": ["user_uid", "account_uid", "member_id"],
    "pid": ["product_pid", "item_pid", "goods_id"],
    "oid": ["order_oid", "transaction_oid", "doc_id"],
    "code": ["snippet", "source_code", "listing"],
    "text": ["content", "message_body", "raw_text"],
    "file": ["upload_file", "input_file", "attachment"],
    "key": ["field_key", "map_key", "attr_key"],
    "config": ["settings", "app_config", "cfg"],
    "body": ["request_body", "payload_data", "msg_body"],
    "domain": ["target_domain", "host_name", "server_domain"],
    "email": ["mail_addr", "contact_email", "user_email"],
    "comment": ["remark", "note", "annotation"],
    "filter": ["search_filter", "where_clause", "condition"],
    "path": ["file_path", "target_path", "resource_path"],
    "tpl": ["template_str", "tpl_text", "render_str"],
    "n": ["count", "limit_n", "size_n"],
    "raw": ["raw_data", "raw_bytes", "raw_input"],
    "total": ["sum_total", "aggregated", "grand_total"],
    "expected": ["expected_val", "reference", "target_val"],
    "target": ["dest", "redirect_target", "target_url_val"],
    # 注意：source / sink 是 CoT 概念词（"危险 sink："），不作为变量名重命名
}

# 框架/库 API 名（绝不能重命名）
PROTECTED_NAMES = {
    "request", "db", "cursor", "app", "session", "response", "jsonify",
    "redirect", "abort", "render_template", "render_template_string",
    "subprocess", "os", "sys", "json", "re", "random", "secrets",
    "hashlib", "bcrypt", "hmac", "base64", "pickle", "yaml", "jwt",
    "open", "exec", "eval", "compile", "import", "from", "def", "class",
    "return", "if", "else", "elif", "for", "while", "try", "except",
    "with", "as", "in", "not", "and", "or", "is", "None", "True", "False",
    "self", "cls", "super", "init", "str", "int", "float", "bool", "list",
    "dict", "set", "tuple", "len", "range", "print", "type", "isinstance",
    "hasattr", "getattr", "setattr", "delattr",
    # Flask
    "Flask", "request", "g", "current_app", "url_for", "flash",
    # Django
    "HttpResponse", "JsonResponse", "render", "get_object_or_404",
    # Java/Spring
    "RestController", "GetMapping", "PostMapping", "RequestParam",
    "RequestBody", "PathVariable", "Autowired", "Service",
    # JS/Node
    "require", "module", "exports", "console",
    # PHP
    "echo", "print", "isset", "empty", "array",
}


def make_rename_map(seed: int) -> dict[str, str]:
    """为本次增强生成一个一致的重命名映射（每个原词随机选一个目标名）。

    不同样本用不同 seed 得到不同映射，增加多样性。
    """
    rng = random.Random(seed)
    mapping = {}
    for src, candidates in RENAME_MAP.items():
        # 50% 概率跳过（不是每个样本都要重命名所有词）
        if rng.random() < 0.5:
            continue
        mapping[src] = rng.choice(candidates)
    return mapping


def rename_in_text(text: str, mapping: dict[str, str]) -> str:
    """在文本中按字边界做整词替换。

    用 \b 词边界正则，避免误伤子串（如 host 不应替换 hostname 中的 host）。
    字符串字面量内部也会被替换——这是有意为之：让模型学会不依赖变量名。
    """
    if not text or not mapping:
        return text
    out = text
    for src, dst in mapping.items():
        # 用 \b 确保整词匹配；大小写敏感
        pattern = r"\b" + re.escape(src) + r"\b"
        out = re.sub(pattern, dst, out)
    return out


def inject_logging(code: str, rng: random.Random) -> str:
    """在函数体开头插入日志语句（不改变语义）。

    只在 def 行后插入，且只在 Python 代码中做（其他语言跳过）。
    """
    lines = code.split("\n")
    out = []
    inserted = False
    log_statements = [
        '    logger.info("processing request")',
        '    logger.debug("entering handler")',
        '    app.logger.info("request received")',
        '    logging.info("handler called")',
    ]
    for line in lines:
        out.append(line)
        # 在 def 行后插入（仅 Python，且只插一次）
        if (not inserted and line.strip().startswith("def ")
                and line.rstrip().endswith(":")):
            # 检查文件是否已 import logging（粗略：不重复 import）
            stmt = rng.choice(log_statements)
            out.append(stmt)
            inserted = True
    if inserted:
        # 在文件顶部加 import（若没有）
        has_logging = any("import logging" in l for l in lines)
        if not has_logging:
            out.insert(0, "import logging")
    return "\n".join(out)


# 顶部可注入的"中性"注释（不改变安全语义，但增加噪声）
NEUTRAL_COMMENTS = [
    "# TODO: refactor this handler",
    "# NOTE: 见 JIRA-1234",
    "# FIXME: 需要添加单元测试",
    "# WARNING: 此处逻辑复杂，修改需谨慎",
    "# 此函数由 team A 维护",
    "# 历史代码，请勿重写",
    "# 性能敏感路径",
    "# reviewer: 张三 2024-01-15",
]


def inject_top_comment(code: str, rng: random.Random) -> str:
    """在代码顶部加一行中性注释（不改变语义）。"""
    comment = rng.choice(NEUTRAL_COMMENTS)
    return comment + "\n" + code


def augment_sample(sample: dict, variant_idx: int, base_seed: int) -> dict:
    """对一个样本生成一个增强变体。

    变换：
      1. 标识符重命名（一致映射，同步 source/sink/taint_path/fix_idea）
      2. 日志注入（仅 Python）
      3. 顶部注释注入

    返回新的 sample dict（深拷贝，不修改原样本）。
    """
    seed = base_seed + variant_idx * 1000 + hash(sample["filename"]) % 1000
    rng = random.Random(seed)
    mapping = make_rename_map(seed)

    new_sample = dict(sample)

    # 1. 标识符重命名（code + 元数据字段同步）
    new_sample["code"] = rename_in_text(sample["code"], mapping)
    new_sample["source"] = rename_in_text(sample.get("source", ""), mapping)
    new_sample["sink"] = rename_in_text(sample.get("sink", ""), mapping)
    new_sample["taint_path"] = rename_in_text(sample.get("taint_path", ""), mapping)
    new_sample["fix_idea"] = rename_in_text(sample.get("fix_idea", ""), mapping)
    # analysis 也需重命名（如果 sample 自带 analysis）
    if sample.get("analysis"):
        new_sample["analysis"] = rename_in_text(sample["analysis"], mapping)
    # filename 加后缀避免重复
    name_parts = sample["filename"].rsplit(".", 1)
    if len(name_parts) == 2:
        new_sample["filename"] = f"{name_parts[0]}_aug{variant_idx}.{name_parts[1]}"
    else:
        new_sample["filename"] = f"{sample['filename']}_aug{variant_idx}"

    # 2. 日志注入（仅 Python）
    if sample["language"] == "python" and rng.random() < 0.4:
        new_sample["code"] = inject_logging(new_sample["code"], rng)

    # 3. 顶部注释注入（30% 概率）
    if rng.random() < 0.3:
        new_sample["code"] = inject_top_comment(new_sample["code"], rng)

    # 清空 analysis 让 build_analysis 用模板重新生成（基于更新后的字段）
    # 除非原样本自带 analysis（噪声样本的手写 CoT），此时保留重命名后的版本
    if not sample.get("analysis"):
        new_sample["analysis"] = None

    return new_sample


def main():
    parser = argparse.ArgumentParser(description="数据增强：变量重命名 + 日志注入 + 注释混淆")
    parser.add_argument("--variants", type=int, default=2,
                        help="每个样本生成 N 个增强变体（默认 2）")
    parser.add_argument("--append", action="store_true",
                        help="合并原 train_chatml.jsonl 一起写到 augmented_train_chatml.jsonl")
    parser.add_argument("--dry-run", action="store_true",
                        help="仅统计不写文件")
    parser.add_argument("--seed", type=int, default=42, help="基础随机种子")
    parser.add_argument("--output", type=str, default=None,
                        help="输出文件路径（默认 data/augmented_train_chatml.jsonl）")
    args = parser.parse_args()

    print(f"原样本数: {len(SAMPLES)}")
    print(f"每个样本生成 {args.variants} 个变体")

    # 生成增强样本
    augmented_samples = []
    for i, sample in enumerate(SAMPLES):
        for v in range(args.variants):
            aug = augment_sample(sample, v, args.seed + i * 100)
            augmented_samples.append(aug)

    print(f"增强样本数: {len(augmented_samples)}")
    print(f"合计（原 + 增强）: {len(SAMPLES) + len(augmented_samples)}")

    # 统计语言/漏洞分布
    all_samples = list(SAMPLES) + augmented_samples
    langs = {}
    vuln = 0
    safe = 0
    for s in all_samples:
        langs[s["language"]] = langs.get(s["language"], 0) + 1
        if s["has_vulnerability"]:
            vuln += 1
        else:
            safe += 1
    print(f"  漏洞: {vuln}  安全: {safe}")
    print(f"  语言分布: {langs}")

    if args.dry_run:
        print("\n--dry-run：不写文件")
        return

    # 写文件
    out_path = Path(args.output) if args.output else OUTPUT_FILE
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        if args.append:
            # 先写原样本
            for sample in SAMPLES:
                record = build_messages(sample)
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
            print(f"已写入原样本 {len(SAMPLES)} 条")
        # 写增强样本
        for sample in augmented_samples:
            record = build_messages(sample)
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"已写入增强样本 {len(augmented_samples)} 条")

    print(f"\n输出文件: {out_path}")

    # 估计 token 数
    total_chars = 0
    for sample in (list(SAMPLES) + augmented_samples if args.append else augmented_samples):
        record = build_messages(sample)
        for msg in record["messages"]:
            total_chars += len(msg["content"])
    print(f"  总字符数: {total_chars}  估计 token: ~{total_chars // 4}")


if __name__ == "__main__":
    main()
