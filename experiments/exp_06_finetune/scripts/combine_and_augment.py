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

设计原则：
  - 质量优先：622 条高质量样本 > 1866 条换皮复制
  - 不做变量重命名增强（不改语义，只增加模板记忆）
  - 不做日志注入（纯噪声，不增加推理能力）
  - 安全样本的 explanation 必须描述具体防御措施，不使用统一模板

用法：
  cd /home/zane/文档/code/毕业设计
  PYTHONPATH=. /home/zane/miniconda3/envs/AI/bin/python \
      experiments/exp_06_finetune/scripts/combine_and_augment.py

  # 指定使用 v1（模板版）而非 v2（教师模型版）
  PYTHONPATH=. python experiments/exp_06_finetune/scripts/combine_and_augment.py --use-v1
"""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import SYSTEM_PROMPT, build_user_prompt
from experiments.exp_06_finetune.scripts.format_distilled import build_messages, build_json_verdict

DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"
ORIGINAL_FILE = DATA_DIR / "train_chatml.jsonl"
DISTILL_V2 = DATA_DIR / "distill_corpus_annotated_v2.jsonl"
DISTILL_V1 = DATA_DIR / "distill_corpus_annotated.jsonl"
SUPPLEMENT_FILE = DATA_DIR / "supplement_chatml.jsonl"
OUTPUT_FILE = DATA_DIR / "train_chatml_v2.jsonl"


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

    # 4. 合并
    print(f"\n[4] 合并所有数据...")
    all_samples = original_samples + distill_chatml + supplement_samples
    print(f"    总计: {len(all_samples)} 条")

    # 5. 统计
    vuln = 0
    safe = 0
    for s in all_samples:
        assistant_msg = s["messages"][-1]["content"]
        if '"has_vulnerability": true' in assistant_msg:
            vuln += 1
        elif '"has_vulnerability": false' in assistant_msg:
            safe += 1
    print(f"    漏洞: {vuln}  安全: {safe}")

    # 检查安全样本 explanation 多样性
    safe_explanations = set()
    for s in all_samples:
        assistant_msg = s["messages"][-1]["content"]
        if '"has_vulnerability": false' in assistant_msg:
            # 提取 explanation 字段
            import re
            m = re.search(r'"explanation"\s*:\s*"([^"]*)"', assistant_msg)
            if m:
                safe_explanations.add(m.group(1))
    print(f"    安全样本 explanation 唯一值: {len(safe_explanations)} 种")
    if len(safe_explanations) <= 3:
        print("    ⚠️  警告：安全样本 explanation 过于单一！")
        for expl in list(safe_explanations)[:5]:
            print(f"      '{expl}'")

    # 6. 写入
    print(f"\n[5] 写入 {OUTPUT_FILE.name}...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for s in all_samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"    完成: {OUTPUT_FILE}")

    # 7. 估计 token 数
    total_chars = 0
    for s in all_samples:
        for msg in s["messages"]:
            total_chars += len(msg["content"])
    print(f"    总字符数: {total_chars}  估计 token: ~{total_chars // 4}")


if __name__ == "__main__":
    main()
"""
合并 + 增强所有训练数据（build_dataset 原始 + 蒸馏数据）。

输入：
  1. data/train_chatml.jsonl           （build_dataset.py 产出，222 条）
  2. data/augmented_train_chatml.jsonl  （augment_data.py 产出，666 条）
  3. data/distill_corpus_annotated.jsonl（generate_distill_data.py 产出，400 条标注）

流程：
  1. 读取 augmented_train_chatml.jsonl（666 条已增强的原始样本）
  2. 读取 distill_corpus_annotated.jsonl（400 条蒸馏标注）
  3. 对蒸馏数据做变量重命名 + 日志注入 + 注释混淆增强（×2 变体）
  4. 用 format_distilled.build_messages 转 ChatML
  5. 合并所有数据 → data/combined_train_chatml.jsonl

最终样本数：666 + 400 + 800 = 1866 条

用法：
  cd /home/zane/文档/code/毕业设计
  PYTHONPATH=/home/zane/文档/code/毕业设计 \
  /home/zane/miniconda3/envs/graproj/bin/python3 \
  experiments/exp_06_finetune/scripts/combine_and_augment.py
"""

import json
import random
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import SYSTEM_PROMPT, build_user_prompt
from experiments.exp_06_finetune.scripts.format_distilled import build_messages, build_json_verdict

DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"
AUGMENTED_FILE = DATA_DIR / "augmented_train_chatml.jsonl"
DISTILL_ANNOTATED = DATA_DIR / "distill_corpus_annotated.jsonl"
OUTPUT_FILE = DATA_DIR / "combined_train_chatml.jsonl"

# 复用 augment_data.py 的重命名映射（简化版）
RENAME_MAP = {
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
    # 新增：蒸馏数据中常见的变量名
    "keyword": ["kw", "search_term", "q_str"],
    "cmd": ["command_str", "shell_cmd", "exec_cmd"],
    "payload": ["load_data", "request_payload", "data_payload"],
    "stmt": ["statement", "prepared_stmt", "sql_stmt"],
    "sql": ["query_str", "sql_text", "db_query"],
    "xml": ["xml_data", "xml_str", "doc_xml"],
    "html": ["html_content", "markup", "html_str"],
    "template": ["tpl_str", "render_template", "view_template"],
    "msg": ["message_str", "info_msg", "log_msg"],
    "buf": ["buffer", "data_buf", "byte_buf"],
    "ptr": ["pointer", "mem_ptr", "ref_ptr"],
    "fd": ["file_descriptor", "handle", "fd_num"],
    "err": ["error_msg", "error_code", "err_info"],
    "ret": ["return_val", "result_val", "ret_code"],
    "len": ["length", "size_val", "count_val"],
    "idx": ["index", "pos", "offset_val"],
    "tmp": ["temp_var", "temp_val", "work_var"],
    "src": ["source_data", "input_src", "origin"],
    "dst": ["dest_data", "output_dst", "target_data"],
}

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
    "Flask", "Django", "FastAPI", "HttpResponse", "JsonResponse",
    "require", "module", "exports", "console", "echo", "isset", "empty",
    "array", "mysqli", "pdo", "pg", "sqlite3",
    "java", "javax", "servlet", "http",
    "fmt", "net", "http", "io",
    "stdio", "stdlib", "string", "malloc", "free", "memcpy", "strcpy",
    "system", "popen", "fgets", "scanf", "printf", "fprintf", "sprintf",
    "snprintf", "strcat", "strncat", "gets",
}

NEUTRAL_COMMENTS = [
    "# TODO: refactor this handler",
    "# NOTE: 见 JIRA-1234",
    "# FIXME: 需要添加单元测试",
    "# WARNING: 此处逻辑复杂，修改需谨慎",
    "# 此函数由 team A 维护",
    "# 历史代码，请勿重写",
    "# 性能敏感路径",
    "# reviewer: 张三 2024-01-15",
    "# TODO: 需要优化性能",
    "# NOTE: 兼容旧版 API",
]

LOG_STATEMENTS = [
    '    logger.info("processing request")',
    '    logger.debug("entering handler")',
    '    app.logger.info("request received")',
    '    logging.info("handler called")',
]


def make_rename_map(seed: int) -> dict[str, str]:
    """生成一致的重命名映射。"""
    rng = random.Random(seed)
    mapping = {}
    for src, candidates in RENAME_MAP.items():
        if rng.random() < 0.5:
            continue
        mapping[src] = rng.choice(candidates)
    return mapping


def rename_in_text(text: str, mapping: dict[str, str]) -> str:
    """整词替换（\b 词边界）。"""
    if not text or not mapping:
        return text
    out = text
    for src, dst in mapping.items():
        pattern = r"\b" + re.escape(src) + r"\b"
        out = re.sub(pattern, dst, out)
    return out


def inject_logging(code: str, rng: random.Random) -> str:
    """在 Python 函数体开头插入日志语句。"""
    lines = code.split("\n")
    out = []
    inserted = False
    for line in lines:
        out.append(line)
        if (not inserted and line.strip().startswith("def ")
                and line.rstrip().endswith(":")):
            stmt = rng.choice(LOG_STATEMENTS)
            out.append(stmt)
            inserted = True
    if inserted:
        has_logging = any("import logging" in l for l in lines)
        if not has_logging:
            out.insert(0, "import logging")
    return "\n".join(out)


def inject_top_comment(code: str, rng: random.Random) -> str:
    """顶部加中性注释。"""
    comment = rng.choice(NEUTRAL_COMMENTS)
    return comment + "\n" + code


def augment_distill_sample(rec: dict, variant_idx: int, base_seed: int) -> dict:
    """对蒸馏标注样本生成一个增强变体。"""
    seed = base_seed + variant_idx * 1000 + hash(rec.get("filename", "")) % 1000
    rng = random.Random(seed)
    mapping = make_rename_map(seed)

    new_rec = dict(rec)
    # 重命名 code + 所有文本字段
    new_rec["code"] = rename_in_text(rec["code"], mapping)
    new_rec["source"] = rename_in_text(rec.get("source", ""), mapping)
    new_rec["sink"] = rename_in_text(rec.get("sink", ""), mapping)
    new_rec["taint_path"] = rename_in_text(rec.get("taint_path", ""), mapping)
    new_rec["fix_idea"] = rename_in_text(rec.get("fix_idea", ""), mapping)
    new_rec["cot_analysis"] = rename_in_text(rec.get("cot_analysis", ""), mapping)

    # filename 加后缀
    fn = rec.get("filename", "sample.py")
    name_parts = fn.rsplit(".", 1)
    if len(name_parts) == 2:
        new_rec["filename"] = f"{name_parts[0]}_aug{variant_idx}.{name_parts[1]}"
    else:
        new_rec["filename"] = f"{fn}_aug{variant_idx}"

    # 日志注入（仅 Python，40% 概率）
    if rec.get("language") == "python" and rng.random() < 0.4:
        new_rec["code"] = inject_logging(new_rec["code"], rng)

    # 顶部注释（30% 概率）
    if rng.random() < 0.3:
        new_rec["code"] = inject_top_comment(new_rec["code"], rng)

    return new_rec


def main():
    print("=" * 60)
    print("合并训练数据：原始增强 + 蒸馏 + 蒸馏增强")
    print("=" * 60)

    # 1. 读取已增强的原始数据
    print(f"\n[1] 读取 {AUGMENTED_FILE.name}...")
    augmented_original = []
    with open(AUGMENTED_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                augmented_original.append(json.loads(line))
    print(f"    {len(augmented_original)} 条")

    # 2. 读取蒸馏标注数据
    print(f"\n[2] 读取 {DISTILL_ANNOTATED.name}...")
    distill_samples = []
    with open(DISTILL_ANNOTATED, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                distill_samples.append(json.loads(line))
    print(f"    {len(distill_samples)} 条")

    # 3. 对蒸馏数据做增强（每个样本 2 个变体）
    print(f"\n[3] 增强蒸馏数据（×2 变体）...")
    augmented_distill_chatml = []
    base_seed = 42
    for i, rec in enumerate(distill_samples):
        for v in range(2):
            aug_rec = augment_distill_sample(rec, v, base_seed + i * 100)
            # 转为 ChatML
            messages = build_messages(aug_rec)
            augmented_distill_chatml.append(messages)
    print(f"    生成 {len(augmented_distill_chatml)} 条增强蒸馏样本")

    # 4. 蒸馏原始数据也转 ChatML
    print(f"\n[4] 转换蒸馏原始数据为 ChatML...")
    distill_chatml = []
    for rec in distill_samples:
        messages = build_messages(rec)
        distill_chatml.append(messages)
    print(f"    {len(distill_chatml)} 条")

    # 5. 合并所有数据
    print(f"\n[5] 合并所有数据...")
    all_samples = (
        augmented_original       # 666 条（原始 222 + 增强 444）
        + distill_chatml         # 400 条（蒸馏原始）
        + augmented_distill_chatml  # 800 条（蒸馏增强 ×2）
    )
    print(f"    总计: {len(all_samples)} 条")

    # 6. 统计
    vuln = 0
    safe = 0
    for s in all_samples:
        # 从 assistant 消息中提取 has_vulnerability
        assistant_msg = s["messages"][-1]["content"]
        if '"has_vulnerability": true' in assistant_msg:
            vuln += 1
        elif '"has_vulnerability": false' in assistant_msg:
            safe += 1
    print(f"    漏洞: {vuln}  安全: {safe}")

    # 7. 写入文件
    print(f"\n[6] 写入 {OUTPUT_FILE.name}...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for s in all_samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"    完成: {OUTPUT_FILE}")

    # 8. 估计 token 数
    total_chars = 0
    for s in all_samples:
        for msg in s["messages"]:
            total_chars += len(msg["content"])
    print(f"    总字符数: {total_chars}  估计 token: ~{total_chars // 4}")


if __name__ == "__main__":
    main()
