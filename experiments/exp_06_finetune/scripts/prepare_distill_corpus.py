"""
蒸馏语料生成器 —— 收集多样化代码样本供用户在 IDE 中补 CoT 标注。

数据来源：
  1. experiments/exp_01_basic_scan/samples/ 现有样本（--include-exp01，默认开启）
  2. experiments/exp_04_hard_samples/samples/ 现有样本（--include-exp04，默认开启）
  3. 自动变体（--generate-variants）：
     - 变量重命名：request→req、cursor→cur 等常见标识符
     - 插入无关代码：在开头插 logging/工具函数，训练模型忽略噪音

输出：
  experiments/exp_06_finetune/data/distill_corpus.jsonl
  每行一个 JSON：
    {"id":"distill_001","code":"...","language":"python",
     "filename":"...","source":"exp04","variant":"original","needs_annotation":true}

重要：
  - 从 manifest.json 读取 expected_present 等元数据用于筛选/统计，
    但【不】输出到 corpus —— CoT 要让 GLM 重新标注，避免泄露答案。
  - 只输出 code/language/filename（加 id/source/variant 元信息）。

后续流程：
  用户在 IDE 里对 distill_corpus.jsonl 逐行补 cot_analysis / has_vulnerability /
  vuln_type / risk_level / source / sink / taint_path / fix_idea 字段，
  然后用 format_distilled.py 转为 ChatML 训练格式。

用法：
  python prepare_distill_corpus.py --max-samples 200 --include-exp01 --include-exp04 --generate-variants
  python prepare_distill_corpus.py --max-samples 10  # 快速试跑
"""

import argparse
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
EXP01_SAMPLES = PROJECT_ROOT / "experiments/exp_01_basic_scan/samples"
EXP04_SAMPLES = PROJECT_ROOT / "experiments/exp_04_hard_samples/samples"
OUTPUT_FILE = PROJECT_ROOT / "experiments/exp_06_finetune/data/distill_corpus.jsonl"

SUPPORTED_EXT = {".py", ".java", ".js", ".php", ".go", ".c", ".rb"}
EXT_LANG = {
    ".py": "python", ".java": "java", ".js": "javascript",
    ".php": "php", ".go": "go", ".c": "c", ".rb": "ruby",
}

# 变量重命名映射（常见标识符 → 短名）
RENAME_MAP = {
    "request": "req",
    "cursor": "cur",
    "keyword": "kw",
    "filename": "fname",
    "user_input": "user_in",
    "username": "uname",
    "password": "pwd",
    "query": "q",
    "result": "res",
    "response": "resp",
    "config": "cfg",
    "content": "body",
    "data": "payload",
    "user_id": "uid",
    "product_id": "pid",
}

# 无关代码片段（插入到文件开头，训练模型忽略噪音）
NOISE_PREFIX = {
    "python": [
        "import logging\nlogger = logging.getLogger(__name__)\n",
        "import os\nimport sys\nDEBUG = os.environ.get('DEBUG', '0') == '1'\n",
    ],
    "java": [
        "import java.util.logging.Logger;\n",
    ],
    "javascript": [
        "const debug = require('debug')('app');\n",
    ],
    "php": [
        "error_reporting(E_ALL);\n",
    ],
    "go": [
        "import \"log\"\n",
    ],
    "c": [
        "#include <stdio.h>\n#define DBG 0\n",
    ],
    "ruby": [
        "require 'logger'\n",
    ],
}


def load_samples(samples_dir: Path) -> list:
    """读取 samples_dir/manifest.json + 对应代码文件。

    返回 [(record, code), ...]，record 含 manifest 元数据（用于筛选，不输出到 corpus）。
    """
    manifest_path = samples_dir / "manifest.json"
    if not manifest_path.exists():
        print(f"[跳过] manifest 不存在: {manifest_path}", file=sys.stderr)
        return []
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    out = []
    for rec in manifest.get("samples", []):
        fname = rec.get("file", "")
        if not fname:
            continue
        ext = Path(fname).suffix.lower()
        if ext not in SUPPORTED_EXT:
            continue
        code_path = samples_dir / fname
        if not code_path.exists():
            continue
        code = code_path.read_text(encoding="utf-8")
        out.append((rec, code))
    return out


def rename_variant(code: str) -> str:
    """对代码做变量重命名变体（word-boundary 替换，避免匹配子串）。"""
    new_code = code
    for old, new in RENAME_MAP.items():
        pattern = r"\b" + re.escape(old) + r"\b"
        new_code = re.sub(pattern, new, new_code)
    return new_code


def insert_noise(code: str, language: str) -> str:
    """在代码开头插入无关 logging/utility 代码（确定性选取第一段）。"""
    candidates = NOISE_PREFIX.get(language)
    if not candidates:
        return code
    prefix = candidates[0]
    return prefix + "\n" + code


def normalize_lang(language: str) -> str:
    """manifest 中的 'Python' -> 'python'（ChatML 训练用小写语言名）。"""
    if not language:
        return "python"
    return language.lower()


def main():
    parser = argparse.ArgumentParser(
        description="收集蒸馏语料（code/language/filename），输出 JSONL 供 IDE 标注"
    )
    parser.add_argument("--max-samples", type=int, default=200,
                        help="最多输出的样本数（默认 200）")
    parser.add_argument("--include-exp01", action=argparse.BooleanOptionalAction, default=True,
                        help="包含 exp_01_basic_scan 样本（默认开启，用 --no-include-exp01 关闭）")
    parser.add_argument("--include-exp04", action=argparse.BooleanOptionalAction, default=True,
                        help="包含 exp_04_hard_samples 样本（默认开启，用 --no-include-exp04 关闭）")
    parser.add_argument("--generate-variants", action="store_true",
                        help="生成变量重命名/插入无关代码的变体")
    parser.add_argument("--output", type=str, default=str(OUTPUT_FILE),
                        help="输出 JSONL 路径")
    args = parser.parse_args()

    # 收集源样本：[(record, code, source_tag)]
    sources = []
    if args.include_exp01:
        n0 = len(sources)
        for rec, code in load_samples(EXP01_SAMPLES):
            sources.append((rec, code, "exp01"))
        print(f"exp_01: 读取 {len(sources) - n0} 条")
    if args.include_exp04:
        n0 = len(sources)
        for rec, code in load_samples(EXP04_SAMPLES):
            sources.append((rec, code, "exp04"))
        print(f"exp_04: 读取 {len(sources) - n0} 条")

    if not sources:
        print("错误：未读取到任何样本", file=sys.stderr)
        sys.exit(1)

    # 构造 corpus 条目（去重 + 限量）
    entries = []
    seen_codes = set()
    counter = 0

    def add_entry(code: str, language: str, filename: str, source_tag: str, variant: str):
        """去重后追加一条 entry。不输出 manifest 的答案字段。"""
        nonlocal counter
        if counter >= args.max_samples:
            return
        key = hash(code)
        if key in seen_codes:
            return
        seen_codes.add(key)
        counter += 1
        entries.append({
            "id": f"distill_{counter:03d}",
            "code": code,
            "language": language,
            "filename": filename,
            "source": source_tag,
            "variant": variant,
            "needs_annotation": True,
        })

    # 1) 原始样本
    for rec, code, source_tag in sources:
        if counter >= args.max_samples:
            break
        lang = normalize_lang(rec.get("language", "python"))
        fname = rec.get("file", "sample.py")
        add_entry(code, lang, fname, source_tag, "original")

    # 2) 变体（重命名 + 插入无关代码）
    if args.generate_variants:
        for rec, code, source_tag in sources:
            if counter >= args.max_samples:
                break
            lang = normalize_lang(rec.get("language", "python"))
            fname = rec.get("file", "sample.py")
            # 变量重命名变体
            renamed = rename_variant(code)
            if renamed != code:
                base = Path(fname).stem + "_renamed" + Path(fname).suffix
                add_entry(renamed, lang, base, source_tag, "rename")
            if counter >= args.max_samples:
                break
            # 插入无关代码变体
            noised = insert_noise(code, lang)
            if noised != code:
                base = Path(fname).stem + "_noise" + Path(fname).suffix
                add_entry(noised, lang, base, source_tag, "noise")

    # 写入 JSONL（UTF-8）
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    # 统计
    lang_dist = {}
    variant_dist = {}
    for e in entries:
        lang_dist[e["language"]] = lang_dist.get(e["language"], 0) + 1
        variant_dist[e["variant"]] = variant_dist.get(e["variant"], 0) + 1
    print(f"\n已写入 {len(entries)} 条到 {out_path}")
    print(f"语言分布: {lang_dist}")
    print(f"变体分布: {variant_dist}")
    print("提示：本文件只含 code/language/filename，需在 IDE 中补 CoT 标注后用 format_distilled.py 转训练格式")


if __name__ == "__main__":
    main()
