"""
KnItLM CPT 语料准备脚本 —— 三层分离版（知识 / 推理 / 代码）。

对应 docs/方法.md §9 Phase 3 KnItLM 知识注入。
2026-07-19 重构：从"扁平拼接"改为"三层分离"，解决规则条文重复 921 次导致
参数化查询幻觉副作用（见 phase3_error_analysis.md 回归样本）。

三层设计（依据用户反馈：推理模式与漏洞知识都值得学习）：
  Layer A 知识层（去重，每条学 1 次）：
    - knowledge.json 72 条结构化 CWE 百科（危险 API / 安全写法 / 判断要点）
    - SYSTEM_PROMPT 的安全模式白名单（抽成 1 条知识，不再每条 ChatML 重复）
  Layer B 推理层（多样化，保留）：
    - ChatML 的 user(代码) + assistant(CoT 推理链)，剥离 system 规则
    - 学的是 source→sink→防御→结论 的推理模式，不是规则条文
  Layer C 代码层（带 CWE 标签，排除测试集泄露）：
    - 从 manifest 读 expected_cwe，生成"CWE-XX 漏洞示例: 代码 + 特征"条目
    - 默认排除 exp_04 测试集（--include-testset 才纳入，且配标签）

设计原则：
  - 规则条文（安全模式白名单）是知识，但只学 1 次，不当指令重复灌
  - 推理模式（assistant CoT）是能力示范，多样化保留
  - 裸代码无标签不学；测试集代码默认不进训练
  - docs/ 元分析文档（改进.md/过程.md）退出知识层（是错误分析，非领域知识）

输出格式：jsonl，每行 {"text": "...", "priority": "...", "layer": "A|B|C"}
供 trl SFTTrainer 做 causal LM CPT。

用法：
  /home/zane/miniconda3/envs/AI/bin/python prepare_cpt_corpus.py
  /home/zane/miniconda3/envs/AI/bin/python prepare_cpt_corpus.py --dry-run
  /home/zane/miniconda3/envs/AI/bin/python prepare_cpt_corpus.py --include-testset  # 纳入测试集代码（带标签）
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"
DOCS_DIR = PROJECT_ROOT / "docs"
HARD_SAMPLES_DIR = PROJECT_ROOT / "experiments/exp_04_hard_samples"
RAG_DIR = PROJECT_ROOT / "experiments/exp_03_rag_knowledge/knowledge_data"

OUTPUT_FILE = DATA_DIR / "cpt_corpus.jsonl"

# 知识层来源
RAG_KNOWLEDGE_FILE = RAG_DIR / "knowledge.json"

# 推理层来源：ChatML + DPO（只取 user+assistant，剥离 system）
CHATML_SOURCES = [
    ("high", DATA_DIR / "train_chatml_v2.jsonl"),
    ("high", DATA_DIR / "distill_corpus_annotated_v2.jsonl"),
    ("medium", DATA_DIR / "supplement_ccot_contrastive_v2.jsonl"),
    ("medium", DATA_DIR / "supplement_ccot_contrastive.jsonl"),
    ("medium", DATA_DIR / "supplement_ccot_v3_expansion.jsonl"),
    ("medium", DATA_DIR / "supplement_longfile_defense.jsonl"),
    ("medium", DATA_DIR / "supplement_longtail_cwe.jsonl"),
    ("medium", DATA_DIR / "supplement_cwe_attribution_ssti.jsonl"),
    ("medium", DATA_DIR / "supplement_cwe_attribution_nosql.jsonl"),
    ("medium", DATA_DIR / "supplement_cwe_attribution_spel.jsonl"),
    ("medium", DATA_DIR / "supplement_crypto_noise.jsonl"),
    ("medium", DATA_DIR / "supplement_chatml.jsonl"),
    ("medium", DATA_DIR / "supplement_7b_weakness.jsonl"),
    ("medium", DATA_DIR / "supplement_blindspot_cwe.jsonl"),
    ("low", DATA_DIR / "distill_corpus_annotated.jsonl"),
]

DPO_SOURCES = [
    ("high", DATA_DIR / "dpo_preference_pairs_v3.jsonl"),
    ("high", DATA_DIR / "dpo_v3_expansion.jsonl"),
    ("high", DATA_DIR / "dpo_preference_pairs.jsonl"),
]

# 知识层文档来源：只保留真正的领域知识文档，排除元分析
# 改进.md/过程.md/必须手动学习的地方.md 是项目错误分析与学习笔记，不是漏洞领域知识
DOC_SOURCES = [
    ("low", DOCS_DIR / "方法.md"),  # 训练方法论，含 CWE/LoRA 等领域术语
]

# 测试集 manifest（用于给代码配 CWE 标签）
MANIFEST_FILE = HARD_SAMPLES_DIR / "samples" / "manifest.json"

# 测试集代码目录（用于泄露检测）
TESTSET_CODE_DIR = HARD_SAMPLES_DIR / "samples"

MAX_TEXT_LEN = 6000  # 字符级切分上限（约 2000 tokens）

# SYSTEM_PROMPT 安全模式白名单文本（从 prompts.py 导入，只学 1 次）
try:
    sys.path.insert(0, str(PROJECT_ROOT))
    from graduation_project.prompts import SAFE_PATTERN_WHITELIST
except Exception:
    # 回退：手动内联（与 prompts.py 保持同步）
    SAFE_PATTERN_WHITELIST = """\
【安全模式白名单（命中以下模式且无其他漏洞时，应判 has_vulnerability=false）】
1. SQL 参数化查询：cursor.execute("... WHERE id=?", (user_id,))，占位符 + 参数元组，非字符串拼接。
2. subprocess 列表参数：subprocess.run(["cmd", arg])，shell 默认 False，列表形式不触发 shell 解释。
3. 路径校验：os.path.abspath + startswith 限定目录，或白名单文件名集合。
4. XSS 防护：html.escape() / 模板自动转义 / textContent。
5. 反序列化：json.loads 替代 pickle.loads，yaml.safe_load 替代 yaml.load。
6. shell 命令转义：shlex.quote() 是 shell=True 场景下的有效防御。"""


def truncate_text(text: str, max_len: int = MAX_TEXT_LEN) -> list[str]:
    """超长文本按段落边界切分。"""
    if len(text) <= max_len:
        return [text]
    paragraphs = text.split("\n\n")
    chunks = []
    current = ""
    for para in paragraphs:
        if len(current) + len(para) + 2 > max_len and current:
            chunks.append(current.strip())
            current = para
        else:
            current = current + "\n\n" + para if current else para
    if current.strip():
        chunks.append(current.strip())
    return chunks


# ---------------------------------------------------------------------------
# Layer A：知识层（去重，每条学 1 次）
# ---------------------------------------------------------------------------

def extract_knowledge_from_rag() -> list[tuple[str, str]]:
    """从 knowledge.json 提取结构化 CWE 百科条目。

    每条转成"CWE-XX 名称：描述 + 危险API + 安全写法 + 判断要点"的知识文本。
    72 条覆盖 39 个 CWE，含 15 条 safe_pattern 安全模式条目。
    """
    texts = []
    if not RAG_KNOWLEDGE_FILE.exists():
        print(f"  ⚠️ knowledge.json 不存在: {RAG_KNOWLEDGE_FILE}", file=sys.stderr)
        return texts

    with open(RAG_KNOWLEDGE_FILE, encoding="utf-8") as f:
        knowledge = json.load(f)

    for entry in knowledge:
        cwe = entry.get("metadata", {}).get("cwe", "")
        vtype = entry.get("metadata", {}).get("type", "")
        is_safe = entry.get("metadata", {}).get("safe_pattern", False)
        doc = entry.get("document", "")

        if not doc.strip():
            continue

        # 构造知识条目标题
        tag = "【安全模式】" if is_safe else "【漏洞模式】"
        title = f"{tag} {cwe} {vtype}" if cwe else f"{tag} {vtype}"

        knowledge_text = f"### 漏洞领域知识：{title}\n\n{doc}"
        texts.append(("high", knowledge_text))

    return texts


def extract_safe_pattern_rules() -> str:
    """把 SYSTEM_PROMPT 的安全模式白名单抽成 1 条知识条目。

    不再随每条 ChatML 重复 921 次，而是作为独立知识学 1 次。
    """
    return f"### 漏洞领域知识：安全模式白名单（通用规则）\n\n{SAFE_PATTERN_WHITELIST}"


def extract_text_from_doc(path: Path) -> str:
    """读取 markdown 文档全文。"""
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Layer B：推理层（多样化，剥离 system 规则）
# ---------------------------------------------------------------------------

def extract_reasoning_from_chatml(record: dict) -> str | None:
    """从 ChatML 记录提取 user+assistant 推理文本（剥离 system 规则条文）。

    2026-07-19 改造：原版把 system+user+assistant 全拼，导致 SYSTEM_PROMPT
    重复 921 次。现剥离 system，只保留 user(代码) + assistant(CoT 推理)，
    让模型学推理模式而非规则背诵。
    """
    if "messages" not in record:
        # DPO 格式：{prompt, chosen, rejected}
        if "chosen" in record:
            return record["chosen"]
        return None

    parts = []
    for msg in record["messages"]:
        role = msg.get("role", "")
        content = msg.get("content", "")
        if not content:
            continue
        # 剥离 system：规则条文归 Layer A，这里只学推理
        if role == "system":
            continue
        parts.append(f"### {role.upper()}\n{content}")
    return "\n\n".join(parts) if parts else None


def extract_text_from_dpo(record: dict) -> str | None:
    """从 DPO 记录提取 chosen（高质量漏洞判定推理）。"""
    if "chosen" not in record:
        return None
    prompt = record.get("prompt", "")
    chosen = record["chosen"]
    return f"{prompt}\n\n### CHOSEN RESPONSE\n{chosen}"


# ---------------------------------------------------------------------------
# Layer C：代码层（带 CWE 标签，排除测试集泄露）
# ---------------------------------------------------------------------------

def load_manifest() -> dict[str, dict]:
    """加载测试集 manifest，返回 {filename: record} 映射。"""
    if not MANIFEST_FILE.exists():
        return {}
    with open(MANIFEST_FILE, encoding="utf-8") as f:
        data = json.load(f)
    return {s["file"]: s for s in data.get("samples", [])}


def extract_labeled_code_samples(manifest_map: dict[str, dict]) -> list[str]:
    """从 exp_04 samples 提取带 CWE 标签的代码示例。

    每条格式：
      ### 漏洞示例：CWE-89 SQL注入（典型）
      ```python
      <代码>
      ```
      特征：用户输入直接拼接到 LIKE 查询
      污染路径：request.args.get('q') → query 拼接 → cursor.execute

    注意：默认不调用此函数（--include-testset 才调用），避免测试集泄露。
    若调用，代码会带 expected_cwe 标签，让模型学"漏洞长什么样"而非裸代码。
    """
    texts = []
    samples_dir = HARD_SAMPLES_DIR / "samples"
    if not samples_dir.exists():
        return texts

    for code_file in samples_dir.glob("*.py"):
        rec = manifest_map.get(code_file.name)
        if not rec:
            continue  # 无 manifest 记录，跳过

        try:
            content = code_file.read_text(encoding="utf-8")
        except Exception as e:
            print(f"  ⚠️ 跳过 {code_file.name}: {e}", file=sys.stderr)
            continue

        cwe = rec.get("expected_cwe", "")
        category = rec.get("category", "")
        vuln_desc = rec.get("expected_vulnerability", "")
        present = rec.get("expected_present", False)
        taint = rec.get("taint_path", "")

        label = "漏洞示例" if present else "安全示例"
        title = f"### {label}：{cwe} {category}" if cwe else f"### {label}：{category}"

        parts = [title, f"\n{vuln_desc}" if vuln_desc else "", f"\n```python\n{content}\n```"]
        if taint:
            parts.append(f"\n污染路径：{taint}")
        texts.append("\n".join(parts))

    return texts


# ---------------------------------------------------------------------------
# 语料清洗：测试集泄露过滤 + 全局去重
# ---------------------------------------------------------------------------

def load_testset_code() -> dict[str, str]:
    """加载 exp_04 测试集代码，返回 {filename: code}。"""
    code_map: dict[str, str] = {}
    if not TESTSET_CODE_DIR.exists():
        return code_map
    for code_file in TESTSET_CODE_DIR.glob("*.py"):
        try:
            code_map[code_file.name] = code_file.read_text(encoding="utf-8")
        except Exception:
            continue
    return code_map


def contains_testset_code(text: str, testset_code: dict[str, str], min_match_len: int = 200) -> bool:
    """检查 text 中的代码片段是否与测试集代码有 ≥min_match_len 字符的匹配。

    仅对 Layer B（推理层）生效——它来自 ChatML/DPO，user 字段常含原始代码。
    Layer A/C 不调用此函数。
    """
    for m in re.finditer(r"```(?:\w+)?\n(.*?)```", text, re.DOTALL):
        frag = m.group(1).strip()
        if len(frag) < min_match_len:
            continue
        # 用前后各 min_match_len 字符做严格匹配，避免仅命中通用模板
        front = frag[:min_match_len]
        back = frag[-min_match_len:]
        for code in testset_code.values():
            if front in code and back in code:
                return True
    return False


def deduplicate_texts(all_texts: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    """按 text 精确去重，保留优先级更高的那条（high > medium > low）。

    返回去重后的 (priority, layer, text) 列表，保持原顺序。
    """
    prio_rank = {"high": 3, "medium": 2, "low": 1}
    seen: dict[str, tuple[str, str, str]] = {}
    for priority, layer, text in all_texts:
        h = hashlib.md5(text.encode("utf-8")).hexdigest()
        if h in seen:
            old_priority, old_layer, old_text = seen[h]
            if prio_rank.get(priority, 0) > prio_rank.get(old_priority, 0):
                seen[h] = (priority, layer, text)
        else:
            seen[h] = (priority, layer, text)
    # 按原顺序重建
    result = []
    seen_hashes = set()
    for priority, layer, text in all_texts:
        h = hashlib.md5(text.encode("utf-8")).hexdigest()
        if h in seen_hashes:
            continue
        # 只保留去重后胜出者
        if seen[h] == (priority, layer, text):
            result.append((priority, layer, text))
            seen_hashes.add(h)
    return result


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="准备 KnItLM CPT 语料（三层分离版）")
    parser.add_argument("--dry-run", action="store_true", help="仅统计，不写文件")
    parser.add_argument("--include-testset", action="store_true",
                        help="纳入 exp_04 测试集代码（带 CWE 标签）。默认排除，避免泄露。")
    parser.add_argument("--legacy-mode", action="store_true",
                        help="兼容旧版扁平模式（system+user+assistant 全拼）。默认三层分离。")
    parser.add_argument("--no-leak-filter", action="store_true",
                        help="禁用测试集泄露过滤。默认启用。")
    parser.add_argument("--no-dedup", action="store_true",
                        help="禁用全局精确去重。默认启用。")
    parser.add_argument("--leak-min-len", type=int, default=200,
                        help="泄露检测最小匹配长度（默认 200 字符）")
    args = parser.parse_args()

    print("=" * 60)
    print("KnItLM CPT 语料准备（三层分离版）")
    print("=" * 60)

    all_texts: list[tuple[str, str, str]] = []  # (priority, layer, text)
    stats: dict[str, dict[str, int]] = {
        "A": {"high": 0, "medium": 0, "low": 0},
        "B": {"high": 0, "medium": 0, "low": 0},
        "C": {"high": 0, "medium": 0, "low": 0},
    }

    # ===== Layer A：知识层（去重）=====
    print("\n[Layer A] 知识层（去重，每条学 1 次）")

    # A1. knowledge.json 结构化 CWE 百科
    print("  A1. 提取 knowledge.json 结构化 CWE 百科...")
    rag_texts = extract_knowledge_from_rag()
    for priority, text in rag_texts:
        for chunk in truncate_text(text):
            all_texts.append((priority, "A", chunk))
            stats["A"][priority] += 1
    print(f"      +{len(rag_texts)} 条 CWE 知识条目")

    # A2. 安全模式白名单（只学 1 次）
    print("  A2. 提取安全模式白名单规则（学 1 次，不再重复 921 次）...")
    safe_pattern_text = extract_safe_pattern_rules()
    for chunk in truncate_text(safe_pattern_text):
        all_texts.append(("high", "A", chunk))
        stats["A"]["high"] += 1
    print(f"      +1 条安全模式规则")

    # A3. 方法论文档（只保留领域知识文档）
    print("  A3. 提取领域知识文档...")
    for priority, path in DOC_SOURCES:
        if not path.exists():
            continue
        content = extract_text_from_doc(path)
        for chunk in truncate_text(content):
            all_texts.append((priority, "A", chunk))
            stats["A"][priority] += 1
        print(f"      +{len(truncate_text(content))} 段 ({path.name})")

    # ===== Layer B：推理层（剥离 system）=====
    print("\n[Layer B] 推理层（ChatML user+assistant，剥离 system 规则）")
    for priority, path in CHATML_SOURCES + DPO_SOURCES:
        if not path.exists():
            print(f"  ⚠️ 跳过不存在的文件: {path.name}")
            continue
        count = 0
        with open(path, "r", encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if "chosen" in rec:
                    text = extract_text_from_dpo(rec)
                elif args.legacy_mode:
                    # 兼容旧版：system+user+assistant 全拼
                    text = extract_reasoning_from_chatml_legacy(rec)
                else:
                    text = extract_reasoning_from_chatml(rec)

                if not text:
                    continue
                for chunk in truncate_text(text):
                    all_texts.append((priority, "B", chunk))
                    count += 1
                    stats["B"][priority] += 1
        print(f"  {priority:6s} {path.name}: +{count} 段")

    # ===== Layer C：代码层（带标签，默认排除测试集）=====
    if args.include_testset:
        print("\n[Layer C] 代码层（带 CWE 标签，--include-testset 已启用）")
        manifest_map = load_manifest()
        print(f"  manifest 加载 {len(manifest_map)} 个样本记录")
        code_texts = extract_labeled_code_samples(manifest_map)
        for t in code_texts:
            for chunk in truncate_text(t):
                all_texts.append(("low", "C", chunk))
                stats["C"]["low"] += 1
        print(f"  +{len(code_texts)} 条带标签代码示例")
    else:
        print("\n[Layer C] 代码层（默认排除测试集，--include-testset 启用）")
        print("  跳过：避免测试集泄露。如需纳入，加 --include-testset")

    # ===== 清洗：测试集泄露过滤 =====
    if not args.no_leak_filter:
        print("\n[清洗] 测试集泄露过滤")
        testset_code = load_testset_code()
        print(f"  已加载 {len(testset_code)} 个测试集代码文件")
        leaked = 0
        cleaned: list[tuple[str, str, str]] = []
        for priority, layer, text in all_texts:
            # 只对 Layer B 做泄露检测（Layer A/C 的代码块要么是知识，要么是带标签测试集）
            if layer == "B" and contains_testset_code(text, testset_code, args.leak_min_len):
                leaked += 1
                continue
            cleaned.append((priority, layer, text))
        all_texts = cleaned
        print(f"  过滤泄露样本: {leaked} 段")

    # ===== 清洗：全局精确去重 =====
    if not args.no_dedup:
        print("\n[清洗] 全局精确去重")
        before = len(all_texts)
        all_texts = deduplicate_texts(all_texts)
        after = len(all_texts)
        print(f"  去重前: {before} 段，去重后: {after} 段，移除: {before - after} 段")

    # ===== 重新统计 =====
    stats = {"A": {"high": 0, "medium": 0, "low": 0},
             "B": {"high": 0, "medium": 0, "low": 0},
             "C": {"high": 0, "medium": 0, "low": 0}}
    for priority, layer, text in all_texts:
        stats[layer][priority] += 1

    total_bytes = sum(len(t.encode("utf-8")) for _, _, t in all_texts)
    print("\n" + "=" * 60)
    print("语料统计（三层分离 + 清洗后）")
    print("=" * 60)
    for layer in ("A", "B", "C"):
        layer_name = {"A": "知识层", "B": "推理层", "C": "代码层"}[layer]
        layer_count = sum(stats[layer].values())
        layer_bytes = sum(
            len(t.encode("utf-8"))
            for p, l, t in all_texts if l == layer
        )
        print(f"  Layer {layer} {layer_name}: {layer_count} 段, {layer_bytes:,} 字节")
        for prio in ("high", "medium", "low"):
            if stats[layer][prio]:
                print(f"    {prio:6s}: {stats[layer][prio]}")
    print(f"  总段数: {len(all_texts)}")
    print(f"  总字节: {total_bytes:,} ({total_bytes / 1024 / 1024:.2f} MB)")

    # 去重效果对比
    sys_count = sum(1 for _, _, t in all_texts if "### SYSTEM" in t)
    print(f"\n  规则条文重复检查：含 '### SYSTEM' 的段数 = {sys_count}"
          f"（旧版 1100，三层版应为 0）")

    if total_bytes < 10 * 1024 * 1024:
        print(f"⚠️ 语料偏少（<10MB），KnItLM 效果可能有限")
        print(f"   建议后续联网补充 CVE/CWE 官方描述文档")
    elif total_bytes > 50 * 1024 * 1024:
        print(f"⚠️ 语料偏多（>50MB），CPT 训练时间会较长")

    if args.dry_run:
        print("\n[dry-run] 不写文件")
        return

    # 写出
    print(f"\n写入: {OUTPUT_FILE}")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as fp:
        for priority, layer, text in all_texts:
            rec = {"text": text, "priority": priority, "layer": layer}
            fp.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"✅ 已写入 {len(all_texts)} 段到 {OUTPUT_FILE}")
    print(f"   下一步用 train_knitlm_cpt.py 加载此语料做 CPT")


def extract_reasoning_from_chatml_legacy(record: dict) -> str | None:
    """旧版兼容：system+user+assistant 全拼（--legacy-mode 启用）。

    保留此函数供回退对比，但默认不使用——它会导致 SYSTEM_PROMPT 重复 921 次。
    """
    if "messages" not in record:
        if "chosen" in record:
            return record["chosen"]
        return None
    parts = []
    for msg in record["messages"]:
        role = msg.get("role", "")
        content = msg.get("content", "")
        if not content:
            continue
        parts.append(f"### {role.upper()}\n{content}")
    return "\n\n".join(parts) if parts else None


if __name__ == "__main__":
    main()
