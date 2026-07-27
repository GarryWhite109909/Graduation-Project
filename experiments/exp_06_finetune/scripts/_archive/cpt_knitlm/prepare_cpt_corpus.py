"""
KnItLM CPT 语料准备脚本 —— 三层分离版（知识 / 推理 / 代码）。

对应 docs/方法.md §9 Phase 3 KnItLM 知识注入。
2026-07-19 重构：从"扁平拼接"改为"三层分离"，解决规则条文重复 921 次导致
参数化查询幻觉副作用（见 phase3_error_analysis.md 回归样本）。
2026-07-19 增补：靶向过滤（--probe-report），基于对话.md的核心洞察——
注入模型已掌握的知识会引发知识冲突（负迁移），应只对盲区做 CPT。

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
  python3 prepare_cpt_corpus.py
  python3 prepare_cpt_corpus.py --dry-run
  python3 prepare_cpt_corpus.py --include-testset  # 纳入测试集代码（带标签）
  python3 prepare_cpt_corpus.py --probe-report data/probe_report.json  # 靶向过滤
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

# 通用代码回放占总语料比例（1:4）
GENERAL_CODE_RATIO = 0.25

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
# 靶向过滤：基于 probe_model.py 的探测报告
# ---------------------------------------------------------------------------

def load_probe_report(path: Path) -> dict[str, str]:
    """加载 probe_model.py 生成的探测报告。

    Returns: {cwe_id: overall_state}，overall_state ∈ {"mastered", "fuzzy", "error", "unknown"}
    """
    if not path or not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    results = data.get("probe_results", {})
    return {cwe: info.get("overall", "unknown") for cwe, info in results.items()}


def should_include_knowledge(
    cwe: str,
    probe_report: dict[str, str],
    include_mastered: bool = False,
) -> bool:
    """根据探测报告决定是否纳入该 CWE 的知识。

    对话.md 核心发现：注入模型已掌握的知识会引发知识冲突（负迁移）。
    因此默认排除 mastered 的 CWE 知识，只注入 fuzzy 和 error 的。

    Args:
        cwe: CWE 编号（如 "CWE-89"）
        probe_report: {cwe: overall_state} 映射
        include_mastered: 是否强制纳入 mastered CWE 的知识

    Returns:
        True 表示应纳入，False 表示应跳过
    """
    if not probe_report:
        return True  # 无探测报告时不过滤

    state = probe_report.get(cwe, "unknown")
    if state == "mastered" and not include_mastered:
        return False  # 模型已掌握，跳过以避免知识冲突
    # fuzzy, error, unknown 都纳入
    return True


# ---------------------------------------------------------------------------
# Layer A：知识层（去重，每条学 1 次）
# ---------------------------------------------------------------------------

def extract_knowledge_from_rag(
    probe_report: dict[str, str] | None = None,
    include_mastered: bool = False,
) -> list[tuple[str, str]]:
    """从 knowledge.json 提取结构化 CWE 百科条目。

    每条转成"CWE-XX 名称：描述 + 危险API + 安全写法 + 判断要点"的知识文本。
    72 条覆盖 39 个 CWE，含 15 条 safe_pattern 安全模式条目。

    新增靶向过滤（--probe-report）：
    基于 probe_model.py 的探测报告，跳过 mastered CWE 的知识，
    避免注入模型已掌握的知识导致知识冲突（负迁移）。
    """
    texts = []
    if not RAG_KNOWLEDGE_FILE.exists():
        print(f"  ⚠️ knowledge.json 不存在: {RAG_KNOWLEDGE_FILE}", file=sys.stderr)
        return texts

    with open(RAG_KNOWLEDGE_FILE, encoding="utf-8") as f:
        knowledge = json.load(f)

    skipped_mastered = 0
    for entry in knowledge:
        cwe = entry.get("metadata", {}).get("cwe", "")
        vtype = entry.get("metadata", {}).get("type", "")
        is_safe = entry.get("metadata", {}).get("safe_pattern", False)
        doc = entry.get("document", "")

        if not doc.strip():
            continue

        # 靶向过滤：跳过 mastered CWE 的知识
        if probe_report and not should_include_knowledge(cwe, probe_report, include_mastered):
            skipped_mastered += 1
            continue

        # 构造知识条目标题
        tag = "【安全模式】" if is_safe else "【漏洞模式】"
        title = f"{tag} {cwe} {vtype}" if cwe else f"{tag} {vtype}"

        knowledge_text = f"### 漏洞领域知识：{title}\n\n{doc}"
        texts.append(("high", knowledge_text))

    if skipped_mastered:
        print(f"      靶向过滤：跳过 {skipped_mastered} 条 mastered CWE 知识（避免知识冲突）")

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


def extract_cwe_from_record(record: dict) -> str:
    """从 Layer B 的 ChatML/DPO 记录中提取 CWE 标签。

    优先级：expected_cwe > cwe > metadata.cwe > 从文本正则提取。
    提取不到返回空字符串（不应跳过过滤，让 should_include_knowledge 默认纳入）。
    """
    cwe = record.get("expected_cwe") or record.get("cwe") or ""
    if not cwe:
        cwe = record.get("metadata", {}).get("cwe", "") if isinstance(record.get("metadata"), dict) else ""
    if cwe:
        return cwe
    # Layer B 的 ChatML/DPO 记录无显式 CWE 字段，从文本内容正则提取
    text_to_search = ""
    if "chosen" in record:
        text_to_search = record.get("chosen", "") or ""
    elif "messages" in record:
        for msg in record.get("messages", []):
            if isinstance(msg, dict) and msg.get("role") == "assistant":
                text_to_search += msg.get("content", "") or ""
    m = re.search(r"CWE-\d+", text_to_search)
    return m.group(0) if m else ""


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


def generate_synthetic_general_code(num_samples: int = 500) -> list[tuple[str, str]]:
    """合成通用代码回放（General Code Replay）。

    目的：防止 CPT 只学漏洞语料后产生灾难性遗忘和保守化倾向。
    这些代码片段与漏洞测试集无关，覆盖通用 Python 编程模式，保护 base 模型
    的通用代码理解能力。

    片段来自常见编程任务模板，通过变量名/结构微调生成多样性。
    """
    import random
    rng = random.Random(42)

    templates = [
        # 1. 排序与搜索
        """def {func}_sort(items):
    if len(items) <= 1:
        return items
    pivot = items[len(items) // 2]
    left = [x for x in items if x < pivot]
    middle = [x for x in items if x == pivot]
    right = [x for x in items if x > pivot]
    return {func}_sort(left) + middle + {func}_sort(right)

nums = [{n1}, {n2}, {n3}, {n4}, {n5}]
print({func}_sort(nums))
""",
        """def {func}_search(arr, target):
    left, right = 0, len(arr) - 1
    while left <= right:
        mid = (left + right) // 2
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            left = mid + 1
        else:
            right = mid - 1
    return -1

sorted_arr = [{n1}, {n2}, {n3}, {n4}, {n5}]
print({func}_search(sorted_arr, {n3}))
""",
        # 2. 数据结构
        """class {Cls}Node:
    def __init__(self, value):
        self.value = value
        self.next = None

class {Cls}LinkedList:
    def __init__(self):
        self.head = None

    def append(self, value):
        new_node = {Cls}Node(value)
        if not self.head:
            self.head = new_node
            return
        cur = self.head
        while cur.next:
            cur = cur.next
        cur.next = new_node

ll = {Cls}LinkedList()
for v in [{n1}, {n2}, {n3}]:
    ll.append(v)
""",
        """from collections import deque

def {func}_bfs(graph, start):
    visited = set([start])
    queue = deque([start])
    while queue:
        node = queue.popleft()
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    return visited

graph = {{
    'a': ['b', 'c'],
    'b': ['d'],
    'c': ['d'],
    'd': []
}}
print({func}_bfs(graph, 'a'))
""",
        # 3. 文件与 JSON 处理
        """import json
from pathlib import Path

def {func}_load_config(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def {func}_save_config(data, path):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

config = {{"name": "{name}", "version": {n1}, "enabled": True}}
{func}_save_config(config, "/tmp/{name}.json")
loaded = {func}_load_config("/tmp/{name}.json")
""",
        """import csv

def {func}_process_csv(input_path, output_path):
    with open(input_path, newline='', encoding='utf-8') as inf, \\
         open(output_path, 'w', newline='', encoding='utf-8') as outf:
        reader = csv.DictReader(inf)
        writer = csv.DictWriter(outf, fieldnames=reader.fieldnames)
        writer.writeheader()
        for row in reader:
            row['score'] = float(row.get('score', 0)) * {n1}
            writer.writerow(row)

{func}_process_csv('input.csv', 'output.csv')
""",
        # 4. 字符串与正则
        """import re

def {func}_extract_emails(text):
    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{{2,}}'
    return re.findall(pattern, text)

sample = "Contact us at {name}@example.com or support@{name}.org"
print({func}_extract_emails(sample))
""",
        """def {func}_slugify(text):
    text = text.lower().strip()
    text = text.replace(' ', '-')
    allowed = set('abcdefghijklmnopqrstuvwxyz0123456789-')
    return ''.join(c for c in text if c in allowed)

print({func}_slugify("Hello World {n1}"))
""",
        # 5. 日期时间
        """from datetime import datetime, timedelta

def {func}_parse_date(s):
    return datetime.strptime(s, '%Y-%m-%d')

def {func}_add_days(d, days):
    return d + timedelta(days=days)

d = {func}_parse_date('2026-{m:02d}-{d:02d}')
print({func}_add_days(d, {n1}))
""",
        # 6. 数学/统计
        """import statistics

def {func}_summarize(values):
    return {{
        'count': len(values),
        'mean': statistics.mean(values),
        'median': statistics.median(values),
        'stdev': statistics.stdev(values) if len(values) > 1 else 0,
    }}

print({func}_summarize([{n1}, {n2}, {n3}, {n4}, {n5}]))
""",
        # 7. 安全的 Web 路由示例（通用，非漏洞）
        """from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/api/{name}', methods=['GET'])
def {func}_get_{name}():
    data = {{"id": {n1}, "name": "{name}", "status": "ok"}}
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True)
""",
        # 8. 配置与日志
        """import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('{name}')

def {func}_process(item):
    logger.info(f'Processing {{item}}')
    return item * {n1}

{func}_process({n2})
""",
        # 9. 上下文管理器
        """from contextlib import contextmanager

@contextmanager
def {func}_managed_resource():
    resource = {{"open": True}}
    try:
        yield resource
    finally:
        resource["open"] = False

with {func}_managed_resource() as r:
    print(r)
""",
        # 10. 迭代器/生成器
        """def {func}_fibonacci(n):
    a, b = 0, 1
    for _ in range(n):
        yield a
        a, b = b, a + b

print(list({func}_fibonacci({n1})))
""",
    ]

    names = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta",
             "iota", "kappa", "lambda", "mu", "nu", "xi", "omicron", "pi"]

    texts = []
    for i in range(num_samples):
        tmpl = rng.choice(templates)
        name = rng.choice(names)
        func = name[:4]
        cls = name.capitalize()
        nums = [rng.randint(1, 100) for _ in range(5)]
        month = rng.randint(1, 12)
        day = rng.randint(1, 28)
        text = tmpl.format(
            func=func, Cls=cls, name=name,
            n1=nums[0], n2=nums[1], n3=nums[2], n4=nums[3], n5=nums[4],
            m=month, d=day,
        )
        texts.append(("medium", f"### 通用代码示例：{name}_{i}\n\n```python\n{text}\n```"))

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
                        help="⚠️ 危险：包含 exp_04 测试集代码会导致数据泄露，仅用于调试，不要用于正式训练")
    parser.add_argument("--legacy-mode", action="store_true",
                        help="兼容旧版扁平模式（system+user+assistant 全拼）。默认三层分离。")
    parser.add_argument("--no-leak-filter", action="store_true",
                        help="禁用测试集泄露过滤。默认启用。")
    parser.add_argument("--no-dedup", action="store_true",
                        help="禁用全局精确去重。默认启用。")
    parser.add_argument("--leak-min-len", type=int, default=200,
                        help="泄露检测最小匹配长度（默认 200 字符）")
    parser.add_argument("--general-code-ratio", type=float, default=GENERAL_CODE_RATIO,
                        help=f"通用代码回放占总语料比例（默认 {GENERAL_CODE_RATIO}）")
    parser.add_argument("--probe-report", type=Path, default=None,
                        help="probe_model.py 的探测报告路径。"
                             "启用后，Layer A 知识层将过滤 mastered CWE，"
                             "避免注入模型已掌握的知识导致冲突（负迁移）。")
    parser.add_argument("--include-mastered", action="store_true",
                        help="即使有探测报告，仍纳入 mastered CWE 的知识（默认排除）")
    args = parser.parse_args()

    # 加载探测报告（靶向过滤）
    probe_report: dict[str, str] = {}
    if args.probe_report:
        probe_report = load_probe_report(args.probe_report)
        if probe_report:
            mastered = sum(1 for s in probe_report.values() if s == "mastered")
            fuzzy = sum(1 for s in probe_report.values() if s == "fuzzy")
            error = sum(1 for s in probe_report.values() if s == "error")
            print(f"探测报告已加载: {len(probe_report)} 个 CWE "
                  f"(mastered={mastered}, fuzzy={fuzzy}, error={error})")
            if not args.include_mastered:
                print(f"  → 将过滤 mastered CWE 的知识，避免知识冲突")
        else:
            print(f"⚠️ 探测报告为空或格式错误: {args.probe_report}")

    print("=" * 60)
    print("KnItLM CPT 语料准备（三层分离版）")
    print("=" * 60)

    all_texts: list[tuple[str, str, str]] = []  # (priority, layer, text)
    stats: dict[str, dict[str, int]] = {
        "A": {"high": 0, "medium": 0, "low": 0},
        "B": {"high": 0, "medium": 0, "low": 0},
        "C": {"high": 0, "medium": 0, "low": 0},
        "D": {"high": 0, "medium": 0, "low": 0},
    }

    # ===== Layer A：知识层（去重）=====
    print("\n[Layer A] 知识层（去重，每条学 1 次）")

    # A1. knowledge.json 结构化 CWE 百科
    print("  A1. 提取 knowledge.json 结构化 CWE 百科...")
    rag_texts = extract_knowledge_from_rag(
        probe_report=probe_report,
        include_mastered=args.include_mastered,
    )
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
    skipped_count = 0       # 格式不匹配（无 messages/chosen 字段）
    skipped_by_probe = 0    # probe 靶向过滤跳过（mastered CWE）
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
                    # v1 蒸馏数据（distill_corpus_annotated*.jsonl）为原始标注格式，
                    # 无 messages/chosen 字段，extract_* 返回 None 被静默跳过。计数并告警。
                    skipped_count += 1
                    continue

                # Layer B 也做 probe 靶向过滤（避免注入已掌握 CWE 导致表示空间排斥）
                if probe_report:
                    record_cwe = extract_cwe_from_record(rec)
                    if record_cwe and not should_include_knowledge(
                        record_cwe, probe_report, args.include_mastered
                    ):
                        skipped_by_probe += 1
                        continue

                for chunk in truncate_text(text):
                    all_texts.append((priority, "B", chunk))
                    count += 1
                    stats["B"][priority] += 1
        print(f"  {priority:6s} {path.name}: +{count} 段")

    if skipped_count > 0:
        print(f"⚠️ 警告：{skipped_count} 条记录因格式不匹配（无 messages/chosen 字段）被跳过")
    if skipped_by_probe > 0:
        print(f"  probe 靶向过滤：Layer B 跳过 {skipped_by_probe} 条 mastered CWE 推理样本")

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

    # ===== Layer D：通用代码回放（防灾难性遗忘 / 保守化）=====
    print("\n[Layer D] 通用代码回放（General Code Replay，防保守化）")
    replay_texts = generate_synthetic_general_code(num_samples=500)
    for priority, text in replay_texts:
        for chunk in truncate_text(text):
            all_texts.append((priority, "D", chunk))
            stats["D"][priority] += 1
    print(f"  +{len(replay_texts)} 条合成通用代码片段")

    # 按 general_code_ratio 控制 Layer D 比例
    if args.general_code_ratio > 0 and replay_texts:
        vuln_count = sum(stats[l][p] for l in ("A", "B", "C") for p in stats[l])
        replay_count = sum(stats["D"].values())
        target_replay = int(vuln_count * args.general_code_ratio / (1 - args.general_code_ratio))
        if replay_count > target_replay:
            # 截断到目标数量（保留前 target_replay 条）
            kept = 0
            filtered = []
            for item in all_texts:
                if item[1] == "D":
                    if kept < target_replay:
                        filtered.append(item)
                        kept += 1
                    # 否则丢弃
                else:
                    filtered.append(item)
            all_texts = filtered
            print(f"  截断到目标比例：{replay_count} → {kept} 条（占总语料 {args.general_code_ratio*100:.0f}%）")
        else:
            print(f"  通用代码不足，全部保留（当前 {replay_count}，目标约 {target_replay}）")

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
             "C": {"high": 0, "medium": 0, "low": 0},
             "D": {"high": 0, "medium": 0, "low": 0}}
    for priority, layer, text in all_texts:
        stats[layer][priority] += 1

    total_bytes = sum(len(t.encode("utf-8")) for _, _, t in all_texts)
    print("\n" + "=" * 60)
    print("语料统计（三层分离 + 通用回放 + 清洗后）")
    print("=" * 60)
    for layer in ("A", "B", "C", "D"):
        layer_name = {"A": "知识层", "B": "推理层", "C": "代码层", "D": "通用回放"}[layer]
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
