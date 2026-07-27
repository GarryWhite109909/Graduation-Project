"""
知识探测脚本 —— 诊断模型对各 CWE 类别的掌握程度。

依据 docs/对话.md 的核心洞察：CPT 注入模型已掌握的知识会引发知识冲突（负迁移）。
本脚本在注入知识前先探测模型已知内容，输出 mastered/fuzzy/error 分类报告，
供 prepare_cpt_corpus.py --probe-report 做靶向过滤，避免知识冲突。

三级探测设计（对应人类学习的"摸底考试"）：
  - concept: 概念辨析 —— 模型是否理解该 CWE 的核心概念？
  - reasoning: 推理深度 —— 模型能否正确推理绕过/防御场景？
  - attribution: CWE 归因 —— 模型能否正确分类漏洞代码的 CWE 编号？

判定逻辑：
  - 三级全对 → mastered（模型已掌握，CPT 不需注入）
  - 概念对但推理/归因错 → fuzzy（需 CPT + SFT 加强推理）
  - 概念就错 → error（需 CPT 从头注入 + DPO 纠偏）

用法：
  # transformers 后端（需 GPU）
  python3 probe_model.py \
      --model-id Qwen/Qwen3-8B \
      --output probe_report.json

  # Ollama 后端（不占训练显存，推荐用于快速摸底）
  python3 probe_model.py \
      --ollama-model qwen3:8b \
      --output probe_report.json

  # 仅探测特定 CWE
  python3 probe_model.py \
      --ollama-model qwen3:8b \
      --cwe-filter CWE-89,CWE-352,CWE-611

  # 探测已微调模型
  python3 probe_model.py \
      --model-id Qwen/Qwen3-8B \
      --adapter-path outputs/lora_r8_a16_e1_s42/best \
      --output probe_report_phase1.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections import Counter
from pathlib import Path

# ROCm 多设备保护
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0")
os.environ.setdefault("HIP_VISIBLE_DEVICES", "0")

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.schema import parse_verdict, normalize_has_vulnerability
from experiments.utils import load_manifest, read_sample_code

# 知识库路径
RAG_KNOWLEDGE_FILE = (
    PROJECT_ROOT / "experiments/exp_03_rag_knowledge/knowledge_data/knowledge.json"
)
MANIFEST_PATH = PROJECT_ROOT / "experiments/exp_04_hard_samples/samples/manifest.json"
SAMPLES_DIR = PROJECT_ROOT / "experiments/exp_04_hard_samples/samples"
OUTPUT_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"

_CWE_PATTERN = re.compile(r"(CWE-\d+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# 三级探测 Prompt 生成
# ---------------------------------------------------------------------------


def extract_cwe(vt: str) -> str:
    """从 vulnerability_type 字符串中提取 CWE 编号。"""
    if not vt:
        return ""
    m = _CWE_PATTERN.search(vt)
    return m.group(1).upper() if m else ""


def load_knowledge_entries(path: Path = RAG_KNOWLEDGE_FILE) -> list[dict]:
    """加载 knowledge.json 中的 CWE 知识条目。"""
    if not path.exists():
        print(f"⚠️ 知识库文件不存在: {path}")
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def get_unique_cwes(knowledge: list[dict]) -> list[str]:
    """从知识条目中提取去重的 CWE 编号列表（按出现顺序）。"""
    seen = set()
    cwes = []
    for entry in knowledge:
        cwe = entry.get("metadata", {}).get("cwe", "")
        if cwe and cwe not in seen:
            seen.add(cwe)
            cwes.append(cwe)
    return cwes


def build_concept_probe(cwe: str, knowledge_entries: list[dict]) -> str:
    """生成概念辨析探测 prompt。

    让模型解释该 CWE 的核心概念和安全/不安全的区别。
    """
    # 收集该 CWE 的知识摘要
    docs = [
        e["document"]
        for e in knowledge_entries
        if e.get("metadata", {}).get("cwe") == cwe
    ]
    summary = docs[0][:200] if docs else f"{cwe} 相关漏洞"

    return (
        f"请简述 {cwe} 漏洞的核心特征和安全写法的关键区别。\n"
        f"要求：\n"
        f"1. 用 2-3 句话说明 {cwe} 的本质\n"
        f"2. 列出 1-2 个该 CWE 的典型危险 API 或模式\n"
        f"3. 列出 1-2 个该 CWE 的正确防御写法\n"
        f"请用 JSON 格式回答：\n"
        f'```json\n{{"cwe_understood": true/false, "dangerous_patterns": ["..."], '
        f'"safe_patterns": ["..."]}}\n```'
    )


def build_reasoning_probe(cwe: str, knowledge_entries: list[dict]) -> str | None:
    """生成推理深度探测 prompt。

    给出一个含绕过/防御混淆的代码场景，让模型判断是否安全。
    这直接测试模型是否只会"模式匹配"还是能真正推理。
    """
    # 根据不同 CWE 类型设计不同的推理探测
    probes = _REASONING_PROBES.get(cwe)
    if probes:
        return probes

    # 通用推理探测：基于知识生成
    docs = [
        e["document"]
        for e in knowledge_entries
        if e.get("metadata", {}).get("cwe") == cwe
    ]
    if not docs:
        # 无真实代码样本可用，返回 None 让调用方跳过推理判定
        return None

    # 提取该 CWE 的安全模式关键词
    safe_keywords = []
    for doc in docs:
        if "安全写法" in doc or "修复" in doc or "防御" in doc:
            # 提取安全模式描述
            for phrase in doc.split("。"):
                if any(kw in phrase for kw in ["安全写法", "修复", "防御", "参数化"]):
                    safe_keywords.append(phrase.strip())
                    break

    return (
        f"以下代码试图防御 {cwe} 漏洞，但防御可能不完全或存在绕过风险。"
        f"请分析代码是否真正安全，还是仍存在漏洞：\n\n"
        f"（请基于你对 {cwe} 的理解，分析是否存在绕过方式）\n"
        f"请用 JSON 格式回答：\n"
        f'```json\n{{"has_vulnerability": true/false, '
        f'"vulnerability_type": "CWE-XXX ...", '
        f'"reasoning": "..."}}\n```'
    )


def build_attribution_probe(
    cwe: str, manifest_records: list[dict]
) -> str | None:
    """生成 CWE 归因探测 prompt。

    从 manifest 中找一个该 CWE 的漏洞代码样本，让模型识别 CWE 编号。
    这直接测试模型的 CWE 归因能力（Phase 3 的 16 个 CWE 错标就是归因问题）。
    """
    # 找一个该 CWE 的漏洞样本
    for rec in manifest_records:
        if not rec.get("expected_present", False):
            continue
        expected_cwe = rec.get("expected_cwe", "")
        if not expected_cwe:
            continue
        # 支持分号分隔的多 CWE
        cwes = [c.strip().upper() for c in expected_cwe.split(";") if c.strip()]
        if cwe in cwes:
            code = read_sample_code(SAMPLES_DIR, rec["file"])
            if code:
                # 截取代码，避免超长
                code_preview = code[:600] + ("..." if len(code) > 600 else "")
                return (
                    f"分析以下 {rec.get('language', 'Python')} 代码的安全问题，"
                    f"指出漏洞类型和对应的 CWE 编号：\n\n"
                    f"```{rec.get('language', 'python').lower()}\n{code_preview}\n```\n\n"
                    f"请用 JSON 格式回答：\n"
                    f'```json\n{{"has_vulnerability": true/false, '
                    f'"vulnerability_type": "CWE-XXX ...", '
                    f'"explanation": "..."}}\n```'
                )
    return None


# ---------------------------------------------------------------------------
# 特定 CWE 的推理探测（精心设计，避免模式匹配能蒙对）
# ---------------------------------------------------------------------------

_REASONING_PROBES = {
    "CWE-89": (
        "以下 Python 代码试图防御 SQL 注入，请判断是否真正安全：\n\n"
        "```python\n"
        "import sqlite3\n"
        "def search(username):\n"
        "    # 防御：替换单引号\n"
        "    safe_name = username.replace(\"'\", \"''\")\n"
        "    conn = sqlite3.connect('app.db')\n"
        "    query = f\"SELECT * FROM users WHERE name = '{safe_name}'\"\n"
        "    return conn.execute(query).fetchall()\n"
        "```\n\n"
        "提示：replace(\"'\", \"''\") 不是参数化查询，仍可能被绕过。"
        "请用 JSON 格式回答：\n"
        '```json\n{"has_vulnerability": true/false, '
        '"vulnerability_type": "CWE-XXX ...", '
        '"reasoning": "..."}\n```'
    ),
    "CWE-78": (
        "以下 Python 代码是否安全？请仔细分析：\n\n"
        "```python\n"
        "import subprocess\n"
        "def ping(host):\n"
        "    # 使用列表形式 + shell=False\n"
        "    result = subprocess.run(\n"
        "        ['ping', '-c', '1', host],\n"
        "        capture_output=True, text=True\n"
        "    )\n"
        "    return result.stdout\n"
        "```\n\n"
        "提示：这是列表形式调用，shell 默认为 False。"
        "请用 JSON 格式回答：\n"
        '```json\n{"has_vulnerability": true/false, '
        '"vulnerability_type": "CWE-XXX ...", '
        '"reasoning": "..."}\n```'
    ),
    "CWE-79": (
        "以下 Python/HTML 代码是否存在 XSS 漏洞？\n\n"
        "```python\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/greet')\n"
        "def greet():\n"
        "    name = request.args.get('name', '')\n"
        "    return f'<h1>Hello, {name}!</h1>'\n"
        "```\n\n"
        "请判断是否存在 XSS 漏洞，并说明理由。"
        "请用 JSON 格式回答：\n"
        '```json\n{"has_vulnerability": true/false, '
        '"vulnerability_type": "CWE-XXX ...", '
        '"reasoning": "..."}\n```'
    ),
    "CWE-22": (
        "以下 Python 代码是否安全？\n\n"
        "```python\n"
        "import os\n"
        "def read_file(filename):\n"
        "    base_dir = '/var/www/files'\n"
        "    filepath = os.path.join(base_dir, filename)\n"
        "    with open(filepath, 'r') as f:\n"
        "        return f.read()\n"
        "```\n\n"
        "提示：os.path.join 不做路径规范化，如果 filename='../../etc/passwd' 会怎样？"
        "请用 JSON 格式回答：\n"
        '```json\n{"has_vulnerability": true/false, '
        '"vulnerability_type": "CWE-XXX ...", '
        '"reasoning": "..."}\n```'
    ),
    "CWE-352": (
        "以下 Python 代码是否存在 CSRF 漏洞？\n\n"
        "```python\n"
        "from flask import Flask, request, session\n"
        "app = Flask(__name__)\n"
        "@app.route('/transfer', methods=['POST'])\n"
        "def transfer():\n"
        "    to = request.form.get('to')\n"
        "    amount = request.form.get('amount')\n"
        "    # 执行转账\n"
        "    return f'Transfer ${amount} to {to}'\n"
        "```\n\n"
        "提示：没有 CSRF token 验证。"
        "请用 JSON 格式回答：\n"
        '```json\n{"has_vulnerability": true/false, '
        '"vulnerability_type": "CWE-XXX ...", '
        '"reasoning": "..."}\n```'
    ),
    "CWE-502": (
        "以下 Python 代码是否安全？\n\n"
        "```python\n"
        "import pickle\n"
        "import base64\n"
        "def load_session(data):\n"
        "    return pickle.loads(base64.b64decode(data))\n"
        "```\n\n"
        "提示：pickle.loads 可以执行任意代码。"
        "请用 JSON 格式回答：\n"
        '```json\n{"has_vulnerability": true/false, '
        '"vulnerability_type": "CWE-XXX ...", '
        '"reasoning": "..."}\n```'
    ),
    "CWE-1336": (
        "以下 Python 代码是否存在 SSTI 漏洞？\n\n"
        "```python\n"
        "from jinja2 import Environment\n"
        "env = Environment()\n"
        "def render_greeting(name):\n"
        "    template = f'Hello {name}!'\n"
        "    return env.from_string(template).render(name=name)\n"
        "```\n\n"
        "提示：用户输入直接进入模板字符串，而不是模板变量。"
        "请用 JSON 格式回答：\n"
        '```json\n{"has_vulnerability": true/false, '
        '"vulnerability_type": "CWE-XXX ...", '
        '"reasoning": "..."}\n```'
    ),
}


# ---------------------------------------------------------------------------
# 模型推理（复用 evaluate.py 的接口模式）
# ---------------------------------------------------------------------------


def load_transformers_model(model_id: str, adapter_path: str | None = None,
                            quantize_4bit: bool = True):
    """加载 transformers 模型。复用 evaluate.py 的模式。"""
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    print(f"加载 tokenizer: {model_id}")
    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    dtype = torch.float16
    bnb_config = None
    if quantize_4bit:
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )

    print(f"加载模型: {model_id} ({'4bit' if bnb_config else 'fp16'})")
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        quantization_config=bnb_config,
        device_map={"": 0},
        trust_remote_code=True,
        torch_dtype=dtype,
        attn_implementation="sdpa",
    )

    if adapter_path:
        print(f"加载 LoRA adapter: {adapter_path}")
        model = PeftModel.from_pretrained(model, adapter_path)
        model = model.merge_and_unload()

    model.eval()
    return model, tokenizer


def generate_transformers(model, tokenizer, prompt: str,
                          max_new_tokens: int = 512) -> str:
    """用 transformers 后端生成回复。"""
    import torch

    messages = [
        {"role": "system", "content": "你是一个代码安全分析专家。请严格按照要求的JSON格式回答。"},
        {"role": "user", "content": prompt},
    ]
    text = tokenizer.apply_chat_template(
        messages, tokenize=False, add_generation_prompt=True,
        enable_thinking=False,  # Qwen3: 禁用 thinking mode
    )
    inputs = tokenizer(text, return_tensors="pt").to(model.device)
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            pad_token_id=tokenizer.pad_token_id,
            do_sample=False,
        )
    input_len = inputs["input_ids"].shape[1]
    return tokenizer.decode(outputs[0][input_len:], skip_special_tokens=True)


def generate_ollama(ollama_model: str, prompt: str,
                    max_new_tokens: int = 512) -> str:
    """用 Ollama 后端生成回复。

    Qwen3 thinking mode 由 OllamaClient 自动处理（chat API + think:false），
    无需在此追加 /no_think 后缀或剥离思考块。
    """
    from graduation_project.llm_client import OllamaClient

    client = OllamaClient(model=ollama_model)
    result = client.generate(
        prompt=prompt,
        system_prompt="你是一个代码安全分析专家。请严格按照要求的JSON格式回答。",
        temperature=0.0,
        max_tokens=max_new_tokens,
        num_ctx=8192,
        keep_alive=300,
    )
    if result.get("error"):
        raise RuntimeError(f"Ollama error: {result['error']}")

    response = result.get("text", "")
    if "<think>" in response:
        print(f"⚠️ 警告：Ollama 输出含 <think> 标签，thinking mode 可能未正确禁用")
    return response


# ---------------------------------------------------------------------------
# 知识状态判定
# ---------------------------------------------------------------------------


def judge_concept(response: str, cwe: str) -> bool:
    """判断概念探测是否正确。

    简单启发式：如果模型输出包含 cwe_understood: true，
    且危险/安全模式描述合理，则判定为已掌握。
    """
    # 尝试直接从 JSON 中提取 cwe_understood（概念探测的 JSON 不含 has_vulnerability，
    # parse_verdict 会跳过，所以直接用 json.loads）
    import re as _re
    json_blocks = _re.findall(r"```json\s*(\{.*?\})\s*```", response, _re.DOTALL)
    if not json_blocks:
        json_blocks = _re.findall(r"\{[^{}]*\"cwe_understood\"[^{}]*\}", response, _re.DOTALL)
    for block in json_blocks:
        try:
            data = json.loads(block)
            understood = data.get("cwe_understood")
            if understood is not None:
                return bool(understood)
        except (json.JSONDecodeError, ValueError):
            continue

    # 尝试 parse_verdict（兜底）
    verdict = parse_verdict(response)
    if verdict:
        understood = verdict.get("cwe_understood")
        if understood is not None:
            return bool(understood)

    # 回退：检查是否同时提到了危险模式和安全模式（不强制要求 CWE 编号，
    # 因为概念探测的回答通常只在 prompt 中提到 CWE 编号，回答本身不一定重复）
    # 收紧判定：需同时出现危险关键词、防御关键词，且响应长度足够（避免短回复误判）
    if len(response) <= 50:
        return False
    resp_lower = response.lower()
    has_danger = any(kw in resp_lower for kw in ["危险", "漏洞", "不安全", "注入", "绕过", "穿越", "执行", "泄露"])
    has_safe = any(kw in resp_lower for kw in ["参数化", "转义", "防御", "修复", "过滤", "校验", "白名单", "编码"])
    return has_danger and has_safe


def judge_reasoning(response: str, cwe: str, expected_vuln: bool) -> bool:
    """判断推理探测是否正确。

    expected_vuln: 该探测 prompt 预期模型应该判出漏洞（True）还是安全（False）。
    """
    verdict = parse_verdict(response)
    if verdict:
        predicted = normalize_has_vulnerability(verdict.get("has_vulnerability"))
        if predicted is not None:
            return predicted == expected_vuln

    # 回退：从文本中推断（避免裸 "true"/"false" 误匹配，如 "this is not true"）
    resp_lower = response.lower()
    if expected_vuln:
        return any(kw in resp_lower for kw in ["存在漏洞", "有漏洞", "不安全", "存在安全风险", "vulnerable"])
    else:
        return any(kw in resp_lower for kw in ["安全", "无漏洞", "未发现漏洞", "no vulnerability", "safe"])


def judge_attribution(response: str, expected_cwe: str) -> tuple[bool | None, str]:
    """判断 CWE 归因探测是否正确。

    Returns: (is_correct, model_cwe)
        - is_correct 为 True/False 表示归因正确/错误
        - is_correct 为 None 表示 expected_cwe 为空，归因能力未验证
    """
    verdict = parse_verdict(response)
    model_vt = ""
    if verdict:
        model_vt = verdict.get("vulnerability_type", "")

    model_cwe = extract_cwe(model_vt)
    if not model_cwe:
        # 回退：从文本中提取 CWE
        m = _CWE_PATTERN.search(response)
        model_cwe = m.group(1).upper() if m else ""

    if not expected_cwe or expected_cwe.upper() == "N/A":
        # 归因能力未验证（无 expected_cwe 可比对），返回 None 而非 True，
        # 避免只有 concept+reasoning 通过的 CWE 被误判为 mastered
        return None, model_cwe

    expected_cwes = [c.strip().upper() for c in expected_cwe.split(";") if c.strip()]
    return model_cwe in expected_cwes, model_cwe


def classify_knowledge_state(
    concept_correct: bool,
    reasoning_correct: bool,
    attribution_correct: bool | None,
) -> str:
    """根据三级探测结果分类为 mastered / fuzzy / error。

    判定逻辑（对应对话.md 的"类人学习范式"）：
      - 三级全对 → mastered（模型已掌握，CPT 不需注入，注入会导致冲突）
      - 概念对但推理/归因错 → fuzzy（需 CPT + SFT 加强推理）
      - 概念就错 → error（需 CPT 从头注入 + DPO 纠偏）
    注意：attribution_correct 为 None 表示归因能力未验证，不能判为 mastered，降级为 fuzzy。
    """
    if attribution_correct is None:
        # 归因能力未验证，不能判为 mastered；概念正确则降级为 fuzzy
        if concept_correct:
            return "fuzzy"
        return "error"
    if concept_correct and reasoning_correct and attribution_correct:
        return "mastered"
    elif concept_correct:
        return "fuzzy"
    else:
        return "error"


# ---------------------------------------------------------------------------
# 主探测流程
# ---------------------------------------------------------------------------


def run_probe(
    cwe: str,
    knowledge_entries: list[dict],
    manifest_records: list[dict],
    model=None,
    tokenizer=None,
    ollama_model: str | None = None,
) -> dict:
    """对单个 CWE 运行三级探测。"""
    results = {
        "concept_level": "unknown",
        "reasoning_level": "unknown",
        "attribution_level": "unknown",
        "overall": "unknown",
        "evidence": {},
        "raw_outputs": {},
    }

    # --- Level 1: 概念辨析 ---
    concept_prompt = build_concept_probe(cwe, knowledge_entries)
    try:
        if ollama_model:
            concept_resp = generate_ollama(ollama_model, concept_prompt)
        else:
            concept_resp = generate_transformers(model, tokenizer, concept_prompt)
        concept_correct = judge_concept(concept_resp, cwe)
        results["concept_level"] = "mastered" if concept_correct else "error"
        results["evidence"]["concept_correct"] = concept_correct
        results["raw_outputs"]["concept"] = concept_resp[:500]
    except Exception as e:
        results["raw_outputs"]["concept"] = f"ERROR: {e}"
        concept_correct = False

    # --- Level 2: 推理深度 ---
    reasoning_prompt = build_reasoning_probe(cwe, knowledge_entries)
    # 大多数推理探测预期模型应判出漏洞
    expected_vuln = True
    # 注意：此 expected_vuln 与 _REASONING_PROBES["CWE-78"] 的内容强耦合
    # 如果修改 CWE-78 的 probe（如改为漏洞示例），需同步更新此处的 expected_vuln
    # CWE-78 的推理探测是安全代码（列表形式 subprocess），预期判安全
    if cwe == "CWE-78":
        expected_vuln = False
    if reasoning_prompt is None:
        # 无真实代码样本可用，跳过推理判定（标记 unknown 而非 error）
        results["reasoning_level"] = "unknown"
        reasoning_correct = False
    else:
        try:
            if ollama_model:
                reasoning_resp = generate_ollama(ollama_model, reasoning_prompt)
            else:
                reasoning_resp = generate_transformers(model, tokenizer, reasoning_prompt)
            reasoning_correct = judge_reasoning(reasoning_resp, cwe, expected_vuln)
            results["reasoning_level"] = "mastered" if reasoning_correct else "error"
            results["evidence"]["reasoning_correct"] = reasoning_correct
            results["evidence"]["reasoning_expected_vuln"] = expected_vuln
            results["raw_outputs"]["reasoning"] = reasoning_resp[:500]
        except Exception as e:
            results["raw_outputs"]["reasoning"] = f"ERROR: {e}"
            reasoning_correct = False

    # --- Level 3: CWE 归因 ---
    attribution_prompt = build_attribution_probe(cwe, manifest_records)
    if attribution_prompt:
        # 找到对应的 expected_cwe
        expected_cwe = ""
        for rec in manifest_records:
            if not rec.get("expected_present", False):
                continue
            rec_cwe = rec.get("expected_cwe", "")
            cwes = [c.strip().upper() for c in rec_cwe.split(";") if c.strip()]
            if cwe in cwes:
                expected_cwe = rec_cwe
                break
        try:
            if ollama_model:
                attribution_resp = generate_ollama(ollama_model, attribution_prompt)
            else:
                attribution_resp = generate_transformers(model, tokenizer, attribution_prompt)
            attribution_correct, model_cwe = judge_attribution(attribution_resp, expected_cwe)
            if attribution_correct is None:
                # expected_cwe 为空，归因能力未验证
                results["attribution_level"] = "unverified"
            else:
                results["attribution_level"] = "mastered" if attribution_correct else "error"
            results["evidence"]["attribution_correct"] = attribution_correct
            results["evidence"]["attribution_cwe"] = model_cwe
            results["evidence"]["expected_cwe"] = expected_cwe
            results["raw_outputs"]["attribution"] = attribution_resp[:500]
        except Exception as e:
            results["raw_outputs"]["attribution"] = f"ERROR: {e}"
            attribution_correct = False
    else:
        # 没有对应的测试样本，归因探测跳过（未验证，不能判为 mastered）
        results["attribution_level"] = "skipped"
        attribution_correct = None  # 跳过时归因未验证，降级为 fuzzy 而非判 mastered

    # --- 综合判定 ---
    results["overall"] = classify_knowledge_state(
        concept_correct, reasoning_correct, attribution_correct
    )

    return results


def generate_probe_report(
    all_results: dict[str, dict],
    model_id: str,
    backend: str,
    output_path: Path,
) -> dict:
    """生成结构化探测报告 JSON。"""
    mastered = []
    fuzzy = []
    error = []

    for cwe, result in sorted(all_results.items()):
        overall = result.get("overall", "unknown")
        if overall == "mastered":
            mastered.append(cwe)
        elif overall == "fuzzy":
            fuzzy.append(cwe)
        elif overall == "error":
            error.append(cwe)

    report = {
        "model_id": model_id,
        "probed_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "backend": backend,
        "total_cwes_probed": len(all_results),
        "probe_results": all_results,
        "summary": {
            "mastered_cwes": mastered,
            "mastered_count": len(mastered),
            "fuzzy_cwes": fuzzy,
            "fuzzy_count": len(fuzzy),
            "error_cwes": error,
            "error_count": len(error),
        },
    }

    # 保存
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n探测报告已保存: {output_path}")
    print(f"  mastered: {len(mastered)} ({', '.join(mastered[:10])}{'...' if len(mastered) > 10 else ''})")
    print(f"  fuzzy:    {len(fuzzy)} ({', '.join(fuzzy[:10])}{'...' if len(fuzzy) > 10 else ''})")
    print(f"  error:    {len(error)} ({', '.join(error[:10])}{'...' if len(error) > 10 else ''})")

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="知识探测：诊断模型对各 CWE 类别的掌握程度",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # 模型选择（二选一）
    model_group = parser.add_mutually_exclusive_group()
    model_group.add_argument(
        "--model-id",
        default="Qwen/Qwen3-8B",
        help="transformers 模型 ID（默认 Qwen/Qwen3-8B）",
    )
    model_group.add_argument(
        "--ollama-model",
        help="Ollama 模型名称（如 qwen3:8b），不占训练显存",
    )

    # 可选参数
    parser.add_argument(
        "--adapter-path",
        help="LoRA adapter 路径（探测已微调模型时使用）",
    )
    parser.add_argument(
        "--no-4bit",
        action="store_true",
        help="禁用 4bit 量化（用 fp16 推理，更准但更慢）",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_DIR / "probe_report.json",
        help=f"探测报告输出路径（默认 {OUTPUT_DIR / 'probe_report.json'}）",
    )
    parser.add_argument(
        "--cwe-filter",
        help="仅探测指定 CWE，逗号分隔（如 CWE-89,CWE-352）",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="仅生成探测 prompt 不运行模型（调试用）",
    )

    args = parser.parse_args()

    # 加载知识库
    knowledge = load_knowledge_entries()
    if not knowledge:
        print("❌ 无法加载知识库，退出")
        sys.exit(1)
    print(f"加载知识库: {len(knowledge)} 条")

    # 加载 manifest（用于归因探测）
    manifest_records = load_manifest(MANIFEST_PATH)
    if isinstance(manifest_records, tuple):
        _, manifest_records = manifest_records  # (manifest_dict, samples_list)
    print(f"加载 manifest: {len(manifest_records)} 条样本")

    # 获取要探测的 CWE 列表
    all_cwes = get_unique_cwes(knowledge)
    if args.cwe_filter:
        filter_cwes = {c.strip().upper() for c in args.cwe_filter.split(",")}
        all_cwes = [c for c in all_cwes if c in filter_cwes]
        print(f"过滤后探测 CWE: {len(all_cwes)} 个")
    else:
        print(f"将探测 {len(all_cwes)} 个 CWE 类别")

    # Dry run 模式
    if args.dry_run:
        print("\n=== Dry Run: 仅展示探测 prompt ===")
        for cwe in all_cwes:
            print(f"\n--- {cwe} ---")
            print(f"[概念] {build_concept_probe(cwe, knowledge)[:200]}...")
            r_probe = build_reasoning_probe(cwe, knowledge)
            print(f"[推理] {r_probe[:200] if r_probe else '（无可用代码样本，跳过）'}...")
            attr = build_attribution_probe(cwe, manifest_records)
            print(f"[归因] {'有' if attr else '无'}对应样本")
        return

    # 加载模型
    model = None
    tokenizer = None
    backend = "transformers"

    if args.ollama_model:
        backend = "ollama"
        print(f"使用 Ollama 后端: {args.ollama_model}")
        # 测试 Ollama 连接
        from graduation_project.llm_client import OllamaClient
        test_client = OllamaClient(model=args.ollama_model)
        test_result = test_client.generate(
            prompt="hello", max_tokens=10, keep_alive=300,
        )
        if test_result.get("error"):
            print(f"❌ Ollama 连接失败: {test_result['error']}")
            sys.exit(1)
        print("Ollama 连接正常")
    else:
        model, tokenizer = load_transformers_model(
            args.model_id,
            adapter_path=args.adapter_path,
            quantize_4bit=not args.no_4bit,
        )

    # 运行探测
    all_results = {}
    model_id = args.ollama_model or args.model_id
    if args.adapter_path:
        model_id += f" + {args.adapter_path}"

    print(f"\n开始探测 {len(all_cwes)} 个 CWE（模型: {model_id}）...\n")

    for i, cwe in enumerate(all_cwes):
        print(f"[{i+1}/{len(all_cwes)}] 探测 {cwe}...", flush=True)
        result = run_probe(
            cwe=cwe,
            knowledge_entries=knowledge,
            manifest_records=manifest_records,
            model=model,
            tokenizer=tokenizer,
            ollama_model=args.ollama_model,
        )
        all_results[cwe] = result
        print(f"  → {result['overall']} "
              f"(概念:{result['concept_level']} "
              f"推理:{result['reasoning_level']} "
              f"归因:{result['attribution_level']})")

    # 生成报告
    report = generate_probe_report(all_results, model_id, backend, args.output)

    # 卸载模型
    if args.ollama_model:
        from graduation_project.llm_client import OllamaClient
        client = OllamaClient(model=args.ollama_model)
        client.unload()
        print("Ollama 模型已卸载")
    elif model is not None:
        import torch
        del model, tokenizer
        torch.cuda.empty_cache()
        print("模型已卸载，GPU 显存已释放")


if __name__ == "__main__":
    main()
