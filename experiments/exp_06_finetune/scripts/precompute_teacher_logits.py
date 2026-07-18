"""
Phase 4 - Prompt Distillation 预计算 teacher logits 脚本。

对应 docs/方法.md §9 Phase 4，论文 Prompt Distillation (TMLR 2025)。

原理：
  Teacher = Qwen-Coder-Instruct + CWE 规则 context（输入看完整规则）
  Student = Qwen-Coder-Instruct + LoRA（输入只看代码，无规则）

  训练 Student 模仿 Teacher 的 token 分布（logits），而非硬标签。
  这样 Student 学会"内部化"规则，推理时不需要检索。

工程实现：
  Teacher 和 Student 同时加载会显存翻倍（7B×2 + 激活值 > 16GB，OOM）
  所以预计算 Teacher logits 到磁盘，训练时只加载 Student。

  为了节省磁盘，只存 top-K logits（K=50 transformers / K=20 ollama）：
  - transformers: 每个样本约 200 tokens × 50 top-K × 8 bytes ≈ 80 KB
  - ollama: 每个样本约 200 tokens × 20 top-K × 8 bytes ≈ 32 KB
  - 823 样本 ≈ 26-64 MB（可接受）

两种后端：
  1. transformers（默认）：直接加载模型做 forward，得到 teacher forcing logits
     - teacher 看 prompt + answer，返回 answer 部分每个位置 top-K
     - 优点：完整 top-K（K=50），token id 与 student 完全对齐
     - 缺点：teacher 占 GPU 显存（7B 4bit≈8GB，14B 4bit≈11GB，30B OOM）
     - 推荐：Qwen2.5-Coder-7B-Instruct 或 14B-Instruct

  2. ollama：通过 Ollama API 调用，借助 llama.cpp 的 MoE offload
     - teacher 看 prompt（CWE + question），自己生成 answer + top-K logprobs
     - 优点：teacher 完全不占训练显存，可用 Qwen3-Coder-30B MoE（你已验证快）
     - 优点：on-policy 蒸馏（TMLR 2025 推荐，减少 exposure bias）
     - 限制：top_logprobs 上限 20（Ollama v0.21.1+）
     - 限制：需手动起 Ollama 服务并拉模型

输出：
  data/teacher_logits/
    sample_0001.pt   - {indices: [N, K], values: [N, K], answer_start: int, ...}
    sample_0002.pt
    ...
  data/teacher_logits_index.json   - 索引（sample_id → file）

用法：
  # transformers 后端（默认，7B 4bit QLoRA teacher）
  HF_HUB_OFFLINE=1 /home/zane/miniconda3/envs/AI/bin/python precompute_teacher_logits.py \\
      --train-file data/train_chatml_v2.jsonl \\
      --top-k 50

  # transformers 后端 + 14B teacher（更高质量，仍安全）
  HF_HUB_OFFLINE=1 /home/zane/miniconda3/envs/AI/bin/python precompute_teacher_logits.py \\
      --model Qwen/Qwen2.5-Coder-14B-Instruct --top-k 50

  # ollama 后端 + Qwen3-Coder-30B MoE teacher（推荐，最强）
  # 前置：ollama serve & ollama pull qwen3-coder:30b
  /home/zane/miniconda3/envs/AI/bin/python precompute_teacher_logits.py \\
      --backend ollama \\
      --ollama-model qwen3-coder:30b \\
      --top-k 20

注意：
  - transformers 后端：只做前向，无需训练，4bit 加载即可
  - ollama 后端：on-policy 蒸馏，teacher 自己生成 answer（与训练数据可能不一致）
"""

import argparse
import json
import math
import os
import sys
from pathlib import Path

os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0")
os.environ.setdefault("HIP_VISIBLE_DEVICES", "0")
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import requests
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"
OUTPUT_DIR = DATA_DIR / "teacher_logits"

INSTRUCT_MODEL_ID = "Qwen/Qwen2.5-Coder-7B-Instruct"

# CWE 规则 context（注入到 teacher 的 system prompt）
# 后续可扩展为按漏洞类型动态选择规则
DEFAULT_CWE_CONTEXT = """你是一名资深的代码安全审计专家。参考以下漏洞检测规则：

 CWE-89 SQL注入: 用户输入拼接到SQL语句，未参数化。
 CWE-79 XSS: 用户输入输出到HTML，未转义。
 CWE-78 命令注入: 用户输入传入shell执行，未用列表形式或shlex.quote。
 CWE-22 路径穿越: 用户输入拼接到文件路径，未用os.path.realpath校验。
 CWE-502 反序列化: pickle/yaml.load加载不可信数据。
 CWE-798 硬编码凭据: 代码中硬编码密码/Token/密钥。
 CWE-209 信息泄露: 错误信息暴露内部细节。
 CWE-117 日志注入: 用户输入写入日志未过滤换行符。
 CWE-327 弱密码学: 使用MD5/SHA1哈希密码。
 CWE-330 弱随机数: 用random模块生成token。
 CWE-94 SSTI: 用户输入作为模板渲染。
 CWE-918 SSRF: 用户输入作为URL请求。
 CWE-352 CSRF: 缺少CSRF token校验。
 CWE-862 缺失授权: 未校验用户权限。
 CWE-287 缺失认证: 关键操作未校验登录。
 CWE-611 XXE: XML解析未禁用外部实体。
 CWE-1333 ReDoS: 正则表达式存在灾难性回溯。

重要约束：
1. 只分析与代码实际内容相关的漏洞类型，不要逐个检查所有CWE。
2. 推理过程控制在5步以内：污染源→数据流→防御检查→漏洞类型→CWE编号。
3. 如果代码安全（有有效防御），推理过程说明防御措施，然后JSON标has_vulnerability=false。
4. JSON输出格式严格如下（用```json包裹）：
```json
{
  "has_vulnerability": true或false,
  "vulnerabilities": [{"cwe_id": "CWE-XXX", "type": "漏洞类型", "description": "简述"}]
}
```
安全样本vulnerabilities为空数组。"""


def parse_args():
    p = argparse.ArgumentParser(description="预计算 teacher logits")
    p.add_argument("--backend", type=str, default="transformers",
                   choices=["transformers", "ollama"],
                   help="后端：transformers（默认，GPU 占显存）或 ollama（API 调用，0 显存）")
    p.add_argument("--train-file", type=Path, default=DATA_DIR / "train_chatml_v2.jsonl",
                   help="训练数据（ChatML 格式）")
    p.add_argument("--cwe-rules", type=str, default=None,
                   help="CWE 规则文本（默认用内置规则）")
    # transformers 后端参数
    p.add_argument("--model", type=str, default=INSTRUCT_MODEL_ID,
                   help="transformers 后端：teacher 模型 ID")
    # ollama 后端参数
    p.add_argument("--ollama-url", type=str, default="http://localhost:11434",
                   help="ollama 后端：Ollama 服务地址")
    p.add_argument("--ollama-model", type=str, default="qwen2.5-coder:7b",
                   help="ollama 后端：Ollama 模型名（如 qwen3-coder:30b、qwen2.5-coder:14b）")
    p.add_argument("--ollama-keepalive", type=int, default=300,
                   help="ollama 后端：模型驻留秒数（5min 默认，遵循项目约定，避免永久占 GPU）")
    p.add_argument("--ollama-max-tokens", type=int, default=1024,
                   help="ollama 后端：每个样本最多生成 token 数")
    p.add_argument("--student-tokenizer", type=str, default=INSTRUCT_MODEL_ID,
                   help="ollama 后端：student tokenizer（用于把 teacher token 转 student token id）")
    # 通用参数
    p.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    p.add_argument("--top-k", type=int, default=50,
                   help="每个 token 只保留 top-K logits（ollama 后端上限 20）")
    p.add_argument("--max-seq-length", type=int, default=2048)
    p.add_argument("--limit", type=int, default=0,
                   help="只处理前 N 个样本（0=全部，调试用）")
    p.add_argument("--resume", action="store_true",
                   help="断点续跑：跳过已存在的 sample_*.pt 文件")
    p.add_argument("--dtype", type=str, default="fp16", choices=["fp16", "fp32"])
    return p.parse_args()


def load_chatml(path: Path, limit: int = 0) -> list[dict]:
    """加载 ChatML 训练数据，提取 (question, answer) pairs。"""
    samples = []
    with open(path, "r", encoding="utf-8") as fp:
        for i, line in enumerate(fp):
            if limit and i >= limit:
                break
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                msgs = rec.get("messages", [])
                # 提取 user content 作为 question，assistant content 作为 answer
                user_msg = next((m for m in msgs if m.get("role") == "user"), None)
                asst_msg = next((m for m in msgs if m.get("role") == "assistant"), None)
                if user_msg and asst_msg:
                    samples.append({
                        "question": user_msg["content"],
                        "answer": asst_msg["content"],
                        "sample_id": len(samples),
                    })
            except json.JSONDecodeError:
                continue
    return samples


def build_teacher_input(question: str, cwe_context: str) -> str:
    """构造 teacher 输入：CWE 规则 + 用户问题。"""
    return f"{cwe_context}\n\n用户问题：\n{question}"


# ============================================================================
# Ollama 后端函数
# ============================================================================

def unload_ollama_model(ollama_url: str, model: str) -> None:
    """Ollama 卸载模型（keep_alive=0），遵循项目约定。"""
    try:
        requests.post(
            f"{ollama_url}/api/generate",
            json={"model": model, "keep_alive": 0},
            timeout=60,
        )
        print(f"✅ Ollama 模型 {model} 已卸载（keep_alive=0）")
    except Exception as e:
        print(f"⚠️ unload_ollama_model 失败（可忽略）: {e}")


def check_ollama_available(ollama_url: str, model: str) -> bool:
    """检查 Ollama 服务可用 + 模型已拉取。"""
    try:
        r = requests.get(f"{ollama_url}/api/tags", timeout=10)
        r.raise_for_status()
        models = [m.get("name", "") for m in r.json().get("models", [])]
        # 模型名匹配：qwen3-coder:30b 也匹配 qwen3-coder:30b-q4_K_M
        if not any(model.split(":")[0] in m for m in models):
            print(f"❌ Ollama 未找到模型 {model}")
            print(f"   已安装模型: {models}")
            print(f"   请先运行: ollama pull {model}")
            return False
        return True
    except requests.exceptions.ConnectionError:
        print(f"❌ 无法连接 Ollama 服务: {ollama_url}")
        print(f"   请先启动: ollama serve")
        return False
    except Exception as e:
        print(f"❌ Ollama 检查失败: {e}")
        return False


def ollama_chat_with_logprobs_stream(
    ollama_url: str,
    model: str,
    messages: list,
    top_logprobs: int,
    keep_alive: int = 300,
    max_tokens: int = 1024,
    timeout: int = 600,
) -> tuple[list[str], list[list[tuple[str, float]]]]:
    """流式调用 Ollama /api/chat，收集 teacher 生成 token + top-K logprobs。

    返回:
        tokens: List[str] - teacher 生成的 token 字符串序列
        topk_per_position: List[List[Tuple[str, float]]] - 每位置 top-K 候选 (token_str, prob)
    """
    # Ollama 限制 top_logprobs 上限 20
    top_logprobs = min(top_logprobs, 20)

    response = requests.post(
        f"{ollama_url}/api/chat",
        json={
            "model": model,
            "messages": messages,
            "stream": True,
            "logprobs": True,
            "top_logprobs": top_logprobs,
            "options": {
                "keep_alive": f"{keep_alive}s",
                "temperature": 0.0,  # greedy，蒸馏需确定性
                "num_predict": max_tokens,
                "top_p": 1.0,
                "seed": 42,
            },
        },
        stream=True,
        timeout=timeout,
    )
    response.raise_for_status()

    tokens = []
    topk_per_position = []

    for line in response.iter_lines():
        if not line:
            continue
        try:
            chunk = json.loads(line.decode("utf-8"))
        except json.JSONDecodeError:
            continue

        if chunk.get("done"):
            break

        msg = chunk.get("message", {})
        content = msg.get("content", "")
        logprobs_list = chunk.get("logprobs") or []

        if logprobs_list:
            for lp in logprobs_list:
                token_str = lp.get("token", content)
                # Ollama API 返回字段是 "logprob"（不是 "prob"），值本身就是 logprob
                top_lps = lp.get("top_logprobs", [])
                topk = [(t.get("token", ""), t.get("logprob", -1e4)) for t in top_lps]
                tokens.append(token_str)
                topk_per_position.append(topk)
        elif content:
            # 没 logprobs 但有 content（向后兼容旧版 Ollama）
            tokens.append(content)
            topk_per_position.append([])

    return tokens, topk_per_position


def tokens_to_student_ids(
    tokens: list[str],
    topk_per_position: list[list[tuple[str, float]]],
    tokenizer,
) -> tuple[torch.Tensor, torch.Tensor, list[str]]:
    """把 Ollama 返回的 token string 序列转成 student tokenizer 的 token id。

    返回:
        indices: Tensor[N, K] - top-K 候选的 student token id
        values: Tensor[N, K] - top-K 候选的 log(prob)
        teacher_answer_tokens: List[str] - 原 teacher token string（debug 用）
    """
    indices_list = []
    values_list = []
    teacher_answer_tokens = []

    unk_id = tokenizer.unk_token_id or 0

    for token_str, topk in zip(tokens, topk_per_position):
        teacher_answer_tokens.append(token_str)

        # 把 token string 转 student token id（用 student tokenizer encode）
        # Qwen2.5 系列内部一致；若 teacher 是 Qwen3 可能轻微不对齐
        topk_ids = []
        topk_logprobs = []
        for cand_str, cand_logprob in topk:
            ids = tokenizer.encode(cand_str, add_special_tokens=False)
            if len(ids) == 1:
                topk_ids.append(ids[0])
            else:
                # token 边界不一致，用 unk 占位（KL loss 会忽略）
                topk_ids.append(unk_id)
            # Ollama 返回的就是 logprob，直接用
            topk_logprobs.append(float(cand_logprob))

        # 如果 topk 为空（旧版 Ollama 无 logprobs），至少存主 token
        if not topk_ids:
            ids = tokenizer.encode(token_str, add_special_tokens=False)
            main_id = ids[0] if ids else unk_id
            topk_ids = [main_id]
            topk_logprobs = [0.0]

        indices_list.append(topk_ids)
        values_list.append(topk_logprobs)

    # 转 tensor（padding 到统一 K）
    if not indices_list:
        return torch.zeros((0, 1), dtype=torch.int), torch.zeros((0, 1), dtype=torch.float16), []

    max_k = max(len(x) for x in indices_list)
    n = len(indices_list)
    indices = torch.full((n, max_k), unk_id, dtype=torch.int)
    # fp16 范围 ±65504，-1e4 已足够小（softmax 后概率 ≈ 0），且不会溢出
    values = torch.full((n, max_k), -1e4, dtype=torch.float16)

    for i, (ids, vals) in enumerate(zip(indices_list, values_list)):
        for j, (tid, val) in enumerate(zip(ids, vals)):
            indices[i, j] = tid
            values[i, j] = val

    return indices, values, teacher_answer_tokens


# ============================================================================
# transformers 后端函数
# ============================================================================

def run_transformers_backend(args, samples: list[dict], cwe_context: str) -> list[dict]:
    """transformers 后端：直接加载模型做 forward。"""
    print(f"\n加载 tokenizer: {args.model}")
    tokenizer = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # 4bit 加载（teacher 只前向，4bit 足够）
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,
    )

    print(f"加载 teacher 模型 (4bit): {args.model}")
    model = AutoModelForCausalLM.from_pretrained(
        args.model,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True,
    )
    model.eval()

    # 显存预估
    vram_alloc = torch.cuda.memory_allocated() / 1e9 if torch.cuda.is_available() else 0
    print(f"模型加载后 GPU 占用: {vram_alloc:.2f} GB")
    if vram_alloc > 14:
        print(f"⚠️  显存超过 14GB，前向时可能 OOM（logits 临时张量 ~2GB）")

    index = []
    print(f"\n开始预计算（transformers 后端）...")
    for i, sample in enumerate(samples):
        full_input = build_teacher_input(sample["question"], cwe_context)
        full_input_with_answer = full_input + "\n\n### 标准答案\n" + sample["answer"]

        inputs = tokenizer(
            full_input_with_answer,
            truncation=True,
            max_length=args.max_seq_length,
            return_tensors="pt",
        ).to(model.device)

        prompt_only = tokenizer(full_input, truncation=True,
                                max_length=args.max_seq_length, return_tensors="pt")
        answer_start = prompt_only["input_ids"].shape[1]

        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits[0]

        answer_logits = logits[answer_start:]
        topk_values, topk_indices = torch.topk(answer_logits.float(), k=args.top_k, dim=-1)
        topk_values = topk_values.half().cpu()
        topk_indices = topk_indices.int().cpu()

        out_path = args.output_dir / f"sample_{i:04d}.pt"
        torch.save({
            "indices": topk_indices,
            "values": topk_values,
            "answer_start": answer_start,
            "sample_id": i,
            "backend": "transformers",
            "teacher_model": args.model,
        }, out_path)

        try:
            file_rel = str(out_path.resolve().relative_to(PROJECT_ROOT))
        except ValueError:
            file_rel = str(out_path)
        index.append({
            "sample_id": i,
            "file": file_rel,
            "answer_len": int(topk_indices.shape[0]),
        })

        if (i + 1) % 50 == 0 or (i + 1) == len(samples):
            print(f"  [{i+1}/{len(samples)}] {out_path.name} answer_len={topk_indices.shape[0]}")

    # transformers 后端用完后 unload（遵循项目约定）
    del model
    torch.cuda.empty_cache()
    print(f"✅ transformers 模型已从 GPU 卸载")

    return index


def run_ollama_backend(args, samples: list[dict], cwe_context: str) -> list[dict]:
    """Ollama 后端：通过 API 调用，借助 MoE offload 用更大 teacher。"""
    if not check_ollama_available(args.ollama_url, args.ollama_model):
        sys.exit(1)

    print(f"\n加载 student tokenizer: {args.student_tokenizer}")
    tokenizer = AutoTokenizer.from_pretrained(args.student_tokenizer, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # Ollama 后端：top-k 上限 20
    if args.top_k > 20:
        print(f"⚠️  Ollama 后端 top-k 上限 20，已从 {args.top_k} 调整为 20")
        args.top_k = 20

    print(f"\n开始预计算（ollama 后端）...")
    print(f"  Teacher: {args.ollama_model}")
    print(f"  Student tokenizer: {args.student_tokenizer}")
    print(f"  估计耗时: {len(samples) * 5 / 60:.1f} min（按 5s/样本）")

    index = []
    skipped = 0
    for i, sample in enumerate(samples):
        # 断点续跑：跳过已存在的文件
        out_path = args.output_dir / f"sample_{i:04d}.pt"
        if args.resume and out_path.exists():
            # 加载已有文件，只重建 index 条目
            existing = torch.load(out_path, map_location="cpu", weights_only=False)
            try:
                file_rel = str(out_path.resolve().relative_to(PROJECT_ROOT))
            except ValueError:
                file_rel = str(out_path)
            index.append({
                "sample_id": i,
                "file": file_rel,
                "answer_len": int(existing["indices"].shape[0]),
                "teacher_answer_preview": existing.get("teacher_answer", "")[:80] + "...",
            })
            skipped += 1
            if skipped <= 3 or (i + 1) % 50 == 0:
                print(f"  [{i+1}/{len(samples)}] ⏭️  已存在，跳过 {out_path.name}")
            continue

        # Ollama 模式：on-policy 蒸馏
        # teacher 看 prompt（CWE + question），自己生成 answer + top-K logprobs
        messages = [
            {"role": "system", "content": cwe_context + "\n\n请按标准格式回答。"},
            {"role": "user", "content": sample["question"]},
        ]

        try:
            tokens, topk_per_position = ollama_chat_with_logprobs_stream(
                ollama_url=args.ollama_url,
                model=args.ollama_model,
                messages=messages,
                top_logprobs=args.top_k,
                keep_alive=args.ollama_keepalive,
                max_tokens=args.ollama_max_tokens,
            )
        except requests.exceptions.RequestException as e:
            print(f"  [{i+1}/{len(samples)}] ❌ API 调用失败: {e}")
            continue

        if not tokens:
            print(f"  [{i+1}/{len(samples)}] ⚠️  空响应，跳过")
            continue

        # 把 teacher token string 转 student token id
        indices, values, teacher_tokens = tokens_to_student_ids(
            tokens, topk_per_position, tokenizer
        )

        # 检查对齐情况
        n_unk = sum(1 for tid_row in indices for tid in tid_row if tid == (tokenizer.unk_token_id or 0))
        n_total = indices.numel()
        unk_ratio = n_unk / max(n_total, 1)
        if unk_ratio > 0.2:
            print(f"  [{i+1}/{len(samples)}] ⚠️  token 对齐率低（unk={unk_ratio*100:.1f}%）"
                  f"，teacher 可能与 student tokenizer 不兼容")

        out_path = args.output_dir / f"sample_{i:04d}.pt"
        torch.save({
            "indices": indices,             # [N, K] student token id
            "values": values,              # [N, K] log(prob)
            "answer_start": 0,              # Ollama 模式全是生成 token
            "sample_id": i,
            "backend": "ollama",
            "teacher_model": args.ollama_model,
            "teacher_answer": "".join(teacher_tokens),  # 完整 answer 字符串
            "teacher_tokens": teacher_tokens,            # token string 序列（debug）
            "on_policy": True,                              # 标记为 on-policy 蒸馏
        }, out_path)

        # 兼容相对路径：转绝对路径后再 relative_to
        try:
            file_rel = str(out_path.resolve().relative_to(PROJECT_ROOT))
        except ValueError:
            file_rel = str(out_path)
        index.append({
            "sample_id": i,
            "file": file_rel,
            "answer_len": int(indices.shape[0]),
            "teacher_answer_preview": "".join(teacher_tokens)[:80] + "...",
        })

        if (i + 1) % 10 == 0 or (i + 1) == len(samples):
            print(f"  [{i+1}/{len(samples)}] {out_path.name} "
                  f"tokens={indices.shape[0]} K={indices.shape[1]} unk={unk_ratio*100:.1f}%")

    # 卸载 Ollama 模型（遵循项目约定，避免永久占 GPU）
    unload_ollama_model(args.ollama_url, args.ollama_model)

    if skipped:
        print(f"  断点续跑：跳过 {skipped} 个已有样本，新计算 {len(index) - skipped} 个")

    return index


def main():
    args = parse_args()

    print("=" * 60)
    print("Prompt Distillation - Teacher Logits 预计算")
    print("=" * 60)
    print(f"后端: {args.backend}")
    if args.backend == "transformers":
        print(f"Teacher 模型: {args.model}")
    else:
        print(f"Ollama 模型: {args.ollama_model}")
        print(f"Ollama URL: {args.ollama_url}")
    print(f"训练数据: {args.train_file}")
    print(f"Top-K: {args.top_k}")
    print(f"输出: {args.output_dir}")

    if not args.train_file.exists():
        print(f"\n❌ 训练数据不存在: {args.train_file}")
        sys.exit(1)

    args.output_dir.mkdir(parents=True, exist_ok=True)

    # 加载样本
    samples = load_chatml(args.train_file, limit=args.limit)
    print(f"加载 {len(samples)} 个样本")

    cwe_context = args.cwe_rules or DEFAULT_CWE_CONTEXT

    # 根据 backend 选择后端
    if args.backend == "ollama":
        index = run_ollama_backend(args, samples, cwe_context)
    else:
        index = run_transformers_backend(args, samples, cwe_context)

    # 写索引
    index_path = args.output_dir / "index.json"
    with open(index_path, "w", encoding="utf-8") as fp:
        json.dump({
            "backend": args.backend,
            "model": args.ollama_model if args.backend == "ollama" else args.model,
            "top_k": args.top_k,
            "total_samples": len(samples),
            "samples": index,
        }, fp, ensure_ascii=False, indent=2)

    print(f"\n✅ 预计算完成")
    print(f"   后端: {args.backend}")
    print(f"   索引: {index_path}")
    print(f"   样本数: {len(samples)}")
    print(f"\n下一步：运行 train_prompt_distillation.py 训 student")
    print(f"  HF_HUB_OFFLINE=1 /home/zane/miniconda3/envs/AI/bin/python train_prompt_distillation.py \\")
    print(f"      --teacher-logits {args.output_dir}")


if __name__ == "__main__":
    main()
