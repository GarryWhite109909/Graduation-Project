"""
Transformers 进程内推理客户端 —— Q4 基座（bitsandbytes NF4）+ FP16 LoRA。

背景：Ollama 发布版是把 base+LoRA 合并后整体压进 GGUF Q4_K_M，训练得到的
LoRA 信号被一并重量化，导致 20 真实召回从 95%（全精度 LoRA）跌到 79%。
本客户端复现 evaluate.py 95% 那套加载方式：
    AutoModelForCausalLM + BitsAndBytesConfig(load_in_4bit, nf4) + PeftModel(FP16 LoRA)
保证 LoRA 增量保持 FP16 精度，只压基座。

接口与 OllamaClient / VLLMClient 对齐（generate / generate_structured /
check_connection / list_models / unload_model / model），便于 Scanner 无缝切换。

使用约定（环境变量）：
    VULN_SCANNER_MODEL_ID   基座模型（默认 Qwen/Qwen3-8B）
    VULN_SCANNER_ADAPTER    LoRA adapter 目录（必填，含 adapter_model.safetensors）
    VULN_SCANNER_NUM_CTX    上下文长度（默认 6144，用户指定）
    VULN_SCANNER_QUANTIZE   是否 NF4 4bit 量化基座（默认 1）
    VULN_SCANNER_FLASH_ATTN 是否优先 flash_attention_2（默认 1；不可用时自动回退 sdpa）
    VULN_SCANNER_COMPUTE_DTYPE 基座计算精度：fp16 / bf16（默认按平台自动：ROCm→bf16，NVIDIA→fp16）
    VULN_SCANNER_COMPILE    是否 torch.compile 加速 decode（默认 auto：NVIDIA 开、ROCm 关；设 0/1 强制覆盖）

性能说明：单条自回归解码是显存带宽瓶颈（GPU 计算单元等权重读取，故功耗上不去）。
要真正吃满功耗，用 generate_batch 把多个 chunk 拼成 batch 一次解码（见本文件与 scanner）。

注意：模型进程内常驻、显存占用高（Q4 基座 ~4.5GB + KV cache@6144 + 激活 ≈ 6-7GB）。
本客户端只负责推理；模型管理（拉取/删除/切换）仍走 Ollama，见 app/backend/main.py。
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Union

# 延迟导入重型依赖（torch/transformers/peft/bitsandbytes），仅在真正加载模型时才 import，
# 避免未安装 transformers 的环境 import 本模块即报错。
_TORCH = None
_TF = None
_PEFT = None


def _lazy_import_torch():
    global _TORCH
    if _TORCH is None:
        import torch
        _TORCH = torch
    return _TORCH


def _lazy_import_transformers():
    global _TF
    if _TF is None:
        from transformers import (
            AutoModelForCausalLM,
            AutoTokenizer,
            BitsAndBytesConfig,
        )
        _TF = {
            "AutoModelForCausalLM": AutoModelForCausalLM,
            "AutoTokenizer": AutoTokenizer,
            "BitsAndBytesConfig": BitsAndBytesConfig,
        }
    return _TF


def _lazy_import_peft():
    global _PEFT
    if _PEFT is None:
        from peft import PeftModel
        _PEFT = {"PeftModel": PeftModel}
    return _PEFT


# 统一输出 schema 的约束描述（与 scanner 的 CoT+JSON 模式一致；transformers 无 guided
# decoding，结构化兜底靠模型训练时学会的 JSON 输出 + 解析层 parse_verdict 容错）。
# 复用 graduation_project.prompts 的 build_user_prompt 组装 user prompt。
from graduation_project.prompts import build_user_prompt
from graduation_project.schema import parse_verdict, normalize_has_vulnerability


class TransformersClient:
    """transformers 进程内推理客户端（NF4 基座 + FP16 LoRA）。

    模型在首次调用时懒加载并常驻显存（进程内全局单例由调用方 Scanner 持有）。
    线程安全：用 _gen_lock 串行化 generate，避免并发 generate 竞争 CUDA。

    Args:
        model_id:   基座模型（HuggingFace 名或本地路径）
        adapter:    LoRA adapter 目录（含 adapter_model.safetensors / adapter_config.json）
        num_ctx:    上下文长度（用于截断输入，保证不超过 max_model_len）
        quantize:   是否用 bitsandbytes NF4 4bit 量化基座
        flash_attn: 是否优先 flash_attention_2（不可用自动回退 sdpa）
        compile:    是否 torch.compile 加速 decode
    """

    def __init__(
        self,
        model_id: str = "",
        adapter: str = "",
        num_ctx: int = 6144,
        quantize: bool = True,
        flash_attn: bool = True,
        compile_: bool = False,
    ):
        self.model_id = model_id or os.environ.get("VULN_SCANNER_MODEL_ID", "Qwen/Qwen3-8B")
        self.adapter = adapter or os.environ.get("VULN_SCANNER_ADAPTER", "")
        self.num_ctx = int(os.environ.get("VULN_SCANNER_NUM_CTX", str(num_ctx)))
        self.quantize = quantize if not os.environ.get("VULN_SCANNER_QUANTIZE") else (
            os.environ.get("VULN_SCANNER_QUANTIZE", "1") != "0"
        )
        self.flash_attn = flash_attn if not os.environ.get("VULN_SCANNER_FLASH_ATTN") else (
            os.environ.get("VULN_SCANNER_FLASH_ATTN", "1") != "0"
        )
        # 计算精度：fp16 / bf16。默认按平台在 load_model 里自动决定（ROCm→bf16，NVIDIA→fp16）。
        self.compute_dtype = os.environ.get("VULN_SCANNER_COMPUTE_DTYPE", "").strip().lower()
        # compile 请求：None=auto（NVIDIA 开、ROCm 关）；显式 "0"/"1" 强制覆盖。
        _compile_env = os.environ.get("VULN_SCANNER_COMPILE")
        self.compile_requested = None
        if _compile_env is not None:
            self.compile_requested = _compile_env.strip() != "0"
        elif compile_:
            self.compile_requested = True
        # 与 OllamaClient/VLLMClient 的 model 字段语义对齐（供 Scanner/model_registry 读取）
        self.model = self.model_id
        self._model = None  # 懒加载
        self._tokenizer = None
        self._gen_lock = threading.Lock()
        self._load_error: Optional[str] = None

    # ------------------------------------------------------------------
    # 加载与生命周期
    # ------------------------------------------------------------------
    def _check_adapter(self) -> Optional[str]:
        """校验 adapter 路径存在且含权重。返回错误信息或 None。"""
        if not self.adapter:
            return "VULN_SCANNER_ADAPTER 未设置：需要 LoRA adapter 目录"
        p = Path(self.adapter)
        if not p.is_dir():
            return f"LoRA adapter 路径不存在: {self.adapter}"
        # 兼容不同权重文件名（adapter_model.safetensors / adapter_model.bin / adapter_model.gguf）
        has_weights = any(
            (p / name).exists()
            for name in ("adapter_model.safetensors", "adapter_model.bin", "adapter_model.gguf")
        )
        if not has_weights:
            return f"LoRA adapter 目录缺少权重文件: {self.adapter}"
        return None

    def load_model(self) -> bool:
        """加载模型 + tokenizer（幂等，仅首次真正加载）。

        Returns:
            True 加载成功；False 失败（错误信息存 self._load_error）。
        """
        if self._model is not None:
            return True
        if self._load_error:
            return False

        err = self._check_adapter()
        if err:
            self._load_error = err
            print(f"[TransformersClient] 加载失败: {err}")
            return False

        torch = _lazy_import_torch()
        tf = _lazy_import_transformers()
        peft = _lazy_import_peft()

        try:
            is_rocm = bool(getattr(torch.version, "hip", None))

            # 计算精度：默认 ROCm→bf16（fp16 在部分 CDNA 卡上慢），NVIDIA→fp16（消费级 2x 速率）。
            compute_dtype_str = self.compute_dtype or ("bf16" if is_rocm else "fp16")
            dtype = torch.bfloat16 if compute_dtype_str == "bf16" else torch.float16

            print(f"[TransformersClient] 加载 tokenizer: {self.model_id}")
            tokenizer = tf["AutoTokenizer"].from_pretrained(
                self.model_id, trust_remote_code=True
            )
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token

            # 注意力后端：真正的可用性探测（原实现 try 内不抛异常，等于永远宣称用 flash，需修复）
            #   - ROCm：flash_attention_2 需 hip flash，通常未安装 → 用 sdpa
            #   - NVIDIA：用 transformers 的 is_flash_attn_2_available() 探测
            attn_impl = "sdpa"
            if self.flash_attn and torch.cuda.is_available() and not is_rocm:
                try:
                    from transformers.utils import is_flash_attn_2_available
                    if is_flash_attn_2_available():
                        attn_impl = "flash_attention_2"
                except Exception:
                    attn_impl = "sdpa"

            kwargs: dict = {
                "device_map": {"": 0},
                "trust_remote_code": True,
                "torch_dtype": dtype,
                "attn_implementation": attn_impl,
            }
            if self.quantize:
                kwargs["quantization_config"] = tf["BitsAndBytesConfig"](
                    load_in_4bit=True,
                    bnb_4bit_quant_type="nf4",
                    bnb_4bit_compute_dtype=dtype,
                    bnb_4bit_use_double_quant=True,
                )

            print(f"[TransformersClient] 加载基座 {self.model_id} "
                  f"(quantize={self.quantize}, dtype={compute_dtype_str}, attn={attn_impl})")
            model = tf["AutoModelForCausalLM"].from_pretrained(self.model_id, **kwargs)

            print(f"[TransformersClient] 加载 LoRA adapter: {self.adapter}")
            model = peft["PeftModel"].from_pretrained(model, self.adapter)
            # 合并 LoRA 权重加速推理（保留 FP16 精度，仅量化基座）
            model = model.merge_and_unload()
            print("[TransformersClient] LoRA 已合并")

            # torch.compile：默认 NVIDIA 开（reduce-overhead + CUDA graph 消除每 token 启动开销），
            # ROCm 关（稳定性/编译慢）；VULN_SCANNER_COMPILE=0/1 可强制覆盖。
            do_compile = self.compile_requested
            if do_compile is None:
                do_compile = not is_rocm
            if do_compile:
                try:
                    model = torch.compile(model, mode="reduce-overhead")
                    print("[TransformersClient] 已启用 torch.compile (reduce-overhead)")
                except Exception as e:
                    print(f"[TransformersClient] torch.compile 失败，跳过: {e}")

            model.eval()
            self._model = model
            self._tokenizer = tokenizer
            self._load_error = None
            return True
        except Exception as e:
            self._load_error = f"{type(e).__name__}: {e}"
            print(f"[TransformersClient] 模型加载失败: {self._load_error}")
            return False

    # ------------------------------------------------------------------
    # OllamaClient/VLLMClient 兼容接口
    # ------------------------------------------------------------------
    def check_connection(self) -> bool:
        """模型是否已加载（进程内，无需网络探测）。"""
        return self._model is not None

    def list_models(self) -> List[str]:
        """返回当前模型名（进程内仅一个模型）。"""
        return [self.model] if self._model is not None else []

    def unload_model(self, timeout: int = 60) -> bool:
        """释放模型占用的显存。"""
        torch = _lazy_import_torch()
        if self._model is not None:
            try:
                del self._model
                self._model = None
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
                return True
            except Exception:
                return False
        return True

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = 2048,
        keep_alive=0,
        timeout: int = 300,
        num_ctx: Optional[int] = None,
        num_gpu: Optional[int] = None,
        num_thread: Optional[int] = None,
        think: Optional[bool] = None,
        format: Optional[Union[str, dict]] = None,
    ) -> Dict:
        """生成文本（确定性贪心解码，Qwen3 禁用 thinking）。

        返回结构与 OllamaClient/VLLMClient 一致：
            {"text", "duration", "tokens", "meta", "error"}
        """
        start_time = time.time()
        if not self.load_model():
            return {
                "text": "", "duration": 0.0,
                "tokens": {"prompt": 0, "completion": 0, "total": 0},
                "meta": {}, "error": self._load_error,
            }

        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        with self._gen_lock:
            try:
                text = tokenizer_apply_chat_template(
                    self._tokenizer, messages, enable_thinking=False
                )
                inputs = self._tokenizer(text, return_tensors="pt")
                # 上下文截断：总长度不超过 num_ctx，并给 max_tokens 预留空间
                ctx = num_ctx or self.num_ctx
                max_new = max_tokens if max_tokens is not None else 2048
                max_input = max(1, ctx - max_new)
                if inputs["input_ids"].shape[1] > max_input:
                    inputs["input_ids"] = inputs["input_ids"][:, -max_input:]
                    inputs["attention_mask"] = inputs["attention_mask"][:, -max_input:]

                # 贪心解码为默认；temperature>0 时才启用采样（与 evaluate.py 一致）
                gen_kwargs = {
                    "max_new_tokens": max_new,
                    "do_sample": False,
                    "pad_token_id": self._tokenizer.pad_token_id,
                }
                if temperature and temperature > 0:
                    gen_kwargs["do_sample"] = True
                    gen_kwargs["temperature"] = temperature
                    gen_kwargs["top_p"] = 0.9

                torch = _lazy_import_torch()
                inputs = {k: v.to(self._model.device) for k, v in inputs.items()}
                with torch.no_grad():
                    outputs = self._model.generate(**inputs, **gen_kwargs)

                input_len = inputs["input_ids"].shape[1]
                generated = outputs[0][input_len:]
                response = self._tokenizer.decode(generated, skip_special_tokens=True)
                duration = time.time() - start_time

                return {
                    "text": response,
                    "duration": duration,
                    "tokens": {
                        "prompt": input_len,
                        "completion": int(generated.shape[0]),
                        "total": input_len + int(generated.shape[0]),
                    },
                    "meta": {"backend": "transformers", "model": self.model_id},
                    "error": None,
                }
            except Exception as e:
                return {
                    "text": "",
                    "duration": time.time() - start_time,
                    "tokens": {"prompt": 0, "completion": 0, "total": 0},
                    "meta": {},
                    "error": f"{type(e).__name__}: {e}",
                }

    def generate_batch(
        self,
        prompts: List[str],
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = 2048,
        num_ctx: Optional[int] = None,
    ) -> List[Dict]:
        """批量解码多条 prompt（一次 generate 走完整 batch）。

        核心优化：单条自回归解码是显存带宽瓶颈（GPU 计算单元等权重读取，功耗上不去）。
        把多条 prompt 拼成一个 batch 后，prefill 与 decode 的权重读取被 batch 摊薄，
        算术强度上升 → 真正吃满 GPU。适合 Scanner 一次分析多个 chunk 的场景。

        Args:
            prompts: 多条 user prompt 文本
            system_prompt: 共享 system prompt（None 则只发 user）
            temperature: 采样温度（>0 才启用采样，否则贪心解码）
            max_tokens: 每条最大生成 token 数
            num_ctx: 上下文长度（截断输入，默认 self.num_ctx）

        Returns:
            长度与 prompts 相同的列表，每项结构与 generate 一致
            {"text", "duration", "tokens", "meta", "error"}
        """
        n = len(prompts)
        start_time = time.time()

        def _err_result(msg: str) -> List[Dict]:
            return [
                {
                    "text": "", "duration": time.time() - start_time,
                    "tokens": {"prompt": 0, "completion": 0, "total": 0},
                    "meta": {}, "error": msg,
                }
                for _ in range(n)
            ]

        if n == 0:
            return []
        if not self.load_model():
            return _err_result(self._load_error)

        torch = _lazy_import_torch()
        ctx = num_ctx or self.num_ctx
        max_new = max_tokens if max_tokens is not None else 2048
        max_input = max(1, ctx - max_new)

        # 逐条应用 ChatML 模板（Qwen3 禁用 thinking）
        texts = []
        for p in prompts:
            messages: List[Dict[str, str]] = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": p})
            texts.append(tokenizer_apply_chat_template(
                self._tokenizer, messages, enable_thinking=False
            ))

        batch_error: Optional[str] = None
        with self._gen_lock:
            # decoder-only 批量解码必须左 padding：右 padding 时短序列的"最后
            # 一个 token"是 pad，生成从 pad 位置继续会产生不可靠输出
            old_padding_side = getattr(self._tokenizer, "padding_side", "right")
            if hasattr(self._tokenizer, "padding_side"):
                self._tokenizer.padding_side = "left"
            try:
                # 批量 tokenize：padding 到 batch 内最长，truncation 到 max_input
                enc = self._tokenizer(
                    texts, return_tensors="pt", padding=True,
                    truncation=True, max_length=max_input,
                )
                enc = {k: v.to(self._model.device) for k, v in enc.items()}

                gen_kwargs = {
                    "max_new_tokens": max_new,
                    "do_sample": False,
                    "pad_token_id": self._tokenizer.pad_token_id,
                }
                if temperature and temperature > 0:
                    gen_kwargs["do_sample"] = True
                    gen_kwargs["temperature"] = temperature
                    gen_kwargs["top_p"] = 0.9

                with torch.no_grad():
                    outputs = self._model.generate(**enc, **gen_kwargs)

                padded_len = enc["input_ids"].shape[1]  # batch 内最长输入长度
                eos_id = self._tokenizer.eos_token_id
                results: List[Dict] = []
                for i in range(n):
                    # 每条的真实输入长度（不含 padding）
                    actual_len = int(enc["attention_mask"][i].sum().item())
                    # 从 padded_len 之后取生成区（避开 padding），再按首个 eos 截断
                    row = outputs[i][padded_len:]
                    if eos_id is not None:
                        eos_pos = (row == eos_id).nonzero(as_tuple=True)[0]
                        if len(eos_pos) > 0:
                            row = row[:eos_pos[0]]
                    response = self._tokenizer.decode(row, skip_special_tokens=True)
                    results.append({
                        "text": response,
                        "duration": time.time() - start_time,
                        "tokens": {
                            "prompt": actual_len,
                            "completion": int(row.shape[0]),
                            "total": actual_len + int(row.shape[0]),
                        },
                        "meta": {"backend": "transformers", "model": self.model_id},
                        "error": None,
                    })
                return results
            except Exception as e:
                batch_error = f"{type(e).__name__}: {e}"
            finally:
                if hasattr(self._tokenizer, "padding_side"):
                    self._tokenizer.padding_side = old_padding_side

        if batch_error is not None:
            # 批量失败（如 OOM）逐条回退（锁外执行，self.generate 会重新取锁），
            # 避免整批因单条超长/显存峰值全部报废
            print(f"[TransformersClient] 批量解码失败（{batch_error}），逐条回退")
            return [
                self.generate(
                    prompt=p, system_prompt=system_prompt,
                    temperature=temperature, max_tokens=max_tokens,
                    num_ctx=num_ctx,
                )
                for p in prompts
            ]

    def generate_structured(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = 1024,
        keep_alive=0,
        timeout: int = 300,
        num_ctx: Optional[int] = None,
        num_gpu: Optional[int] = None,
        num_thread: Optional[int] = None,
        think: Optional[bool] = None,
    ) -> Dict:
        """结构化输出兜底。

        transformers 无 guided decoding，此方法退化为普通 generate（模型训练时已学会
        输出 schema 要求的 JSON），由上层 parse_verdict 容错解析。接口与其余 client 对齐。
        注意：与 Ollama format=json 的"数学上保证可解析"不同，本路径不保证——
        首次调用时打印一次警告，监控侧应关注 parse_fail 率。
        """
        if not getattr(self, "_structured_warned", False):
            print("[TransformersClient] 警告: 本后端无约束解码，generate_structured "
                  "退化为普通 generate，解析成功率依赖模型格式遵循")
            self._structured_warned = True
        return self.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            keep_alive=keep_alive,
            timeout=timeout,
            num_ctx=num_ctx,
        )

    def analyze_vulnerability(
        self,
        code: str,
        language: str = "python",
        rag_context: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> Dict:
        """分析代码漏洞（接口与其余 client 对齐，供 standalone 使用）。"""
        prompt = build_user_prompt(
            code=code, language=language, filename=filename, rag_context=rag_context
        )
        return self.generate(prompt, system_prompt=os.environ.get("VULN_SCANNER_SYSTEM_PROMPT"))


def tokenizer_apply_chat_template(tokenizer, messages, enable_thinking=False) -> str:
    """对 messages 应用 ChatML 模板（Qwen3 默认 disable thinking）。"""
    apply = getattr(tokenizer, "apply_chat_template", None)
    if apply is not None:
        try:
            return apply(
                messages, tokenize=False, add_generation_prompt=True,
                enable_thinking=enable_thinking,
            )
        except TypeError:
            return apply(messages, tokenize=False, add_generation_prompt=True)
    # 兜底：手动拼接（无模板时）
    parts = []
    for m in messages:
        role = m["role"]
        content = m["content"]
        if role == "system":
            parts.append(f"<|im_start|>system\n{content}<|im_end|>")
        elif role == "user":
            parts.append(f"<|im_start|>user\n{content}<|im_end|>")
        elif role == "assistant":
            parts.append(f"<|im_start|>assistant\n{content}<|im_end|>")
    parts.append("<|im_start|>assistant\n")
    return "\n".join(parts)


# 兼容工厂：与 create_llm_client 对齐，便于按 backend 名创建
def create_llm_client(backend: str = "transformers", **kwargs):
    """按 backend 名创建客户端。'transformers' 返回 TransformersClient；其余转发。"""
    backend_lower = backend.strip().lower()
    if backend_lower in ("transformers", "hf", "peft"):
        return TransformersClient(**kwargs)
    if backend_lower == "ollama":
        from graduation_project.llm_client import OllamaClient
        return OllamaClient(**kwargs)
    if backend_lower == "vllm":
        from graduation_project.vllm_client import VLLMClient
        return VLLMClient(**kwargs)
    if backend_lower in ("llamacpp", "llama-cpp", "llama_cpp", "gguf"):
        from graduation_project.llamacpp_client import LlamaCppClient
        return LlamaCppClient(**kwargs)
    raise ValueError(f"未知 backend: {backend}，支持 'transformers'/'ollama'/'vllm'/'llamacpp'")


if __name__ == "__main__":
    # 自检：加载 + 推理一条注入漏洞
    client = TransformersClient()
    ok = client.load_model()
    print(f"[自检] 加载成功: {ok}")
    if not ok:
        print(f"[自检] 错误: {client._load_error}")
    else:
        test_code = (
            "import sqlite3\n"
            "def get_user(username):\n"
            "    cur = sqlite3.connect('users.db').cursor()\n"
            "    cur.execute(\"SELECT * FROM users WHERE name='\" + username + \"'\")\n"
        )
        result = client.analyze_vulnerability(test_code, "python")
        print(f"[自检] 耗时: {result['duration']:.2f}s")
        print(f"[自检] error: {result['error']}")
        if not result["error"]:
            verdict = parse_verdict(result["text"])
            print(f"[自检] has_vuln = {normalize_has_vulnerability(verdict.get('has_vulnerability'))}")