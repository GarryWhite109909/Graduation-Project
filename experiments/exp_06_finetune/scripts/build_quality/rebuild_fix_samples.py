#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase B：重建正样本 → 精确行号定位 + 可运行补丁 + 自洽分析。

对 clean_base.jsonl 中的每个正样本（漏洞），用 DeepSeek V4-Flash 重写：
  - source / sink 精确到 `行号 + 具体构造`（如 "line 19: free(data_) 后未置 NULL"）
  - fix_suggestion 为**完整可运行的最小补丁**（```lang 包裹），而非纯文字建议
  - analysis ≤5 步，每步锚定代码中真实行号
  - explanation 保持数据流描述

质量门禁：对 python/js/java 用 FixVerifier 做语法校验 + 危险模式移除检查；
不通过则重试（最多 --max-retries 次），仍不过则丢弃；C/C++ 等无法语法校验的语言
仅做补丁抽取检查（必须含代码块）。

API Key 通过环境变量 DEEPSEEK_API_KEY 传入（不写入文件）。

用法：
  export DEEPSEEK_API_KEY=sk-xxx
  python3 rebuild_fix_samples.py --input data/quality/clean_base.jsonl \
      --output data/quality/positives_rebuilt.jsonl --limit 20   # 先试点
  python3 rebuild_fix_samples.py --input data/quality/clean_base.jsonl \
      --output data/quality/positives_rebuilt.jsonl              # 全量
"""
import argparse
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(PROJECT_ROOT))
from graduation_project.schema import parse_verdict
from graduation_project.fix_verifier import FixVerifier

API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
BASE_URL = "https://api.deepseek.com/v1"
MODEL = "deepseek-v4-flash"
CONCURRENCY = 8
MAX_TOKENS = 8192
TIMEOUT = 90

SYSTEM_PROMPT = """你是一名资深安全研究员，正在为漏洞检测模型精修正样本。给定一段有漏洞的代码，输出一份"精确定位 + 可执行修复"的高质量标准答案。

你必须只输出一个 JSON 对象，用 ```json 包裹，**字段名必须完全一致**，不得增删改名：

```json
{
  "source": "line 19: free(data_) 后未置 NULL，指针悬空",
  "sink": "line 8-9: 析构函数再次 free(data_)",
  "explanation": "line 19 free(data_) 后未置 NULL → 若 line 21 malloc 失败，data_ 仍指向已释放内存 → 析构函数再次 free → 双重释放",
  "fix_code": "修复后的完整代码（纯代码字符串，不含任何 ``` 围栏，换行用 \\n）"
}
```

【字段要求】
1. source / sink 必须**精确到行号 + 具体构造**，如 `line 19: free(data_) 后未置 NULL`。行号必须真实存在于给定代码中。
2. fix_code 是**完整、可运行、最小化**的修复版代码（纯字符串，不要围栏、不要解释）。修复必须能消除该漏洞且不引入新漏洞。
3. explanation 用箭头简明描述数据流/成因。
4. analysis（分析过程）用 1. 2. 3. 编号，≤5 步，每步以"第X行/line X"锚定真实行号，禁止套话，放在 JSON 之前。

【输出格式】
先给分析过程（≤5 步，锚定行号），再输出 ```json 结论块。只输出这两个部分，不要其它文字。"""


def build_user(code: str, lang: str, cwe: str) -> str:
    return (
        f"以下是 {lang} 语言的漏洞代码，漏洞类型为 {cwe}。\n"
        "请给出精确定位到行号的 source/sink、完整可运行的修复补丁，以及 ≤5 步锚定行号的分析。\n"
        "输出要求见 system 提示。\n\n"
        f"```{lang}\n{code}\n```"
    )


def call_deepseek(code: str, lang: str, cwe: str) -> str:
    import openai
    client = openai.OpenAI(api_key=API_KEY, base_url=BASE_URL, timeout=TIMEOUT)
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user(code, lang, cwe)},
        ],
        temperature=0.3,
        max_tokens=MAX_TOKENS,
        extra_body={"reasoning_effort": "none"},  # 关闭推理链，避免 token 全耗在 reasoning 上导致截断
    )
    return resp.choices[0].message.content


def extract_json_block(text: str):
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except Exception:
        return None


def extract_code_and_lang(user_content: str):
    """从 user 消息提取代码和语言。

    兼容两种格式：
      1. ```python\n...```（语言在代码块标记里）
      2. ```\n...```（语言在 user 文本的"语言：xxx"里声明）
    """
    m = re.search(r"```(\w*)\n(.*?)```", user_content, re.DOTALL)
    if not m:
        return None, None
    mark_lang, code = m.group(1), m.group(2)
    if not mark_lang:
        lm = re.search(r"语言[：:]\s*(\w+)", user_content)
        mark_lang = lm.group(1) if lm else "text"
    return mark_lang, code


def rebuild_one(rec: dict, verifier: FixVerifier, max_retries: int) -> dict:
    """返回 {rec, ok, error}。ok=True 表示重建成功且通过门禁。"""
    msgs = rec["messages"]
    lang, code = extract_code_and_lang(msgs[1]["content"])
    if code is None:
        return {"rec": rec, "ok": False, "error": "no_code_in_user"}
    j0 = parse_verdict(msgs[2]["content"])
    cwe = j0.get("vulnerability_type", "CWE-unknown") if j0 else "CWE-unknown"
    risk = j0.get("risk_level", "High") if j0 else "High"

    for attempt in range(max_retries):
        try:
            raw = call_deepseek(code, lang, cwe)
        except Exception as e:
            if attempt == max_retries - 1:
                return {"rec": rec, "ok": False, "error": f"api:{e}"}
            time.sleep(2)
            continue
        j = extract_json_block(raw)
        if j is None:
            if attempt == max_retries - 1:
                return {"rec": rec, "ok": False, "error": "no_json_block"}
            continue
        j["has_vulnerability"] = True
        j["vulnerability_type"] = cwe
        j["risk_level"] = risk
        # fix_code 是纯代码字符串 → 包成 fix_suggestion（```lang 包裹）
        fix_code = str(j.get("fix_code", "")).strip()
        if not fix_code:
            if attempt == max_retries - 1:
                return {"rec": rec, "ok": False, "error": "no_fix_code"}
            continue
        fs = f"```{lang}\n{fix_code}\n```"
        j["fix_suggestion"] = fs
        # 门禁：语法校验 + 危险模式移除
        syntax_ok, err = verifier.verify_syntax(fix_code, lang)
        if not syntax_ok:
            if attempt == max_retries - 1:
                return {"rec": rec, "ok": False, "error": f"syntax:{err}"}
            continue
        tests = verifier.run_test(code, fix_code, lang)
        if tests is False:
            continue
        # 重建 assistant：原分析 + 新 JSON（含可运行补丁）
        new_json = json.dumps({k: v for k, v in j.items() if k != "fix_code"}, ensure_ascii=False)
        analysis = msgs[2]["content"].split("```json")[0].strip()
        new_asst = analysis + "\n```json\n" + new_json + "\n```"
        new_rec = dict(rec)
        new_rec["messages"] = [msgs[0], msgs[1], {"role": "assistant", "content": new_asst}]
        return {"rec": new_rec, "ok": True, "error": None}
    return {"rec": rec, "ok": False, "error": "max_retries"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=str, default="data/quality/clean_base.jsonl")
    parser.add_argument("--output", type=str, default="data/quality/positives_rebuilt.jsonl")
    parser.add_argument("--limit", type=int, default=0, help=">0 时只处理前 N 条（试点）")
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--concurrency", type=int, default=CONCURRENCY)
    args = parser.parse_args()

    if not API_KEY:
        raise SystemExit("缺少 DEEPSEEK_API_KEY 环境变量")

    in_path = Path(args.input)
    recs = [json.loads(l) for l in open(in_path, encoding="utf-8") if l.strip()]
    pos = [r for r in recs if parse_verdict(r["messages"][2]["content"]).get("has_vulnerability") is True]
    print(f"正样本 {len(pos)} 条")
    if args.limit:
        pos = pos[:args.limit]
        print(f"试点模式：只处理前 {args.limit} 条")

    verifier = FixVerifier()
    ok_recs, fail = [], []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = {ex.submit(rebuild_one, r, verifier, args.max_retries): r for r in pos}
        for i, f in enumerate(as_completed(futs), 1):
            res = f.result()
            if res["ok"]:
                ok_recs.append(res["rec"])
            else:
                fail.append((futs[f]["messages"][1]["content"][:40], res["error"]))
            if i % 50 == 0:
                print(f"  进度 {i}/{len(pos)} 通过 {len(ok_recs)} 失败 {len(fail)} 耗时 {time.time()-t0:.0f}s")

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for r in ok_recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"\n重建完成: 通过 {len(ok_recs)} / 失败 {len(fail)}")
    print(f"输出: {out_path}")
    if fail:
        from collections import Counter
        print("失败原因分布:", dict(Counter(e for _, e in fail)))


if __name__ == "__main__":
    main()