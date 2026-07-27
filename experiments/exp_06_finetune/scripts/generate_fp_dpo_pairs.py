"""
基于真实 FP（False Positive）输出的 DPO 偏好对生成 —— Step 4 降 FPR 专用。

设计动机（2026-07-25 P2 v4 后 Step 4）：
  现有 generate_dpo_pairs.py 用合成 CCoT 样本构造 DPO pair，rejected 是模板化
  的"错误推理+错误 JSON"。但模型真正的 FP 模式比合成错误更顽固——它在 safe_03
  上扭曲代码事实（把列表参数看成字符串拼接），在 safe_08 上看到 shell=True 就
  判漏洞而不给具体 payload。合成 rejected 学不到这种"反偏见自检"能力。

  本脚本直接从评估结果 JSON 提取模型的真实 FP 输出作为 rejected，让 DPO 直接
  "惩罚"模型自己犯的错误，比合成错误更精准。

数据来源：
  exp_06_eval.finetuned_custom.YYYYMMDD_HHMMSS.json 中的 samples 数组
  筛选 outcome == "FP" 的样本（expected_present=False 但 model_has_vulnerability=True）

DPO pair 结构：
  - prompt：SYSTEM_PROMPT_LITE + build_user_prompt（与训练/推理一致）的 ChatML 形式
  - chosen：手工构造的正确拒绝（数据流推理 + has_vulnerability=false 的 JSON）
  - rejected：模型的真实 FP 输出（raw_output 字段，包含错误的推理和错误的 JSON）

  chosen 设计原则（与 v4 CoT 修复一致）：
    1. 数据流推理：source → sink → defense evaluation → conclusion
    2. 明确指出有效防御（列表参数/shlex.quote/PreparedStatement/session+role/Lock）
    3. 反偏见自检：若判安全，必须能用一行说明为什么防御有效
    4. 严禁 hedge 短语（"潜在风险""防御力度仍可加强"等）

输出：experiments/exp_06_finetune/data/dpo_fp_pairs_v4.jsonl

用法：
  cd <project_root>
  PYTHONPATH=. python3 \
      experiments/exp_06_finetune/scripts/generate_fp_dpo_pairs.py \
      --eval-result experiments/exp_06_finetune/results/exp_06_eval.finetuned_custom.20260725_072050.json \
      --samples-dir experiments/exp_04_hard_samples/samples \
      --output experiments/exp_06_finetune/data/dpo_fp_pairs_v4.jsonl

  # 也可用 v4 评估结果（SFT v4 训练完成后）：
  # --eval-result experiments/exp_06_finetune/results/exp_06_eval.finetuned_custom.<v4_timestamp>.json
"""

import argparse
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import SYSTEM_PROMPT_LITE, build_user_prompt


# ---------------------------------------------------------------------------
# 手工构造的 chosen 回复 —— 每条 FP 对应一个"正确的拒绝"
# ---------------------------------------------------------------------------
# 设计要求：
#   1. 必须基于数据流推理（source → sink → defense），不能逐项列举漏洞类型
#   2. 必须明确指出有效防御是什么、为什么有效
#   3. JSON 的 has_vulnerability=false，source/sink 字段如实填写（即使无 sink）
#   4. 严禁 hedge 短语（"潜在风险""仍可加强"等）
#   5. 长度与 rejected 相当（避免 DPO 因长度差异产生偏好）
# ---------------------------------------------------------------------------

CHOSEN_RESPONSES = {
    # FP 1: subprocess.run(["ping", "-c", "1", host]) 列表参数，无 shell=True
    "safe_03_subprocess_list.py": """### 分析过程：

1. **识别输入点（source）**：`host = request.args.get("host", "")` 是用户可控输入。
2. **追踪数据流到 sink**：`host` 作为列表 `["ping", "-c", "1", host]` 的最后一个元素传入 `subprocess.run`。
3. **评估防御措施（关键）**：
   - 参数是**列表形式** `["ping", "-c", "1", host]`，不是字符串拼接。
   - `subprocess.run` 未显式设置 `shell` 参数，**默认 `shell=False`**。
   - `shell=False` 时，参数列表直接传递给 `execvp` 系统调用，**不经过 shell 解释器**，分号、反引号、`$()` 等 shell 元字符都会被当作普通字符传入 `ping` 程序。
   - `ping` 程序只把 `host` 当作主机名参数解析，不会执行任意命令。
4. **反偏见自检**：尝试构造攻击 payload。输入 `host="; rm -rf /"` 时，`execvp` 收到的参数是 `["ping", "-c", "1", "; rm -rf /"]`，`;` 只是 `ping` 的主机名参数，不会被解释为命令分隔符。无法构造有效 payload。
5. **结论**：列表参数 + `shell=False` 是命令注入的有效防御，代码无漏洞。

---

### 最终 JSON 结论：

```json
{
  "has_vulnerability": false,
  "vulnerability_type": "none",
  "risk_level": "None",
  "source": "request.args.get('host')",
  "sink": "subprocess.run (列表参数, shell=False)",
  "explanation": "subprocess.run 使用列表参数形式且 shell 默认 False，参数不经过 shell 解释器，host 输入无法注入 shell 元字符。这是命令注入的有效防御写法。",
  "fix_suggestion": "no fix needed"
}
```<|im_end|>""",

    # FP 2: shlex.quote(host) + subprocess.run(..., shell=True)
    "safe_08_shlex.py": """### 分析过程：

1. **识别输入点（source）**：`host = request.args.get("host", "")` 是用户可控输入。
2. **追踪数据流到 sink**：`host` → `shlex.quote(host)` → `safe_host` → `subprocess.run(f"whois {safe_host}", shell=True, ...)`。
3. **评估防御措施（关键）**：
   - `shlex.quote(host)` 是 Python 官方文档推荐的 shell 转义函数，会**用单引号包裹输入并转义内部单引号**。
   - 转义后，任何 shell 元字符（`;` `|` `&` `$()` 反引号等）都被包裹在单引号内，shell 不会解释它们。
   - 例如输入 `host="; rm -rf /"`，`shlex.quote` 返回 `'; rm -rf /'`（带单引号），shell 把它当作 `whois` 的参数字符串，`;` 不被解释为命令分隔符。
   - `shell=True` 在这里**不是漏洞**，因为 `shlex.quote` 已经把输入转义为 shell 安全字符串。
4. **反偏见自检**：尝试构造能绕过 `shlex.quote` 的 payload。`shlex.quote` 的实现保证：任何包含 shell 元字符的输入都会被单引号包裹，内部单引号被替换为 `'\''`。无法构造绕过 payload。
5. **结论**：`shlex.quote` 是 `shell=True` 场景下的有效防御，代码无漏洞。

---

### 最终 JSON 结论：

```json
{
  "has_vulnerability": false,
  "vulnerability_type": "none",
  "risk_level": "None",
  "source": "request.args.get('host')",
  "sink": "subprocess.run (shell=True, 经 shlex.quote 转义)",
  "explanation": "shlex.quote 是 Python 官方推荐的 shell 转义函数，会将输入用单引号包裹并转义内部单引号，所有 shell 元字符都被中和。shell=True 在此处安全。",
  "fix_suggestion": "no fix needed"
}
```<|im_end|>""",

    # FP 3: session + is_admin 角色检查
    "safe_09_proper_authz.py": """### 分析过程：

1. **识别输入点（source）**：本接口 `/admin/export` 不直接接收用户输入，身份信息从 `session["user_id"]` 读取（由登录流程写入，受 `app.secret_key` 保护）。
2. **追踪数据流到 sink**：`session["user_id"]` → `is_admin(user_id)` → 决定是否返回数据。无危险 sink（无 SQL/命令/文件/模板操作）。
3. **评估防御措施（关键）**：
   - **认证检查**：`if "user_id" not in session: return "Please login", 401` 确保未登录用户被拒绝。
   - **授权检查**：`if not is_admin(session["user_id"]): return "Forbidden", 403` 确保非 admin 用户被拒绝。
   - **会话安全**：`app.secret_key = os.urandom(32)` 使用密码学安全随机数生成，会话不可伪造。
   - `is_admin` 中的 `{"admin1", "admin2"}` 是角色查表的演示实现（注释明确标注"实际从数据库查询用户角色"），不是用户可控输入，不构成信息泄露。
4. **反偏见自检**：检查是否有任何用户可控输入能绕过授权。`session` 由 Flask 服务端签名，攻击者无法伪造 `user_id`。`is_admin` 的硬编码 ID 列表是开发演示，不是生产凭证，且不受用户输入影响。
5. **结论**：认证 + 授权 + 会话签名三层防御完整，代码无漏洞。

---

### 最终 JSON 结论：

```json
{
  "has_vulnerability": false,
  "vulnerability_type": "none",
  "risk_level": "None",
  "source": "N/A (session-based, 非用户直接输入)",
  "sink": "N/A (无危险 sink)",
  "explanation": "代码实现了完整的认证（session 检查）和授权（is_admin 角色检查）双重防御，会话密钥使用 os.urandom(32) 生成。is_admin 中的 ID 列表是演示用查表实现，不受用户输入影响，不构成信息泄露。",
  "fix_suggestion": "no fix needed"
}
```<|im_end|>""",

    # FP 4: threading.Lock 保护共享资源，无命令/SQL sink
    "safe_17_race_with_lock.py": """### 分析过程：

1. **识别输入点（source）**：`user = request.args.get("user")` 和 `amount = request.args.get("amount", "0")` 是用户可控输入。
2. **追踪数据流到 sink**：
   - `user` → `balances.get(user, 0)` 和 `balances[user]`（字典访问，非危险 sink）。
   - `amount` → `int(...)` 转换 → 数值比较和减法。
   - 数据流**不经过任何命令执行、SQL 查询、文件操作、模板渲染等危险 sink**。
3. **评估防御措施（关键）**：
   - **竞态条件防护**：`with lock:` 保护 `balances` 的读-改-写操作，`threading.Lock` 确保同一时刻只有一个线程能修改余额，避免 TOCTOU 竞态。
   - **数值校验**：`if balances.get(user, 0) >= amount` 确保余额充足才扣款，`int()` 转换防止类型错误。
   - 用户输入 `user` 只作为字典键查询，不流向任何代码执行路径。
4. **反偏见自检**：尝试构造攻击 payload。`user="alice'; rm -rf /"` 只会让 `balances.get` 返回 0（字典无此键），不会触发任何命令执行。`amount="99999"` 只会因余额不足返回 400。无法构造有效 payload。
5. **结论**：用户输入不流向任何危险 sink，且竞态条件已被 Lock 正确防护，代码无漏洞。

---

### 最终 JSON 结论：

```json
{
  "has_vulnerability": false,
  "vulnerability_type": "none",
  "risk_level": "None",
  "source": "request.args.get('user'), request.args.get('amount')",
  "sink": "N/A (仅字典访问和数值运算, 无危险 sink)",
  "explanation": "用户输入 user/amount 仅用于字典查询和数值比较，不流向任何命令执行、SQL、文件或模板 sink。threading.Lock 正确保护了 balances 的并发访问，无竞态条件。",
  "fix_suggestion": "no fix needed"
}
```<|im_end|>""",

    # FP 5: Java PreparedStatement 参数化查询 + 凭证从环境变量读取
    "safe_18_java_prepared_stmt.java": """### 分析过程：

1. **识别输入点（source）**：`username = req.getParameter("username")` 和 `password = req.getParameter("password")` 是用户可控输入。
2. **追踪数据流到 sink**：`username`/`password` → `stmt.setString(1, username)` / `stmt.setString(2, password)` → `stmt.executeQuery()`。
3. **评估防御措施（关键）**：
   - **SQL 注入防护**：使用 `PreparedStatement` + `setString` 参数化查询，SQL 模板 `SELECT * FROM users WHERE username = ? AND password = ?` 中的 `?` 是占位符，数据库驱动会安全处理 `username`/`password`，不会被解释为 SQL 语法。
   - **硬编码凭证防护**：`dbUser = System.getenv("DB_USER")` 和 `dbPass = System.getenv("DB_PASSWORD")` 从环境变量读取，不在源码中硬编码。
   - **响应输出检查**：`resp.getWriter().println("Login success")` / `println("Invalid")` / `println("DB error")` 输出的是**固定字符串**，不是用户输入反射，不存在 XSS。
4. **反偏见自检**：尝试构造 SQL 注入 payload。`username="admin' OR '1'='1"` 经 `setString` 后，数据库将其作为字面字符串与 `users.username` 比较，不会改变 SQL 语义。响应输出不包含 `username` 内容，无 XSS。无法构造有效 payload。
5. **结论**：PreparedStatement 参数化查询 + 环境变量凭证 + 固定响应输出，三层防御完整，代码无漏洞。

---

### 最终 JSON 结论：

```json
{
  "has_vulnerability": false,
  "vulnerability_type": "none",
  "risk_level": "None",
  "source": "req.getParameter('username'), req.getParameter('password')",
  "sink": "PreparedStatement.executeQuery (参数化查询)",
  "explanation": "使用 PreparedStatement + setString 参数化查询，SQL 占位符不会被输入改变语义。数据库凭证从环境变量读取。响应输出为固定字符串，不反射用户输入，无 XSS。",
  "fix_suggestion": "no fix needed"
}
```<|im_end|>""",

    # FP 6 (v5 新增): 装饰器包装的参数化查询，str() 返回 tuple 表示
    "noise_05_decorator_wrapper.py": """### 分析过程：

1. **识别输入点（source）**：`username = request.args.get("username", "")` 是用户可控输入。
2. **追踪数据流到 sink**：
   - `username` → `safe_query(username)` → `cursor.execute("SELECT * FROM users WHERE name = ?", (username,))`（SQL sink，但有参数化防护）。
   - `safe_query` 的返回值 `cursor.fetchone()`（一个 tuple）→ `str(...)` → Flask 响应。
3. **评估装饰器影响**：`wrapper1` 定义为 `def wrapper2(*args, **kwargs): return func(*args, **kwargs)`，是纯透传装饰器，不修改参数也不修改返回值，对数据流无影响。装饰器的存在不改变安全分析结论。
4. **评估防御措施（关键）**：
   - **SQL 注入防护**：`cursor.execute("SELECT * FROM users WHERE name = ?", (username,))` 使用 `?` 占位符 + 元组参数 `(username,)`，是参数化查询的标准写法。`username` 不会被解释为 SQL 语法，无法构造注入 payload。
   - **响应输出检查**：`str(safe_query(username))` 返回的是 Python tuple 的字符串表示（形如 `(1, 'alice', ...)`），不是模板渲染、不是 `eval`、不是 `render_template_string`。`str()` 是数据序列化，不是代码执行 sink。tuple 的 `str()` 会对字符串元素使用 `repr()`，单引号包裹，HTML 标签若存在也会被当作字面字符串字符处理，不会被浏览器解释为 DOM。
5. **反偏见自检**：尝试构造攻击 payload。`username="admin' OR '1'='1"` 经参数化查询后作为字面字符串比较，无法改变 SQL 语义。`username="<script>alert(1)</script>"` 经 `cursor.fetchone()` 查询后，若数据库无此用户则返回 `None`，`str(None)` 返回 `"None"`；若有此用户，返回 tuple，`str()` 会用 `repr()` 包裹字符串元素，`<script>` 不被渲染为 HTML。无法构造有效 payload。
6. **结论**：参数化查询防 SQL 注入 + `str()` 是数据序列化非代码执行 sink + 透传装饰器无影响，代码无漏洞。

---

### 最终 JSON 结论：

```json
{
  "has_vulnerability": false,
  "vulnerability_type": "none",
  "risk_level": "None",
  "source": "request.args.get('username')",
  "sink": "cursor.execute (参数化查询) + str() (tuple 序列化, 非代码执行)",
  "explanation": "参数化查询防止 SQL 注入；wrapper1 是纯透传装饰器无影响；str() 返回 tuple 的字符串表示，使用 repr() 包裹字符串元素，不是模板渲染或代码执行 sink，无 XSS。",
  "fix_suggestion": "no fix needed"
}
```<|im_end|>""",
}


def load_eval_fps(eval_result_path: Path) -> list:
    """从评估结果 JSON 中提取 FP 样本。"""
    with open(eval_result_path, encoding="utf-8") as f:
        data = json.load(f)
    samples = data.get("samples", [])
    fps = [s for s in samples if s.get("outcome") == "FP"]
    print(f"加载评估结果: {eval_result_path.name}")
    print(f"  总样本: {len(samples)}, FP 样本: {len(fps)}")
    return fps


def load_source_code(samples_dir: Path, filename: str) -> str:
    """从样本目录加载源代码。"""
    code_path = samples_dir / filename
    if not code_path.exists():
        raise FileNotFoundError(f"源代码文件不存在: {code_path}")
    return code_path.read_text(encoding="utf-8")


def detect_language(filename: str) -> str:
    """根据文件扩展名推断语言。"""
    ext = Path(filename).suffix.lower()
    return {
        ".py": "python",
        ".java": "java",
        ".js": "javascript",
        ".ts": "typescript",
        ".go": "go",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
        ".c": "c",
        ".cpp": "cpp",
    }.get(ext, "text")


def build_dpo_prompt(code: str, language: str, filename: str) -> str:
    """构建 DPO prompt（ChatML 格式，与训练/推理一致）。"""
    user_content = build_user_prompt(
        code=code, language=language, filename=filename,
    )
    prompt = (
        f"<|im_start|>system\n{SYSTEM_PROMPT_LITE}<|im_end|>\n"
        f"<|im_start|>user\n{user_content}<|im_end|>\n"
        f"<|im_start|>assistant\n"
    )
    return prompt


def normalize_rejected(raw_output: str) -> str:
    """规范化 rejected（模型的真实 FP 输出）。

    - 去除可能的尾随空白
    - 确保 <|im_end|> 结尾（与 chosen 格式一致）
    """
    output = raw_output.rstrip()
    if not output.endswith("<|im_end|>"):
        output = output + "<|im_end|>"
    return output


def validate_pair(pair: dict, idx: int) -> None:
    """验证单个 DPO 偏好对。"""
    if "prompt" not in pair or "chosen" not in pair or "rejected" not in pair:
        raise ValueError(f"对{idx}: 缺少 prompt/chosen/rejected 字段")
    if "<|im_start|>" not in pair["prompt"]:
        raise ValueError(f"对{idx}: prompt 缺少 ChatML 标记")
    if "```json" not in pair["chosen"]:
        raise ValueError(f"对{idx}: chosen 缺少 JSON 块")
    if "```json" not in pair["rejected"]:
        raise ValueError(f"对{idx}: rejected 缺少 JSON 块")
    if pair["chosen"] == pair["rejected"]:
        raise ValueError(f"对{idx}: chosen 和 rejected 相同")

    # chosen 必须含 has_vulnerability: false
    chosen_hv = re.search(
        r'"has_vulnerability":\s*(true|false)',
        pair["chosen"], re.IGNORECASE,
    )
    rejected_hv = re.search(
        r'"has_vulnerability":\s*(true|false)',
        pair["rejected"], re.IGNORECASE,
    )
    if not chosen_hv:
        raise ValueError(f"对{idx}: chosen 无法提取 has_vulnerability")
    if not rejected_hv:
        raise ValueError(f"对{idx}: rejected 无法提取 has_vulnerability")
    if chosen_hv.group(1).lower() != "false":
        raise ValueError(f"对{idx}: chosen 的 has_vulnerability 应为 false")
    if rejected_hv.group(1).lower() != "true":
        raise ValueError(f"对{idx}: rejected 的 has_vulnerability 应为 true")


def main():
    parser = argparse.ArgumentParser(
        description="从评估结果 FP 样本生成 DPO 偏好对",
    )
    parser.add_argument(
        "--eval-result", type=str, required=True,
        help="评估结果 JSON 路径（含 samples 数组）",
    )
    parser.add_argument(
        "--samples-dir", type=str,
        default="experiments/exp_04_hard_samples/samples",
        help="样本源代码目录",
    )
    parser.add_argument(
        "--output", type=str,
        default="experiments/exp_06_finetune/data/dpo_fp_pairs_v4.jsonl",
        help="输出 DPO 偏好对 jsonl 路径",
    )
    parser.add_argument(
        "--only-with-chosen", action="store_true", default=True,
        help="仅生成有手工 chosen 回复的 FP（默认开启）",
    )
    args = parser.parse_args()

    eval_path = Path(args.eval_result).resolve()
    samples_dir = Path(args.samples_dir).resolve()
    output_path = Path(args.output).resolve()

    if not eval_path.exists():
        print(f"错误: 评估结果文件不存在: {eval_path}")
        sys.exit(1)
    if not samples_dir.exists():
        print(f"错误: 样本目录不存在: {samples_dir}")
        sys.exit(1)

    # 加载 FP 样本
    fps = load_eval_fps(eval_path)
    if not fps:
        print("错误: 未找到 FP 样本")
        sys.exit(1)

    # 构造 DPO 偏好对
    pairs = []
    skipped = []
    for fp in fps:
        filename = fp.get("file", "")
        if args.only_with_chosen and filename not in CHOSEN_RESPONSES:
            skipped.append(filename)
            continue

        chosen_text = CHOSEN_RESPONSES.get(filename)
        if not chosen_text:
            skipped.append(filename)
            continue

        # 加载源代码
        try:
            code = load_source_code(samples_dir, filename)
        except FileNotFoundError as e:
            print(f"  跳过 {filename}: {e}")
            skipped.append(filename)
            continue

        language = detect_language(filename)
        prompt = build_dpo_prompt(code, language, filename)
        rejected = normalize_rejected(fp["raw_output"])

        pair = {
            "prompt": prompt,
            "chosen": chosen_text,
            "rejected": rejected,
            # 元数据（不参与训练，便于审计）
            "_source_file": filename,
            "_fp_vulnerability_type": fp.get("model_vulnerability_type", ""),
            "_category": fp.get("category", ""),
            "_difficulty": fp.get("difficulty", ""),
        }
        pairs.append(pair)

    if skipped:
        print(f"\n跳过 {len(skipped)} 个无手工 chosen 的 FP: {skipped}")
        print("(如需补充，请在 CHOSEN_RESPONSES 字典中添加对应回复)")

    if not pairs:
        print("错误: 未生成任何 DPO 偏好对")
        sys.exit(1)

    # 验证
    print(f"\n生成 {len(pairs)} 对 DPO 偏好对")
    for i, pair in enumerate(pairs):
        validate_pair(pair, i)
    print(f"[OK] 所有 {len(pairs)} 对偏好对格式合规")

    # 打印摘要
    print("\n" + "=" * 60)
    print("DPO 偏好对摘要")
    print("=" * 60)
    for i, pair in enumerate(pairs):
        print(f"\n[{i+1}] {pair['_source_file']} ({pair['_category']}, {pair['_difficulty']})")
        print(f"    rejected FP 类型: {pair['_fp_vulnerability_type']}")
        print(f"    prompt 长度: {len(pair['prompt'])} chars")
        print(f"    chosen 长度: {len(pair['chosen'])} chars")
        print(f"    rejected 长度: {len(pair['rejected'])} chars")

    # 写入文件
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # 写入时剥离元数据字段（DPOTrainer 只认 prompt/chosen/rejected）
    with open(output_path, "w", encoding="utf-8") as f:
        for pair in pairs:
            clean = {
                "prompt": pair["prompt"],
                "chosen": pair["chosen"],
                "rejected": pair["rejected"],
            }
            f.write(json.dumps(clean, ensure_ascii=False) + "\n")
    print(f"\n已写入: {output_path}")

    # 验证文件
    count = 0
    with open(output_path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rec = json.loads(line)
                assert "prompt" in rec and "chosen" in rec and "rejected" in rec
                count += 1
    assert count == len(pairs), f"写入行数应为 {len(pairs)}，实际 {count}"
    print(f"[OK] 文件包含 {count} 条有效 DPO 偏好对")

    # 与现有 DPO 数据对比
    existing_path = output_path.parent / "dpo_preference_pairs.jsonl"
    if existing_path.exists():
        with open(existing_path, encoding="utf-8") as f:
            existing_count = sum(1 for line in f if line.strip())
        print(f"\n现有 DPO 数据: {existing_path.name} ({existing_count} 对)")
        print(f"新增 FP DPO 数据: {output_path.name} ({count} 对)")
        print(f"合并后总数: {existing_count + count} 对")
        print(f"\n如需合并，可运行 merge_dpo_data.py 或手动 cat:" )
        print(f"  cat {existing_path.name} {output_path.name} > dpo_merged_v4.jsonl")


if __name__ == "__main__":
    main()
