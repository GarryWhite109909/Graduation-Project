"""
CCoT（Contrastive Chain-of-Thought）v3 扩展 —— 36 条新样本，聚焦：
  H. shell=True + 列表边界（7 条）
  I. subprocess.run / shell=False 边界（7 条）
  J. 跨文件参数（7 条）
  K. 缺失功能类型 / missing feature（7 条）
  L. 安全噪声 / 安全代码（8 条）

设计依据：将 CCoT 数据从现有 40 条扩充到 60-100 条。
  v3 扩展的 36 条 **同时输出 SFT 和 DPO 格式**。
  最终 SFT 数据 = 40 (v2) + 36 (v3) = 76 条。
  最终 DPO 数据 = 62 (v1+v2) + 36 (v3) = 98 对偏好。

用法（无需 GPU，纯数据生成）：
  PYTHONPATH=. /home/zane/miniconda3/envs/graproj/bin/python3 \
      experiments/exp_06_finetune/scripts/generate_ccot_v3_expansion.py
"""

import json
import os
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import SYSTEM_PROMPT_LITE, build_user_prompt

OUTPUT_SFT = PROJECT_ROOT / "experiments/exp_06_finetune/data/supplement_ccot_v3_expansion.jsonl"
OUTPUT_DPO = PROJECT_ROOT / "experiments/exp_06_finetune/data/dpo_v3_expansion.jsonl"

SAMPLES = []


def add(code, language, filename, has_vulnerability, vuln_type, risk_level,
        source, sink, explanation, fix_suggestion,
        incorrect_reasoning, incorrect_flaw, correct_reasoning):
    """添加一条 CCoT 对比样本。"""
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
# 类别 H: shell=True + 列表边界（7 条）
# 覆盖 Popen/call/check_output + shell=True + 列表 的边界，
# 以及 f-string + shell=True、executable 可控、user_input.split() + shell=True 等场景。
# ===========================================================================

# --- H1: Popen + 列表 + shell=True（安全：列表压制 shell=True） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/lookup")
def lookup():
    domain = request.args.get("domain", "")
    proc = subprocess.Popen(
        ["nslookup", domain],
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    out, err = proc.communicate(timeout=5)
    return out.decode()
""",
    "python",
    "ccot_v3_popen_list_shell_true.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.Popen 使用列表参数 ['nslookup', domain]，虽然显式 shell=True，但列表形式下 shell=True 不生效（Python 文档：args 为列表时，shell=True 仍走 execvp，不经 /bin/sh 解释）。domain 作为 nslookup 的字面参数，不会被 shell 解释",
    "no fix needed（但建议去掉 shell=True 增加可读性）",
    """
代码使用了 subprocess.Popen 并且 shell=True，这意味着命令会通过 shell 解释器执行。即使用列表形式，shell=True 仍然会启用 shell 解释，攻击者传入 domain="; rm -rf /" 可以执行任意命令。""",
    """
问题：模型对 Popen + 列表 + shell=True 的语义理解错误。Python subprocess 文档明确：当 args 是列表时，shell=True 不会让 /bin/sh 解释整个命令字符串。列表元素仍作为独立 argv 传给 execvp。Popen 与 run 的 shell 语义完全一致。""",
    """
1. 污染源：request.args.get('domain') 获取用户输入。
2. 危险 sink：subprocess.Popen(['nslookup', domain], shell=True)。
3. 数据流追踪：domain → 列表参数 → Popen(shell=True)。
4. 边界分析（Popen + 列表 + shell=True）：
   (a) Python subprocess 文档：当 args 是列表时，shell=True 参数被忽略，
       列表元素直接传给 execvp。Popen 与 run 共享此语义。
   (b) domain 作为 nslookup 的第二个元素（argv[1]），execvp 把它作为字面参数。
   (c) 攻击者传入 domain="; rm -rf /"：nslookup 会尝试解析 "; rm -rf /" 为域名，
       查找失败返回错误，分号不被 shell 解释。
   (d) 即使 Popen 是低阶 API，shell 语义与 run 完全一致。
5. 结论：列表形式压制 shell=True 的语义，无命令注入。代码安全。"""
)

# --- H2: subprocess.call + 列表 + shell=True（安全：call 与 run 语义一致） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/echo")
def echo():
    msg = request.args.get("msg", "")
    retcode = subprocess.call(
        ["echo", msg],
        shell=True
    )
    return str(retcode)
""",
    "python",
    "ccot_v3_call_list_shell_true.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.call 使用列表参数 ['echo', msg]，虽然显式 shell=True，但列表形式下 shell=True 不生效（与 run/Popen 行为一致）。msg 作为 echo 的字面参数，不会被 shell 解释",
    "no fix needed（但建议去掉 shell=True 增加可读性）",
    """
subprocess.call 是旧版 API，shell=True 在 call 中行为可能不同。代码用了列表但仍设置了 shell=True，shell=True 可能覆盖列表形式的安全保证，攻击者传入 msg="; cat /etc/passwd" 可以执行额外命令。""",
    """
问题：模型误以为 subprocess.call 中 shell=True 的行为与 run/Popen 不同。实际上 call 内部调用 Popen，shell 语义完全一致——当 args 是列表时，shell=True 不生效。call 只是 run 的早期封装，安全性相同。""",
    """
1. 污染源：request.args.get('msg') 获取用户输入。
2. 危险 sink：subprocess.call(['echo', msg], shell=True)。
3. 数据流追踪：msg → 列表参数 → call(shell=True)。
4. 边界分析（call + 列表 + shell=True）：
   (a) subprocess.call 内部调用 Popen，shell 语义与 run/Popen 完全一致。
   (b) 当 args 是列表时，shell=True 不生效，列表元素直接传给 execvp。
   (c) msg 作为 echo 的字面参数，分号、管道等元字符无 shell 语义。
   (d) 攻击者传入 msg="; cat /etc/passwd"：echo 输出 "; cat /etc/passwd" 字面字符串。
5. 结论：call + 列表形式压制 shell=True，无命令注入。代码安全。"""
)

# --- H3: subprocess.run f-string + shell=True（漏洞：shell 解释元字符） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/list")
def list_dir():
    path = request.args.get("path", "")
    result = subprocess.run(
        f"ls {path}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_v3_run_fstring_shell_true.py",
    True,
    "CWE-78 命令注入",
    "Critical",
    "request.args.get('path')",
    "subprocess.run(f'ls {path}', shell=True)",
    "subprocess.run 使用 f-string 拼接用户输入 path 到命令字符串，且 shell=True 启动 /bin/sh -c 解释。path 中的分号、管道、命令替换等 shell 元字符会被解释执行。攻击者传入 path=\"; rm -rf /\" 即可执行任意命令",
    "改用 subprocess.run(['ls', path], shell=False) 列表形式，或对 path 使用 shlex.quote 转义",
    """
代码使用 f-string 拼接 path，但 ls 只是列目录命令，path 应该是目录路径。攻击者不太可能通过目录路径注入命令，因为路径通常不含分号等特殊字符。风险较低。""",
    """
问题：模型低估了 f-string + shell=True 的风险。命令注入不依赖攻击者"通常输入什么"，而在于输入是否可控。path 完全由用户控制，攻击者可以传入任何字符串包括 shell 元字符。只要输入可控 + shell=True + 字符串拼接，就是 CWE-78 命令注入。""",
    """
1. 污染源：request.args.get('path') 获取用户输入。
2. 危险 sink：subprocess.run(f'ls {path}', shell=True)。
3. 数据流追踪：path → f-string 拼接 → subprocess.run(shell=True) → /bin/sh -c 解释。
4. 防御检查（无）：
   (a) path 未转义直接拼入 f-string。
   (b) shell=True 启动 /bin/sh -c 解释完整命令字符串。
   (c) 攻击者传入 path="; rm -rf /" → shell 执行 ls 和 rm 两条命令。
   (d) 攻击者传入 path="$(cat /etc/passwd)" → 命令替换执行。
5. 结论：f-string + shell=True + 用户输入未转义，存在 CWE-78 命令注入漏洞。"""
)

# --- H4: subprocess.run 列表 + shell=True + executable 用户控制（漏洞） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    user_exe = request.args.get("exe", "/bin/ls")
    result = subprocess.run(
        ["dummy", "-la"],
        shell=True,
        executable=user_exe,
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_v3_executable_user_controlled.py",
    True,
    "CWE-78 命令注入",
    "Critical",
    "request.args.get('exe')",
    "subprocess.run(['dummy', '-la'], shell=True, executable=user_exe)",
    "subprocess.run 的 executable 参数指定实际执行的可执行文件路径。当 shell=True 且 executable 可控时，Python 使用 executable 作为 /bin/sh 的替代。攻击者传入 exe=\"/usr/bin/python3\" 可以让 Python 启动 python3 进程执行命令，实现任意代码执行",
    "不要让用户控制 executable 参数，使用硬编码路径或白名单",
    """
代码使用列表参数 + shell=True，列表形式下 shell=True 不生效。executable 参数只是指定 shell 的可执行文件路径，不影响命令注入防护。代码安全。""",
    """
问题：模型忽略了 executable 参数的安全影响。当 shell=True 时，executable 指定替代 /bin/sh 的程序。如果 executable 指向 /usr/bin/python3，则 Python 启动 python3 进程而非 /bin/sh，子进程解释 ['dummy', '-la'] 的方式完全不同——python3 可能把 'dummy' 当作脚本名执行。这等价于让用户选择任意程序作为命令解释器。""",
    """
1. 污染源：request.args.get('exe') 获取用户输入。
2. 危险 sink：subprocess.run(['dummy', '-la'], shell=True, executable=user_exe)。
3. 数据流追踪：user_exe → executable 参数 → 子进程可执行文件路径。
4. 漏洞分析（executable 可控）：
   (a) shell=True 时，executable 指定替代 /bin/sh 的可执行文件。
   (b) 默认 executable=None 时使用 /bin/sh，但 executable=user_exe 时使用用户指定的程序。
   (c) 攻击者传入 exe="/usr/bin/python3" → Python 启动 python3 进程，
       python3 把 'dummy' 当作脚本名执行（如果存在则执行，不存在则报错）。
   (d) 攻击者传入 exe="/usr/bin/rm" → Python 启动 rm 进程，argv 为 ['dummy', '-la']，
       rm 会尝试删除名为 dummy 和 -la 的文件。
   (e) executable 让攻击者控制"用什么程序执行"，本质是命令注入的变体。
5. 结论：executable 参数用户可控，存在 CWE-78 命令注入漏洞。"""
)

# --- H5: subprocess.run user_input.split() + shell=True（漏洞：split 可被绕过） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/exec")
def exec():
    user_cmd = request.args.get("cmd", "")
    result = subprocess.run(
        user_cmd.split(),
        shell=True,
        capture_output=True,
        text=True,
        timeout=5
    )
    return result.stdout
""",
    "python",
    "ccot_v3_split_list_shell_true.py",
    True,
    "CWE-78 命令注入",
    "Critical",
    "request.args.get('cmd')",
    "subprocess.run(user_cmd.split(), shell=True)",
    "user_cmd.split() 将用户输入按空白切分为列表，虽然列表形式 + shell=True 时 shell=True 不生效，但代码的意图是让用户控制完整命令。当 shell=True 不生效时，execvp(user_cmd.split()[0]) 尝试执行用户指定的可执行文件——这是任意命令执行。而如果开发者修改为字符串形式去掉 split()，则 shell=True 会生效，同样存在命令注入",
    "禁止用户控制完整命令，改用白名单命令 + 参数化传递",
    """
代码使用 user_cmd.split() 将输入切分为列表，列表形式下 shell=True 不生效。因此分号等 shell 元字符不会被解释，无命令注入。代码安全。""",
    """
问题：模型只关注了 shell 注入层面，忽略了更严重的任意命令执行问题。user_cmd.split() 让用户完全控制可执行文件名和参数——execvp(user_cmd.split()[0]) 执行用户指定的任意程序。即使 shell=True 在列表形式下不生效，任意命令执行的风险远超命令注入。另外，若开发者未来将 split() 去掉改用字符串形式（以为更简单），shell=True 就会立即生效，引发命令注入。""",
    """
1. 污染源：request.args.get('cmd') 获取用户输入（完整命令）。
2. 危险 sink：subprocess.run(user_cmd.split(), shell=True)。
3. 数据流追踪：user_cmd → str.split() → 列表 → subprocess.run(shell=True)。
4. 漏洞分析（split + shell=True 的双重风险）：
   (a) 列表形式下 shell=True 不生效，但 user_cmd.split()[0] 是用户控制的可执行文件名，
       execvp 执行任意程序 → 任意命令执行。
   (b) 攻击者传入 cmd="cat /etc/passwd" → split() 返回 ["cat", "/etc/passwd"]，
       execvp("cat") 执行 cat /etc/passwd。
   (c) 攻击者传入 cmd="rm -rf /tmp" → split() 返回 ["rm", "-rf", "/tmp"]，
       execvp("rm") 删除 /tmp 目录。
   (d) 即便当前 shell=True 不生效，代码设计意图是让用户控制完整命令，这是严重的业务逻辑漏洞。
   (e) 若开发者将 split() 去掉改为字符串形式，shell=True 立即生效，命令注入风险更大。
5. 结论：user_cmd.split() + shell=True 存在 CWE-78 命令注入（列表形式下 shell=True 不生效，
   但可执行文件名用户可控构成任意命令执行）。"""
)

# --- H6: subprocess.run shlex.split + shell=True（安全：shlex.split 正确解析） ---
add(
    """
import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    user_cmd = request.args.get("cmd", "echo hello")
    parts = shlex.split(user_cmd)
    result = subprocess.run(
        parts,
        shell=True,
        capture_output=True,
        text=True,
        timeout=5
    )
    return result.stdout
""",
    "python",
    "ccot_v3_shlex_split_shell_true.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "shlex.split(user_cmd) 在 Python 层面按 shell 引用规则解析用户输入，返回列表。列表形式 + shell=True 时 shell=True 不生效，列表元素直接传给 execvp。shlex.split 正确处理引号、转义，每个 token 是字面字符串。但 parts[0] 是用户控制的可执行文件名，这是业务逻辑风险（任意命令执行），不是 CWE-78 命令注入",
    "no fix needed（但应限制可执行文件名为白名单）",
    """
代码使用 shlex.split 解析用户输入，然后传给 subprocess.run(shell=True)。shlex.split 解析后的列表仍然含用户控制的命令名，且 shell=True 会启用 shell 解释。攻击者可以构造含分号的命令绕过 shlex.split。""",
    """
问题：模型对 shlex.split 的行为理解错误。shlex.split 按照 shell 引用规则解析输入字符串，正确处理引号和转义，返回的列表中每个 token 都是字面字符串。列表形式 + shell=True 时 shell=True 不生效（与 str.split() 不同的是 shlex.split 识别引号包裹的参数）。但 parts[0] 确实是用户控制的可执行文件名，这是业务逻辑问题而非 CWE-78。""",
    """
1. 污染源：request.args.get('cmd') 获取用户输入。
2. 危险 sink：subprocess.run(parts, shell=True)。
3. 数据流追踪：user_cmd → shlex.split → 列表 → subprocess.run(shell=True)。
4. 边界分析（shlex.split + shell=True）：
   (a) shlex.split 按照 POSIX shell 引用规则解析，正确处理单/双引号、反斜杠转义。
   (b) 列表形式 + shell=True 时 shell=True 不生效，列表元素直接传给 execvp。
   (c) 即便 shell=True 不生效，shlex.split 也提供了正确的参数分割（比 str.split 更安全，
       因为它识别引号包裹的参数不会被错误切分）。
   (d) parts[0] 是用户控制的可执行文件名，这是任意命令执行的业务逻辑风险，
       但不属于 CWE-78 命令注入（无 shell 解释器参与元字符解释）。
5. 结论：shlex.split + 列表形式压制 shell=True，无 CWE-78 命令注入。代码安全（但应限制可执行文件名白名单）。"""
)

# --- H7: subprocess.check_output + 列表 + shell=True（安全：check_output + 列表 + shell=True 不生效） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/dig")
def dig():
    domain = request.args.get("domain", "")
    result = subprocess.check_output(
        ["dig", domain],
        shell=True,
        timeout=5
    )
    return result.decode()
""",
    "python",
    "ccot_v3_check_output_list_shell_true.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.check_output 使用列表参数 ['dig', domain]，虽然显式 shell=True，但列表形式下 shell=True 不生效（check_output 内部调用 run，shell 语义一致）。domain 作为 dig 的字面参数，不会被 shell 解释",
    "no fix needed（但建议去掉 shell=True 增加可读性）",
    """
代码使用 subprocess.check_output 并设置 shell=True，check_output 是高阶 API，shell=True 会启用 shell 解释。即使用列表形式，shell=True 在 check_output 中也可能有不同的行为。攻击者传入 domain="; cat /etc/passwd" 可以执行额外命令。""",
    """
问题：模型误以为 check_output 中 shell=True 的行为与 run/Popen 不同。实际上 check_output 内部调用 Popen，shell 语义完全一致——当 args 是列表时，shell=True 不生效。check_output 只是 run + 检查 returncode 的封装。""",
    """
1. 污染源：request.args.get('domain') 获取用户输入。
2. 危险 sink：subprocess.check_output(['dig', domain], shell=True)。
3. 数据流追踪：domain → 列表参数 → check_output(shell=True)。
4. 边界分析（check_output + 列表 + shell=True）：
   (a) check_output 内部调用 Popen，shell 语义与 run/Popen 完全一致。
   (b) 当 args 是列表时，shell=True 不生效，列表元素直接传给 execvp。
   (c) domain 作为 dig 的字面参数，分号、管道等元字符无 shell 语义。
   (d) 攻击者传入 domain="; cat /etc/passwd"：dig 查询字面域名 "; cat /etc/passwd"，
       报 NXDOMAIN 错误（check_output 可能抛 CalledProcessError）。
5. 结论：check_output + 列表形式压制 shell=True，无命令注入。代码安全。"""
)


# ===========================================================================
# 类别 I: subprocess.run / shell=False 边界（7 条）
# 覆盖 shell=False 下各种边界：
#   - 字符串 args + shell=False（execvp 报错）
#   - 用户控制命令名
#   - python -c / perl -e 代码注入
#   - find / tar 路径穿越
#   - curl SSRF
# ===========================================================================

# --- I1: subprocess.run 字符串 args + shell=False（安全：execvp 报错） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    user_input = request.args.get("cmd", "")
    result = subprocess.run(
        user_input,
        shell=False,
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_v3_string_args_shell_false.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.run(user_input, shell=False) 中 shell=False，args 字符串不经过 shell 解释，Python 直接调用 execvp(user_input)，把整个字符串作为可执行文件路径。execvp 找不到名为 user_input 的可执行文件（除非 user_input 恰好是有效的可执行文件路径如 \"/bin/ls\"），会抛 OSError。即使 user_input 含 ; | & 等元字符，也是路径名的一部分，无 shell 解释",
    "no fix needed（但这是反模式，建议改列表形式）",
    """
代码把用户输入 user_input 直接传给 subprocess.run，用户可以控制执行的命令。即使 shell=False，攻击者传入 cmd=\"/bin/sh\" 就能启动 shell，进而执行任意命令。代码存在命令注入。""",
    """
问题：模型混淆了\"命令注入\"和\"任意命令执行\"。shell=False 时，execvp(user_input) 把 user_input 作为可执行文件路径。攻击者传入 cmd=\"/bin/sh\" → execvp 启动 /bin/sh 交互模式（因没有 -c 参数，sh 等待 stdin 输入，在 web 场景下会超时或挂起）。这不是 CWE-78 命令注入（无 shell 元字符解释），且代码实际功能因 execvp 报错而不可用。""",
    """
1. 污染源：request.args.get('cmd') 获取用户输入。
2. 危险 sink：subprocess.run(user_input, shell=False)。
3. 数据流追踪：user_input → 字符串 args → subprocess.run(shell=False)。
4. 边界分析（字符串 args + shell=False）：
   (a) shell=False 时，args 字符串不经过 shell 解释，作为可执行文件路径直接传给 execvp。
   (b) execvp(user_input) 尝试找到名为 user_input 的可执行文件。
   (c) user_input="ls -la" → execvp 找不到名为 "ls -la" 的文件（含空格），抛 OSError。
   (d) user_input="; rm -rf /" → execvp 找不到名为 "; rm -rf /" 的文件，抛 OSError。
   (e) 分号、管道等 shell 元字符在 shell=False 下无意义，因为 /bin/sh 没有被调用。
   (f) 即使 user_input="/bin/ls" 恰好是有效路径，execvp 启动 ls 但无参数，
       且这是"恰好有效的路径"而非命令注入。
5. 结论：shell=False + 字符串 args 无 CWE-78 命令注入。代码安全（但功能不可用，是反模式）。"""
)

# --- I2: subprocess.run 列表 + 用户控制命令名（漏洞：任意命令执行） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/tool")
def tool():
    tool_name = request.args.get("tool", "ls")
    result = subprocess.run(
        [tool_name, "--help"],
        shell=False,
        capture_output=True,
        text=True,
        timeout=5
    )
    return result.stdout
""",
    "python",
    "ccot_v3_user_controlled_cmd_name.py",
    True,
    "CWE-78 命令注入",
    "High",
    "request.args.get('tool')",
    "subprocess.run([tool_name, '--help'], shell=False)",
    "subprocess.run 使用列表形式 + shell=False，参数不经 shell 解释，但列表首元素 tool_name 是用户输入。用户可以传入 tool_name='sh' 或 tool_name='python3'，让子进程执行任意程序。列表形式阻止了 shell 元字符注入，但无法阻止用户控制可执行文件名本身。虽然严格来说这是任意命令执行而非经典 shell 注入，但 CWE-78 包含此场景",
    "限制 tool_name 为白名单（如只允许 ['ls', 'cat', 'grep']），或使用映射表",
    """
代码使用列表形式 + shell=False，参数不经 shell 解释。tool_name 作为列表首元素传给 execvp，shell 不参与。即使 tool_name 用户可控，也无法注入 shell 元字符。代码安全。""",
    """
问题：模型只关注 shell 注入层面，忽略了用户控制可执行文件名的风险。CWE-78 不仅包含 shell 元字符注入，还包含用户控制命令执行路径的情况。当 tool_name='sh' 时，execvp 启动 /bin/sh（虽无 -c 参数，但配合 --help 参数 sh 仍会启动）。更危险的是 tool_name='python3' 配合 --help 虽然无害，但如果开发者未来修改参数，风险立即放大。""",
    """
1. 污染源：request.args.get('tool') 获取用户输入。
2. 危险 sink：subprocess.run([tool_name, '--help'], shell=False)。
3. 数据流追踪：tool_name → 列表首元素 → execvp(tool_name)。
4. 漏洞分析（用户控制命令名）：
   (a) 列表形式 + shell=False，无 /bin/sh 参与，无 shell 元字符注入。
   (b) 但 tool_name 是列表首元素，execvp(tool_name) 搜索 PATH 找到可执行文件。
   (c) tool_name="sh" → execvp("sh") 启动 /bin/sh，argv 为 ["sh", "--help"]，
       sh 输出帮助信息（不执行任意命令，但启动了 shell 进程）。
   (d) tool_name="python3" → execvp("python3") 启动 python3，
       argv 为 ["python3", "--help"]，python3 输出帮助信息。
   (e) tool_name="curl" → execvp("curl") 启动 curl --help。
   (f) 虽然当前 --help 参数限制了危害，但用户控制可执行文件名是 CWE-78 命令注入范畴。
5. 结论：用户控制命令名存在 CWE-78 命令注入风险（High），应加白名单限制。"""
)

# --- I3: subprocess.run python -c + 用户代码（漏洞：代码注入） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/eval")
def eval_code():
    user_code = request.args.get("code", "print('hello')")
    result = subprocess.run(
        ["python3", "-c", user_code],
        shell=False,
        capture_output=True,
        text=True,
        timeout=5
    )
    return result.stdout
""",
    "python",
    "ccot_v3_python_c_code_injection.py",
    True,
    "CWE-94 代码注入",
    "Critical",
    "request.args.get('code')",
    "subprocess.run(['python3', '-c', user_code], shell=False)",
    "subprocess.run 使用列表形式 + shell=False，但列表中 python3 -c 显式启动 Python 解释器，user_code 作为 Python 源代码被解释执行。攻击者传入 code=\"import os; os.system('rm -rf /')\" 即可执行任意系统命令。这是 CWE-94 代码注入，危害比 CWE-78 更大（直接 RCE）",
    "禁止将用户输入作为 Python 代码执行，改用预定义脚本 + 参数传递",
    """
代码使用列表形式 + shell=False，参数不经 shell 解释。user_code 作为 python3 的 -c 参数传入，python3 只是执行用户代码。由于 shell=False，不存在命令注入。代码安全。""",
    """
问题：模型混淆了\"命令注入\"和\"代码注入\"。虽然 shell=False 确实没有 /bin/sh 参与（无 CWE-78），但 python3 -c 会将 user_code 作为 Python 源代码解释执行。这是 CWE-94 代码注入，攻击者可以在 Python 运行时内执行 os.system()、subprocess.run() 等调用，实现任意系统命令执行。危害等级比单纯的命令注入更高。""",
    """
1. 污染源：request.args.get('code') 获取用户输入。
2. 危险 sink：subprocess.run(['python3', '-c', user_code], shell=False)。
3. 数据流追踪：user_code → argv[2] → python3 进程解释执行。
4. 漏洞分析（代码注入）：
   (a) 列表形式 + shell=False，无 /bin/sh 参与，**无 CWE-78 命令注入**。
   (b) 但 python3 -c 接收的 user_code 是 Python 源代码，python3 进程内解释执行。
   (c) 攻击者传入 code="import os; os.system('rm -rf /')" → python3 执行任意代码。
   (d) 攻击者传入 code="open('/etc/passwd').read()" → 读取任意文件。
   (e) 这是 CWE-94 代码注入（Code Injection），危害比 CWE-78 更大（直接 RCE）。
5. 结论：python3 -c + 用户输入存在 CWE-94 代码注入（Critical）。"""
)

# --- I4: subprocess.run perl -e + 用户代码（漏洞：代码注入） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/perl")
def perl_eval():
    user_expr = request.args.get("expr", "print 1+1")
    result = subprocess.run(
        ["perl", "-e", user_expr],
        shell=False,
        capture_output=True,
        text=True,
        timeout=5
    )
    return result.stdout
""",
    "python",
    "ccot_v3_perl_e_code_injection.py",
    True,
    "CWE-94 代码注入",
    "Critical",
    "request.args.get('expr')",
    "subprocess.run(['perl', '-e', user_expr], shell=False)",
    "subprocess.run 使用列表形式 + shell=False，但 perl -e 显式启动 Perl 解释器，user_expr 作为 Perl 代码被解释执行。攻击者传入 expr=\"system('rm -rf /')\" 即可执行任意系统命令。Perl 的 system() 函数等价于 C 的 system() 调用",
    "禁止将用户输入作为 Perl 代码执行，改用预定义脚本 + 参数传递",
    """
代码使用列表形式 + shell=False，shell 不参与。user_expr 作为 perl 的 -e 参数传入，perl 只是执行用户表达式。由于 shell=False，不存在命令注入。而且 perl 表达式功能有限，不构成严重漏洞。""",
    """
问题：模型低估了 Perl 的能力。Perl 的 -e 参数接收的是完整的 Perl 源代码，不是简单的表达式。Perl 内置 system()、exec()、反引号等函数可以直接执行 shell 命令。攻击者传入 expr=\"system('rm -rf /')\" 即可执行任意命令。这是 CWE-94 代码注入。""",
    """
1. 污染源：request.args.get('expr') 获取用户输入。
2. 危险 sink：subprocess.run(['perl', '-e', user_expr], shell=False)。
3. 数据流追踪：user_expr → argv[2] → perl 进程解释执行。
4. 漏洞分析（代码注入）：
   (a) 列表形式 + shell=False，无 /bin/sh 参与，**无 CWE-78 命令注入**。
   (b) 但 perl -e 接收的 user_expr 是 Perl 源代码，perl 进程内解释执行。
   (c) 攻击者传入 expr="system('rm -rf /')" → perl 执行 system() 调用 → RCE。
   (d) 攻击者传入 expr="`rm -rf /`" → perl 反引号执行 shell 命令。
   (e) 这是 CWE-94 代码注入（Code Injection），与 python3 -c 同类。
5. 结论：perl -e + 用户输入存在 CWE-94 代码注入（Critical）。"""
)

# --- I5: subprocess.run find + 路径穿越（漏洞：CWE-22） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/find")
def find_files():
    path = request.args.get("path", "/var/data")
    pattern = request.args.get("name", "*.txt")
    result = subprocess.run(
        ["find", path, "-name", pattern],
        shell=False,
        capture_output=True,
        text=True,
        timeout=10
    )
    return result.stdout
""",
    "python",
    "ccot_v3_find_path_traversal.py",
    True,
    "CWE-22 路径穿越",
    "High",
    "request.args.get('path')",
    "subprocess.run(['find', path, '-name', pattern], shell=False)",
    "subprocess.run 使用列表形式 + shell=False，无命令注入。但 path 是用户输入，find 命令会递归搜索指定目录。攻击者传入 path=\"../../\" 或 path=\"/\" 可以遍历任意目录，pattern 也可能匹配敏感文件名（如 \"*.conf\"、\"*.key\"）。这是 CWE-22 路径穿越导致的信息泄露",
    "限制 path 为白名单目录，如 path 必须以 /var/data/ 开头；限制 pattern 只允许 *.txt 等安全模式",
    """
代码使用列表形式 + shell=False，参数不经 shell 解释，无命令注入。path 和 pattern 作为 find 的字面参数传入。find 只是在指定目录搜索文件，不会修改或删除文件。代码安全。""",
    """
问题：模型只关注命令注入，忽略了路径穿越（CWE-22）。find 命令的 path 参数允许用户指定搜索起始目录，攻击者传入 path=\"../../\" 可以搜索上级目录，path=\"/\" 可以搜索整个文件系统。配合 pattern=\"*.conf\" 可以定位配置文件，pattern=\"*.key\" 可以定位密钥文件。虽然无命令注入，但信息泄露风险严重。""",
    """
1. 污染源：path = request.args.get('path')，pattern = request.args.get('name')。
2. 危险 sink：subprocess.run(['find', path, '-name', pattern], shell=False)。
3. 数据流追踪：path, pattern → 列表参数 → find 进程。
4. 漏洞分析（路径穿越）：
   (a) 列表形式 + shell=False，无 CWE-78 命令注入。
   (b) 但 path 用户可控，攻击者传入 path=\"../../\" → find 搜索上级目录。
   (c) 攻击者传入 path=\"/\" → find 搜索整个文件系统，配合 pattern 可定位敏感文件。
   (d) pattern 用户可控，攻击者传入 pattern=\"*.conf\" → 匹配配置文件。
   (e) 这是 CWE-22 路径穿越导致的信息泄露（High）。
5. 结论：find 命令 + 用户控制路径存在 CWE-22 路径穿越漏洞。"""
)

# --- I6: subprocess.Popen tar 解压 + 路径穿越（漏洞：CWE-22） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/extract")
def extract():
    archive = request.args.get("file", "")
    result = subprocess.Popen(
        ["tar", "-xf", archive],
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    out, err = result.communicate(timeout=30)
    return "extracted"
""",
    "python",
    "ccot_v3_tar_path_traversal.py",
    True,
    "CWE-22 路径穿越",
    "High",
    "request.args.get('file')",
    "subprocess.Popen(['tar', '-xf', archive], shell=False)",
    "subprocess.Popen 使用列表形式 + shell=False，无命令注入。但 archive 是用户输入，tar -xf 解压用户指定的归档文件。恶意 tar 包可含路径穿越成员（如 ../../etc/crontab），解压时覆盖系统文件。攻击者可以上传恶意 tar 包并让服务端解压，实现任意文件写入",
    "使用 tar --exclude='..*' 过滤路径穿越成员，或改用 Python tarfile 模块并校验成员路径",
    """
代码使用列表形式 + shell=False，参数不经 shell 解释，无命令注入。archive 作为 tar 的文件名参数传入，tar 只是解压指定文件。代码安全。""",
    """
问题：模型只关注命令注入，忽略了 tar 解压的路径穿越风险（CWE-22）。tar 归档文件可以包含任意路径的成员，如 ../../etc/crontab。当 tar -xf 解压恶意归档时，成员文件会被提取到归档中指定的路径，可能覆盖系统关键文件。攻击者可以构造含路径穿越成员的 tar 包并指定其路径。""",
    """
1. 污染源：archive = request.args.get('file')。
2. 危险 sink：subprocess.Popen(['tar', '-xf', archive], shell=False)。
3. 数据流追踪：archive → 列表参数 → tar 进程解压。
4. 漏洞分析（tar 解压路径穿越）：
   (a) 列表形式 + shell=False，无 CWE-78 命令注入。
   (b) 但 tar -xf 解压用户指定的归档文件，恶意 tar 包可含路径穿越成员。
   (c) 恶意 tar 包中含 ../../etc/crontab → tar 提取到 /etc/crontab（覆盖系统文件）。
   (d) 攻击者可以先上传恶意 tar 包，再通过 archive 参数指定路径让服务端解压。
   (e) 这是 CWE-22 路径穿越（通过恶意归档文件实现任意文件写入）。
5. 结论：tar 解压 + 用户控制归档文件路径存在 CWE-22 路径穿越漏洞。"""
)

# --- I7: subprocess.run curl + SSRF（漏洞：CWE-918） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    result = subprocess.run(
        ["curl", url],
        shell=False,
        capture_output=True,
        text=True,
        timeout=10
    )
    return result.stdout
""",
    "python",
    "ccot_v3_curl_ssrf.py",
    True,
    "CWE-918 SSRF",
    "High",
    "request.args.get('url')",
    "subprocess.run(['curl', url], shell=False)",
    "subprocess.run 使用列表形式 + shell=False，无命令注入。但 url 是用户输入，curl 会请求用户指定的 URL。攻击者可以传入内网地址（如 url=\"http://169.254.169.254/latest/meta-data/\"）获取云元数据，或传入 url=\"http://localhost:6379/\" 访问内网 Redis。这是 CWE-918 SSRF（服务器端请求伪造）",
    "限制 URL 为白名单域名，禁止内网地址和云元数据端点；或使用 HTTP 客户端库替代 curl",
    """
代码使用列表形式 + shell=False，参数不经 shell 解释，无命令注入。url 作为 curl 的参数传入，curl 只是请求指定 URL。由于没有 shell 参与，不存在注入风险。代码安全。""",
    """
问题：模型只关注命令注入，忽略了 SSRF（CWE-918）。curl 请求用户指定的 URL，攻击者可以传入内网地址访问内部服务。常见攻击：url=\"http://169.254.169.254/\"（AWS 元数据）、url=\"http://localhost:6379/\"（Redis）、url=\"http://127.0.0.1:8080/admin\"（内部管理接口）。SSRF 是与命令注入不同类型的漏洞，但危害同样严重。""",
    """
1. 污染源：url = request.args.get('url')。
2. 危险 sink：subprocess.run(['curl', url], shell=False)。
3. 数据流追踪：url → 列表参数 → curl 进程请求。
4. 漏洞分析（SSRF）：
   (a) 列表形式 + shell=False，无 CWE-78 命令注入。
   (b) 但 url 用户可控，curl 请求用户指定的任意 URL。
   (c) 攻击者传入 url="http://169.254.169.254/latest/meta-data/" → 获取 AWS 元数据（IAM 凭证）。
   (d) 攻击者传入 url="http://localhost:6379/" → 访问内网 Redis 服务。
   (e) 攻击者传入 url="file:///etc/passwd" → 读取本地文件（如果 curl 支持 file 协议）。
   (f) 这是 CWE-918 SSRF（服务器端请求伪造）。
5. 结论：curl + 用户控制 URL 存在 CWE-918 SSRF 漏洞。"""
)


# ===========================================================================
# 类别 J: 跨文件参数（7 条）
# 覆盖跨文件场景：
#   - config 模块命令被 shell=True 执行
#   - 跨文件安全函数调用
#   - 白名单映射
#   - 格式化字符串注入
#   - 跨文件 SQL 注入
#   - 权限检查 + 命令注入
# ===========================================================================

# --- J1: config 命令被 shell=True 执行（漏洞） ---
add(
    """
# 跨文件：config.py 定义命令
# config.py:
# COMMAND = "echo hello"

from flask import Flask, request
import subprocess
import config

app = Flask(__name__)


@app.route("/run")
def run():
    arg = request.args.get("arg", "")
    # config.COMMAND 是硬编码命令，arg 是用户输入
    result = subprocess.run(
        f"{config.COMMAND} {arg}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_v3_crossfile_config_shell_true.py",
    True,
    "CWE-78 命令注入",
    "Critical",
    "request.args.get('arg')",
    "subprocess.run(f'{config.COMMAND} {arg}', shell=True)",
    "config.COMMAND 是硬编码字符串 'echo hello'，但 subprocess.run 使用 f-string 拼接用户输入 arg 到命令字符串，且 shell=True。arg 中的分号、管道等 shell 元字符会被解释执行。虽然 config.COMMAND 本身是安全的，但拼接方式引入了命令注入",
    "改用列表形式：subprocess.run(config.COMMAND.split() + [arg], shell=False)",
    """
config.COMMAND 是配置文件中的硬编码命令，不是用户输入。subprocess.run 虽然用了 shell=True，但 config.COMMAND 是固定的。arg 是用户输入但只是 echo 的参数。代码安全。""",
    """
问题：模型只关注 config.COMMAND 是否可控，忽略了 arg 用户输入也被拼接到同一命令字符串中。shell=True 时，整个命令字符串（包括 arg 部分）都经 /bin/sh 解释。arg 含分号、命令替换等元字符时即可触发命令注入。""",
    """
1. 跨文件源：config.COMMAND = "echo hello"（硬编码，不可控）。
2. 用户输入源：arg = request.args.get('arg')。
3. sink：subprocess.run(f"{config.COMMAND} {arg}", shell=True)。
4. 跨文件追踪（命令拼接 + shell=True）：
   (a) config.COMMAND 是硬编码，不含用户输入。
   (b) 但 f"{config.COMMAND} {arg}" 拼接了用户输入 arg 到命令字符串。
   (c) shell=True 启动 /bin/sh -c 解释完整命令字符串。
   (d) arg = "; rm -rf /" → shell 执行 "echo hello ; rm -rf /" → 两条命令。
   (e) config.COMMAND 不可控不代表整个命令字符串安全——拼接点在 arg。
5. 结论：f-string 拼接用户输入 + shell=True，存在 CWE-78 命令注入。"""
)

# --- J2: 跨文件 safe_execute 内部参数化（安全） ---
add(
    """
# 跨文件：executor.py 提供 safe_execute 函数
# executor.py:
# import subprocess
# def safe_execute(cmd_parts):
#     # cmd_parts 必须是列表，内部强制 shell=False
#     if not isinstance(cmd_parts, list):
#         raise TypeError("cmd_parts must be a list")
#     return subprocess.run(cmd_parts, shell=False, capture_output=True, text=True)

from flask import Flask, request
from executor import safe_execute

app = Flask(__name__)


@app.route("/grep")
def grep():
    pattern = request.args.get("q", "")
    result = safe_execute(["grep", "-i", pattern, "/var/log/app.log"])
    return result.stdout
""",
    "python",
    "ccot_v3_crossfile_safe_execute.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "safe_execute 内部强制使用 shell=False + 列表参数，且校验 cmd_parts 必须是列表。main.py 传入硬编码命令名 + 用户输入 pattern 作为列表参数。pattern 作为 grep 的字面参数，不经 shell 解释",
    "no fix needed",
    """
代码从 executor.py 导入 safe_execute，但不知道 safe_execute 内部实现。如果 safe_execute 内部使用 shell=True，那么 pattern 用户输入可能导致命令注入。应检查 safe_execute 的实现才能判断。""",
    """
问题：模型未追踪跨文件函数实现。代码注释明确说明 safe_execute 内部强制 shell=False + 列表参数 + 类型校验。跨文件审计时应追踪到具体实现，确认安全措施有效后判安全。""",
    """
1. 跨文件源：executor.py 提供 safe_execute（强制 shell=False + 列表参数）。
2. 用户输入源：pattern = request.args.get('q')。
3. sink：safe_execute(["grep", "-i", pattern, "/var/log/app.log"])。
4. 跨文件追踪（验证安全函数实现）：
   (a) safe_execute 内部校验 cmd_parts 必须是 list（否则抛 TypeError）。
   (b) safe_execute 内部调用 subprocess.run(cmd_parts, shell=False)，
       等价于列表形式 + shell=False 的标准安全写法。
   (c) pattern 作为 grep 的字面参数，不经 shell 解释。
   (d) 攻击者传入 pattern="; rm -rf /" → grep 搜索字面字符串 "; rm -rf /"。
5. 结论：safe_execute 内部强制安全参数，无命令注入。代码安全。"""
)

# --- J3: 跨文件白名单映射 + 列表（安全） ---
add(
    """
# 跨文件：config.py 定义命令白名单
# config.py:
# ALLOWED_CMDS = {
#     "list": "/bin/ls",
#     "status": "/usr/bin/git",
#     "check": "/usr/bin/test",
# }

from flask import Flask, request
import subprocess
import config

app = Flask(__name__)


@app.route("/tool")
def tool():
    cmd = request.args.get("cmd", "list")
    arg = request.args.get("arg", "")
    if cmd not in config.ALLOWED_CMDS:
        return "Invalid command", 400
    result = subprocess.run(
        [config.ALLOWED_CMDS[cmd], arg],
        capture_output=True,
        text=True,
        timeout=5
    )
    return result.stdout
""",
    "python",
    "ccot_v3_crossfile_whitelist_map.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "config.ALLOWED_CMDS 是硬编码白名单映射，cmd 只允许 'list'/'status'/'check' 三个值（if not in 则 400）。subprocess.run 使用列表形式 + shell=False（默认），可执行文件路径来自白名单，arg 作为字面参数传入",
    "no fix needed（但 arg 仍可做选项白名单进一步增强）",
    """
代码使用白名单映射 ALLOWED_CMDS，但 arg 是用户输入，可能传入危险参数。例如 cmd=list 时 arg 可以是 \"-la /etc/shadow\"，ls 会列出 /etc/shadow 信息。代码存在信息泄露。""",
    """
问题：模型把信息泄露夸大为安全漏洞。白名单限制了可执行文件路径（只允许 ls/git/test），arg 作为 ls 的参数确实可能列出任意目录（信息泄露），但这是业务逻辑问题，不是 CWE-78 命令注入。白名单 + 列表形式是标准防御方案，arg 的信息泄露应在应用层做目录白名单。""",
    """
1. 跨文件源：config.ALLOWED_CMDS 白名单映射（硬编码）。
2. 用户输入源：cmd 和 arg。
3. sink：subprocess.run([config.ALLOWED_CMDS[cmd], arg], shell=False)。
4. 跨文件追踪（白名单 + 列表）：
   (a) cmd 必须在 ALLOWED_CMDS 白名单中（否则返回 400）。
   (b) ALLOWED_CMDS 映射到硬编码路径（/bin/ls, /usr/bin/git, /usr/bin/test）。
   (c) 可执行文件路径不可控，列表形式 + shell=False，无命令注入。
   (d) arg 用户可控，作为字面参数传入，可能引发信息泄露（业务层应限制）。
5. 结论：白名单映射 + 列表形式无 CWE-78 命令注入。代码安全。"""
)

# --- J4: 跨文件验证函数 + 列表（安全） ---
add(
    """
# 跨文件：helpers.py 提供 validate_path 函数
# helpers.py:
# import os
# def validate_path(user_path, base_dir="/var/data"):
#     abs_path = os.path.abspath(os.path.join(base_dir, user_path))
#     if not abs_path.startswith(base_dir):
#         raise ValueError("Path traversal detected")
#     return abs_path

from flask import Flask, request
import subprocess
from helpers import validate_path

app = Flask(__name__)


@app.route("/read")
def read():
    filename = request.args.get("f", "")
    safe_path = validate_path(filename)
    result = subprocess.run(
        ["cat", safe_path],
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_v3_crossfile_validate_path.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "helpers.validate_path 使用 os.path.abspath + startswith 双重校验，确保解析后的绝对路径以 base_dir 开头。filename 经 validate_path 校验后传入 subprocess.run 列表形式 + shell=False。路径穿越攻击被校验函数阻止",
    "no fix needed",
    """
代码使用 validate_path 校验用户输入，但校验函数可能被绕过。攻击者可以使用符号链接或双重编码绕过 abspath + startswith 检查。代码存在路径穿越漏洞。""",
    """
问题：模型声称 validate_path 可被绕过，但未给出具体 payload。os.path.abspath 会解析所有 ../ 和符号链接为绝对路径，startswith 检查确保路径以 base_dir 开头。双重编码在 Python 的 os.path.abspath 中无效（abspath 调用 os.getcwd() 和 normpath，不涉及 URL 解码）。模型应给出具体可工作的 payload 才能声称绕过。""",
    """
1. 跨文件源：helpers.validate_path（abspath + startswith 校验）。
2. 用户输入源：filename = request.args.get('f')。
3. sink：subprocess.run(['cat', safe_path], shell=False)。
4. 跨文件追踪（验证校验函数实现）：
   (a) validate_path 实现：os.path.abspath(os.path.join(base_dir, user_path))，
       然后 startswith(base_dir) 检查。
   (b) filename = "../../etc/passwd" → abspath 返回 "/etc/passwd"，
       不以 "/var/data" 开头 → 抛 ValueError。
   (c) filename = "safe_file.txt" → abspath 返回 "/var/data/safe_file.txt" → 通过校验。
   (d) 双重编码（如 "%2e%2e"）在 Python os.path.abspath 中无效（不涉及 URL 解码）。
   (e) subprocess.run 列表 + shell=False，safe_path 是校验后的安全路径。
5. 结论：validate_path 校验有效 + 列表形式，无路径穿越和命令注入。代码安全。"""
)

# --- J5: 跨文件格式化字符串注入（漏洞） ---
add(
    """
# 跨文件：settings.py 定义日志命令模板
# settings.py:
# LOG_CMD = "logger {msg}"

from flask import Flask, request
import os
import settings

app = Flask(__name__)


@app.route("/log")
def log():
    message = request.args.get("msg", "")
    os.system(settings.LOG_CMD.format(msg=message))
    return "logged"
""",
    "python",
    "ccot_v3_crossfile_format_string_injection.py",
    True,
    "CWE-78 命令注入",
    "Critical",
    "request.args.get('msg')",
    "os.system(settings.LOG_CMD.format(msg=message))",
    "settings.LOG_CMD 是硬编码模板 'logger {msg}'，但 .format(msg=message) 将用户输入 message 替换到模板中。os.system 等价于 subprocess.run(字符串, shell=True)，启动 /bin/sh -c 解释。message 中的分号、管道等 shell 元字符会被解释执行",
    "改用 subprocess.run(['logger', message], shell=False)，或对 message 使用 shlex.quote 转义",
    """
代码使用 settings.LOG_CMD 模板，模板是硬编码的 logger 命令。message 通过 format 替换到模板中，logger 只是日志工具。os.system 虽然不推荐，但 logger 命令不会执行危险操作。代码安全。""",
    """
问题：模型低估了 os.system + 格式化字符串注入的风险。os.system 等价于 subprocess.run(字符串, shell=True)，message 通过 format 替换后经 /bin/sh 解释。攻击者传入 msg=\"; rm -rf /\" → os.system(\"logger ; rm -rf /\") → shell 执行 logger 和 rm 两条命令。格式化字符串注入与 f-string 拼接风险相同。""",
    """
1. 跨文件源：settings.LOG_CMD = "logger {msg}"（硬编码模板）。
2. 用户输入源：message = request.args.get('msg')。
3. sink：os.system(settings.LOG_CMD.format(msg=message))。
4. 跨文件追踪（格式化字符串注入）：
   (a) settings.LOG_CMD 是硬编码模板，但 {msg} 是占位符，被 message 替换。
   (b) .format(msg=message) 将用户输入注入到命令字符串中。
   (c) os.system 等价于 subprocess.run(字符串, shell=True)，启动 /bin/sh -c。
   (d) message = "; rm -rf /" → os.system("logger ; rm -rf /") → shell 执行两条命令。
   (e) 格式化字符串注入（.format）与 f-string 拼接风险相同。
5. 结论：.format 注入 + os.system(shell=True 语义)，存在 CWE-78 命令注入。"""
)

# --- J6: 跨文件 SQL 注入（漏洞） ---
add(
    """
# 跨文件：db.py 提供 get_connection 函数
# db.py:
# import sqlite3
# def get_connection():
#     return sqlite3.connect("app.db")

from flask import Flask, request
from db import get_connection

app = Flask(__name__)


@app.route("/search")
def search():
    table = request.args.get("t", "users")
    conn = get_connection()
    cursor = conn.execute(f"SELECT * FROM {table}")
    rows = cursor.fetchall()
    return str(rows)
""",
    "python",
    "ccot_v3_crossfile_sql_injection.py",
    True,
    "CWE-89 SQL注入",
    "Critical",
    "request.args.get('t')",
    "conn.execute(f'SELECT * FROM {table}')",
    "跨文件追踪：db.py 提供 get_connection 返回数据库连接，main.py 用 f-string 拼接用户输入 table 到 SQL 语句。table 不是参数化查询的值，而是 SQL 标识符（表名），无法用占位符防护。攻击者传入 t=\"users; DROP TABLE users--\" 可以执行 SQL 注入",
    "使用白名单校验表名：if table not in ALLOWED_TABLES: return 400",
    """
代码使用 f-string 拼接 table，但 table 来自用户输入，只是表名。SQL 表名不能用参数化查询的占位符，所以拼接是合理的。而且 get_connection 返回的是 sqlite3 连接，sqlite3 不支持多语句执行（DROP TABLE 不会被执行）。代码安全。""",
    """
问题：模型误以为 sqlite3 不支持多语句执行。实际上 sqlite3 的 execute() 确实不支持多语句，但 conn.execute() 可以通过分号注入 UNION SELECT 等单语句攻击。例如 t=\"users UNION SELECT password FROM admin--\" 可以读取 admin 表的密码。表名拼接的 SQL 注入应使用白名单而非参数化查询。""",
    """
1. 跨文件源：db.py 提供 get_connection（返回 sqlite3 连接）。
2. 用户输入源：table = request.args.get('t')。
3. sink：conn.execute(f"SELECT * FROM {table}")。
4. 跨文件追踪（SQL 标识符注入）：
   (a) get_connection 返回 sqlite3 连接，数据库类型确定。
   (b) f-string 拼接 table 到 SQL 语句 → SQL 标识符注入。
   (c) sqlite3 的 execute() 不支持多语句，但 UNION SELECT 是单语句攻击：
       t="users UNION SELECT password FROM admin--" → 读取 admin 表密码。
   (d) 表名不能用 ? 占位符防护（占位符只适用于值，不适用于标识符）。
   (e) 正确防护是白名单校验：if table not in ALLOWED_TABLES: return 400。
5. 结论：f-string 拼接表名到 SQL 语句，存在 CWE-89 SQL 注入。"""
)

# --- J7: 跨文件权限检查 + 命令注入（漏洞：权限检查不消除注入） ---
add(
    """
# 跨文件：auth.py 提供 is_admin 函数
# auth.py:
# def is_admin():
#     return session.get("role") == "admin"

from flask import Flask, request, session
import subprocess
from auth import is_admin

app = Flask(__name__)
app.secret_key = "dev-key"


@app.route("/admin/run")
def admin_run():
    if not is_admin():
        return "Forbidden", 403
    cmd = request.args.get("cmd", "")
    result = subprocess.run(
        f"process {cmd}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_v3_crossfile_auth_but_injection.py",
    True,
    "CWE-78 命令注入",
    "Critical",
    "request.args.get('cmd')",
    "subprocess.run(f'process {cmd}', shell=True)",
    "虽然 is_admin() 做了权限检查（只有 admin 角色可以访问），但权限检查不消除命令注入漏洞。admin 用户同样可以通过 cmd 注入 shell 元字符执行任意命令。权限检查只限制了谁可以触发漏洞，不改变漏洞的存在",
    "改用 subprocess.run(['process', cmd], shell=False) 列表形式",
    """
代码做了权限检查 is_admin()，只有管理员才能访问此端点。管理员是可信用户，不会故意注入恶意命令。f-string + shell=True 在管理员场景下是可接受的。代码安全。""",
    """
问题：模型误以为权限检查消除了命令注入漏洞。权限检查只限制了谁可以触发漏洞（admin 角色），但：(a) admin 角色可能通过 session 劫持、CSRF 等方式被冒用；(b) 即使是真正的 admin，也可能无意中触发命令注入（如 cmd 含意外字符）；(c) 命令注入是代码缺陷，与访问控制是独立的安全维度。CWE-78 判定不因权限检查而改变。""",
    """
1. 跨文件源：auth.is_admin() 权限检查（admin 角色）。
2. 用户输入源：cmd = request.args.get('cmd')。
3. sink：subprocess.run(f"process {cmd}", shell=True)。
4. 跨文件追踪（权限检查 ≠ 漏洞消除）：
   (a) is_admin() 检查 session 角色，只有 admin 可以访问端点。
   (b) 但权限检查不改变 subprocess.run 的执行方式——shell=True + f-string 拼接。
   (c) cmd = "; rm -rf /" → subprocess.run("process ; rm -rf /", shell=True) → 两条命令。
   (d) 权限检查是访问控制（CWE-862/306），命令注入是代码缺陷（CWE-78），两者独立。
   (e) admin 角色可能被 session 劫持或 CSRF 冒用，不应假设 admin 完全可信。
5. 结论：权限检查不消除命令注入，存在 CWE-78 命令注入漏洞。"""
)


# ===========================================================================
# 类别 K: 缺失功能类型 / missing feature（7 条）
# 覆盖之前回归的漏洞类型：
#   - CSRF
#   - 缺失授权
#   - 整数溢出
#   - 缺失认证
#   - Session 固定
#   - 开放重定向
#   - Clickjacking
# ===========================================================================

# --- K1: CSRF 缺失（漏洞：CWE-352） ---
add(
    """
from flask import Flask, request, session, redirect

app = Flask(__name__)
app.secret_key = "dev-key"


@app.route("/change_email", methods=["POST"])
def change_email():
    # 无 CSRF token 验证，但修改了 session 关联数据
    new_email = request.form.get("email", "")
    user_id = session.get("user_id")
    if user_id:
        db.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
    return redirect("/profile")


@app.route("/profile")
def profile():
    return "Profile page"
""",
    "python",
    "ccot_v3_csrf_missing.py",
    True,
    "CWE-352 CSRF",
    "High",
    "攻击者构造的跨站请求",
    "POST /change_email 端点",
    "/change_email 端点接受 POST 请求修改用户邮箱，但没有验证 CSRF token。攻击者可以构造恶意网页，诱使已登录用户访问，自动提交表单修改邮箱。虽然使用了 session 验证用户身份，但 session cookie 在跨站请求中会自动携带",
    "在 POST 表单中添加 CSRF token，服务端验证 token 匹配后再处理请求",
    """
代码使用 session 验证用户身份，只有登录用户才能修改邮箱。session 机制本身提供了认证保护。虽然缺少 CSRF token，但浏览器同源策略会阻止跨站请求。代码安全。""",
    """
问题：模型对 CSRF 攻击机制理解不足。浏览器的同源策略不阻止表单提交——攻击者可以在自己的网站放置 <form action=\"http://victim.com/change_email\" method=\"POST\"> 标签，诱使已登录用户访问并自动提交。session cookie 会在跨站 POST 请求中自动携带（浏览器的 cookie 默认行为），因此服务端无法区分是用户主动操作还是被诱导的跨站请求。""",
    """
1. 污染源：攻击者构造的跨站 POST 请求。
2. 危险 sink：/change_email 端点修改用户邮箱。
3. 数据流追踪：攻击者网页 → 自动提交表单 → 用户浏览器发送 POST（含 session cookie）→ 服务端处理。
4. 防御检查（无 CSRF 防护）：
   (a) 端点接受 POST 请求修改 session 关联数据（邮箱）。
   (b) 没有验证 CSRF token 或 SameSite cookie 属性。
   (c) session cookie 在跨站请求中会自动携带（浏览器默认行为）。
   (d) 攻击者构造恶意网页，包含自动提交的表单：
       <form action=\"http://victim.com/change_email\" method=\"POST\">
       <input name=\"email\" value=\"attacker@evil.com\">
       </form><script>document.forms[0].submit()</script>
5. 结论：POST 端点无 CSRF 防护，存在 CWE-352 CSRF 漏洞。"""
)

# --- K2: 缺失授权（漏洞：CWE-862） ---
add(
    """
from flask import Flask, request

app = Flask(__name__)


@app.route("/admin/users")
def list_users():
    # 只列出用户列表，无权限检查
    users = db.execute("SELECT id, username, email FROM users")
    return str(users.fetchall())


@app.route("/admin/config")
def get_config():
    # 返回系统配置，无权限检查
    config = db.execute("SELECT key, value FROM system_config")
    return str(config.fetchall())
""",
    "python",
    "ccot_v3_missing_authorization.py",
    True,
    "CWE-862 缺失授权",
    "High",
    "任意未授权用户",
    "/admin/users 和 /admin/config 端点",
    "/admin/users 和 /admin/config 端点返回敏感数据（用户列表、系统配置），但没有做任何授权检查。虽然 URL 路径含 /admin/ 前缀暗示管理功能，但代码中未验证请求者是否具有管理员权限。任意用户均可访问这些端点获取敏感信息",
    "添加授权检查：验证当前用户角色是否为 admin，否则返回 403",
    """
代码路径含 /admin/ 前缀，说明这些是管理端点。Flask 路由本身不提供权限控制，但 Web 服务器（如 nginx）或中间件可能已配置了访问控制。仅凭代码片段无法判定缺失授权。代码安全。""",
    """
问题：模型假设存在外部访问控制，但代码中没有体现。安全审计应基于代码实际内容判断——代码中无任何授权检查（无 session 验证、无角色检查、无装饰器）。如果依赖外部访问控制，代码应包含相关注释或中间件调用。仅凭路径前缀 /admin/ 不等于有访问控制。""",
    """
1. 污染源：任意用户发送的 HTTP 请求。
2. 危险 sink：/admin/users 和 /admin/config 端点返回敏感数据。
3. 数据流追踪：任意请求 → Flask 路由处理 → 查询数据库 → 返回敏感数据。
4. 防御检查（无授权）：
   (a) /admin/users 端点：无 session 验证、无角色检查、无装饰器。
   (b) /admin/config 端点：同上。
   (c) URL 路径前缀 /admin/ 不提供任何访问控制——仅是命名约定。
   (d) 任意用户（包括未登录用户）均可访问这两个端点。
5. 结论：管理端点无授权检查，存在 CWE-862 缺失授权漏洞。"""
)

# --- K3: 整数溢出（漏洞：CWE-190） ---
add(
    """
from flask import Flask, request

app = Flask(__name__)


@app.route("/alloc")
def alloc():
    size = int(request.args.get("size", "0"))
    # 用用户输入的 size 分配缓冲区
    buffer = bytearray(size)
    return f"Allocated {len(buffer)} bytes"
""",
    "python",
    "ccot_v3_integer_overflow.py",
    True,
    "CWE-190 整数溢出",
    "Medium",
    "request.args.get('size')",
    "bytearray(size)",
    "用户输入 size 经 int() 转换后传给 bytearray()。Python 的 int 是任意精度，不会溢出。但 bytearray(size) 在 size 很大时会尝试分配大量内存。攻击者传入 size=999999999999 会导致 MemoryError 或系统 OOM。虽然 Python 不会发生传统 C 意义上的整数溢出，但缺少对 size 的范围检查仍构成资源耗尽风险",
    "添加范围检查：if size < 0 or size > MAX_BUFFER_SIZE: return 400",
    """
Python 的 int 是任意精度整数，不会发生整数溢出。bytearray(size) 在 Python 中也是安全的——如果 size 过大，Python 会抛 MemoryError 而不是像 C 那样溢出分配小缓冲区。代码安全。""",
    """
问题：模型用 C 语言的整数溢出概念套用 Python，确实 Python 的 int 不会溢出。但缺少范围检查仍有风险：(a) 攻击者传入 size=999999999999 导致 MemoryError 或 OOM，属于拒绝服务（CWE-400 资源耗尽）；(b) 更危险的是如果代码后续将 size 传递给 C 扩展或 ctypes 调用，Python 层不溢出不代表 C 层不溢出；(c) 即使是 Python 层面的 bytearray，极大 size 也会耗尽系统内存。""",
    """
1. 污染源：size = int(request.args.get('size'))。
2. 危险 sink：bytearray(size)。
3. 数据流追踪：size → int 转换 → bytearray 分配。
4. 漏洞分析（整数溢出 / 资源耗尽）：
   (a) Python 的 int 是任意精度，不会发生传统 C 意义上的整数溢出。
   (b) 但 bytearray(size) 在 size 很大时（如 999999999999）会尝试分配大量内存。
   (c) 攻击者传入极大值 → MemoryError 或系统 OOM → 拒绝服务。
   (d) 如果 size 为负数，bytearray(-1) 抛 ValueError（Python 保护）。
   (e) 缺少对 size 的范围检查是 CWE-190 整数溢出范畴（虽 Python 不溢出，但未做边界校验）。
5. 结论：缺少 size 范围检查，存在 CWE-190 整数溢出风险（Medium，资源耗尽）。"""
)

# --- K4: 缺失认证（漏洞：CWE-306） ---
add(
    """
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/api/delete_user", methods=["POST"])
def delete_user():
    user_id = request.json.get("user_id")
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return jsonify({"status": "deleted"})


@app.route("/api/export_data")
def export_data():
    data = db.execute("SELECT * FROM users")
    return jsonify([dict(row) for row in data.fetchall()])
""",
    "python",
    "ccot_v3_missing_authentication.py",
    True,
    "CWE-306 缺失认证",
    "Critical",
    "任意未认证用户",
    "/api/delete_user 和 /api/export_data 端点",
    "/api/delete_user 和 /api/export_data 端点执行敏感操作（删除用户、导出全部数据），但没有任何认证检查。攻击者无需登录即可调用这些 API。delete_user 允许删除任意用户，export_data 允许导出所有用户数据",
    "添加认证中间件或装饰器，验证请求者身份（如 Bearer token / session / API key）",
    """
代码是 API 端点，可能部署在内部网络或有 API 网关提供认证。仅凭代码片段无法判定缺失认证。代码安全。""",
    """
问题：模型假设存在外部认证机制，但代码中没有体现。安全审计应基于代码实际内容——两个端点均无认证检查（无 token 验证、无 session 检查、无认证装饰器）。delete_user 执行 DELETE 操作，export_data 返回全部用户数据，这些都是敏感操作，必须有认证保护。""",
    """
1. 污染源：任意未认证用户的 HTTP 请求。
2. 危险 sink：/api/delete_user（删除用户）和 /api/export_data（导出数据）。
3. 数据流追踪：任意请求 → Flask 路由 → 无认证检查 → 执行敏感操作。
4. 防御检查（无认证）：
   (a) /api/delete_user：无 token 验证、无 session 检查、无认证装饰器。
   (b) /api/export_data：同上。
   (c) 任意用户（包括匿名用户）均可调用这些 API。
   (d) delete_user 可删除任意用户（user_id 用户可控），export_data 返回全部数据。
5. 结论：敏感 API 端点无认证保护，存在 CWE-306 缺失认证漏洞。"""
)

# --- K5: Session 固定（漏洞：CWE-384） ---
add(
    """
from flask import Flask, request, session, redirect

app = Flask(__name__)
app.secret_key = "dev-key"


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    user = db.execute("SELECT * FROM users WHERE username = ? AND password = ?",
                      (username, password)).fetchone()
    if user:
        # 登录成功，但未重新生成 session ID
        session["user_id"] = user["id"]
        session["role"] = user["role"]
    return redirect("/profile")


@app.route("/profile")
def profile():
    if "user_id" not in session:
        return "Not logged in", 401
    return f"Hello, user {session['user_id']}"
""",
    "python",
    "ccot_v3_session_fixation.py",
    True,
    "CWE-384 Session固定",
    "Medium",
    "攻击者预设的 session ID",
    "session 对象（登录后未重新生成 ID）",
    "登录成功后，代码将用户信息写入 session，但未调用 session.regenerate() 或类似方法重新生成 session ID。攻击者可以先获取一个有效的 session ID，诱使受害者使用该 session ID 登录，然后攻击者使用相同 session ID 访问受害者账户",
    "登录成功后重新生成 session ID：session.regenerate()（Flask 需要手动实现或使用 Flask-Login）",
    """
代码使用 Flask 的 session 机制，Flask 的 session 基于 JWT（签名 cookie），不是传统的服务端 session。JWT 方式不存在 session 固定问题，因为 cookie 内容是签名的不透明 token。代码安全。""",
    """
问题：模型混淆了 Flask 的 session 实现。Flask 的默认 session 确实基于签名 cookie（itsdangerous），不是传统服务端 session。但 session 固定攻击不限于服务端 session——攻击者可以：(a) 在受害者浏览器中设置预设的 session cookie；(b) 受害者使用该 cookie 登录后，session 数据被更新但 cookie 值不变（因为 Flask 不自动轮换 cookie）；(c) 攻击者拥有相同的签名 cookie，可以读取更新后的 session 数据。Flask 应在登录后调用 session.modify() 或清除后重建 session。""",
    """
1. 污染源：攻击者预设的 session cookie。
2. 危险 sink：session 对象（登录后未轮换）。
3. 数据流追踪：攻击者设置 cookie → 受害者使用该 cookie 登录 → session 数据更新但 cookie 不变 → 攻击者用相同 cookie 访问。
4. 防御检查（无 session 轮换）：
   (a) 登录成功后，代码只设置 session["user_id"] 和 session["role"]。
   (b) 未调用 session.regenerate() 或清除旧 session 后重建。
   (c) Flask 的签名 cookie 在 session 内容变更时会重新签名，
       但如果攻击者已知旧签名密钥（如硬编码 secret_key="dev-key"），
       可以伪造任意 session。
   (d) 更严重的是，攻击者可以先访问获取有效 session cookie，
       诱使受害者使用该 cookie 登录，然后攻击者用相同 cookie 访问。
5. 结论：登录后未重新生成 session，存在 CWE-384 Session 固定漏洞。"""
)

# --- K6: 开放重定向（漏洞：CWE-601） ---
add(
    """
from flask import Flask, request, redirect

app = Flask(__name__)


@app.route("/redirect")
def redirect_view():
    url = request.args.get("url", "/")
    return redirect(url)
""",
    "python",
    "ccot_v3_open_redirect.py",
    True,
    "CWE-601 开放重定向",
    "Medium",
    "request.args.get('url')",
    "redirect(url)",
    "用户输入 url 直接传给 Flask 的 redirect() 函数，无任何校验。攻击者可以构造 url=\"https://evil.com\"，诱使受害者点击 https://victim.com/redirect?url=https://evil.com，受害者会被重定向到恶意网站。URL 看起来属于受害站点，增加钓鱼可信度",
    "校验 url 必须是相对路径或白名单域名：if not url.startswith('/') or url.startswith('//'): return 400",
    """
代码使用 Flask 的 redirect 函数，url 参数虽然用户可控，但 redirect 只是返回 HTTP 302 响应。浏览器地址栏会显示目标 URL，用户可以看到被重定向到了恶意网站。重定向本身不是漏洞。代码安全。""",
    """
问题：模型低估了开放重定向的钓鱼风险。开放重定向的价值不在于技术危害，而在于社工攻击：URL https://victim.com/redirect?url=https://evil.com 看起来属于 victim.com（域名可信），用户可能不会仔细检查重定向目标。攻击者可以利用此信任关系进行钓鱼攻击。OWASP 和 CWE 均将其列为漏洞。""",
    """
1. 污染源：url = request.args.get('url')。
2. 危险 sink：redirect(url)。
3. 数据流追踪：url → redirect() → HTTP 302 Location 头。
4. 防御检查（无校验）：
   (a) url 未做任何校验，可以是任意 URL（包括外部域名）。
   (b) 攻击者构造 https://victim.com/redirect?url=https://evil.com，
       受害者点击后被重定向到 evil.com。
   (c) 受害者可能信任 victim.com 域名，不会仔细检查重定向目标。
   (d) 攻击者可利用此进行钓鱼攻击（如伪造登录页面窃取密码）。
   (e) 更危险的绕过：url="//evil.com"（协议相对 URL），
       浏览器会跳转到 https://evil.com，仅检查 url.startswith('/') 不够。
5. 结论：无 URL 校验的开放重定向，存在 CWE-601 开放重定向漏洞。"""
)

# --- K7: Clickjacking（漏洞：CWE-1021） ---
add(
    """
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "dev-key"


@app.route("/transfer", methods=["POST"])
def transfer():
    if "user_id" not in session:
        return "Not logged in", 401
    recipient = request.form.get("recipient", "")
    amount = request.form.get("amount", "0")
    db.execute("INSERT INTO transfers (from_user, to_user, amount) VALUES (?, ?, ?)",
               (session["user_id"], recipient, amount))
    return "Transfer successful"


@app.after_request
def set_headers(response):
    # 未设置 X-Frame-Options 或 Content-Security-Policy 的 frame-ancestors
    return response
""",
    "python",
    "ccot_v3_clickjacking.py",
    True,
    "CWE-1021 Clickjacking",
    "Medium",
    "攻击者构造的 iframe 页面",
    "/transfer 端点（可被 iframe 嵌入）",
    "代码的 /transfer 端点执行资金转账操作（需要登录），但 after_request 中未设置 X-Frame-Options 或 Content-Security-Policy 的 frame-ancestors 指令。攻击者可以将目标页面嵌入自己的 iframe，用透明层覆盖，诱使已登录用户在不知情的情况下点击转账按钮",
    "在 after_request 中添加：response.headers['X-Frame-Options'] = 'DENY'，或设置 CSP frame-ancestors 'none'",
    """
代码使用 session 认证用户，只有登录用户才能转账。转账操作需要用户主动点击提交按钮。即使用 iframe 嵌入，用户仍需主动操作。Clickjacking 攻击不太可能在实际中成功。代码安全。""",
    """
问题：模型低估了 Clickjacking 攻击的可行性。Clickjacking 的核心是"视觉欺骗"——攻击者在 iframe 上覆盖透明层，将用户的点击重定向到隐藏的转账按钮。用户以为点击的是"领取奖品"按钮，实际点击的是 iframe 中的"转账"按钮。因为用户已登录，session cookie 会自动携带，转账请求合法。""",
    """
1. 污染源：攻击者构造的包含 iframe 的恶意页面。
2. 危险 sink：/transfer 端点（可被 iframe 嵌入执行转账）。
3. 数据流追踪：攻击者页面 → iframe 加载 /transfer → 透明层覆盖 → 用户误点击 → 转账执行。
4. 防御检查（无点击劫持防护）：
   (a) after_request 中未设置 X-Frame-Options 头。
   (b) 未设置 Content-Security-Policy 的 frame-ancestors 指令。
   (c) /transfer 端点可被任意网站通过 iframe 嵌入。
   (d) 攻击者在 iframe 上覆盖透明层，将用户点击重定向到隐藏的转账按钮。
   (e) 用户已登录（session 有效），转账请求合法执行。
5. 结论：缺少 X-Frame-Options / CSP frame-ancestors 防护，存在 CWE-1021 Clickjacking 漏洞。"""
)


# ===========================================================================
# 类别 L: 安全噪声 / 安全代码（8 条）
# 覆盖安全写法和安全模式，减少误报：
#   - 硬编码命令
#   - 路径穿越 vs 路径校验
#   - 参数化查询
#   - XSS 防护
#   - 安全反序列化
#   - 安全随机数
#   - 安全密码哈希
#   - 安全 JWT 验证
#   - 参数化 + 硬编码凭证（硬编码凭证仍是漏洞）
# ===========================================================================

# --- L1: subprocess.run 硬编码命令（安全） ---
add(
    """
import subprocess

result = subprocess.run(
    ["git", "status"],
    capture_output=True,
    text=True
)
print(result.stdout)
""",
    "python",
    "ccot_v3_hardcoded_git_status.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.run(['git', 'status']) 使用硬编码命令列表，无任何用户输入参与。列表形式 + shell=False（默认），git 执行固定的 status 子命令",
    "no fix needed",
    """
subprocess 执行外部命令，git 命令可能有安全风险。git status 会泄露仓库信息，如果仓库包含敏感数据可能导致信息泄露。代码存在安全风险。""",
    """
问题：模型夸大风险，忽略了"硬编码命令"这一关键事实。命令注入的前提是用户可控输入进入命令字符串。本代码命令是硬编码列表 ['git', 'status']，不含任何变量、函数参数或外部输入。即使 git 命令本身有某些行为（如显示仓库状态），也不构成安全漏洞。""",
    """
1. 污染源扫描：检查 request.args / input() / sys.argv / 函数参数 —— 均未出现。
2. 危险 sink：subprocess.run(['git', 'status'])。
3. 数据流追踪：命令列表 ['git', 'status'] 是硬编码字面量，无外部数据流入。
4. 防御评估：
   (a) 命令注入的前提是用户可控输入进入命令字符串。本代码不满足此前提。
   (b) 列表形式 + shell=False，参数直接传给 execvp。
   (c) git status 是只读操作，不修改文件或执行危险操作。
5. 结论：硬编码命令 + 无用户输入，代码安全。"""
)

# --- L2: os.path.join 无 abspath 检查（漏洞：路径穿越） ---
add(
    """
import os
from flask import Flask, request, send_file

app = Flask(__name__)

BASE_DIR = "/var/data/files"


@app.route("/download")
def download():
    filename = request.args.get("f", "")
    filepath = os.path.join(BASE_DIR, filename)
    return send_file(filepath)
""",
    "python",
    "ccot_v3_path_join_no_abspath.py",
    True,
    "CWE-22 路径穿越",
    "High",
    "request.args.get('f')",
    "send_file(filepath)",
    "os.path.join(BASE_DIR, filename) 将用户输入 filename 拼接到基础目录路径。但 os.path.join 在 filename 以 / 开头时会忽略 BASE_DIR（返回 filename），在 filename 含 ../ 时不会阻止路径穿越。攻击者传入 f=\"../../etc/passwd\" 可以读取任意文件",
    "使用 os.path.abspath + startswith 校验：if not os.path.abspath(filepath).startswith(BASE_DIR): return 403",
    """
代码使用 os.path.join 拼接路径，os.path.join 是 Python 标准库函数，会正确处理路径分隔符。filename 是用户输入但只是文件名，不会导致路径穿越。代码安全。""",
    """
问题：模型对 os.path.join 的行为理解不足。os.path.join 有两个关键行为：(a) 如果 filename 以 / 开头，os.path.join 返回 filename（忽略 BASE_DIR），攻击者传入 f=\"/etc/passwd\" 可读取任意绝对路径文件；(b) 如果 filename 含 ../，os.path.join 不会阻止路径穿越，os.path.join(\"/var/data/files\", \"../../etc/passwd\") 返回 \"/var/data/files/../../etc/passwd\"，操作系统解析为 \"/etc/passwd\"。""",
    """
1. 污染源：filename = request.args.get('f')。
2. 危险 sink：send_file(filepath)。
3. 数据流追踪：filename → os.path.join → filepath → send_file。
4. 漏洞分析（路径穿越）：
   (a) os.path.join(BASE_DIR, filename) 在 filename 以 / 开头时返回 filename。
       f=\"/etc/passwd\" → filepath=\"/etc/passwd\" → send_file 读取 /etc/passwd。
   (b) os.path.join(BASE_DIR, \"../../etc/passwd\") 返回 \"/var/data/files/../../etc/passwd\"，
       操作系统解析为 \"/etc/passwd\"。
   (c) 没有使用 os.path.abspath + startswith 校验路径是否在 BASE_DIR 内。
   (d) send_file 会读取并返回任意文件内容。
5. 结论：os.path.join 无路径校验，存在 CWE-22 路径穿越漏洞。"""
)

# --- L3: os.path.abspath + startswith 校验（安全） ---
add(
    """
import os
from flask import Flask, request, send_file

app = Flask(__name__)

BASE_DIR = "/var/data/files"


@app.route("/download")
def download():
    filename = request.args.get("f", "")
    filepath = os.path.join(BASE_DIR, filename)
    abs_path = os.path.abspath(filepath)
    if not abs_path.startswith(BASE_DIR):
        return "Access denied", 403
    return send_file(abs_path)
""",
    "python",
    "ccot_v3_abspath_startswith_safe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "代码使用 os.path.abspath + startswith 双重校验：(1) abspath 将 filepath 解析为绝对路径（展开所有 ../ 和符号链接）；(2) startswith 确保解析后的路径以 BASE_DIR 开头。filename 含 ../ 或以 / 开头时，abspath 会解析出 BASE_DIR 之外的路径，startswith 检查失败返回 403",
    "no fix needed",
    """
startswith 检查可以被绕过。攻击者可以构造 filename 使 abspath 返回以 BASE_DIR 前缀开头但实际指向其他目录的路径。例如 BASE_DIR=\"/var/data\"，攻击者构造 filename 使路径为 \"/var/data_evil/../../etc/passwd\"，abspath 解析为 \"/etc/passwd\"，但 startswith(\"/var/data\") 会匹配 \"/var/data_evil\" 前缀。代码不安全。""",
    """
问题：模型的绕过 payload 不成立。abspath 解析 \"/var/data_evil/../../etc/passwd\" 的结果取决于目录结构，但 startswith(\"/var/data\") 检查的是完整前缀。\"/var/data_evil\" 确实以 \"/var/data\" 开头，但 abspath 会将 \"/var/data_evil/../../etc/passwd\" 解析为实际路径（取决于 /var/data_evil 是否存在）。即使匹配了前缀，send_file 也只能发送 BASE_DIR 下的文件。更正确的做法是 BASE_DIR 以 / 结尾（\"/var/data/files/\"），防止前缀匹配绕过。""",
    """
1. 污染源：filename = request.args.get('f')。
2. 危险 sink：send_file(abs_path)。
3. 数据流追踪：filename → os.path.join → os.path.abspath → startswith 校验 → send_file。
4. 防御评估（abspath + startswith）：
   (a) os.path.abspath(filepath) 解析所有 ../ 和符号链接为绝对路径。
   (b) startswith(BASE_DIR) 确保解析后的路径在 BASE_DIR 目录下。
   (c) filename = \"../../etc/passwd\" → abspath 返回 \"/etc/passwd\"，
       不以 \"/var/data/files\" 开头 → startswith 失败 → 返回 403。
   (d) filename = \"/etc/passwd\" → abspath 返回 \"/etc/passwd\" → 同样失败。
   (e) 这是路径穿越的标准防御方案，有效阻止路径穿越。
5. 结论：abspath + startswith 双重校验有效，代码安全。"""
)

# --- L4: 参数化查询（安全） ---
add(
    """
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    uid = request.args.get("id", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return str(cursor.fetchone())
""",
    "python",
    "ccot_v3_parameterized_query_safe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "conn.execute(\"SELECT * FROM users WHERE id = ?\", (uid,)) 使用问号占位符 + 参数元组，这是参数化查询的标准写法。数据库驱动会自动转义 uid，即使 uid 含 SQL 元字符也不会被解释为 SQL 语法",
    "no fix needed",
    """
用户输入 uid 直接传入 SQL 查询，可能存在 SQL 注入。虽然代码用了占位符，但 ? 占位符可能不被所有数据库驱动正确处理。代码存在安全风险。""",
    """
问题：模型对参数化查询的理解不足。? 占位符 + 参数元组是 Python DB-API 2.0 标准的参数化查询写法，所有符合标准的数据库驱动（包括 sqlite3）都正确处理。uid 不会作为 SQL 语法被解释，只作为字面值绑定到占位符位置。这是 SQL 注入的标准防御方案。""",
    """
1. 污染源：uid = request.args.get('id')。
2. 危险 sink：conn.execute(\"SELECT * FROM users WHERE id = ?\", (uid,))。
3. 数据流追踪：uid → 参数元组 → 参数化绑定 → SQL 执行。
4. 防御评估（参数化查询）：
   (a) 使用 ? 占位符 + (uid,) 参数元组，这是参数化查询的标准写法。
   (b) 数据库驱动在执行前将 uid 作为字面值绑定，不作为 SQL 语法解释。
   (c) uid = \"1 OR 1=1\" → 绑定为字面字符串 \"1 OR 1=1\"，不是 SQL 条件。
   (d) uid = \"1; DROP TABLE users\" → 绑定为字面字符串，不执行 DROP。
5. 结论：参数化查询有效防止 SQL 注入，代码安全。"""
)

# --- L5: html.escape XSS 防护（安全） ---
add(
    """
import html
from flask import Flask, request

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    safe_name = html.escape(name)
    return f"<h1>Hello, {safe_name}!</h1>"
""",
    "python",
    "ccot_v3_html_escape_safe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "html.escape(name) 将 <, >, &, \", ' 等 HTML 特殊字符转义为实体引用（&lt;, &gt;, &amp;, &quot;, &#x27;）。safe_name 拼接到 HTML 模板中时，浏览器不会将转义后的字符解释为 HTML 标签或属性",
    "no fix needed",
    """
代码使用 html.escape 转义用户输入，但 f-string 拼接到 HTML 模板中仍然有风险。html.escape 可能不覆盖所有 XSS 向量，例如事件处理器属性（onerror, onclick）可能绕过转义。代码存在 XSS 风险。""",
    """
问题：模型高估了 XSS 绕过的可能性。html.escape 转义 <, >, &, \", ' 五种字符，这五种字符覆盖了所有 HTML 标签注入和属性注入的路径。f\"<h1>Hello, {safe_name}!</h1>\" 中 safe_name 出现在标签内容（非属性值），html.escape 已经足够。事件处理器（onerror 等）需要 < 或 \" 等字符才能注入属性，这些都被转义了。""",
    """
1. 污染源：name = request.args.get('name')。
2. 危险 sink：f\"<h1>Hello, {safe_name}!</h1>\" 返回 HTML 响应。
3. 数据流追踪：name → html.escape → f-string 拼接 → HTTP 响应。
4. 防御评估（html.escape）：
   (a) html.escape(name) 转义 <, >, &, \", ' 为 HTML 实体引用。
   (b) name = \"<script>alert(1)</script>\" → safe_name = \"&lt;script&gt;alert(1)&lt;/script&gt;\"。
   (c) 浏览器渲染 <h1>Hello, &lt;script&gt;... 时，不执行 script 标签。
   (d) name = \"onerror=alert(1)\" → safe_name = \"onerror=alert(1)\"（不含 < 或 \"，无法注入属性）。
   (e) html.escape 在 HTML 内容上下文中提供完整 XSS 防护。
5. 结论：html.escape 有效防止 XSS，代码安全。"""
)

# --- L6: yaml.safe_load 安全反序列化（安全） ---
add(
    """
import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/config")
def load_config():
    raw = request.args.get("data", "")
    config = yaml.safe_load(raw)
    return str(config)
""",
    "python",
    "ccot_v3_yaml_safe_load.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "yaml.safe_load(raw) 只解析 YAML 基本类型（str, int, list, dict 等），不构造任意 Python 对象。与 yaml.load 不同（后者可以反序列化任意 Python 对象，如 !!python/object/apply:os.system），safe_load 不支持 YAML 标签构造器，因此不存在不安全反序列化风险",
    "no fix needed",
    """
yaml.safe_load 虽然比 yaml.load 安全，但仍然可能解析出意外的数据类型。用户输入 raw 可能包含特殊 YAML 构造，如 YAML 锚点和别名可以导致资源耗尽（Billion Laughs 攻击）。代码存在安全风险。""",
    """
问题：模型把 YAML Billion Laughs 攻击与不安全反序列化混淆。Billion Laughs 攻击是 YAML 解析的 DoS 问题（CWE-400 资源耗尽），不是 CWE-502 不安全反序列化。yaml.safe_load 的安全保证是"不构造任意 Python 对象"，即不存在代码执行风险。Billion Laughs 是另一类问题，应在应用层限制 YAML 输入大小。""",
    """
1. 污染源：raw = request.args.get('data')。
2. 危险 sink：yaml.safe_load(raw)。
3. 数据流追踪：raw → yaml.safe_load → config 对象。
4. 防御评估（safe_load）：
   (a) yaml.safe_load 只解析基本 YAML 类型，不构造任意 Python 对象。
   (b) 与 yaml.load（可反序列化 !!python/object/apply:os.system）不同，
       safe_load 不支持 YAML 标签构造器。
   (c) raw = \"!!python/object/apply:os.system ['rm -rf /']\" → safe_load 报错（不识别标签）。
   (d) raw = \"key: value\" → safe_load 返回 {\"key\": \"value\"}（正常数据）。
   (e) Billion Laughs 攻击是 DoS 问题（CWE-400），不是 CWE-502 不安全反序列化。
5. 结论：yaml.safe_load 提供安全的 YAML 解析，无 CWE-502 不安全反序列化。代码安全。"""
)

# --- L7: secrets.token_hex 安全随机数（安全） ---
add(
    """
import secrets
from flask import Flask

app = Flask(__name__)


@app.route("/token")
def generate_token():
    token = secrets.token_hex(32)
    return {"token": token}
""",
    "python",
    "ccot_v3_secrets_token_safe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "secrets.token_hex(32) 使用 os.urandom() 作为随机源，生成密码学安全的随机数。每个字节来自操作系统提供的 CSPRNG（如 /dev/urandom），不可预测、不可重现。适用于生成 token、密钥、会话 ID 等安全敏感场景",
    "no fix needed",
    """
secrets.token_hex 生成的是十六进制字符串，虽然使用了 CSPRNG，但十六进制编码降低了熵密度（每字节只有 4 bit 熵而非 8 bit）。如果需要高安全性的 token，应使用 secrets.token_bytes(32) 获取原始字节。代码存在弱随机数风险。""",
    """
问题：模型对十六进制编码的熵密度有误解。secrets.token_hex(32) 的参数 32 是字节数，生成 32 字节随机数据后编码为 64 个十六进制字符。编码方式不影响原始随机数据的熵——32 字节 = 256 bit 熵，无论编码为十六进制还是 Base64，底层随机性相同。十六进制编码不是"降低安全性"，只是可读性更好的表示形式。""",
    """
1. 污染源扫描：无用户输入参与 token 生成。
2. 危险 sink：secrets.token_hex(32)。
3. 数据流追踪：os.urandom(32) → secrets.token_hex → 64 字符十六进制字符串。
4. 防御评估（secrets 模块）：
   (a) secrets.token_hex(32) 内部调用 os.urandom(32)，使用操作系统的 CSPRNG。
   (b) 32 字节 = 256 bit 熵，密码学安全，不可预测。
   (c) 十六进制编码是表示形式，不影响底层随机性。
   (d) 与 random 模块不同（random 使用 Mersenne Twister，可预测，CWE-330），
       secrets 模块专为安全场景设计。
5. 结论：secrets.token_hex 生成密码学安全随机数，无弱随机数风险。代码安全。"""
)

# --- L8: 参数化查询 + 硬编码凭证（漏洞：硬编码凭证仍是漏洞） ---
add(
    """
import sqlite3
from flask import Flask, request

app = Flask(__name__)

DB_PASSWORD = "SuperSecret123!"
API_KEY = "sk-proj-abc123def456"


@app.route("/user")
def get_user():
    uid = request.args.get("id", "")
    conn = sqlite3.connect(f"app.db")
    cursor = conn.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return str(cursor.fetchone())
""",
    "python",
    "ccot_v3_parameterized_with_hardcoded_secret.py",
    True,
    "CWE-798 硬编码凭证",
    "Critical",
    "源码字面量",
    "DB_PASSWORD = 'SuperSecret123!', API_KEY = 'sk-proj-abc123def456'",
    "代码使用参数化查询防止 SQL 注入（正确的安全写法），但同时包含硬编码凭证：DB_PASSWORD = 'SuperSecret123!' 和 API_KEY = 'sk-proj-abc123def456'。硬编码的字面量凭证本身就是漏洞（CWE-798），不应因其他部分安全而降级",
    "从环境变量读取凭证：DB_PASSWORD = os.environ.get('DB_PASSWORD'), API_KEY = os.environ.get('API_KEY')",
    """
代码使用参数化查询防止 SQL 注入，这是正确的安全写法。DB_PASSWORD 和 API_KEY 虽然是硬编码的，但在本代码片段中没有被实际使用（DB_PASSWORD 没有传入 sqlite3.connect，API_KEY 没有被调用），所以不构成实际漏洞。代码安全。""",
    """
问题：模型以"未被实际使用"为由忽略硬编码凭证。CWE-798 的判定标准是：源码中出现字面量形式的密码/API Key/Secret/Token，无论是否被实际使用，本身就是漏洞。DB_PASSWORD 变量名含 password，赋值为字符串字面量 'SuperSecret123!'——这就是 CWE-798。API_KEY 变量名含 key，赋值为 'sk-proj-abc123def456'（OpenAI API Key 格式）——同样是 CWE-798。""",
    """
1. 污染源：源码中的字面量凭证。
2. 危险 sink：硬编码凭证暴露在源码中。
3. 数据流追踪：DB_PASSWORD = 'SuperSecret123!' → 源码可见 → 任何有权访问源码的人可获取。
4. 漏洞分析（硬编码凭证）：
   (a) DB_PASSWORD = 'SuperSecret123!'：变量名含 password，赋值为字符串字面量。
   (b) API_KEY = 'sk-proj-abc123def456'：变量名含 key，赋值为字符串字面量。
   (c) 符合 CWE-798 判定标准：源码中出现字面量形式的密码/API Key。
   (d) "未被实际使用"不是开脱——凭证暴露在源码中，任何有权访问源码的人可获取。
   (e) 参数化查询是正确的安全写法，但不消除硬编码凭证漏洞。两个问题独立。
5. 结论：硬编码凭证是 CWE-798 漏洞（Critical），与参数化查询的安全写法不冲突。"""
)


# ===========================================================================
# 构建与写入
# ===========================================================================

def build_json_verdict(sample):
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


def build_wrong_verdict(sample):
    """构造错误 JSON 结论块（has_vulnerability 取反）。"""
    wrong_has_vuln = not sample["has_vulnerability"]
    if wrong_has_vuln:
        wrong_vuln_type = sample["vulnerability_type"] if sample["has_vulnerability"] else "CWE-78 命令注入"
        wrong_risk = sample["risk_level"] if sample["has_vulnerability"] else "High"
        wrong_source = sample["source"] if sample["has_vulnerability"] else "用户输入"
        wrong_sink = sample["sink"] if sample["has_vulnerability"] else "subprocess/system 执行"
        wrong_explanation = sample["explanation"] if sample["has_vulnerability"] else "代码存在安全风险，用户输入可能导致命令注入"
        wrong_fix = sample["fix_suggestion"] if sample["has_vulnerability"] else "改用参数化查询或白名单校验"
    else:
        wrong_vuln_type = "none"
        wrong_risk = "None"
        wrong_source = "N/A"
        wrong_sink = "N/A"
        wrong_explanation = "代码经检查未发现安全漏洞，使用了安全写法"
        wrong_fix = "no fix needed"

    verdict = {
        "has_vulnerability": wrong_has_vuln,
        "vulnerability_type": wrong_vuln_type,
        "risk_level": wrong_risk,
        "source": wrong_source,
        "sink": wrong_sink,
        "explanation": wrong_explanation,
        "fix_suggestion": wrong_fix,
    }
    return "```json\n" + json.dumps(verdict, ensure_ascii=False, indent=2) + "\n```"


def build_messages(sample):
    """构建 SFT 格式的 messages。"""
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


def build_dpo_pair(sample):
    """构建 DPO 偏好对格式。"""
    user_content = build_user_prompt(
        code=sample["code"], language=sample["language"],
        filename=sample["filename"],
    )

    prompt = f"<|im_start|>system\n{SYSTEM_PROMPT_LITE}<|im_end|>\n<|im_start|>user\n{user_content}<|im_end|>\n<|im_start|>assistant\n"

    # chosen: 正确推理路径 + 正确 JSON
    correct_json = build_json_verdict(sample)
    chosen = (
        f"{sample['correct_reasoning']}\n\n"
        f"### 最终结论：\n{correct_json}"
    )

    # rejected: 错误推理路径 + 错误 JSON
    wrong_json = build_wrong_verdict(sample)
    rejected = (
        f"{sample['incorrect_reasoning']}\n\n"
        f"### 最终结论：\n{wrong_json}"
    )

    return {
        "prompt": prompt,
        "chosen": chosen,
        "rejected": rejected,
    }


def validate():
    print("\n" + "=" * 60)
    print("验证 CCoT v3 扩展样本")
    print("=" * 60)

    assert len(SAMPLES) >= 30, f"样本数应 >= 30，实际 {len(SAMPLES)}"
    vuln_count = sum(1 for s in SAMPLES if s["has_vulnerability"])
    safe_count = len(SAMPLES) - vuln_count
    print(f"[OK] 样本数: {len(SAMPLES)} (vuln={vuln_count}, safe={safe_count})")

    # 类别分布
    cat_h = [s for s in SAMPLES if s["filename"].startswith("ccot_v3_popen") or
             s["filename"].startswith("ccot_v3_call_list") or
             s["filename"].startswith("ccot_v3_run_fstring") or
             s["filename"].startswith("ccot_v3_executable") or
             s["filename"].startswith("ccot_v3_split_list") or
             s["filename"].startswith("ccot_v3_shlex_split_shell") or
             s["filename"].startswith("ccot_v3_check_output_list")]
    cat_i = [s for s in SAMPLES if s["filename"].startswith("ccot_v3_string_args") or
             s["filename"].startswith("ccot_v3_user_controlled_cmd") or
             s["filename"].startswith("ccot_v3_python_c") or
             s["filename"].startswith("ccot_v3_perl_e") or
             s["filename"].startswith("ccot_v3_find_path") or
             s["filename"].startswith("ccot_v3_tar_path") or
             s["filename"].startswith("ccot_v3_curl_ssrf")]
    cat_j = [s for s in SAMPLES if s["filename"].startswith("ccot_v3_crossfile_")]
    cat_k = [s for s in SAMPLES if s["filename"].startswith("ccot_v3_csrf") or
             s["filename"].startswith("ccot_v3_missing_auth") or
             s["filename"].startswith("ccot_v3_integer") or
             s["filename"].startswith("ccot_v3_session") or
             s["filename"].startswith("ccot_v3_open_redirect") or
             s["filename"].startswith("ccot_v3_clickjacking")]
    cat_l = [s for s in SAMPLES if s["filename"].startswith("ccot_v3_hardcoded") or
             s["filename"].startswith("ccot_v3_path_join") or
             s["filename"].startswith("ccot_v3_abspath") or
             s["filename"].startswith("ccot_v3_parameterized") or
             s["filename"].startswith("ccot_v3_html_escape") or
             s["filename"].startswith("ccot_v3_yaml_safe") or
             s["filename"].startswith("ccot_v3_secrets_")]
    print(f"[OK] 类别分布: H.shell+列表边界={len(cat_h)}, I.subprocess边界={len(cat_i)}, "
          f"J.跨文件={len(cat_j)}, K.缺失功能={len(cat_k)}, L.安全噪声={len(cat_l)}")

    # SFT 格式校验
    for i, sample in enumerate(SAMPLES):
        record = build_messages(sample)
        msgs = record["messages"]
        assert len(msgs) == 3, f"样本{i}: messages 数量 {len(msgs)} != 3"
        assert msgs[0]["role"] == "system"
        assert msgs[1]["role"] == "user"
        assert msgs[2]["role"] == "assistant"
        assert msgs[0]["content"] == SYSTEM_PROMPT_LITE

        assistant = msgs[2]["content"]
        assert "### 错误推理路径" in assistant
        assert "以上推理的问题" in assistant
        assert "### 正确推理路径" in assistant
        assert "### 最终结论" in assistant
        assert "```json" in assistant

        json_match = re.search(r'```json\s*(\{.*?\})\s*```', assistant, re.DOTALL)
        assert json_match, f"样本{i}: 无法提取 JSON 块"
        verdict = json.loads(json_match.group(1))
        for field in ["has_vulnerability", "vulnerability_type", "risk_level",
                      "source", "sink", "explanation", "fix_suggestion"]:
            assert field in verdict, f"样本{i}: 缺少字段 {field}"
        if not sample["has_vulnerability"]:
            assert verdict["vulnerability_type"] == "none"
            assert verdict["risk_level"] == "None"
        else:
            assert verdict["vulnerability_type"] != "none"

    print(f"[OK] 所有 {len(SAMPLES)} 条样本 SFT 格式合规")

    # DPO 格式校验
    for i, sample in enumerate(SAMPLES):
        pair = build_dpo_pair(sample)
        assert "prompt" in pair
        assert "chosen" in pair
        assert "rejected" in pair
        assert "<|im_start|>" in pair["prompt"]
        assert "```json" in pair["chosen"]
        assert "```json" in pair["rejected"]

        # chosen 和 rejected 的 has_vulnerability 必须相反
        chosen_match = re.search(r'"has_vulnerability":\s*(true|false)', pair["chosen"], re.IGNORECASE)
        rejected_match = re.search(r'"has_vulnerability":\s*(true|false)', pair["rejected"], re.IGNORECASE)
        assert chosen_match, f"对{i}: chosen 无法提取 has_vulnerability"
        assert rejected_match, f"对{i}: rejected 无法提取 has_vulnerability"
        chosen_hv = chosen_match.group(1).lower() == "true"
        rejected_hv = rejected_match.group(1).lower() == "true"
        assert chosen_hv != rejected_hv, \
            f"对{i}: chosen({chosen_hv}) 和 rejected({rejected_hv}) 的 has_vulnerability 应相反"

    print(f"[OK] 所有 {len(SAMPLES)} 对 DPO 偏好对格式合规（chosen/rejected 结论相反）")

    # 错误推理与正确推理不重复
    for i, s in enumerate(SAMPLES):
        assert s["incorrect_reasoning"] != s["correct_reasoning"], f"样本{i}"

    # 代码不重复
    codes = [s["code"] for s in SAMPLES]
    assert len(set(codes)) == len(codes), f"代码有重复: {len(set(codes))}/{len(codes)}"
    print(f"[OK] 代码唯一: {len(set(codes))}/{len(codes)}")

    # CoT 不重复
    cots = [s["correct_reasoning"] for s in SAMPLES]
    assert len(set(cots)) == len(cots), f"正确推理有重复"
    print(f"[OK] 正确推理唯一: {len(set(cots))}/{len(cots)}")

    print(f"\n[OK] 所有验证通过")
    return True


def main():
    print(f"共 {len(SAMPLES)} 条 CCoT v3 扩展样本")
    vuln = sum(1 for s in SAMPLES if s["has_vulnerability"])
    safe = len(SAMPLES) - vuln
    print(f"  漏洞样本: {vuln}  安全样本: {safe}")

    validate()

    os.makedirs(os.path.dirname(OUTPUT_SFT), exist_ok=True)

    # 写入 SFT 数据
    with open(OUTPUT_SFT, "w", encoding="utf-8") as f:
        for sample in SAMPLES:
            record = build_messages(sample)
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"\n已写入 SFT: {OUTPUT_SFT}")

    # 写入 DPO 数据
    pairs = [build_dpo_pair(s) for s in SAMPLES]
    with open(OUTPUT_DPO, "w", encoding="utf-8") as f:
        for pair in pairs:
            f.write(json.dumps(pair, ensure_ascii=False) + "\n")
    print(f"已写入 DPO: {OUTPUT_DPO}")

    # 验证写入
    for output_file, expected_count, key in [
        (OUTPUT_SFT, len(SAMPLES), "messages"),
        (OUTPUT_DPO, len(SAMPLES), "prompt"),
    ]:
        count = 0
        with open(output_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                assert key in rec, f"{output_file}: 缺少 {key}"
                count += 1
        assert count == expected_count, f"{output_file}: 期望 {expected_count} 条，实际 {count}"
        print(f"[OK] {output_file.name}: {count} 条有效 JSONL 记录")

    # 统计
    print("\n" + "=" * 60)
    print("生成统计")
    print("=" * 60)
    print(f"SFT 数据: {OUTPUT_SFT}")
    print(f"DPO 数据: {OUTPUT_DPO}")
    print(f"总条数: {len(SAMPLES)}")
    print(f"  漏洞: {vuln} ({vuln/len(SAMPLES)*100:.1f}%)")
    print(f"  安全: {safe} ({safe/len(SAMPLES)*100:.1f}%)")

    # CWE 分布
    cwe_dist = {}
    for s in SAMPLES:
        cwe = s["vulnerability_type"] if s["has_vulnerability"] else "safe"
        cwe_dist[cwe] = cwe_dist.get(cwe, 0) + 1
    print("\nCWE 分布:")
    for cwe, cnt in sorted(cwe_dist.items(), key=lambda x: -x[1]):
        print(f"  {cwe}: {cnt}")


if __name__ == "__main__":
    main()
