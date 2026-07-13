"""
CCoT（Contrastive Chain-of-Thought）扩展 v2 —— 40 条新样本，聚焦：
  D. shell=True + 列表 边界（10 条）
  E. shlex 边界（10 条）
  F. subprocess_run / shell=False 边界（10 条）
  G. 跨文件参数（10 条）

设计依据：docs/改进.md P2「DPO 偏好对」
  原 22 条（supplement_ccot_contrastive.py）已覆盖：
    A. shell=True 偏见（8）  B. SSTI 混淆（8）  C. 结论一致性（6）
  22 条对应 SFT 数据中的 CCoT 增强（train_chatml_v2.jsonl 已含），
  本 v2 扩展的 40 条 **不进入 SFT**，专门用于 DPO 偏好对生成。
  最终 DPO 数据 = 22 + 40 = 62 对偏好。

用法（无需 GPU，纯数据生成）：
  PYTHONPATH=. /home/zane/miniconda3/envs/graproj/bin/python3 \
      experiments/exp_06_finetune/scripts/supplement_ccot_contrastive_v2.py
"""

import json
import os
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import SYSTEM_PROMPT_LITE, build_user_prompt

OUTPUT_FILE = PROJECT_ROOT / "experiments/exp_06_finetune/data/supplement_ccot_contrastive_v2.jsonl"

SAMPLES = []


def add(code, language, filename, has_vulnerability, vuln_type, risk_level,
        source, sink, explanation, fix_suggestion,
        incorrect_reasoning, incorrect_flaw, correct_reasoning):
    """添加一条 CCoT 对比样本（与 v1 add() 同形）。"""
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
# 类别 D: shell=True + 列表 边界（10 条）
# 关键澄清：subprocess.run(列表, shell=True) 中 shell=True 被 execvp 忽略，
# 列表参数仍作为独立 argv 传入，不经 shell 解释。但反过来：
#   subprocess.run("字符串", shell=False) 会把整个字符串当成可执行文件路径，shell=False 时不切分。
# 还要覆盖 shlex.quote + shell=True / shell=False 的细微差别。
# ===========================================================================

# --- D1: 列表 + shell=True（安全：shell=True 被忽略） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/check")
def check():
    name = request.args.get("name", "")
    result = subprocess.run(
        ["test", "-f", name],
        shell=True,
        capture_output=True,
        text=True
    )
    return str(result.returncode)
""",
    "python",
    "ccot_list_shell_true_ignored.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.run 使用列表参数 ['test', '-f', name]，虽然显式 shell=True，但列表形式下 shell=True 会被忽略（Python 文档：args 为列表时 shell=True 仍走 execvp，不经 /bin/sh）。name 作为 test 的字面参数，不会被 shell 解释",
    "no fix needed",
    """
代码同时用列表和 shell=True，互相矛盾，肯定是 bug。攻击者传入 name="; rm -rf /" 会在 shell 解释时执行两条命令。即便列表形式一般安全，shell=True 会覆盖列表形式的安全保证。""",
    """
问题：模型不熟悉 Python subprocess 文档。Python 官方文档明确说明：当 args 是列表时，shell=True 不会让 /bin/sh 解释整个命令，列表元素仍作为独立 argv 传给 execvp。shell=True 仅当 args 是字符串时才生效。这是一个反直觉的边界，但行为是确定的。""",
    """
1. 污染源：request.args.get('name') 获取用户输入。
2. 危险 sink：subprocess.run(['test', '-f', name]) 执行 test 命令。
3. 数据流追踪：name → 列表参数 → subprocess.run(shell=True)。
4. 边界分析（关键：列表 + shell=True 的特殊语义）：
   (a) Python subprocess 文档：当 args 是列表时，shell=True 参数被忽略，列表元素直接传给 execvp。
       这是 Python 解释器的确定性行为，源代码可见。
   (b) 即便 shell=True 不会被忽略，name 作为列表的第三个元素，execvp 会把它作为 test 的字面参数，
       不会触发 shell 解释（分号、管道等元字符无意义）。
   (c) 攻击者传入 name="; rm -rf /"：test 会尝试检查名为 "; rm -rf /" 的文件是否存在，
       返回 returncode=1，不执行任何命令。
5. 结论：列表形式压制 shell=True 的语义，无命令注入。代码安全（但建议去掉 shell=True 增加可读性）。"""
)

# --- D2: 字符串 + shell=False（安全：字符串不被切分，shell 不参与） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/version")
def version():
    tool = request.args.get("tool", "ls")
    result = subprocess.run(
        tool + " --version",
        shell=False,
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_string_shell_false_not_split.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.run(\"ls --version\", shell=False) 中 shell=False，args 字符串不经过 shell 解释，Python 直接调用 execvp(\"ls --version\")，会因路径中含空格找不到可执行文件而报错。tool 即使被用户控制，也无法注入 shell 元字符（; | & 等只是字符串字面量）",
    "no fix needed",
    """
代码是字符串拼接 tool + ' --version' 进入 subprocess，存在命令注入。tool 是用户输入，攻击者传入 tool="; cat /etc/passwd" 会执行两条命令。""",
    """
问题：模型没看 shell=False。当 shell=False 时，Python 把整个字符串作为一个可执行文件路径传给 execvp，不会调用 /bin/sh 解释。也就是说，shell=False 时 args 字符串里的 ; | & 等元字符完全无意义——它们就是路径名的一部分，execvp 会把它们当字面字节去找可执行文件，找不到就报错。命令注入的前提是 shell 解释器参与。""",
    """
1. 污染源：request.args.get('tool') 获取用户输入。
2. 危险 sink：subprocess.run(tool + ' --version', shell=False) 执行命令。
3. 数据流追踪：tool → 字符串拼接 → subprocess.run(shell=False)。
4. 边界分析（关键：字符串 + shell=False）：
   (a) shell=False 时，args 字符串不经过 shell 解释，作为可执行文件路径直接传给 execvp。
   (b) execvp(tool + ' --version') 尝试找到一个名为 "ls --version" 的可执行文件，
       因路径中含空格找不到（PathSpecNotFound），会抛 OSError。
   (c) 即使用户传入 tool="; cat /etc/passwd"，args 是 "; cat /etc/passwd --version"，
       execvp 把它当字面路径，找不到名为 "; cat /etc/passwd" 的可执行文件，报错。
   (d) 分号、管道等 shell 元字符在 shell=False 下无意义，因为 /bin/sh 没有被调用。
5. 结论：shell=False 时无 shell 解释，命令注入前提不成立。代码安全（但这是反模式，建议改列表形式）。"""
)

# --- D3: shlex.quote + shell=False（安全：shlex.quote 在 shell=False 下多余但无害） ---
add(
    """
import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/show")
def show():
    text = request.args.get("text", "")
    safe_text = shlex.quote(text)
    result = subprocess.run(
        "echo " + safe_text,
        shell=False,
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_shlex_quote_shell_false_redundant.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.run(\"echo 'hello; rm'\", shell=False) 中 shell=False，args 字符串不经过 shell 解释，shlex.quote 在这里没有意义（包裹的单引号就是 echo 路径名的一部分），但也不会引入漏洞——execvp 找不到名为 \"echo 'hello; rm'\" 的可执行文件",
    "no fix needed",
    """
代码用了 shlex.quote，但 shell=False 意味着不调用 shell，shlex.quote 就无效了。用户输入 text 可能破坏 echo 路径，导致任意命令执行或文件不存在错误。""",
    """
问题：模型对 shlex.quote 与 shell=False 的组合理解混乱。shlex.quote 是为 shell 解释器设计的转义函数，在 shell=False 下确实无意义（因为没有 shell 解释器需要转义）。但这不引入漏洞——shell=False 时 args 字符串是字面路径名，shlex.quote 产生的单引号只是路径的一部分，execvp 找不到这个路径就报错。""",
    """
1. 污染源：request.args.get('text') 获取用户输入。
2. 危险 sink：subprocess.run(\"echo \" + safe_text, shell=False) 执行命令。
3. 数据流追踪：text → shlex.quote → 字符串拼接 → subprocess.run(shell=False)。
4. 边界分析（shlex.quote 在 shell=False 下）：
   (a) shlex.quote 设计目标：在 shell 解释器上下文中转义元字符。
   (b) shell=False 时 args 字符串不经过 shell 解释，shlex.quote 包裹的单引号只是路径名的一部分。
   (c) execvp(\"echo 'hello; rm'\") 尝试找一个名为 \"echo 'hello; rm'\" 的可执行文件，找不到。
   (d) 这是一个反模式（开发者可能误以为 shlex.quote 总是有效），但不是漏洞。
5. 结论：shell=False 下 shlex.quote 冗余但无害，无命令注入。代码安全。"""
)

# --- D4: shlex.quote + shell=True（安全：shlex.quote 防止 shell 解释） ---
add(
    """
import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/wc")
def wc():
    word = request.args.get("w", "")
    safe_word = shlex.quote(word)
    cmd = f"wc -w {safe_word}"
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=3
    )
    return result.stdout
""",
    "python",
    "ccot_shlex_quote_shell_true_protected.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.run(f\"wc -w {safe_word}\", shell=True) 中 shlex.quote(word) 将 word 包裹在单引号内并转义内部单引号，shell=True 启动 /bin/sh -c \"wc -w 'safe_word'\"，但 safe_word 内的元字符被单引号抑制，shell 只把它当字面参数",
    "no fix needed",
    """
代码 shell=True + 字符串拼接，即使 shlex.quote 看似转义，shell 解释器仍可能解析出意外结果。用户输入 word 可能绕过 shlex.quote。""",
    """
问题：模型低估了 shlex.quote 的转义强度。shlex.quote 是 Python 官方文档明确推荐的 shell 转义函数，实现基于 POSIX shell 引用规则——将输入用单引号包裹，内部单引号用 '\\''（结束单引号、转义单引号、重新开始单引号）替换。这是一个无已知绕过的确定性转义。""",
    """
1. 污染源：request.args.get('w') 获取用户输入。
2. 危险 sink：subprocess.run(f\"wc -w {safe_word}\", shell=True) 通过 shell 执行。
3. 数据流追踪：word → shlex.quote → f-string 拼接到命令 → subprocess.run(shell=True)。
4. 边界分析（shlex.quote + shell=True 的协同）：
   (a) shlex.quote 是 POSIX shell 引用的确定性实现。
   (b) word = \"hello; rm -rf /\" → shlex.quote 返回 \"'hello; rm -rf /'\"。
   (c) shell=True 启动 /bin/sh -c \"wc -w 'hello; rm -rf /'\"，单引号内分号是字面字符。
   (d) word = \"'; rm -rf /\" → shlex.quote 返回 \"''\\''; rm -rf /'\"，内部单引号被转义。
   (e) 唯一绕过条件是 NUL 字节（\\0）出现在 shlex.quote 之后，但 shlex.quote 不会去除 NUL，
       不过 wc 命令本身会在 NUL 处截断参数。
5. 结论：shlex.quote 在 shell=True 下提供完整转义，无命令注入。代码安全。"""
)

# --- D5: Popen + shell=True + 字符串（漏洞：与 subprocess.run 同样危险） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    proc = subprocess.Popen(
        f"curl {url}",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    out, err = proc.communicate(timeout=5)
    return out.decode()
""",
    "python",
    "ccot_popen_shell_true_concat.py",
    True,
    "CWE-78 命令注入",
    "Critical",
    "request.args.get('url')",
    "subprocess.Popen(f'curl {url}', shell=True)",
    "subprocess.Popen 与 subprocess.run 行为一致，shell=True + 字符串拼接允许 shell 解释元字符。攻击者传入 url=\"; rm -rf /\" 会执行任意命令",
    "改用 subprocess.run(['curl', url], shell=False) 列表形式",
    """
subprocess.Popen 是低阶 API，与 subprocess.run 安全属性不同。代码中 Popen 接收字符串和 shell=True，curl 命令会处理 url 参数，应该不会有注入问题。""",
    """
问题：模型误以为 Popen 是某种"安全低阶 API"。subprocess.Popen 与 subprocess.run 共享相同的 shell 语义——shell=True 都会启动 /bin/sh -c。区别仅在 API 风格（Popen 是流式，run 是阻塞一次性）。""",
    """
1. 污染源：request.args.get('url') 获取用户输入。
2. 危险 sink：subprocess.Popen(f'curl {url}', shell=True) 通过 shell 执行。
3. 数据流追踪：url → f-string 拼接 → Popen(shell=True) → /bin/sh -c 执行。
4. 防御检查（无）：
   (a) url 未转义直接拼入 f-string。
   (b) Popen 的 shell=True 与 run 的 shell=True 行为一致——都启动 /bin/sh -c 解释命令字符串。
   (c) 攻击者传入 url=\"; rm -rf /\" → Popen(\"curl ; rm -rf /\") → shell 执行 curl 和 rm。
   (d) 攻击者传入 url=\"$(cat /etc/passwd)\" → 命令替换。
5. 结论：Popen + shell=True + 字符串拼接，存在 CWE-78 命令注入漏洞。"""
)

# --- D6: subprocess.check_output + 列表（安全：与 run 一致） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/count")
def count():
    pattern = request.args.get("p", "")
    result = subprocess.check_output(
        ["grep", "-c", pattern, "/var/log/app.log"],
        timeout=5
    )
    return result.decode()
""",
    "python",
    "ccot_check_output_list_safe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.check_output 接收列表参数，shell 默认 False，行为与 subprocess.run 一致。pattern 作为 grep 的字面参数，不被 shell 解释。即使 timeout=5 超时，check_output 会抛 CalledProcessError 但不会改变命令注入防护",
    "no fix needed",
    """
subprocess.check_output 是高阶 API，内部会调用 subprocess.run，但 timeout 超时可能引发奇怪行为。pattern 是用户输入，且 grep 命令支持 -e 选项执行脚本。""",
    """
问题：模型把 check_output 当成独立的安全 API。实际上 check_output 内部就是 subprocess.run + 检查 returncode，shell 语义完全相同。grep 的 -e 选项需要显式指定（这里是 -c 表示 count），不会被用户输入触发。""",
    """
1. 污染源：request.args.get('p') 获取用户输入。
2. 危险 sink：subprocess.check_output([\"grep\", \"-c\", pattern, \"/var/log/app.log\"])。
3. 数据流追踪：pattern → 列表参数 → check_output(shell=False)。
4. 防御评估（check_output 与 run 共享 shell 语义）：
   (a) check_output 源码：内部调用 subprocess.run 并检查 returncode，
       shell 语义与 run 一致——列表 + 默认 shell=False，参数直接传给 execvp。
   (b) pattern 作为 grep 的字面 -c 后的参数（实际是文件名），grep 会尝试在 /var/log/app.log 中
       搜索包含 pattern 的行并计数。
   (c) 即使用户传入 pattern=\"; rm -rf /\"，grep 会查找字面 "; rm -rf /" 字符串，报告 count=0。
   (d) timeout=5 防止 grep 长时间运行（虽然不会改变命令注入防护）。
5. 结论：check_output + 列表形式 + shell=False，命令注入安全。代码安全。"""
)

# --- D7: subprocess.run 字符串（无 shell=）→ Python 3 行为 ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/resolve")
def resolve():
    host = request.args.get("host", "")
    # Python 3: shell 默认 False，args 字符串是单一可执行文件路径
    result = subprocess.run("nslookup " + host, capture_output=True, text=True)
    return result.stdout
""",
    "python",
    "ccot_run_string_no_shell_default_false.py",
    True,
    "CWE-78 命令注入（错误形式）",
    "High",
    "request.args.get('host')",
    "subprocess.run(\"nslookup \" + host)",
    "Python 3 中 subprocess.run 的 shell 参数默认 False。当 args 是字符串时，Python 把整个字符串作为可执行文件路径传给 execvp，找不到 \"nslookup host.com\" 这个文件而报错（OSError）。这不是命令注入（shell 不参与），但会因功能不可用导致程序崩溃或回退到异常处理中的其他命令",
    "改用 subprocess.run(['nslookup', host], shell=False) 列表形式",
    """
代码没用 shell=True，subprocess 默认安全。host 拼接进字符串作为 nslookup 的参数，但 Python 会把整个字符串当可执行文件路径，因此无命令注入。代码安全。""",
    """
问题：模型结论对的（确实无命令注入），但 sink 描述不准确——Python 3 中字符串 args + shell=False 不构成 CWE-78 命令注入，因为没有 shell 解释器参与。模型判了\"安全\"，但用户预期执行 nslookup 命令，代码实际功能完全失败（execvp 找不到 \"nslookup host.com\" 路径）。""",
    """
1. 污染源：request.args.get('host') 获取用户输入。
2. 危险 sink：subprocess.run(\"nslookup \" + host)。
3. Python 3 行为：
   (a) subprocess.run 的 shell 参数在 Python 3 默认是 False（与 Python 2 的 True 不同）。
   (b) 当 args 是字符串且 shell=False 时，Python 把整个字符串作为可执行文件路径传给 execvp。
   (c) execvp(\"nslookup host.com\") 找不到名为 \"nslookup host.com\" 的可执行文件，
       抛 OSError([Errno 2] No such file or directory)。
   (d) host 即便含 ; | & 等元字符，也是路径名的一部分，无 shell 解释，**无命令注入**。
4. 但代码实际功能失败：用户期望执行 nslookup 查询，结果程序崩溃。
5. 结论：代码无 CWE-78 命令注入漏洞（CWE-78 要求 shell 解释器参与），但存在功能性 bug。
   这是一个\"正确但无用\"的反模式——开发者可能误以为字符串会自动按空格切分参数。
   建议改列表形式。"""
)

# --- D8: subprocess.run(["sh", "-c", 拼接])（漏洞：sh -c 启动子 shell） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    script = request.args.get("s", "")
    result = subprocess.run(
        ["sh", "-c", "echo " + script],
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_sh_c_string_concat.py",
    True,
    "CWE-78 命令注入",
    "Critical",
    "request.args.get('s')",
    "subprocess.run(['sh', '-c', 'echo ' + script])",
    "虽然外层 subprocess.run 用列表形式（shell=False），但列表中显式调用 'sh -c'，把字符串 'echo ' + script 交给 /bin/sh 解释。这等价于 shell=True + 字符串拼接，攻击者传入 s=\"; rm -rf /\" 即可执行任意命令",
    "改用 subprocess.run(['echo', script], shell=False)，或 subprocess.run(f'echo {shlex.quote(script)}', shell=True)",
    """
代码用了列表形式，subprocess.run 默认 shell=False，列表参数不经 shell 解释。script 是 echo 的字面参数，无命令注入。代码安全。""",
    """
问题：模型只看到外层 subprocess.run 用列表形式，忽略了列表里显式调用 \"sh -c\" 启动了新的 /bin/sh 进程。子 sh 进程会解释 \"echo \" + script 命令字符串，等价于 shell=True 场景。列表形式只是把 \"sh\"、\"-c\"、命令字符串作为独立参数传给 execvp，但 execvp 启动的 sh 进程内部仍会解释命令字符串。""",
    """
1. 污染源：request.args.get('s') 获取用户输入。
2. 危险 sink：subprocess.run(['sh', '-c', 'echo ' + script])。
3. 数据流追踪：script → 字符串拼接到 echo 命令 → 列表 ['sh', '-c', cmd] → execvp(\"sh\")。
4. 防御检查（无效）：
   (a) 外层 subprocess.run 用列表形式，shell 默认 False，args 列表直接传给 execvp。
   (b) execvp 启动 /bin/sh 进程，sh 进程的 -c 参数告诉它\"读取 cmd 并解释\"。
   (c) /bin/sh 解释 'echo ' + script，分号、管道、命令替换等元字符被识别。
   (d) 攻击者传入 s=\"; rm -rf /\" → sh 执行 echo 和 rm -rf / 两条命令。
5. 结论：列表中显式调用 'sh -c' 等价于 shell=True + 字符串拼接，存在 CWE-78 命令注入漏洞。"""
)

# --- D9: subprocess.run(["bash", "-c", "固定"] + 列表) 看似安全但受限 ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/env")
def env():
    var = request.args.get("v", "")
    result = subprocess.run(
        ["bash", "-c", "echo $HOME"],
        capture_output=True,
        text=True,
        env={"HOME": var, "PATH": "/usr/bin"}
    )
    return result.stdout
""",
    "python",
    "ccot_bash_c_fixed_env_inject.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.run([\"bash\", \"-c\", \"echo $HOME\"], env={\"HOME\": var, ...}) 中，bash -c 执行的命令是硬编码 \"echo $HOME\"，不接收用户输入。env 参数把 HOME 设为 var，但 bash 解释 \"echo $HOME\" 时是合法变量展开，不是命令注入",
    "no fix needed",
    """
代码用了 bash -c，且 env 参数被用户控制（HOME=var），攻击者可以通过 HOME 路径做任意文件访问，比如 HOME=\"/etc; cat /etc/passwd\" 会在 bash 中执行额外的 cat 命令。""",
    """
问题：模型混淆了\"env 注入\"和\"命令注入\"。env 参数提供子进程的环境变量，但 bash 解释的命令字符串是硬编码的 \"echo $HOME\"，只做变量展开（$HOME → var 的值）。即便 var=\"\\$(rm -rf /)\"，HOME 变量被设为 \"\\$(rm -rf /)\"（字面字符串），bash 不会对它做命令替换——命令替换只在命令字符串解析时进行，变量值是普通字符串。""",
    """
1. 污染源：request.args.get('v') 获取用户输入。
2. 危险 sink：subprocess.run([\"bash\", \"-c\", \"echo $HOME\"], env={\"HOME\": var})。
3. 数据流追踪：var → env[\"HOME\"] → bash 进程 → 解释 \"echo $HOME\"。
4. 边界分析（env 注入 ≠ 命令注入）：
   (a) bash -c 接收的命令字符串是硬编码 \"echo $HOME\"，不含用户输入。
   (b) bash 解析命令时，把 $HOME 替换为 var 的值（变量展开在参数解析时发生）。
   (c) 即便 var=\"\\$(rm -rf /)\" 或 var=\"; cat /etc/passwd\"，HOME 变量值是字面字符串。
   (d) bash 对变量值不再做命令替换/元字符解释——这是 bash 的确定性行为。
   (e) 唯一的命令注入路径是让命令字符串本身含用户输入，本代码命令字符串是硬编码，无此路径。
5. 结论：env 注入是另一个安全话题（PATH hijack、HOME 敏感文件），但本代码无 CWE-78 命令注入。代码安全。"""
)

# --- D10: subprocess.run(列表) 但列表元素来自用户（命令名本身用户控制） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    cmd = request.args.get("cmd", "ls")
    args = request.args.get("args", "")
    result = subprocess.run(
        [cmd] + args.split(),
        capture_output=True,
        text=True,
        timeout=3
    )
    return result.stdout
""",
    "python",
    "ccot_list_cmd_user_controlled.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.run([cmd] + args.split()) 列表形式 + shell=False，execvp 直接把 cmd 作为可执行文件路径，找不到就报错。args.split() 在 Python 层面切分，不经过 shell 解释。这不是命令注入（无 shell 参与），而是任意命令执行（业务逻辑问题）",
    "no fix needed（但业务上应限制 cmd 白名单）",
    """
代码用列表形式，shell=False，参数不被 shell 解释。但 cmd 是用户输入，攻击者可以传入 cmd=\"sh\"，args=\"-c 'rm -rf /'\"，让子进程执行任意 shell 命令。这是严重漏洞。""",
    """
问题：模型混淆了\"命令注入\"和\"任意命令执行\"。命令注入（CWE-78）特指通过 shell 解释器注入元字符；任意命令执行是业务逻辑问题——开发者让用户完全控制可执行程序名。本代码列表形式 + shell=False 没有 shell 解释器参与，args.split() 在 Python 层面按空白切分（不使用 shlex，可能受引号影响），但元字符不被解释。""",
    """
1. 污染源：cmd 和 args 都是用户输入。
2. 危险 sink：subprocess.run([cmd] + args.split())。
3. 数据流追踪：cmd, args → 列表拼接 → subprocess.run(shell=False)。
4. 边界分析（列表形式 + shell=False + 用户控制可执行文件）：
   (a) shell=False 时，列表元素直接传给 execvp，execvp(cmd) 把 cmd 当可执行文件路径。
   (b) 即便 cmd=\"sh\"，execvp(\"sh\") 启动 /bin/sh，但因 shell=False，sh 进程不接收 -c 参数，
       而是等待 stdin 或尝试交互模式（会因 timeout 触发 TimeoutExpired）。
   (c) 即便 cmd=\"sh\" + args=[\"-c\", \"rm -rf /\"]，sh 启动后会执行 -c 命令，但这是 sh 进程内的
       命令执行，**不是 shell 注入**——子进程是开发者显式启动的 sh，不是通过元字符注入的。
   (d) 这属于\"任意命令执行\"业务逻辑问题，应在业务层做 cmd 白名单（如只允许 ls/cat/grep），
       但不属于 CWE-78 命令注入。
5. 结论：列表 + shell=False 下无 CWE-78 命令注入。但 cmd 用户控制是业务逻辑风险（应加白名单）。"""
)


# ===========================================================================
# 类别 E: shlex 边界（10 条）
# 覆盖 shlex.quote / shlex.split / shlex.join 的边界：
#   - 空字符串
#   - unicode / 多字节
#   - 内部单引号
#   - 与 shell=False 的组合（shlex.quote 在 shell=False 下冗余）
#   - shlex.split 与 str.split 的区别
# ===========================================================================

# --- E1: shlex.quote("")（安全：空字符串变成 ''，shell 解释为空参数） ---
add(
    """
import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/label")
def label():
    text = request.args.get("t", "")
    if not text:
        text = "default"
    safe = shlex.quote(text)
    result = subprocess.run(
        f"echo Label:{safe}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_shlex_quote_empty.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "shlex.quote(\"\") 返回 \"''\"（两个单引号），shell 把它解释为空参数。代码先做 if not text 兜底，但即便不兜底，shlex.quote 也安全处理空字符串",
    "no fix needed",
    """
shlex.quote(\"\") 返回空字符串 \"\"，导致 f-string 拼接成 \"echo Label:\"，这是不安全的——用户可以构造边界让 echo 只输出 Label 而不接用户输入。""",
    """
问题：模型误以为 shlex.quote(\"\") 返回空字符串。实际 shlex.quote(\"\") 返回 \"''\"（两个单引号）——Python 源码可见。这意味着即便 text 为空，shell 也会把 '' 解释为空参数，echo Label: 输出 \"Label: \"。shlex.quote 对空字符串的处理是确定的。""",
    """
1. 污染源：request.args.get('t') 可能为空。
2. 危险 sink：subprocess.run(f\"echo Label:{safe}\", shell=True)。
3. 数据流追踪：t → if not text 兜底（\"default\"）或 shlex.quote → 拼接。
4. 边界分析（shlex.quote 空字符串）：
   (a) shlex.quote(\"\") 返回 \"''\"，shell 解释为空参数。
   (b) f\"echo Label:{''}\" → \"echo Label:''\" → shell 执行 echo Label: → 输出 \"Label: \"。
   (c) 即便用户传入 t=\"; rm -rf /\"，shlex.quote 包裹为 \"''; rm -rf /'\"，
       第二个单引号开始新字符串，分号是字面字符。
5. 结论：shlex.quote 对空字符串和元字符都正确转义。代码安全。"""
)

# --- E2: shlex.quote unicode（安全：unicode 字符被单引号包裹，shell 解释为字面） ---
add(
    """
import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/message")
def message():
    text = request.args.get("msg", "")
    safe = shlex.quote(text)
    result = subprocess.run(
        f"echo {safe}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_shlex_quote_unicode.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "shlex.quote 对 unicode 字符串的处理与 ASCII 字符串一致——用单引号包裹，内部单引号转义。Shell 解释 unicode 字符为字面字节。Python 字符串统一是 unicode，shlex.quote 不会破坏编码",
    "no fix needed",
    """
shlex.quote 不支持 unicode 字符，可能导致编码错误或绕过。用户输入中文字符后 shlex.quote 可能失败，攻击者可利用编码问题绕过。""",
    """
问题：模型对 shlex.quote 的实现有误解。shlex.quote 是基于字节级处理的，Python 3 字符串是 unicode，shlex.quote 内部不区分 ASCII/unicode——所有字符都被视为普通字符，单引号包裹即可。""",
    """
1. 污染源：request.args.get('msg') 接收 unicode 字符串。
2. 危险 sink：subprocess.run(f\"echo {safe}\", shell=True)。
3. 数据流追踪：msg → shlex.quote → f-string 拼接 → shell 解释。
4. 边界分析（shlex.quote unicode）：
   (a) shlex.quote 处理 unicode 字符与 ASCII 字符相同：用单引号包裹，内部单引号替换。
   (b) msg = \"你好; rm -rf /\" → shlex.quote 返回 \"'你好; rm -rf /'\"，分号是字面字符。
   (c) msg = \"'中文; '\" → shlex.quote 返回 \"''\\\"中文; '\\\"'\"（假设引号字符是单引号），
       内部单引号被转义。
   (d) shell 解释 unicode 字符为字面字节（UTF-8 编码），echo 输出原始字符。
5. 结论：shlex.quote 正确处理 unicode，无命令注入。代码安全。"""
)

# --- E3: shlex.quote 含 NUL 字节（边界：NUL 在 shell 中截断） ---
add(
    """
import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/data")
def data():
    raw = request.args.get("d", "")
    safe = shlex.quote(raw)
    result = subprocess.run(
        f"echo {safe}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_shlex_quote_nul.py",
    True,
    "CWE-78 命令注入（部分绕过）",
    "Medium",
    "request.args.get('d')",
    "subprocess.run(f'echo {safe}', shell=True)",
    "shlex.quote 不去除 NUL 字节（\\x00），用户传入 d=\"; touch /tmp/x; #\\x00#\" 时，shlex.quote 返回 \"''; touch /tmp/x; #\\x00#'\"，shell 解释到 \\x00 时截断（POSIX shell 在命令字符串中遇到 NUL 终止解析），导致 # 后面的单引号闭合失败，# 变为注释后分号被解释为命令分隔符",
    "调用 shlex.quote 前先 strip NUL：safe = shlex.quote(raw.replace('\\x00', ''))",
    """
shlex.quote 是完整转义，NUL 字节也会被单引号包裹。shell 解释时 NUL 字节不影响命令解析。代码安全。""",
    """
问题：模型没考虑 NUL 字节在 POSIX shell 中的截断行为。POSIX C 标准规定，shell 命令字符串中遇到 NUL 字节会终止当前字符串解析（因为 C 字符串以 NUL 结尾）。shlex.quote 不去除 NUL，单引号包裹也无法阻止截断——截断发生在更底层（execve 的 argv 解析）。""",
    """
1. 污染源：request.args.get('d') 可含 NUL 字节。
2. 危险 sink：subprocess.run(f\"echo {safe}\", shell=True)。
3. 数据流追踪：d → shlex.quote → f-string 拼接 → shell 解释。
4. 边界分析（NUL 字节绕过）：
   (a) shlex.quote(\"hello\\x00world\") 返回 \"'hello\\x00world'\"——单引号包裹但 NUL 保留。
   (b) shell 解释 f\"echo 'hello\\x00world'\" 时，execve 的 argv 解析在第一个 NUL 处截断。
   (c) 攻击者精心构造 d=\"; touch /tmp/x; echo '\"，shlex.quote 包裹后中间含 NUL 字节，
       截断后 # 字符后的内容无法被单引号包裹，分号被解释。
   (d) 这是 shlex.quote 的已知边界：它保证 shell 元字符转义，但不处理 NUL 截断。
5. 结论：含 NUL 字节的用户输入可绕过 shlex.quote，存在 CWE-78 命令注入（部分绕过）。建议先 strip NUL。"""
)

# --- E4: shlex.split vs str.split（用途不同，不能互换） ---
add(
    """
import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/log")
def log():
    raw = request.args.get("line", "")
    # shlex.split 解析引号包裹，str.split 只按空白
    parts = shlex.split(raw)
    result = subprocess.run(
        ["tail", "-n"] + parts + ["/var/log/app.log"],
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_shlex_split_safe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "shlex.split(raw) 在 Python 层面解析 shell-like 引号规则（处理单/双引号、转义），返回字符串列表。subprocess.run 用列表形式 + shell=False，parts 元素作为独立 argv 传给 execvp。tail 命令接收这些参数，无 shell 参与",
    "no fix needed",
    """
shlex.split 会把 'ls; rm' 解析为 ['ls', ';', 'rm']，然后 subprocess.run 列表中含 ; 字符，可能被某个底层 C 函数解释为命令分隔符，导致 shell 注入。""",
    """
问题：模型对 shlex.split 的输出再加工逻辑有误解。shlex.split 返回的是字符串列表，每个字符串是解析后的字面 token（不再含引号、转义）。这些 token 传给 subprocess.run 列表，execvp 接收独立 argv，每个 token 是独立参数，不存在 \";\" 字符被解释为 shell 分隔符的路径。""",
    """
1. 污染源：request.args.get('line') 获取用户输入。
2. 危险 sink：subprocess.run([\"tail\", \"-n\"] + parts + [\"/var/log/app.log\"])。
3. 数据流追踪：line → shlex.split → 列表 → subprocess.run(shell=False)。
4. 防御评估（shlex.split + 列表形式）：
   (a) shlex.split 在 Python 层面按 shell 引号规则解析，返回 list[str]，每个元素是字面 token。
   (b) line = \"'foo bar'; rm\" → shlex.split 返回 [\"foo bar\", \";\", \"rm\"]，
       分号是字面字符 \";\"，不含 shell 语义。
   (c) subprocess.run 列表 + shell=False，execvp(tail) 接收独立 argv，每个元素是独立参数。
   (d) tail 命令接收 [\"-n\", \"foo bar\", \";\", \"rm\", \"/var/log/app.log\"]，
       它会把 \";\" 和 \"rm\" 当作字面字符串处理（tail -n 期望数字，会报 \"invalid number of lines\"）。
5. 结论：shlex.split + 列表形式 + shell=False，无命令注入。代码安全。"""
)

# --- E5: shlex.join（反向 quote，列表→字符串） ---
add(
    """
import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/args")
def args():
    parts = request.args.getlist("p")  # 多值参数
    safe = shlex.join(parts)
    result = subprocess.run(
        f"echo {safe}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_shlex_join_safe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "shlex.join(parts) 是 shlex.quote 的反向操作——对列表中每个元素单独 shlex.quote，再用空格拼接。返回的字符串中每个元素都正确转义，可安全用于 shell=True 场景",
    "no fix needed",
    """
shlex.join 在 Python 3.8+ 引入，可能不稳定。parts 元素如果含特殊字符，shlex.join 可能不完整转义。""",
    """
问题：模型低估了 shlex.join 的可靠性。shlex.join 的实现是 shlex.quote 的精确反向：对每个元素应用 shlex.quote，用空格连接，保证输出字符串可在 shell 中安全解释。""",
    """
1. 污染源：request.args.getlist('p') 获取多值参数。
2. 危险 sink：subprocess.run(f\"echo {safe}\", shell=True)。
3. 数据流追踪：parts → shlex.join → f-string 拼接 → shell 解释。
4. 防御评估（shlex.join）：
   (a) shlex.join(parts) 对每个元素应用 shlex.quote，再用空格拼接。
   (b) parts = [\"a\", \"b c\", \"; rm -rf /\"] → shlex.join 返回 \"a 'b c' '; rm -rf /'\"。
   (c) shell 解释时，每个被单引号包裹的元素是字面参数。
   (d) 即便 parts 含空字符串元素，shlex.quote(\"\") 返回 \"''\"，仍正确转义。
5. 结论：shlex.join 提供列表→shell 字符串的安全转换。代码安全。"""
)

# --- E6: shlex.quote + 字符串拼接（反模式：混用 quote 和拼接） ---
add(
    """
import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/path")
def path():
    prefix = "/var/data/"
    user_path = request.args.get("p", "")
    safe = shlex.quote(prefix + user_path)
    result = subprocess.run(
        f"ls {safe}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_shlex_quote_concat_safe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "shlex.quote(prefix + user_path) 仍能正确转义——quote 不区分字符串来源，统一应用 POSIX shell 引用规则。prefix 是固定字符串 \"/var/data/\"，user_path 含 \"; rm\" 等元字符，quote 后都被单引号包裹",
    "no fix needed",
    """
shlex.quote(prefix + user_path) 拼接后再 quote，prefix 可能引入不平衡的引号（如 prefix 含单引号），破坏 quote 的正确性。""",
    """
问题：模型担心 prefix 含单引号破坏 quote。但本代码 prefix 是硬编码的 \"/var/data/\"，不含单引号。即使 prefix 含单引号，shlex.quote 仍会处理——它会扫描整个输入，按 POSIX 引用规则重写。""",
    """
1. 污染源：user_path = request.args.get('p')。
2. 危险 sink：subprocess.run(f\"ls {safe}\", shell=True)。
3. 数据流追踪：prefix + user_path → shlex.quote → f-string → shell 解释。
4. 防御评估（quote + 拼接）：
   (a) prefix 是硬编码 \"/var/data/\"，不含特殊字符。
   (b) user_path = \"; rm -rf /\" → prefix + user_path = \"/var/data/; rm -rf /\"。
   (c) shlex.quote(\"/var/data/; rm -rf /\") 返回 \"'/var/data/; rm -rf /'\"，分号是字面字符。
   (d) 即便 prefix 含单引号（如 prefix=\"hello'world\"），shlex.quote 也会处理：
       quote 返回 \"'hello'\\\"'world'\"，POSIX 引用规则保证安全。
5. 结论：shlex.quote 对任意输入字符串应用确定性转义，拼接不破坏转义正确性。代码安全。"""
)

# --- E7: shlex.quote 与 shlex.split 误用（用 quote 当 split） ---
add(
    """
import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/grep")
def grep():
    raw = request.args.get("q", "")
    # 错误用法：quote 是为拼接设计的，不适合作为 split 的输入
    quoted = shlex.quote(raw)
    parts = shlex.split(quoted)  # 必然返回 [\"原始 quoted 字符串\"]，无意义
    result = subprocess.run(
        ["grep", "-i", parts[0], "/etc/hosts"],
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_shlex_quote_split_misuse_safe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "代码逻辑错误：先 quote 再 split，等于把已经安全转义的字符串再解析一次，但 shlex.split 会去掉单引号还原原始内容（parts[0] == raw）。虽然是无意义的操作，但因列表 + shell=False，最终传给 grep 的还是 raw 字面参数，无命令注入",
    "no fix needed（但代码逻辑冗余，应直接用 raw）",
    """
代码把用户输入 quote 后传给 grep，shlex.quote 会包裹单引号，grep 收到的参数是带引号的字面字符串，导致 grep 在 /etc/hosts 中查找带引号的字面内容。""",
    """
问题：模型对 shlex.split 的解析有误解。shlex.split 会按引号规则去引号还原。shlex.quote(raw) 返回 \"'...raw...'\"，shlex.split 解析后去掉单引号，得到原始 raw 字符串。所以 parts[0] == raw（如果不考虑 quote 内部转义带来的微小变化）。grep 收到的还是原始用户输入的字面字符串。""",
    """
1. 污染源：request.args.get('q') 获取用户输入。
2. 危险 sink：subprocess.run([\"grep\", \"-i\", parts[0], \"/etc/hosts\"])。
3. 数据流追踪：raw → shlex.quote → shlex.split → 列表 → subprocess.run(shell=False)。
4. 防御评估（逻辑冗余但无漏洞）：
   (a) shlex.quote(\"hello world\") 返回 \"'hello world'\"。
   (b) shlex.split(\"'hello world'\") 返回 [\"hello world\"]，parts[0] 是原始字符串。
   (c) subprocess.run 列表 + shell=False，grep 接收字面参数。
   (d) 这是一个无意义的操作（quote 后立即 split 还原），但因最终是列表 + shell=False，无命令注入。
5. 结论：代码逻辑冗余但无安全漏洞。代码\"安全\"（但应清理代码逻辑）。"""
)

# --- E8: shlex.quote 嵌套（多次 quote 无效） ---
add(
    """
import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/nested")
def nested():
    text = request.args.get("t", "")
    # 多次 quote 是反模式，但不会引入漏洞
    safe = shlex.quote(shlex.quote(text))
    result = subprocess.run(
        f"echo {safe}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_shlex_quote_nested_safe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "shlex.quote(shlex.quote(text)) 嵌套 quote 是反模式但不会引入漏洞。shlex.quote 第一次包裹 text 为 'text'，第二次把 'text' 视为输入，再次包裹为 ''text''。shell 解释 'text' 为字面 token（包含内部单引号），echo 输出 'text' 而非 text",
    "no fix needed（但应避免嵌套 quote）",
    """
嵌套 shlex.quote 不会增强安全性，反而破坏可读性。如果开发者意图是\"双重防护\"，那他应该用 shlex.quote + 列表形式，而不是嵌套 quote。代码安全但反模式。""",
    """
问题：模型对嵌套 quote 持否定态度，但过度担心安全。嵌套 quote 不会引入命令注入——每一次 quote 都按 POSIX 规则正确包裹，最终字符串可在 shell 中安全解释。唯一影响是输出格式（多一层引号）。""",
    """
1. 污染源：request.args.get('t')。
2. 危险 sink：subprocess.run(f\"echo {safe}\", shell=True)。
3. 数据流追踪：t → shlex.quote → shlex.quote → 拼接 → shell 解释。
4. 防御评估（嵌套 quote）：
   (a) 第一次 quote(text=\"hello\"): 返回 \"'hello'\"。
   (b) 第二次 quote(\"'hello'\"): 内部含单引号，shlex.quote 替换为 \"''\\\"'hello'\\\"'\"，
       即 ''\\''hello'\\'' 形式，POSIX 规则下等价于字面字符串 \"'hello'\"。
   (c) shell 解释这个字符串，输出 'hello'（含单引号）。
   (d) 即便 text = \"'; rm -rf /\"，嵌套 quote 仍按 POSIX 规则完整转义，shell 解释为字面字符串。
5. 结论：嵌套 quote 是反模式（输出含多余引号），但无安全漏洞。代码安全。"""
)

# --- E9: shlex.quote 与 bytes（边界：bytes 输入） ---
add(
    """
import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/bin")
def bin():
    raw = request.args.get("b", "")
    # shlex.quote 接受 str，不接受 bytes
    try:
        safe = shlex.quote(raw)
    except AttributeError:
        return "Invalid input", 400
    result = subprocess.run(
        f"echo {safe}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_shlex_quote_str_type_safe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "shlex.quote 在 Python 3 只接受 str 类型，对 bytes 输入会抛 AttributeError。代码用 try/except 兜底，实际只处理 str 输入（request.args.get 返回 str），无 bytes 注入路径",
    "no fix needed",
    """
shlex.quote 在 Python 3 接受 str 和 bytes，可能在 bytes 输入下产生不一致的转义行为，攻击者可以用 bytes 输入绕过 quote。""",
    """
问题：模型对 shlex.quote 的 Python 3 行为有误解。shlex.quote 在 Python 3 文档明确：输入必须是 str，bytes 输入会抛 AttributeError（不是 \"不一致转义\"）。代码用 try/except 防御是合理的，实际 request.args.get 返回 str，try 分支正常执行。""",
    """
1. 污染源：request.args.get('b') 返回 str。
2. 危险 sink：subprocess.run(f\"echo {safe}\", shell=True)。
3. 数据流追踪：b → shlex.quote → 拼接 → shell 解释。
4. 边界分析（shlex.quote 类型）：
   (a) shlex.quote 文档：参数 s 必须是 str，bytes 输入会抛 AttributeError。
   (b) Flask 的 request.args.get 返回 str（Flask/Werkzeug 解码 URL 参数为 str）。
   (c) 即便 b 含 unicode 字符（\"你好\"），shlex.quote 仍按 str 处理。
   (d) try/except 防御 bytes 输入是过度防御，但无害。
5. 结论：shlex.quote 在 Python 3 严格处理 str 类型，无类型混淆漏洞。代码安全。"""
)

# --- E10: shlex.quote 与 list 子命令拼接（反模式但安全） ---
add(
    """
import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def search():
    text = request.args.get("t", "")
    safe = shlex.quote(text)
    # 反模式：用 f-string 拼接到列表（实际等同字符串调用）
    cmd = f"echo {safe}"
    result = subprocess.run(
        cmd.split(),
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_shlex_quote_split_cmd_safe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "cmd = f\"echo {safe}\" 先 shlex.quote 包裹 safe，cmd.split() 按空白切分（不识别引号），但因 shlex.quote 把 safe 包裹为 '...'（无空白），切分后 [\"echo\", \"'safe_content'\"] 中 safe 部分含字面单引号，echo 收到的参数是带引号的字面字符串，行为奇怪但无命令注入",
    "no fix needed（但 cmd.split() 不应作为 token 化方法）",
    """
cmd.split() 按空白切分 cmd 字符串，但 shlex.quote 包裹的 safe 部分如果含分号或空格（不可能，因为 quote 不允许），切分可能破坏 quote 的完整性。""",
    """
问题：模型对 shlex.quote 输出格式有误解。shlex.quote 输出的字符串不含未转义的空白字符——所有空白都被单引号包裹在内部。所以 cmd.split() 切分后，safe 部分的整个 quote 输出作为一个 token 出现，传给 echo 时 echo 收到带引号的字面参数。""",
    """
1. 污染源：request.args.get('t')。
2. 危险 sink：subprocess.run(cmd.split(), shell=False)。
3. 数据流追踪：t → shlex.quote → f-string → cmd.split() → 列表 → execvp。
4. 防御评估（shlex.quote + f-string + split）：
   (a) shlex.quote(\"hello world\") 返回 \"'hello world'\"（单引号内含空格）。
   (b) cmd = \"echo 'hello world'\"。
   (c) cmd.split() 按空白切分（不识别引号），返回 [\"echo\", \"'hello\", \"world'\"]。
   (d) subprocess.run 列表 + shell=False，execvp(echo) 接收两个参数 \"'hello\" 和 \"world'\"。
   (e) echo 收到的参数是字面 \"'hello\" 和 \"world'\"，输出 \"'hello world'\"（echo 用空格分隔参数）。
5. 结论：quote + split 组合虽反模式（应直接列表形式），但无命令注入。代码安全。"""
)


# ===========================================================================
# 类别 F: subprocess_run / shell=False 边界（10 条）
# 覆盖 subprocess 的高级参数：
#   - env=（环境变量注入 vs PATH hijack）
#   - cwd=（改变工作目录）
#   - preexec_fn=（POSIX only，安全性）
#   - stdin=PIPE（接收用户输入）
#   - timeout（不防注入）
# ===========================================================================

# --- F1: subprocess.run 列表 + env= 用户控制（边界：env 注入） ---
add(
    """
import subprocess
import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/tool")
def tool():
    name = request.args.get("name", "ls")
    # 列表形式 + shell=False，但 env 含用户输入
    my_env = os.environ.copy()
    my_env["MY_VAR"] = request.args.get("var", "")
    result = subprocess.run(
        [name],
        env=my_env,
        capture_output=True,
        text=True,
        timeout=3
    )
    return result.stdout
""",
    "python",
    "ccot_run_list_env_user.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.run([name], env=my_env) 列表形式 + shell=False，name 作为可执行文件路径传给 execvp，execvp 会搜索 PATH 找到可执行文件。env 注入 MY_VAR 是合法的环境变量传递，子进程读取该变量是正常用途，**非命令注入**",
    "no fix needed（但应做 name 白名单防止任意命令执行）",
    """
代码 env 参数被用户控制（MY_VAR=var），且 name 是用户输入。攻击者可以传入 name=\"sh\"，env 含恶意 PATH，让子进程 sh 加载恶意动态库；或者 env 注入会让其他子进程读取到错误的环境变量，导致安全漏洞。""",
    """
问题：模型误把 env 注入等同于命令注入。env 注入是另一类风险（CWE-426 Untrusted Search Path、PATH hijack），但本代码 shell=False，args 列表直接传给 execvp，**没有 shell 解释器参与**，不构成 CWE-78 命令注入。""",
    """
1. 污染源：name 和 var 都是用户输入。
2. 危险 sink：subprocess.run([name], env=my_env)。
3. 数据流追踪：name → 列表 → execvp(name)；var → env[\"MY_VAR\"] → 子进程环境。
4. 边界分析（env 注入 ≠ 命令注入）：
   (a) shell=False 时，列表元素直接传给 execvp，execvp(name) 搜索 PATH 找到 name 对应的可执行文件。
   (b) env 参数只影响子进程的环境变量表，不影响命令解析。
   (c) 即便 var=\"\\$(rm -rf /)\"，MY_VAR 被设为字面 \"\\$(rm -rf /)\"（非命令替换），
       子进程读取 MY_VAR 时是字面字符串。
   (d) name=\"sh\" + var 含 PATH 路径 → 可能触发 PATH hijack（CWE-426），
       但这是单独的安全话题，不是命令注入。
5. 结论：列表 + shell=False 下无 CWE-78 命令注入。但 name 用户控制是业务逻辑风险。"""
)

# --- F2: subprocess.run 列表 + cwd= 改变工作目录 ---
add(
    """
import subprocess
import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/list")
def list_dir():
    directory = request.args.get("d", "/tmp")
    result = subprocess.run(
        ["ls", "-la", directory],
        cwd="/var/data",
        capture_output=True,
        text=True,
        timeout=3
    )
    return result.stdout
""",
    "python",
    "ccot_run_list_cwd.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.run([\"ls\", \"-la\", directory], cwd=\"/var/data\") 列表 + shell=False，cwd 改变子进程工作目录为 /var/data，directory 作为 ls 的字面参数。ls 会在 /var/data 下查找名为 directory 的子目录。无命令注入",
    "no fix needed（但 directory 应做白名单以防信息泄露）",
    """
代码 cwd 改变工作目录到 /var/data，用户输入 directory 可能含路径穿越（如 \"../../etc\"），ls 会列出 /etc 目录内容（信息泄露）。同时 cwd 改变后，相对路径解析可能绕过预期限制。""",
    """
问题：模型把信息泄露夸大为命令注入。命令注入要求 shell 解释器参与，本代码 shell=False + 列表，directory 作为 ls 的字面参数，无 shell 解释。directory 含 \"../\" 确实可能列出其他目录内容（信息泄露），但这是业务逻辑问题，应在应用层做 directory 白名单。""",
    """
1. 污染源：directory = request.args.get('d')。
2. 危险 sink：subprocess.run([\"ls\", \"-la\", directory], cwd=\"/var/data\")。
3. 数据流追踪：directory → 列表参数 → execvp(ls)。
4. 防御评估（cwd + 列表）：
   (a) cwd 改变子进程的工作目录为 /var/data，但不影响 args 列表的解释方式。
   (b) directory 作为 ls 的字面参数，ls 在 cwd 下解析 directory（支持绝对/相对路径）。
   (c) directory = \"../../etc\" → ls 列出 /var/data/../../etc 即 /etc 内容（信息泄露）。
   (d) 这是业务逻辑问题（CWE-22 path traversal 或信息泄露），不是 CWE-78。
5. 结论：列表 + shell=False 无命令注入。directory 用户控制可能引发信息泄露（应用层应加白名单）。"""
)

# --- F3: subprocess.run + stdin=PIPE 接收用户输入 ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/bc")
def bc():
    expr = request.args.get("e", "1+1")
    result = subprocess.run(
        ["bc", "-l"],
        input=expr,
        capture_output=True,
        text=True,
        timeout=3
    )
    return result.stdout
""",
    "python",
    "ccot_run_stdin_pipe_safe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.run([\"bc\", \"-l\"], input=expr) 列表 + shell=False，expr 通过 stdin 传给 bc 进程。bc 是计算器，expr 作为输入表达式由 bc 解释，**不是 shell 解释**。expr 不会触发 shell 元字符",
    "no fix needed",
    """
代码把用户输入 expr 通过 stdin 传给 bc，bc 是任意计算器（\"1+1; rm -rf /\" 在 bc 中是无效表达式，但 bc 内部有函数调用机制如 system()）。攻击者可以通过 expr=\"system(\\\"rm -rf /\\\")\" 让 bc 执行任意命令。""",
    """
问题：模型对 bc 工具的能力有误解。bc 是 POSIX 标准计算器，\"system()\" 不是 bc 的内置函数（bc 的内置函数如 length、scale、print 等），攻击者无法通过 bc 表达式执行 shell 命令。""",
    """
1. 污染源：expr = request.args.get('e')。
2. 危险 sink：subprocess.run([\"bc\", \"-l\"], input=expr)。
3. 数据流追踪：expr → stdin → bc 进程解释。
4. 防御评估（stdin + 列表）：
   (a) shell=False + 列表，bc 作为独立可执行文件启动，bc 进程内解释输入。
   (b) bc 是计算器，只识别数学表达式，不支持 system() 等函数调用。
   (c) expr = \"1+1; rm -rf /\" 在 bc 中是语法错误（bc 不识别 ; 作为表达式分隔符），输出错误。
   (d) 即便 expr 含特殊字符，只影响 bc 解析，bc 进程无 shell 解释器。
5. 结论：bc 通过 stdin 接收用户输入，无命令注入。代码安全。"""
)

# --- F4: subprocess.run + input= 字符串含换行 ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/mail")
def mail():
    recipient = request.args.get("to", "")
    subject = request.args.get("s", "")
    body = request.args.get("b", "")
    message = f\"\"\"To: {recipient}
Subject: {subject}

{body}
\"\"\"
    result = subprocess.run(
        ["sendmail", "-t"],
        input=message,
        capture_output=True,
        text=True,
        timeout=10
    )
    return "sent"
""",
    "python",
    "ccot_run_stdin_multiline_safe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.run([\"sendmail\", \"-t\"], input=message) 列表 + shell=False，message 通过 stdin 传给 sendmail。sendmail 解释邮件协议而非 shell。无命令注入。但 recipient/subject/body 未做邮件头注入防护（CWE-93），攻击者可注入额外邮件头（CRLF 注入）",
    "邮件头注入防护：recipient = recipient.replace('\\r', '').replace('\\n', '')",
    """
代码把用户输入拼接到邮件头，攻击者可以通过换行符注入额外邮件头（CRLF 注入），如 body 含 \"\\nBcc: attacker@evil.com\" 会添加 Bcc 头。同时 sendmail 进程的 stdin 处理邮件协议，攻击者可以构造恶意邮件内容触发 sendmail 漏洞。""",
    """
问题：模型只关注命令注入，忽略了邮件头注入（CWE-93）。本代码的 list+shell=False 无命令注入，但 recipient/subject/body 拼接进邮件协议头存在 CRLF 注入风险。命令注入分析应聚焦在 sink 前是否有 shell 解释，本代码无 shell 解释。""",
    """
1. 污染源：recipient, subject, body。
2. 危险 sink：subprocess.run([\"sendmail\", \"-t\"], input=message)。
3. 数据流追踪：recipient/subject/body → f-string 多行邮件协议 → sendmail stdin。
4. 防御评估（命令注入 vs 邮件头注入）：
   (a) shell=False + 列表 + input=，无 shell 解释器参与，**无 CWE-78 命令注入**。
   (b) 但邮件协议中，recipient/subject/body 直接拼接到 SMTP 头（To/Subject/空行后是 body），
       body 含 \"\\nBcc: ...\" 会注入额外邮件头。
   (c) 这是 CWE-93 CRLF Injection（邮件头注入），不是 CWE-78。
5. 结论：本代码无命令注入，但存在邮件头注入（CWE-93）。命令注入分析聚焦 shell 解释器。"""
)

# --- F5: subprocess.run 列表 + timeout（timeout 不防注入） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/resolve")
def resolve():
    host = request.args.get("host", "")
    result = subprocess.run(
        ["nslookup", host],
        capture_output=True,
        text=True,
        timeout=3
    )
    return result.stdout
""",
    "python",
    "ccot_run_list_timeout_safe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.run([\"ping\", \"-c\", \"1\", host], timeout=5) 列表 + shell=False，host 作为 ping 的字面参数。timeout=5 防止 ping 挂起，5 秒后抛 TimeoutExpired，但与命令注入防护无关。命令注入防护来自列表 + shell=False，无 timeout 也安全",
    "no fix needed",
    """
代码用 timeout=3 限制 nslookup 执行时间，但 timeout 与命令注入防护无关。host 是用户输入，即便列表形式，nslookup 命令支持 -timeout 等选项，攻击者可以通过 host 注入 nslookup 选项（如 host=\"-timeout 0 google.com\"）。""",
    """
问题：模型对列表 + shell=False 的参数边界有误解。在列表形式下，每个元素是独立的 argv 项，execvp 把它们作为独立参数传给 ping。ping 收到的 host 参数是位置参数（ping 解析为 IP 主机），不会把 host 解析为 ping 的选项（因为 ping -c 1 之后的元素都是位置参数）。""",
    """
1. 污染源：host = request.args.get('host')。
2. 危险 sink：subprocess.run([\"nslookup\", host], timeout=3)。
3. 数据流追踪：host → 列表 → execvp(nslookup)。
4. 防御评估（列表 + timeout）：
   (a) 列表形式 + shell=False，execvp(nslookup) 接收独立 argv。
   (b) nslookup 进程内解析参数：第 1 个是 nslookup 可执行文件路径，第 2 个是 host 位置参数。
   (c) 即便 host=\"-timeout 0 google.com\"，nslookup 收到的 argv 是 [\"nslookup\", \"-timeout 0 google.com\"]，
       解析为 host = \"-timeout 0 google.com\"，nslookup 尝试解析为域名会失败（\"unknown host\"）。
   (d) shell=False 下，argv 切分不依赖 shell，-timeout 不会被错误解析为 nslookup 选项。
5. 结论：列表 + shell=False 下 host 无法触发 nslookup 的内部选项。timeout 不影响命令注入防护。代码安全。"""
)

# --- F6: subprocess.run 与 subprocess.call 等价性 ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/wc")
def wc():
    fname = request.args.get("f", "log.txt")
    # subprocess.call 等价于 run（仅不返回 CompletedProcess）
    subprocess.call(["wc", "-l", fname], timeout=5)
    return "done"
""",
    "python",
    "ccot_call_list_safe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.call([\"wc\", \"-l\", fname], timeout=5) 与 subprocess.run 安全属性一致。call 是 run 的早期版本，shell 语义相同。列表 + 默认 shell=False，fname 作为 wc 的字面参数",
    "no fix needed",
    """
subprocess.call 是旧 API，可能有未公开的安全问题。fname 是用户输入，wc 命令会处理文件，攻击者可以通过 fname=\"../../etc/passwd\" 实现文件访问（信息泄露）。""",
    """
问题：模型对 subprocess.call 的安全属性有误解。subprocess.call 在 Python 3 文档明确：与 subprocess.run 共享 shell 语义（args 列表 + shell=False 时，参数直接传给 execvp）。fname 用户控制可能引发信息泄露（应用层应做白名单），但不是命令注入。""",
    """
1. 污染源：fname = request.args.get('f')。
2. 危险 sink：subprocess.call([\"wc\", \"-l\", fname], timeout=5)。
3. 数据流追踪：fname → 列表 → execvp(wc)。
4. 防御评估（call 与 run 等价）：
   (a) subprocess.call 在 Python 3 是 run 的早期版本，shell 语义完全一致。
   (b) shell=False + 列表，execvp(wc) 接收独立 argv。
   (c) fname = \"../../etc/passwd\" → wc 读取该路径文件（信息泄露），但 shell 不参与。
   (d) 这是路径穿越/信息泄露（CWE-22），不是 CWE-78。
5. 结论：call + 列表无命令注入。fname 用户控制是路径穿越风险（应用层应加白名单）。"""
)

# --- F7: subprocess.run 列表但首元素是变量（混淆） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/exec")
def exec():
    tool = "git"
    cmd = request.args.get("c", "status")
    result = subprocess.run(
        [tool, cmd],
        capture_output=True,
        text=True,
        timeout=10
    )
    return result.stdout
""",
    "python",
    "ccot_run_list_first_const.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.run([\"git\", cmd]) 列表 + shell=False，tool 是硬编码 \"git\"，cmd 是用户输入。git 接收 cmd 作为子命令，shell 不参与。无命令注入",
    "no fix needed（但 cmd 应做白名单限制 git 子命令）",
    """
代码中 tool=\"git\" 看似安全，但 git 本身支持很多危险操作（git config core.editor / git push 远程仓库等），攻击者可以通过 cmd=\"config core.editor vim\" 间接实现任意命令执行。""",
    """
问题：模型把\"git 子命令风险\"夸大为\"命令注入\"。git 是独立可执行文件，git 进程内解释子命令，不调用 shell。cmd=\"config core.editor vim\" 在 git 中执行 git config 命令，修改 git 配置。这是 git 内部行为，不是 shell 注入。""",
    """
1. 污染源：cmd = request.args.get('c')。
2. 危险 sink：subprocess.run([\"git\", cmd])。
3. 数据流追踪：cmd → 列表第二个元素 → execvp(git) → git 进程解释。
4. 防御评估（git 子命令边界）：
   (a) shell=False + 列表，git 作为独立可执行文件启动。
   (b) git 进程内解释 argv[1] 作为子命令，git 不调用 shell 解释。
   (c) cmd = \"config core.editor vim\" 在 git 中是合法的子命令，git 修改本地配置。
   (d) 这是 git 内部行为，不是 CWE-78 命令注入。
5. 结论：git + 列表形式无命令注入。cmd 用户控制是 git 子命令风险（应用层应做白名单）。"""
)

# --- F8: subprocess.run 列表 + check=True（异常处理） ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ensure")
def ensure():
    path = request.args.get("p", "/tmp")
    # check=True 时 returncode != 0 抛 CalledProcessError
    result = subprocess.run(
        ["test", "-d", path],
        check=True,
        capture_output=True,
        text=True
    )
    return "exists"
""",
    "python",
    "ccot_run_list_check_safe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.run([\"test\", \"-d\", path], check=True) 列表 + shell=False，check=True 只控制 returncode != 0 时的异常行为，与命令注入防护无关。path 作为 test 的字面参数",
    "no fix needed",
    """
check=True 会让命令失败时抛 CalledProcessError，可能泄露错误信息。path 是用户输入，攻击者可以通过 path=\"../etc\" 触发 test 失败错误，错误信息可能泄露文件系统结构。""",
    """
问题：模型把错误信息泄露夸大为命令注入。check=True 的副作用是异常处理，不是 shell 解释。path = \"../etc\" 让 test 检查 ../etc 目录，test 返回 0（如果存在），如果不存在抛 CalledProcessError 显示错误信息——这是正常的异常处理路径，不是命令注入。""",
    """
1. 污染源：path = request.args.get('p')。
2. 危险 sink：subprocess.run([\"test\", \"-d\", path], check=True)。
3. 数据流追踪：path → 列表 → execvp(test)。
4. 防御评估（check=True + 列表）：
   (a) check=True 是异常处理标志，与 shell 解释无关。
   (b) shell=False + 列表，test 进程内解析 path 为目录路径。
   (c) test 不存在目录时返回 1，check=True 抛 CalledProcessError 异常。
   (d) 这是正常的错误处理，不是命令注入。
5. 结论：check=True + 列表无命令注入。代码安全。"""
)

# --- F9: subprocess.run 列表 + close_fds ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/isolate")
def isolate():
    cmd_input = request.args.get("c", "")
    result = subprocess.run(
        [\"python3\", \"-c\", cmd_input],
        capture_output=True,
        text=True,
        timeout=5,
        close_fds=True
    )
    return result.stdout
""",
    "python",
    "ccot_run_python3_c_arg.py",
    True,
    "CWE-94 代码注入",
    "Critical",
    "request.args.get('c')",
    "subprocess.run(['python3', '-c', cmd_input])",
    "subprocess.run([\"python3\", \"-c\", cmd_input]) 把用户输入 cmd_input 作为 Python 代码传给 python3 -c 解释执行。python3 进程内执行任意 Python 代码，攻击者可执行 os.system('rm -rf /')、读取文件、网络请求等任意操作。这是 CWE-94 代码注入，不是 CWE-78",
    "禁止把用户输入作为 Python 代码执行，应改用预定义脚本 + 参数传递",
    """
代码用列表 + shell=False，python3 -c 是合法 Python 选项，cmd_input 作为 Python 代码参数传给 python3 进程。python3 进程会执行 cmd_input 中的 Python 代码，但 shell 不参与，无命令注入。代码安全。""",
    """
问题：模型把\"python3 -c 执行任意代码\"误判为安全。这不是 CWE-78（无 shell 解释器），而是更严重的 CWE-94 代码注入——python3 进程内执行任意 Python 代码，攻击者可执行 os.system、subprocess.Popen、读文件等。命令注入分析应区分 shell 注入和代码注入。""",
    """
1. 污染源：cmd_input = request.args.get('c')。
2. 危险 sink：subprocess.run([\"python3\", \"-c\", cmd_input])。
3. 数据流追踪：cmd_input → argv[2] → python3 进程解释。
4. 漏洞分析（代码注入 vs 命令注入）：
   (a) shell=False + 列表，无 /bin/sh 参与，**无 CWE-78 命令注入**。
   (b) 但 python3 -c 接收的 cmd_input 是 Python 源代码，python3 进程内解释执行。
   (c) 攻击者传入 cmd_input=\"import os; os.system('rm -rf /')\" → python3 执行任意代码。
   (d) 这是 CWE-94 代码注入（Code Injection），危害比 CWE-78 更大（RCE）。
5. 结论：python3 -c + 用户输入存在 CWE-94 代码注入（Critical）。建议禁止此模式，改用预定义脚本。"""
)

# --- F10: subprocess.run 与 os.popen 区别 ---
add(
    """
import os
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/read")
def read():
    path = request.args.get("p", "")
    # 反模式：混用 os.popen 和 subprocess.run
    if path.startswith("/safe/"):
        stream = os.popen(f"cat {path}")
        out = stream.read()
        stream.close()
    else:
        result = subprocess.run(
            ["cat", path],
            capture_output=True,
            text=True
        )
        out = result.stdout
    return out
""",
    "python",
    "ccot_os_popen_vuln_vs_run_safe.py",
    True,
    "CWE-78 命令注入",
    "Critical",
    "request.args.get('p')",
    "os.popen(f'cat {path}')",
    "os.popen 内部调用 subprocess.Popen(shell=True)，等价于 subprocess.run 字符串 + shell=True。path 拼接进 f-string 直接被 /bin/sh -c 解释，存在 CWE-78 命令注入。else 分支的 subprocess.run 列表 + shell=False 是安全的，但 if 分支不安全",
    "用 subprocess.run(['cat', path], shell=False) 替代 os.popen",
    """
代码用 os.popen 和 subprocess.run 两种方式，os.popen 是 subprocess 的早期封装，安全性相同。if 分支的 f\"cat {path}\" 看似安全（因 path.startsWith(\"/safe/\") 白名单），但攻击者可以通过路径穿越如 path=\"/safe/../../etc/passwd\" 触发 cat。else 分支的列表形式安全。代码整体无命令注入。""",
    """
问题：模型对 os.popen 的语义理解错误。os.popen 在 Python 3 文档明确：\"Open a pipe to or from command. The return value is an open file object connected to the pipe.\"，内部实现是 subprocess.Popen(shell=True) 或类似。os.popen(cmd) 等价于 subprocess.run(cmd, shell=True)，需要 shell 解释 cmd 字符串。path = \"/safe/../../etc/passwd\" 在 f-string 拼接后是 \"cat /safe/../../etc/passwd\"，shell 解释为 cat 单一参数（含路径穿越），无 shell 元字符——但 os.popen 调用了 /bin/sh -c，只要 f-string 拼接用户输入 + shell=True 模式，就是 CWE-78 命令注入（即便当前无有效元字符，攻击者仍可传入 ; | & 等）。""",
    """
1. 污染源：path = request.args.get('p')。
2. 危险 sink：os.popen(f\"cat {path}\")（if 分支）。
3. 数据流追踪：path → f-string 拼接 → os.popen → subprocess.Popen(shell=True) → /bin/sh -c。
4. 防御评估（os.popen + shell=True）：
   (a) os.popen 内部用 subprocess.Popen + shell=True，行为等价于 subprocess.run(字符串, shell=True)。
   (b) path = \"/safe/../../etc/passwd\" 在 f-string 后是 \"cat /safe/../../etc/passwd\"，
       shell 解释为 cat + 路径，cat 读取文件（路径穿越是信息泄露，非命令注入）。
   (c) 但 path = \"; rm -rf /\" → os.popen(\"cat ; rm -rf /\") → shell 执行 cat 和 rm 两条命令。
   (d) 这是 CWE-78 命令注入。
5. 结论：os.popen + f-string 拼接用户输入存在 CWE-78 命令注入。else 分支（subprocess.run 列表）安全。"""
)


# ===========================================================================
# 类别 G: 跨文件参数（10 条）
# 覆盖常见跨文件场景：
#   - config.py 硬编码凭证
#   - config.yaml/env 注入
#   - 跨文件函数调用（helper.py sanitize）
#   - 跨模块的命令构造
# ===========================================================================

# --- G1: config.py 硬编码凭证（典型 CWE-798） ---
add(
    """
# 跨文件：main.py 导入 config 模块
# config.py 内容（注释示意）：
# DB_PASSWORD = \"supersecret123\"
# API_KEY = \"sk-abc123def456\"

from flask import Flask, request
import config

app = Flask(__name__)


@app.route(\"/login\")
def login():
    user = request.args.get(\"user\", \"\")
    # 使用 config 中的硬编码密码连接数据库
    conn = connect_db(config.DB_PASSWORD)
    return login_with_conn(conn, user)
""",
    "python",
    "ccot_crossfile_config_hardcoded.py",
    True,
    "CWE-798 硬编码凭证",
    "Critical",
    "config.py 字面量",
    "config.DB_PASSWORD = 'supersecret123'",
    "跨文件追踪：config.py 定义 DB_PASSWORD/API_KEY 为字符串字面量（凭据），main.py 通过 import config 引用。代码中确实存在硬编码凭证，符合 CWE-798 判定标准——硬编码的字面量凭证本身就是漏洞",
    "从 os.environ.get('DB_PASSWORD') 读取，不在源码中硬编码",
    """
代码从 config 模块导入 DB_PASSWORD，但 config.py 是配置文件，不在 main.py 中。所以 main.py 本身没有硬编码凭证，应该判安全。凭证在 config.py 中的问题应单独审计。""",
    """
问题：模型不追踪跨文件 import。代码注释明确说明 config.py 含 DB_PASSWORD = \"supersecret123\"，main.py 通过 `import config` 引用该常量。审计时应跨文件追踪，看到 config.DB_PASSWORD 的来源（字面量）就应判 CWE-798。安全审计的视野不应局限于单文件。""",
    """
1. 跨文件污染源：config.py 模块级变量 DB_PASSWORD = 'supersecret123'。
2. 跨文件 sink：main.py 通过 `import config` 引用 config.DB_PASSWORD，传入 connect_db。
3. 数据流追踪：config.py 字面量 → 模块导入 → main.py 函数调用 → connect_db。
4. 漏洞分析（跨文件 CWE-798）：
   (a) 凭证定义在 config.py（注释明确），main.py 跨文件引用。
   (b) 凭据是字面量字符串（\"supersecret123\"），符合 CWE-798 硬编码凭证判定。
   (c) 安全审计应追踪模块导入，看到 config.DB_PASSWORD 来源是字面量即判 True。
   (d) \"在 config.py 而非 main.py\"不是开脱——只要源码中存在字面量凭证就是 CWE-798。
5. 结论：跨文件追踪识别 CWE-798 硬编码凭证。代码有漏洞。"""
)

# --- G2: config.yaml 含用户控制值（边界：配置文件污染） ---
add(
    """
# 跨文件：app.yaml 含远程地址配置
# app.yaml:
# database:
#   host: \"db.example.com\"

import yaml
from flask import Flask, request

app = Flask(__name__)


def load_config():
    with open(\"app.yaml\") as f:
        return yaml.safe_load(f)


@app.route(\"/query\")
def query():
    table = request.args.get(\"t\", \"\")
    config = load_config()
    host = config[\"database\"][\"host\"]  # 来自 yaml 文件
    conn = connect_to_db(host=host, table=table)
    return conn.execute(f\"SELECT * FROM {table}\")
""",
    "python",
    "ccot_crossfile_yaml_config_safe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "load_config 用 yaml.safe_load 解析配置文件，host 来自 yaml 文件（不可控），table 来自用户输入。连接数据库用 f-string 拼接 table 是 SQL 注入（CWE-89），但**非 CWE-78 命令注入**。审计跨文件追踪时，要区分不同的 sink 类型",
    "用参数化查询替换 f-string 拼接：conn.execute(\"SELECT * FROM %s\", (table,))",
    """
代码加载 yaml 配置后用 f-string 拼接 table，table 是用户输入，存在命令注入。攻击者可以传入 table=\"; rm -rf /\" 触发 shell 执行。""",
    """
问题：模型混淆了 SQL 注入和命令注入。f-string 拼接 table 进入 SQL 语句（conn.execute），这是 CWE-89 SQL 注入，不是 CWE-78 命令注入（无 shell 解释器参与）。同时 yaml.safe_load 正确处理 yaml 文件，无 yaml.load 风险。审计跨文件场景时要区分不同 sink 的漏洞类型。""",
    """
1. 跨文件源：app.yaml (host=\"db.example.com\")，不可控。
2. 用户输入源：table = request.args.get('t')。
3. sink1：yaml.safe_load（安全，无 yaml.load 风险）。
4. sink2：conn.execute(f\"SELECT * FROM {table}\")。
5. 跨文件追踪（区分漏洞类型）：
   (a) host 来自 yaml 文件（不可控），不参与拼接。
   (b) table 是用户输入，进入 SQL 语句 → CWE-89 SQL 注入。
   (c) SQL 注入不涉及 shell 解释器，是单独的漏洞类型。
   (d) **无 CWE-78 命令注入**。
6. 结论：跨文件追踪识别 CWE-89 SQL 注入，无 CWE-78 命令注入。SQL 注入修复：参数化查询。"""
)

# --- G3: helper.py 提供的 sanitize 函数（验证是否真被调用） ---
add(
    """
# 跨文件：sanitize.py 提供 escape_shell_arg 函数
# sanitize.py:
# def escape_shell_arg(s):
#     import shlex
#     return shlex.quote(s)

from flask import Flask, request
from sanitize import escape_shell_arg
import subprocess

app = Flask(__name__)


@app.route(\"/run\")
def run():
    cmd = request.args.get(\"c\", \"\")
    # 反模式：开发者在 sanitize.py 中实现了 shlex.quote，
    # 但 main.py 在拼接到命令字符串时忘了调用
    full_cmd = f\"echo User input: {cmd}\"
    result = subprocess.run(
        full_cmd,
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_crossfile_helper_unused.py",
    True,
    "CWE-78 命令注入",
    "Critical",
    "request.args.get('c')",
    "subprocess.run(f'echo User input: {cmd}', shell=True)",
    "虽然 sanitize.py 提供了 escape_shell_arg 函数，但 main.py 在拼接 full_cmd 时**没有调用**该函数，cmd 直接拼入 f-string。shell=True 启动 /bin/sh -c 解释 full_cmd，cmd 中的元字符（; | &）可触发命令注入",
    "调用 escape_shell_arg：full_cmd = f'echo User input: {escape_shell_arg(cmd)}'",
    """
代码从 sanitize.py 导入了 escape_shell_arg 函数，开发者意图是用该函数转义 cmd。subprocess.run 默认 shell=False，full_cmd 作为可执行文件路径，shell 不解释，代码安全。""",
    """
问题：模型只看到\"导入了 escape_shell_arg\"就认为开发者意图转义，没实际验证 sanitize 函数是否被调用。审计跨文件场景时，必须追踪到具体的 sink 调用点，确认防御函数是否真的被执行。本代码 escape_shell_arg 被 import 但从未被调用，full_cmd 中 cmd 是原始未转义字符串，shell=True 触发命令注入。""",
    """
1. 跨文件源：sanitize.py 提供 escape_shell_arg（基于 shlex.quote）。
2. 用户输入源：cmd = request.args.get('c')。
3. sink：subprocess.run(full_cmd, shell=True)。
4. 跨文件追踪（验证防御是否实际执行）：
   (a) main.py 导入 escape_shell_arg 但**未调用**。
   (b) full_cmd = f\"echo User input: {cmd}\"，cmd 是原始用户输入。
   (c) shell=True 启动 /bin/sh -c 解释 full_cmd，cmd 含 ; | & 时触发命令注入。
   (d) 即便 sanitize.py 提供了正确转义，未调用等同于无防御。
5. 结论：跨文件追踪识别防御函数未实际调用，存在 CWE-78 命令注入。"""
)

# --- G4: env 变量从外部传入 → 命令构造 ---
add(
    """
import os
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route(\"/bin\")
def bin():
    # 跨进程：环境变量从外部传入（docker -e / shell export）
    user_bin = os.environ.get(\"USER_BIN\", \"/usr/bin/ls\")
    arg = request.args.get(\"a\", \"-l\")
    result = subprocess.run(
        [user_bin, arg],
        capture_output=True,
        text=True,
        timeout=5
    )
    return result.stdout
""",
    "python",
    "ccot_crossfile_env_user_bin.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "subprocess.run([user_bin, arg]) 列表 + shell=False，user_bin 来自环境变量 USER_BIN（部署时设置），arg 来自用户输入。execvp(user_bin) 把 user_bin 作为可执行文件路径。无 shell 解释，无 CWE-78 命令注入",
    "no fix needed（但 user_bin 应做白名单，arg 应做选项白名单）",
    """
代码 user_bin 来自环境变量（部署时可被攻击者控制，如 docker exec -e USER_BIN=\"/bin/sh\"），攻击者可以设置 USER_BIN=\"/bin/sh\"，让子进程启动 sh。arg 也是用户输入，可能触发 sh 的 -c 参数执行任意命令。""",
    """
问题：模型把\"环境变量注入\"夸大为\"命令注入\"。环境变量是部署时设置的，攻击者需要先获得部署环境访问权限才能注入 env（不在 web 漏洞范围内）。即便 user_bin=\"/bin/sh\"，subprocess.run 列表 + shell=False，execvp(\"/bin/sh\") 启动 sh 但 sh 等待 stdin 输入或尝试交互模式（不会执行任意命令）。arg 用户控制是业务逻辑问题，不是命令注入。""",
    """
1. 跨进程源：USER_BIN 环境变量（部署时设置）。
2. 用户输入源：arg = request.args.get('a')。
3. sink：subprocess.run([user_bin, arg])。
4. 防御评估（env + 列表）：
   (a) shell=False + 列表，execvp(user_bin) 把 user_bin 作为可执行文件路径。
   (b) user_bin=\"/bin/sh\" → execvp 启动 /bin/sh，但因 shell=False，sh 等待 stdin 或超时，
       arg 作为 sh 的位置参数而非 -c 参数。
   (c) 这是业务逻辑问题（env 用户控制 + arg 用户控制 → 任意命令执行），不是 CWE-78。
5. 结论：env + 列表无 CWE-78 命令注入。env 用户控制属于环境配置问题，应用层应做白名单。"""
)

# --- G5: 跨文件函数 sanitize_shell 但 sink 用 shlex.quote ---
add(
    """
# 跨文件：utils.py 提供 sanitize_for_shell
# utils.py:
# def sanitize_for_shell(s):
#     # 实现错误：仅替换 ; 和 |，不处理 $ ` \\
#     return s.replace(\";\", \"\").replace(\"|\", \"\")

from flask import Flask, request
from utils import sanitize_for_shell
import subprocess

app = Flask(__name__)


@app.route(\"/run\")
def run():
    text = request.args.get(\"t\", \"\")
    safe = sanitize_for_shell(text)
    result = subprocess.run(
        f\"echo {safe}\",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_crossfile_weak_sanitize.py",
    True,
    "CWE-78 命令注入",
    "Critical",
    "request.args.get('t')",
    "subprocess.run(f'echo {safe}', shell=True)",
    "utils.py 的 sanitize_for_shell 实现是黑名单过滤（只去除 ; |），不处理 $ ` \\ & 等其他 shell 元字符。攻击者传入 text=\"\\$(rm -rf /)\" 可绕过 sanitize 触发命令替换。**跨文件审计必须验证 sanitize 函数的实现**",
    "用 shlex.quote 替代自实现的 sanitize：safe = shlex.quote(text)",
    """
代码从 utils.py 导入了 sanitize_for_shell，开发者意图是过滤危险字符。subprocess.run shell=True 会用 sh 解释，但 sanitize 已经去除了 ; 和 | 等常见元字符，代码安全。""",
    """
问题：模型只看到\"有 sanitize 函数\"就判安全，没验证 sanitize 的实现。跨文件审计必须追踪到 sanitize 函数的实际实现，验证过滤是否完整。本代码 sanitize_for_shell 是黑名单过滤（仅 ; |），不处理 $ ` \\ & 等元字符，存在绕过。""",
    """
1. 跨文件源：utils.py 提供 sanitize_for_shell（黑名单过滤 ; |）。
2. 用户输入源：text = request.args.get('t')。
3. sink：subprocess.run(f\"echo {safe}\", shell=True)。
4. 跨文件追踪（验证 sanitize 实现）：
   (a) sanitize_for_shell 实现：仅 replace \";\" → \"\" 和 \"|\" → \"\"，不处理其他元字符。
   (b) text=\"\\$(rm -rf /)\" → safe=\"\\$(rm -rf /)\"（未过滤）。
   (c) shell=True 启动 /bin/sh -c \"echo \\$(rm -rf /)\"，$() 命令替换执行。
   (d) 攻击者还可用 `cmd`（反引号）、& (background)、\\ (escape) 等绕过。
5. 结论：跨文件追踪识别 sanitize 实现不完整，存在 CWE-78 命令注入。"""
)

# --- G6: 配置文件含固定 shell 命令字符串 ---
add(
    """
# 跨文件：settings.py 含命令模板
# settings.py:
# PING_TEMPLATE = \"ping -c 1 {host}\"

from flask import Flask, request
import settings
import subprocess

app = Flask(__name__)


@app.route(\"/ping\")
def ping():
    host = request.args.get(\"host\", \"\")
    cmd = settings.PING_TEMPLATE.format(host=host)
    result = subprocess.run(
        cmd.split(),
        capture_output=True,
        text=True,
        timeout=5
    )
    return result.stdout
""",
    "python",
    "ccot_crossfile_template_str_split.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "settings.PING_TEMPLATE 是硬编码模板 \"ping -c 1 {host}\"，format 替换后 cmd = \"ping -c 1 USER_HOST\"。cmd.split() 按空白切分（不识别引号），传 subprocess.run 列表。shell=False 下 execvp 接收独立 argv，host 用户控制只影响参数值（ping 会尝试解析为 IP 主机）",
    "no fix needed",
    """
cmd.split() 切分字符串，host 用户输入可能含空格（如 host=\"google.com; rm\"），切分后列表中含 \";\" 和 \"rm\"，execvp 可能错误处理。攻击者可借此执行额外命令。""",
    """
问题：模型担心 cmd.split() 切分不识别引号，但本代码 host 是 IP/域名，开发者意图是单值。host=\"google.com; rm\" 是用户异常输入，cmd.split() 切分为 [\"ping\", \"-c\", \"1\", \"google.com;\", \"rm\"]，execvp 接收 5 个独立 argv，ping 收到的额外参数 \"rm\" 是字面字符串（ping 期望单个 host，会报错 \"unknown host\"）。无 shell 解释，无命令注入。""",
    """
1. 跨文件源：settings.PING_TEMPLATE = \"ping -c 1 {host}\"（硬编码）。
2. 用户输入源：host = request.args.get('host')。
3. sink：subprocess.run(cmd.split())。
4. 跨文件追踪（模板 + split）：
   (a) settings.py 中 PING_TEMPLATE 是硬编码模板，无用户输入。
   (b) format 替换后 cmd = \"ping -c 1 {host}\"，host 是用户输入。
   (c) cmd.split() 按空白切分（不识别引号），host 含空格时切分为多个 token。
   (d) subprocess.run 列表 + shell=False，execvp(ping) 接收独立 argv。
   (e) host=\"google.com; rm\" 切分后 ping 收到 [\"ping\", \"-c\", \"1\", \"google.com;\", \"rm\"]，
       ping 解析为 host = \"google.com;\"（含分号字面字符），报 unknown host 错误。
5. 结论：模板 + cmd.split() + 列表 + shell=False 无命令注入。代码安全。"""
)

# --- G7: 跨文件 import 的 subprocess 调用 ---
add(
    """
# 跨文件：runner.py 提供 run_command 函数
# runner.py:
# import subprocess
# def run_command(cmd):
#     return subprocess.run(cmd, shell=True, capture_output=True, text=True)

from flask import Flask, request
from runner import run_command

app = Flask(__name__)


@app.route(\"/exec\")
def exec():
    user_cmd = request.args.get(\"c\", \"ls\")
    result = run_command(f\"echo {user_cmd}\")
    return result.stdout
""",
    "python",
    "ccot_crossfile_runner_shell_true.py",
    True,
    "CWE-78 命令注入",
    "Critical",
    "request.args.get('c')",
    "subprocess.run(f'echo {user_cmd}', shell=True)（在 runner.py）",
    "跨文件追踪：main.py 调用 runner.run_command，runner.py 内部用 subprocess.run(字符串, shell=True)。user_cmd 通过 f-string 拼接后传入 runner，shell=True 启动 /bin/sh -c 解释完整命令，user_cmd 含 ; | & 时触发命令注入",
    "改用 runner.run_command_safe（列表形式）或在 main.py 用 shlex.quote(user_cmd)",
    """
代码用列表 + shell=False 风格（subprocess.run 接收列表），无 shell 解释。user_cmd 用户输入作为 echo 的字面参数，代码安全。""",
    """
问题：模型没追踪到 runner.py 的实际实现。审计跨文件调用时，必须追踪到被调用函数的源码，确认实际使用的 subprocess 参数。本代码 runner.run_command 内部用 shell=True + 字符串，与 main.py 的列表形式假设不一致。""",
    """
1. 跨文件源：runner.py 提供 run_command(cmd) → subprocess.run(cmd, shell=True)。
2. 用户输入源：user_cmd = request.args.get('c')。
3. sink（实际在 runner.py）：subprocess.run(f\"echo {user_cmd}\", shell=True)。
4. 跨文件追踪（必须追踪到被调用函数）：
   (a) main.py 调用 run_command(f\"echo {user_cmd}\")，传字符串而非列表。
   (b) runner.py 内部用 subprocess.run(字符串, shell=True)，等价于命令注入模式。
   (c) user_cmd = \"; rm -rf /\" → runner 执行 \"echo ; rm -rf /\" → shell 执行 echo 和 rm。
   (d) main.py 的调用模式（看似列表）和 runner.py 的实现（实际 shell=True）不一致。
5. 结论：跨文件追踪识别 runner.py 使用 shell=True，存在 CWE-78 命令注入。"""
)

# --- G8: 跨文件 logger.py 写入用户输入到日志 ---
add(
    """
# 跨文件：logger.py 提供 log_event 函数
# logger.py:
# import logging, subprocess
# def log_event(msg):
#     # 反模式：用 echo 写入日志
#     subprocess.run(f\"echo {msg} >> /var/log/app.log\", shell=True)

from flask import Flask, request
from logger import log_event

app = Flask(__name__)


@app.route(\"/submit\")
def submit():
    username = request.args.get(\"u\", \"\")
    log_event(f\"User login: {username}\")
    return \"ok\"
""",
    "python",
    "ccot_crossfile_logger_log_injection.py",
    True,
    "CWE-78 命令注入（间接）",
    "High",
    "request.args.get('u')",
    "subprocess.run(f'echo {msg} >> /var/log/app.log', shell=True)（在 logger.py）",
    "跨文件追踪：logger.py 用 echo + 字符串拼接 + shell=True 写入日志。username 通过 main.py 拼接到 msg 后传入 log_event，msg 含 ; | & 时触发命令注入。同时还存在日志注入（CWE-117），username 含换行符可伪造日志条目",
    "用 logging 模块替代 subprocess 写入日志；或 shlex.quote(msg)",
    """
代码用 logger.py 的 log_event 记录用户登录，username 用户输入。log_event 是普通日志函数，username 通过 f-string 拼接进入日志消息，触发日志注入（CWE-117），但不构成命令注入。""",
    """
问题：模型只关注日志注入（CWE-117），忽略了 logger.py 内部用 subprocess shell=True 写日志。跨文件追踪必须看到 logger.py 实际使用 subprocess + shell=True + f-string 拼接，存在 CWE-78 命令注入。同时还存在 CWE-117 日志注入。""",
    """
1. 跨文件源：logger.py 提供 log_event(msg) → subprocess.run(f\"echo {msg} >> /var/log/app.log\", shell=True)。
2. 用户输入源：username = request.args.get('u')。
3. sink（实际在 logger.py）：subprocess.run(shell=True) + 字符串拼接。
4. 跨文件追踪（必须追踪到实际 subprocess 调用）：
   (a) main.py 调用 log_event(f\"User login: {username}\")，username 用户输入拼入 msg。
   (b) logger.py 内部用 subprocess.run(f\"echo {msg} >> ...\", shell=True)。
   (c) username = \"; rm -rf /\" → msg = \"User login: ; rm -rf /\" → echo 执行两条命令。
   (d) 同时 username=\"fake_user\\nERROR: ...\" 触发日志注入（CWE-117）。
5. 结论：跨文件追踪识别 logger.py 的 subprocess shell=True，存在 CWE-78 + CWE-117。"""
)

# --- G9: 跨文件 constants.py 含危险常量 ---
add(
    """
# 跨文件：constants.py 定义 USE_SHELL = True
# constants.py:
# USE_SHELL = True

from flask import Flask, request
import subprocess
import constants

app = Flask(__name__)


@app.route(\"/cmd\")
def cmd():
    arg = request.args.get(\"a\", \"\")
    # 跨文件常量 USE_SHELL 决定 shell 参数
    result = subprocess.run(
        f\"process {arg}\",
        shell=constants.USE_SHELL,
        capture_output=True,
        text=True
    )
    return result.stdout
""",
    "python",
    "ccot_crossfile_constants_shell.py",
    True,
    "CWE-78 命令注入",
    "Critical",
    "request.args.get('a')",
    "subprocess.run(f'process {arg}', shell=True)",
    "跨文件追踪：constants.USE_SHELL = True 是硬编码常量，main.py 用作 subprocess.run 的 shell 参数。arg 用户输入拼入 f-string，shell=True 启动 /bin/sh -c 解释完整命令",
    "改 shell=False + 列表形式：subprocess.run(['process', arg], shell=False)",
    """
代码从 constants.py 导入 USE_SHELL 常量，开发者意图是控制 shell 参数。subprocess.run 默认 shell=False（Python 3），arg 用户输入作为 process 的字面参数，代码安全。""",
    """
问题：模型假设 constants.USE_SHELL 默认是 False，但实际 constants.py 定义为 True。跨文件审计必须追踪到常量的实际值，不能假设默认安全。""",
    """
1. 跨文件源：constants.USE_SHELL = True（硬编码）。
2. 用户输入源：arg = request.args.get('a')。
3. sink：subprocess.run(f\"process {arg}\", shell=constants.USE_SHELL)。
4. 跨文件追踪（必须追踪常量值）：
   (a) main.py 用 constants.USE_SHELL 作为 shell 参数。
   (b) constants.py 中 USE_SHELL = True（注释明确），shell 实际为 True。
   (c) arg = \"; rm -rf /\" → subprocess.run(\"process ; rm -rf /\", shell=True) → shell 执行两条命令。
   (d) 不能假设 subprocess.run 默认安全——必须追踪 shell 参数的实际值。
5. 结论：跨文件追踪识别 constants.USE_SHELL = True，存在 CWE-78 命令注入。"""
)

# --- G10: 跨文件 __init__.py 副作用 ---
add(
    """
# 跨文件：db/__init__.py 在 import 时执行命令
# db/__init__.py:
# import os
# os.system(f\"echo 'DB module loaded: {os.getcwd()}'\")
# 这种反模式在 import 时执行命令，跨文件审计困难

from flask import Flask, request
import db  # 触发 db/__init__.py 执行

app = Flask(__name__)


@app.route(\"/test\")
def test():
    return \"ok\"
""",
    "python",
    "ccot_crossfile_init_side_effect.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "import db 触发 db/__init__.py 执行，但 db/__init__.py 中的 os.system 使用的是 os.getcwd()（不可控）拼接到固定字符串。无用户输入进入 os.system 命令字符串。**无 CWE-78 命令注入**。但 import 副作用是反模式，应避免",
    "no fix needed（但应重构 db/__init__.py，避免 import 时执行命令）",
    """
代码 import db，db 模块的 __init__.py 在 import 时执行 os.system(f\"echo 'DB module loaded: {os.getcwd()}'\")，传入 os.getcwd() 是不可控的，但 os.system 模式本身有风险。如果 os.getcwd() 含特殊字符（不可能，因 Python 内部函数），可能触发命令注入。代码安全（但反模式）。""",
    """
问题：模型过度担心 os.getcwd() 的安全性。os.getcwd() 返回当前工作目录的绝对路径，不含 shell 元字符。即便路径含空格或引号（罕见），命令字符串 'echo \"...\"' 中的 echo 是字面命令，路径作为 echo 的字面参数传入。**无 CWE-78 命令注入**。""",
    """
1. 跨文件源：db/__init__.py 在 import 时执行 os.system。
2. 用户输入源：无（os.getcwd() 不可控）。
3. sink：os.system(f\"echo 'DB module loaded: {os.getcwd()}'\")（在 db/__init__.py）。
4. 跨文件追踪（验证 import 副作用）：
   (a) main.py 导入 db 触发 db/__init__.py 执行。
   (b) os.system 接收的字符串是硬编码 + os.getcwd()，无用户输入。
   (c) os.getcwd() 返回绝对路径，不含 shell 元字符。
   (d) 即便路径含特殊字符，echo 是字面命令，路径作为 echo 的字面参数。
5. 结论：跨文件 import 副作用无 CWE-78 命令注入。但 import 时执行命令是反模式，应重构。"""
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


def build_messages(sample):
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
    print("\n" + "=" * 60)
    print("验证 CCoT v2 对比样本")
    print("=" * 60)

    assert len(SAMPLES) >= 30, f"样本数应 >= 30，实际 {len(SAMPLES)}"
    vuln_count = sum(1 for s in SAMPLES if s["has_vulnerability"])
    safe_count = len(SAMPLES) - vuln_count
    print(f"[OK] 样本数: {len(SAMPLES)} (vuln={vuln_count}, safe={safe_count})")

    # 类别分布
    cat_d = [s for s in SAMPLES if s["filename"].startswith("ccot_list_shell") or s["filename"].startswith("ccot_string_shell") or s["filename"].startswith("ccot_shlex_quote_shell") or s["filename"].startswith("ccot_popen") or s["filename"].startswith("ccot_check_output") or s["filename"].startswith("ccot_run_string") or s["filename"].startswith("ccot_sh_c") or s["filename"].startswith("ccot_bash_c") or s["filename"].startswith("ccot_list_cmd")]
    cat_e = [s for s in SAMPLES if s["filename"].startswith("ccot_shlex_quote_empty") or s["filename"].startswith("ccot_shlex_quote_unicode") or s["filename"].startswith("ccot_shlex_quote_nul") or s["filename"].startswith("ccot_shlex_split") or s["filename"].startswith("ccot_shlex_join") or s["filename"].startswith("ccot_shlex_quote_concat") or s["filename"].startswith("ccot_shlex_quote_split_misuse") or s["filename"].startswith("ccot_shlex_quote_nested") or s["filename"].startswith("ccot_shlex_quote_str") or s["filename"].startswith("ccot_shlex_quote_split_cmd")]
    cat_f = [s for s in SAMPLES if s["filename"].startswith("ccot_run_list_env") or s["filename"].startswith("ccot_run_list_cwd") or s["filename"].startswith("ccot_run_stdin") or s["filename"].startswith("ccot_run_list_timeout") or s["filename"].startswith("ccot_call_list") or s["filename"].startswith("ccot_run_list_first") or s["filename"].startswith("ccot_run_list_check") or s["filename"].startswith("ccot_run_python3_c") or s["filename"].startswith("ccot_os_popen")]
    cat_g = [s for s in SAMPLES if s["filename"].startswith("ccot_crossfile_")]
    print(f"[OK] 类别分布: D.shell+列表边界={len(cat_d)}, E.shlex边界={len(cat_e)}, F.subprocess边界={len(cat_f)}, G.跨文件={len(cat_g)}")

    # CCoT 格式校验
    for i, sample in enumerate(SAMPLES):
        record = build_messages(sample)
        msgs = record["messages"]
        assert len(msgs) == 3
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
        assert json_match
        verdict = json.loads(json_match.group(1))
        for field in ["has_vulnerability", "vulnerability_type", "risk_level",
                      "source", "sink", "explanation", "fix_suggestion"]:
            assert field in verdict
        if not sample["has_vulnerability"]:
            assert verdict["vulnerability_type"] == "none"
            assert verdict["risk_level"] == "None"
        else:
            assert verdict["vulnerability_type"] != "none"

    print(f"[OK] 所有 {len(SAMPLES)} 条样本 CCoT 格式合规")

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
    print(f"共 {len(SAMPLES)} 条 CCoT v2 对比样本")
    vuln = sum(1 for s in SAMPLES if s["has_vulnerability"])
    safe = len(SAMPLES) - vuln
    print(f"  漏洞样本: {vuln}  安全样本: {safe}")

    validate()

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for sample in SAMPLES:
            record = build_messages(sample)
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"\n已写入: {OUTPUT_FILE}")

    # 验证写入
    count = 0
    with open(OUTPUT_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            assert "messages" in rec
            count += 1
    assert count == len(SAMPLES)
    print(f"[OK] 文件包含 {count} 条有效 JSONL 记录")


if __name__ == "__main__":
    main()
