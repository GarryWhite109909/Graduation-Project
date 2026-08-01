"""
Batch 2: 追加到 distill_glm_cwe_cvss.jsonl 和 distill_glm_web.jsonl
- cwe_cvss: CWE-78 OS 命令注入 (12 条: 3 漏洞 + 9 安全)
- web:      CWE-79 XSS (12 条: 3 漏洞 + 9 安全)

复用 batch1 的系统提示词和辅助函数。
"""
import sys
import os
import json
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from gen_glm_distill_batch1 import (
    GLM_SYSTEM, build_user_cwe_cvss, build_user_web,
    assistant_response, write_sample,
)

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


# =====================================================================
# Batch 2: cwe_cvss  ——  CWE-78 OS 命令注入
# 12 条：3 漏洞 + 9 安全，覆盖 Python / Go / JavaScript
# =====================================================================

CWE_CVSS_BATCH2 = [
    # ----- 漏洞样本 3 条 -----
    {
        "lang": "Python", "has_vuln": True, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_013.py
import os
from flask import Flask, request

app = Flask(__name__)


@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    os.system(f"ping -c 1 {host}")
    return {'status': 'ok'}
```""",
        "steps": [
            "第 8 行 request.args.get('host') 获取用户输入，未做白名单或格式校验",
            "第 9 行 f-string 把 host 直接拼入 shell 命令字符串",
            "第 9 行 os.system 通过 /bin/sh -c 执行拼接后的命令字符串",
            "source→sink 间无任何防御，攻击者传 host=; rm -rf / 可注入任意命令",
            "CWE-78 OS 命令注入，Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-78 OS命令注入",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score": 9.8,
            "source": "request.args.get('host')",
            "sink": "os.system(f\"ping -c 1 {host}\")",
            "explanation": "request.args.get('host') → host → f-string 拼接进 shell 命令 → os.system 执行",
            "fix_suggestion": "使用 subprocess.run(['ping', '-c', '1', host], shell=False) 列表参数，避免 shell 解释",
        },
    },
    {
        "lang": "Python", "has_vuln": True, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_014.py
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route('/lookup')
def lookup():
    domain = request.args.get('domain', '')
    result = subprocess.run(
        f"dig +short {domain}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return {'result': result.stdout}
```""",
        "steps": [
            "第 9 行 request.args.get('domain') 获取用户输入，未做格式校验",
            "第 11 行 f-string 把 domain 拼入命令字符串",
            "第 12 行 shell=True 使 subprocess 通过 /bin/sh -c 执行拼接后的字符串",
            "shell=True + 字符串拼接是命令注入的典型组合，攻击者传 domain=; cat /etc/passwd 可执行任意命令",
            "CWE-78 OS 命令注入，Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-78 OS命令注入",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score": 9.8,
            "source": "request.args.get('domain')",
            "sink": "subprocess.run(f\"dig +short {domain}\", shell=True)",
            "explanation": "request.args.get('domain') → domain → f-string 拼接 → subprocess.run(shell=True) 执行",
            "fix_suggestion": "使用列表参数 + shell=False：subprocess.run(['dig', '+short', domain], shell=False)",
        },
    },
    {
        "lang": "Go", "has_vuln": True, "difficulty": "中等",
        "code": """```go
// distill_glm_cwe_cvss_015.go
package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	out, err := cmd.Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, "%s", out)
}
```""",
        "steps": [
            "第 11 行 r.URL.Query().Get(\"host\") 获取用户输入，未做白名单",
            "第 12 行 exec.Command(\"sh\", \"-c\", \"ping -c 1 \"+host) 显式调用 sh -c 解释命令字符串",
            "第 12 行用 + 把 host 拼入 sh -c 的命令参数，sh 会解释 ;、|、&& 等 shell 元字符",
            "source→sink 间无任何防御，攻击者传 host=; id 可注入任意命令",
            "CWE-78 OS 命令注入，Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-78 OS命令注入",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score": 9.8,
            "source": "r.URL.Query().Get(\"host\")",
            "sink": "exec.Command(\"sh\", \"-c\", \"ping -c 1 \"+host)",
            "explanation": "r.URL.Query().Get → host → 字符串拼接进 sh -c 参数 → exec.Command 执行",
            "fix_suggestion": "使用 exec.Command(\"ping\", \"-c\", \"1\", host) 直接传参，不经过 shell",
        },
    },
    # ----- 安全样本 9 条 -----
    {
        "lang": "Python", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_016.py
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    result = subprocess.run(
        ['ping', '-c', '1', host],
        shell=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return {'stdout': result.stdout}
```""",
        "steps": [
            "第 9 行 request.args.get('host') 获取用户输入",
            "第 11 行 ['ping', '-c', '1', host] 使用列表参数，每个元素作为独立 argv 传入",
            "第 12 行 shell=False（默认值）不经过 /bin/sh，host 不会被解释为 shell 元字符",
            "已检查：列表参数 + shell=False + timeout，host 仅作为 ping 的最后一个参数，无命令注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('host')",
            "sink": "subprocess.run(['ping', '-c', '1', host], shell=False)",
            "explanation": "host 作为列表参数的元素传入，shell=False 不经过 shell 解释，无命令注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_017.py
import subprocess
import shlex
from flask import Flask, request

app = Flask(__name__)


@app.route('/lookup')
def lookup():
    domain = request.args.get('domain', '')
    # shlex.quote 对 shell 元字符做转义，使输入仅作为单个参数
    quoted = shlex.quote(domain)
    result = subprocess.run(
        f"dig +short {quoted}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return {'result': result.stdout}
```""",
        "steps": [
            "第 10 行 request.args.get('domain') 获取用户输入",
            "第 12 行 shlex.quote(domain) 对 shell 元字符做转义，将输入包裹为单引号字符串",
            "第 14 行 f-string 拼接的是已转义的 quoted，shell 不会解释其中的元字符",
            "已检查：shlex.quote 是有效的 shell 转义防御，shell=True + quote 安全；但列表参数更优",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('domain')",
            "sink": "subprocess.run(f\"dig +short {quoted}\", shell=True)",
            "explanation": "domain 经 shlex.quote 转义后再拼接，shell=True 不会解释元字符，无命令注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_018.py
import subprocess
import re
from flask import Flask, request

app = Flask(__name__)

# 白名单：仅允许域名格式（字母、数字、点、连字符）
HOST_RE = re.compile(r'^[a-zA-Z0-9.\\-]+$')


@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    if not HOST_RE.match(host) or len(host) > 253:
        return {'error': 'invalid host'}, 400
    result = subprocess.run(
        ['ping', '-c', '1', host],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return {'stdout': result.stdout}
```""",
        "steps": [
            "第 13 行 request.args.get('host') 获取用户输入",
            "第 14-15 行 HOST_RE.match + len 校验：仅允许字母数字点连字符且长度 ≤253，非法输入被 400 拒绝",
            "第 17 行 ['ping', '-c', '1', host] 列表参数 + shell 默认 False",
            "已检查：白名单正则校验 + 列表参数 + shell=False + timeout，四层防御，无命令注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('host')",
            "sink": "subprocess.run(['ping', '-c', '1', host])",
            "explanation": "host 经白名单正则校验 + 列表参数传入，shell=False，无命令注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Go", "has_vuln": False, "difficulty": "典型",
        "code": """```go
// distill_glm_cwe_cvss_019.go
package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// exec.Command 直接传参，不经过 shell
	cmd := exec.Command("ping", "-c", "1", host)
	out, err := cmd.Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, "%s", out)
}
```""",
        "steps": [
            "第 11 行 r.URL.Query().Get(\"host\") 获取用户输入",
            "第 13 行 exec.Command(\"ping\", \"-c\", \"1\", host) 直接传参，每个参数作为独立 argv",
            "Go 的 exec.Command 不经过 /bin/sh，host 仅作为 ping 的最后一个 argv，不会被解释为元字符",
            "已检查：exec.Command 直接传参（非 sh -c），无 shell 解释层，无命令注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "r.URL.Query().Get(\"host\")",
            "sink": "exec.Command(\"ping\", \"-c\", \"1\", host)",
            "explanation": "host 作为 exec.Command 的独立 argv 传入，不经过 shell，无命令注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_020.py
import subprocess
from flask import Flask, request

app = Flask(__name__)

# 白名单：仅允许这些命令名
ALLOWED = {'ls', 'du', 'df'}


@app.route('/disk')
def disk():
    cmd = request.args.get('cmd', 'df')
    if cmd not in ALLOWED:
        return {'error': 'command not allowed'}, 403
    result = subprocess.run(
        [cmd, '-h'],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return {'stdout': result.stdout}
```""",
        "steps": [
            "第 13 行 request.args.get('cmd') 获取用户输入",
            "第 14-15 行白名单 ALLOWED 校验，仅允许 ls/du/df 三个命令名，其他被 403 拒绝",
            "第 17 行 [cmd, '-h'] 列表参数 + shell 默认 False，cmd 已被白名单限定",
            "已检查：白名单枚举校验 + 列表参数 + shell=False + timeout，无命令注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('cmd')",
            "sink": "subprocess.run([cmd, '-h'])",
            "explanation": "cmd 经白名单枚举校验 + 列表参数传入，shell=False，无命令注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "JavaScript", "has_vuln": False, "difficulty": "典型",
        "code": """```javascript
// distill_glm_cwe_cvss_021.js
const express = require('express');
const { execFile } = require('child_process');
const app = express();

app.get('/ping', (req, res) => {
    const host = req.query.host || '';
    // execFile 不经过 shell，参数以数组形式传入
    execFile('ping', ['-c', '1', host], (err, stdout) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ stdout });
    });
});
```""",
        "steps": [
            "第 8 行 req.query.host 获取用户输入",
            "第 11 行 execFile('ping', ['-c', '1', host]) 使用 execFile 而非 exec",
            "execFile 不经过 /bin/sh，参数以数组形式传入，host 仅作为 ping 的 argv，不会被 shell 解释",
            "已检查：execFile + 数组参数（非 exec + 字符串拼接），无 shell 解释层，无命令注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "req.query.host",
            "sink": "execFile('ping', ['-c', '1', host])",
            "explanation": "host 作为 execFile 的数组参数元素传入，不经过 shell，无命令注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_022.py
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route('/file_info')
def file_info():
    path = request.args.get('path', '')
    # subprocess.check_output 列表参数 + shell=False
    out = subprocess.check_output(
        ['stat', path],
        stderr=subprocess.STDOUT,
        timeout=5,
    )
    return {'info': out.decode()}
```""",
        "steps": [
            "第 9 行 request.args.get('path') 获取用户输入",
            "第 12 行 ['stat', path] 列表参数，path 作为 stat 的独立 argv",
            "subprocess.check_output 默认 shell=False，不经过 /bin/sh",
            "已检查：列表参数 + shell=False + timeout，path 仅作为 stat 的参数，无 shell 解释",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('path')",
            "sink": "subprocess.check_output(['stat', path])",
            "explanation": "path 作为列表参数的元素传入，shell=False 不经过 shell，无命令注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Go", "has_vuln": False, "difficulty": "中等",
        "code": """```go
// distill_glm_cwe_cvss_023.go
package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
)

var hostRe = regexp.MustCompile(`^[a-zA-Z0-9.\\-]+$`)

func handler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if !hostRe.MatchString(host) || len(host) > 253 {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}
	cmd := exec.Command("ping", "-c", "1", host)
	out, _ := cmd.Output()
	fmt.Fprintf(w, "%s", out)
}
```""",
        "steps": [
            "第 13 行 r.URL.Query().Get(\"host\") 获取用户输入",
            "第 14-16 行 hostRe.MatchString + len 白名单校验，仅允许字母数字点连字符且长度 ≤253",
            "第 18 行 exec.Command(\"ping\", \"-c\", \"1\", host) 直接传参，不经过 shell",
            "已检查：白名单正则校验 + exec.Command 直接传参（非 sh -c），无命令注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "r.URL.Query().Get(\"host\")",
            "sink": "exec.Command(\"ping\", \"-c\", \"1\", host)",
            "explanation": "host 经白名单正则校验 + exec.Command 直接传参，无命令注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_024.py
import subprocess
import shlex
from flask import Flask, request

app = Flask(__name__)


@app.route('/convert')
def convert():
    infile = request.args.get('input', '')
    outfile = request.args.get('output', '')
    # shlex.join 构造安全的命令字符串（配合 shell=False 时直接用列表更佳）
    args = ['ffmpeg', '-i', infile, '-vn', '-acodec', 'libmp3lame', outfile]
    result = subprocess.run(
        args,
        shell=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return {'stdout': result.stdout}
```""",
        "steps": [
            "第 10-11 行 request.args.get 获取用户输入",
            "第 14 行 args 是列表，infile/outfile 作为独立 argv 元素",
            "第 15-16 行 subprocess.run(args, shell=False) 不经过 shell",
            "已检查：列表参数 + shell=False + timeout，infile/outfile 仅作为 ffmpeg 的参数，无 shell 解释",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('input')",
            "sink": "subprocess.run(args, shell=False)",
            "explanation": "infile/outfile 作为列表参数的元素传入，shell=False 不经过 shell，无命令注入",
            "fix_suggestion": "no fix needed",
        },
    },
]


# =====================================================================
# Batch 2: web  ——  CWE-79 XSS
# 12 条：3 漏洞 + 9 安全，覆盖 Flask / Django / Express / FastAPI
# =====================================================================

WEB_BATCH2 = [
    # ----- 漏洞样本 3 条 -----
    {
        "lang": "Python", "framework": "Flask", "scene": "模板渲染", "has_vuln": True, "difficulty": "典型",
        "code": """```python
# distill_glm_web_013.py
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    template = "<h1>Hello " + name + "!</h1>"
    return render_template_string(template)
```""",
        "steps": [
            "第 8 行 request.args.get('name') 获取用户输入",
            "第 9 行用 + 把 name 拼入模板字符串，未使用变量绑定",
            "第 10 行 render_template_string 将拼接后的字符串作为 Jinja2 模板编译并渲染",
            "攻击者传 name={{7*7}} 可执行任意 Jinja2 表达式，传 name=<script>alert(1)</script> 可注入 XSS",
            "CWE-79 XSS（兼含 SSTI），Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-79 XSS",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
            "cvss_score": 9.0,
            "source": "request.args.get('name')",
            "sink": "render_template_string(\"<h1>Hello \" + name + \"!</h1>\")",
            "explanation": "request.args.get('name') → name → + 拼接进模板字符串 → render_template_string 编译渲染",
            "fix_suggestion": "使用固定模板 + 变量绑定：render_template_string(\"<h1>Hello {{ name }}!</h1>\", name=name)",
        },
    },
    {
        "lang": "Python", "framework": "Django", "scene": "评论展示", "has_vuln": True, "difficulty": "典型",
        "code": """```python
# distill_glm_web_014.py
from django.http import HttpResponse
from django.utils.safestring import mark_safe
from myapp.models import Comment


def show_comment(request, cid):
    comment = Comment.objects.get(id=cid)
    # mark_safe 将用户输入标记为安全，跳过 Django 自动转义
    html = f"<div class='comment'>{mark_safe(comment.content)}</div>"
    return HttpResponse(html)
```""",
        "steps": [
            "第 9 行 comment.content 来自数据库（用户提交的评论内容），是用户可控输入",
            "第 10 行 mark_safe(comment.content) 显式标记为安全字符串，绕过 Django autoescape",
            "第 11 行 HttpResponse 直接输出含未转义用户输入的 HTML",
            "mark_safe 绕过了 Django 的自动转义防御，攻击者提交 <script>alert(document.cookie)</script> 可注入 XSS",
            "CWE-79 XSS，High",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-79 XSS",
            "risk_level": "High",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
            "cvss_score": 5.4,
            "source": "comment.content（用户提交的评论）",
            "sink": "mark_safe(comment.content)",
            "explanation": "comment.content 经 mark_safe 标记为安全 → 绕过 autoescape → HttpResponse 输出未转义 HTML",
            "fix_suggestion": "移除 mark_safe，依赖 Django autoescape 自动转义；或使用 escape(comment.content)",
        },
    },
    {
        "lang": "JavaScript", "framework": "Express", "scene": "搜索结果", "has_vuln": True, "difficulty": "典型",
        "code": """```javascript
// distill_glm_web_015.js
const express = require('express');
const app = express();

app.get('/search', (req, res) => {
    const q = req.query.q || '';
    // 直接拼接 HTML 返回，未转义
    const html = `<h2>搜索结果：${q}</h2><p>共找到 0 条结果</p>`;
    res.send(html);
});
```""",
        "steps": [
            "第 8 行 req.query.q 获取用户输入",
            "第 10 行模板字符串把 q 直接拼入 HTML，未做 HTML 转义",
            "第 11 行 res.send 以默认 Content-Type: text/html 返回，浏览器会解析 HTML",
            "攻击者传 q=<script>alert(1)</script> 可注入并执行任意 JS",
            "CWE-79 XSS，Medium",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-79 XSS",
            "risk_level": "Medium",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "cvss_score": 5.4,
            "source": "req.query.q",
            "sink": "res.send(`<h2>搜索结果：${q}</h2>`)",
            "explanation": "req.query.q → q → 模板字符串拼接进 HTML → res.send 以 text/html 返回未转义内容",
            "fix_suggestion": "使用 escape-html 转义：const escape = require('escape-html'); res.send(`<h2>${escape(q)}</h2>`)",
        },
    },
    # ----- 安全样本 9 条 -----
    {
        "lang": "Python", "framework": "Flask", "scene": "模板渲染", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_016.py
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    # 固定模板 + 变量绑定，Jinja2 autoescape 自动转义
    return render_template_string(
        "<h1>Hello {{ name }}!</h1>",
        name=name,
    )
```""",
        "steps": [
            "第 8 行 request.args.get('name') 获取用户输入",
            "第 11 行模板字符串为固定字面量，name 通过 {{ name }} 变量绑定传入",
            "Jinja2 的 autoescape 默认对 render_template_string 生效，{{ name }} 会被自动 HTML 转义",
            "已检查：固定模板 + 变量绑定 + autoescape，<script> 会被转义为 &lt;script&gt;",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('name')",
            "sink": "render_template_string(\"<h1>Hello {{ name }}!</h1>\", name=name)",
            "explanation": "name 通过 {{ name }} 变量绑定 + Jinja2 autoescape 自动转义，无 XSS",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Django", "scene": "评论展示", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_017.py
from django.shortcuts import render
from myapp.models import Comment


def show_comment(request, cid):
    comment = Comment.objects.get(id=cid)
    # Django 模板 autoescape 默认开启，{{ comment.content }} 自动转义
    return render(request, 'comment.html', {'comment': comment})
```""",
        "steps": [
            "第 7 行 comment.content 来自数据库（用户提交），是用户可控输入",
            "第 9 行 render(request, 'comment.html', {...}) 使用固定模板文件 + context 传递",
            "Django 模板 autoescape 默认开启，{{ comment.content }} 会被自动 HTML 转义",
            "已检查：固定模板 + context 传递 + autoescape，无 mark_safe，<script> 会被转义",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "comment.content",
            "sink": "render(request, 'comment.html', {'comment': comment})",
            "explanation": "comment.content 经 Django 模板 autoescape 自动转义，无 mark_safe，无 XSS",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "JavaScript", "framework": "Express", "scene": "搜索结果", "has_vuln": False, "difficulty": "典型",
        "code": """```javascript
// distill_glm_web_018.js
const express = require('express');
const escape = require('escape-html');
const app = express();

app.get('/search', (req, res) => {
    const q = req.query.q || '';
    // 使用 escape-html 对用户输入做 HTML 转义
    const html = `<h2>搜索结果：${escape(q)}</h2><p>共找到 0 条结果</p>`;
    res.send(html);
});
```""",
        "steps": [
            "第 9 行 req.query.q 获取用户输入",
            "第 11 行 escape(q) 对 HTML 特殊字符（<、>、&、\\\"、'）做实体转义",
            "第 12 行 res.send 返回转义后的 HTML，<script> 已变为 &lt;script&gt;",
            "已检查：escape-html 转义 + 固定 HTML 模板，<script> 无法被浏览器解析为标签",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "req.query.q",
            "sink": "res.send(`<h2>搜索结果：${escape(q)}</h2>`)",
            "explanation": "q 经 escape-html 转义后拼入 HTML，<script> 被转义为实体，无 XSS",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Flask", "scene": "模板渲染", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_web_019.py
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route('/profile')
def profile():
    bio = request.args.get('bio', '')
    # 固定模板 + |safe 过滤器仅用于可信 HTML，bio 不加 |safe
    template = "<div class='bio'>{{ bio }}</div>"
    return render_template_string(template, bio=bio)
```""",
        "steps": [
            "第 8 行 request.args.get('bio') 获取用户输入",
            "第 10 行模板为固定字面量，bio 通过 {{ bio }} 变量绑定传入（未加 |safe 过滤器）",
            "Jinja2 autoescape 对 {{ bio }} 自动转义，<script> 会被转义为 &lt;script&gt;",
            "已检查：固定模板 + 变量绑定（无 |safe）+ autoescape，无 XSS",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('bio')",
            "sink": "render_template_string(template, bio=bio)",
            "explanation": "bio 通过 {{ bio }} 变量绑定（无 |safe），Jinja2 autoescape 自动转义，无 XSS",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Django", "scene": "API 响应", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_020.py
from django.http import JsonResponse
from myapp.models import Product


def product_info(request, pid):
    product = Product.objects.get(id=pid)
    # JsonResponse 以 application/json 返回，浏览器不会解析为 HTML
    return JsonResponse({
        'id': product.id,
        'name': product.name,
        'price': str(product.price),
    })
```""",
        "steps": [
            "第 7 行 product.name 等来自数据库（可能含用户输入），是用户可控输入",
            "第 9-12 行 JsonResponse 以 Content-Type: application/json 返回 JSON 数据",
            "浏览器对 application/json 响应不会解析 HTML 标签，<script> 会作为 JSON 字符串值显示",
            "已检查：JsonResponse + application/json Content-Type，浏览器不解析 HTML，无 XSS",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "product.name",
            "sink": "JsonResponse({...})",
            "explanation": "product.name 作为 JSON 值返回，Content-Type 为 application/json，浏览器不解析 HTML，无 XSS",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "JavaScript", "framework": "Express", "scene": "API 响应", "has_vuln": False, "difficulty": "典型",
        "code": """```javascript
// distill_glm_web_021.js
const express = require('express');
const app = express();

app.get('/api/search', (req, res) => {
    const q = req.query.q || '';
    // res.json 以 application/json 返回，浏览器不解析 HTML
    res.json({ query: q, results: [] });
});
```""",
        "steps": [
            "第 8 行 req.query.q 获取用户输入",
            "第 10 行 res.json 以 Content-Type: application/json 返回 JSON 对象",
            "浏览器对 application/json 响应不解析 HTML 标签，q 作为 JSON 字符串值",
            "已检查：res.json + application/json Content-Type，浏览器不解析 HTML，无 XSS",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "req.query.q",
            "sink": "res.json({ query: q, results: [] })",
            "explanation": "q 作为 JSON 值返回，Content-Type 为 application/json，浏览器不解析 HTML，无 XSS",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Flask", "scene": "模板渲染", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_web_022.py
from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)


@app.route('/highlight')
def highlight():
    keyword = request.args.get('kw', '')
    # 显式 escape + 固定模板变量绑定（双重保障）
    safe_kw = escape(keyword)
    return render_template_string(
        "<span class='kw'>{{ kw }}</span>",
        kw=safe_kw,
    )
```""",
        "steps": [
            "第 9 行 request.args.get('kw') 获取用户输入",
            "第 11 行 escape(keyword) 对 HTML 特殊字符做实体转义",
            "第 13 行 {{ kw }} 变量绑定传入已转义的 safe_kw，Jinja2 autoescape 再做一次（无害）",
            "已检查：显式 escape + 变量绑定 + autoescape 三重保障，<script> 被转义为实体",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('kw')",
            "sink": "render_template_string(\"<span class='kw'>{{ kw }}</span>\", kw=safe_kw)",
            "explanation": "kw 经 escape 转义 + 变量绑定 + autoescape，<script> 被转义为实体，无 XSS",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Django", "scene": "评论展示", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_web_023.py
from django.http import HttpResponse
from django.utils.html import escape
from myapp.models import Comment


def show_comment(request, cid):
    comment = Comment.objects.get(id=cid)
    # 使用 escape() 显式转义，不使用 mark_safe
    html = f"<div class='comment'>{escape(comment.content)}</div>"
    return HttpResponse(html)
```""",
        "steps": [
            "第 8 行 comment.content 来自数据库（用户提交），是用户可控输入",
            "第 10 行 escape(comment.content) 对 HTML 特殊字符做实体转义",
            "第 11 行 HttpResponse 返回含已转义内容的 HTML，<script> 已变为 &lt;script&gt;",
            "已检查：escape() 显式转义 + 无 mark_safe，<script> 被转义为实体，无 XSS",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "comment.content",
            "sink": "escape(comment.content)",
            "explanation": "comment.content 经 escape() 显式转义，<script> 被转义为实体，无 XSS",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "JavaScript", "framework": "Express", "scene": "搜索结果", "has_vuln": False, "difficulty": "中等",
        "code": """```javascript
// distill_glm_web_024.js
const express = require('express');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const app = express();

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

app.get('/search', (req, res) => {
    const q = req.query.q || '';
    // 允许部分 HTML 标签（如 <b>），但过滤 <script> 等危险标签
    const clean = DOMPurify.sanitize(q, { ALLOWED_TAGS: ['b', 'i', 'em', 'strong'] });
    const html = `<h2>搜索结果：${clean}</h2>`;
    res.send(html);
});
```""",
        "steps": [
            "第 12 行 req.query.q 获取用户输入",
            "第 14 行 DOMPurify.sanitize(q, { ALLOWED_TAGS: ['b','i','em','strong'] }) 过滤危险标签，仅保留格式标签",
            "第 15 行 clean 中 <script> 等危险标签已被移除，仅保留 <b>/<i>/<em>/<strong>",
            "已检查：DOMPurify 白名单 sanitize，<script> 被移除，无 XSS",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "req.query.q",
            "sink": "DOMPurify.sanitize(q, { ALLOWED_TAGS: [...] })",
            "explanation": "q 经 DOMPurify 白名单 sanitize 过滤危险标签，仅保留格式标签，无 XSS",
            "fix_suggestion": "no fix needed",
        },
    },
]


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # 追加到 cwe_cvss
    cvss_path = DATA_DIR / "distill_glm_cwe_cvss.jsonl"
    with cvss_path.open("a", encoding="utf-8") as fp:
        for s in CWE_CVSS_BATCH2:
            user = build_user_cwe_cvss("CWE-78 OS命令注入", s["lang"], s["has_vuln"], s["difficulty"])
            assistant = assistant_response(s["code"], s["steps"], s["json"])
            write_sample(fp, GLM_SYSTEM, user, assistant)
    print(f"[OK] {cvss_path}: appended {len(CWE_CVSS_BATCH2)} samples (CWE-78)")

    # 追加到 web
    web_path = DATA_DIR / "distill_glm_web.jsonl"
    with web_path.open("a", encoding="utf-8") as fp:
        for s in WEB_BATCH2:
            user = build_user_web(s["lang"], s["framework"], s["scene"], s["has_vuln"], s["difficulty"])
            assistant = assistant_response(s["code"], s["steps"], s["json"])
            write_sample(fp, GLM_SYSTEM, user, assistant)
    print(f"[OK] {web_path}: appended {len(WEB_BATCH2)} samples (CWE-79)")


if __name__ == "__main__":
    main()
