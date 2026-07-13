"""
SSTI（CWE-94）CWE 归因推理补充样本生成。

背景：
  微调后模型把 SSTI 误标为 CWE-89（SQL 注入），根因是训练数据 CoT 缺少
  "CWE 归因推理"步骤——模型没学到如何区分 CWE-94 与 CWE-89。本脚本生成
  14 条高质量 SSTI 样本（10 漏洞 + 4 安全），CoT 第 5 步显式推理"为什么
  是 CWE-94 而不是 CWE-89/78"，覆盖 Flask/Jinja2/Mako/Django/EJS/Pug/
  Thymeleaf/Velocity/Freemarker 等主流模板引擎。

  漏洞样本的 CoT 必须包含 6 步，第 5 步"CWE 归因"显式排除 CWE-89 和 CWE-78，
  确定 CWE-94；安全样本的 CoT 第 5 步显式说明为何不构成 CWE-94。

输出：
  data/supplement_cwe_attribution_ssti.jsonl（14 条 ChatML 样本）

用法：
  cd /home/zane/文档/code/毕业设计
  PYTHONPATH=. /home/zane/miniconda3/envs/graproj/bin/python \
      experiments/exp_06_finetune/scripts/supplement_cwe_attribution_ssti.py
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import build_user_prompt

OUTPUT_FILE = PROJECT_ROOT / "experiments/exp_06_finetune/data/supplement_cwe_attribution_ssti.jsonl"

# ---------------------------------------------------------------------------
# SYSTEM_PROMPT_LITE（固定，每条样本通用）
# ---------------------------------------------------------------------------
SYSTEM_PROMPT_LITE = (
    "你是一名资深的代码安全审计专家。请对给出的代码片段进行安全分析，"
    "判断其中是否存在安全漏洞。分析范围包括但不限于："
    "SQL 注入、跨站脚本（XSS）、命令注入、路径穿越、"
    "硬编码敏感信息（密钥/密码/Token）、不安全的反序列化、"
    "日志注入（CWE-117）、弱密码学（MD5/SHA1 哈希密码、CWE-327）、"
    "弱随机数（random 模块生成 token、CWE-330）、CSRF、"
    "SSTI、XXE、SSRF、未授权访问、安全配置错误、文件上传、"
    "会话固定、LDAP 注入、NoSQL 注入、XPath 注入、表达式注入（SpEL/OGNL）。\n\n"
    "要求：\n"
    "1. 仔细阅读代码语义，结合上下文判断用户可控输入是否被安全处理。\n"
    "2. 不要夸大风险，也不要遗漏明显的漏洞。\n"
    "3. 判定必须基于代码实际内容，不能凭空臆造 API 参数或行为。\n"
    "4. 用户输入到达 sink 不等于漏洞，必须看 sink 前的防御措施是否有效。\n"
    "5. 硬编码的字面量凭证（key/secret/password/token）本身就是漏洞，"
    "不要降级为“敏感但非漏洞”。\n"
    "6. 结论一致性校验：JSON 的 has_vulnerability 必须与上述分析过程的推理结论一致。"
    "若分析过程中识别出风险（如“弱随机”“不安全”“存在漏洞”），JSON 不得标 false；"
    "若分析过程未识别出风险，JSON 不得标 true。\n\n"
    "在回答的最后，必须严格输出一个 JSON 对象作为最终结论，"
    "JSON 块用 ```json 包裹，字段如下（统一 schema，全项目一致）：\n"
    "- has_vulnerability: boolean\n"
    "- vulnerability_type: string（如 \"CWE-89 SQL注入\" 或 \"none\"）\n"
    "- risk_level: string（\"Critical\"/\"High\"/\"Medium\"/\"Low\"/\"none\"）\n"
    "- source: string（污染源，如 \"request.args.get('id')\"）\n"
    "- sink: string（危险 sink）\n"
    "- taint_path: string（数据流路径）\n"
    "- explanation: string（简要说明）\n\n"
    "请先给出分析过程，然后在最后给出 JSON 结论。"
)


# ===========================================================================
# 样本定义：14 条（10 漏洞 + 4 安全）
# 每条含 code / language / filename / cot / verdict
# CoT 第 5 步为 CWE 归因，显式区分 CWE-94 与 CWE-89/78
# ===========================================================================
SAMPLES = [
    # =====================================================================
    # 漏洞样本 1: Flask render_template_string
    # =====================================================================
    {
        "filename": "ssti_01_flask_render_string.py",
        "language": "python",
        "code": '''from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    template = "<h1>Hello " + name + "!</h1>"
    return render_template_string(template)''',
        "cot": """分析过程：
1. 污染源：request.args.get('name') 获取用户输入。
2. 危险 sink：render_template_string(template) 将字符串作为 Jinja2 模板编译并渲染。
3. 数据流：name → 字符串拼接进 template（"<h1>Hello " + name + "!</h1>"）→ render_template_string 编译执行。
4. 防御检查：模板字符串由用户输入拼接而成，未使用固定模板文件，未启用沙箱环境，autoescape 未配置。
5. CWE 归因：
   - 漏洞类型：模板注入（SSTI）
   - 排除 CWE-89（SQL 注入）：不涉及数据库查询，用户输入未进入 SQL 语句
   - 排除 CWE-78（命令注入）：不涉及系统命令执行，用户输入未进入 subprocess
   - 确定 CWE-94（代码注入）：用户输入直接拼接到模板字符串，通过模板引擎渲染可执行任意代码（如 {{7*7}} 或 {{config}}）
6. 结论：用户输入拼入模板字符串，经 render_template_string 编译渲染，可注入 {{ }} 标签执行任意 Python 表达式，存在 SSTI 漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-94 代码注入（SSTI）",
            "risk_level": "Critical",
            "source": "request.args.get('name')",
            "sink": "render_template_string(template)",
            "taint_path": "name → 字符串拼接进 template → render_template_string 编译渲染",
            "explanation": "用户输入直接拼接到模板字符串，攻击者可注入 {{7*7}} 或 {{config}} 等标签通过 Jinja2 引擎执行任意代码",
        },
    },
    # =====================================================================
    # 漏洞样本 2: Jinja2 Environment.from_string
    # =====================================================================
    {
        "filename": "ssti_02_jinja2_from_string.py",
        "language": "python",
        "code": '''from flask import Flask, request
from jinja2 import Environment

app = Flask(__name__)
env = Environment()


@app.route("/preview")
def preview():
    user_template = request.args.get("tpl", "")
    template = env.from_string("Welcome: " + user_template)
    return template.render()''',
        "cot": """分析过程：
1. 污染源：request.args.get('tpl') 获取用户输入。
2. 危险 sink：env.from_string("Welcome: " + user_template) 将含用户输入的字符串编译为 Jinja2 模板。
3. 数据流：user_template → 字符串拼接到模板源码 → env.from_string 编译 → template.render() 执行。
4. 防御检查：模板字符串由用户输入拼接而成，未使用固定模板，env 为裸 Environment（未启用 autoescape，未使用 SandboxedEnvironment）。
5. CWE 归因：
   - 漏洞类型：模板注入（SSTI）
   - 排除 CWE-89（SQL 注入）：不涉及数据库查询，用户输入未进入 SQL 语句
   - 排除 CWE-78（命令注入）：不涉及系统命令执行，用户输入未进入 subprocess
   - 确定 CWE-94（代码注入）：用户输入拼接到模板源码经 from_string 编译，攻击者可注入 {{ }} 或 {% %} 标签执行任意代码
6. 结论：用户输入拼入模板源码经 Jinja2 from_string 编译渲染，可注入模板标签执行任意代码，存在 SSTI 漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-94 代码注入（SSTI）",
            "risk_level": "Critical",
            "source": "request.args.get('tpl')",
            "sink": "env.from_string(\"Welcome: \" + user_template)",
            "taint_path": "user_template → 字符串拼接到模板源码 → from_string 编译 → render 执行",
            "explanation": "用户输入拼接到模板源码经 Jinja2 from_string 编译，攻击者可注入 {{config}} 或 {{''.__class__.__mro__[1].__subclasses__()}} 执行任意代码",
        },
    },
    # =====================================================================
    # 漏洞样本 3: Jinja2 Template()
    # =====================================================================
    {
        "filename": "ssti_03_jinja2_template.py",
        "language": "python",
        "code": '''from flask import Flask, request
from jinja2 import Template

app = Flask(__name__)


@app.route("/render")
def render():
    content = request.args.get("content", "")
    tpl = Template("Content: " + content)
    return tpl.render()''',
        "cot": """分析过程：
1. 污染源：request.args.get('content') 获取用户输入。
2. 危险 sink：Template("Content: " + content) 将含用户输入的字符串直接编译为 Jinja2 模板对象。
3. 数据流：content → 字符串拼接到模板源码 → Template() 编译 → tpl.render() 执行。
4. 防御检查：模板源码由用户输入拼接，Template() 构造器直接编译字符串为模板，无 autoescape，无沙箱。
5. CWE 归因：
   - 漏洞类型：模板注入（SSTI）
   - 排除 CWE-89（SQL 注入）：不涉及数据库查询，用户输入未进入 SQL 语句
   - 排除 CWE-78（命令注入）：不涉及系统命令执行，用户输入未进入 subprocess
   - 确定 CWE-94（代码注入）：用户输入拼入模板源码经 Template() 编译，可注入 {{7*7}} 执行任意 Python 表达式
6. 结论：用户输入拼入模板源码经 Template() 编译渲染，可注入模板标签执行任意代码，存在 SSTI 漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-94 代码注入（SSTI）",
            "risk_level": "Critical",
            "source": "request.args.get('content')",
            "sink": "Template(\"Content: \" + content)",
            "taint_path": "content → 字符串拼接到模板源码 → Template() 编译 → render 执行",
            "explanation": "用户输入拼接到模板源码经 Jinja2 Template() 直接编译，攻击者可注入 {{ }} 标签执行任意 Python 代码",
        },
    },
    # =====================================================================
    # 漏洞样本 4: Mako Template()
    # =====================================================================
    {
        "filename": "ssti_04_mako_template.py",
        "language": "python",
        "code": '''from flask import Flask, request
from mako.template import Template

app = Flask(__name__)


@app.route("/page")
def page():
    body = request.args.get("body", "")
    tpl = Template("Page: " + body)
    return tpl.render()''',
        "cot": """分析过程：
1. 污染源：request.args.get('body') 获取用户输入。
2. 危险 sink：Template("Page: " + body) 将含用户输入的字符串编译为 Mako 模板对象。
3. 数据流：body → 字符串拼接到模板源码 → Template() 编译 → tpl.render() 执行。
4. 防御检查：模板源码由用户输入拼接，Mako 的 Template() 直接编译字符串为模板，未启用严格模式（strict_undefined），无输入过滤。
5. CWE 归因：
   - 漏洞类型：模板注入（SSTI）
   - 排除 CWE-89（SQL 注入）：不涉及数据库查询，用户输入未进入 SQL 语句
   - 排除 CWE-78（命令注入）：不涉及系统命令执行，用户输入未进入 subprocess
   - 确定 CWE-94（代码注入）：用户输入拼入 Mako 模板源码经 Template() 编译，可注入 ${} 或 <% %> 标签执行任意 Python 代码
6. 结论：用户输入拼入 Mako 模板源码经编译渲染，可注入 ${} 或 <% %> 标签执行任意代码，存在 SSTI 漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-94 代码注入（SSTI）",
            "risk_level": "Critical",
            "source": "request.args.get('body')",
            "sink": "Template(\"Page: \" + body)",
            "taint_path": "body → 字符串拼接到模板源码 → Template() 编译 → render 执行",
            "explanation": "用户输入拼接到 Mako 模板源码经编译，攻击者可注入 ${__import__('os').system('id')} 或 <% %> 标签执行任意代码",
        },
    },
    # =====================================================================
    # 漏洞样本 5: Django Template().render()
    # =====================================================================
    {
        "filename": "ssti_05_django_template.py",
        "language": "python",
        "code": '''from django.template import Template, Context
from django.http import HttpResponse


def greet(request):
    name = request.GET.get("name", "")
    template = Template("<h1>Hello " + name + "</h1>")
    context = Context({"name": name})
    return HttpResponse(template.render(context))''',
        "cot": """分析过程：
1. 污染源：request.GET.get('name') 获取用户输入。
2. 危险 sink：Template("<h1>Hello " + name + "</h1>") 将含用户输入的字符串编译为 Django 模板。
3. 数据流：name → 字符串拼接到模板源码 → Template() 编译 → template.render(context) 执行。
4. 防御检查：模板源码由用户输入拼接，Django 的 Template() 直接编译字符串为模板，未使用模板文件加载机制（get_template），无 autoescape 模板标签（{% autoescape on %}）。
5. CWE 归因：
   - 漏洞类型：模板注入（SSTI）
   - 排除 CWE-89（SQL 注入）：不涉及数据库查询，用户输入未进入 SQL 语句
   - 排除 CWE-78（命令注入）：不涉及系统命令执行，用户输入未进入 subprocess
   - 确定 CWE-94（代码注入）：用户输入拼入 Django 模板源码经 Template() 编译，可注入 {{ }} 或 {% %} 标签执行模板表达式
6. 结论：用户输入拼入 Django 模板源码经编译渲染，可注入 {{ }} 标签执行模板表达式，存在 SSTI 漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-94 代码注入（SSTI）",
            "risk_level": "Critical",
            "source": "request.GET.get('name')",
            "sink": "Template(\"<h1>Hello \" + name + \"</h1>\")",
            "taint_path": "name → 字符串拼接到模板源码 → Template() 编译 → render 执行",
            "explanation": "用户输入拼接到 Django 模板源码经 Template() 编译，攻击者可注入 {{settings.SECRET_KEY}} 等标签读取敏感配置",
        },
    },
    # =====================================================================
    # 漏洞样本 6: Node.js EJS render
    # =====================================================================
    {
        "filename": "ssti_06_ejs_render.js",
        "language": "javascript",
        "code": '''const express = require('express');
const ejs = require('ejs');
const app = express();

app.get('/page', (req, res) => {
    const userContent = req.query.content || '';
    const html = ejs.render('<div>' + userContent + '</div>');
    res.send(html);
});

app.listen(3000);''',
        "cot": """分析过程：
1. 污染源：req.query.content 获取用户输入。
2. 危险 sink：ejs.render('<div>' + userContent + '</div>') 将含用户输入的字符串编译为 EJS 模板并渲染。
3. 数据流：userContent → 字符串拼接到模板源码 → ejs.render 编译执行。
4. 防御检查：模板源码由用户输入拼接，未使用固定模板文件，未启用 EJS 的 escape 选项（默认关闭）。
5. CWE 归因：
   - 漏洞类型：模板注入（SSTI）
   - 排除 CWE-89（SQL 注入）：不涉及数据库查询，用户输入未进入 SQL 语句
   - 排除 CWE-78（命令注入）：不涉及系统命令执行，用户输入未进入 child_process
   - 确定 CWE-94（代码注入）：用户输入拼入 EJS 模板源码经 render 编译，可注入 <%= %> 或 <%- %> 标签执行任意 JavaScript 代码
6. 结论：用户输入拼入 EJS 模板源码经编译渲染，可注入 <%= %> 标签执行任意 JS 代码，存在 SSTI 漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-94 代码注入（SSTI）",
            "risk_level": "Critical",
            "source": "req.query.content",
            "sink": "ejs.render('<div>' + userContent + '</div>')",
            "taint_path": "userContent → 字符串拼接到模板源码 → ejs.render 编译执行",
            "explanation": "用户输入拼接到 EJS 模板源码经编译，攻击者可注入 <%= require('child_process').execSync('id') %> 执行任意代码",
        },
    },
    # =====================================================================
    # 漏洞样本 7: Node.js Pug compile
    # =====================================================================
    {
        "filename": "ssti_07_pug_compile.js",
        "language": "javascript",
        "code": '''const express = require('express');
const pug = require('pug');
const app = express();

app.get('/view', (req, res) => {
    const userInput = req.query.input || '';
    const compiledFunction = pug.compile('p ' + userInput);
    res.send(compiledFunction());
});

app.listen(3000);''',
        "cot": """分析过程：
1. 污染源：req.query.input 获取用户输入。
2. 危险 sink：pug.compile('p ' + userInput) 将含用户输入的字符串编译为 Pug 模板函数。
3. 数据流：userInput → 字符串拼接到模板源码 → pug.compile 编译 → compiledFunction() 执行。
4. 防御检查：模板源码由用户输入拼接，Pug 的 compile 直接编译字符串为模板函数，未使用沙箱选项，无输入过滤。
5. CWE 归因：
   - 漏洞类型：模板注入（SSTI）
   - 排除 CWE-89（SQL 注入）：不涉及数据库查询，用户输入未进入 SQL 语句
   - 排除 CWE-78（命令注入）：不涉及系统命令执行，用户输入未进入 child_process
   - 确定 CWE-94（代码注入）：用户输入拼入 Pug 模板源码经 compile 编译，可注入 #{ } 或 - 等标签执行任意 JavaScript 代码
6. 结论：用户输入拼入 Pug 模板源码经编译渲染，可注入 #{ } 标签执行任意 JS 代码，存在 SSTI 漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-94 代码注入（SSTI）",
            "risk_level": "Critical",
            "source": "req.query.input",
            "sink": "pug.compile('p ' + userInput)",
            "taint_path": "userInput → 字符串拼接到模板源码 → pug.compile 编译 → 执行",
            "explanation": "用户输入拼接到 Pug 模板源码经编译，攻击者可注入 #{global.process.mainModule.require('child_process').execSync('id')} 执行任意代码",
        },
    },
    # =====================================================================
    # 漏洞样本 8: Spring Thymeleaf
    # =====================================================================
    {
        "filename": "ssti_08_thymeleaf.java",
        "language": "java",
        "code": '''import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.context.Context;

@Controller
public class PageController {
    private final SpringTemplateEngine templateEngine;

    public PageController(SpringTemplateEngine templateEngine) {
        this.templateEngine = templateEngine;
    }

    @GetMapping("/page")
    @ResponseBody
    public String page(@RequestParam String content) {
        String template = "<div>" + content + "</div>";
        Context ctx = new Context();
        return templateEngine.process(template, ctx);
    }
}''',
        "cot": """分析过程：
1. 污染源：@RequestParam String content 获取用户输入。
2. 危险 sink：templateEngine.process(template, ctx) 将含用户输入的字符串作为 Thymeleaf 模板处理。
3. 数据流：content → 字符串拼接到 template（\"<div>\" + content + \"</div>\"）→ templateEngine.process 编译执行。
4. 防御检查：模板字符串由用户输入拼接，未使用模板文件解析（TemplateResolver），直接用 process 处理字符串模板，无输入过滤。
5. CWE 归因：
   - 漏洞类型：模板注入（SSTI）
   - 排除 CWE-89（SQL 注入）：不涉及数据库查询，用户输入未进入 SQL 语句
   - 排除 CWE-78（命令注入）：不涉及系统命令执行，用户输入未进入 Runtime.exec
   - 确定 CWE-94（代码注入）：用户输入拼入 Thymeleaf 模板字符串经 process 处理，可注入 [[${...}]] 或 th:text 等表达式执行任意代码
6. 结论：用户输入拼入 Thymeleaf 模板字符串经引擎处理，可注入 [[${T(java.lang.Runtime).getRuntime().exec('id')}]] 执行任意代码，存在 SSTI 漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-94 代码注入（SSTI）",
            "risk_level": "Critical",
            "source": "@RequestParam String content",
            "sink": "templateEngine.process(template, ctx)",
            "taint_path": "content → 字符串拼接到 template → templateEngine.process 处理执行",
            "explanation": "用户输入拼接到 Thymeleaf 模板字符串经引擎处理，攻击者可注入 [[${T(java.lang.Runtime).getRuntime().exec('id')}]] 执行任意代码",
        },
    },
    # =====================================================================
    # 漏洞样本 9: Apache Velocity evaluate
    # =====================================================================
    {
        "filename": "ssti_09_velocity.java",
        "language": "java",
        "code": '''import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.VelocityContext;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import java.io.StringWriter;

@Controller
public class PageController {
    private final VelocityEngine velocityEngine;

    public PageController(VelocityEngine velocityEngine) {
        this.velocityEngine = velocityEngine;
    }

    @GetMapping("/page")
    @ResponseBody
    public String page(@RequestParam String name) throws Exception {
        VelocityContext context = new VelocityContext();
        context.put("name", name);
        StringWriter writer = new StringWriter();
        velocityEngine.evaluate(context, writer, "tag", "Hello " + name);
        return writer.toString();
    }
}''',
        "cot": """分析过程：
1. 污染源：@RequestParam String name 获取用户输入。
2. 危险 sink：velocityEngine.evaluate(context, writer, "tag", "Hello " + name) 将含用户输入的字符串作为 Velocity 模板求值。
3. 数据流：name → 字符串拼接到模板源码（"Hello " + name）→ velocityEngine.evaluate 编译执行。
4. 防御检查：模板源码由用户输入拼接，Velocity 的 evaluate 直接对字符串模板求值，未启用 SecureUberspector（沙箱），无输入过滤。
5. CWE 归因：
   - 漏洞类型：模板注入（SSTI）
   - 排除 CWE-89（SQL 注入）：不涉及数据库查询，用户输入未进入 SQL 语句
   - 排除 CWE-78（命令注入）：不涉及系统命令执行，用户输入未进入 Runtime.exec
   - 确定 CWE-94（代码注入）：用户输入拼入 Velocity 模板源码经 evaluate 求值，可注入 #set 或 ${} 表达式执行任意 Java 代码
6. 结论：用户输入拼入 Velocity 模板源码经引擎求值，可注入 ${java.lang.Runtime.getRuntime().exec('id')} 执行任意代码，存在 SSTI 漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-94 代码注入（SSTI）",
            "risk_level": "Critical",
            "source": "@RequestParam String name",
            "sink": "velocityEngine.evaluate(context, writer, \"tag\", \"Hello \" + name)",
            "taint_path": "name → 字符串拼接到模板源码 → velocityEngine.evaluate 求值执行",
            "explanation": "用户输入拼接到 Velocity 模板源码经引擎求值，攻击者可注入 ${java.lang.Runtime.getRuntime().exec('id')} 执行任意代码",
        },
    },
    # =====================================================================
    # 漏洞样本 10: Freemarker Template
    # =====================================================================
    {
        "filename": "ssti_10_freemarker.java",
        "language": "java",
        "code": '''import freemarker.template.Configuration;
import freemarker.template.Template;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

@Controller
public class PageController {
    private final Configuration cfg;

    public PageController(Configuration cfg) {
        this.cfg = cfg;
    }

    @GetMapping("/page")
    @ResponseBody
    public String page(@RequestParam String name) throws Exception {
        Template template = new Template("page", "Hello " + name, cfg);
        Map<String, Object> data = new HashMap<>();
        data.put("name", name);
        StringWriter writer = new StringWriter();
        template.process(data, writer);
        return writer.toString();
    }
}''',
        "cot": """分析过程：
1. 污染源：@RequestParam String name 获取用户输入。
2. 危险 sink：new Template("page", "Hello " + name, cfg) 将含用户输入的字符串编译为 Freemarker 模板。
3. 数据流：name → 字符串拼接到模板源码（"Hello " + name）→ Template 构造器编译 → template.process 执行。
4. 防御检查：模板源码由用户输入拼接，Template 构造器直接编译字符串为模板，未启用 Freemarker 的禁用危险指令配置（new_builtin_class_resolver），无输入过滤。
5. CWE 归因：
   - 漏洞类型：模板注入（SSTI）
   - 排除 CWE-89（SQL 注入）：不涉及数据库查询，用户输入未进入 SQL 语句
   - 排除 CWE-78（命令注入）：不涉及系统命令执行，用户输入未进入 Runtime.exec
   - 确定 CWE-94（代码注入）：用户输入拼入 Freemarker 模板源码经 Template 编译，可注入 ${} 或 <#...> 指令执行任意代码
6. 结论：用户输入拼入 Freemarker 模板源码经编译渲染，可注入 <#assign value="freemarker.template.utility.Execute"?new()>${value("id")} 执行任意代码，存在 SSTI 漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-94 代码注入（SSTI）",
            "risk_level": "Critical",
            "source": "@RequestParam String name",
            "sink": "new Template(\"page\", \"Hello \" + name, cfg)",
            "taint_path": "name → 字符串拼接到模板源码 → Template 构造器编译 → process 执行",
            "explanation": "用户输入拼接到 Freemarker 模板源码经编译，攻击者可注入 ${\"freemarker.template.utility.Execute\"?new()(\"id\")} 执行任意代码",
        },
    },
    # =====================================================================
    # 安全样本 11: Flask render_template 固定模板文件
    # =====================================================================
    {
        "filename": "safe_ssti_01_flask_render_template.py",
        "language": "python",
        "code": '''from flask import Flask, request, render_template

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template("greet.html", name=name)''',
        "cot": """分析过程：
1. 污染源：request.args.get('name') 获取用户输入，但仅作为模板变量传入。
2. 危险 sink：render_template 加载固定模板文件 greet.html 并渲染，模板字符串本身不由用户控制。
3. 数据流：name → render_template 的 context 参数（name=name）→ 模板变量 {{ name }} → 自动转义 → 安全输出。
4. 防御检查：render_template 从 templates 目录加载固定模板文件，Flask 默认启用 autoescape（Jinja2 对 HTML 模板自动转义），用户输入仅作为 context 变量传入而非模板源码。
5. CWE 归因：
   - 不构成 CWE-94（代码注入）：用户输入不控制模板字符串本身，仅作为模板变量传入，模板引擎对变量自动转义
   - SSTI 的关键是"谁控制模板内容"，此处模板内容由开发者固定的 greet.html 文件控制，用户无法注入模板语法
6. 结论：安全，模板字符串为固定文件，用户输入仅作为模板变量且经过自动转义，未发现漏洞。""",
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "none",
            "source": "none",
            "sink": "none",
            "taint_path": "none",
            "explanation": "模板字符串为固定文件 greet.html，用户输入仅作为模板变量且经过 Flask 自动转义",
        },
    },
    # =====================================================================
    # 安全样本 12: Jinja2 from_string 固定模板 + autoescape
    # =====================================================================
    {
        "filename": "safe_ssti_02_jinja2_fixed.py",
        "language": "python",
        "code": '''from flask import Flask, request
from jinja2 import Environment, select_autoescape

app = Flask(__name__)
env = Environment(autoescape=select_autoescape(["html", "xml"]))


@app.route("/preview")
def preview():
    user_input = request.args.get("msg", "")
    template = env.from_string("Message: {{ msg }}")
    return template.render(msg=user_input)''',
        "cot": """分析过程：
1. 污染源：request.args.get('msg') 获取用户输入，仅作为模板变量传入。
2. 危险 sink：env.from_string 编译模板字符串，但模板源码为固定常量 "Message: {{ msg }}"。
3. 数据流：user_input → render(msg=user_input) 作为 context → 模板变量 {{ msg }} → autoescape 自动转义 → 安全输出。
4. 防御检查：模板源码为固定字符串常量 "Message: {{ msg }}"（不含用户输入），autoescape=select_autoescape(["html","xml"]) 开启自动转义，用户输入仅作为 context 变量传入。
5. CWE 归因：
   - 不构成 CWE-94（代码注入）：用户输入不控制模板字符串本身，仅作为模板变量传入，模板引擎对变量自动转义
   - SSTI 的关键是"谁控制模板内容"，此处模板内容为开发者固定的字符串常量，用户输入只填充 {{ msg }} 变量，无法注入模板语法
6. 结论：安全，模板字符串为固定常量，用户输入仅作为模板变量且经过自动转义，未发现漏洞。""",
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "none",
            "source": "none",
            "sink": "none",
            "taint_path": "none",
            "explanation": "模板字符串为固定常量，用户输入仅作为模板变量且经过 autoescape 自动转义",
        },
    },
    # =====================================================================
    # 安全样本 13: Django render 固定模板文件
    # =====================================================================
    {
        "filename": "safe_ssti_03_django_render.py",
        "language": "python",
        "code": '''from django.shortcuts import render


def greet(request):
    name = request.GET.get("name", "")
    return render(request, "greet.html", {"name": name})''',
        "cot": """分析过程：
1. 污染源：request.GET.get('name') 获取用户输入，仅作为模板变量传入。
2. 危险 sink：render 加载固定模板文件 greet.html 并渲染，模板字符串本身不由用户控制。
3. 数据流：name → render 的 context（{"name": name}）→ 模板变量 {{ name }} → Django 自动转义 → 安全输出。
4. 防御检查：render 从模板目录加载固定模板文件 greet.html，Django 模板引擎默认开启自动转义（autoescape），用户输入仅作为 context 字典的值传入而非模板源码。
5. CWE 归因：
   - 不构成 CWE-94（代码注入）：用户输入不控制模板字符串本身，仅作为模板变量传入，Django 模板引擎对变量自动转义
   - SSTI 的关键是"谁控制模板内容"，此处模板内容由开发者固定的 greet.html 文件控制，用户无法注入模板语法
6. 结论：安全，模板字符串为固定文件，用户输入仅作为模板变量且经过 Django 自动转义，未发现漏洞。""",
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "none",
            "source": "none",
            "sink": "none",
            "taint_path": "none",
            "explanation": "模板字符串为固定文件 greet.html，用户输入仅作为模板变量且经过 Django 自动转义",
        },
    },
    # =====================================================================
    # 安全样本 14: Jinja2 SandboxedEnvironment + 固定模板
    # =====================================================================
    {
        "filename": "safe_ssti_04_jinja2_sandbox.py",
        "language": "python",
        "code": '''from flask import Flask, request
from jinja2.sandbox import SandboxedEnvironment

app = Flask(__name__)
sandbox = SandboxedEnvironment(autoescape=True)


@app.route("/preview")
def preview():
    user_input = request.args.get("msg", "")
    template = sandbox.from_string("Message: {{ msg }}")
    return template.render(msg=user_input)''',
        "cot": """分析过程：
1. 污染源：request.args.get('msg') 获取用户输入，仅作为模板变量传入。
2. 危险 sink：sandbox.from_string 编译模板字符串，但模板源码为固定常量 "Message: {{ msg }}"。
3. 数据流：user_input → render(msg=user_input) 作为 context → 模板变量 {{ msg }} → SandboxedEnvironment 自动转义 → 安全输出。
4. 防御检查：模板源码为固定字符串常量 "Message: {{ msg }}"（不含用户输入），使用 SandboxedEnvironment 限制危险属性访问（禁止 __import__、os.popen 等），autoescape=True 开启自动转义，用户输入仅作为 context 变量传入。
5. CWE 归因：
   - 不构成 CWE-94（代码注入）：用户输入不控制模板字符串本身，仅作为模板变量传入，SandboxedEnvironment 对变量自动转义并限制危险属性访问
   - SSTI 的关键是"谁控制模板内容"，此处模板内容为开发者固定的字符串常量，用户输入只填充 {{ msg }} 变量，即使变量含 {{ }} 也会被当作普通文本输出
6. 结论：安全，模板字符串为固定常量，用户输入仅作为模板变量且经过 SandboxedEnvironment 自动转义，未发现漏洞。""",
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "none",
            "source": "none",
            "sink": "none",
            "taint_path": "none",
            "explanation": "模板字符串为固定常量，用户输入仅作为模板变量且经过 SandboxedEnvironment 自动转义",
        },
    },
]


# ===========================================================================
# 构建与写入逻辑
# ===========================================================================
def build_sample(sample: dict) -> dict:
    """构建一条 ChatML 样本。"""
    user_prompt = build_user_prompt(
        code=sample["code"], language=sample["language"], filename=sample["filename"]
    )
    json_str = json.dumps(sample["verdict"], ensure_ascii=False, indent=2)
    assistant_content = f"{sample['cot']}\n\n```json\n{json_str}\n```"
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_LITE},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": assistant_content},
        ]
    }


def verify_output(filepath: Path) -> None:
    """验证输出文件：合法 JSON、3 条消息、json 块可解析、CWE 归因正确。"""
    print("\n=== 验证输出文件 ===")
    with open(filepath, encoding="utf-8") as f:
        lines = [l for l in f if l.strip()]

    errors = []
    cwe_counter = Counter()

    for i, line in enumerate(lines, 1):
        # 1. 合法 JSON
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            errors.append(f"行 {i}: JSON 解析失败 - {e}")
            continue

        # 2. messages 有 3 条
        messages = obj.get("messages", [])
        if len(messages) != 3:
            errors.append(f"行 {i}: messages 数量为 {len(messages)}，期望 3")
            continue

        roles = [m["role"] for m in messages]
        if roles != ["system", "user", "assistant"]:
            errors.append(f"行 {i}: roles 为 {roles}，期望 [system, user, assistant]")
            continue

        # 3. assistant content 包含可解析的 ```json 块
        assistant_content = messages[2]["content"]
        json_blocks = re.findall(r"```json\s*(\{.*?\})\s*```", assistant_content, re.DOTALL)
        if not json_blocks:
            errors.append(f"行 {i}: assistant content 中未找到 ```json 块")
            continue

        verdict = None
        for block in json_blocks:
            try:
                verdict = json.loads(block)
                break
            except json.JSONDecodeError:
                continue
        if verdict is None:
            errors.append(f"行 {i}: JSON 块无法解析")
            continue

        has_vuln = verdict.get("has_vulnerability")
        vuln_type = verdict.get("vulnerability_type", "")

        # 4. 漏洞样本的 vulnerability_type 包含 "CWE-94"
        if has_vuln is True:
            if "CWE-94" not in vuln_type:
                errors.append(f"行 {i}: 漏洞样本 vulnerability_type 为 '{vuln_type}'，缺少 'CWE-94'")
            cwe_counter[vuln_type] += 1
        # 5. 安全样本的 has_vulnerability 为 false
        elif has_vuln is False:
            if vuln_type != "none":
                errors.append(f"行 {i}: 安全样本 vulnerability_type 为 '{vuln_type}'，期望 'none'")
            cwe_counter["none（安全）"] += 1
        else:
            errors.append(f"行 {i}: has_vulnerability 为 {has_vuln}，非布尔值")

    if errors:
        print(f"发现 {len(errors)} 个错误：")
        for e in errors:
            print(f"  [ERROR] {e}")
    else:
        print("所有验证通过：")
        print(f"  - {len(lines)} 条样本均为合法 JSON")
        print(f"  - 每条 messages 数组有 3 条（system/user/assistant）")
        print(f"  - assistant content 的 ```json 块均可解析")
        print(f"  - 漏洞样本 vulnerability_type 均包含 'CWE-94'")
        print(f"  - 安全样本 has_vulnerability 均为 false")

    print(f"\nCWE 分布统计：")
    for k, v in cwe_counter.most_common():
        print(f"  {v}  {k}")


def main():
    print(f"生成 {len(SAMPLES)} 条 SSTI（CWE-94）CWE 归因推理补充样本")
    vuln_count = sum(1 for s in SAMPLES if s["verdict"]["has_vulnerability"])
    safe_count = len(SAMPLES) - vuln_count
    print(f"  漏洞样本: {vuln_count} 条")
    print(f"  安全样本: {safe_count} 条")
    print(f"输出: {OUTPUT_FILE}")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for s in SAMPLES:
            chatml = build_sample(s)
            f.write(json.dumps(chatml, ensure_ascii=False) + "\n")

    # 确认写入数量
    with open(OUTPUT_FILE, encoding="utf-8") as f:
        lines = [l for l in f if l.strip()]
    print(f"\n已写入 {len(lines)} 条样本")

    # CWE 分布统计
    cwe_counter = Counter()
    for s in SAMPLES:
        v = s["verdict"]
        if v["has_vulnerability"]:
            cwe_counter[v["vulnerability_type"]] += 1
        else:
            cwe_counter["none（安全）"] += 1
    print(f"\nCWE 分布统计：")
    for k, v in cwe_counter.most_common():
        print(f"  {v}  {k}")

    # 验证
    verify_output(OUTPUT_FILE)


if __name__ == "__main__":
    main()
