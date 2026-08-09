#!/usr/bin/env python3
"""SSTI 隐藏场景 + 授权类 CWE 归属混淆 训练样本生成。

生成两类特殊训练样本（共 75 条）：
  第一部分（40 条）：SSTI 隐藏场景变体
    - 长文件 SSTI（15 条）：漏洞行在文件后部（第 30 行之后），前面有大量业务代码
    - from_string / render_template_string 变体（15 条）：不同框架的等价危险 API
    - SSTI vs XSS 边界对比（10 条）：5 对结构相似但漏洞类型不同的样本

  第二部分（35 条）：授权类 CWE 归属混淆对比样本
    - CWE-639 Authorization Bypass / IDOR（10 条）
    - CWE-862 Missing Authorization（10 条）
    - CWE-312 Cleartext Storage（5 条）
    - IDOR vs Missing Auth 对比配对（5 对 = 10 条）

约 20% 样本包含"防御迷惑"代码（看似有防御但实际无效）。
语言覆盖：Python, JavaScript, Java, PHP, Go。

输出：
  experiments/exp_06_finetune/data/supplement_ssti_auth.jsonl

用法：
  python experiments/exp_06_finetune/scripts/generate_ssti_auth_samples.py
"""

import json
import re
from pathlib import Path
from collections import Counter

# ===========================================================================
# 路径与常量
# ===========================================================================
SCRIPT_DIR = Path(__file__).resolve().parent          # scripts/
EXP_DIR = SCRIPT_DIR.parent                            # exp_06_finetune/
OUTPUT_FILE = EXP_DIR / "data" / "supplement_ssti_auth.jsonl"

SYSTEM_PROMPT = (
    "你是一名安全研究员，分析给定代码的安全漏洞。\n"
    "\n"
    "在回答的最后，必须严格输出一个 JSON 对象作为最终结论，JSON 块用 ```json 包裹，"
    "字段如下（统一 schema，全项目一致）：\n"
    "   - has_vulnerability: bool, true 表示存在漏洞，false 表示未发现漏洞\n"
    "   - vulnerability_type: str, 单个字符串（禁止拆成多个逗号分隔的值），"
    "格式如 'CWE-编号 漏洞名'，例如 'CWE-89 SQL Injection'、"
    "'CWE-79 Cross-site Scripting (XSS)'；无漏洞填 'none'\n"
    "   - risk_level: str, Critical/High/Medium/Low；无漏洞填 'None'\n"
    "   - source: str, 污染来源（用户可控输入点）。必须锚定行号，"
    "如 'line 12: request.args.get(\"id\")'；无漏洞填 'N/A'\n"
    "   - sink: str, 危险函数或触发点。必须锚定行号，"
    "如 'line 18: cursor.execute(query)'；无漏洞填 'N/A'\n"
    "   - explanation: str, 漏洞或安全现状说明（数据流/成因，用 -> 箭头描述）\n"
    "   - fix_suggestion: str, 行号锚定的简短修复建议（单行、不含换行），"
    "格式如 'line 3: 应改为 ...' 或 '第 3 行：... 建议改为 ...'；"
    "指出应修改的具体行与改法即可，禁止输出完整代码/补丁/围栏代码块，"
    "行号必须是代码中真实存在的；无漏洞填 'no fix needed'\n"
    "\n"
    "请先给出分析过程，然后在最后给出 JSON 结论。"
)


# ===========================================================================
# 辅助函数
# ===========================================================================
def _ln(code, marker):
    """返回 code 中第一个包含 marker 的行的 1-based 行号。"""
    for i, line in enumerate(code.split("\n"), 1):
        if marker in line:
            return i
    raise ValueError(f"代码中未找到标记: {marker!r}")


def make_verdict(code, *, has_vuln, vuln_type, risk,
                 source_marker=None, source_desc=None,
                 sink_marker=None, sink_desc=None,
                 explanation, fix_marker=None, fix_desc=None):
    """构造 verdict dict，行号从 code 中自动解析。

    has_vuln=False 时返回统一的"无漏洞"结论。
    """
    if not has_vuln:
        return {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": explanation,
            "fix_suggestion": "no fix needed",
        }
    src_line = _ln(code, source_marker)
    sink_line = _ln(code, sink_marker)
    fix_line = _ln(code, fix_marker) if fix_marker else sink_line
    fix_suggestion = f"line {fix_line}: 应改为 {fix_desc}"
    fix_suggestion = fix_suggestion.replace("\n", " ")
    if len(fix_suggestion) > 500:
        fix_suggestion = fix_suggestion[:497] + "..."
    return {
        "has_vulnerability": True,
        "vulnerability_type": vuln_type,
        "risk_level": risk,
        "source": f"line {src_line}: {source_desc}",
        "sink": f"line {sink_line}: {sink_desc}",
        "explanation": explanation,
        "fix_suggestion": fix_suggestion,
    }


def make_sample(lang, code, analysis, verdict):
    """构造 ChatML JSON 记录。"""
    user_content = (
        f"代码片段（语言: {lang}）：\n"
        f"```{lang}\n{code}\n```\n"
        f"请先给出分析过程，然后在最后给出 JSON 结论。"
    )
    json_str = json.dumps(verdict, ensure_ascii=False)
    assistant_content = f"{analysis}\n\n```json\n{json_str}\n```"
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ]
    }


def _spec(lang, code, analysis, **verdict_kw):
    """快捷构造样本规格 dict（code + verdict 由 make_verdict 解析行号）。"""
    return {
        "lang": lang,
        "code": code,
        "analysis": analysis,
        "verdict": make_verdict(code, **verdict_kw),
    }


def validate_spec(spec):
    """校验单条样本规格，返回错误列表（空列表表示通过）。"""
    errors = []
    code = spec["code"]
    verdict = spec["verdict"]
    lines = code.split("\n")
    num_lines = len(lines)

    # 必填字段
    for field in ("has_vulnerability", "vulnerability_type", "risk_level",
                  "source", "sink", "explanation", "fix_suggestion"):
        if field not in verdict:
            errors.append(f"缺少字段: {field}")

    if verdict.get("has_vulnerability") is True:
        vt = verdict.get("vulnerability_type", "")
        if not vt.startswith("CWE-"):
            errors.append(f"vulnerability_type '{vt}' 不以 'CWE-' 开头")
        if verdict.get("risk_level") not in ("Critical", "High", "Medium", "Low"):
            errors.append(f"risk_level '{verdict.get('risk_level')}' 不合法")

        for field in ("source", "sink", "fix_suggestion"):
            val = verdict.get(field, "")
            m = re.search(r"line (\d+)", val)
            if not m:
                errors.append(f"{field} 缺少行号引用: {val[:60]}")
            else:
                ln = int(m.group(1))
                if ln < 1 or ln > num_lines:
                    errors.append(f"{field} 行号 {ln} 超出范围 (1-{num_lines})")

        fix = verdict.get("fix_suggestion", "")
        if "\n" in fix:
            errors.append("fix_suggestion 含换行符")
        if len(fix) > 500:
            errors.append(f"fix_suggestion 过长 ({len(fix)} 字符)")
    return errors


# ===========================================================================
# 第一部分 - 1: 长文件 SSTI（15 条）
# ===========================================================================
def gen_ssti_long():
    """15 条长文件 SSTI 样本，漏洞行在第 30 行之后。"""
    S = []

    # --- 1. Python / Jinja2 — 通知服务 ---
    code = r'''# notification_service.py
import os
import json
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-key-1234")


class User:
    def __init__(self, user_id, username, email, role="user"):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.role = role


class Notification:
    def __init__(self, notif_id, user_id, title, body, created_at=None):
        self.notif_id = notif_id
        self.user_id = user_id
        self.title = title
        self.body = body
        self.created_at = created_at or datetime.utcnow()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def validate_email(email):
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None


def format_timestamp(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


import re
users_db = {}
notifications_db = {}
counter = 0


@app.route("/api/users/register", methods=["POST"])
def register_user():
    global counter
    data = request.get_json()
    username = data.get("username", "")
    email = data.get("email", "")
    password = data.get("password", "")
    if not username or not email or not password:
        return jsonify({"error": "Missing fields"}), 400
    if not validate_email(email):
        return jsonify({"error": "Invalid email"}), 400
    counter += 1
    user = User(counter, username, email)
    users_db[counter] = user
    return jsonify({"user_id": counter, "username": username}), 201


@app.route("/api/notifications/preview", methods=["GET"])
def preview_notification():
    template = request.args.get("template", "Hello {{ name }}!")
    name = request.args.get("name", "Guest")
    rendered = render_template_string(template, name=name)
    return jsonify({"rendered": rendered})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 62: request.args.get('template') 获取用户可控的模板字符串。\n"
        "2. line 64: render_template_string(template, name=name) 将其作为 Jinja2 模板渲染。\n"
        "3. 攻击者传入 {{7*7}} 或 {{config}} 可在服务端执行表达式，导致 SSTI / 信息泄露。\n"
        "4. 结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker='request.args.get("template"',
        source_desc="request.args.get('template') 用户可控模板内容",
        sink_marker="render_template_string(template",
        sink_desc="render_template_string(template, name=name) Jinja2 服务端模板渲染",
        explanation="line 62 用户输入 template -> line 64 render_template_string 服务端执行 -> 攻击者注入 {{7*7}} 或 {{config}} -> SSTI 导致 RCE / 信息泄露",
        fix_marker="render_template_string(template",
        fix_desc="使用 render_template('notification.html', name=name) 加载固定模板文件，用户输入仅作为模板变量而非模板内容"))

    # --- 2. Python / Jinja2 — 博客平台 Template() ---
    code = r'''# blog_platform.py
"""博客平台核心服务模块。"""
import os
import logging
from datetime import datetime
from jinja2 import Template, Environment, FileSystemLoader
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

env = Environment(loader=FileSystemLoader("templates"))

BLOG_POSTS = {}
CATEGORIES = {"tech": [], "life": [], "news": []}
TAGS = set()


class BlogPost:
    def __init__(self, post_id, title, content, author, category="tech"):
        self.post_id = post_id
        self.title = title
        self.content = content
        self.author = author
        self.category = category
        self.created_at = datetime.utcnow()
        self.tags = []

    def add_tag(self, tag):
        self.tags.append(tag)
        TAGS.add(tag)

    def to_dict(self):
        return {
            "id": self.post_id,
            "title": self.title,
            "content": self.content,
            "author": self.author,
            "category": self.category,
            "tags": self.tags,
        }


def generate_slug(title):
    return title.lower().replace(" ", "-").replace(".", "")


def paginate(items, page, per_page=10):
    start = (page - 1) * per_page
    end = start + per_page
    return items[start:end]


post_counter = 0


@app.route("/api/posts", methods=["POST"])
def create_post():
    global post_counter
    data = request.get_json()
    title = data.get("title", "")
    content = data.get("content", "")
    author = data.get("author", "anonymous")
    category = data.get("category", "tech")
    post_counter += 1
    post = BlogPost(post_counter, title, content, author, category)
    BLOG_POSTS[post_counter] = post
    CATEGORIES.setdefault(category, []).append(post.post_id)
    return jsonify(post.to_dict()), 201


@app.route("/api/posts/preview", methods=["GET"])
def preview_post():
    template_str = request.args.get("tpl", "{{ content }}")
    content = request.args.get("content", "")
    tmpl = Template(template_str)
    return jsonify({"html": tmpl.render(content=content)})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 61: request.args.get('tpl') 获取用户可控模板字符串。\n"
        "2. line 63: Template(template_str) 编译用户输入为 Jinja2 模板并执行 .render()。\n"
        "3. 攻击者传入 {{ ''.__class__.__mro__[1].__subclasses__() }} 可执行任意代码。\n"
        "4. 结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker='request.args.get("tpl"',
        source_desc="request.args.get('tpl') 用户可控模板字符串",
        sink_marker="Template(template_str)",
        sink_desc="Template(template_str).render(content=content) Jinja2 编译并执行用户模板",
        explanation="line 61 用户输入 tpl -> line 63 Template() 编译 -> .render() 执行 -> 攻击者注入沙箱逃逸 payload -> SSTI RCE",
        fix_marker="Template(template_str)",
        fix_desc="使用 env.get_template('preview.html') 加载预定义模板文件，禁止将用户输入作为模板源码"))

    # --- 3. PHP / Twig — 邮件模板服务 ---
    code = r'''<?php
// EmailTemplateService.php
require_once __DIR__ . '/vendor/autoload.php';

use Twig\Environment;
use Twig\Loader\FilesystemLoader;
use Twig\Loader\ChainLoader;
use Twig\Loader\ArrayLoader;

class EmailTemplateService
{
    private $twig;
    private $db;
    private $logger;

    public function __construct($pdo)
    {
        $this->db = $pdo;
        $this->logger = new Logger();
        $loader = new FilesystemLoader(__DIR__ . '/templates');
        $this->twig = new Environment($loader, [
            'cache' => __DIR__ . '/cache',
            'autoescape' => true,
        ]);
    }

    public function sendEmail($to, $subject, $templateName, $params)
    {
        $template = $this->twig->load($templateName);
        $body = $template->render($params);
        $headers = "From: noreply@example.com\r\n";
        $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
        mail($to, $subject, $body, $headers);
        $this->logger->info("Email sent to: $to");
        return true;
    }

    public function getTemplateList()
    {
        $stmt = $this->db->query("SELECT id, name FROM email_templates");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function previewTemplate($templateName, $params)
    {
        $this->logger->info("Previewing template: $templateName");
        $template = $this->twig->load($templateName);
        return $template->render($params);
    }

    public function renderCustomTemplate($templateSource, $params)
    {
        $loader = new ArrayLoader([
            'custom' => $templateSource,
        ]);
        $twig = new Environment($loader);
        $template = $twig->load('custom');
        return $template->render($params);
    }
}

class Logger
{
    public function info($msg)
    {
        error_log("[INFO] " . $msg);
    }
}

$service = new EmailTemplateService($pdo);
if (isset($_GET['action']) && $_GET['action'] === 'preview') {
    $source = $_GET['template_source'] ?? '';
    $params = ['user' => $_GET['user'] ?? 'guest'];
    echo $service->renderCustomTemplate($source, $params);
}
'''
    S.append(_spec("php", code,
        "分析过程：\n"
        "1. line 57: $_GET['template_source'] 获取用户可控的 Twig 模板源码。\n"
        "2. line 49-50: ArrayLoader 将用户输入加载为模板，new Environment 编译并执行。\n"
        "3. 攻击者传入 {{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}} 可执行系统命令。\n"
        "4. 结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker="$_GET['template_source']",
        source_desc="$_GET['template_source'] 用户可控 Twig 模板源码",
        sink_marker="$twig->load('custom')",
        sink_desc="$twig->load('custom')->render($params) Twig 服务端模板执行",
        explanation="line 57 $_GET['template_source'] -> line 49 ArrayLoader 加载 -> line 50 Environment 编译 -> line 51 render 执行 -> Twig SSTI RCE",
        fix_marker="$twig->load('custom')",
        fix_desc="禁止从用户输入加载模板源码，仅允许从预定义模板文件列表中选择 templateName"))

    # --- 4. Java / Freemarker — 报表生成器 ---
    code = r'''package com.example.report;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;
import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ReportGenerator {

    private final Configuration cfg;
    private final Connection conn;

    public ReportGenerator(String dbUrl) throws Exception {
        cfg = new Configuration(Configuration.VERSION_2_3_31);
        cfg.setDirectoryForTemplateLoading(new File("templates"));
        cfg.setDefaultEncoding("UTF-8");
        cfg.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
        conn = DriverManager.getConnection(dbUrl);
    }

    public List<Map<String, Object>> querySalesData(String region) throws Exception {
        String sql = "SELECT product, amount, sale_date FROM sales WHERE region = ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, region);
        ResultSet rs = ps.executeQuery();
        List<Map<String, Object>> results = new ArrayList<>();
        while (rs.next()) {
            Map<String, Object> row = new HashMap<>();
            row.put("product", rs.getString("product"));
            row.put("amount", rs.getDouble("amount"));
            row.put("sale_date", rs.getString("sale_date"));
            results.add(row);
        }
        return results;
    }

    public String generateReport(String templateName, Map<String, Object> data) throws Exception {
        Template template = cfg.getTemplate(templateName);
        StringWriter writer = new StringWriter();
        template.process(data, writer);
        return writer.toString();
    }

    public String renderInlineTemplate(String templateContent, Map<String, Object> data)
            throws IOException, TemplateException {
        Template template = new Template("inline", templateContent, cfg);
        StringWriter writer = new StringWriter();
        template.process(data, writer);
        return writer.toString();
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 62: templateContent 参数来自 HTTP 请求，用户可控。\n"
        "2. line 64: new Template('inline', templateContent, cfg) 将用户输入编译为 Freemarker 模板。\n"
        "3. 攻击者传入 ${\"freemarker.template.utility.Execute\"?new()(\"id\")} 可执行系统命令。\n"
        "4. 结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker="String templateContent",
        source_desc="renderInlineTemplate(String templateContent, ...) 用户可控模板内容",
        sink_marker='new Template("inline"',
        sink_desc="new Template('inline', templateContent, cfg) Freemarker 编译用户模板",
        explanation="line 62 templateContent 用户输入 -> line 64 new Template() 编译 -> line 66 template.process() 执行 -> Freemarker SSTI RCE",
        fix_marker='new Template("inline"',
        fix_desc="禁止从用户输入构造 Template 对象，仅使用 cfg.getTemplate() 加载预定义模板文件"))

    # --- 5. Java / Thymeleaf — 管理后台 ---
    code = r'''package com.example.admin.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.jdbc.core.JdbcTemplate;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

@Controller
@RequestMapping("/admin")
public class DashboardController {

    private final JdbcTemplate jdbc;

    public DashboardController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/overview")
    public String overview(Model model) {
        Integer userCount = jdbc.queryForObject(
            "SELECT COUNT(*) FROM users", Integer.class);
        Integer orderCount = jdbc.queryForObject(
            "SELECT COUNT(*) FROM orders", Integer.class);
        model.addAttribute("userCount", userCount);
        model.addAttribute("orderCount", orderCount);
        return "admin/overview";
    }

    @GetMapping("/users")
    public String listUsers(Model model) {
        List<Map<String, Object>> users = jdbc.queryForList(
            "SELECT id, username, email, role FROM users ORDER BY id");
        model.addAttribute("users", users);
        return "admin/users";
    }

    @GetMapping("/greeting")
    public String greeting(@RequestParam String name, Model model) {
        model.addAttribute("name", name);
        return "admin/greeting";
    }

    @GetMapping("/custom")
    public String customPage(@RequestParam String fragment) {
        return "admin/custom :: " + fragment;
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 51: @RequestParam String fragment 来自用户请求参数。\n"
        "2. line 53: 返回视图名 'admin/custom :: ' + fragment，Thymeleaf 解析 fragment 表达式。\n"
        "3. 攻击者传入 __${T(java.lang.Runtime).getRuntime().exec('id')}__::.x 可触发 SpEL 注入。\n"
        "4. 结论：CWE-1336 SSTI（Thymeleaf 模板注入），风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker="@RequestParam String fragment",
        source_desc="@RequestParam String fragment 用户可控视图片段表达式",
        sink_marker='return "admin/custom :: "',
        sink_desc='return "admin/custom :: " + fragment Thymeleaf 视图名拼接导致表达式注入',
        explanation="line 51 fragment 用户输入 -> line 53 视图名拼接 -> Thymeleaf 解析 __${}__ 表达式 -> SpEL 执行 -> SSTI RCE",
        fix_marker='return "admin/custom :: "',
        fix_desc="对 fragment 做白名单校验（仅允许字母数字下划线），或使用 @ResponseBody 直接返回数据而非模板视图"))

    # --- 6. Node.js / EJS — 页面构建器 ---
    code = r'''// pageBuilder.js
const express = require('express');
const ejs = require('ejs');
const path = require('path');
const fs = require('fs');

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const PAGES_DIR = path.join(__dirname, 'pages');
const COMPONENTS = ['header', 'footer', 'sidebar', 'navbar', 'hero'];

class PageConfig {
    constructor(name, title, components = []) {
        this.name = name;
        this.title = title;
        this.components = components;
        this.createdAt = new Date().toISOString();
    }

    validate() {
        if (!this.name || this.name.length > 100) return false;
        return this.components.every(c => COMPONENTS.includes(c));
    }

    toJSON() {
        return { name: this.name, title: this.title, components: this.components };
    }
}

function loadPageConfig(pageName) {
    const configPath = path.join(PAGES_DIR, pageName + '.json');
    if (!fs.existsSync(configPath)) return null;
    const raw = fs.readFileSync(configPath, 'utf-8');
    return JSON.parse(raw);
}

function sanitizeInput(input) {
    return input.replace(/[<>]/g, '');
}

const pageConfigs = {};

app.get('/api/pages/:name', (req, res) => {
    const config = loadPageConfig(req.params.name);
    if (!config) return res.status(404).json({ error: 'Page not found' });
    res.json(config);
});

app.get('/api/pages/render', (req, res) => {
    const template = req.query.template || '<h1><%= title %></h1>';
    const data = { title: req.query.title || 'Default' };
    const html = ejs.render(template, data);
    res.send(html);
});

app.listen(3000, () => console.log('PageBuilder running on port 3000'));
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 51: req.query.template 获取用户可控的 EJS 模板字符串。\n"
        "2. line 53: ejs.render(template, data) 在服务端编译并执行用户模板。\n"
        "3. 攻击者传入 <%= require('child_process').execSync('id') %> 可执行系统命令。\n"
        "4. 结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker="req.query.template",
        source_desc="req.query.template 用户可控 EJS 模板字符串",
        sink_marker="ejs.render(template",
        sink_desc="ejs.render(template, data) 服务端 EJS 模板编译执行",
        explanation="line 51 req.query.template 用户输入 -> line 53 ejs.render() 编译执行 -> 注入 <%= require('child_process').execSync('id') %> -> SSTI RCE",
        fix_marker="ejs.render(template",
        fix_desc="使用 res.render('page', data) 加载预定义 EJS 模板文件，禁止将用户输入作为模板源码"))

    # --- 7. Node.js / Pug — 落地页生成器 ---
    code = r'''// landingPageGenerator.js
const express = require('express');
const pug = require('pug');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));

const CAMPAIGNS = new Map();

class Campaign {
    constructor(id, name, slug, status = 'draft') {
        this.id = id;
        this.name = name;
        this.slug = slug;
        this.status = status;
        this.createdAt = new Date();
        this.metrics = { views: 0, clicks: 0, conversions: 0 };
    }

    recordView() { this.metrics.views++; }
    recordClick() { this.metrics.clicks++; }
    recordConversion() { this.metrics.conversions++; }

    getCTR() {
        return this.metrics.views > 0
            ? (this.metrics.clicks / this.metrics.views * 100).toFixed(2)
            : '0.00';
    }

    toJSON() {
        return { id: this.id, name: this.name, slug: this.slug,
                 status: this.status, metrics: this.metrics, ctr: this.getCTR() };
    }
}

function generateSlug(name) {
    return crypto.createHash('md5').update(name).digest('hex').slice(0, 8);
}

function validateCampaign(c) {
    return c.name && c.name.length <= 200 && ['draft', 'active', 'archived'].includes(c.status);
}

app.post('/api/campaigns', (req, res) => {
    const campaign = new Campaign(Date.now(), req.body.name, generateSlug(req.body.name));
    CAMPAIGNS.set(campaign.id, campaign);
    res.json(campaign.toJSON());
});

app.get('/api/campaigns/preview', (req, res) => {
    const template = req.query.tpl || 'h1= title';
    const data = { title: req.query.title || 'Welcome' };
    const html = pug.render(template, data);
    res.send(html);
});

app.listen(3000);
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 56: req.query.tpl 获取用户可控的 Pug 模板字符串。\n"
        "2. line 58: pug.render(template, data) 在服务端编译并执行用户模板。\n"
        "3. 攻击者传入 -var x=global.process.mainModule.require('child_process').execSync('id') 可执行系统命令。\n"
        "4. 结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker="req.query.tpl",
        source_desc="req.query.tpl 用户可控 Pug 模板字符串",
        sink_marker="pug.render(template",
        sink_desc="pug.render(template, data) 服务端 Pug 模板编译执行",
        explanation="line 56 req.query.tpl 用户输入 -> line 58 pug.render() 编译执行 -> 注入 unbuffered code 块调用 require('child_process') -> SSTI RCE",
        fix_marker="pug.render(template",
        fix_desc="使用 res.render('campaign', data) 加载预定义 Pug 模板文件，禁止将用户输入作为模板源码"))

    # --- 8. Python / Jinja2 — 表单渲染器（防御迷惑：escape() 不阻止 SSTI） ---
    code = r'''# form_renderer.py
"""动态表单渲染服务。"""
import os
import json
from markupsafe import escape
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

FORM_TEMPLATES = {
    "contact": "templates/contact_form.html",
    "signup": "templates/signup_form.html",
    "survey": "templates/survey_form.html",
}

FORM_FIELDS = {
    "text": lambda name, label: f'<input type="text" name="{name}" />',
    "email": lambda name, label: f'<input type="email" name="{name}" />',
    "textarea": lambda name, label: f'<textarea name="{name}"></textarea>',
    "select": lambda name, label, options: f'<select name="{name}"></select>',
}


class FormConfig:
    def __init__(self, form_id, fields=None, action="/submit", method="POST"):
        self.form_id = form_id
        self.fields = fields or []
        self.action = action
        self.method = method

    def add_field(self, field_type, name, label):
        self.fields.append({"type": field_type, "name": name, "label": label})

    def to_html(self):
        parts = [f'<form action="{self.action}" method="{self.method}">']
        for f in self.fields:
            renderer = FORM_FIELDS.get(f["type"])
            if renderer:
                parts.append(f'<label>{f["label"]}</label>')
                parts.append(renderer(f["name"], f["label"]))
        parts.append("</form>")
        return "\n".join(parts)


def validate_form_id(form_id):
    return form_id.replace("-", "").replace("_", "").isalnum()


@app.route("/api/forms/<form_id>/render", methods=["GET"])
def render_form(form_id):
    if not validate_form_id(form_id):
        return jsonify({"error": "Invalid form ID"}), 400
    user_template = request.args.get("layout", "{{ form_html }}")
    safe_user = escape(user_template)
    form = FormConfig(form_id)
    form_html = form.to_html()
    result = render_template_string(safe_user, form_html=form_html)
    return jsonify({"html": result})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 57: request.args.get('layout') 获取用户可控模板字符串。\n"
        "2. line 58: escape(user_template) 仅做 HTML 实体转义，不阻止 Jinja2 表达式 {{ }}。\n"
        "3. line 61: render_template_string(safe_user, ...) 仍将转义后的字符串作为模板编译执行。\n"
        "4. 防御迷惑：escape() 转义了 < > & 但保留了 {{ }}，攻击者传 {{config}} 仍可执行。结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker='request.args.get("layout"',
        source_desc="request.args.get('layout') 用户可控模板（escape 不阻止 SSTI）",
        sink_marker="render_template_string(safe_user",
        sink_desc="render_template_string(safe_user, form_html=form_html) Jinja2 渲染转义后仍含 {{}} 的模板",
        explanation="line 57 用户输入 layout -> line 58 escape() 仅转义 HTML 实体不阻止 {{}} -> line 61 render_template_string 编译执行 -> 攻击者注入 {{config}} -> SSTI（防御迷惑：escape 无效）",
        fix_marker="render_template_string(safe_user",
        fix_desc="禁止将用户输入作为模板源码，应使用 render_template('form_layout.html', form_html=form_html) 加载固定模板"))

    # --- 9. PHP / Twig — 消息渲染器（防御迷惑：strip_tags 不阻止 SSTI） ---
    code = r'''<?php
// MessageRenderer.php
require_once __DIR__ . '/vendor/autoload.php';

use Twig\Environment;
use Twig\Loader\FilesystemLoader;

class MessageRenderer
{
    private $twig;
    private $db;
    private $cache = [];

    public function __construct($pdo)
    {
        $this->db = $pdo;
        $loader = new FilesystemLoader(__DIR__ . '/templates');
        $this->twig = new Environment($loader, ['autoescape' => true]);
    }

    public function getMessage($messageId)
    {
        if (isset($this->cache[$messageId])) {
            return $this->cache[$messageId];
        }
        $stmt = $this->db->prepare("SELECT * FROM messages WHERE id = ?");
        $stmt->execute([$messageId]);
        $msg = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($msg) {
            $this->cache[$messageId] = $msg;
        }
        return $msg;
    }

    public function listMessages($userId)
    {
        $stmt = $this->db->prepare(
            "SELECT id, subject, from_user, created_at FROM messages WHERE to_user = ?"
        );
        $stmt->execute([$userId]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function sanitize($input)
    {
        $cleaned = strip_tags($input);
        $cleaned = htmlspecialchars($cleaned, ENT_QUOTES, 'UTF-8');
        return $cleaned;
    }

    public function renderCustomMessage($templateSource, $variables)
    {
        $safe = $this->sanitize($templateSource);
        $template = $this->twig->createTemplate($safe);
        return $template->render($variables);
    }
}

$renderer = new MessageRenderer($pdo);
if (isset($_GET['action']) && $_GET['action'] === 'custom') {
    $tpl = $_GET['msg_template'] ?? '';
    $vars = ['user' => $_GET['user'] ?? 'guest'];
    echo $renderer->renderCustomMessage($tpl, $vars);
}
'''
    S.append(_spec("php", code,
        "分析过程：\n"
        "1. line 58: $_GET['msg_template'] 获取用户可控模板源码。\n"
        "2. line 51: sanitize() 用 strip_tags + htmlspecialchars 清理，但不移除 {{ }} Twig 语法。\n"
        "3. line 53: createTemplate($safe) 将清理后的字符串编译为 Twig 模板并执行。\n"
        "4. 防御迷惑：strip_tags/htmlspecialchars 不阻止 Twig 表达式。结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker="$_GET['msg_template']",
        source_desc="$_GET['msg_template'] 用户可控 Twig 模板源码",
        sink_marker="$this->twig->createTemplate",
        sink_desc="$this->twig->createTemplate($safe) Twig 从字符串编译模板",
        explanation="line 58 $_GET['msg_template'] -> line 51 sanitize(strip_tags+htmlspecialchars) 不移除 {{}} -> line 53 createTemplate 编译 -> line 54 render 执行 -> Twig SSTI（防御迷惑：HTML 清理无效）",
        fix_marker="$this->twig->createTemplate",
        fix_desc="禁止从用户输入创建模板，应使用 $this->twig->load('message.html') 加载预定义模板文件"))

    # --- 10. Java / Freemarker — 模板处理器（防御迷惑：HTML escape 不阻止 SSTI） ---
    code = r'''package com.example.template;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;
import org.apache.commons.text.StringEscapeUtils;
import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

public class TemplateProcessor {

    private final Configuration cfg;

    public TemplateProcessor() throws IOException {
        cfg = new Configuration(Configuration.VERSION_2_3_31);
        cfg.setDirectoryForTemplateLoading(new File("templates"));
        cfg.setDefaultEncoding("UTF-8");
        cfg.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
        cfg.setNumberFormat("0.######");
    }

    public String processTemplate(String templateName, Map<String, Object> data)
            throws IOException, TemplateException {
        Template template = cfg.getTemplate(templateName);
        StringWriter writer = new StringWriter();
        template.process(data, writer);
        return writer.toString();
    }

    public String processUserTemplate(String userTemplate, Map<String, Object> data)
            throws IOException, TemplateException {
        String escaped = StringEscapeUtils.escapeHtml4(userTemplate);
        Template template = new Template("userTpl", escaped, cfg);
        StringWriter writer = new StringWriter();
        template.process(data, writer);
        return writer.toString();
    }

    public Map<String, Object> buildDefaultContext() {
        Map<String, Object> ctx = new HashMap<>();
        ctx.put("appName", "TemplateProcessor");
        ctx.put("version", "1.0.0");
        return ctx;
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 39: userTemplate 参数来自 HTTP 请求，用户可控。\n"
        "2. line 41: StringEscapeUtils.escapeHtml4 转义 HTML 实体，但不移除 Freemarker ${} 语法。\n"
        "3. line 42: new Template('userTpl', escaped, cfg) 将转义后字符串编译为 Freemarker 模板。\n"
        "4. 防御迷惑：HTML escape 不阻止 ${} 模板表达式。结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker="String userTemplate",
        source_desc="processUserTemplate(String userTemplate, ...) 用户可控模板内容",
        sink_marker='new Template("userTpl"',
        sink_desc='new Template("userTpl", escaped, cfg) Freemarker 从转义后字符串编译模板',
        explanation="line 39 userTemplate 用户输入 -> line 41 escapeHtml4 仅转义 HTML 不移除 ${} -> line 42 new Template 编译 -> line 44 process 执行 -> Freemarker SSTI（防御迷惑：HTML escape 无效）",
        fix_marker='new Template("userTpl"',
        fix_desc="禁止从用户输入构造 Template 对象，应仅使用 cfg.getTemplate() 加载预定义模板文件"))

    # --- 11. Node.js / EJS — 内容管理系统 ---
    code = r'''// cms.js
const express = require('express');
const ejs = require('ejs');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

const app = express();
const upload = multer({ dest: 'uploads/' });
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const ARTICLES = new Map();
const MEDIA = new Map();

class Article {
    constructor(id, title, body, author, status = 'draft') {
        this.id = id;
        this.title = title;
        this.body = body;
        this.author = author;
        this.status = status;
        this.tags = [];
        this.createdAt = new Date();
    }
    publish() { this.status = 'published'; }
    addTag(tag) { this.tags.push(tag); }
    toJSON() {
        return { id: this.id, title: this.title, body: this.body,
                 author: this.author, status: this.status, tags: this.tags };
    }
}

function slugify(text) {
    return text.toString().toLowerCase()
        .replace(/\s+/g, '-')
        .replace(/[^\w\-]+/g, '')
        .replace(/\-\-+/g, '-')
        .replace(/^-+/, '');
}

function paginate(items, page = 1, perPage = 10) {
    const start = (page - 1) * perPage;
    return { items: items.slice(start, start + perPage),
             total: items.length, page, perPage };
}

app.get('/api/articles', (req, res) => {
    const articles = Array.from(ARTICLES.values());
    const result = paginate(articles, parseInt(req.query.page) || 1);
    res.json(result);
});

app.post('/api/articles', upload.none(), (req, res) => {
    const article = new Article(Date.now(), req.body.title, req.body.body, req.body.author);
    ARTICLES.set(article.id, article);
    res.json(article.toJSON());
});

app.get('/api/articles/:id/preview', (req, res) => {
    const article = ARTICLES.get(parseInt(req.params.id));
    if (!article) return res.status(404).json({ error: 'Not found' });
    const tpl = req.query.layout || '<h1><%= title %></h1><div><%= body %></div>';
    const html = ejs.render(tpl, { title: article.title, body: article.body });
    res.send(html);
});

app.listen(3000);
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 58: req.query.layout 获取用户可控 EJS 模板字符串。\n"
        "2. line 59: ejs.render(tpl, ...) 在服务端编译并执行用户模板。\n"
        "3. 攻击者传入 <%= global.process.mainModule.require('child_process').execSync('id') %> 可 RCE。\n"
        "4. 结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker="req.query.layout",
        source_desc="req.query.layout 用户可控 EJS 模板字符串",
        sink_marker="ejs.render(tpl",
        sink_desc="ejs.render(tpl, { title, body }) 服务端 EJS 模板编译执行",
        explanation="line 58 req.query.layout 用户输入 -> line 59 ejs.render() 编译执行 -> 注入 require('child_process').execSync() -> SSTI RCE",
        fix_marker="ejs.render(tpl",
        fix_desc="使用 res.render('article_preview', { title, body }) 加载预定义 EJS 模板文件"))

    # --- 12. Python / Jinja2 — 简报服务，漏洞在辅助函数 ---
    code = r'''# newsletter_service.py
import os
import json
import logging
from jinja2 import Environment, FileSystemLoader, Template
from flask import Flask, request, jsonify

app = Flask(__name__)
logger = logging.getLogger(__name__)
env = Environment(loader=FileSystemLoader("templates"))

SUBSCRIBERS = {}
NEWSLETTERS = {}


class Subscriber:
    def __init__(self, email, name, preferences=None):
        self.email = email
        self.name = name
        self.preferences = preferences or {"format": "html", "frequency": "weekly"}
        self.subscribed_at = None
        self.active = True

    def unsubscribe(self):
        self.active = False
        logger.info(f"Unsubscribed: {self.email}")


class Newsletter:
    def __init__(self, nl_id, subject, body, target_segment="all"):
        self.nl_id = nl_id
        self.subject = subject
        self.body = body
        self.target_segment = target_segment
        self.sent_count = 0

    def record_send(self):
        self.sent_count += 1


def validate_email(email):
    import re
    return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) is not None


def render_newsletter_content(template_str, context):
    tmpl = Template(template_str)
    return tmpl.render(**context)


@app.route("/api/subscribers/subscribe", methods=["POST"])
def subscribe():
    data = request.get_json()
    email = data.get("email", "")
    name = data.get("name", "")
    if not validate_email(email):
        return jsonify({"error": "Invalid email"}), 400
    sub = Subscriber(email, name)
    SUBSCRIBERS[email] = sub
    return jsonify({"status": "subscribed", "email": email}), 201


@app.route("/api/newsletters/preview", methods=["GET"])
def preview_newsletter():
    body = request.args.get("body", "Hello {{ name }}!")
    name = request.args.get("name", "Subscriber")
    html = render_newsletter_content(body, {"name": name})
    return jsonify({"html": html})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 58: request.args.get('body') 获取用户可控模板字符串。\n"
        "2. line 42: render_newsletter_content() 内部调用 Template(template_str) 编译用户输入。\n"
        "3. line 43: .render(**context) 执行模板，攻击者注入 {{config}} 可泄露密钥。\n"
        "4. 结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker='request.args.get("body"',
        source_desc="request.args.get('body') 用户可控模板内容",
        sink_marker="Template(template_str)",
        sink_desc="render_newsletter_content() 内 Template(template_str).render() Jinja2 编译执行",
        explanation="line 58 用户输入 body -> line 42 Template() 编译 -> line 43 .render() 执行 -> 攻击者注入 {{config}} 或沙箱逃逸 payload -> SSTI RCE",
        fix_marker="Template(template_str)",
        fix_desc="使用 env.get_template('newsletter.html') 加载预定义模板，用户输入仅作为 context 变量传入"))

    # --- 13. Java / Thymeleaf — 用户面板控制器 ---
    code = r'''package com.example.user.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.jdbc.core.JdbcTemplate;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/dashboard")
public class UserDashboardController {

    private final JdbcTemplate jdbc;

    public UserDashboardController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/profile/{userId}")
    public String profile(@PathVariable Long userId, Model model) {
        Map<String, Object> user = jdbc.queryForMap(
            "SELECT id, username, email, avatar FROM users WHERE id = ?", userId);
        model.addAttribute("user", user);
        return "dashboard/profile";
    }

    @GetMapping("/settings")
    public String settings(Model model) {
        model.addAttribute("sections", List.of("account", "security", "notifications"));
        return "dashboard/settings";
    }

    @GetMapping("/activity")
    public String activity(Model model) {
        List<Map<String, Object>> logs = jdbc.queryForList(
            "SELECT action, ip, created_at FROM activity_log ORDER BY created_at DESC LIMIT 50");
        model.addAttribute("logs", logs);
        return "dashboard/activity";
    }

    @GetMapping("/widget")
    public String widget(@RequestParam String name, Model model) {
        model.addAttribute("widgetName", name);
        return "dashboard/widget :: " + name;
    }

    @GetMapping("/health")
    @ResponseBody
    public String health() {
        return "{\"status\": \"ok\"}";
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 47: @RequestParam String name 来自用户请求参数。\n"
        "2. line 49: 返回 'dashboard/widget :: ' + name，Thymeleaf 解析片段表达式。\n"
        "3. 攻击者传入 __${T(java.lang.Runtime).getRuntime().exec('id')}__::.x 触发 SpEL 注入。\n"
        "4. 结论：CWE-1336 SSTI（Thymeleaf 模板注入），风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker="@RequestParam String name",
        source_desc="@RequestParam String name 用户可控片段名",
        sink_marker='return "dashboard/widget :: "',
        sink_desc='return "dashboard/widget :: " + name Thymeleaf 视图名拼接导致表达式注入',
        explanation="line 47 name 用户输入 -> line 49 视图名拼接 -> Thymeleaf 解析 __${}__ 表达式 -> SpEL 执行 -> SSTI RCE",
        fix_marker='return "dashboard/widget :: "',
        fix_desc="对 name 做白名单校验（仅允许字母数字下划线），禁止直接拼入视图名"))

    # --- 14. PHP / Twig — CMS 插件 ---
    code = r'''<?php
// CmsPlugin.php
require_once __DIR__ . '/vendor/autoload.php';

use Twig\Environment;
use Twig\Loader\FilesystemLoader;

class CmsPlugin
{
    private $twig;
    private $db;
    private $config;

    public function __construct($pdo, $config = [])
    {
        $this->db = $pdo;
        $this->config = array_merge([
            'site_name' => 'My CMS',
            'max_pages' => 100,
            'cache_ttl' => 3600,
        ], $config);
        $loader = new FilesystemLoader(__DIR__ . '/templates');
        $this->twig = new Environment($loader, ['autoescape' => true]);
    }

    public function getPage($slug)
    {
        $stmt = $this->db->prepare("SELECT * FROM pages WHERE slug = ?");
        $stmt->execute([$slug]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function listPages($limit = 20)
    {
        $stmt = $this->db->prepare("SELECT id, title, slug FROM pages LIMIT ?");
        $stmt->execute([$limit]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function updatePage($id, $title, $content)
    {
        $stmt = $this->db->prepare("UPDATE pages SET title = ?, content = ? WHERE id = ?");
        return $stmt->execute([$title, $content, $id]);
    }

    public function renderPage($page)
    {
        $template = $this->twig->load('page.html');
        return $template->render(['page' => $page, 'site' => $this->config]);
    }

    public function renderCustomBlock($blockTemplate, $data)
    {
        $template = $this->twig->createTemplate($blockTemplate);
        return $template->render($data);
    }
}

$plugin = new CmsPlugin($pdo);
if (isset($_GET['action']) && $_GET['action'] === 'block') {
    $blockTpl = $_GET['block_template'] ?? '';
    $blockData = ['title' => $_GET['title'] ?? 'Block'];
    echo $plugin->renderCustomBlock($blockTpl, $blockData);
}
'''
    S.append(_spec("php", code,
        "分析过程：\n"
        "1. line 57: $_GET['block_template'] 获取用户可控 Twig 模板源码。\n"
        "2. line 50: createTemplate($blockTemplate) 将用户输入编译为 Twig 模板。\n"
        "3. 攻击者传入 {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}} 可 RCE。\n"
        "4. 结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker="$_GET['block_template']",
        source_desc="$_GET['block_template'] 用户可控 Twig 模板源码",
        sink_marker="$this->twig->createTemplate",
        sink_desc="$this->twig->createTemplate($blockTemplate) Twig 从字符串编译模板",
        explanation="line 57 $_GET['block_template'] -> line 50 createTemplate 编译 -> line 51 render 执行 -> 注入回调执行系统命令 -> Twig SSTI RCE",
        fix_marker="$this->twig->createTemplate",
        fix_desc="禁止从用户输入创建模板，应使用 $this->twig->load('block.html') 加载预定义模板"))

    # --- 15. Node.js / Pug — 静态站点生成器 ---
    code = r'''// ssg.js
const express = require('express');
const pug = require('pug');
const path = require('path');
const fs = require('fs');
const matter = require('gray-matter');

const app = express();
const PAGES_DIR = path.join(__dirname, 'content');
const OUTPUT_DIR = path.join(__dirname, 'dist');

class Page {
    constructor(frontmatter, content) {
        this.title = frontmatter.title || 'Untitled';
        this.date = frontmatter.date || new Date();
        this.tags = frontmatter.tags || [];
        this.layout = frontmatter.layout || 'default';
        this.content = content;
    }
}

function loadPages() {
    const pages = [];
    const files = fs.readdirSync(PAGES_DIR).filter(f => f.endsWith('.md'));
    for (const file of files) {
        const raw = fs.readFileSync(path.join(PAGES_DIR, file), 'utf-8');
        const { data, content } = matter(raw);
        pages.push(new Page(data, content));
    }
    return pages;
}

function buildSitemap(pages) {
    return pages.map(p => ({
        url: `/${p.title.toLowerCase().replace(/\s+/g, '-')}`,
        lastmod: p.date.toISOString(),
    }));
}

function writeOutput(filename, content) {
    const filepath = path.join(OUTPUT_DIR, filename);
    fs.mkdirSync(path.dirname(filepath), { recursive: true });
    fs.writeFileSync(filepath, content);
}

app.get('/api/preview', (req, res) => {
    const tpl = req.query.template || 'h1= title\ndiv= content';
    const data = {
        title: req.query.title || 'Preview',
        content: req.query.content || '',
    };
    const html = pug.render(tpl, data);
    res.send(html);
});

app.listen(3000, () => console.log('SSG preview server on port 3000'));
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 53: req.query.template 获取用户可控 Pug 模板字符串。\n"
        "2. line 59: pug.render(tpl, data) 在服务端编译并执行用户模板。\n"
        "3. 攻击者传入 -var x=global.process.mainModule.require('child_process').execSync('id') 可 RCE。\n"
        "4. 结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker="req.query.template",
        source_desc="req.query.template 用户可控 Pug 模板字符串",
        sink_marker="pug.render(tpl",
        sink_desc="pug.render(tpl, data) 服务端 Pug 模板编译执行",
        explanation="line 53 req.query.template 用户输入 -> line 59 pug.render() 编译执行 -> 注入 unbuffered code 调用 require('child_process') -> SSTI RCE",
        fix_marker="pug.render(tpl",
        fix_desc="使用 pug.renderFile('preview.pug', data) 加载预定义模板文件，禁止将用户输入作为模板源码"))

    return S


# ===========================================================================
# 第一部分 - 2: from_string / render_template_string 变体（15 条）
# ===========================================================================
def gen_ssti_from_string():
    """15 条 from_string / render_template_string 变体样本。"""
    S = []

    # --- 1. Flask render_template_string 基本模式 ---
    code = r'''from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 7: request.args.get('name') 获取用户输入，拼入模板字符串。\n"
        "2. line 8: f-string 将用户输入直接嵌入模板 HTML。\n"
        "3. line 9: render_template_string(template) 编译执行含用户输入的模板。\n"
        "4. 攻击者传入 {{config}} 可泄露 Flask 配置。结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker='request.args.get("name"',
        source_desc="request.args.get('name') 用户可控输入",
        sink_marker="render_template_string(template)",
        sink_desc="render_template_string(template) Jinja2 编译执行含用户输入的模板",
        explanation="line 7 用户输入 name -> line 8 f-string 拼入模板 -> line 9 render_template_string 编译执行 -> 注入 {{config}} -> SSTI",
        fix_marker="render_template_string(template)",
        fix_desc="使用 render_template('greet.html', name=name) 加载固定模板，用户输入仅作为变量"))

    # --- 2. Django Template.from_string ---
    code = r'''from django.http import HttpResponse
from django.template import Template, Context
from django.views import View


class GreetingView(View):
    def get(self, request):
        user_template = request.GET.get("tpl", "Hello {{ name }}")
        name = request.GET.get("name", "Guest")
        template = Template(user_template)
        context = Context({"name": name})
        return HttpResponse(template.render(context))
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 8: request.GET.get('tpl') 获取用户可控模板字符串。\n"
        "2. line 10: Template(user_template) 将用户输入编译为 Django 模板。\n"
        "3. line 12: template.render(context) 执行模板，攻击者注入 {% debug %} 可泄露环境变量。\n"
        "4. 结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker='request.GET.get("tpl"',
        source_desc="request.GET.get('tpl') 用户可控模板字符串",
        sink_marker="Template(user_template)",
        sink_desc="Template(user_template) Django 模板编译用户输入",
        explanation="line 8 用户输入 tpl -> line 10 Template() 编译 -> line 12 render() 执行 -> 注入 {% debug %} 或 {% load %} -> Django SSTI",
        fix_marker="Template(user_template)",
        fix_desc="使用 get_template('greeting.html') 加载预定义模板文件，禁止 Template() 从用户输入构造"))

    # --- 3. Jinja2 Environment().from_string() ---
    code = r'''from jinja2 import Environment, BaseLoader
from flask import Flask, request, jsonify

app = Flask(__name__)
env = Environment(loader=BaseLoader())


@app.route("/api/render")
def render():
    template_source = request.args.get("src", "{{ message }}")
    message = request.args.get("msg", "Hello")
    template = env.from_string(template_source)
    result = template.render(message=message)
    return jsonify({"result": result})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 9: request.args.get('src') 获取用户可控模板源码。\n"
        "2. line 11: env.from_string(template_source) 编译用户输入为 Jinja2 模板。\n"
        "3. line 12: template.render() 执行，攻击者注入 {{ ''.__class__.__mro__[1].__subclasses__() }} 可 RCE。\n"
        "4. 结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker='request.args.get("src"',
        source_desc="request.args.get('src') 用户可控模板源码",
        sink_marker="env.from_string(template_source)",
        sink_desc="env.from_string(template_source) Jinja2 从字符串编译模板",
        explanation="line 9 用户输入 src -> line 11 from_string 编译 -> line 12 render 执行 -> 注入沙箱逃逸 payload -> SSTI RCE",
        fix_marker="env.from_string(template_source)",
        fix_desc="使用 env.get_template('template.html') 加载预定义模板，禁止 from_string 处理用户输入"))

    # --- 4. Jinja2 from_string with autoescape=True（防御迷惑：autoescape 不阻止 SSTI） ---
    code = r'''from jinja2 import Environment, BaseLoader, select_autoescape
from flask import Flask, request, jsonify

app = Flask(__name__)
env = Environment(loader=BaseLoader(), autoescape=select_autoescape(["html", "xml"]))


@app.route("/api/template")
def template_view():
    user_tpl = request.args.get("tpl", "{{ data }}")
    data = request.args.get("data", "test")
    template = env.from_string(user_tpl)
    return jsonify({"result": template.render(data=data)})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 9: request.args.get('tpl') 获取用户可控模板源码。\n"
        "2. line 6: autoescape=True 仅自动转义模板输出的 HTML 实体，不阻止模板表达式解析。\n"
        "3. line 11: env.from_string(user_tpl) 编译用户输入，line 12 render 执行。\n"
        "4. 防御迷惑：autoescape 不阻止 {{ }} 表达式执行。结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker='request.args.get("tpl"',
        source_desc="request.args.get('tpl') 用户可控模板源码（autoescape 不阻止 SSTI）",
        sink_marker="env.from_string(user_tpl)",
        sink_desc="env.from_string(user_tpl) Jinja2 从字符串编译模板",
        explanation="line 9 用户输入 tpl -> line 6 autoescape 仅转义输出不阻止 {{}} -> line 11 from_string 编译 -> line 12 render 执行 -> SSTI（防御迷惑：autoescape 无效）",
        fix_marker="env.from_string(user_tpl)",
        fix_desc="禁止 from_string 处理用户输入，应使用 env.get_template() 加载预定义模板文件"))

    # --- 5. nunjucks.renderString() (Node.js) ---
    code = r'''const express = require('express');
const nunjucks = require('nunjucks');

const app = express();
nunjucks.configure('views', { express: app, autoescape: true });

app.get('/render', (req, res) => {
    const tpl = req.query.tpl || 'Hello {{ name }}';
    const name = req.query.name || 'World';
    const html = nunjucks.renderString(tpl, { name });
    res.send(html);
});

app.listen(3000);
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 8: req.query.tpl 获取用户可控 nunjucks 模板字符串。\n"
        "2. line 10: nunjucks.renderString(tpl, { name }) 在服务端编译并执行用户模板。\n"
        "3. 攻击者注入 {{ range.constructor('return global.process.mainModule.require(\"child_process\").execSync(\"id\")')() }} 可 RCE。\n"
        "4. 结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker="req.query.tpl",
        source_desc="req.query.tpl 用户可控 nunjucks 模板字符串",
        sink_marker="nunjucks.renderString(tpl",
        sink_desc="nunjucks.renderString(tpl, { name }) 服务端 nunjucks 模板编译执行",
        explanation="line 8 req.query.tpl 用户输入 -> line 10 renderString 编译执行 -> 注入 constructor 逃逸 payload -> nunjucks SSTI RCE",
        fix_marker="nunjucks.renderString(tpl",
        fix_desc="使用 nunjucks.render('template.html', { name }) 加载预定义模板文件"))

    # --- 6. Flask render_template_string in API endpoint ---
    code = r"""from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)


@app.route("/api/v1/email/preview", methods=["GET"])
def preview_email():
    subject = request.args.get("subject", "Welcome")
    body = request.args.get("body", "Hello!")
    email_tpl = f'''
    <html><body>
    <h1>{{{{ subject }}}}</h1>
    <p>{{{{ body }}}}</p>
    </body></html>
    '''
    html = render_template_string(email_tpl, subject=subject, body=body)
    return jsonify({"html": html})
"""
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 8-9: request.args.get('subject')/('body') 获取用户可控输入。\n"
        "2. line 10: f-string 将用户输入拼入模板 HTML（作为变量值，但 subject/body 可含 {{}}）。\n"
        "3. line 17: render_template_string(email_tpl, ...) 编译执行模板。\n"
        "4. 攻击者传入 subject={{config}} 可泄露配置。结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker='request.args.get("subject"',
        source_desc="request.args.get('subject') 用户可控输入（拼入模板）",
        sink_marker="render_template_string(email_tpl",
        sink_desc="render_template_string(email_tpl, subject=subject, body=body) Jinja2 渲染含用户输入的模板",
        explanation="line 8 用户输入 subject -> line 10 f-string 拼入模板 -> line 17 render_template_string 编译执行 -> 注入 {{config}} -> SSTI",
        fix_marker="render_template_string(email_tpl",
        fix_desc="使用 render_template('email_preview.html', subject=subject, body=body) 加载固定模板文件"))

    # --- 7. Django from_string with context dict ---
    code = r'''from django.http import JsonResponse
from django.template import Template, Context
from django.views.decorators.http import require_GET


@require_GET
def render_template_view(request):
    template_text = request.GET.get("template", "{{ content }}")
    content = request.GET.get("content", "Default content")
    template = Template(template_text)
    context = Context({"content": content})
    rendered = template.render(context)
    return JsonResponse({"rendered": rendered})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 7: request.GET.get('template') 获取用户可控模板字符串。\n"
        "2. line 9: Template(template_text) 将用户输入编译为 Django 模板。\n"
        "3. line 11: template.render(context) 执行模板，攻击者注入 {% debug %} 可泄露环境。\n"
        "4. 结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker='request.GET.get("template"',
        source_desc="request.GET.get('template') 用户可控模板字符串",
        sink_marker="Template(template_text)",
        sink_desc="Template(template_text) Django 模板编译用户输入",
        explanation="line 7 用户输入 template -> line 9 Template() 编译 -> line 11 render() 执行 -> 注入 {% debug %} -> Django SSTI",
        fix_marker="Template(template_text)",
        fix_desc="使用 get_template('template_view.html') 加载预定义模板文件"))

    # --- 8. Jinja2 from_string with custom filter ---
    code = r'''from jinja2 import Environment, BaseLoader
from flask import Flask, request, jsonify

app = Flask(__name__)
env = Environment(loader=BaseLoader())


def truncate(text, length=50):
    return text[:length] if len(text) > length else text


env.filters["trunc"] = truncate


@app.route("/api/format")
def format_text():
    tpl = request.args.get("tpl", "{{ text | trunc(10) }}")
    text = request.args.get("text", "Hello World")
    template = env.from_string(tpl)
    return jsonify({"result": template.render(text=text)})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 15: request.args.get('tpl') 获取用户可控模板字符串。\n"
        "2. line 17: env.from_string(tpl) 编译用户输入为 Jinja2 模板（含自定义 filter）。\n"
        "3. line 18: template.render() 执行，攻击者可利用自定义 filter 或沙箱逃逸。\n"
        "4. 结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker='request.args.get("tpl"',
        source_desc="request.args.get('tpl') 用户可控模板字符串",
        sink_marker="env.from_string(tpl)",
        sink_desc="env.from_string(tpl) Jinja2 从字符串编译含自定义 filter 的模板",
        explanation="line 15 用户输入 tpl -> line 17 from_string 编译 -> line 18 render 执行 -> 注入沙箱逃逸 payload 利用 Python 内省 -> SSTI RCE",
        fix_marker="env.from_string(tpl)",
        fix_desc="使用 env.get_template('format.html') 加载预定义模板文件"))

    # --- 9. nunjucks.renderString with autoescape（防御迷惑） ---
    code = r'''const express = require('express');
const nunjucks = require('nunjucks');

const app = express();
const env = nunjucks.configure('views', {
    autoescape: true,
    throwOnUndefined: true,
});

app.get('/preview', (req, res) => {
    const userTemplate = req.query.tpl || 'Hello {{ name }}';
    const name = req.query.name || 'Guest';
    const html = env.renderString(userTemplate, { name });
    res.send(html);
});

app.listen(3000);
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 10: req.query.tpl 获取用户可控模板字符串。\n"
        "2. line 5: autoescape: true 仅转义输出 HTML 实体，不阻止 {{ }} 表达式解析。\n"
        "3. line 12: env.renderString(userTemplate, ...) 编译并执行用户模板。\n"
        "4. 防御迷惑：autoescape 不阻止模板表达式执行。结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker="req.query.tpl",
        source_desc="req.query.tpl 用户可控模板字符串（autoescape 不阻止 SSTI）",
        sink_marker="env.renderString(userTemplate",
        sink_desc="env.renderString(userTemplate, { name }) nunjucks 编译执行用户模板",
        explanation="line 10 req.query.tpl 用户输入 -> line 5 autoescape 仅转义输出不阻止 {{}} -> line 12 renderString 编译执行 -> SSTI（防御迷惑：autoescape 无效）",
        fix_marker="env.renderString(userTemplate",
        fix_desc="使用 env.render('preview.html', { name }) 加载预定义模板文件"))

    # --- 10. Flask render_template_string with Markup escape（防御迷惑） ---
    code = r'''from flask import Flask, request, render_template_string
from markupsafe import Markup, escape

app = Flask(__name__)


@app.route("/welcome")
def welcome():
    name = request.args.get("name", "Guest")
    safe_name = escape(name)
    template = f"<h1>Welcome, {safe_name}!</h1>"
    return render_template_string(template)
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 8: request.args.get('name') 获取用户输入。\n"
        "2. line 9: escape(name) 转义 HTML 实体（< > &），但不移除 {{ }} Jinja2 语法。\n"
        "3. line 10: f-string 将转义后的用户输入拼入模板字符串。\n"
        "4. line 11: render_template_string(template) 编译执行。防御迷惑：escape 不阻止 SSTI。结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker='request.args.get("name"',
        source_desc="request.args.get('name') 用户可控输入（escape 不阻止 SSTI）",
        sink_marker="render_template_string(template)",
        sink_desc="render_template_string(template) Jinja2 渲染含用户输入的模板",
        explanation="line 8 用户输入 name -> line 9 escape() 仅转义 HTML 不移除 {{}} -> line 10 f-string 拼入模板 -> line 11 render_template_string 执行 -> SSTI（防御迷惑：escape 无效）",
        fix_marker="render_template_string(template)",
        fix_desc="使用 render_template('welcome.html', name=name) 加载固定模板，用户输入仅作为变量"))

    # --- 11. Django from_string in CBV ---
    code = r'''from django.http import HttpResponse
from django.template import Template, Context
from django.views.generic import View


class CustomPageView(View):
    template_source = None

    def get(self, request, *args, **kwargs):
        self.template_source = request.GET.get("page_template", "<h1>{{ title }}</h1>")
        title = request.GET.get("title", "Page")
        template = Template(self.template_source)
        context = Context({"title": title})
        return HttpResponse(template.render(context))
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 10: request.GET.get('page_template') 获取用户可控模板字符串。\n"
        "2. line 12: Template(self.template_source) 编译用户输入为 Django 模板。\n"
        "3. line 13: template.render(context) 执行模板。\n"
        "4. 结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker='request.GET.get("page_template"',
        source_desc="request.GET.get('page_template') 用户可控模板字符串",
        sink_marker="Template(self.template_source)",
        sink_desc="Template(self.template_source) Django 模板编译用户输入",
        explanation="line 10 用户输入 page_template -> line 12 Template() 编译 -> line 13 render() 执行 -> 注入 {% debug %} -> Django SSTI",
        fix_marker="Template(self.template_source)",
        fix_desc="使用 get_template('custom_page.html') 加载预定义模板文件"))

    # --- 12. Jinja2 from_string in utility module ---
    code = r'''from jinja2 import Environment, BaseLoader
from flask import Flask, request, jsonify

app = Flask(__name__)
_env = Environment(loader=BaseLoader())


def render_inline(template_str, **kwargs):
    """渲染内联模板字符串。"""
    return _env.from_string(template_str).render(**kwargs)


@app.route("/api/inline")
def inline_view():
    user_template = request.args.get("tpl", "{{ data }}")
    data = request.args.get("data", "Hello")
    result = render_inline(user_template, data=data)
    return jsonify({"result": result})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 12: request.args.get('tpl') 获取用户可控模板字符串。\n"
        "2. line 8: render_inline() 调用 _env.from_string(template_str) 编译用户输入。\n"
        "3. line 9: .render(**kwargs) 执行模板，攻击者注入 {{config}} 可泄露配置。\n"
        "4. 结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker='request.args.get("tpl"',
        source_desc="request.args.get('tpl') 用户可控模板字符串",
        sink_marker="_env.from_string(template_str)",
        sink_desc="render_inline() 内 _env.from_string(template_str).render() Jinja2 编译执行",
        explanation="line 12 用户输入 tpl -> line 8 from_string 编译 -> line 9 render 执行 -> 注入沙箱逃逸 payload -> SSTI RCE",
        fix_marker="_env.from_string(template_str)",
        fix_desc="使用 _env.get_template('inline.html') 加载预定义模板文件"))

    # --- 13. nunjucks in Express middleware ---
    code = r'''const express = require('express');
const nunjucks = require('nunjucks');

const app = express();
nunjucks.configure('views', { express: app });

function templateMiddleware(req, res, next) {
    res.renderTemplate = function(tplString, data) {
        return nunjucks.renderString(tplString, data);
    };
    next();
}

app.use(templateMiddleware);

app.get('/dynamic', (req, res) => {
    const tpl = req.query.tpl || '<h1>{{ title }}</h1>';
    const title = req.query.title || 'Page';
    const html = res.renderTemplate(tpl, { title });
    res.send(html);
});

app.listen(3000);
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 15: req.query.tpl 获取用户可控 nunjucks 模板字符串。\n"
        "2. line 9: res.renderTemplate 调用 nunjucks.renderString(tplString, data) 编译执行。\n"
        "3. 攻击者注入 {{ constructor('return process')() }} 可逃逸沙箱。\n"
        "4. 结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker="req.query.tpl",
        source_desc="req.query.tpl 用户可控 nunjucks 模板字符串",
        sink_marker="nunjucks.renderString(tplString",
        sink_desc="res.renderTemplate 内 nunjucks.renderString(tplString, data) 服务端编译执行",
        explanation="line 15 req.query.tpl 用户输入 -> line 9 renderString 编译执行 -> 注入 constructor 逃逸 payload -> nunjucks SSTI RCE",
        fix_marker="nunjucks.renderString(tplString",
        fix_desc="使用 nunjucks.render('dynamic.html', { title }) 加载预定义模板文件"))

    # --- 14. Flask render_template_string with format string ---
    code = r'''from flask import Flask, request, render_template_string

app = Flask(__name__)

TEMPLATES = {
    "welcome": "<h1>Welcome, {{ name }}!</h1><p>{{ message }}</p>",
    "goodbye": "<h1>Goodbye, {{ name }}!</h1>",
}


@app.route("/notify")
def notify():
    template_name = request.args.get("type", "welcome")
    name = request.args.get("name", "User")
    message = request.args.get("message", "")
    template = TEMPLATES.get(template_name, TEMPLATES["welcome"])
    if "{{" in message:
        message = message.replace("{{", "").replace("}}", "")
    return render_template_string(template, name=name, message=message)
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 11-12: request.args 获取用户可控 name/message。\n"
        "2. line 15: message 过滤了 {{ }} 但未过滤 {% %} Jinja2 标签语法。\n"
        "3. line 16: render_template_string(template, name=name, message=message) 执行。\n"
        "4. 防御迷惑：仅过滤 {{ }} 未过滤 {% %}。攻击者传入 {% print(config) %} 可执行。结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker='request.args.get("message"',
        source_desc="request.args.get('message') 用户可控输入（过滤不完整）",
        sink_marker="render_template_string(template, name=name",
        sink_desc="render_template_string(template, name=name, message=message) Jinja2 渲染",
        explanation="line 12 用户输入 message -> line 15 仅过滤 {{}} 未过滤 {%%} -> line 16 render_template_string 执行 -> 注入 {% print(config) %} -> SSTI（防御迷惑：过滤不完整）",
        fix_marker="render_template_string(template, name=name",
        fix_desc="使用 render_template('notify.html', name=name, message=message) 加载固定模板文件"))

    # --- 15. Jinja2 from_string with sandbox attempt (bypassed) ---
    code = r'''from jinja2 import Environment, BaseLoader
from jinja2.sandbox import SandboxedEnvironment
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/api/safe_render")
def safe_render():
    user_tpl = request.args.get("tpl", "{{ data }}")
    data = request.args.get("data", "Hello")
    sandbox = SandboxedEnvironment(loader=BaseLoader())
    template = sandbox.from_string(user_tpl)
    result = template.render(data=data)
    return jsonify({"result": result})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 9: request.args.get('tpl') 获取用户可控模板字符串。\n"
        "2. line 12: SandboxedEnvironment 限制了部分内省操作但不完全安全。\n"
        "3. line 13: sandbox.from_string(user_tpl) 编译用户输入，line 14 render 执行。\n"
        "4. 攻击者仍可利用已知绕过 payload 如 {{ cycler.__init__.__globals__.os.popen('id').read() }}。结论：CWE-1336 SSTI，风险 High。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="High",
        source_marker='request.args.get("tpl"',
        source_desc="request.args.get('tpl') 用户可控模板字符串",
        sink_marker="sandbox.from_string(user_tpl)",
        sink_desc="sandbox.from_string(user_tpl) SandboxedEnvironment 从字符串编译模板",
        explanation="line 9 用户输入 tpl -> line 13 sandbox.from_string 编译 -> line 14 render 执行 -> 利用 cycler.__init__.__globals__ 绕过沙箱 -> SSTI",
        fix_marker="sandbox.from_string(user_tpl)",
        fix_desc="禁止从用户输入创建模板，应使用 sandbox.get_template('template.html') 加载预定义模板文件"))

    return S


# ===========================================================================
# 第一部分 - 3: SSTI vs XSS 边界对比（10 条 = 5 对）
# ===========================================================================
def gen_ssti_vs_xss():
    """10 条 SSTI/XSS 对比样本（5 对），结构相似但漏洞类型不同。"""
    S = []

    # --- 对 1 (Python/Flask) ---
    # 1a. SSTI
    code = r'''from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    template = "<h1>Hello {{ name }}!</h1>"
    return render_template_string(template, name=name)
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 7: request.args.get('name') 作为模板变量传入，但 name 可含 {{ }} 表达式。\n"
        "2. line 8: 模板 <h1>Hello {{ name }}!</h1> 含 Jinja2 表达式。\n"
        "3. line 9: render_template_string 在服务端执行模板，若 name={{config}} 则泄露配置。\n"
        "4. 这是 SSTI（服务端模板执行），不是 XSS（客户端浏览器执行）。结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker='request.args.get("name"',
        source_desc="request.args.get('name') 用户可控输入",
        sink_marker="render_template_string(template, name=name)",
        sink_desc="render_template_string(template, name=name) Jinja2 服务端模板渲染",
        explanation="line 7 用户输入 name -> line 9 render_template_string 服务端执行模板 -> 注入 {{config}} 在服务端执行 -> SSTI（非 XSS，执行发生在服务端非浏览器）",
        fix_marker="render_template_string(template, name=name)",
        fix_desc="使用 render_template('greet.html', name=name) 加载固定模板文件"))

    # 1b. XSS
    code = r'''from flask import Flask, request

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    html = f"<h1>Hello {name}!</h1>"
    return html
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 7: request.args.get('name') 获取用户可控输入。\n"
        "2. line 8: f-string 将用户输入直接拼入 HTML 字符串（无模板引擎）。\n"
        "3. line 9: return html 返回原始 HTML，用户输入在浏览器中执行。\n"
        "4. 这是 XSS（客户端浏览器执行），不是 SSTI（无模板引擎在服务端执行）。结论：CWE-79 XSS，风险 High。",
        has_vuln=True, vuln_type="CWE-79 Cross-site Scripting (XSS)",
        risk="High",
        source_marker='request.args.get("name"',
        source_desc="request.args.get('name') 用户可控输入",
        sink_marker='html = f"<h1>Hello {name}',
        sink_desc='f"<h1>Hello {name}!</h1>" 用户输入直接拼入 HTML 响应',
        explanation="line 7 用户输入 name -> line 8 f-string 直接拼入 HTML -> line 9 返回响应 -> 浏览器执行 <script> -> XSS（非 SSTI，无模板引擎，执行发生在浏览器非服务端）",
        fix_marker='html = f"<h1>Hello {name}',
        fix_desc="使用 markupsafe.escape(name) 转义 HTML 特殊字符后再拼入响应"))

    # --- 对 2 (Python/Flask) ---
    # 2a. SSTI
    code = r'''from flask import Flask, request
from jinja2 import Template

app = Flask(__name__)


@app.route("/profile")
def profile():
    bio = request.args.get("bio", "No bio")
    tpl = Template("<div class='bio'>{{ bio }}</div>")
    return tpl.render(bio=bio)
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 8: request.args.get('bio') 作为模板变量传入，但可含 {{ }} 表达式。\n"
        "2. line 9: Template() 编译模板，{{ bio }} 是 Jinja2 表达式。\n"
        "3. line 10: tpl.render(bio=bio) 在服务端执行，bio={{config}} 可泄露配置。\n"
        "4. 这是 SSTI（服务端模板引擎执行），不是 XSS。结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker='request.args.get("bio"',
        source_desc="request.args.get('bio') 用户可控输入",
        sink_marker="tpl.render(bio=bio)",
        sink_desc="Template().render(bio=bio) Jinja2 服务端模板执行",
        explanation="line 8 用户输入 bio -> line 10 Template().render() 服务端执行 -> 注入 {{config}} 在服务端执行 -> SSTI（非 XSS，模板引擎在服务端执行非浏览器）",
        fix_marker="Template(",
        fix_desc="使用 render_template('profile.html', bio=bio) 加载固定模板文件"))

    # 2b. XSS
    code = r'''from flask import Flask, request, render_template

app = Flask(__name__)


@app.route("/profile")
def profile():
    bio = request.args.get("bio", "No bio")
    return render_template("profile.html", bio=bio)
'''
    # profile.html 中 bio 使用了 |safe 过滤器导致 XSS
    code_xss = r'''from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/profile")
def profile():
    bio = request.args.get("bio", "No bio")
    html = "<div class='bio'>" + bio + "</div>"
    return html
'''
    S.append(_spec("python", code_xss,
        "分析过程：\n"
        "1. line 8: request.args.get('bio') 获取用户可控输入。\n"
        "2. line 9: 字符串拼接将用户输入直接嵌入 HTML（无模板引擎、无转义）。\n"
        "3. line 10: return html 返回原始 HTML，攻击者注入 <script>alert(1)</script> 在浏览器执行。\n"
        "4. 这是 XSS（客户端浏览器执行），不是 SSTI（无模板引擎在服务端执行）。结论：CWE-79 XSS，风险 High。",
        has_vuln=True, vuln_type="CWE-79 Cross-site Scripting (XSS)",
        risk="High",
        source_marker='request.args.get("bio"',
        source_desc="request.args.get('bio') 用户可控输入",
        sink_marker='html = "<div class',
        sink_desc='"<div class=\'bio\'>" + bio + "</div>" 用户输入直接拼入 HTML',
        explanation="line 8 用户输入 bio -> line 9 字符串拼接直接嵌入 HTML -> line 10 返回响应 -> 浏览器执行 <script> -> XSS（非 SSTI，无模板引擎，执行在浏览器）",
        fix_marker='html = "<div class',
        fix_desc="使用 markupsafe.escape(bio) 转义 HTML 特殊字符后再拼入响应"))

    # --- 对 3 (PHP) ---
    # 3a. SSTI (Twig)
    code = r'''<?php
require_once __DIR__ . '/vendor/autoload.php';

use Twig\Environment;
use Twig\Loader\ArrayLoader;

$loader = new ArrayLoader(['tpl' => '<p>{{ message }}</p>']);
$twig = new Environment($loader);

$message = $_GET['message'] ?? 'Hello';
echo $twig->render('tpl', ['message' => $message]);
'''
    S.append(_spec("php", code,
        "分析过程：\n"
        "1. line 8: $_GET['message'] 作为模板变量传入，但可含 Twig {{ }} 表达式。\n"
        "2. line 9: $twig->render('tpl', ...) 在服务端执行 Twig 模板。\n"
        "3. 攻击者传入 message={{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}} 可 RCE。\n"
        "4. 这是 SSTI（服务端模板引擎执行），不是 XSS。结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker="$_GET['message']",
        source_desc="$_GET['message'] 用户可控输入",
        sink_marker="$twig->render('tpl'",
        sink_desc="$twig->render('tpl', ['message' => $message]) Twig 服务端模板渲染",
        explanation="line 8 $_GET['message'] 用户输入 -> line 9 twig->render 服务端执行 -> 注入 {{_self.env...}} 回调执行系统命令 -> SSTI（非 XSS，模板引擎在服务端执行）",
        fix_marker="$twig->render('tpl'",
        fix_desc="对 message 使用 Twig 的 escape 过滤器或确保 autoescape 开启，但核心修复是禁止用户输入含模板表达式"))

    # 3b. XSS (PHP echo)
    code = r'''<?php
$message = $_GET['message'] ?? 'Hello';
echo "<p>" . $message . "</p>";
'''
    S.append(_spec("php", code,
        "分析过程：\n"
        "1. line 2: $_GET['message'] 获取用户可控输入。\n"
        "2. line 3: echo 直接输出用户输入拼入 HTML（无转义、无模板引擎）。\n"
        "3. 攻击者传入 message=<script>alert(document.cookie)</script> 在浏览器执行。\n"
        "4. 这是 XSS（客户端浏览器执行），不是 SSTI（无模板引擎在服务端执行）。结论：CWE-79 XSS，风险 High。",
        has_vuln=True, vuln_type="CWE-79 Cross-site Scripting (XSS)",
        risk="High",
        source_marker="$_GET['message']",
        source_desc="$_GET['message'] 用户可控输入",
        sink_marker='echo "<p>"',
        sink_desc='echo "<p>" . $message . "</p>" 用户输入直接输出到 HTML',
        explanation="line 2 $_GET['message'] 用户输入 -> line 3 echo 直接输出 HTML -> 浏览器执行 <script> -> XSS（非 SSTI，无模板引擎，执行在浏览器）",
        fix_marker='echo "<p>"',
        fix_desc="使用 htmlspecialchars($message, ENT_QUOTES, 'UTF-8') 转义后输出"))

    # --- 对 4 (Node.js/EJS) ---
    # 4a. SSTI
    code = r'''const express = require('express');
const ejs = require('ejs');
const app = express();

app.get('/display', (req, res) => {
    const content = req.query.content || 'Hello';
    const tpl = '<div><%= content %></div>';
    const html = ejs.render(tpl, { content });
    res.send(html);
});

app.listen(3000);
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 6: req.query.content 作为模板变量传入，但可含 EJS <%= %> 表达式。\n"
        "2. line 7: 模板含 <%= content %> EJS 表达式。\n"
        "3. line 8: ejs.render(tpl, { content }) 在服务端执行模板，content=<%= require('child_process').execSync('id') %> 可 RCE。\n"
        "4. 这是 SSTI（服务端模板引擎执行），不是 XSS。结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker="req.query.content",
        source_desc="req.query.content 用户可控输入",
        sink_marker="ejs.render(tpl",
        sink_desc="ejs.render(tpl, { content }) 服务端 EJS 模板编译执行",
        explanation="line 6 req.query.content 用户输入 -> line 8 ejs.render() 服务端执行 -> 注入 <%= require('child_process') %> -> SSTI（非 XSS，模板引擎在服务端执行）",
        fix_marker="ejs.render(tpl",
        fix_desc="使用 res.render('display.ejs', { content }) 加载预定义模板文件"))

    # 4b. XSS
    code = r'''const express = require('express');
const app = express();

app.get('/display', (req, res) => {
    const content = req.query.content || 'Hello';
    const html = '<div>' + content + '</div>';
    res.send(html);
});

app.listen(3000);
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 5: req.query.content 获取用户可控输入。\n"
        "2. line 6: 字符串拼接将用户输入直接嵌入 HTML（无模板引擎、无转义）。\n"
        "3. line 7: res.send(html) 返回原始 HTML，攻击者注入 <script> 在浏览器执行。\n"
        "4. 这是 XSS（客户端浏览器执行），不是 SSTI（无模板引擎在服务端执行）。结论：CWE-79 XSS，风险 High。",
        has_vuln=True, vuln_type="CWE-79 Cross-site Scripting (XSS)",
        risk="High",
        source_marker="req.query.content",
        source_desc="req.query.content 用户可控输入",
        sink_marker="const html = '<div>'",
        sink_desc="'<div>' + content + '</div>' 用户输入直接拼入 HTML",
        explanation="line 5 req.query.content 用户输入 -> line 6 字符串拼接嵌入 HTML -> line 7 res.send 返回 -> 浏览器执行 <script> -> XSS（非 SSTI，无模板引擎，执行在浏览器）",
        fix_marker="const html = '<div>'",
        fix_desc="使用 const escape = require('escape-html'); html = '<div>' + escape(content) + '</div>'"))

    # --- 对 5 (Node.js/Pug) ---
    # 5a. SSTI
    code = r'''const express = require('express');
const pug = require('pug');
const app = express();

app.get('/page', (req, res) => {
    const title = req.query.title || 'Page';
    const tpl = 'h1= title';
    const html = pug.render(tpl, { title });
    res.send(html);
});

app.listen(3000);
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 6: req.query.title 作为模板变量传入，但模板本身可被注入。\n"
        "2. line 7: tpl = 'h1= title' 若攻击者控制 tpl 可注入 unbuffered code。\n"
        "3. line 8: pug.render(tpl, { title }) 在服务端执行模板。\n"
        "4. 这是 SSTI（服务端模板引擎执行），不是 XSS。结论：CWE-1336 SSTI，风险 Critical。",
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)",
        risk="Critical",
        source_marker="req.query.title",
        source_desc="req.query.title 用户可控输入（若同时控制 tpl 则为完整 SSTI）",
        sink_marker="pug.render(tpl",
        sink_desc="pug.render(tpl, { title }) 服务端 Pug 模板编译执行",
        explanation="line 6 req.query.title 用户输入 -> line 8 pug.render() 服务端执行 -> 注入 unbuffered code 调用 require('child_process') -> SSTI（非 XSS，模板引擎在服务端执行）",
        fix_marker="pug.render(tpl",
        fix_desc="使用 res.render('page.pug', { title }) 加载预定义模板文件"))

    # 5b. XSS
    code = r'''const express = require('express');
const app = express();

app.get('/page', (req, res) => {
    const title = req.query.title || 'Page';
    res.write('<h1>' + title + '</h1>');
    res.end();
});

app.listen(3000);
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 5: req.query.title 获取用户可控输入。\n"
        "2. line 6: res.write 直接输出用户输入拼入 HTML（无模板引擎、无转义）。\n"
        "3. 攻击者传入 title=<img src=x onerror=alert(1)> 在浏览器执行。\n"
        "4. 这是 XSS（客户端浏览器执行），不是 SSTI（无模板引擎在服务端执行）。结论：CWE-79 XSS，风险 High。",
        has_vuln=True, vuln_type="CWE-79 Cross-site Scripting (XSS)",
        risk="High",
        source_marker="req.query.title",
        source_desc="req.query.title 用户可控输入",
        sink_marker="res.write(",
        sink_desc="res.write('<h1>' + title + '</h1>') 用户输入直接输出到 HTML",
        explanation="line 5 req.query.title 用户输入 -> line 6 res.write 直接输出 HTML -> 浏览器执行 <img onerror> -> XSS（非 SSTI，无模板引擎，执行在浏览器）",
        fix_marker="res.write(",
        fix_desc="使用 const escape = require('escape-html'); res.write('<h1>' + escape(title) + '</h1>')"))

    return S


# ===========================================================================
# 第二部分 - 1: CWE-639 Authorization Bypass / IDOR（10 条）
# ===========================================================================
def gen_idor():
    """10 条 CWE-639 IDOR 样本。"""
    S = []

    # --- 1. Flask 订单查询 ---
    code = r'''from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///shop.db"
db = SQLAlchemy(app)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    total = db.Column(db.Float)
    status = db.Column(db.String(20))


@app.route("/api/orders/<int:order_id>")
def get_order(order_id):
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    order = Order.query.get(order_id)
    if not order:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"id": order.id, "total": order.total, "status": order.status})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 18: session 检查确保用户已登录（有认证）。\n"
        "2. line 21: Order.query.get(order_id) 按 order_id 查询，但未校验 order.user_id == session['user_id']。\n"
        "3. 任意已登录用户修改 URL 中的 order_id 即可访问他人订单。\n"
        "4. 结论：CWE-639 授权绕过（IDOR），风险 High。",
        has_vuln=True, vuln_type="CWE-639 Authorization Bypass (IDOR)",
        risk="High",
        source_marker="order_id)",
        source_desc="get_order(order_id) 路由参数用户可控",
        sink_marker="Order.query.get(order_id)",
        sink_desc="Order.query.get(order_id) 按参数查询订单未校验归属",
        explanation="line 18 session 认证通过（有认证）-> line 21 Order.query.get(order_id) 查任意订单 -> 未校验 order.user_id == session['user_id'] -> IDOR 授权绕过",
        fix_marker="Order.query.get(order_id)",
        fix_desc="查询后校验 if order.user_id != session['user_id']: return 403，或使用 Order.query.filter_by(id=order_id, user_id=session['user_id']).first()"))

    # --- 2. Express 文件下载 ---
    code = r'''const express = require('express');
const jwt = require('jsonwebtoken');
const { File } = require('./models');

const app = express();

function authMiddleware(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (e) {
        res.status(401).json({ error: 'Unauthorized' });
    }
}

app.get('/api/files/:fileId/download', authMiddleware, async (req, res) => {
    const file = await File.findById(req.params.fileId);
    if (!file) return res.status(404).json({ error: 'Not found' });
    res.download(file.path, file.name);
});

app.listen(3000);
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 10-16: authMiddleware 校验 JWT（有认证）。\n"
        "2. line 19: File.findById(req.params.fileId) 按 fileId 查询，未校验 file.ownerId == req.user.id。\n"
        "3. 任意已认证用户修改 fileId 即可下载他人文件。\n"
        "4. 结论：CWE-639 授权绕过（IDOR），风险 High。",
        has_vuln=True, vuln_type="CWE-639 Authorization Bypass (IDOR)",
        risk="High",
        source_marker="req.params.fileId",
        source_desc="req.params.fileId 路由参数用户可控",
        sink_marker="File.findById(req.params.fileId)",
        sink_desc="File.findById(req.params.fileId) 按参数查询文件未校验归属",
        explanation="line 10 authMiddleware JWT 认证通过 -> line 19 File.findById 查任意文件 -> 未校验 file.ownerId == req.user.id -> IDOR 授权绕过",
        fix_marker="File.findById(req.params.fileId)",
        fix_desc="使用 File.findOne({ _id: req.params.fileId, ownerId: req.user.id }) 确保只返回当前用户的文件"))

    # --- 3. Java Spring Profile 查看 ---
    code = r'''package com.example.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ProfileController {

    private final JdbcTemplate jdbc;

    public ProfileController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/users/{userId}/profile")
    public Map<String, Object> getProfile(@PathVariable Long userId,
                                          @RequestHeader("X-User-Id") Long currentUserId) {
        Map<String, Object> profile = jdbc.queryForMap(
            "SELECT id, username, email, phone, address FROM users WHERE id = ?", userId);
        return profile;
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 19: @RequestHeader('X-User-Id') 获取当前用户 ID（有身份标识）。\n"
        "2. line 21: jdbc.queryForMap 按传入的 userId 查询，未校验 userId == currentUserId。\n"
        "3. 任意已认证用户修改路径中的 userId 即可查看他人 profile（含 email、phone、address）。\n"
        "4. 结论：CWE-639 授权绕过（IDOR），风险 High。",
        has_vuln=True, vuln_type="CWE-639 Authorization Bypass (IDOR)",
        risk="High",
        source_marker="@PathVariable Long userId",
        source_desc="@PathVariable Long userId 路径参数用户可控",
        sink_marker="jdbc.queryForMap(",
        sink_desc="jdbc.queryForMap(...WHERE id = ?, userId) 按参数查询用户资料未校验归属",
        explanation="line 19 X-User-Id 标识当前用户（有身份）-> line 21 queryForMap 按 userId 查任意用户资料 -> 未校验 userId == currentUserId -> IDOR 授权绕过",
        fix_marker="jdbc.queryForMap(",
        fix_desc="查询前校验 if (!userId.equals(currentUserId)) throw new ForbiddenException()，或 WHERE id = ? AND id = ? 传入 currentUserId"))

    # --- 4. Flask API 资源访问 ---
    code = r'''from flask import Flask, request, jsonify, g
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
auth = HTTPBasicAuth()


@auth.verify_password
def verify_password(username, password):
    user = check_credentials(username, password)
    if user:
        g.current_user = user
        return True
    return False


@app.route("/api/resources/<int:resource_id>")
@auth.login_required
def get_resource(resource_id):
    resource = db.session.query(Resource).get(resource_id)
    if not resource:
        return jsonify({"error": "Not found"}), 404
    return jsonify(resource.to_dict())
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 15-16: @auth.login_required 确保用户已通过 Basic Auth 认证。\n"
        "2. line 18: db.session.query(Resource).get(resource_id) 按 resource_id 查询，未校验 resource.owner_id == g.current_user.id。\n"
        "3. 任意已认证用户修改 resource_id 即可访问他人资源。\n"
        "4. 结论：CWE-639 授权绕过（IDOR），风险 High。",
        has_vuln=True, vuln_type="CWE-639 Authorization Bypass (IDOR)",
        risk="High",
        source_marker="resource_id)",
        source_desc="get_resource(resource_id) 路由参数用户可控",
        sink_marker="db.session.query(Resource).get(resource_id)",
        sink_desc="db.session.query(Resource).get(resource_id) 按参数查询资源未校验归属",
        explanation="line 15 @auth.login_required 认证通过 -> line 18 query.get(resource_id) 查任意资源 -> 未校验 resource.owner_id == g.current_user.id -> IDOR 授权绕过",
        fix_marker="db.session.query(Resource).get(resource_id)",
        fix_desc="使用 db.session.query(Resource).filter_by(id=resource_id, owner_id=g.current_user.id).first() 确保只返回当前用户的资源"))

    # --- 5. Go 文档访问 ---
    code = r'''package main

import (
    "database/sql"
    "encoding/json"
    "net/http"
    "github.com/gorilla/mux"
    _ "github.com/lib/pq"
)

type Document struct {
    ID      int    `json:"id"`
    Title   string `json:"title"`
    OwnerID int    `json:"owner_id"`
    Content string `json:"content"`
}

var db *sql.DB

func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        session, _ := store.Get(r, "session")
        if session.Values["user_id"] == nil {
            http.Error(w, "Unauthorized", 401)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func GetDocument(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    docID := vars["doc_id"]
    var doc Document
    err := db.QueryRow(
        "SELECT id, title, owner_id, content FROM documents WHERE id = $1", docID,
    ).Scan(&doc.ID, &doc.Title, &doc.OwnerID, &doc.Content)
    if err != nil {
        http.Error(w, "Not found", 404)
        return
    }
    json.NewEncoder(w).Encode(doc)
}

func main() {
    r := mux.NewRouter()
    r.Handle("/api/docs/{doc_id}", AuthMiddleware(http.HandlerFunc(GetDocument)))
    http.ListenAndServe(":8080", r)
}
'''
    S.append(_spec("go", code,
        "分析过程：\n"
        "1. line 28-33: AuthMiddleware 检查 session user_id（有认证）。\n"
        "2. line 39: db.QueryRow 按 doc_id 查询文档，未校验 doc.OwnerID == session user_id。\n"
        "3. 任意已登录用户修改 URL 中 doc_id 即可访问他人文档。\n"
        "4. 结论：CWE-639 授权绕过（IDOR），风险 High。",
        has_vuln=True, vuln_type="CWE-639 Authorization Bypass (IDOR)",
        risk="High",
        source_marker='vars["doc_id"]',
        source_desc="vars['doc_id'] 路由参数用户可控",
        sink_marker="db.QueryRow(",
        sink_desc="db.QueryRow(...WHERE id = $1, docID) 按参数查询文档未校验归属",
        explanation="line 28 AuthMiddleware session 认证通过 -> line 39 db.QueryRow 按 doc_id 查任意文档 -> 未校验 doc.OwnerID == session['user_id'] -> IDOR 授权绕过",
        fix_marker="db.QueryRow(",
        fix_desc="查询时加 WHERE id = $1 AND owner_id = $2 传入 docID 和 session.Values['user_id']"))

    # --- 6. PHP 发票查看 ---
    code = r'''<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Not authenticated']);
    exit;
}

$invoiceId = $_GET['invoice_id'] ?? null;
if (!$invoiceId) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing invoice_id']);
    exit;
}

$stmt = $pdo->prepare("SELECT id, user_id, amount, status, items FROM invoices WHERE id = ?");
$stmt->execute([$invoiceId]);
$invoice = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$invoice) {
    http_response_code(404);
    echo json_encode(['error' => 'Not found']);
    exit;
}

echo json_encode($invoice);
'''
    S.append(_spec("php", code,
        "分析过程：\n"
        "1. line 2-6: session_start + 检查 $_SESSION['user_id']（有认证）。\n"
        "2. line 16: SQL 按 invoice_id 查询，未加 WHERE user_id = ? 条件。\n"
        "3. 任意已登录用户修改 invoice_id 参数即可查看他人发票。\n"
        "4. 结论：CWE-639 授权绕过（IDOR），风险 High。",
        has_vuln=True, vuln_type="CWE-639 Authorization Bypass (IDOR)",
        risk="High",
        source_marker="$_GET['invoice_id']",
        source_desc="$_GET['invoice_id'] 用户可控参数",
        sink_marker="$stmt->execute(",
        sink_desc="$stmt->execute([$invoiceId]) 按参数查询发票未校验归属",
        explanation="line 2 session 认证通过 -> line 16 SQL 查任意发票 -> 未加 WHERE user_id = $_SESSION['user_id'] -> IDOR 授权绕过",
        fix_marker="$stmt->execute(",
        fix_desc="SQL 改为 WHERE id = ? AND user_id = ? 并传入 $invoiceId 和 $_SESSION['user_id']"))

    # --- 7. Express 用户设置 ---
    code = r'''const express = require('express');
const app = express();
app.use(express.json());

// 认证中间件
app.use((req, res, next) => {
    const token = req.cookies.session;
    if (!token) return res.status(401).json({ error: 'Login required' });
    try {
        req.user = verifySession(token);
        next();
    } catch (e) {
        res.status(401).json({ error: 'Invalid session' });
    }
});

app.get('/api/users/:uid/settings', async (req, res) => {
    const settings = await db.Settings.findOne({ where: { userId: req.params.uid } });
    if (!settings) return res.status(404).json({ error: 'Not found' });
    res.json(settings);
});

app.listen(3000);
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 6-15: 认证中间件校验 session token（有认证）。\n"
        "2. line 18: db.Settings.findOne 按 req.params.uid 查询，未校验 uid == req.user.id。\n"
        "3. 任意已认证用户修改 URL 中 uid 即可查看他人设置。\n"
        "4. 结论：CWE-639 授权绕过（IDOR），风险 High。",
        has_vuln=True, vuln_type="CWE-639 Authorization Bypass (IDOR)",
        risk="High",
        source_marker="req.params.uid",
        source_desc="req.params.uid 路由参数用户可控",
        sink_marker="db.Settings.findOne(",
        sink_desc="db.Settings.findOne({ where: { userId: req.params.uid } }) 按参数查询设置未校验归属",
        explanation="line 6 认证中间件通过 -> line 18 findOne 按 uid 查任意用户设置 -> 未校验 uid == req.user.id -> IDOR 授权绕过",
        fix_marker="db.Settings.findOne(",
        fix_desc="使用 { where: { userId: req.params.uid, userId: req.user.id } } 或查询后校验 settings.userId === req.user.id"))

    # --- 8. Flask 带防御迷惑（@login_required 但无归属校验） ---
    code = r'''from flask import Flask, request, jsonify, session
from functools import wraps

app = Flask(__name__)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Login required"}), 401
        return f(*args, **kwargs)
    return decorated


@app.route("/api/projects/<int:project_id>")
@login_required
def get_project(project_id):
    project = Project.query.filter_by(id=project_id).first()
    if not project:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"name": project.name, "data": project.data})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 8-13: login_required 装饰器检查 session['user_id']（有认证，看似有防御）。\n"
        "2. line 19: Project.query.filter_by(id=project_id) 按 project_id 查询，未加 user_id 条件。\n"
        "3. 防御迷惑：@login_required 仅保证登录，不保证资源归属。任意已登录用户可访问他人项目。\n"
        "4. 结论：CWE-639 授权绕过（IDOR），风险 High。",
        has_vuln=True, vuln_type="CWE-639 Authorization Bypass (IDOR)",
        risk="High",
        source_marker="project_id)",
        source_desc="get_project(project_id) 路由参数用户可控",
        sink_marker="Project.query.filter_by(id=project_id)",
        sink_desc="Project.query.filter_by(id=project_id) 按参数查询项目未校验归属",
        explanation="line 8 @login_required 认证通过（防御迷惑：仅认证未授权）-> line 19 filter_by(id=project_id) 查任意项目 -> 未加 user_id=session['user_id'] -> IDOR 授权绕过",
        fix_marker="Project.query.filter_by(id=project_id)",
        fix_desc="改为 Project.query.filter_by(id=project_id, user_id=session['user_id']).first() 确保只返回当前用户的项目"))

    # --- 9. Java 项目访问 ---
    code = r'''package com.example.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import java.util.Map;
import java.util.List;

@RestController
@RequestMapping("/api")
public class ProjectController {

    private final JdbcTemplate jdbc;

    public ProjectController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/projects/{projectId}")
    public Map<String, Object> getProject(@PathVariable Long projectId,
                                          @AuthenticationPrincipal UserDetails currentUser) {
        Map<String, Object> project = jdbc.queryForMap(
            "SELECT id, name, description, config FROM projects WHERE id = ?", projectId);
        return project;
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 20: @AuthenticationPrincipal UserDetails currentUser 获取当前认证用户（有认证）。\n"
        "2. line 22: jdbc.queryForMap 按 projectId 查询，未校验项目归属。\n"
        "3. 任意已认证用户修改 projectId 即可访问他人项目（含 config 敏感配置）。\n"
        "4. 结论：CWE-639 授权绕过（IDOR），风险 High。",
        has_vuln=True, vuln_type="CWE-639 Authorization Bypass (IDOR)",
        risk="High",
        source_marker="@PathVariable Long projectId",
        source_desc="@PathVariable Long projectId 路径参数用户可控",
        sink_marker="jdbc.queryForMap(",
        sink_desc="jdbc.queryForMap(...WHERE id = ?, projectId) 按参数查询项目未校验归属",
        explanation="line 20 @AuthenticationPrincipal 认证用户 -> line 22 queryForMap 按 projectId 查任意项目 -> 未校验 project.owner == currentUser -> IDOR 授权绕过",
        fix_marker="jdbc.queryForMap(",
        fix_desc="SQL 加 WHERE id = ? AND owner_id = (SELECT id FROM users WHERE username = ?) 传入 projectId 和 currentUser.getUsername()"))

    # --- 10. Go 附件下载（防御迷惑：有 session 但无归属校验） ---
    code = r'''package main

import (
    "database/sql"
    "net/http"
    "github.com/gorilla/mux"
    _ "github.com/lib/pq"
)

var db *sql.DB

func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        cookie, err := r.Cookie("session_id")
        if err != nil {
            http.Error(w, "Unauthorized", 401)
            return
        }
        userID, ok := validateSession(cookie.Value)
        if !ok {
            http.Error(w, "Invalid session", 401)
            return
        }
        r = withUserID(r, userID)
        next.ServeHTTP(w, r)
    })
}

func DownloadAttachment(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    attachmentID := vars["attachment_id"]
    var filePath string
    err := db.QueryRow(
        "SELECT file_path FROM attachments WHERE id = $1", attachmentID,
    ).Scan(&filePath)
    if err != nil {
        http.Error(w, "Not found", 404)
        return
    }
    http.ServeFile(w, r, filePath)
}

func main() {
    r := mux.NewRouter()
    r.Handle("/api/attachments/{attachment_id}/download",
        AuthMiddleware(http.HandlerFunc(DownloadAttachment)))
    http.ListenAndServe(":8080", r)
}
'''
    S.append(_spec("go", code,
        "分析过程：\n"
        "1. line 13-26: AuthMiddleware 校验 session cookie（有认证，看似有防御）。\n"
        "2. line 33: db.QueryRow 按 attachment_id 查询文件路径，未校验附件归属当前用户。\n"
        "3. 防御迷惑：session 认证通过但不校验资源归属。任意已登录用户可下载他人附件。\n"
        "4. 结论：CWE-639 授权绕过（IDOR），风险 High。",
        has_vuln=True, vuln_type="CWE-639 Authorization Bypass (IDOR)",
        risk="High",
        source_marker='vars["attachment_id"]',
        source_desc="vars['attachment_id'] 路由参数用户可控",
        sink_marker="db.QueryRow(",
        sink_desc="db.QueryRow(...WHERE id = $1, attachmentID) 按参数查询附件路径未校验归属",
        explanation="line 13 AuthMiddleware session 认证通过（防御迷惑：仅认证未授权）-> line 33 QueryRow 按 attachment_id 查任意附件 -> 未校验归属 -> IDOR 授权绕过",
        fix_marker="db.QueryRow(",
        fix_desc="SQL 加 WHERE id = $1 AND owner_id = $2 传入 attachmentID 和当前 session user_id"))

    return S


# ===========================================================================
# 第二部分 - 2: CWE-862 Missing Authorization（10 条）
# ===========================================================================
def gen_missing_auth():
    """10 条 CWE-862 Missing Authorization 样本。"""
    S = []

    # --- 1. Flask admin API 无 @login_required ---
    code = r'''from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/api/admin/users/list")
def list_all_users():
    users = User.query.all()
    return jsonify([{"id": u.id, "username": u.username, "email": u.email} for u in users])


@app.route("/api/admin/users/<int:user_id>/delete", methods=["DELETE"])
def delete_user(user_id):
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({"status": "deleted"})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 6: /api/admin/users/list 路由无 @login_required 或角色检查装饰器。\n"
        "2. line 12: /api/admin/users/<id>/delete 同样无任何授权检查。\n"
        "3. 任意未认证用户可直接访问 admin API，列出所有用户或删除用户。\n"
        "4. 结论：CWE-862 缺少授权检查，风险 Critical。",
        has_vuln=True, vuln_type="CWE-862 Missing Authorization",
        risk="Critical",
        source_marker='"/api/admin/users/list"',
        source_desc="/api/admin/users/list 路由无任何授权装饰器",
        sink_marker="def delete_user(user_id):",
        sink_desc="delete_user() 删除用户操作完全缺少授权检查",
        explanation="line 6 admin 路由无 @login_required / 无角色检查 -> line 12 delete 操作同样无授权 -> 任意未认证用户可访问 admin API -> CWE-862 缺少授权（非 IDOR，完全无授权检查）",
        fix_marker="def delete_user(user_id):",
        fix_desc="在路由上添加 @login_required + @admin_required 装饰器，确保只有管理员角色可访问"))

    # --- 2. Express admin 路由无 auth 中间件 ---
    code = r'''const express = require('express');
const app = express();

// 普通用户路由有认证
app.get('/api/profile', authMiddleware, (req, res) => {
    res.json({ user: req.user });
});

// 管理后台路由无认证
app.get('/api/admin/config', (req, res) => {
    const config = readConfigFile();
    res.json(config);
});

app.post('/api/admin/users/:id/ban', (req, res) => {
    banUser(req.params.id);
    res.json({ status: 'banned' });
});

app.listen(3000);
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 6: /api/profile 有 authMiddleware（普通路由有认证）。\n"
        "2. line 11: /api/admin/config 无 authMiddleware（admin 路由完全无授权）。\n"
        "3. line 16: /api/admin/users/:id/ban 同样无授权，任意未认证用户可封禁他人。\n"
        "4. 结论：CWE-862 缺少授权检查，风险 Critical。",
        has_vuln=True, vuln_type="CWE-862 Missing Authorization",
        risk="Critical",
        source_marker="'/api/admin/config'",
        source_desc="/api/admin/config 路由无 authMiddleware 授权中间件",
        sink_marker="banUser(req.params.id)",
        sink_desc="banUser() 封禁用户操作完全缺少授权检查",
        explanation="line 6 /api/profile 有 authMiddleware -> line 11 /api/admin/config 无 authMiddleware -> line 16 ban 操作无授权 -> CWE-862 缺少授权（非 IDOR，完全无授权检查）",
        fix_marker="'/api/admin/config'",
        fix_desc="在 admin 路由上添加 authMiddleware + adminOnlyMiddleware，确保只有管理员角色可访问"))

    # --- 3. Java Spring admin 控制器无 @PreAuthorize ---
    code = r'''package com.example.admin.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
public class AdminUserController {

    private final JdbcTemplate jdbc;

    public AdminUserController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/users")
    public List<Map<String, Object>> listUsers() {
        return jdbc.queryForList("SELECT id, username, email, role FROM users");
    }

    @PostMapping("/users/{id}/role")
    public Map<String, Object> updateRole(@PathVariable Long id, @RequestParam String role) {
        jdbc.update("UPDATE users SET role = ? WHERE id = ?", role, id);
        return Map.of("status", "updated");
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 10: @RequestMapping('/api/admin') 标识 admin 控制器，但无 @PreAuthorize 或角色检查。\n"
        "2. line 18: listUsers() 返回所有用户信息，无授权注解。\n"
        "3. line 23: updateRole() 修改用户角色，同样无授权检查。\n"
        "4. 结论：CWE-862 缺少授权检查，风险 Critical。",
        has_vuln=True, vuln_type="CWE-862 Missing Authorization",
        risk="Critical",
        source_marker='@RequestMapping("/api/admin")',
        source_desc="@RequestMapping('/api/admin') 控制器无 @PreAuthorize 授权注解",
        sink_marker="jdbc.update(",
        sink_desc="jdbc.update(...UPDATE users SET role...) 修改角色操作完全缺少授权检查",
        explanation="line 10 @RequestMapping('/api/admin') 无 @PreAuthorize -> line 18 listUsers 无授权 -> line 23 updateRole 无授权 -> CWE-862 缺少授权（非 IDOR，完全无授权检查）",
        fix_marker="jdbc.update(",
        fix_desc="在控制器类或方法上添加 @PreAuthorize('hasRole(\"ADMIN\")') 注解，确保只有管理员角色可访问"))

    # --- 4. Flask 配置修改无角色检查 ---
    code = r'''from flask import Flask, request, jsonify

app = Flask(__name__)
app.config["FEATURE_FLAGS"] = {"maintenance": False, "signup": True}


@app.route("/api/config/feature-flags", methods=["GET"])
def get_feature_flags():
    return jsonify(app.config["FEATURE_FLAGS"])


@app.route("/api/config/feature-flags", methods=["PUT"])
def update_feature_flags():
    data = request.get_json()
    app.config["FEATURE_FLAGS"].update(data)
    return jsonify(app.config["FEATURE_FLAGS"])
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 7: GET /api/config/feature-flags 无 @login_required 或角色检查。\n"
        "2. line 12: PUT /api/config/feature-flags 修改功能开关，同样无授权检查。\n"
        "3. 任意未认证用户可查看和修改系统功能开关（如开启 maintenance 模式）。\n"
        "4. 结论：CWE-862 缺少授权检查，风险 High。",
        has_vuln=True, vuln_type="CWE-862 Missing Authorization",
        risk="High",
        source_marker='"/api/config/feature-flags", methods=["PUT"]',
        source_desc="PUT /api/config/feature-flags 路由无授权检查",
        sink_marker='app.config["FEATURE_FLAGS"].update(data)',
        sink_desc="app.config['FEATURE_FLAGS'].update(data) 修改系统配置无授权检查",
        explanation="line 7 GET 无 @login_required -> line 12 PUT 无授权检查 -> 任意未认证用户可修改功能开关 -> CWE-862 缺少授权（非 IDOR，完全无授权检查）",
        fix_marker='app.config["FEATURE_FLAGS"].update(data)',
        fix_desc="在 PUT 路由上添加 @login_required + @admin_required 装饰器，确保只有管理员可修改配置"))

    # --- 5. Go admin 端点无认证 ---
    code = r'''package main

import (
    "encoding/json"
    "net/http"
)

func main() {
    http.HandleFunc("/api/admin/system/info", func(w http.ResponseWriter, r *http.Request) {
        info := map[string]interface{}{
            "os":         "linux",
            "go_version": "1.21",
            "env":        "production",
        }
        json.NewEncoder(w).Encode(info)
    })

    http.HandleFunc("/api/admin/system/shutdown", func(w http.ResponseWriter, r *http.Request) {
        go func() {
            // graceful shutdown
        }()
        json.NewEncoder(w).Encode(map[string]string{"status": "shutting down"})
    })

    http.ListenAndServe(":8080", nil)
}
'''
    S.append(_spec("go", code,
        "分析过程：\n"
        "1. line 9: /api/admin/system/info 无认证中间件，直接返回系统信息。\n"
        "2. line 18: /api/admin/system/shutdown 无授权检查，任意用户可触发关机。\n"
        "3. 结论：CWE-862 缺少授权检查，风险 Critical。",
        has_vuln=True, vuln_type="CWE-862 Missing Authorization",
        risk="Critical",
        source_marker='"/api/admin/system/info"',
        source_desc="/api/admin/system/info 端点无认证中间件",
        sink_marker='"/api/admin/system/shutdown"',
        sink_desc="/api/admin/system/shutdown 关机操作无授权检查",
        explanation="line 9 /api/admin/system/info 无认证 -> line 18 /api/admin/system/shutdown 无授权 -> 任意未认证用户可获取系统信息或触发关机 -> CWE-862 缺少授权（非 IDOR，完全无授权检查）",
        fix_marker='"/api/admin/system/shutdown"',
        fix_desc="用认证中间件包装 admin 路由，如 http.Handle('/api/admin/system/shutdown', AuthMiddleware(AdminOnly(handler)))"))

    # --- 6. PHP 管理面板无 session 检查 ---
    code = r'''<?php
// admin_panel.php
$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '');

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action'])) {
    if ($_GET['action'] === 'list_users') {
        $stmt = $pdo->query("SELECT id, username, email, role FROM users");
        echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
    } elseif ($_GET['action'] === 'delete_user') {
        $userId = $_GET['user_id'] ?? 0;
        $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        echo json_encode(['status' => 'deleted']);
    } elseif ($_GET['action'] === 'update_config') {
        $key = $_GET['key'] ?? '';
        $value = $_GET['value'] ?? '';
        $stmt = $pdo->prepare("UPDATE config SET value = ? WHERE key = ?");
        $stmt->execute([$value, $key]);
        echo json_encode(['status' => 'updated']);
    }
}
'''
    S.append(_spec("php", code,
        "分析过程：\n"
        "1. line 3: 脚本无 session_start() 或 session 检查。\n"
        "2. line 6-8: list_users 直接查询所有用户，无认证。\n"
        "3. line 10-13: delete_user 直接删除用户，无授权检查。\n"
        "4. line 15-19: update_config 修改系统配置，无授权检查。结论：CWE-862 缺少授权检查，风险 Critical。",
        has_vuln=True, vuln_type="CWE-862 Missing Authorization",
        risk="Critical",
        source_marker="$_GET['action'] === 'list_users'",
        source_desc="$_GET['action'] === 'list_users' 管理操作无 session 检查",
        sink_marker="$stmt->execute([$userId])",
        sink_desc="$stmt->execute([$userId]) 删除用户操作完全缺少授权检查",
        explanation="line 3 无 session_start / 无 session 检查 -> line 6 list_users 无授权 -> line 12 delete_user 无授权 -> CWE-862 缺少授权（非 IDOR，完全无授权检查）",
        fix_marker="$stmt->execute([$userId])",
        fix_desc="在脚本顶部添加 session_start() + if ($_SESSION['role'] !== 'admin') { http_response_code(403); exit; }"))

    # --- 7. Express 用户管理 API 无认证 ---
    code = r'''const express = require('express');
const app = express();
app.use(express.json());

const users = new Map();

app.get('/api/users', (req, res) => {
    const userList = Array.from(users.values()).map(u => ({
        id: u.id, username: u.username, email: u.email,
    }));
    res.json(userList);
});

app.delete('/api/users/:id', (req, res) => {
    const id = parseInt(req.params.id);
    if (users.has(id)) {
        users.delete(id);
        res.json({ status: 'deleted' });
    } else {
        res.status(404).json({ error: 'Not found' });
    }
});

app.listen(3000);
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 8: GET /api/users 无 authMiddleware，任意用户可列出所有用户。\n"
        "2. line 15: DELETE /api/users/:id 同样无授权检查，任意用户可删除他人。\n"
        "3. 两个端点均完全缺少认证和授权检查。\n"
        "4. 结论：CWE-862 缺少授权检查，风险 Critical。",
        has_vuln=True, vuln_type="CWE-862 Missing Authorization",
        risk="Critical",
        source_marker="app.get('/api/users'",
        source_desc="GET /api/users 路由无认证中间件",
        sink_marker="users.delete(id)",
        sink_desc="users.delete(id) 删除用户操作完全缺少授权检查",
        explanation="line 8 GET /api/users 无 authMiddleware -> line 15 DELETE 无授权 -> 任意未认证用户可列出/删除用户 -> CWE-862 缺少授权（非 IDOR，完全无授权检查）",
        fix_marker="app.get('/api/users'",
        fix_desc="在路由上添加 authMiddleware + adminOnlyMiddleware，确保只有管理员可访问用户管理 API"))

    # --- 8. Flask 防御迷惑（部分路由有 @login_required 但漏洞路由没有） ---
    code = r'''from flask import Flask, request, jsonify, session

app = Flask(__name__)


@app.route("/api/profile")
def get_profile():
    if "user_id" not in session:
        return jsonify({"error": "Login required"}), 401
    return jsonify({"user": session.get("username")})


@app.route("/api/admin/export")
def export_data():
    data = collect_all_user_data()
    return jsonify(data)


@app.route("/api/admin/reset-cache")
def reset_cache():
    cache.flush_all()
    return jsonify({"status": "cache cleared"})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 7-9: /api/profile 有 session 检查（有认证，防御迷惑）。\n"
        "2. line 14: /api/admin/export 无 @login_required 或角色检查，直接导出所有用户数据。\n"
        "3. line 20: /api/admin/reset-cache 同样无授权检查。\n"
        "4. 防御迷惑：部分路由有认证但 admin 路由完全没有。结论：CWE-862 缺少授权检查，风险 Critical。",
        has_vuln=True, vuln_type="CWE-862 Missing Authorization",
        risk="Critical",
        source_marker='"/api/admin/export"',
        source_desc="/api/admin/export 路由无授权检查（部分路由有但此路由没有）",
        sink_marker="cache.flush_all()",
        sink_desc="cache.flush_all() 清空缓存操作完全缺少授权检查",
        explanation="line 7 /api/profile 有 session 检查（防御迷惑）-> line 14 /api/admin/export 无授权 -> line 20 reset-cache 无授权 -> CWE-862 缺少授权（非 IDOR，admin 路由完全无授权）",
        fix_marker='"/api/admin/export"',
        fix_desc="在 admin 路由上添加 @login_required + @admin_required 装饰器，确保只有管理员可访问"))

    # --- 9. Java 配置更新无授权 ---
    code = r'''package com.example.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ConfigController {

    private final JdbcTemplate jdbc;

    public ConfigController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @PutMapping("/config/{key}")
    public Map<String, Object> updateConfig(@PathVariable String key,
                                            @RequestBody Map<String, String> body) {
        String value = body.get("value");
        jdbc.update("UPDATE app_config SET value = ? WHERE key_name = ?", value, key);
        return Map.of("status", "updated", "key", key);
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 16: @PutMapping('/config/{key}') 无 @PreAuthorize 或角色检查注解。\n"
        "2. line 19: jdbc.update 直接修改系统配置表，无授权检查。\n"
        "3. 任意未认证用户可修改任意系统配置项。\n"
        "4. 结论：CWE-862 缺少授权检查，风险 Critical。",
        has_vuln=True, vuln_type="CWE-862 Missing Authorization",
        risk="Critical",
        source_marker="@PutMapping(\"/config/{key}\")",
        source_desc="@PutMapping('/config/{key}') 无 @PreAuthorize 授权注解",
        sink_marker="jdbc.update(",
        sink_desc="jdbc.update(...UPDATE app_config...) 修改系统配置无授权检查",
        explanation="line 16 @PutMapping 无 @PreAuthorize -> line 19 jdbc.update 直接改配置 -> 任意未认证用户可修改系统配置 -> CWE-862 缺少授权（非 IDOR，完全无授权检查）",
        fix_marker="jdbc.update(",
        fix_desc="在方法上添加 @PreAuthorize('hasRole(\"ADMIN\")') 注解，确保只有管理员可修改配置"))

    # --- 10. Go 删除用户无认证 ---
    code = r'''package main

import (
    "database/sql"
    "encoding/json"
    "net/http"
    _ "github.com/lib/pq"
)

var db *sql.DB

func DeleteUser(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    _, err := db.Exec("DELETE FROM users WHERE id = $1", id)
    if err != nil {
        http.Error(w, "Failed", 500)
        return
    }
    json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

func main() {
    http.HandleFunc("/api/users/delete", DeleteUser)
    http.ListenAndServe(":8080", nil)
}
'''
    S.append(_spec("go", code,
        "分析过程：\n"
        "1. line 15: /api/users/delete 端点无认证中间件。\n"
        "2. line 11: db.Exec 直接执行 DELETE，无授权检查。\n"
        "3. 任意未认证用户可通过 ?id=N 删除任意用户。\n"
        "4. 结论：CWE-862 缺少授权检查，风险 Critical。",
        has_vuln=True, vuln_type="CWE-862 Missing Authorization",
        risk="Critical",
        source_marker='http.HandleFunc("/api/users/delete"',
        source_desc="/api/users/delete 端点无认证中间件",
        sink_marker="db.Exec(",
        sink_desc="db.Exec(...DELETE FROM users...) 删除用户无授权检查",
        explanation="line 15 /api/users/delete 无认证中间件 -> line 11 db.Exec 直接删除 -> 任意未认证用户可删除任意用户 -> CWE-862 缺少授权（非 IDOR，完全无授权检查）",
        fix_marker="db.Exec(",
        fix_desc="用认证+授权中间件包装路由：http.Handle('/api/users/delete', AuthMiddleware(AdminOnly(http.HandlerFunc(DeleteUser))))"))

    return S


# ===========================================================================
# 第二部分 - 3: CWE-312 Cleartext Storage（5 条）
# ===========================================================================
def gen_cleartext_storage():
    """5 条 CWE-312 明文存储敏感信息样本。"""
    S = []

    # --- 1. Python 密码明文存储到 SQLite ---
    code = r'''import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    email = data.get("email", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
        (username, password, email),
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "registered"}), 201
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 10: password 从用户请求获取明文密码。\n"
        "2. line 16: cursor.execute 将明文 password 直接写入数据库。\n"
        "3. 数据库泄露时所有密码暴露，无哈希、无加盐。\n"
        "4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information",
        risk="High",
        source_marker='password = data.get("password"',
        source_desc="data.get('password') 用户提交的明文密码",
        sink_marker='(username, password, email)',
        sink_desc="cursor.execute(...VALUES (?, ?, ?), (username, password, email)) 明文密码写入数据库",
        explanation="line 10 用户明文密码 -> line 16 INSERT INTO users 直接存储明文 -> 无哈希/无加盐 -> 数据库泄露时密码全部暴露 -> CWE-312 明文存储",
        fix_marker='(username, password, email)',
        fix_desc="使用 bcrypt 或 argon2 对密码做哈希后再存储：hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())"))

    # --- 2. Node.js 密码明文存储到 MongoDB ---
    code = r'''const express = require('express');
const { MongoClient } = require('mongodb');
const app = express();
app.use(express.json());

const client = new MongoClient('mongodb://localhost:27017');

app.post('/api/signup', async (req, res) => {
    const { username, password, email } = req.body;
    const db = client.db('appdb');
    await db.collection('users').insertOne({
        username,
        password,
        email,
        createdAt: new Date(),
    });
    res.json({ status: 'created' });
});

app.listen(3000);
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 10: password 从请求体解构获取明文密码。\n"
        "2. line 13: insertOne 将明文 password 直接存入 MongoDB。\n"
        "3. 无哈希、无加密，数据库泄露时密码全部暴露。\n"
        "4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information",
        risk="High",
        source_marker="const { username, password, email }",
        source_desc="req.body 解构获取明文 password",
        sink_marker="password,",
        sink_desc="insertOne({ username, password, email }) 明文密码写入 MongoDB",
        explanation="line 10 用户明文密码 -> line 13 insertOne 直接存储 -> 无哈希/无加密 -> 数据库泄露时密码全部暴露 -> CWE-312 明文存储",
        fix_marker="password,",
        fix_desc="使用 bcrypt.hash(password, 10) 对密码做哈希后再存储"))

    # --- 3. Java 密码明文存储到 JDBC ---
    code = r'''package com.example.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class UserRegistrationController {

    private final JdbcTemplate jdbc;

    public UserRegistrationController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @PostMapping("/register")
    public Map<String, Object> register(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");
        String email = body.get("email");
        jdbc.update("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                     username, password, email);
        return Map.of("status", "registered");
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 18: password 从请求体获取明文密码。\n"
        "2. line 21: jdbc.update 将明文 password 直接 INSERT 到数据库。\n"
        "3. 无哈希、无加密，数据库泄露时密码全部暴露。\n"
        "4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information",
        risk="High",
        source_marker='String password = body.get("password")',
        source_desc="body.get('password') 用户提交的明文密码",
        sink_marker="jdbc.update(",
        sink_desc="jdbc.update(...INSERT INTO users...password) 明文密码写入数据库",
        explanation="line 18 用户明文密码 -> line 21 jdbc.update 直接存储 -> 无哈希/无加密 -> 数据库泄露时密码全部暴露 -> CWE-312 明文存储",
        fix_marker="jdbc.update(",
        fix_desc="使用 BCryptPasswordEncoder 对密码做哈希：String hashed = encoder.encode(password); 然后存储 hashed"))

    # --- 4. PHP 密码明文存储到 MySQL ---
    code = r'''<?php
$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $email = $_POST['email'] ?? '';

    $stmt = $pdo->prepare("INSERT INTO users (username, password, email) VALUES (?, ?, ?)");
    $stmt->execute([$username, $password, $email]);
    echo json_encode(['status' => 'registered']);
}
'''
    S.append(_spec("php", code,
        "分析过程：\n"
        "1. line 6: $password 从 $_POST 获取明文密码。\n"
        "2. line 10: $stmt->execute([$username, $password, $email]) 将明文密码存入 MySQL。\n"
        "3. 无哈希、无加密，数据库泄露时密码全部暴露。\n"
        "4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information",
        risk="High",
        source_marker="$password = $_POST['password']",
        source_desc="$_POST['password'] 用户提交的明文密码",
        sink_marker="$stmt->execute([$username, $password",
        sink_desc="$stmt->execute([$username, $password, $email]) 明文密码写入 MySQL",
        explanation="line 6 用户明文密码 -> line 10 execute 直接存储 -> 无哈希/无加密 -> 数据库泄露时密码全部暴露 -> CWE-312 明文存储",
        fix_marker="$stmt->execute([$username, $password",
        fix_desc="使用 password_hash($password, PASSWORD_DEFAULT) 对密码做哈希后再存储"))

    # --- 5. Go API Key 明文存储到配置文件（防御迷惑：base64 编码不是加密） ---
    code = r'''package main

import (
    "encoding/base64"
    "encoding/json"
    "os"
    "net/http"
)

type APIKeyEntry struct {
    Service string `json:"service"`
    Key     string `json:"key"`
}

func StoreAPIKey(w http.ResponseWriter, r *http.Request) {
    var entry APIKeyEntry
    json.NewDecoder(r.Body).Decode(&entry)
    encodedKey := base64.StdEncoding.EncodeToString([]byte(entry.Key))
    entry.Key = encodedKey
    data, _ := json.MarshalIndent(entry, "", "  ")
    os.WriteFile("config/api_keys.json", data, 0644)
    json.NewEncoder(w).Encode(map[string]string{"status": "stored"})
}

func main() {
    http.HandleFunc("/api/admin/store-key", StoreAPIKey)
    http.ListenAndServe(":8080", nil)
}
'''
    S.append(_spec("go", code,
        "分析过程：\n"
        "1. line 17: entry.Key 从请求体获取 API Key 明文。\n"
        "2. line 18: base64.StdEncoding.EncodeToString 对 Key 做 base64 编码（非加密）。\n"
        "3. line 20: os.WriteFile 将编码后的 Key 写入配置文件。\n"
        "4. 防御迷惑：base64 是编码不是加密，可轻易解码。结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information",
        risk="High",
        source_marker="json.NewDecoder(r.Body).Decode(&entry)",
        source_desc="r.Body 解码获取 API Key 明文",
        sink_marker="os.WriteFile(",
        sink_desc="os.WriteFile('config/api_keys.json', data, 0644) 将 base64 编码的 Key 写入文件（非加密）",
        explanation="line 17 用户 API Key 明文 -> line 18 base64 编码（防御迷惑：编码非加密）-> line 20 写入配置文件 -> 可 base64 解码还原 -> CWE-312 明文存储",
        fix_marker="os.WriteFile(",
        fix_desc="使用 AES-GCM 加密 API Key 后再存储，密钥从环境变量获取，而非使用 base64 编码"))

    return S


# ===========================================================================
# 第二部分 - 4: IDOR vs Missing Auth 对比配对（5 对 = 10 条）
# ===========================================================================
def gen_contrastive_pairs():
    """5 对 IDOR vs Missing Auth 对比样本。

    每对使用相同语言和相似业务场景：
      - IDOR 版：有认证（@login_required / JWT / session 检查），但缺少资源归属校验
      - Missing Auth 版：完全无认证，任意未登录用户可访问

    通过对比训练模型区分：
      CWE-639 = 有认证但无授权（资源归属未校验）
      CWE-862 = 完全无认证/无授权
    """
    S = []

    # =====================================================================
    # 对比 1: Python Flask 用户资料查询
    # =====================================================================
    # --- 1a. IDOR 版（有 @login_required，无归属校验） ---
    code = r'''from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
db = SQLAlchemy(app)


class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))


def login_required(f):
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


@app.route("/api/profiles/<int:profile_id>")
@login_required
def get_profile(profile_id):
    profile = Profile.query.get(profile_id)
    if not profile:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"phone": profile.phone, "address": profile.address})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 22: @login_required 确保用户已登录（有认证）。\n"
        "2. line 24: Profile.query.get(profile_id) 按参数查询资料，未校验 profile.user_id == session['user_id']。\n"
        "3. 任意已登录用户修改 URL 中 profile_id 即可查看他人资料。\n"
        "4. 关键区分：有认证（login_required）但无授权（归属校验），属于 IDOR 而非 Missing Auth。\n"
        "5. 结论：CWE-639 授权绕过（IDOR），风险 High。",
        has_vuln=True, vuln_type="CWE-639 Authorization Bypass (IDOR)",
        risk="High",
        source_marker="profile_id)",
        source_desc="get_profile(profile_id) 路由参数用户可控",
        sink_marker="Profile.query.get(profile_id)",
        sink_desc="Profile.query.get(profile_id) 按参数查询资料未校验归属",
        explanation="line 22 @login_required 认证通过（有认证）-> line 24 Profile.query.get 查任意资料 -> 未校验 profile.user_id == session['user_id'] -> IDOR 授权绕过（非 Missing Auth，因为有认证）",
        fix_marker="Profile.query.get(profile_id)",
        fix_desc="使用 Profile.query.filter_by(id=profile_id, user_id=session['user_id']).first() 确保只返回当前用户的资料"))

    # --- 1b. Missing Auth 版（无 @login_required，完全无认证） ---
    code = r'''from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
db = SQLAlchemy(app)


class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))


def login_required(f):
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


@app.route("/api/profiles/<int:profile_id>")
def get_profile(profile_id):
    profile = Profile.query.get(profile_id)
    if not profile:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"phone": profile.phone, "address": profile.address})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 22: get_profile 路由无 @login_required 装饰器（与 IDOR 版对比，缺少认证）。\n"
        "2. line 23: Profile.query.get(profile_id) 按参数查询资料，无认证也无授权。\n"
        "3. 任意未登录用户修改 URL 中 profile_id 即可查看任意用户资料。\n"
        "4. 关键区分：完全无认证（无 @login_required），属于 Missing Auth 而非 IDOR。\n"
        "5. 结论：CWE-862 缺少授权检查，风险 Critical。",
        has_vuln=True, vuln_type="CWE-862 Missing Authorization",
        risk="Critical",
        source_marker='"/api/profiles/<int:profile_id>")',
        source_desc="/api/profiles/<profile_id> 路由无 @login_required 认证装饰器",
        sink_marker="Profile.query.get(profile_id)",
        sink_desc="Profile.query.get(profile_id) 查询资料完全缺少认证和授权",
        explanation="line 22 路由无 @login_required（无认证）-> line 23 Profile.query.get 查任意资料 -> 任意未登录用户可访问 -> CWE-862 缺少授权（非 IDOR，因为完全无认证）",
        fix_marker='"/api/profiles/<int:profile_id>")',
        fix_desc="在路由上添加 @login_required 装饰器确保用户已登录，并添加归属校验 profile.user_id == session['user_id']"))

    # =====================================================================
    # 对比 2: Express.js 文档下载
    # =====================================================================
    # --- 2a. IDOR 版（有 JWT 认证，无归属校验） ---
    code = r'''const express = require('express');
const jwt = require('jsonwebtoken');
const { Document } = require('./models');

const app = express();

function authMiddleware(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (e) {
        res.status(401).json({ error: 'Unauthorized' });
    }
}

app.get('/api/documents/:docId/download', authMiddleware, async (req, res) => {
    const doc = await Document.findById(req.params.docId);
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.download(doc.filePath, doc.name);
});

app.listen(3000);
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 8-15: authMiddleware 校验 JWT 确保用户已登录（有认证）。\n"
        "2. line 17: Document.findById(req.params.docId) 按 docId 查询，未校验 doc.ownerId == req.user.id。\n"
        "3. 任意已认证用户修改 docId 即可下载他人文档。\n"
        "4. 关键区分：有认证（authMiddleware）但无授权（归属校验），属于 IDOR。\n"
        "5. 结论：CWE-639 授权绕过（IDOR），风险 High。",
        has_vuln=True, vuln_type="CWE-639 Authorization Bypass (IDOR)",
        risk="High",
        source_marker="req.params.docId",
        source_desc="req.params.docId 路由参数用户可控",
        sink_marker="Document.findById(req.params.docId)",
        sink_desc="Document.findById(req.params.docId) 查询文档未校验归属",
        explanation="line 8 authMiddleware JWT 认证通过（有认证）-> line 17 Document.findById 查任意文档 -> 未校验 doc.ownerId == req.user.id -> IDOR 授权绕过（非 Missing Auth，因为有认证）",
        fix_marker="Document.findById(req.params.docId)",
        fix_desc="使用 Document.findOne({ _id: req.params.docId, ownerId: req.user.id }) 确保只返回当前用户的文档"))

    # --- 2b. Missing Auth 版（无 authMiddleware，完全无认证） ---
    code = r'''const express = require('express');
const jwt = require('jsonwebtoken');
const { Document } = require('./models');

const app = express();

function authMiddleware(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (e) {
        res.status(401).json({ error: 'Unauthorized' });
    }
}

app.get('/api/documents/:docId/download', async (req, res) => {
    const doc = await Document.findById(req.params.docId);
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.download(doc.filePath, doc.name);
});

app.listen(3000);
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 8-15: authMiddleware 定义了但未在 line 17 路由上使用（与 IDOR 版对比，缺少认证中间件）。\n"
        "2. line 17: /api/documents/:docId/download 路由无 authMiddleware，任意未登录用户可访问。\n"
        "3. line 18: Document.findById(req.params.docId) 查询文档，无认证也无授权。\n"
        "4. 关键区分：完全无认证（未挂载 authMiddleware），属于 Missing Auth 而非 IDOR。\n"
        "5. 结论：CWE-862 缺少授权检查，风险 Critical。",
        has_vuln=True, vuln_type="CWE-862 Missing Authorization",
        risk="Critical",
        source_marker="'/api/documents/:docId/download', async",
        source_desc="/api/documents/:docId/download 路由未挂载 authMiddleware 认证中间件",
        sink_marker="Document.findById(req.params.docId)",
        sink_desc="Document.findById(req.params.docId) 查询文档完全缺少认证和授权",
        explanation="line 17 路由未挂载 authMiddleware（无认证）-> line 18 Document.findById 查任意文档 -> 任意未登录用户可下载 -> CWE-862 缺少授权（非 IDOR，因为完全无认证）",
        fix_marker="'/api/documents/:docId/download', async",
        fix_desc="在路由上添加 authMiddleware 中间件确保用户已登录，并校验 doc.ownerId == req.user.id"))

    # =====================================================================
    # 对比 3: Java Spring 订单详情
    # =====================================================================
    # --- 3a. IDOR 版（有 @PreAuthorize isAuthenticated，无归属校验） ---
    code = r'''package com.example.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import com.example.model.Order;
import com.example.repository.OrderRepository;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    private final OrderRepository orderRepository;

    public OrderController(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    @GetMapping("/{orderId}")
    @PreAuthorize("isAuthenticated()")
    public Order getOrder(@PathVariable Long orderId) {
        Order order = orderRepository.findById(orderId).orElse(null);
        if (order == null) {
            throw new RuntimeException("Order not found");
        }
        return order;
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 22: @PreAuthorize('isAuthenticated()') 确保用户已认证（有认证）。\n"
        "2. line 24: orderRepository.findById(orderId) 按参数查询，未校验 order.userId 是否等于当前认证用户 ID。\n"
        "3. 任意已认证用户修改 orderId 即可查看他人订单。\n"
        "4. 关键区分：有认证（@PreAuthorize isAuthenticated）但无授权（归属校验），属于 IDOR。\n"
        "5. 结论：CWE-639 授权绕过（IDOR），风险 High。",
        has_vuln=True, vuln_type="CWE-639 Authorization Bypass (IDOR)",
        risk="High",
        source_marker="@PathVariable Long orderId",
        source_desc="getOrder(@PathVariable Long orderId) 路径参数用户可控",
        sink_marker="orderRepository.findById(orderId)",
        sink_desc="orderRepository.findById(orderId) 查询订单未校验归属",
        explanation="line 22 @PreAuthorize('isAuthenticated()') 认证通过（有认证）-> line 24 findById 查任意订单 -> 未校验 order.userId == 当前用户 -> IDOR 授权绕过（非 Missing Auth，因为有认证）",
        fix_marker="orderRepository.findById(orderId)",
        fix_desc="在查询后校验 order.getUserId().equals(currentUserId)，或使用自定义查询 findByUserIdAndId(currentUserId, orderId)"))

    # --- 3b. Missing Auth 版（无 @PreAuthorize，完全无认证） ---
    code = r'''package com.example.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import com.example.model.Order;
import com.example.repository.OrderRepository;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    private final OrderRepository orderRepository;

    public OrderController(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    @GetMapping("/{orderId}")
    public Order getOrder(@PathVariable Long orderId) {
        Order order = orderRepository.findById(orderId).orElse(null);
        if (order == null) {
            throw new RuntimeException("Order not found");
        }
        return order;
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 22: getOrder 方法无 @PreAuthorize 注解（与 IDOR 版对比，缺少认证）。\n"
        "2. line 23: orderRepository.findById(orderId) 按参数查询，无认证也无授权。\n"
        "3. 任意未认证用户修改 orderId 即可查看任意订单。\n"
        "4. 关键区分：完全无认证（无 @PreAuthorize），属于 Missing Auth 而非 IDOR。\n"
        "5. 结论：CWE-862 缺少授权检查，风险 Critical。",
        has_vuln=True, vuln_type="CWE-862 Missing Authorization",
        risk="Critical",
        source_marker="@GetMapping(\"/{orderId}\")",
        source_desc="@GetMapping('/{orderId}') 方法无 @PreAuthorize 认证注解",
        sink_marker="orderRepository.findById(orderId)",
        sink_desc="orderRepository.findById(orderId) 查询订单完全缺少认证和授权",
        explanation="line 22 getOrder 无 @PreAuthorize（无认证）-> line 23 findById 查任意订单 -> 任意未登录用户可访问 -> CWE-862 缺少授权（非 IDOR，因为完全无认证）",
        fix_marker="@GetMapping(\"/{orderId}\")",
        fix_desc="在方法上添加 @PreAuthorize('isAuthenticated()') 确保用户已登录，并校验 order.getUserId() == 当前用户 ID"))

    # =====================================================================
    # 对比 4: PHP 发票下载
    # =====================================================================
    # --- 4a. IDOR 版（有 session 检查，无归属校验） ---
    code = r'''<?php
session_start();
$pdo = new PDO('mysql:host=localhost;dbname=billing', 'root', '');

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$invoiceId = $_GET['invoice_id'] ?? '';
$stmt = $pdo->prepare("SELECT * FROM invoices WHERE id = ?");
$stmt->execute([$invoiceId]);
$invoice = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$invoice) {
    http_response_code(404);
    echo json_encode(['error' => 'Not found']);
    exit;
}

header('Content-Type: application/pdf');
echo $invoice['pdf_content'];
?>
'''
    S.append(_spec("php", code,
        "分析过程：\n"
        "1. line 4-7: session_start + isset($_SESSION['user_id']) 确保用户已登录（有认证）。\n"
        "2. line 9: $_GET['invoice_id'] 获取用户可控参数。\n"
        "3. line 11: $stmt->execute([$invoiceId]) 查询发票，未校验 invoice.user_id == $_SESSION['user_id']。\n"
        "4. 关键区分：有认证（session 检查）但无授权（归属校验），属于 IDOR。\n"
        "5. 结论：CWE-639 授权绕过（IDOR），风险 High。",
        has_vuln=True, vuln_type="CWE-639 Authorization Bypass (IDOR)",
        risk="High",
        source_marker="$_GET['invoice_id']",
        source_desc="$_GET['invoice_id'] 用户可控参数",
        sink_marker="$stmt->execute([$invoiceId])",
        sink_desc="$stmt->execute([$invoiceId]) 查询发票未校验归属",
        explanation="line 4 isset($_SESSION['user_id']) 认证通过（有认证）-> line 11 execute 查任意发票 -> 未校验 invoice.user_id == $_SESSION['user_id'] -> IDOR 授权绕过（非 Missing Auth，因为有认证）",
        fix_marker="$stmt->execute([$invoiceId])",
        fix_desc="修改 SQL 为 SELECT * FROM invoices WHERE id = ? AND user_id = ?，并传入 $_SESSION['user_id'] 确保只返回当前用户的发票"))

    # --- 4b. Missing Auth 版（无 session 检查，完全无认证） ---
    code = r'''<?php
session_start();
$pdo = new PDO('mysql:host=localhost;dbname=billing', 'root', '');

$invoiceId = $_GET['invoice_id'] ?? '';
$stmt = $pdo->prepare("SELECT * FROM invoices WHERE id = ?");
$stmt->execute([$invoiceId]);
$invoice = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$invoice) {
    http_response_code(404);
    echo json_encode(['error' => 'Not found']);
    exit;
}

header('Content-Type: application/pdf');
echo $invoice['pdf_content'];
?>
'''
    S.append(_spec("php", code,
        "分析过程：\n"
        "1. line 3: session_start 存在但 line 4 未做 isset($_SESSION['user_id']) 检查（与 IDOR 版对比，缺少认证）。\n"
        "2. line 5: $_GET['invoice_id'] 获取用户可控参数，无认证直接查询。\n"
        "3. line 7: $stmt->execute([$invoiceId]) 查询发票，无认证也无授权。\n"
        "4. 关键区分：完全无认证（无 session 检查），属于 Missing Auth 而非 IDOR。\n"
        "5. 结论：CWE-862 缺少授权检查，风险 Critical。",
        has_vuln=True, vuln_type="CWE-862 Missing Authorization",
        risk="Critical",
        source_marker="$invoiceId = $_GET['invoice_id']",
        source_desc="$invoiceId = $_GET['invoice_id'] 无 session 认证直接获取参数",
        sink_marker="$stmt->execute([$invoiceId])",
        sink_desc="$stmt->execute([$invoiceId]) 查询发票完全缺少认证和授权",
        explanation="line 4 无 isset($_SESSION['user_id']) 检查（无认证）-> line 7 execute 查任意发票 -> 任意未登录用户可下载 -> CWE-862 缺少授权（非 IDOR，因为完全无认证）",
        fix_marker="$invoiceId = $_GET['invoice_id']",
        fix_desc="在查询前添加 if (!isset($_SESSION['user_id'])) { http_response_code(401); exit; } 确保用户已登录，并校验 invoice 归属"))

    # =====================================================================
    # 对比 5: Go API Key 查询
    # =====================================================================
    # --- 5a. IDOR 版（有 auth 中间件，无归属校验） ---
    code = r'''package main

import (
    "database/sql"
    "encoding/json"
    "net/http"
    "strings"

    _ "github.com/lib/pq"
)

var db *sql.DB

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        token := r.Header.Get("Authorization")
        if token == "" || !strings.HasPrefix(token, "Bearer ") {
            http.Error(w, `{"error":"Unauthorized"}`, 401)
            return
        }
        // 简化：实际应校验 JWT
        next(w, r)
    }
}

func GetAPIKey(w http.ResponseWriter, r *http.Request) {
    keyID := r.URL.Query().Get("key_id")
    var service, keyValue string
    err := db.QueryRow("SELECT service, key_value FROM api_keys WHERE id = $1", keyID).
        Scan(&service, &keyValue)
    if err != nil {
        http.Error(w, `{"error":"Not found"}`, 404)
        return
    }
    json.NewEncoder(w).Encode(map[string]string{"service": service, "key": keyValue})
}

func main() {
    http.HandleFunc("/api/keys/view", authMiddleware(GetAPIKey))
    http.ListenAndServe(":8080", nil)
}
'''
    S.append(_spec("go", code,
        "分析过程：\n"
        "1. line 14-22: authMiddleware 校验 Bearer token 确保用户已登录（有认证）。\n"
        "2. line 32: authMiddleware(GetAPIKey) 在 main 中挂载认证中间件。\n"
        "3. line 25: r.URL.Query().Get('key_id') 获取用户可控参数。\n"
        "4. line 28: db.QueryRow 查询 API Key，未校验 key.owner_id 是否等于当前用户 ID。\n"
        "5. 关键区分：有认证（authMiddleware）但无授权（归属校验），属于 IDOR。\n"
        "6. 结论：CWE-639 授权绕过（IDOR），风险 High。",
        has_vuln=True, vuln_type="CWE-639 Authorization Bypass (IDOR)",
        risk="High",
        source_marker='keyID := r.URL.Query().Get("key_id")',
        source_desc="r.URL.Query().Get('key_id') 用户可控参数",
        sink_marker="db.QueryRow(",
        sink_desc="db.QueryRow(...WHERE id = $1...) 查询 API Key 未校验归属",
        explanation="line 14 authMiddleware 认证通过（有认证）-> line 28 db.QueryRow 查任意 Key -> 未校验 key.owner_id == 当前用户 -> IDOR 授权绕过（非 Missing Auth，因为有认证）",
        fix_marker="db.QueryRow(",
        fix_desc="修改 SQL 为 SELECT service, key_value FROM api_keys WHERE id = $1 AND owner_id = $2，并传入从 token 解析的当前用户 ID"))

    # --- 5b. Missing Auth 版（无 auth 中间件，完全无认证） ---
    code = r'''package main

import (
    "database/sql"
    "encoding/json"
    "net/http"
    "strings"

    _ "github.com/lib/pq"
)

var db *sql.DB

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        token := r.Header.Get("Authorization")
        if token == "" || !strings.HasPrefix(token, "Bearer ") {
            http.Error(w, `{"error":"Unauthorized"}`, 401)
            return
        }
        // 简化：实际应校验 JWT
        next(w, r)
    }
}

func GetAPIKey(w http.ResponseWriter, r *http.Request) {
    keyID := r.URL.Query().Get("key_id")
    var service, keyValue string
    err := db.QueryRow("SELECT service, key_value FROM api_keys WHERE id = $1", keyID).
        Scan(&service, &keyValue)
    if err != nil {
        http.Error(w, `{"error":"Not found"}`, 404)
        return
    }
    json.NewEncoder(w).Encode(map[string]string{"service": service, "key": keyValue})
}

func main() {
    http.HandleFunc("/api/keys/view", GetAPIKey)
    http.ListenAndServe(":8080", nil)
}
'''
    S.append(_spec("go", code,
        "分析过程：\n"
        "1. line 14-22: authMiddleware 定义了但 line 32 未使用（与 IDOR 版对比，缺少认证中间件）。\n"
        "2. line 32: http.HandleFunc('/api/keys/view', GetAPIKey) 直接挂载处理器，无 authMiddleware 包装。\n"
        "3. line 25: r.URL.Query().Get('key_id') 获取参数，无认证直接查询。\n"
        "4. 关键区分：完全无认证（未挂载 authMiddleware），属于 Missing Auth 而非 IDOR。\n"
        "5. 结论：CWE-862 缺少授权检查，风险 Critical。",
        has_vuln=True, vuln_type="CWE-862 Missing Authorization",
        risk="Critical",
        source_marker='"/api/keys/view", GetAPIKey)',
        source_desc="http.HandleFunc('/api/keys/view', GetAPIKey) 未挂载 authMiddleware 认证中间件",
        sink_marker="db.QueryRow(",
        sink_desc="db.QueryRow(...WHERE id = $1...) 查询 API Key 完全缺少认证和授权",
        explanation="line 32 http.HandleFunc 未用 authMiddleware 包装（无认证）-> line 28 db.QueryRow 查任意 Key -> 任意未登录用户可访问 -> CWE-862 缺少授权（非 IDOR，因为完全无认证）",
        fix_marker='"/api/keys/view", GetAPIKey)',
        fix_desc="将路由注册改为 http.HandleFunc('/api/keys/view', authMiddleware(GetAPIKey)) 确保用户已登录，并校验 key 归属"))

    return S


# ===========================================================================
# 主函数
# ===========================================================================
def main():
    """组合所有生成器，校验样本，写入 JSONL，打印统计。"""
    generators = [
        ("SSTI 长文件", gen_ssti_long),
        ("SSTI from_string 变体", gen_ssti_from_string),
        ("SSTI vs XSS 边界对比", gen_ssti_vs_xss),
        ("CWE-639 IDOR", gen_idor),
        ("CWE-862 Missing Auth", gen_missing_auth),
        ("CWE-312 Cleartext Storage", gen_cleartext_storage),
        ("IDOR vs Missing Auth 对比配对", gen_contrastive_pairs),
    ]

    all_specs = []
    print("=" * 70)
    print("SSTI 隐藏场景 + 授权类 CWE 归属混淆 训练样本生成")
    print("=" * 70)

    for name, gen_func in generators:
        specs = gen_func()
        print(f"  [{name}] 生成 {len(specs)} 条")
        all_specs.extend(specs)

    total = len(all_specs)
    print(f"\n总样本数: {total}")

    # --- 校验所有样本 ---
    print("\n--- 校验样本 ---")
    has_error = False
    for i, spec in enumerate(all_specs, 1):
        errors = validate_spec(spec)
        if errors:
            has_error = True
            print(f"  [FAIL] 样本 #{i}:")
            for err in errors:
                print(f"         - {err}")

    if has_error:
        print("\n[错误] 存在校验失败的样本，请修复后再运行。")
        return 1

    print("  所有样本校验通过。")

    # --- 写入 JSONL ---
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for spec in all_specs:
            record = make_sample(spec["lang"], spec["code"], spec["analysis"], spec["verdict"])
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"\n--- 输出 ---")
    print(f"  文件: {OUTPUT_FILE}")
    print(f"  行数: {total}")

    # --- 统计 ---
    print(f"\n--- 统计 ---")
    lang_counter = Counter(spec["lang"] for spec in all_specs)
    vuln_counter = Counter(
        spec["verdict"]["vulnerability_type"] for spec in all_specs
        if spec["verdict"]["has_vulnerability"]
    )
    risk_counter = Counter(
        spec["verdict"]["risk_level"] for spec in all_specs
        if spec["verdict"]["has_vulnerability"]
    )
    safe_count = sum(1 for spec in all_specs if not spec["verdict"]["has_vulnerability"])
    vuln_count = total - safe_count

    print(f"  漏洞/安全: {vuln_count} 漏洞 + {safe_count} 安全")
    print(f"  语言分布: {dict(sorted(lang_counter.items(), key=lambda x: -x[1]))}")
    print(f"  风险分布: {dict(sorted(risk_counter.items(), key=lambda x: -x[1]))}")
    print(f"  CWE 分布:")
    for cwe, count in sorted(vuln_counter.items(), key=lambda x: -x[1]):
        print(f"    {cwe}: {count}")

    print(f"\n[完成] 已生成 {total} 条样本到 {OUTPUT_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())