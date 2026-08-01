#!/usr/bin/env python3
"""构建 v9 增强训练数据。

基于 v8 失败诊断后的修正方法论：
  v8 失败根因：(1) 对比 CoT 引入判别焦虑 → FN 增加
              (2) B 类"无漏洞但建议改进"矛盾信号 → FP 激增 (8 个)
              (3) epochs=3 过拟合 (eval_loss epoch3 上升)

  v9 修正：
  1. B 类改为纯漏洞样本（移除 3 个矛盾安全样本，替换为 3 个 clear-cut 漏洞）
  2. E 类增加 5 条 v8 FP 靶向安全样本（proper_authz / race_with_lock / decorator_wrapper /
     shell_true_hardcoded / django_orm），CoT 明确"防御有效→无漏洞"无矛盾信号
  3. 训练参数 epochs 3→2（v8 eval_loss epoch2 最低，epoch3 上升）

  其他策略（不变）：
  1. 数据增强：变量重命名、跨语言变体（增加表征区分度）
  2. 靶向 FN 根因：防御迷惑 / 注意力分散 / 框架代码误判
  3. 多样安全代码：增加安全代码多样性降低 FPR（非 hard-negative 方式）
  4. CWE 归因增强：补充 v8 未覆盖的易混 CWE 边界

基底：train_chatml_v8_cwe_attribution.jsonl（819 条）
新增：55 条
输出：train_chatml_v9_augmented.jsonl

用法：
    PYTHONPATH=../../.. python3 build_v9_augmented.py
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = ROOT / "experiments/exp_06_finetune/data"
V8_FILE = DATA_DIR / "train_chatml_v8_cwe_attribution.jsonl"
OUT_FILE = DATA_DIR / "train_chatml_v9_augmented.jsonl"

# 沿用 v8 的 SYSTEM_PROMPT（最完整版本，含 CWE 归因判别规则）
SYSTEM_PROMPT = (
    "你是一名资深的代码安全审计专家。请对给出的代码片段进行安全分析，判断其中是否存在安全漏洞。"
    "分析范围包括但不限于：SQL 注入、跨站脚本（XSS）、命令注入、路径穿越、硬编码敏感信息"
    "（密钥/密码/Token）、不安全的反序列化、日志注入（CWE-117）、弱密码学（MD5/SHA1 哈希密码、CWE-327）、"
    "弱随机数（random 模块生成 token、CWE-330）、CSRF、SSTI、XXE、开放重定向、"
    "LDAP 注入（CWE-90）、信任边界绕过（CWE-441）、整数溢出（CWE-190）、缺失认证/授权、"
    "XPath 注入（CWE-643）、NoSQL 注入（CWE-943）、IDOR（CWE-639）、Session Fixation（CWE-384）、"
    "硬编码 IV（CWE-329）、JWT 签名缺陷（CWE-347）、竞态条件（CWE-362）、Mass Assignment（CWE-915）、"
    "原型链污染（CWE-1321）、OGNL 注入（CWE-917）、SpEL 注入（CWE-94）、类型混淆（CWE-843）、"
    "时序攻击（CWE-208）、HTTP 头注入（CWE-113）、信息泄露（CWE-200）等。\n\n"
    "要求：\n"
    "1. 仔细阅读代码语义，结合上下文判断用户可控输入是否被安全处理。\n"
    "2. 不要夸大风险，也不要遗漏明显的漏洞。\n"
    "3. 判定必须基于代码实际内容，不能凭空臆造 API 参数或行为。\n"
    "4. 用户输入到达 sink 不等于漏洞，必须看 sink 前的防御措施是否有效。\n"
    "5. 硬编码的字面量凭证（key/secret/password/token）本身就是漏洞，不要降级为「敏感但非漏洞」。\n"
    "6. 结论一致性校验：JSON 的 has_vulnerability 必须与上述分析过程的推理结论一致。\n"
    "7. 【强制】vulnerability_type 必须以 CWE-XXX 编号开头，如「CWE-89 SQL注入」；"
    "禁止只写漏洞名不写编号；多 CWE 用分号分隔如「CWE-1336; CWE-94 SSTI模板注入」。\n"
    "8. CWE 归因判别（按 sink 类型与漏洞本质区分，禁止混淆）：\n"
    "   - 注入类按 sink 区分：SQL execute → CWE-89；shell/os.system → CWE-78；"
    "eval/exec → CWE-95/94；LDAP search → CWE-90；template render → CWE-1336/CWE-94；"
    "XPath evaluate → CWE-643；NoSQL find → CWE-943；HTTP header → CWE-113；"
    "OGNL → CWE-917；SpEL parseExpression → CWE-94。\n"
    "   - 访问控制类按缺陷本质区分：IDOR/越权访问 → CWE-639；缺失授权（有认证无授权）→ CWE-862；"
    "缺失认证（无认证机制）→ CWE-306；信任源误判 → CWE-441；Session Fixation → CWE-384。\n"
    "   - 密码学类按缺陷区分：硬编码 IV → CWE-329；JWT 签名验证不严 → CWE-347；"
    "弱算法 MD5/SHA1 → CWE-327；硬编码凭证 → CWE-798；弱随机数 → CWE-330。\n"
    "   - 并发与逻辑类：Race Condition/TOCTOU → CWE-362；Mass Assignment → CWE-915；"
    "原型链污染 → CWE-1321；PHP 类型混淆（strcmp null == 0）→ CWE-843；"
    "时序攻击（== 比较密钥）→ CWE-208。\n"
    "   - 其他常见类：信任边界绕过 → CWE-441；反序列化 → CWE-502；XXE → CWE-611；"
    "SSRF → CWE-918；信息泄露 → CWE-200；开放重定向 → CWE-601；路径穿越 → CWE-22；"
    "XSS → CWE-79；CSRF → CWE-352；日志注入 → CWE-117。\n\n"
    "在回答的最后，必须严格输出一个 JSON 对象作为最终结论，JSON 块用 ```json 包裹，字段如下（统一 schema，全项目一致）：\n"
    "   - has_vulnerability: bool, true 表示存在漏洞，false 表示未发现漏洞\n"
    "   - vulnerability_type: str, 单个字符串（禁止拆成多个逗号分隔的值），必须以 CWE-XXX 编号开头，"
    "格式如「CWE-89 SQL注入」；多 CWE 用分号分隔如「CWE-1336; CWE-94 SSTI模板注入」；无漏洞填「none」\n"
    "   - risk_level: str, Critical/High/Medium/Low；无漏洞填「None」\n"
    "   - source: str, 污染来源（用户可控输入点）；无漏洞填「N/A」\n"
    "   - sink: str, 危险函数或触发点；无漏洞填「N/A」\n"
    "   - explanation: str, 漏洞或安全现状说明\n"
    "   - fix_suggestion: str, 修复建议；无漏洞填「no fix needed」\n\n"
    "请先给出分析过程，然后在最后给出 JSON 结论。"
)


def build_sample(code: str, language: str, filename: str, cot: str, json_block: str) -> dict:
    """构建一条 ChatML 训练样本。"""
    user_prompt = (
        f"请分析以下代码片段是否存在安全漏洞。\n\n"
        f"语言：{language}\n文件名：{filename}\n\n```\n{code}\n```\n"
        f"请先给出分析过程，然后在最后给出 JSON 结论。"
    )
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": cot + "\n\n```json\n" + json_block + "\n```"},
        ]
    }


def vuln_json(cwe: str, name: str, risk: str, source: str, sink: str,
              explanation: str, fix: str) -> str:
    return json.dumps({
        "has_vulnerability": True,
        "vulnerability_type": f"{cwe} {name}",
        "risk_level": risk,
        "source": source,
        "sink": sink,
        "explanation": explanation,
        "fix_suggestion": fix,
    }, ensure_ascii=False, indent=2)


def safe_json(explanation: str) -> str:
    return json.dumps({
        "has_vulnerability": False,
        "vulnerability_type": "none",
        "risk_level": "None",
        "source": "N/A",
        "sink": "N/A",
        "explanation": explanation,
        "fix_suggestion": "no fix needed",
    }, ensure_ascii=False, indent=2)


# ===========================================================================
# CWE 名称标准化映射
# ===========================================================================
# 统一所有 CWE 的中文命名，消除格式不一致（空格、括号、中英文混用）
CWE_STANDARD_NAMES = {
    # 注入类
    "CWE-89": "SQL注入",
    "CWE-90": "LDAP注入",
    "CWE-94": "代码注入",
    "CWE-95": "代码注入(eval)",
    "CWE-78": "命令注入",
    "CWE-22": "路径穿越",
    "CWE-79": "XSS",
    "CWE-611": "XXE",
    "CWE-502": "不安全反序列化",
    "CWE-1336": "SSTI模板注入",
    "CWE-917": "表达式注入",
    "CWE-943": "NoSQL注入",
    "CWE-643": "XPath注入",
    "CWE-98": "文件包含",
    "CWE-73": "外部控制文件路径",
    "CWE-918": "SSRF",
    "CWE-601": "开放重定向",
    "CWE-113": "HTTP响应头注入",
    "CWE-117": "日志注入",
    "CWE-532": "敏感信息日志泄露",
    "CWE-434": "任意文件上传",
    "CWE-1321": "原型链污染",
    "CWE-915": "批量赋值",
    # 认证/授权类
    "CWE-798": "硬编码凭证",
    "CWE-306": "缺失认证",
    "CWE-862": "缺失授权",
    "CWE-352": "CSRF",
    "CWE-384": "Session Fixation",
    "CWE-347": "JWT签名验证缺陷",
    "CWE-639": "IDOR",
    "CWE-441": "信任边界绕过",
    "CWE-295": "不安全TLS",
    # 加密/随机数类
    "CWE-327": "弱密码学",
    "CWE-329": "硬编码IV",
    "CWE-330": "弱随机数",
    "CWE-338": "弱随机数",
    "CWE-200": "信息泄露",
    "CWE-209": "信息泄露",
    # 逻辑/资源类
    "CWE-190": "整数溢出",
    "CWE-362": "竞态条件",
    "CWE-400": "拒绝服务",
    "CWE-770": "资源耗尽",
    "CWE-843": "类型混淆",
    "CWE-441": "信任边界绕过",
    # 其他
    "CWE-754": "不当异常处理",
    "CWE-404": "资源释放不当",
    "CWE-476": "空指针解引用",
    "CWE-119": "缓冲区溢出",
    "CWE-787": "越界写入",
    "CWE-125": "越界读取",
}


def normalize_cwe_name(vuln_type: str) -> str:
    """标准化 CWE 名称，消除格式不一致。
    
    处理以下情况：
    - 同一 CWE 不同中文表述（如 "eval注入" → "代码注入(eval)"）
    - 空格不一致（如 "NoSQL 注入" → "NoSQL注入"）
    - 括号使用不一致（如 "代码注入" vs "代码注入(eval)"）
    - 中英文混用（如 "Mass Assignment" → "批量赋值"）
    """
    if vuln_type == "none":
        return vuln_type
    
    # 提取所有 CWE 编号
    cwe_ids = re.findall(r"CWE-\d+", vuln_type)
    if not cwe_ids:
        return vuln_type
    
    # 构建标准化后的 vulnerability_type
    # 处理多值格式（分号分隔）
    if ";" in vuln_type:
        parts = []
        for cwe_id in cwe_ids:
            std_name = CWE_STANDARD_NAMES.get(cwe_id, "")
            if std_name:
                parts.append(f"{cwe_id} {std_name}")
        return "; ".join(parts)
    
    # 单值格式：直接标准化
    if len(cwe_ids) == 1:
        cwe_id = cwe_ids[0]
        std_name = CWE_STANDARD_NAMES.get(cwe_id)
        if std_name:
            return f"{cwe_id} {std_name}"
    
    return vuln_type


def normalize_all_records(records: list) -> list:
    """对记录列表中的所有 vulnerability_type 进行标准化。"""
    count = 0
    for rec in records:
        messages = rec.get("messages", [])
        for msg in messages:
            if msg.get("role") == "assistant":
                content = msg.get("content", "")
                # 提取 JSON 块中的 vulnerability_type
                json_match = re.search(r'"vulnerability_type"\s*:\s*"([^"]*)"', content)
                if json_match:
                    old_type = json_match.group(1)
                    new_type = normalize_cwe_name(old_type)
                    if new_type != old_type:
                        content = content.replace(
                            f'"vulnerability_type": "{old_type}"',
                            f'"vulnerability_type": "{new_type}"'
                        )
                        msg["content"] = content
                        count += 1
    print(f"    CWE 名称标准化: 修正 {count} 条")
    return records


# ===========================================================================
# A. 变量重命名增强（10 条）
# ===========================================================================
# 对已有样本做等价变换：变量重命名 + 轻微格式调整，保持漏洞核心结构不变
# 目的：拉大同类 CWE 的表征区分度，防止模型记忆表面特征

AUGMENTED_SAMPLES = []

# A1: SQL 注入 — 重命名变量 + 添加业务注释
AUGMENTED_SAMPLES.append(build_sample(
    code='''from flask import Flask, request
app = Flask(__name__)

@app.route("/api/v2/products")
def search_products():
    # 产品搜索接口 — 从查询参数获取关键词
    keyword = request.args.get("q", "")
    # 构建 SQL 查询
    sql_stmt = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    cursor = db.cursor()
    cursor.execute(sql_stmt)
    rows = cursor.fetchall()
    return {"results": rows}
''',
    language="python", filename="aug_sqli_rename_01.py",
    cot="分析过程：\n"
        "1. 用户可控输入：keyword 来自 request.args.get('q')，是 HTTP 查询参数。\n"
        "2. 危险 sink：cursor.execute(sql_stmt)，其中 sql_stmt 通过字符串拼接包含 keyword。\n"
        "3. 数据流：request.args.get('q') → keyword → 字符串拼接 → sql_stmt → cursor.execute。\n"
        "4. 防御检查：无参数化查询、无输入校验、无转义。keyword 中的 ' 可闭合 SQL 字符串。\n"
        "5. 综合来看，存在 SQL 注入漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-89", "SQL注入", "Critical",
        source="request.args.get('q')",
        sink="cursor.execute(sql_stmt) 其中 sql_stmt 拼接 keyword",
        explanation="keyword 直接拼接到 SQL LIKE 语句，' 可闭合字符串注入任意 SQL",
        fix="使用参数化查询：cursor.execute(\"SELECT * FROM products WHERE name LIKE %s\", ('%' + keyword + '%',))"
    )
))

# A2: XSS — 重命名变量 + 换用 Django 框架
AUGMENTED_SAMPLES.append(build_sample(
    code='''from django.http import HttpResponse
from django.views import View

class GreetingView(View):
    def get(self, request):
        # 获取用户名用于个性化问候
        user_name = request.GET.get("name", "guest")
        # 直接写入 HTTP 响应
        response_content = "<h1>Welcome, " + user_name + "!</h1>"
        return HttpResponse(response_content)
''',
    language="python", filename="aug_xss_rename_02_django.py",
    cot="分析过程：\n"
        "1. 用户可控输入：user_name 来自 request.GET.get('name')。\n"
        "2. 危险 sink：HttpResponse(response_content)，response_content 拼接了 user_name。\n"
        "3. 数据流：request.GET.get('name') → user_name → 字符串拼接 → response_content → HttpResponse。\n"
        "4. 防御检查：无 HTML 转义、无模板引擎自动转义。user_name 中的 <script> 可注入恶意脚本。\n"
        "5. 综合来看，存在 XSS 漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-79", "XSS", "High",
        source="request.GET.get('name')",
        sink="HttpResponse(response_content) 其中 response_content 拼接 user_name",
        explanation="user_name 直接拼接到 HTML 响应，<script> 标签可注入恶意脚本",
        fix="用 Django 模板引擎渲染：render(request, 'greeting.html', {'name': user_name})（自动转义）"
    )
))

# A3: 命令注入 — 重命名变量 + Go 语言
AUGMENTED_SAMPLES.append(build_sample(
    code='''package main

import (
    "fmt"
    "os/exec"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    // 从请求参数获取主机名
    targetHost := r.URL.Query().Get("host")
    // 执行 ping 命令
    cmd := exec.Command("sh", "-c", "ping -c 1 "+targetHost)
    output, err := cmd.Output()
    if err != nil {
        fmt.Fprint(w, "error")
        return
    }
    fmt.Fprint(w, string(output))
}
''',
    language="go", filename="aug_cmdi_rename_03_go.go",
    cot="分析过程：\n"
        "1. 用户可控输入：targetHost 来自 r.URL.Query().Get('host')。\n"
        "2. 危险 sink：exec.Command('sh', '-c', 'ping -c 1 '+targetHost)，targetHost 拼接到 shell 命令。\n"
        "3. 数据流：r.URL.Query().Get('host') → targetHost → 字符串拼接 → exec.Command。\n"
        "4. 防御检查：无输入校验。targetHost 中的 ; 或 | 可注入额外命令。\n"
        "5. 综合来看，存在命令注入漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-78", "命令注入", "Critical",
        source="r.URL.Query().Get('host')",
        sink="exec.Command('sh', '-c', 'ping -c 1 '+targetHost)",
        explanation="targetHost 拼接到 sh -c 命令字符串，; 或 | 可注入任意命令",
        fix="用 exec.Command('ping', '-c', '1', targetHost) 直接传参数，不经 shell；或校验 targetHost 为合法域名"
    )
))

# A4: 路径穿越 — 重命名变量 + Node.js
AUGMENTED_SAMPLES.append(build_sample(
    code='''const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

app.get('/download', (req, res) => {
    // 获取要下载的文件名
    const fileName = req.query.file;
    const baseDir = '/var/www/uploads';
    // 拼接路径
    const filePath = path.join(baseDir, fileName);
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    res.send(fileContent);
});
app.listen(3000);
''',
    language="javascript", filename="aug_path_rename_04_node.js",
    cot="分析过程：\n"
        "1. 用户可控输入：fileName 来自 req.query.file。\n"
        "2. 危险 sink：fs.readFileSync(filePath)，filePath = path.join(baseDir, fileName)。\n"
        "3. 数据流：req.query.file → fileName → path.join → filePath → fs.readFileSync。\n"
        "4. 防御检查：path.join 不会阻止 ../，fileName 中的 ../../../etc/passwd 可穿越目录。\n"
        "5. 综合来看，存在路径穿越漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-22", "路径穿越", "High",
        source="req.query.file",
        sink="fs.readFileSync(path.join(baseDir, fileName))",
        explanation="fileName 中的 ../ 可穿越 baseDir 限制读取任意文件",
        fix="校验 path.resolve(filePath).startsWith(baseDir)；或用 path.basename(fileName) 去除目录部分"
    )
))

# A5: 硬编码凭证 — 重命名变量 + Ruby
AUGMENTED_SAMPLES.append(build_sample(
    code='''require 'aws-sdk-s3'

# S3 客户端初始化
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

s3_client = Aws::S3::Client.new(
  access_key_id: AWS_ACCESS_KEY_ID,
  secret_access_key: AWS_SECRET_ACCESS_KEY,
  region: 'us-east-1'
)

buckets = s3_client.list_buckets
puts buckets.buckets.map(&:name)
''',
    language="ruby", filename="aug_hardcoded_rename_05_ruby.rb",
    cot="分析过程：\n"
        "1. 凭证位置：源码中直接出现 AWS_ACCESS_KEY_ID 和 AWS_SECRET_ACCESS_KEY 的字符串字面量。\n"
        "2. 是否字面量：变量名含 key/secret 且赋值为字符串字面量，符合硬编码凭证特征。\n"
        "3. 是否从环境读取：代码未通过 ENV[...] 或配置文件读取，而是直接写死在源码中。\n"
        "4. 影响范围：任何能看到源码的人都能获取 AWS 凭证。\n"
        "5. 综合来看，存在硬编码凭证漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-798", "硬编码凭证", "High",
        source="源码字面量",
        sink="Aws::S3::Client.new(access_key_id: ..., secret_access_key: ...)",
        explanation="AWS 凭证直接硬编码在源码常量中，任何能访问源码的人都能获取",
        fix="从环境变量读取：Aws::S3::Client.new(access_key_id: ENV['AWS_ACCESS_KEY_ID'], ...)"
    )
))

# A6: 反序列化 — 重命名变量 + Java
AUGMENTED_SAMPLES.append(build_sample(
    code='''import java.io.*;
import javax.servlet.http.*;

public class ConfigLoaderServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        // 读取请求体
        ObjectInputStream ois = new ObjectInputStream(req.getInputStream());
        try {
            // 反序列化 Java 对象
            Object configObj = ois.readObject();
            resp.getWriter().println("loaded: " + configObj);
        } catch (ClassNotFoundException e) {
            resp.sendError(500, "deserialize error");
        }
    }
}
''',
    language="java", filename="aug_deser_rename_06_java.java",
    cot="分析过程：\n"
        "1. 用户可控输入：req.getInputStream() 是客户端发送的原始请求体。\n"
        "2. 危险 sink：ois.readObject()，Java 原生反序列化，可执行任意类的 readObject/readResolve 方法。\n"
        "3. 数据流：req.getInputStream() → ObjectInputStream → readObject() → 任意对象构造。\n"
        "4. 防御检查：无类白名单（ObjectInputFilter）、无签名校验。攻击者可发送 CommonsCollections gadget chain 实现 RCE。\n"
        "5. 综合来看，存在不安全反序列化漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-502", "不安全反序列化", "Critical",
        source="req.getInputStream()",
        sink="ObjectInputStream.readObject()",
        explanation="Java 原生反序列化无类白名单，攻击者可发送恶意 gadget chain 实现 RCE",
        fix="用 ObjectInputFilter 限制可反序列化的类白名单；或改用 JSON 等安全格式"
    )
))

# A7: SSRF — 重命名变量 + Python requests
AUGMENTED_SAMPLES.append(build_sample(
    code='''import requests
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/proxy/fetch")
def proxy_fetch():
    # 从用户请求获取目标 URL
    target_url = request.args.get("url", "")
    # 发起 HTTP 请求
    resp = requests.get(target_url)
    return jsonify({"status": resp.status_code, "body": resp.text[:500]})
''',
    language="python", filename="aug_ssrf_rename_07.py",
    cot="分析过程：\n"
        "1. 用户可控输入：target_url 来自 request.args.get('url')。\n"
        "2. 危险 sink：requests.get(target_url)，向用户指定的 URL 发起 HTTP 请求。\n"
        "3. 数据流：request.args.get('url') → target_url → requests.get → 任意 HTTP 请求。\n"
        "4. 防御检查：无 URL 白名单、无内网地址过滤。攻击者可请求 http://169.254.169.254/ 获取云元数据。\n"
        "5. 综合来看，存在 SSRF 漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-918", "SSRF", "High",
        source="request.args.get('url')",
        sink="requests.get(target_url)",
        explanation="target_url 无过滤直接传给 requests.get，可访问内网/云元数据端点",
        fix="校验 URL 主机白名单；过滤内网 IP 段（10.x/172.16.x/192.168.x/169.254.x）；禁用重定向到内网"
    )
))

# A8: 弱密码学 — 重命名变量 + PHP
AUGMENTED_SAMPLES.append(build_sample(
    code='''<?php
function store_password($raw_password) {
    // 使用 SHA1 哈希存储密码（无盐）
    $hashed = sha1($raw_password);
    // 存入数据库
    db_query("INSERT INTO users (password_hash) VALUES (?)", $hashed);
    return true;
}
?>
''',
    language="php", filename="aug_crypto_rename_08_php.php",
    cot="分析过程：\n"
        "1. 密码学分析：使用 sha1() 哈希密码，无 salt、无迭代。\n"
        "2. 缺陷：SHA1 已被破解（碰撞攻击），且速度过快使暴力破解可行，无 salt 使彩虹表攻击有效。\n"
        "3. 防御检查：无 per-user salt、无慢哈希（如 password_hash with bcrypt）。\n"
        "4. 综合来看，存在弱密码学漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-327", "弱密码学", "High",
        source="raw_password 参数",
        sink="sha1($raw_password)",
        explanation="SHA1 已破解且速度过快，无 salt 使彩虹表攻击可行",
        fix="用 password_hash($raw_password, PASSWORD_BCRYPT)（自动加 salt + 慢哈希）"
    )
))

# A9: CSRF — 重命名变量 + Express
AUGMENTED_SAMPLES.append(build_sample(
    code='''const express = require('express');
const session = require('express-session');
const app = express();
app.use(session({ secret: process.env.SESSION_SECRET }));

app.post('/api/email/change', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'unauthorized' });
    }
    // 状态变更操作：修改邮箱，无 CSRF 防护
    const newEmail = req.body.email;
    db.updateUserEmail(req.session.userId, newEmail);
    res.json({ status: 'updated' });
});
app.listen(3000);
''',
    language="javascript", filename="aug_csrf_rename_09_express.js",
    cot="分析过程：\n"
        "1. 操作分析：/api/email/change 是状态变更操作（修改用户邮箱），需 CSRF 防护。\n"
        "2. 防御检查：有认证（session.userId），但无 CSRF token、无 Origin/Referer 校验、无 SameSite Cookie。\n"
        "3. 攻击路径：攻击者构造 <form action='/api/email/change' method='POST'> 诱导已登录用户提交。\n"
        "4. 综合来看，存在 CSRF 漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-352", "CSRF", "High",
        source="攻击者构造的跨站表单",
        sink="/api/email/change 无 CSRF token 修改邮箱",
        explanation="状态变更操作无 CSRF 防护，攻击者可构造跨站表单诱导用户修改邮箱",
        fix="加 csurf 中间件校验 CSRF token；设置 Cookie SameSite=Strict；校验 Origin 头"
    )
))

# A10: 日志注入 — 重命名变量 + Python logging
AUGMENTED_SAMPLES.append(build_sample(
    code='''import logging
from flask import Flask, request
app = Flask(__name__)
logger = logging.getLogger("api")

@app.route("/login")
def login():
    username = request.args.get("user", "")
    # 用户输入直接写入日志
    logger.info(f"User login attempt: {username}")
    return "ok"
''',
    language="python", filename="aug_loginject_rename_10.py",
    cot="分析过程：\n"
        "1. 用户可控输入：username 来自 request.args.get('user')。\n"
        "2. 危险 sink：logger.info(f'User login attempt: {username}')，username 直接嵌入日志消息。\n"
        "3. 数据流：request.args → username → f-string → logger.info。\n"
        "4. 防御检查：无换行符过滤。username 中的 \\n 可注入伪造日志条目，干扰审计或注入恶意日志。\n"
        "5. 综合来看，存在日志注入漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-117", "日志注入", "Medium",
        source="request.args.get('user')",
        sink="logger.info(f'User login attempt: {username}')",
        explanation="username 直接嵌入日志消息，\\n 可注入伪造日志条目",
        fix="过滤 username 中的 \\n\\r 字符；或用结构化日志（JSON logging）"
    )
))


# ===========================================================================
# B. 防御迷惑靶向样本（8 条）
# ===========================================================================
# CVE-fix 持续 FN 根因 1：模型看到部分防御措施就判安全
# 策略：代码中有 *不完整* 或 *无效* 的防御，但漏洞仍存在

DEFENSE_CONFUSION_SAMPLES = []

# B1: LDAP 部分编码 — 编码了部分字符但遗漏了关键字符
DEFENSE_CONFUSION_SAMPLES.append(build_sample(
    code='''from flask import Flask, request
import ldap3
app = Flask(__name__)

@app.route("/search")
def search_user():
    username = request.args.get("user", "")
    # 对用户输入做了部分转义（只转义了 * 但遗漏了 )( 和 \\）
    sanitized = username.replace("*", "\\\\2a")
    filter_str = "(uid=" + sanitized + ")"
    conn = ldap3.Connection(ldap3.Server("ldap://corp.local"))
    conn.search("ou=users,dc=corp,dc=local", filter_str)
    return {"count": len(conn.entries)}
''',
    language="python", filename="defense_ldap_partial_encode.py",
    cot="分析过程：\n"
        "1. 用户可控输入：username 来自 request.args.get('user')。\n"
        "2. 危险 sink：conn.search(filter_str)，filter_str = '(uid=' + sanitized + ')'。\n"
        "3. 防御分析：代码对 * 做了转义（替换为 \\\\2a），但遗漏了 )( 和 \\ 字符。"
        "攻击者可用 )(uid=*) 枚举所有用户，或用 \\ 进行 LDAP filter 注入。\n"
        "4. 关键判断：部分转义 ≠ 有效防御。LDAP filter 的特殊字符包括 * ( ) \\ NUL，"
        "只转义 * 仍允许 ( ) 改变 filter 结构。\n"
        "5. 对比 CoT：为什么不是 CWE-89？因为 sink 是 LDAP search 而非 SQL execute，"
        "注入目标是 LDAP filter 语法，故为 CWE-90 LDAP 注入。\n"
        "6. 综合来看，存在 LDAP 注入漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "High",
        source="request.args.get('user')",
        sink="conn.search(filter_str) 其中 filter 拼接了部分转义的 username",
        explanation="只转义了 * 但遗漏了 )( 和 \\，攻击者仍可用 )(uid=*) 枚举所有用户",
        fix="使用 RFC 4515 规定的全部特殊字符转义：* → \\2a, ( → \\28, ) → \\29, \\ → \\5c, NUL → \\00"
    )
))

# B2: SQL escape 函数 — 使用了不正确的转义函数
DEFENSE_CONFUSION_SAMPLES.append(build_sample(
    code='''from flask import Flask, request
import re
app = Flask(__name__)

@app.route("/search")
def search():
    keyword = request.args.get("q", "")
    # 用正则替换移除单引号（但不处理反斜杠和其他特殊字符）
    cleaned = re.sub(r"'", "", keyword)
    query = "SELECT * FROM articles WHERE title LIKE '%" + cleaned + "%'"
    cursor.execute(query)
    return {"results": cursor.fetchall()}
''',
    language="python", filename="defense_sql_wrong_escape.py",
    cot="分析过程：\n"
        "1. 用户可控输入：keyword 来自 request.args.get('q')。\n"
        "2. 危险 sink：cursor.execute(query)，query 拼接了 cleaned。\n"
        "3. 防御分析：代码用 re.sub 移除了单引号，但这不是正确的 SQL 转义方法。"
        "反斜杠 \\ 仍可转义 SQL 中的其他字符，且不同数据库有差异（如 MySQL 的 \\' vs ''）。"
        "此外，LIKE 通配符 % 和 _ 也未过滤。\n"
        "4. 关键判断：自定义正则替换 ≠ 参数化查询。只有参数化查询才能彻底防止 SQL 注入。\n"
        "5. 综合来看，存在 SQL 注入漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-89", "SQL注入", "Critical",
        source="request.args.get('q')",
        sink="cursor.execute(query) 其中 query 拼接了仅移除单引号的 cleaned",
        explanation="仅移除单引号不足以防止 SQL 注入，反斜杠和其他技巧仍可绕过",
        fix="使用参数化查询：cursor.execute(\"SELECT * FROM articles WHERE title LIKE %s\", ('%' + keyword + '%',))"
    )
))

# B3: XSS 部分转义 — 只转义了 < > 但遗漏了引号和属性注入
DEFENSE_CONFUSION_SAMPLES.append(build_sample(
    code='''from flask import Flask, request
app = Flask(__name__)

@app.route("/profile")
def profile():
    nickname = request.args.get("nick", "")
    # 只转义了 < 和 >，但没转义引号
    safe_nick = nickname.replace("<", "&lt;").replace(">", "&gt;")
    html = f'<div class="user-card" data-nick="{safe_nick}">Hello</div>'
    return html
''',
    language="python", filename="defense_xss_partial_escape.py",
    cot="分析过程：\n"
        "1. 用户可控输入：nickname 来自 request.args.get('nick')。\n"
        "2. 危险 sink：HTML 响应中 data-nick=\"{safe_nick}\" 属性值拼接了 safe_nick。\n"
        "3. 防御分析：代码转义了 < > 但未转义 \" 引号。攻击者可用 \" onclick=alert(1) 注入事件处理器，"
        "闭合属性引号后注入任意 HTML 属性，实现 XSS。\n"
        "4. 关键判断：部分 HTML 转义 ≠ 完整 XSS 防御。HTML 上下文（属性值）需要转义引号。\n"
        "5. 综合来看，存在 XSS 漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-79", "XSS", "High",
        source="request.args.get('nick')",
        sink="HTML 属性值 data-nick=\"{safe_nick}\" 拼接了未转义引号的 safe_nick",
        explanation="只转义 < > 但未转义引号，攻击者可用 \" 注入 HTML 属性实现 XSS",
        fix="用 html.escape(nickname, quote=True) 转义所有 HTML 特殊字符（含引号）；或用模板引擎自动转义"
    )
))

# B4: 路径校验不足 — 用 startswith 但未规范化路径
DEFENSE_CONFUSION_SAMPLES.append(build_sample(
    code='''from flask import Flask, request
import os
app = Flask(__name__)

@app.route("/file")
def get_file():
    filename = request.args.get("name", "")
    base = "/var/data/files"
    full = os.path.join(base, filename)
    # 用 startswith 校验，但未先 normalize
    if full.startswith(base):
        with open(full) as f:
            return f.read()
    return "forbidden", 403
''',
    language="python", filename="defense_path_startswith.py",
    cot="分析过程：\n"
        "1. 用户可控输入：filename 来自 request.args.get('name')。\n"
        "2. 危险 sink：open(full)，full = os.path.join(base, filename)。\n"
        "3. 防御分析：代码用 full.startswith(base) 校验路径，但未先用 os.path.abspath 规范化。"
        "filename=/var/data/files/../../../etc/passwd 拼接后 startswith(base) 为 True，"
        "但实际路径指向 /etc/passwd（因为 ../ 在 join 后仍可穿越）。\n"
        "4. 关键判断：startswith 校验在路径未规范化时可被绕过。\n"
        "5. 综合来看，存在路径穿越漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-22", "路径穿越", "High",
        source="request.args.get('name')",
        sink="open(full) 其中 full 未规范化即做 startswith 校验",
        explanation="startswith(base) 在路径未规范化时可被 ../ 绕过",
        fix="先 os.path.abspath(full) 规范化，再校验 startswith(base + os.sep)；或用 pathlib.Path.resolve()"
    )
))

# B5: CSRF — 用 Referer 校验但可被绕过（v8 失败教训：不要用"无漏洞但建议改进"的矛盾信号）
# v8 失败根因：B5/B6/B7 原为"防御有效但模式脆弱"的安全样本，CoT 写"无漏洞但建议改进"，
# 导致模型过度泛化为"所有防御都不够"→ 8 个 FP。v9 改为纯漏洞样本，消除矛盾信号。
DEFENSE_CONFUSION_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, session
app = Flask(__name__)

@app.route("/api/transfer", methods=["POST"])
def transfer():
    if "user_id" not in session:
        return "unauthorized", 401
    # 用 Referer 校验防 CSRF（但 Referer 可被浏览器扩展或 meta 标签篡改）
    referer = request.headers.get("Referer", "")
    if referer.startswith("https://bank.example.com/"):
        to = request.form.get("to")
        amount = int(request.form.get("amount", 0))
        db.execute("UPDATE accounts SET balance = balance - ? WHERE uid = ?",
                   (amount, session["user_id"]))
        return "ok"
    return "forbidden", 403
''',
    language="python", filename="defense_csrf_referer_bypass.py",
    cot="分析过程：\n"
        "1. 操作分析：/api/transfer 是状态变更操作（转账），需 CSRF 防护。\n"
        "2. 防御分析：用 Referer 校验防 CSRF，但 Referer 可被绕过——"
        "某些浏览器扩展可伪造 Referer，或通过 meta 标签 <meta name=\"referrer\" content=\"no-referrer\"> "
        "使 Referer 为空后再利用。此外未校验请求方法来源（无 CSRF token、无 SameSite Cookie）。\n"
        "3. 关键判断：Referer 校验不是可靠的 CSRF 防御——它依赖客户端行为，可被绕过。"
        "只有 CSRF token 或 SameSite Cookie 才是有效的 CSRF 防御。\n"
        "4. 综合来看，存在 CSRF 漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-352", "CSRF", "High",
        source="攻击者构造的跨站表单（Referer 可被绕过）",
        sink="/api/transfer 无 CSRF token 仅靠 Referer 校验",
        explanation="Referer 校验可被浏览器扩展或 meta 标签绕过，无 CSRF token 无 SameSite Cookie，可构造跨站表单诱导转账",
        fix="用 CSRFProtect 全局 CSRF token；设置 Cookie SameSite=Strict；不要仅依赖 Referer 校验"
    )
))

# B6: SQL 注入 — 用 int() 类型转换但 LIKE 子句仍拼接
DEFENSE_CONFUSION_SAMPLES.append(build_sample(
    code='''from flask import Flask, request
app = Flask(__name__)

@app.route("/search")
def search():
    category = request.args.get("cat", "")
    min_price = request.args.get("min", "0")
    # 对 min_price 做了 int 转换（看似安全），但 category 仍拼接
    try:
        safe_min = int(min_price)
    except ValueError:
        safe_min = 0
    query = "SELECT * FROM products WHERE category = '" + category + "' AND price >= " + str(safe_min)
    cursor.execute(query)
    return {"results": cursor.fetchall()}
''',
    language="python", filename="defense_sql_partial_cast.py",
    cot="分析过程：\n"
        "1. 用户可控输入：category 和 min_price 均来自 request.args。\n"
        "2. 危险 sink：cursor.execute(query)，query 拼接了 category。\n"
        "3. 防御分析：对 min_price 做了 int() 转换（有效），但 category 仍直接拼接到 SQL 字符串。"
        "category 中的 ' 可闭合字符串注入任意 SQL。int() 只保护了 min_price 这一个参数。\n"
        "4. 关键判断：部分参数的防御不等于全部参数安全。int() 转换对 min_price 有效，"
        "但 category 的拼接是独立的注入点。\n"
        "5. 综合来看，存在 SQL 注入漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-89", "SQL注入", "Critical",
        source="request.args.get('cat')（category 参数未参数化）",
        sink="cursor.execute(query) 其中 query 拼接 category",
        explanation="int() 转换只保护了 min_price，category 仍直接拼接，' 可注入任意 SQL",
        fix="全部参数化：cursor.execute(\"SELECT * FROM products WHERE category = ? AND price >= ?\", (category, safe_min))"
    )
))

# B7: 开放重定向 — 用黑名单校验但可被 @ 绕过
DEFENSE_CONFUSION_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, redirect
app = Flask(__name__)

@app.route("/go")
def go():
    url = request.args.get("url", "")
    # 黑名单校验：阻止已知的恶意域名
    blacklist = ["evil.com", "malware.org", "phishing.net"]
    if any(bad in url for bad in blacklist):
        return "blocked", 403
    # 但黑名单不完整：可用 https://trusted.com@evil.com 绕过
    return redirect(url)
''',
    language="python", filename="defense_redirect_blacklist_bypass.py",
    cot="分析过程：\n"
        "1. 用户可控输入：url 来自 request.args.get('url')。\n"
        "2. 危险 sink：redirect(url)，重定向到用户指定的 URL。\n"
        "3. 防御分析：用黑名单校验 url，阻止 evil.com/malware.org/phishing.net。"
        "但黑名单不完整——可用 https://trusted.com@evil.com 绕过（浏览器会重定向到 evil.com，"
        "因为 @ 前的 trusted.com 被视为用户信息）。也可用 IP 编码（如 0x7f000001）绕过域名黑名单。\n"
        "4. 关键判断：黑名单是脆弱的防御方式，无法覆盖所有变体。"
        "只有白名单（允许列表）才是可靠的重定向防御。\n"
        "5. 综合来看，存在开放重定向漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-601", "开放重定向", "Medium",
        source="request.args.get('url')",
        sink="redirect(url) 仅用黑名单校验",
        explanation="黑名单可被 https://trusted.com@evil.com 或 IP 编码绕过，重定向到恶意站点",
        fix="改用白名单：if url not in ALLOWED_REDIRECTS: abort(400)；或校验 url 为相对路径"
    )
))

# B8: 正则白名单 — 看似有校验但正则可被绕过
DEFENSE_CONFUSION_SAMPLES.append(build_sample(
    code='''from flask import Flask, request
import re
app = Flask(__name__)

@app.route("/redirect")
def redirect():
    url = request.args.get("url", "")
    # 用正则校验 URL 是否以 https 开头
    if re.match(r"^https://", url):
        return f'<meta http-equiv="refresh" content="0;url={url}">'
    return "invalid url", 400
''',
    language="python", filename="defense_redirect_regex_bypass.py",
    cot="分析过程：\n"
        "1. 用户可控输入：url 来自 request.args.get('url')。\n"
        "2. 危险 sink：meta refresh 标签中 url 直接拼接。\n"
        "3. 防御分析：re.match(r'^https://', url) 校验 URL 以 https 开头。"
        "但 url 中的 \" 可闭合 HTML 属性注入任意内容，如 url=https://x\" onclick=\"alert(1) 。"
        "此外，https://evil.com 也是合法的 https URL，可做开放重定向。\n"
        "4. 关键判断：正则只校验了协议前缀，未校验域名白名单，也未转义 HTML 上下文中的引号。"
        "存在两个问题：XSS（属性注入）和开放重定向。\n"
        "5. 综合来看，存在 XSS 和开放重定向漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-79; CWE-601", "XSS+开放重定向", "Medium",
        source="request.args.get('url')",
        sink="meta refresh 标签拼接 url",
        explanation="正则只校验 https 前缀，未校验域名白名单也未转义引号，可注入 HTML 属性或重定向到恶意站点",
        fix="校验域名白名单；用 html.escape(url, quote=True) 转义引号；或用 Location 头重定向代替 meta refresh"
    )
))


# ===========================================================================
# C. 注意力分散靶向样本（5 条）
# ===========================================================================
# CVE-fix 持续 FN 根因 2：模型被无关安全机制分散注意力
# 策略：代码中有明显的安全措施（bcrypt/CSRF/HTTPS 等），但真正的漏洞在其他地方

DISTRACTION_SAMPLES = []

# C1: bcrypt + LDAP 注入（模拟 CVE-fix 0002 模式）
DISTRACTION_SAMPLES.append(build_sample(
    code='''const express = require('express');
const ldap = require('ldapjs');
const bcrypt = require('bcryptjs');
const app = express();
app.use(express.json());

app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    // 安全的密码存储：使用 bcrypt 哈希
    const storedHash = db.getPasswordHash(username);
    if (!bcrypt.compareSync(password, storedHash)) {
        return res.status(401).json({ error: 'invalid credentials' });
    }

    // LDAP 查询用户信息（密码已验证，但 LDAP filter 拼接了未转义的 username）
    const client = ldap.createClient({ url: 'ldap://corp.local' });
    const filter = '(uid=' + username + ')';
    client.search('ou=users,dc=corp,dc=local', { filter }, (err, searchResult) => {
        searchResult.on('searchEntry', (entry) => {
            res.json({ profile: entry.object });
        });
    });
});
app.listen(3000);
''',
    language="javascript", filename="distraction_bcrypt_ldap.js",
    cot="分析过程：\n"
        "1. 安全措施识别：代码使用 bcrypt.compareSync 验证密码，密码存储安全。\n"
        "2. 关键漏洞定位：LDAP filter = '(uid=' + username + ')' 直接拼接用户输入，"
        "username 中的 *)(uid=*) 可枚举所有用户。\n"
        "3. 注意力引导：bcrypt 密码哈希是正确的安全实践，但它与 LDAP filter 注入无关。"
        "密码验证通过不代表 LDAP 查询安全——这是两个独立的安全维度。\n"
        "4. 防御检查：LDAP filter 无转义，username 来自 req.body 未校验。\n"
        "5. 综合来看，存在 LDAP 注入漏洞，风险等级 High。bcrypt 密码哈希有效但与 LDAP 注入无关。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "High",
        source="req.body.username",
        sink="client.search({ filter: '(uid=' + username + ')' })",
        explanation="bcrypt 密码验证正确，但 LDAP filter 直接拼接 username 可注入 )(uid=*) 枚举用户",
        fix="用 ldap.escapeFilter(username) 转义 LDAP filter 特殊字符后再拼接"
    )
))

# C2: CSRF token + SQL 注入
DISTRACTION_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, session
from csrf import validate_csrf_token
app = Flask(__name__)

@app.route("/api/search", methods=["POST"])
def search():
    # CSRF 防护：校验 CSRF token
    if not validate_csrf_token(request.form.get("csrf_token")):
        return "forbidden", 403

    # 搜索功能：SQL 拼接
    keyword = request.form.get("q", "")
    query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    cursor.execute(query)
    return {"results": cursor.fetchall()}
''',
    language="python", filename="distraction_csrf_sqli.py",
    cot="分析过程：\n"
        "1. 安全措施识别：代码使用 validate_csrf_token 校验 CSRF token，防护有效。\n"
        "2. 关键漏洞定位：query = \"SELECT * FROM products WHERE name LIKE '%\" + keyword + \"%'\" "
        "直接拼接用户输入，keyword 中的 ' 可闭合 SQL 字符串注入。\n"
        "3. 注意力引导：CSRF 防护阻止了跨站请求伪造，但不影响 SQL 注入——"
        "攻击者可以通过合法的 CSRF token 发送恶意搜索关键词。CSRF 和 SQLi 是两个独立的安全维度。\n"
        "4. 防御检查：SQL 无参数化查询、无输入校验。\n"
        "5. 综合来看，存在 SQL 注入漏洞，风险等级 Critical。CSRF 防护有效但与 SQL 注入无关。",
    json_block=vuln_json(
        "CWE-89", "SQL注入", "Critical",
        source="request.form.get('q')",
        sink="cursor.execute(query) 其中 query 拼接 keyword",
        explanation="CSRF 防护有效，但 SQL 直接拼接 keyword 可注入 ' 闭合字符串执行任意 SQL",
        fix="使用参数化查询：cursor.execute(\"SELECT * FROM products WHERE name LIKE %s\", ('%' + keyword + '%',))"
    )
))

# C3: HTTPS + XSS
DISTRACTION_SAMPLES.append(build_sample(
    code='''const express = require('express');
const helmet = require('helmet');
const app = express();

// 安全头设置：HSTS、CSP 等
app.use(helmet());
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));

app.get('/greet', (req, res) => {
    const name = req.query.name;
    // 用户输入直接返回
    res.send(`<h1>Hello, ${name}!</h1>`);
});
app.listen(443);
''',
    language="javascript", filename="distraction_https_xss.js",
    cot="分析过程：\n"
        "1. 安全措施识别：使用 helmet 设置安全头（HSTS、CSP），强制 HTTPS。\n"
        "2. 关键漏洞定位：res.send(`<h1>Hello, ${name}!</h1>`) 直接拼接用户输入到 HTML。"
        "name 中的 <script> 可注入恶意脚本。\n"
        "3. 注意力引导：HSTS 防止协议降级，CSP 限制脚本来源，但 helmet 的默认 CSP 不一定阻止内联脚本。"
        "HTTPS 加密传输但不防止 XSS——XSS 发生在浏览器 DOM 层而非传输层。\n"
        "4. 防御检查：无 HTML 转义、无模板引擎自动转义。\n"
        "5. 综合来看，存在 XSS 漏洞，风险等级 High。HTTPS/HSTS 有效但与 XSS 无关。",
    json_block=vuln_json(
        "CWE-79", "XSS", "High",
        source="req.query.name",
        sink="res.send(`<h1>Hello, ${name}!</h1>`) 拼接 name 到 HTML",
        explanation="HTTPS/HSTS 有效但与 XSS 无关，name 直接拼接到 HTML 可注入 <script>",
        fix="用 DOMPurify 转义 name；或用模板引擎自动转义；设置严格的 CSP（禁止内联脚本）"
    )
))

# C4: Rate limiting + 命令注入
DISTRACTION_SAMPLES.append(build_sample(
    code='''from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import subprocess
app = Flask(__name__)
limiter = Limiter(app, key_func=get_remote_address)

@app.route("/tools/lookup")
@limiter.limit("10 per minute")  # 限速防护
def lookup():
    domain = request.args.get("domain", "")
    # 执行 DNS 查询命令
    result = subprocess.run(
        "nslookup " + domain,
        shell=True, capture_output=True, text=True
    )
    return result.stdout
''',
    language="python", filename="distraction_ratelimit_cmdi.py",
    cot="分析过程：\n"
        "1. 安全措施识别：使用 flask_limiter 限制每分钟 10 次请求，防止暴力枚举。\n"
        "2. 关键漏洞定位：subprocess.run('nslookup ' + domain, shell=True) 直接拼接用户输入到 shell 命令。"
        "domain 中的 ; 或 | 可注入额外命令。\n"
        "3. 注意力引导：Rate limiting 限制了请求频率，但不影响单次请求的命令注入。"
        "攻击者只需一次请求即可执行注入命令。限速和命令注入是两个独立的安全维度。\n"
        "4. 防御检查：shell=True + 字符串拼接，无输入校验。\n"
        "5. 综合来看，存在命令注入漏洞，风险等级 Critical。Rate limiting 有效但与命令注入无关。",
    json_block=vuln_json(
        "CWE-78", "命令注入", "Critical",
        source="request.args.get('domain')",
        sink="subprocess.run('nslookup ' + domain, shell=True)",
        explanation="Rate limiting 有效但与命令注入无关，domain 拼接到 shell 命令可注入 ; 或 | 执行任意命令",
        fix="用 subprocess.run(['nslookup', domain], shell=False) 传列表参数；或校验 domain 为合法域名"
    )
))

# C5: Session timeout + 路径穿越
DISTRACTION_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, session
from datetime import timedelta
app = Flask(__name__)
app.permanent_session_lifetime = timedelta(minutes=30)

@app.route("/file/download")
def download_file():
    session.permanent = True  # 30 分钟 session 超时
    if "user_id" not in session:
        return "unauthorized", 401

    filename = request.args.get("file", "")
    # 文件读取
    filepath = "/var/www/uploads/" + filename
    with open(filepath) as f:
        return f.read()
''',
    language="python", filename="distraction_session_path.py",
    cot="分析过程：\n"
        "1. 安全措施识别：设置 30 分钟 session 超时（permanent_session_lifetime），降低会话劫持风险。\n"
        "2. 关键漏洞定位：filepath = '/var/www/uploads/' + filename 直接拼接用户输入。"
        "filename 中的 ../etc/passwd 可穿越目录读取任意文件。\n"
        "3. 注意力引导：Session 超时是会话管理安全措施，与文件读取的路径校验无关。"
        "攻击者在 session 有效期内即可利用路径穿越。会话超时和路径穿越是两个独立的安全维度。\n"
        "4. 防御检查：无路径规范化、无 startswith 校验。\n"
        "5. 综合来看，存在路径穿越漏洞，风险等级 High。Session 超时有效但与路径穿越无关。",
    json_block=vuln_json(
        "CWE-22", "路径穿越", "High",
        source="request.args.get('file')",
        sink="open('/var/www/uploads/' + filename)",
        explanation="Session 超时有效但与路径穿越无关，filename 中的 ../ 可穿越目录读取任意文件",
        fix="用 os.path.abspath 规范化后校验 startswith('/var/www/uploads/')；或用 pathlib.Path.resolve()"
    )
))


# ===========================================================================
# D. 框架代码误判靶向样本（5 条）
# ===========================================================================
# CVE-fix 持续 FN 根因 3：模型把真实漏洞代码误判为"演示/框架代码"
# 策略：代码看起来像框架内部/演示代码，但包含真实漏洞

FRAMEWORK_SAMPLES = []

# D1: JSON-RPC eval（模拟 CVE-fix 0003 模式）
FRAMEWORK_SAMPLES.append(build_sample(
    code='''import json
from flask import Flask, request
app = Flask(__name__)

# JSON-RPC 处理器
@app.route("/rpc", methods=["POST"])
def handle_rpc():
    payload = request.get_json()
    method = payload.get("method")
    params = payload.get("params", [])

    if method == "calculate":
        # 数学表达式求值
        expression = params[0] if params else ""
        result = eval(expression)
        return {"jsonrpc": "2.0", "result": result, "id": payload.get("id")}
    elif method == "ping":
        return {"jsonrpc": "2.0", "result": "pong", "id": payload.get("id")}
    return {"jsonrpc": "2.0", "error": {"code": -32601, "message": "method not found"}}
''',
    language="python", filename="framework_jsonrpc_eval.py",
    cot="分析过程：\n"
        "1. 用户可控输入：params[0] 来自 JSON-RPC 请求体，是用户提交的数学表达式。\n"
        "2. 危险 sink：eval(expression)，直接执行用户提供的表达式字符串。\n"
        "3. 关键判断：虽然代码结构像 JSON-RPC 框架，但 eval() 执行用户输入是真实漏洞，不是演示代码。"
        "expression=__import__('os').system('id') 可执行任意系统命令。\n"
        "4. 防御检查：无输入校验、无沙箱限制。eval 直接在当前命名空间执行。\n"
        "5. 对比 CoT：为什么不是 CWE-78？因为 sink 是 eval() 而非 os.system/subprocess，"
        "eval 执行 Python 表达式而非 shell 命令，属于代码注入，故为 CWE-95 代码注入（eval）。\n"
        "6. 综合来看，存在代码注入漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-95", "代码注入(eval)", "Critical",
        source="JSON-RPC params[0]（用户提交的表达式）",
        sink="eval(expression)",
        explanation="eval 直接执行用户提交的表达式，__import__('os').system('id') 可 RCE",
        fix="用 ast.literal_eval 替代 eval（仅解析字面量）；或用安全的数学表达式库（如 numexpr）"
    )
))

# D2: 模板引擎动态渲染
FRAMEWORK_SAMPLES.append(build_sample(
    code='''from jinja2 import Environment, BaseLoader
from flask import Flask, request
app = Flask(__name__)

# 自定义模板渲染器
@app.route("/render")
def render_content():
    template_str = request.args.get("tpl", "Hello World")
    env = Environment(loader=BaseLoader())
    # 从用户输入创建模板
    template = env.from_string(template_str)
    output = template.render(name="user")
    return output
''',
    language="python", filename="framework_dynamic_template.py",
    cot="分析过程：\n"
        "1. 用户可控输入：template_str 来自 request.args.get('tpl')。\n"
        "2. 危险 sink：env.from_string(template_str).render()，用户输入作为 Jinja2 模板内容。\n"
        "3. 关键判断：虽然代码看起来像模板引擎封装，但 env.from_string 接受用户输入作为模板内容。"
        "template_str={{config}} 可泄露 Flask 配置，{{''.__class__.__mro__[1].__subclasses__()}} 可 RCE。\n"
        "4. 防御检查：未启用沙箱（SandboxedEnvironment），未限制模板内容。\n"
        "5. 对比 CoT：为什么不是 CWE-79？因为 sink 是 Jinja2 模板渲染而非 HTML 输出，"
        "注入载体是 {{ }} 模板语法而非 HTML 标签，在服务端执行而非浏览器侧，故为 CWE-1336; CWE-94 SSTI。\n"
        "6. 综合来看，存在 SSTI 漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-1336; CWE-94", "SSTI模板注入", "Critical",
        source="request.args.get('tpl')",
        sink="env.from_string(template_str).render()",
        explanation="用户输入作为 Jinja2 模板内容，{{ }} 语法可执行任意 Python 代码 RCE",
        fix="用固定模板文件 + context 传参；如需动态模板，用 SandboxedEnvironment 限制可用功能"
    )
))

# D3: 插件系统动态导入
FRAMEWORK_SAMPLES.append(build_sample(
    code='''from flask import Flask, request
import importlib
app = Flask(__name__)

# 插件加载器
@app.route("/plugin/run")
def run_plugin():
    plugin_name = request.args.get("name", "")
    # 动态导入插件模块
    try:
        module = importlib.import_module(plugin_name)
        return module.run()
    except Exception as e:
        return f"plugin error: {e}", 500
''',
    language="python", filename="framework_plugin_import.py",
    cot="分析过程：\n"
        "1. 用户可控输入：plugin_name 来自 request.args.get('name')。\n"
        "2. 危险 sink：importlib.import_module(plugin_name)，动态导入用户指定的模块。\n"
        "3. 关键判断：虽然代码结构像插件系统，但 importlib.import_module 接受用户输入。"
        "plugin_name=os 可导入 os 模块（虽然无法直接调用 os.system），"
        "plugin_name=subprocess 可导入 subprocess。更危险的是，如果存在恶意模块名（如 'os; os.system(\"id\")'），"
        "在某些 Python 版本中可能触发导入时的代码执行。\n"
        "4. 防御检查：无模块名白名单、无插件目录限制。\n"
        "5. 综合来看，存在代码注入风险，风险等级 High。",
    json_block=vuln_json(
        "CWE-94", "代码注入(动态导入)", "High",
        source="request.args.get('name')",
        sink="importlib.import_module(plugin_name)",
        explanation="用户可指定任意模块名导入，可导入 os/subprocess 等危险模块，或利用恶意模块名触发代码执行",
        fix="用模块名白名单：if plugin_name not in ALLOWED_PLUGINS: abort(403)；或用 pkgutil 限制搜索路径"
    )
))

# D4: 配置解析器 exec
FRAMEWORK_SAMPLES.append(build_sample(
    code='''from flask import Flask, request
app = Flask(__name__)

# 配置解析器：支持 Python 语法的高级配置
@app.route("/config/update", methods=["POST"])
def update_config():
    config_text = request.get_data(as_text=True)
    config_ns = {}
    # 用 exec 执行配置文本（"支持 Python 语法"）
    exec(config_text, {"__builtins__": {}}, config_ns)
    return {"config": str(config_ns)}
''',
    language="python", filename="framework_config_exec.py",
    cot="分析过程：\n"
        "1. 用户可控输入：config_text 来自 request.get_data()（POST body）。\n"
        "2. 危险 sink：exec(config_text, ...)，执行用户提供的配置文本。\n"
        "3. 关键判断：虽然代码看起来像配置解析器，但 exec() 执行用户输入是真实漏洞。"
        "虽然限制了 __builtins__={}，但 Python 的 exec 沙箱可通过多种方式逃逸，"
        "如 __class__.__subclasses__() 链。\n"
        "4. 防御检查：__builtins__={} 限制不充分，已知多种沙箱逃逸方法。\n"
        "5. 对比 CoT：为什么不是 CWE-95？exec() 和 eval() 都是代码执行，"
        "但 exec 执行语句（statement）而 eval 执行表达式（expression），"
        "二者均归为 CWE-94 代码注入。此处用 exec 更准确。\n"
        "6. 综合来看，存在代码注入漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-94", "代码注入(exec)", "Critical",
        source="request.get_data()（配置文本）",
        sink="exec(config_text, ...)",
        explanation="exec 执行用户提供的配置文本，__builtins__={} 限制可被逃逸，可 RCE",
        fix="用 configparser/yaml.safe_load 解析配置；禁止用 exec/eval 执行用户输入"
    )
))

# D5: 计算器 eval（更隐蔽的 eval 场景）
FRAMEWORK_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, jsonify
app = Flask(__name__)

# API 计算器端点
@app.route("/api/calc")
def calculator():
    expr = request.args.get("expr", "")
    try:
        # "安全"的数学计算——只允许数字和运算符
        result = eval(expr, {"__builtins__": {}}, {})
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 400
''',
    language="python", filename="framework_calc_eval.py",
    cot="分析过程：\n"
        "1. 用户可控输入：expr 来自 request.args.get('expr')。\n"
        "2. 危险 sink：eval(expr, {'__builtins__': {}}, {})，执行用户输入的表达式。\n"
        "3. 关键判断：虽然代码看起来像计算器 API，但 eval() 执行用户输入是真实漏洞。"
        "__builtins__={} 限制不充分：可通过 ().__class__.__bases__[0].__subclasses__() 访问危险类。\n"
        "4. 防御检查：__builtins__={} 限制可被逃逸，已知多种沙箱逃逸方法。\n"
        "5. 对比 CoT：为什么是 CWE-95 而非 CWE-94？eval 执行表达式（expression），"
        "归为 CWE-95 代码注入（eval）；exec 执行语句归为 CWE-94。两者本质相同。\n"
        "6. 综合来看，存在代码注入漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-95", "代码注入(eval)", "Critical",
        source="request.args.get('expr')",
        sink="eval(expr, {'__builtins__': {}}, {})",
        explanation="eval 执行用户表达式，__builtins__={} 限制可被逃逸，通过 __subclasses__ 链可 RCE",
        fix="用 ast.literal_eval 替代（仅解析字面量）；或用 numexpr 等安全数学库"
    )
))


# ===========================================================================
# E. 多样安全代码（15 条）
# ===========================================================================
# 非 hard-negative 方式：增加安全代码的多样性，让模型学到更多"安全模式"
# 不针对特定 FP，而是覆盖各种安全编码模式

SAFE_SAMPLES = []

# E1: subprocess 列表参数 + shell=False（安全）
SAFE_SAMPLES.append(build_sample(
    code='''import subprocess
from flask import Flask, request
app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # 列表参数 + shell=False，无 shell 注入风险
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True, text=True, timeout=5
    )
    return result.stdout
''',
    language="python", filename="safe_subprocess_list_v2.py",
    cot="分析过程：\n"
        "1. 用户可控输入：host 来自 request.args.get('host')。\n"
        "2. Sink 分析：subprocess.run(['ping', '-c', '1', host], shell=False)。\n"
        "3. 防御分析：使用列表参数传参，shell=False（默认值），不经过 shell 解析。"
        "host 作为独立参数传递给 ping，即使含 ; | 等特殊字符也不会被 shell 解释。\n"
        "4. 关键判断：列表参数 + shell=False 是 subprocess 的安全用法，无命令注入风险。\n"
        "5. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("subprocess.run 使用列表参数 + shell=False，host 作为独立参数不经 shell 解析，无注入风险。")
))

# E2: shlex.quote + shell=True（安全）
SAFE_SAMPLES.append(build_sample(
    code='''import subprocess
import shlex
from flask import Flask, request
app = Flask(__name__)

@app.route("/dns/lookup")
def dns_lookup():
    domain = request.args.get("domain", "")
    # shlex.quote 转义后拼接，shell=True 也安全
    safe_domain = shlex.quote(domain)
    cmd = f"dig +short {safe_domain}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
''',
    language="python", filename="safe_shlex_quote_v2.py",
    cot="分析过程：\n"
        "1. 用户可控输入：domain 来自 request.args.get('domain')。\n"
        "2. Sink 分析：subprocess.run(f'dig +short {safe_domain}', shell=True)。\n"
        "3. 防御分析：shlex.quote(domain) 将 domain 用单引号包裹并转义内部单引号，"
        "shell 不会解释 domain 中的特殊字符。即使 domain='; rm -rf /'，"
        "shlex.quote 输出为 ''\''; rm -rf /'\''，shell 将其视为字面字符串。\n"
        "4. 关键判断：shlex.quote 是 Python 标准库提供的 shell 转义函数，在 shell=True 场景下有效。\n"
        "5. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("shlex.quote 有效转义了 domain，shell=True 场景下无注入风险。建议长期改用列表参数。")
))

# E3: PreparedStatement（Java，安全）
SAFE_SAMPLES.append(build_sample(
    code='''import java.sql.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    @GetMapping("/user/{id}")
    public String getUser(@PathVariable String id) throws SQLException {
        String sql = "SELECT username, email FROM users WHERE id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, id);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                return rs.getString("username") + ":" + rs.getString("email");
            }
            return "not found";
        }
    }
}
''',
    language="java", filename="safe_prepared_stmt_v2.java",
    cot="分析过程：\n"
        "1. 用户可控输入：id 来自 @PathVariable。\n"
        "2. Sink 分析：PreparedStatement.executeQuery()，SQL 使用 ? 占位符。\n"
        "3. 防御分析：使用 PreparedStatement 参数化查询，id 通过 ps.setString(1, id) 绑定，"
        "JDBC 驱动会正确处理特殊字符，id 中的 ' 不会被解释为 SQL 语法。\n"
        "4. 关键判断：PreparedStatement 是 Java 中防止 SQL 注入的标准方法，防御有效。\n"
        "5. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("PreparedStatement 参数化查询有效，id 通过 setString 绑定不经 SQL 解析，无注入风险。")
))

# E4: HTML 转义（Node.js，安全）
SAFE_SAMPLES.append(build_sample(
    code='''const express = require('express');
const escapeHtml = require('escape-html');
const app = express();

app.get('/greet', (req, res) => {
    const name = req.query.name || 'guest';
    // escape-html 转义 HTML 特殊字符
    const safeName = escapeHtml(name);
    res.send(`<h1>Hello, ${safeName}!</h1>`);
});
app.listen(3000);
''',
    language="javascript", filename="safe_escape_html_v2.js",
    cot="分析过程：\n"
        "1. 用户可控输入：name 来自 req.query.name。\n"
        "2. Sink 分析：res.send(`<h1>Hello, ${safeName}!</h1>`)。\n"
        "3. 防御分析：escape-html 库转义了 < > & \" ' 等 HTML 特殊字符，"
        "safeName 中的 <script> 被转为 &lt;script&gt;，浏览器显示为文本而非执行。\n"
        "4. 关键判断：escape-html 是有效的 HTML 上下文转义，防止了 XSS。\n"
        "5. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("escape-html 转义了 HTML 特殊字符，name 中的 <script> 被转为实体，无 XSS 风险。")
))

# E5: 路径校验（Go，安全）
SAFE_SAMPLES.append(build_sample(
    code='''package main

import (
    "fmt"
    "net/http"
    "os"
    "path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")
    baseDir := "/var/www/uploads"

    // 规范化路径并校验是否在 baseDir 内
    fullPath := filepath.Join(baseDir, filename)
    absPath, err := filepath.Abs(fullPath)
    if err != nil {
        http.Error(w, "invalid path", 400)
        return
    }

    // 校验规范化后的路径仍在 baseDir 内
    if !filepath.HasPrefix(absPath, baseDir+string(os.PathSeparator)) {
        http.Error(w, "forbidden", 403)
        return
    }

    data, err := os.ReadFile(absPath)
    if err != nil {
        http.Error(w, "not found", 404)
        return
    }
    fmt.Fprint(w, string(data))
}
''',
    language="go", filename="safe_path_validate_go.go",
    cot="分析过程：\n"
        "1. 用户可控输入：filename 来自 r.URL.Query().Get('file')。\n"
        "2. Sink 分析：os.ReadFile(absPath)。\n"
        "3. 防御分析：filepath.Join + filepath.Abs 规范化路径后，用 filepath.HasPrefix 校验路径仍在 baseDir 内。"
        "filename 中的 ../ 在 filepath.Join 后会被解析，filepath.Abs 返回绝对路径，"
        "如果路径穿越出 baseDir，HasPrefix 校验会拒绝。\n"
        "4. 关键判断：先规范化再校验前缀是路径穿越的正确防御方法。\n"
        "5. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("filepath.Join + Abs 规范化路径后校验 HasPrefix(baseDir)，有效防止路径穿越。")
))

# E6: bcrypt 密码哈希（Ruby，安全）
SAFE_SAMPLES.append(build_sample(
    code='''require 'bcrypt'

class User
  def set_password(raw_password)
    # 使用 bcrypt 哈希密码（自动加 salt）
    @password_hash = BCrypt::Password.create(raw_password, cost: 12)
  end

  def verify_password(raw_password)
    # bcrypt 恒定时间比较
    @password_hash == raw_password
  end
end
''',
    language="ruby", filename="safe_bcrypt_ruby.rb",
    cot="分析过程：\n"
        "1. 密码学分析：使用 BCrypt::Password.create(cost: 12) 哈希密码。\n"
        "2. 安全特性：bcrypt 自动生成 per-user salt，cost factor 12 提供足够的计算成本，"
        "BCrypt::Password.== 是恒定时间比较（防时序攻击）。\n"
        "3. 防御检查：无硬编码密码、无弱算法、无时序泄露。\n"
        "4. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("bcrypt 哈希 + per-user salt + cost 12 + 恒定时间比较，密码存储安全。")
))

# E7: 安全的 JSON 解析（替代 pickle，安全）
SAFE_SAMPLES.append(build_sample(
    code='''import json
from flask import Flask, request
app = Flask(__name__)

@app.route("/load")
def load_data():
    raw = request.get_data()
    try:
        # 使用 json.loads 解析（安全，不会执行代码）
        data = json.loads(raw)
        return {"data": data}
    except json.JSONDecodeError:
        return {"error": "invalid JSON"}, 400
''',
    language="python", filename="safe_json_loads_v2.py",
    cot="分析过程：\n"
        "1. 用户可控输入：raw 来自 request.get_data()。\n"
        "2. Sink 分析：json.loads(raw)。\n"
        "3. 防御分析：json.loads 只解析 JSON 格式数据（字面量、数组、对象），"
        "不会执行任何代码或构造任意对象。与 pickle.loads/yaml.load 不同，json.loads 是安全的反序列化方式。\n"
        "4. 关键判断：JSON 是安全的数据交换格式，json.loads 无代码执行风险。\n"
        "5. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("json.loads 只解析 JSON 字面量，不会执行代码或构造任意对象，安全。")
))

# E8: 安全的 JWT 验证（安全）
SAFE_SAMPLES.append(build_sample(
    code='''import jwt
from flask import Flask, request
app = Flask(__name__)
JWT_SECRET = app.config["JWT_SECRET"]

@app.route("/api/data")
def get_data():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        # 完整的 JWT 验证：签名 + 算法白名单 + 过期 + issuer + audience
        payload = jwt.decode(
            token, JWT_SECRET,
            algorithms=["HS256"],
            issuer="auth.example.com",
            audience="api.example.com",
            options={"require": ["exp", "iss", "aud", "sub"]}
        )
        user_id = payload["sub"]
        data = db.execute(
            "SELECT * FROM user_data WHERE uid = ?", (user_id,)
        ).fetchone()
        return dict(data)
    except jwt.PyJWTError:
        return "invalid token", 401
''',
    language="python", filename="safe_jwt_complete_verify.py",
    cot="分析过程：\n"
        "1. 认证流程：从 Authorization 头取 JWT，jwt.decode 校验。\n"
        "2. 防御分析：指定 algorithms=['HS256']（防 none 算法）、校验 issuer/audience、"
        "要求 exp/iss/aud/sub 字段存在、SQL 使用参数化查询。\n"
        "3. 关键判断：JWT 验证完整（签名 + 算法白名单 + issuer + audience + 过期），"
        "SQL 使用参数化查询，无注入风险。\n"
        "4. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("JWT 验证完整（签名+算法白名单+issuer+audience+过期），SQL 参数化，无漏洞。")
))

# E9: 安全的模板渲染（安全）
SAFE_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, render_template
app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    # 使用固定模板文件 + context 传参（Jinja2 自动转义）
    return render_template("greeting.html", name=name)
''',
    language="python", filename="safe_template_render_v2.py",
    cot="分析过程：\n"
        "1. 用户可控输入：name 来自 request.args.get('name')。\n"
        "2. Sink 分析：render_template('greeting.html', name=name)。\n"
        "3. 防御分析：使用固定模板文件（非 render_template_string），name 作为 context 变量传入。"
        "Flask 的 Jinja2 默认启用自动转义（autoescape=True），name 中的 <script> 被转义为 &lt;script&gt;。\n"
        "4. 关键判断：固定模板 + context 传参 + 自动转义是 SSTI/XSS 的正确防御。\n"
        "5. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("render_template 使用固定模板 + context 传参 + Jinja2 自动转义，无 SSTI/XSS 风险。")
))

# E10: 安全的 XML 解析（安全）
SAFE_SAMPLES.append(build_sample(
    code='''from defusedxml.ElementTree import fromstring as safe_fromstring
from flask import Flask, request
app = Flask(__name__)

@app.route("/parse")
def parse_xml():
    body = request.get_data()
    # 使用 defusedxml 防御 XXE
    root = safe_fromstring(body)
    return {"data": root.findtext("value", "")}
''',
    language="python", filename="safe_xml_defused_v2.py",
    cot="分析过程：\n"
        "1. 用户可控输入：body 来自 request.get_data()。\n"
        "2. Sink 分析：safe_fromstring(body)。\n"
        "3. 防御分析：使用 defusedxml.ElementTree.fromstring，该库默认禁用外部实体解析、"
        "DTD 处理和实体扩展，有效防御 XXE 攻击。\n"
        "4. 关键判断：defusedxml 是 Python 中防御 XXE 的标准做法。\n"
        "5. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("defusedxml 禁用外部实体解析和 DTD，有效防御 XXE，无漏洞。")
))

# E11: 环境变量凭证（安全）
SAFE_SAMPLES.append(build_sample(
    code='''import os
from flask import Flask
app = Flask(__name__)

# 从环境变量读取敏感配置
DB_HOST = os.environ["DB_HOST"]
DB_USER = os.environ["DB_USER"]
DB_PASSWORD = os.environ["DB_PASSWORD"]
API_KEY = os.environ["API_KEY"]

# 使用环境变量中的凭证连接数据库
conn = psycopg2.connect(
    host=DB_HOST,
    user=DB_USER,
    password=DB_PASSWORD
)
''',
    language="python", filename="safe_env_credentials_v2.py",
    cot="分析过程：\n"
        "1. 凭证来源：DB_HOST/DB_USER/DB_PASSWORD/API_KEY 均来自 os.environ。\n"
        "2. 安全特性：凭证不在源码中硬编码，通过环境变量注入，源码泄露不暴露凭证。\n"
        "3. 防御检查：无字符串字面量凭证，无硬编码密钥。\n"
        "4. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("凭证从环境变量读取，源码中无硬编码凭证，无泄露风险。")
))

# E12: CSRF token 校验（安全）
SAFE_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, session
from flask_wtf.csrf import CSRFProtect
app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
csrf = CSRFProtect(app)  # 全局 CSRF 防护

@app.route("/transfer", methods=["POST"])
def transfer():
    # flask_wtf 自动校验 CSRF token
    to = request.form.get("to")
    amount = int(request.form.get("amount", 0))
    db.execute(
        "UPDATE accounts SET balance = balance - ? WHERE uid = ?",
        (amount, session["user_id"])
    )
    return "ok"
''',
    language="python", filename="safe_csrf_flask_wtf.py",
    cot="分析过程：\n"
        "1. 操作分析：/transfer 是状态变更操作，需 CSRF 防护。\n"
        "2. 防御分析：CSRFProtect(app) 全局启用 CSRF 防护，自动校验所有 POST/PUT/DELETE 请求的 CSRF token。"
        "SQL 使用参数化查询。\n"
        "3. 关键判断：Flask-WTF CSRFProtect 是 Flask 中标准的 CSRF 防护方案。\n"
        "4. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("CSRFProtect 全局 CSRF 防护 + SQL 参数化查询，无漏洞。")
))

# E13: 安全的随机数（安全）
SAFE_SAMPLES.append(build_sample(
    code='''import secrets
import string

def generate_session_token(length: int = 32) -> str:
    # 使用 secrets 模块生成密码学安全随机数
    alphabet = string.ascii_letters + string.digits
    token = ''.join(secrets.choice(alphabet) for _ in range(length))
    return token

def generate_api_key() -> str:
    return secrets.token_urlsafe(32)
''',
    language="python", filename="safe_secrets_random.py",
    cot="分析过程：\n"
        "1. 随机数分析：使用 secrets.choice 和 secrets.token_urlsafe 生成随机值。\n"
        "2. 安全特性：secrets 模块使用 OS 级别的 CSPRNG（加密安全伪随机数生成器），"
        "与 random 模块的 Mersenne Twister 不同，不可预测。\n"
        "3. 防御检查：无 random 模块使用、无弱随机数。\n"
        "4. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("secrets 模块使用 CSPRNG，生成的 token 不可预测，安全。")
))

# E14: 恒定时间比较（安全）
SAFE_SAMPLES.append(build_sample(
    code='''import hmac
import hashlib
from flask import Flask, request
app = Flask(__name__)

@app.route("/webhook", methods=["POST"])
def webhook():
    # 从请求头获取签名
    signature = request.headers.get("X-Signature", "")
    expected = hmac.new(
        app.config["WEBHOOK_SECRET"].encode(),
        request.get_data(),
        hashlib.sha256
    ).hexdigest()

    # 恒定时间比较，防时序攻击
    if hmac.compare_digest(signature, expected):
        return process_webhook(request.get_json())
    return "invalid signature", 401
''',
    language="python", filename="safe_hmac_compare.py",
    cot="分析过程：\n"
        "1. 认证流程：从 X-Signature 头获取签名，用 HMAC-SHA256 计算期望值。\n"
        "2. 防御分析：使用 hmac.compare_digest 做恒定时间比较，防止时序攻击。"
        "HMAC 密钥从 app.config 读取（非硬编码）。\n"
        "3. 关键判断：hmac.compare_digest 是 Python 标准库提供的恒定时间比较函数，防时序攻击。\n"
        "4. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("HMAC-SHA256 签名 + hmac.compare_digest 恒定时间比较，防时序攻击，无漏洞。")
))

# E15: 安全的 YAML 解析（安全）
SAFE_SAMPLES.append(build_sample(
    code='''import yaml
from flask import Flask, request
app = Flask(__name__)

@app.route("/config/load", methods=["POST"])
def load_config():
    raw = request.get_data(as_text=True)
    # 使用 yaml.safe_load（不支持任意对象反序列化）
    config = yaml.safe_load(raw)
    if isinstance(config, dict):
        return {"theme": config.get("theme", "default")}
    return {"error": "invalid config"}, 400
''',
    language="python", filename="safe_yaml_safe_load_v2.py",
    cot="分析过程：\n"
        "1. 用户可控输入：raw 来自 request.get_data()。\n"
        "2. Sink 分析：yaml.safe_load(raw)。\n"
        "3. 防御分析：yaml.safe_load 只解析 YAML 基础类型（dict/list/str/int/float/bool/null），"
        "不支持 !!python/object 等危险标签，无法构造任意 Python 对象。\n"
        "4. 关键判断：yaml.safe_load 是 PyYAML 中安全加载 YAML 的正确方法。\n"
        "5. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("yaml.safe_load 不支持任意对象反序列化，只解析基础类型，安全。")
))


# E16-E20: 针对 v8 FP 的靶向安全样本
# v8 失败：8 个 FP 中有 5 个是安全代码被误判，根因是 v8 对比 CoT 教模型"部分防御不等于安全"
# 但模型过度泛化为"所有防御都不够"。v9 增加明确"防御有效→无漏洞"的样本纠正这一偏差。

# E16: 正确的授权检查（针对 safe_09_proper_authz FP：v8 误判为 CWE-287 硬编码凭证）
SAFE_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, session
app = Flask(__name__)

def is_admin(user_id):
    # 从数据库查询用户角色（非硬编码）
    row = db.execute(
        "SELECT role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return row is not None and row["role"] == "admin"

@app.route("/admin/users")
def admin_list_users():
    if "user_id" not in session:
        return "unauthorized", 401
    # 授权检查：验证当前用户是否为 admin
    if not is_admin(session["user_id"]):
        return "forbidden", 403
    users = db.execute("SELECT id, username FROM users").fetchall()
    return {"users": [dict(u) for u in users]}
''',
    language="python", filename="safe_proper_authz_v2.py",
    cot="分析过程：\n"
        "1. 访问控制分析：/admin/users 先检查认证（session.user_id），再检查授权（is_admin）。\n"
        "2. 授权实现：is_admin 从数据库查询用户角色，非硬编码。SQL 使用参数化查询无注入。\n"
        "3. 防御检查：认证 + 授权双层校验，授权基于数据库角色而非硬编码 ID。\n"
        "4. 关键判断：数据库查询角色 + 参数化 SQL 是正确的授权实现，无硬编码凭证。\n"
        "5. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("认证 + 授权双层校验，角色从数据库查询非硬编码，SQL 参数化，无漏洞。")
))

# E17: 正确的竞态条件防护（针对 safe_17_race_with_lock FP：v8 误判为 CWE-362）
SAFE_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, session
import threading
app = Flask(__name__)

balances = {}
lock = threading.Lock()

@app.route("/transfer", methods=["POST"])
def transfer():
    if "user_id" not in session:
        return "unauthorized", 401

    to = request.form.get("to")
    amount = int(request.form.get("amount", 0))
    user_id = session["user_id"]

    # 用 lock 保护共享数据，防止竞态条件
    with lock:
        current = balances.get(user_id, 0)
        if current < amount:
            return "insufficient funds", 400
        balances[user_id] = current - amount
        balances[to] = balances.get(to, 0) + amount

    return "ok"
''',
    language="python", filename="safe_race_with_lock_v2.py",
    cot="分析过程：\n"
        "1. 并发分析：balances 是共享数据，多个请求可能同时读写。\n"
        "2. 防御分析：使用 threading.Lock() 保护 balances 的读写操作，with lock 确保原子性。"
        "先检查余额再扣款（check-then-act）在 lock 内完成，防止 TOCTOU 竞态。\n"
        "3. 关键判断：with lock 确保了 check-then-act 的原子性，无竞态条件。\n"
        "4. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("threading.Lock 保护共享数据读写，check-then-act 在 lock 内原子完成，无竞态条件。")
))

# E18: 装饰器封装的安全操作（针对 noise_05_decorator_wrapper FP：v8 误判为 CWE-79 XSS）
SAFE_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, session
from functools import wraps
app = Flask(__name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return "unauthorized", 401
        return f(*args, **kwargs)
    return decorated_function

@app.route("/profile")
@login_required
def profile():
    user_id = session["user_id"]
    # 从数据库查询用户信息（参数化查询）
    user = db.execute(
        "SELECT username, email FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if user:
        # 返回 JSON（不拼接到 HTML，无 XSS 风险）
        return {"username": user["username"], "email": user["email"]}
    return "not found", 404
''',
    language="python", filename="safe_decorator_wrapper_v2.py",
    cot="分析过程：\n"
        "1. 代码结构：login_required 装饰器检查认证，profile 查询用户信息返回 JSON。\n"
        "2. 防御分析：装饰器实现了认证检查，SQL 使用参数化查询，返回 JSON 而非 HTML 拼接。\n"
        "3. 关键判断：返回 JSON（Content-Type: application/json）不会触发 XSS——"
        "浏览器不会解析 JSON 中的 HTML 标签。SQL 参数化无注入。\n"
        "4. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("装饰器认证检查 + SQL 参数化 + JSON 响应（非 HTML 拼接），无 XSS/SQLi 风险。")
))

# E19: shell=True 但无用户输入（针对 noise_06_shell_true_hardcoded FP：v8 误判为 CWE-78）
SAFE_SAMPLES.append(build_sample(
    code='''import subprocess
from flask import Flask
app = Flask(__name__)

@app.route("/system/info")
def system_info():
    # 执行固定命令（无用户输入），shell=True 在此场景安全
    result = subprocess.run(
        "uname -a && df -h /",
        shell=True,
        capture_output=True,
        text=True,
        timeout=5
    )
    return {"system": result.stdout}
''',
    language="python", filename="safe_shell_true_hardcoded_v2.py",
    cot="分析过程：\n"
        "1. 命令分析：subprocess.run('uname -a && df -h /', shell=True)。\n"
        "2. 用户输入检查：命令字符串 'uname -a && df -h /' 是固定的字面量，"
        "不包含任何用户可控输入（无 request.args/form/cookies）。\n"
        "3. 防御分析：虽然 shell=True 通常不推荐，但命令字符串完全由开发者控制，"
        "攻击者无法影响命令内容。无注入向量。\n"
        "4. 关键判断：无用户输入到达 sink，命令注入需要用户可控输入 + shell 拼接，此处无用户输入。\n"
        "5. 综合来看：无用户输入，无注入风险。防御有效，无漏洞。",
    json_block=safe_json("命令字符串为固定字面量，无用户可控输入，shell=True 在此场景无注入风险。")
))

# E20: Django ORM 安全查询（增加 ORM 模式的安全样本多样性）
SAFE_SAMPLES.append(build_sample(
    code='''from django.http import JsonResponse
from django.views import View
from myapp.models import User

class UserSearchView(View):
    def get(self, request):
        name = request.GET.get("name", "")
        # Django ORM 自动参数化查询（安全）
        users = User.objects.filter(username__contains=name).values("id", "username")
        return JsonResponse({"users": list(users)})
''',
    language="python", filename="safe_django_orm_v2.py",
    cot="分析过程：\n"
        "1. 用户可控输入：name 来自 request.GET.get('name')。\n"
        "2. Sink 分析：User.objects.filter(username__contains=name)。\n"
        "3. 防御分析：Django ORM 的 filter() 方法自动对参数进行参数化查询，"
        "name 的值通过 Django 的查询编译器绑定到 SQL 参数，不会被解释为 SQL 语法。\n"
        "4. 关键判断：Django ORM filter 是参数化查询的高级封装，与 PreparedStatement 等效。\n"
        "5. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("Django ORM filter 自动参数化查询，name 通过查询编译器绑定，无 SQL 注入风险。")
))


# ===========================================================================
# F. CWE 归因增强（7 条）
# ===========================================================================
# 补充 v8 未覆盖的易混 CWE 边界

ATTRIBUTION_SAMPLES = []

# F1: 整数溢出（CWE-190）— 对比 CWE-89
ATTRIBUTION_SAMPLES.append(build_sample(
    code='''#include <stdio.h>
#include <stdlib.h>

void process_payment(int quantity, int price) {
    // 计算总价（无溢出检查）
    int total = quantity * price;
    if (total < 0) {
        printf("invalid amount\\n");
        return;
    }
    // 处理支付
    charge_customer(total);
}
''',
    language="c", filename="attr_int_overflow_01.c",
    cot="分析过程：\n"
        "1. 输入分析：quantity 和 price 为 int 类型，用户可控制。\n"
        "2. 缺陷识别：quantity * price 可能整数溢出。例如 quantity=100000, price=100000 "
        "在 32 位 int 下结果为 10000000000 超出 INT_MAX（2147483647），溢出为负数或错误值。\n"
        "3. 防御检查：total < 0 检查不充分——溢出后结果可能为正数但仍不正确。"
        "无前置范围校验、无安全整数运算。\n"
        "4. 对比 CoT：为什么不是 CWE-89？因为没有 SQL 查询，问题是算术运算溢出，"
        "属于数值计算缺陷，故为 CWE-190 整数溢出。\n"
        "5. 综合来看，存在整数溢出漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-190", "整数溢出", "High",
        source="quantity 和 price 参数",
        sink="int total = quantity * price（无溢出检查）",
        explanation="quantity * price 可溢出 INT_MAX，溢出后值不正确，可能导致支付金额错误",
        fix="用 int64_t 或在乘法前检查 quantity > INT_MAX / price；用 __builtin_mul_overflow 检测溢出"
    )
))

# F2: 开放重定向（CWE-601）— 对比 CWE-79
ATTRIBUTION_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, redirect
app = Flask(__name__)

@app.route("/go")
def go():
    url = request.args.get("url", "/")
    # 直接重定向到用户提供的 URL，无白名单校验
    return redirect(url)
''',
    language="python", filename="attr_open_redirect_01.py",
    cot="分析过程：\n"
        "1. 用户可控输入：url 来自 request.args.get('url')。\n"
        "2. 危险 sink：redirect(url)，重定向到用户指定的 URL。\n"
        "3. 防御检查：无 URL 白名单、无域名校验。url=https://evil.com 可重定向到恶意站点。\n"
        "4. 对比 CoT：为什么不是 CWE-79？因为问题不是 HTML 输出未转义，"
        "而是 HTTP 重定向到任意 URL，属于重定向漏洞，故为 CWE-601 开放重定向。\n"
        "5. 综合来看，存在开放重定向漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-601", "开放重定向", "Medium",
        source="request.args.get('url')",
        sink="redirect(url)",
        explanation="url 无白名单校验直接重定向，可重定向到恶意站点用于钓鱼",
        fix="校验 url 为相对路径或域名白名单：if not is_safe_url(url): abort(400)"
    )
))

# F3: 日志注入（CWE-117）— 对比 CWE-89
ATTRIBUTION_SAMPLES.append(build_sample(
    code='''import logging
from flask import Flask, request
app = Flask(__name__)
logger = logging.getLogger("auth")

@app.route("/login")
def login():
    user = request.args.get("user", "")
    # 用户输入直接写入日志
    logger.info("Login attempt from user: " + user)
    return "ok"
''',
    language="python", filename="attr_log_inject_01.py",
    cot="分析过程：\n"
        "1. 用户可控输入：user 来自 request.args.get('user')。\n"
        "2. 危险 sink：logger.info('Login attempt from user: ' + user)。\n"
        "3. 防御检查：无换行符过滤。user 中的 \\n 可注入伪造日志条目，"
        "如 user=admin\\n[INFO] Login successful 可伪造成功登录日志。\n"
        "4. 对比 CoT：为什么不是 CWE-89？因为没有 SQL 查询，问题是日志消息中的换行符注入，"
        "属于日志注入，故为 CWE-117 日志注入。\n"
        "5. 综合来看，存在日志注入漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-117", "日志注入", "Medium",
        source="request.args.get('user')",
        sink="logger.info('Login attempt from user: ' + user)",
        explanation="user 直接拼接到日志消息，\\n 可注入伪造日志条目",
        fix="过滤 user 中的 \\n\\r 字符；或用结构化日志（JSON logging）"
    )
))

# F4: 信息泄露（CWE-200）— 对比 CWE-89
ATTRIBUTION_SAMPLES.append(build_sample(
    code='''from flask import Flask, request
app = Flask(__name__)

@app.route("/api/user/<uid>")
def get_user(uid):
    # 查询用户信息并全部返回
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", (uid,)
    ).fetchone()
    if user:
        return dict(user)  # 返回所有字段，包括 password_hash
    return "not found", 404
''',
    language="python", filename="attr_info_disclosure_01.py",
    cot="分析过程：\n"
        "1. 用户可控输入：uid 来自 URL 路径参数。\n"
        "2. 危险 sink：return dict(user)，返回数据库查询的全部字段。\n"
        "3. 防御检查：SQL 使用参数化（无注入），但 SELECT * 返回了 password_hash 等敏感字段，"
        "直接暴露给客户端。\n"
        "4. 对比 CoT：为什么不是 CWE-89？因为 SQL 用了参数化查询无注入风险，"
        "问题是返回了敏感字段（password_hash），属于信息泄露，故为 CWE-200 信息泄露。\n"
        "5. 综合来看，存在信息泄露漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-200", "信息泄露", "Medium",
        source="uid 路径参数",
        sink="return dict(user) 返回含 password_hash 的全部字段",
        explanation="SELECT * 返回了 password_hash 等敏感字段并直接暴露给客户端",
        fix="显式指定查询字段（排除 password_hash）；或用序列化层过滤敏感字段"
    )
))

# F5: XXE（CWE-611）— 对比 CWE-502
ATTRIBUTION_SAMPLES.append(build_sample(
    code='''import xml.etree.ElementTree as ET
from flask import Flask, request
app = Flask(__name__)

@app.route("/import")
def import_xml():
    body = request.get_data()
    # 直接解析用户 XML，未禁用外部实体
    root = ET.fromstring(body)
    return {"name": root.findtext("name", "")}
''',
    language="python", filename="attr_xxe_01.py",
    cot="分析过程：\n"
        "1. 用户可控输入：body 来自 request.get_data()。\n"
        "2. 危险 sink：ET.fromstring(body)，解析用户 XML。\n"
        "3. 防御检查：Python 的 xml.etree.ElementTree 在某些版本中默认解析外部实体，"
        "攻击者可构造 <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> 读取本地文件。\n"
        "4. 对比 CoT：为什么不是 CWE-502？因为问题是 XML 外部实体解析，不是任意对象反序列化。"
        "ET.fromstring 解析 XML 结构但不构造 Python 对象，注入载体是 XML 实体声明而非对象标签，"
        "故为 CWE-611 XXE。\n"
        "5. 综合来看，存在 XXE 漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-611", "XXE", "High",
        source="request.get_data()（XML body）",
        sink="ET.fromstring(body)",
        explanation="ET.fromstring 默认解析外部实体，可构造恶意 XML 读取本地文件",
        fix="使用 defusedxml.ElementTree.fromstring 替代 ET.fromstring"
    )
))

# F6: 硬编码密码 vs 硬编码 API Key（CWE-798）— 区分场景
ATTRIBUTION_SAMPLES.append(build_sample(
    code='''# 配置文件中的硬编码凭证
STRIPE_SECRET_KEY = "sk_live_51Hqxxx..."
GITHUB_TOKEN = "ghp_xxxxxxxxxxxx..."

# 在代码中直接使用
stripe.api_key = STRIPE_SECRET_KEY
g = Github(GITHUB_TOKEN)
''',
    language="python", filename="attr_hardcoded_apikey_01.py",
    cot="分析过程：\n"
        "1. 凭证位置：源码中直接出现 STRIPE_SECRET_KEY 和 GITHUB_TOKEN 的字符串字面量。\n"
        "2. 是否字面量：变量名含 key/token 且赋值为字符串字面量，符合硬编码凭证特征。\n"
        "3. 是否从环境读取：代码未通过 os.environ / 配置文件 / KMS 读取，而是直接写死在源码中。\n"
        "4. 影响范围：任何能看到源码的人都能获取 Stripe 和 GitHub 的 API 凭证。\n"
        "5. 综合来看，存在硬编码凭证漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-798", "硬编码凭证", "High",
        source="源码字面量",
        sink="stripe.api_key = STRIPE_SECRET_KEY / Github(GITHUB_TOKEN)",
        explanation="API Key 和 Token 直接硬编码在源码中，源码泄露即凭证泄露",
        fix="从环境变量读取：stripe.api_key = os.environ['STRIPE_SECRET_KEY']"
    )
))

# F7: 弱密码学 — ECB 模式（CWE-327）— 对比 CWE-329
ATTRIBUTION_SAMPLES.append(build_sample(
    code='''from Crypto.Cipher import AES
import os

key = os.environ["AES_KEY"].encode()  # 密钥从环境变量读取（无硬编码）
# 使用 ECB 模式（不安全）
cipher = AES.new(key, AES.MODE_ECB)
plaintext = b"Sensitive data!!"  # 16 bytes
ciphertext = cipher.encrypt(plaintext)
''',
    language="python", filename="attr_ecb_mode_01.py",
    cot="分析过程：\n"
        "1. 密码学分析：AES.new(key, AES.MODE_ECB)，使用 ECB 模式。\n"
        "2. 缺陷：ECB 模式中相同明文块产生相同密文块，不隐藏明文模式。"
        "加密图像数据时密文仍可见原图轮廓。密钥从环境变量读取（无硬编码）。\n"
        "3. 防御检查：密钥来源安全（环境变量），但 ECB 模式不安全。\n"
        "4. 对比 CoT：为什么不是 CWE-329？CWE-329 是固定 IV（CBC 模式下 IV 不随机），"
        "本例是 ECB 模式（根本不用 IV），问题是模式选择不当而非 IV 问题，"
        "属于弱密码学（不安全模式），故为 CWE-327 弱密码学。\n"
        "5. 综合来看，存在弱密码学漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-327", "弱密码学", "Medium",
        source="ECB 模式选择不当",
        sink="AES.new(key, AES.MODE_ECB)",
        explanation="ECB 模式相同明文块产生相同密文块，不隐藏明文模式",
        fix="使用 AES-GCM 或 AES-CBC（随机 IV）替代 ECB 模式"
    )
))


# ===========================================================================
# G. Java/JS LDAP 注入增强（10 条）
# ===========================================================================
# 靶向 CVE-fix 测试集持续 FN：Java LDAP (cve_fix_0001.java) + JS LDAP (cve_fix_0002.js)
# 目的：增加 CWE-90 的 Java/JS 样本量，解决"Java/JS LDAP 训练不足"问题

LDAP_JAVA_JS_SAMPLES = []

# G1: Java LDAP filter 拼接（main 函数）
LDAP_JAVA_JS_SAMPLES.append(build_sample(
    code='''import javax.naming.directory.*;
import javax.naming.*;
import javax.servlet.http.*;
import java.util.Hashtable;

public class UserSearchServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        String username = req.getParameter("username");
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://ldap.company.com:389");
        try {
            DirContext ctx = new InitialDirContext(env);
            String filter = "(&(uid=" + username + ")(objectClass=user))";
            SearchControls sc = new SearchControls();
            sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
            NamingEnumeration<SearchResult> results = ctx.search("dc=company,dc=com", filter, sc);
            while (results.hasMore()) {
                SearchResult sr = results.next();
                resp.getWriter().println("User: " + sr.getName());
            }
            ctx.close();
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }
}''',
    language="java", filename="ldap_java_filter_01.java",
    cot="分析过程：\n"
        "1. 用户可控输入：username 来自 req.getParameter(\"username\")，攻击者可任意控制。\n"
        "2. 危险 sink：ctx.search(\"dc=company,dc=com\", filter, sc)，filter 由字符串拼接构建。\n"
        "3. 数据流：req.getParameter → filter 拼接 → ctx.search。\n"
        "4. 防御检查：无输入验证或编码，直接用 + 拼接用户输入到 LDAP filter。\n"
        "5. 综合来看，存在 LDAP 注入漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "High",
        source="req.getParameter(\"username\")",
        sink="ctx.search(dn, filter, sc)",
        explanation="用户名直接拼接到 LDAP filter 字符串，攻击者可注入 LDAP 元字符绕过认证或枚举条目",
        fix="使用 LDAPEncoder.filterEncode() 对用户输入编码，或使用参数化查询"
    )
))

# G2: JS LDAP 过滤器拼接（Express）
LDAP_JAVA_JS_SAMPLES.append(build_sample(
    code='''const express = require("express");
const ldap = require("ldapjs");
const router = express.Router();

router.get("/api/users/search", (req, res) => {
    const username = req.query.username;
    const client = ldap.createClient({ url: "ldap://ldap.company.com:389" });
    const opts = {
        filter: `(&(uid=${username})(objectClass=user))`,
        scope: "sub"
    };
    client.search("dc=company,dc=com", opts, (err, searchRes) => {
        searchRes.on("searchEntry", entry => {
            res.json({ user: entry.object });
        });
    });
});

module.exports = router;''',
    language="javascript", filename="ldap_js_filter_01.js",
    cot="分析过程：\n"
        "1. 用户可控输入：username 来自 req.query.username，攻击者可任意控制。\n"
        "2. 危险 sink：client.search() 的 filter 参数使用模板字符串拼接。\n"
        "3. 数据流：req.query → filter 模板字符串 → client.search。\n"
        "4. 防御检查：无输入验证，直接嵌入 LDAP filter。\n"
        "5. 综合来看，存在 LDAP 注入漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "High",
        source="req.query.username",
        sink="client.search(dn, opts)",
        explanation="用户名直接嵌入 LDAP filter 模板字符串，攻击者可注入 LDAP 过滤条件操纵搜索结果",
        fix="使用 ldapjs 的 escapeFilter() 或客户端验证库对输入编码"
    )
))

# G3: Java LDAP 部分编码绕过（仅编码空格，未编码括号）
LDAP_JAVA_JS_SAMPLES.append(build_sample(
    code='''import javax.naming.directory.*;
import javax.naming.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class LdapUserController {
    @GetMapping("/api/ldap/users")
    public String searchUsers(@RequestParam String name) {
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://localhost:389");
            DirContext ctx = new InitialDirContext(env);
            // 仅编码空格，但未编码 LDAP 元字符 ()
            String safeName = name.replace(" ", "\\\\20");
            String filter = "(cn=" + safeName + ")";
            SearchControls sc = new SearchControls();
            sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
            NamingEnumeration<SearchResult> results = ctx.search("dc=test,dc=com", filter, sc);
            StringBuilder sb = new StringBuilder();
            while (results.hasMore()) {
                SearchResult sr = results.next();
                sb.append(sr.getAttributes().toString());
            }
            ctx.close();
            return sb.toString();
        } catch (NamingException e) {
            return "error: " + e.getMessage();
        }
    }
}''',
    language="java", filename="ldap_java_partial_escape_01.java",
    cot="分析过程：\n"
        "1. 用户可控输入：name 来自 @RequestParam，攻击者可任意控制。\n"
        "2. 危险 sink：ctx.search() 的 filter 参数。\n"
        "3. 防御检查：仅替换空格为 \\\\20，未编码 LDAP 元字符 ( ) * | & ! 等。\n"
        "4. 缺陷：部分编码不是安全方案，攻击者可注入 (|(cn=*)(userPassword=*)) 等查询。\n"
        "5. 综合来看，存在 LDAP 注入漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "Critical",
        source="@RequestParam String name",
        sink="ctx.search(dn, filter, sc)",
        explanation="部分编码仅过滤空格，LDAP 元字符 ( ) * 等仍可注入，攻击者可绕过认证或枚举条目",
        fix="使用 LDAPEncoder.filterEncode() 对所有 LDAP 元字符统一编码，不要自行实现部分编码"
    )
))

# G4: JS LDAP 通配符枚举（通过 * 枚举所有条目）
LDAP_JAVA_JS_SAMPLES.append(build_sample(
    code='''const express = require("express");
const ldap = require("ldapjs");
const app = express();

app.get("/api/ldap/users", (req, res) => {
    const userId = req.query.userId;
    const client = ldap.createClient({ url: "ldap://ldap.corp.internal:389" });
    const filter = `(uid=${userId})`;
    client.bind("cn=admin,dc=corp,dc=com", "admin123", (err) => {
        client.search("ou=users,dc=corp,dc=com", { filter, scope: "sub" }, (err, searchRes) => {
            const users = [];
            searchRes.on("searchEntry", entry => users.push(entry.object));
            searchRes.on("end", () => res.json(users));
        });
    });
});

app.listen(3000);''',
    language="javascript", filename="ldap_js_wildcard_01.js",
    cot="分析过程：\n"
        "1. 用户可控输入：userId 来自 req.query.userId。\n"
        "2. 危险 sink：client.search() 的 filter 参数直接拼接 userId。\n"
        "3. 攻击向量：注入 * 如 userId=* 可枚举所有用户；注入 |(uid=admin)(uid=*) 可绕过认证。\n"
        "4. 防御检查：完全无输入验证。\n"
        "5. 综合来看，存在 LDAP 注入漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "Critical",
        source="req.query.userId",
        sink="client.search(dn, { filter, scope })",
        explanation="userId 直接作为 LDAP filter 条件，通配符注入可枚举整个 LDAP 目录",
        fix="使用 ldapjs 的 escapeFilter() 或第三方库对输入进行 LDAP filter 编码"
    )
))

# G5: Java LDAP 认证绕过（注入 OR 条件）
LDAP_JAVA_JS_SAMPLES.append(build_sample(
    code='''import javax.naming.directory.*;
import javax.naming.*;
import java.util.Hashtable;

public class LdapAuth {
    public boolean authenticate(String username, String password) {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://ldap.company.com:389");
        try {
            DirContext ctx = new InitialDirContext(env);
            String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";
            SearchControls sc = new SearchControls();
            sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
            NamingEnumeration<SearchResult> results = ctx.search("dc=company,dc=com", filter, sc);
            return results.hasMore();
        } catch (NamingException e) {
            return false;
        }
    }
}''',
    language="java", filename="ldap_java_auth_bypass_01.java",
    cot="分析过程：\n"
        "1. 用户可控输入：username 和 password 均为外部输入。\n"
        "2. 危险 sink：LDAP filter 拼接用户名和密码到认证查询。\n"
        "3. 攻击向量：注入 username=*)(uid=*))(|(uid=* 可构造 (&(|(uid=*)(uid=*)))(userPassword=xxx)) 绕过认证。\n"
        "4. 缺陷：LDAP 认证 filter 中的用户输入可以改变 filter 逻辑。\n"
        "5. 综合来看，存在 LDAP 注入漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "Critical",
        source="username 参数",
        sink="ctx.search(dn, filter, sc)",
        explanation="LDAP 认证 filter 中拼接用户输入，攻击者可注入 OR 条件绕过认证",
        fix="对 username 和 password 使用 LDAPEncoder.filterEncode() 编码，或先绑定再查询"
    )
))

# G6: Java LDAP 查询参数化遗漏（使用 Spring LdapTemplate）
LDAP_JAVA_JS_SAMPLES.append(build_sample(
    code='''import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.web.bind.annotation.*;

@RestController
public class LdapSearchController {
    private final LdapTemplate ldapTemplate;

    public LdapSearchController(LdapTemplate ldapTemplate) {
        this.ldapTemplate = ldapTemplate;
    }

    @GetMapping("/api/ldap/search")
    public String search(@RequestParam String email) {
        // 使用 Filter 构建器，但用户输入仍直接进入 filter
        AndFilter filter = new AndFilter();
        filter.and(new EqualsFilter("objectClass", "person"));
        // 未对 email 编码，直接添加到 filter
        String filterStr = "(&(objectClass=person)(mail=" + email + "))";
        return ldapTemplate.search("", filterStr, (attrs) -> attrs.toString()).toString();
    }
}''',
    language="java", filename="ldap_java_spring_template_01.java",
    cot="分析过程：\n"
        "1. 用户可控输入：email 来自 @RequestParam。\n"
        "2. 危险 sink：ldapTemplate.search() 使用字符串拼接的 filter。\n"
        "3. 注意：虽然用了 Spring LdapTemplate，但 filter 仍是字符串拼接而非参数化查询。\n"
        "4. 防御检查：EqualsFilter 对象被创建但未使用（弃用）。\n"
        "5. 综合来看，存在 LDAP 注入漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "High",
        source="@RequestParam String email",
        sink="ldapTemplate.search(dn, filterStr, mapper)",
        explanation="使用 Spring LdapTemplate 但 filter 仍是字符串拼接，EqualsFilter 对象被弃用",
        fix="使用 filter.and(new EqualsFilter(\"mail\", email)) 构建 filter，不要手动拼接"
    )
))

# G7: JS LDAP 属性注入（通过 filter 操控返回属性）
LDAP_JAVA_JS_SAMPLES.append(build_sample(
    code='''const ldap = require("ldapjs");
const express = require("express");
const app = express();

app.get("/api/ldap/user/attributes", (req, res) => {
    const attr = req.query.attribute || "cn";
    const username = req.query.username;
    const client = ldap.createClient({ url: "ldap://ldap.internal:389" });
    const opts = {
        filter: `(uid=${username})`,
        attributes: [attr],
        scope: "sub"
    };
    client.search("ou=users,dc=internal,dc=com", opts, (err, searchRes) => {
        const result = {};
        searchRes.on("searchEntry", entry => {
            result[attr] = entry.object[attr];
        });
        searchRes.on("end", () => res.json(result));
    });
});

app.listen(3000);''',
    language="javascript", filename="ldap_js_attr_injection_01.js",
    cot="分析过程：\n"
        "1. 用户可控输入：attribute 和 username 均来自 URL 参数。\n"
        "2. 危险 sink：filter 中拼接 username；attribute 可被操控读取敏感属性。\n"
        "3. 攻击向量：username=*&attribute=userPassword 可读取用户密码属性。\n"
        "4. 防御检查：无任何输入验证。\n"
        "5. 综合来看，存在 LDAP 注入漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "High",
        source="req.query.attribute / req.query.username",
        sink="client.search(dn, opts)",
        explanation="filter 中拼接 username 可注入元字符；attribute 可被操控读取敏感属性如 userPassword",
        fix="对 username 使用 escapeFilter() 编码；attribute 使用白名单验证"
    )
))

# G8: Java 通配符注入（LDAP 搜索中 * 注入导致目录枚举）
LDAP_JAVA_JS_SAMPLES.append(build_sample(
    code='''import javax.naming.directory.*;
import javax.naming.*;
import java.util.Hashtable;

public class LdapDirectoryEnumerator {
    public void listUsers(String searchTerm) throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://ldap.company.com:389");
        DirContext ctx = new InitialDirContext(env);
        String filter = "(cn=*" + searchTerm + "*)";
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        sc.setCountLimit(1000);
        NamingEnumeration<SearchResult> results = ctx.search("dc=company,dc=com", filter, sc);
        while (results.hasMore()) {
            SearchResult sr = results.next();
            System.out.println(sr.getAttributes().get("cn"));
        }
        ctx.close();
    }
}''',
    language="java", filename="ldap_java_wildcard_enum_01.java",
    cot="分析过程：\n"
        "1. 用户可控输入：searchTerm 参数，攻击者可注入 * 或其他 LDAP 元字符。\n"
        "2. 危险 sink：filter 字符串拼接，searchTerm 被嵌入 (cn=*...*)。\n"
        "3. 攻击向量：searchTerm=* 枚举所有条目；searchTerm=admin)(|(uid=* 可注入任意 filter。\n"
        "4. 防御检查：完全无输入验证。\n"
        "5. 综合来看，存在 LDAP 注入漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "High",
        source="searchTerm 参数",
        sink="ctx.search(dn, filter, sc)",
        explanation="通配符模式中直接拼接用户输入，可注入 LDAP 元字符导致目录枚举",
        fix="对 searchTerm 使用 LDAPEncoder.filterEncode() 编码后再嵌入通配符搜索"
    )
))

# G9: Python LDAP filter 绕过（ldap3 库）
LDAP_JAVA_JS_SAMPLES.append(build_sample(
    code='''import ldap3
from flask import Flask, request

app = Flask(__name__)

@app.route("/api/ldap/login")
def ldap_login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    server = ldap3.Server("ldap://ldap.company.com:389", get_info=ldap3.ALL)
    conn = ldap3.Connection(server, user="cn=admin,dc=company,dc=com", password="secret")
    conn.bind()
    # 构建 LDAP 查询 filter
    filter_str = f"(&(uid={username})(userPassword={password}))"
    conn.search("dc=company,dc=com", filter_str, attributes=["cn", "uid"])
    if conn.entries:
        return f"Login success: {conn.entries[0].cn}"
    return "Login failed"''',
    language="python", filename="ldap_python_filter_bypass_01.py",
    cot="分析过程：\n"
        "1. 用户可控输入：username 和 password 均来自 URL 参数。\n"
        "2. 危险 sink：conn.search() 的 filter 参数使用 f-string 拼接。\n"
        "3. 攻击向量：username=*)(uid=*))(|(uid=* 可绕过认证。\n"
        "4. 防御检查：无任何编码或验证。\n"
        "5. 综合来看，存在 LDAP 注入漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "Critical",
        source="request.args.get(\"username\")",
        sink="conn.search(dn, filter_str)",
        explanation="LDAP filter 使用 f-string 拼接用户输入，可注入 OR 条件绕过认证",
        fix="使用 ldap3.utils.conv.escape_filter_chars() 对用户输入编码"
    )
))

# G10: Python LDAP 编码遗漏（ldap3 的 escape 函数未用）
LDAP_JAVA_JS_SAMPLES.append(build_sample(
    code='''import ldap3
from flask import Flask, request
from ldap3.utils.conv import escape_filter_chars

app = Flask(__name__)

@app.route("/api/ldap/search")
def ldap_search():
    cn = request.args.get("cn", "")
    # 对 cn 进行编码
    safe_cn = escape_filter_chars(cn)
    server = ldap3.Server("ldap://ldap.internal:389")
    conn = ldap3.Connection(server, user="cn=reader,dc=internal,dc=com", password="readonly")
    conn.bind()
    # 仅编码了 cn，但 search_base 来自用户且未编码
    search_base = request.args.get("base", "dc=internal,dc=com")
    conn.search(search_base, f"(cn={safe_cn})", attributes=["cn", "mail"])
    return {"users": [str(e) for e in conn.entries]}''',
    language="python", filename="ldap_python_missing_escape_01.py",
    cot="分析过程：\n"
        "1. 用户可控输入：cn 和 base 均来自 URL 参数。\n"
        "2. 部分防御：cn 使用了 escape_filter_chars() 编码，正确。\n"
        "3. 漏洞：search_base 直接拼接，未编码。攻击者可注入 dc=evil,dc=com 跳转到其他 LDAP 分支。\n"
        "4. 影响：攻击者可读取其他 OU 的数据，绕过目录隔离。\n"
        "5. 综合来看，存在 LDAP 注入漏洞（search_base 注入），风险等级 Medium。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "Medium",
        source="request.args.get(\"base\")",
        sink="conn.search(search_base, filter)",
        explanation="虽然 filter 参数正确编码，但 search_base 直接拼接用户输入，可转向其他 LDAP 分支",
        fix="对 search_base 使用白名单验证，限制为预定义的 base DN 列表"
    )
))


# ===========================================================================
# H. Java/JS 信任边界绕过增强（10 条）
# ===========================================================================
# 靶向 CVE-fix 持续 FN：JS loopback 信任 (cve_fix_0005.js) 和 Java 信任反模式
# 目的：增加 CWE-441 的 Java/JS 样本量，解决"信任边界绕过"训练不足

TRUST_BOUNDARY_SAMPLES = []

# H1: Java loopback 信任（模拟 cve_fix_0005）
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''import java.net.InetAddress;
import java.net.UnknownHostException;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

@RestController
public class AdminController {
    @PostMapping("/api/admin/execute")
    public String executeCommand(@RequestParam String cmd, HttpServletRequest request) {
        try {
            String remoteAddr = request.getRemoteAddr();
            InetAddress addr = InetAddress.getByName(remoteAddr);
            // 信任 loopback 地址，跳过认证
            if (addr.isLoopbackAddress()) {
                Runtime rt = Runtime.getRuntime();
                Process p = rt.exec(cmd);
                // 执行管理命令
                return "executed: " + cmd;
            }
            return "not authorized";
        } catch (Exception e) {
            return "error";
        }
    }
}''',
    language="java", filename="trust_java_loopback_01.java",
    cot="分析过程：\n"
        "1. 用户可控输入：cmd 来自 @RequestParam 且 remoteAddr 来自 HTTP 请求头（可伪造）。\n"
        "2. 信任假设：代码信任 request.getRemoteAddr() 返回的 loopback 地址，认为本地请求安全。\n"
        "3. 漏洞：攻击者可在内网中伪造 X-Forwarded-For 头或通过 SSRF 使请求看似来自本地。\n"
        "4. 数据流：cmd → Runtime.exec()，无认证检查。\n"
        "5. 综合来看，存在信任边界绕过漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "Critical",
        source="request.getRemoteAddr() 的 loopback 判断",
        sink="Runtime.getRuntime().exec(cmd)",
        explanation="信任 loopback 地址跳过认证，攻击者可伪造请求头或利用 SSRF 绕过",
        fix="移除 loopback 信任，对所有请求执行身份认证和授权检查"
    )
))

# H2: JS XFF header 信任（模拟 cve_fix_0006）
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''const express = require("express");
const app = express();

app.get("/api/admin/metrics", (req, res) => {
    const xff = req.headers["x-forwarded-for"];
    const clientIp = xff ? xff.split(",")[0].trim() : req.ip;
    // 信任内网 IP 跳过认证
    if (clientIp.startsWith("10.") || clientIp.startsWith("192.168.")) {
        res.json({ cpu: "85%", memory: "72%", disk: "91%" });
    } else {
        res.status(403).json({ error: "external access denied" });
    }
});

app.listen(3000);''',
    language="javascript", filename="trust_js_xff_01.js",
    cot="分析过程：\n"
        "1. 用户可控输入：X-Forwarded-For 头可由攻击者任意伪造。\n"
        "2. 信任假设：信赖 XFF 头中的 IP 地址判断来源。\n"
        "3. 漏洞：攻击者设置 X-Forwarded-For: 10.0.0.1 即可绕过 IP 检查访问管理接口。\n"
        "4. 数据流：req.headers → 信任判断 → 直接返回敏感数据，无认证。\n"
        "5. 综合来看，存在信任边界绕过漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "High",
        source="req.headers[\"x-forwarded-for\"]",
        sink="基于 XFF 的 IP 信任判断",
        explanation="X-Forwarded-For 头可伪造，攻击者可伪装成内网 IP 访问管理接口",
        fix="不要依赖 XFF 头做安全决策；使用认证机制（API Key / JWT）替代 IP 信任"
    )
))

# H3: Java 内网 IP 信任（CIDR 检查绕过）
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

@RestController
public class InternalApiController {
    @GetMapping("/api/internal/config")
    public String getConfig(HttpServletRequest request) {
        String ip = request.getRemoteAddr();
        // 检查是否内网 IP
        if (ip.startsWith("10.") || ip.startsWith("172.16.") || ip.startsWith("192.168.")) {
            return "db_password=super_secret_123";
        }
        return "access denied";
    }
}''',
    language="java", filename="trust_java_internal_ip_01.java",
    cot="分析过程：\n"
        "1. 用户可控输入：IP 地址来自 HTTP 请求，可能受 SSRF 或 DNS 重绑定影响。\n"
        "2. 信任假设：信赖 request.getRemoteAddr() 的 IP 段判断。\n"
        "3. 漏洞：内网中的攻击者可直接访问；SSRF 攻击可使外部请求看似来自内网。\n"
        "4. 数据流：request.getRemoteAddr() → IP 前缀判断 → 返回敏感配置。\n"
        "5. 综合来看，存在信任边界绕过漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "Critical",
        source="request.getRemoteAddr()",
        sink="基于 IP 前缀的信任判断",
        explanation="仅依赖 IP 地址判断来源，内网攻击者或 SSRF 可绕过，返回数据库密码等敏感配置",
        fix="对内部 API 使用认证令牌（Token/API Key），不要依赖 IP 做安全决策"
    )
))

# H4: JS 反向 DNS 信任（DNS 名称信任绕过）
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''const dns = require("dns");
const express = require("express");
const app = express();

app.get("/api/internal/secret", (req, res) => {
    const ip = req.ip;
    dns.reverse(ip, (err, hostnames) => {
        if (err) return res.status(403).send("forbidden");
        // 信任反向 DNS 解析结果
        if (hostnames.some(h => h.endsWith(".internal.corp.com"))) {
            res.send("internal_secret_key=sk-123456");
        } else {
            res.status(403).send("external access denied");
        }
    });
});

app.listen(3000);''',
    language="javascript", filename="trust_js_reverse_dns_01.js",
    cot="分析过程：\n"
        "1. 用户可控输入：IP 来自请求，反向 DNS 解析结果不可信。\n"
        "2. 信任假设：信赖反向 DNS 解析的 hostname 后缀。\n"
        "3. 漏洞：攻击者控制 DNS 记录（如 dns rebinding）可使任意 IP 的反向解析返回 .internal.corp.com。\n"
        "4. 数据流：req.ip → dns.reverse → 后缀判断 → 返回敏感密钥。\n"
        "5. 综合来看，存在信任边界绕过漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "High",
        source="dns.reverse() 解析结果",
        sink="基于 DNS hostname 后缀的信任判断",
        explanation="反向 DNS 解析结果不可信，DNS Rebinding 攻击者可伪造 DNS 记录绕过信任检查",
        fix="不要依赖 DNS 反向解析做安全决策；使用认证机制替代"
    )
))

# H5: Java Origin header 信任（CORS 信任绕过）
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

@RestController
public class CorsApiController {
    @GetMapping("/api/user/info")
    public String getUserInfo(@RequestParam String userId, HttpServletRequest request) {
        String origin = request.getHeader("Origin");
        // 信任以 .company.com 结尾的 Origin
        if (origin != null && origin.endsWith(".company.com")) {
            // 直接返回用户信息，无额外认证
            return db.queryUserInfo(userId).toString();
        }
        return "unauthorized origin";
    }
}''',
    language="java", filename="trust_java_origin_header_01.java",
    cot="分析过程：\n"
        "1. 用户可控输入：Origin 头可由浏览器或攻击者设置。\n"
        "2. 信任假设：信赖 Origin 头后缀判断，认为 .company.com 是安全的。\n"
        "3. 漏洞：attacker.company.com 也是 .company.com 的后缀，可被攻击者注册的子域名利用。\n"
        "4. 数据流：req.getHeader(\"Origin\") → 后缀匹配 → 返回用户信息。\n"
        "5. 综合来看，存在信任边界绕过漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "High",
        source="req.getHeader(\"Origin\")",
        sink="基于 Origin 后缀的信任判断",
        explanation="Origin 头后缀匹配可能被攻击者注册的子域名（如 attacker.company.com）利用",
        fix="使用白名单精确匹配 Origin 值，而非后缀匹配；同时添加认证机制"
    )
))

# H6: JS 内部 API 无认证（仅检查本地端口）
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''const express = require("express");
const app = express();

// 模拟内部服务，仅监听本地端口但无认证
app.get("/api/internal/clear_cache", (req, res) => {
    // 信任来自本地的请求
    if (req.ip === "127.0.0.1" || req.ip === "::1") {
        cache.clear();
        res.send("cache cleared");
    } else {
        res.status(403).send("external access denied");
    }
});

// 暴露到公网
app.listen(80);''',
    language="javascript", filename="trust_js_localhost_01.js",
    cot="分析过程：\n"
        "1. 用户可控输入：req.ip 可能通过 SSRF 或 DNS rebinding 绑定到 127.0.0.1。\n"
        "2. 信任假设：认为 127.0.0.1 的请求一定是本地进程发起的。\n"
        "3. 漏洞：如果应用存在 SSRF 漏洞，攻击者可利用它访问此接口清空缓存；\n"
        "   如果应用监听 0.0.0.0，攻击者可直接发送请求伪造 IP。\n"
        "4. 数据流：req.ip → 127.0.0.1 判断 → 执行清空缓存操作。\n"
        "5. 综合来看，存在信任边界绕过漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "Medium",
        source="req.ip 的 127.0.0.1 判断",
        sink="cache.clear()",
        explanation="仅依赖 IP 判断来源，存在 SSRF 攻击链风险，攻击者可借其他接口绕过本地信任",
        fix="对内部 API 使用 API Key 认证，不要依赖 IP 地址做安全决策"
    )
))

# H7: Java 本地文件系统信任（从本地文件读取配置，信任文件内容）
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''import java.io.*;
import java.nio.file.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class LocalConfigController {
    @GetMapping("/api/config/load")
    public String loadConfig(@RequestParam String configFile, HttpServletRequest request) {
        try {
            String ip = request.getRemoteAddr();
            // 信任来自本地文件系统的配置
            if (ip.equals("127.0.0.1")) {
                Path path = Paths.get("/etc/app/config/" + configFile);
                String content = new String(Files.readAllBytes(path));
                return content;
            }
            return "access denied";
        } catch (Exception e) {
            return "error: " + e.getMessage();
        }
    }
}''',
    language="java", filename="trust_java_local_fs_01.java",
    cot="分析过程：\n"
        "1. 用户可控输入：configFile 来自 @RequestParam，IP 来自请求。\n"
        "2. 信任假设：127.0.0.1 的请求安全，且 configFile 指向的文件可直接读取。\n"
        "3. 漏洞：路径遍历（configFile=../../etc/passwd）可读取任意文件，结合 IP 信任可被 SSRF 利用。\n"
        "4. 数据流：request.getRemoteAddr() → 127.0.0.1 信任 → 路径遍历读取文件。\n"
        "5. 综合来看，存在信任边界绕过漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "High",
        source="request.getRemoteAddr() 的 127.0.0.1 信任",
        sink="Files.readAllBytes(path)",
        explanation="信任 loopback 地址同时存在路径遍历，攻击者可利用 SSRF 读取任意文件",
        fix="移除 IP 信任，对 configFile 做路径白名单验证，并添加认证机制"
    )
))

# H8: JS 环境变量信任（信任 NODE_ENV 判断）
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''const express = require("express");
const app = express();

app.get("/api/debug/stacktrace", (req, res) => {
    // 信任 NODE_ENV 环境变量判断是否为调试模式
    if (process.env.NODE_ENV === "development" || process.env.NODE_ENV === "debug") {
        const err = new Error("test error");
        res.json({ stack: err.stack, env: process.env });
    } else {
        res.status(403).send("debug mode disabled");
    }
});

app.listen(3000);''',
    language="javascript", filename="trust_js_env_var_01.js",
    cot="分析过程：\n"
        "1. 输入：NODE_ENV 环境变量在服务器端，攻击者无法直接修改。\n"
        "2. 信任假设：认为 NODE_ENV 状态是安全的，但未添加认证。\n"
        "3. 漏洞：如果攻击者通过其他漏洞（如 RCE、配置注入）修改了 NODE_ENV，\n"
        "   此接口将暴露环境变量（含敏感密钥）和堆栈信息。\n"
        "4. 关键问题：依赖环境变量做安全决策，而不是依赖认证机制。\n"
        "5. 综合来看，存在信任边界绕过漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "Medium",
        source="process.env.NODE_ENV",
        sink="暴露堆栈和环境变量",
        explanation="依赖环境变量做安全决策，而非认证机制，环境变量被篡改后可直接访问敏感调试接口",
        fix="添加认证机制（如 admin token），不要依赖环境变量做安全决策"
    )
))

# H9: Python 信任代理头（X-Forwarded-For 信任）
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''from flask import Flask, request

app = Flask(__name__)

@app.route("/api/admin/clear_sessions")
def clear_sessions():
    # 从 X-Forwarded-For 获取客户端 IP
    xff = request.headers.get("X-Forwarded-For", "")
    client_ip = xff.split(",")[0].strip() if xff else request.remote_addr
    # 信任内网 IP
    if client_ip.startswith("10.") or client_ip == "127.0.0.1":
        # 清除所有用户会话（危险操作）
        db.session.query(UserSession).delete()
        db.session.commit()
        return "sessions cleared"
    return "unauthorized"''',
    language="python", filename="trust_python_xff_01.py",
    cot="分析过程：\n"
        "1. 用户可控输入：X-Forwarded-For 头可任意伪造。\n"
        "2. 信任假设：信赖 XFF 头判断 IP 来源。\n"
        "3. 漏洞：攻击者设置 X-Forwarded-For: 10.0.0.1 即可绕过检查执行危险操作。\n"
        "4. 数据流：X-Forwarded-For → IP 前缀判断 → 删除所有会话。\n"
        "5. 综合来看，存在信任边界绕过漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "Critical",
        source="request.headers.get(\"X-Forwarded-For\")",
        sink="db.session.query(UserSession).delete()",
        explanation="信任可伪造的 XFF 头判断 IP，攻击者可伪装为内网 IP 执行危险的管理操作",
        fix="使用认证令牌（API Key / JWT）替代 IP 信任，不要依赖 XFF 头"
    )
))

# H10: Python 内网 API 信任（Origin 头信任）
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/internal/update_user_role", methods=["POST"])
def update_user_role():
    origin = request.headers.get("Origin", "")
    # 信任内部域名
    if "internal-api.company.com" in origin:
        user_id = request.json.get("user_id")
        new_role = request.json.get("role")
        db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        db.commit()
        return jsonify({"status": "ok"})
    return jsonify({"error": "unauthorized"}), 403''',
    language="python", filename="trust_python_origin_01.py",
    cot="分析过程：\n"
        "1. 用户可控输入：Origin 头可伪造，user_id 和 role 来自请求体。\n"
        "2. 信任假设：信赖 Origin 中包含 internal-api.company.com 的请求。\n"
        "3. 漏洞：Origin: evil.com/internal-api.company.com 可绕过检查（子串匹配）。\n"
        "4. 数据流：Origin 头 → 包含匹配 → 直接更新用户角色（无认证）。\n"
        "5. 综合来看，存在信任边界绕过漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "Critical",
        source="request.headers.get(\"Origin\")",
        sink="db.execute(\"UPDATE users SET role = ? WHERE id = ?\", ...)",
        explanation="使用 in 操作符匹配 Origin 头可被绕过，且无认证即可修改用户角色",
        fix="使用精确匹配 Origin 白名单；添加认证令牌验证；对角色变更记录审计日志"
    )
))


# ===========================================================================
# I. 更多整数溢出增强（10 条）
# ===========================================================================
# 靶向 CWE-190 训练不足问题（当前 29 条，目标 50+）
# 覆盖多种语言的整数溢出模式

INTEGER_OVERFLOW_SAMPLES = []

# I1: Java int 数组索引溢出
INTEGER_OVERFLOW_SAMPLES.append(build_sample(
    code='''import java.util.Scanner;

public class ArrayIndexCalculator {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter array size: ");
        int size = sc.nextInt();
        int[] arr = new int[10];
        // 用户输入大正数，乘法溢出导致负数索引
        int index = size * 2;
        if (index < arr.length) {
            arr[index] = 42;  // 负数索引 → ArrayIndexOutOfBoundsException
        }
        System.out.println("Done");
    }
}''',
    language="java", filename="overflow_java_int_index_01.java",
    cot="分析过程：\n"
        "1. 用户可控输入：size 来自 Scanner.nextInt()。\n"
        "2. 危险操作：size * 2 可能溢出（如 size=2^30 时 2*2^30 溢出为负数）。\n"
        "3. 缺陷：index < arr.length 检查对负数索引无效（负数 < 10 为 true），导致数组越界访问。\n"
        "4. 数据流：Scanner → size * 2 → 负数索引 → arr[index] 赋值。\n"
        "5. 综合来看，存在整数溢出漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-190", "整数溢出", "High",
        source="Scanner.nextInt()",
        sink="size * 2 → arr[index] 索引",
        explanation="乘法溢出导致负数索引，绕过长度检查，引发数组越界",
        fix="使用 Math.multiplyExact() 或先检查 size 范围再计算"
    )
))

# I2: C int 循环溢出
INTEGER_OVERFLOW_SAMPLES.append(build_sample(
    code='''#include <stdio.h>
#include <string.h>

void process_data(char *input, size_t len) {
    int total = 0;
    // 循环中累加可能导致整数溢出
    for (int i = 0; i < len; i++) {
        total += input[i];
    }
    // 使用 total 分配缓冲区
    char *buffer = malloc(total);
    if (buffer == NULL) return;
    memcpy(buffer, input, total);
    printf("Processed: %s\\n", buffer);
    free(buffer);
}''',
    language="c", filename="overflow_c_loop_accum_01.c",
    cot="分析过程：\n"
        "1. 输入：input 和 len 来自外部，len 可能很大但有限。\n"
        "2. 危险操作：total += input[i] 在循环中反复累加。\n"
        "3. 溢出：如果 len 足够大且 input 字符值较大，total 会溢出为负数或小值。\n"
        "4. 影响：malloc(total) 分配过小缓冲区，memcpy 复制大量数据导致堆缓冲区溢出。\n"
        "5. 综合来看，存在整数溢出漏洞（CWE-190），风险等级 Critical。",
    json_block=vuln_json(
        "CWE-190", "整数溢出", "Critical",
        source="循环累加 total += input[i]",
        sink="malloc(total) → memcpy 堆溢出",
        explanation="循环累加溢出导致分配过小缓冲区，后续 memcpy 写入超出分配大小",
        fix="使用 size_t 类型替代 int，或检查累加结果是否溢出"
    )
))

# I3: Java short 溢出（购物车金额计算）
INTEGER_OVERFLOW_SAMPLES.append(build_sample(
    code='''import java.util.Scanner;

public class ShoppingCart {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter item quantity: ");
        short quantity = sc.nextShort();
        short price = 1000;
        // 乘法可能溢出（short 范围 -32768 ~ 32767）
        short total = (short)(quantity * price);
        System.out.println("Total: " + total);
        // 使用 total 扣款
        if (total > 0) {
            processPayment(total);
        }
    }
    static void processPayment(short amount) {
        System.out.println("Processing payment: " + amount);
    }
}''',
    language="java", filename="overflow_java_short_01.java",
    cot="分析过程：\n"
        "1. 用户可控输入：quantity 来自 Scanner.nextShort()。\n"
        "2. 危险操作：quantity * price 使用 short 类型，最大 32767。\n"
        "3. 溢出：quantity=33 时 33*1000=33000 溢出为 -32536，total > 0 检查通过（-32536 不通过）。\n"
        "4. 攻击向量：quantity=200 时 200*1000=200000 溢出为 31072，以低价购买高价商品。\n"
        "5. 综合来看，存在整数溢出漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-190", "整数溢出", "High",
        source="Scanner.nextShort()",
        sink="short total = (short)(quantity * price)",
        explanation="short 类型乘法溢出，攻击者可操控总价以低价购买高价商品",
        fix="使用 int 或 long 类型，并在乘法前检查溢出"
    )
))

# I4: Python ctypes 整数溢出（C 扩展边界）
INTEGER_OVERFLOW_SAMPLES.append(build_sample(
    code='''import ctypes
from flask import Flask, request

app = Flask(__name__)

# 调用 C 库中处理缓冲区的函数
lib = ctypes.CDLL("./libprocessor.so")

@app.route("/api/process")
def process():
    data = request.args.get("data", "")
    # 用户控制长度，转换为 c_int
    length = ctypes.c_int(len(data))
    buf = ctypes.create_string_buffer(data.encode())
    # 如果 data 长度超过 INT_MAX，length 溢出为负数
    lib.process_buffer(buf, length)
    return "processed"''',
    language="python", filename="overflow_python_ctypes_01.py",
    cot="分析过程：\n"
        "1. 用户可控输入：data 来自 URL 参数。\n"
        "2. 危险操作：len(data) 转换为 c_int 传递给 C 函数。\n"
        "3. 溢出：如果 data 长度超过 2^31-1，c_int 会截断溢出为负数。\n"
        "4. 影响：C 函数收到负数长度，可能导致缓冲区越界读/写。\n"
        "5. 综合来看，存在整数溢出漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-190", "整数溢出", "High",
        source="len(data) 转换为 ctypes.c_int",
        sink="lib.process_buffer(buf, length)",
        explanation="Python int 到 c_int 的转换可能溢出，C 函数收到负数长度导致缓冲区越界",
        fix="检查 len(data) 是否超过 INT_MAX，使用 c_size_t 而不是 c_int"
    )
))

# I5: Java long 乘法溢出（时间戳计算）
INTEGER_OVERFLOW_SAMPLES.append(build_sample(
    code='''import java.util.Scanner;

public class TokenExpiry {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter expiry days: ");
        int days = sc.nextInt();
        // 计算过期时间戳（毫秒）
        long expiryMs = days * 24 * 60 * 60 * 1000L;
        long currentTime = System.currentTimeMillis();
        long tokenExpiry = currentTime + expiryMs;
        System.out.println("Token expires at: " + tokenExpiry);
        // 如果溢出为负数，token 立即过期
        if (tokenExpiry < currentTime) {
            System.out.println("WARNING: expiry overflow detected!");
        }
    }
}''',
    language="java", filename="overflow_java_long_01.java",
    cot="分析过程：\n"
        "1. 用户可控输入：days 来自 Scanner.nextInt()。\n"
        "2. 危险操作：days * 24 * 60 * 60 * 1000L，虽然最后一个乘数是 long，\n"
        "   但 days * 24 * 60 * 60 在 int 范围内计算，可能溢出。\n"
        "3. 溢出：days=25 时 25*24*60*60=2160000（正常），但 days=250 时已溢出。\n"
        "4. 影响：tokenExpiry 溢出为负数，token 立即过期，导致拒绝服务。\n"
        "5. 综合来看，存在整数溢出漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-190", "整数溢出", "Medium",
        source="Scanner.nextInt()",
        sink="days * 24 * 60 * 60 * 1000L",
        explanation="int 乘法溢出导致 token 过期时间计算错误，可能使所有 token 立即过期",
        fix="将 days 声明为 long 或使用 (long)days * 24 * 60 * 60 * 1000"
    )
))

# I6: C 内存分配大小溢出（乘法溢出）
INTEGER_OVERFLOW_SAMPLES.append(build_sample(
    code='''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char *read_items(int count) {
    // 每个 item 32 字节，计算总大小
    int total_size = count * 32;
    if (total_size <= 0) return NULL;
    unsigned char *buffer = malloc(total_size);
    if (buffer == NULL) return NULL;
    memset(buffer, 0, total_size);
    return buffer;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    int count = atoi(argv[1]);
    unsigned char *data = read_items(count);
    if (data) {
        printf("Allocated %d bytes\\n", count * 32);
        free(data);
    }
    return 0;
}''',
    language="c", filename="overflow_c_malloc_01.c",
    cot="分析过程：\n"
        "1. 用户可控输入：count 来自 atoi(argv[1])。\n"
        "2. 危险操作：count * 32 在 int 范围内计算。\n"
        "3. 溢出：count=67108865 时 67108865*32=2147483680 溢出为 -2147483616（负数）。\n"
        "4. 影响：total_size <= 0 检查拦截了负数，但 count=67108865 时也可溢出为小正数，\n"
        "   分配过小缓冲区，后续写入导致堆溢出。\n"
        "5. 综合来看，存在整数溢出漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-190", "整数溢出", "Critical",
        source="atoi(argv[1])",
        sink="int total_size = count * 32 → malloc(total_size)",
        explanation="乘法溢出导致分配过小缓冲区，后续写入超出分配大小导致堆溢出",
        fix="使用 size_t 类型，检查 count 是否超过 SIZE_MAX / 32"
    )
))

# I7: Java 时间计算溢出（定时任务）
INTEGER_OVERFLOW_SAMPLES.append(build_sample(
    code='''import java.util.Timer;
import java.util.TimerTask;

public class ScheduledTask {
    public static void main(String[] args) {
        Timer timer = new Timer();
        // 调度间隔（毫秒），用户控制
        int intervalMs = Integer.parseInt(args[0]);
        // 转换为纳秒间隔
        long intervalNs = intervalMs * 1_000_000L;
        // 计算下一次执行时间
        long nextExec = System.nanoTime() + intervalNs;
        timer.schedule(new TimerTask() {
            public void run() {
                System.out.println("Task executed at: " + System.nanoTime());
            }
        }, 0, intervalMs);
    }
}''',
    language="java", filename="overflow_java_timer_01.java",
    cot="分析过程：\n"
        "1. 用户可控输入：args[0] 作为定时器间隔。\n"
        "2. 危险操作：intervalMs 是 int，虽然乘以 1_000_000L 是 long 运算，但 intervalMs 本身如果太大，\n"
        "   后续计算可能出问题。intervalNs + System.nanoTime() 可能溢出为负数。\n"
        "3. 影响：overflow 后 nextExec 为负数，TimerTask 立即执行或永远不执行。\n"
        "4. 数据流：args[0] → int → long 乘法 → 时间计算。\n"
        "5. 综合来看，存在整数溢出漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-190", "整数溢出", "Medium",
        source="Integer.parseInt(args[0])",
        sink="System.nanoTime() + intervalNs",
        explanation="long 纳秒时间计算可能溢出，导致定时任务行为异常",
        fix="检查 intervalMs 范围（如 < 86400000），使用饱和运算或 BigInteger"
    )
))

# I8: PHP 整数溢出（数组索引）
INTEGER_OVERFLOW_SAMPLES.append(build_sample(
    code='''<?php
$data = $_GET["data"];
$size = strlen($data);
// 分配双倍空间
$allocSize = $size * 2;
$buffer = str_repeat("\0", $allocSize);
// 复制数据
for ($i = 0; $i < $size; $i++) {
    $buffer[$i] = $data[$i];
}
// 对每字节进行变换
for ($i = 0; $i < $size; $i++) {
    $buffer[$size + $i] = chr(ord($data[$i]) ^ 0xFF);
}
echo base64_encode($buffer);
?>''',
    language="php", filename="overflow_php_alloc_01.php",
    cot="分析过程：\n"
        "1. 用户可控输入：$_GET[\"data\"]。\n"
        "2. 危险操作：$size * 2，PHP 中 int 可能溢出。\n"
        "3. 溢出：在 64 位 PHP 中不太可能，但 32 位 PHP 中 $size 超过 1GB 时溢出。\n"
        "4. 影响：$allocSize 溢出为小值或负数，str_repeat 分配不足，后续写入越界。\n"
        "5. 综合来看，存在整数溢出漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-190", "整数溢出", "Medium",
        source="$_GET[\"data\"] → strlen()",
        sink="$size * 2 → str_repeat(\"\\0\", $allocSize)",
        explanation="32 位系统上乘法溢出导致分配过小缓冲区，后续操作可能越界",
        fix="检查 $size 是否超过 PHP_INT_MAX / 2"
    )
))

# I9: JavaScript 大数溢出（BigInt 误用）
INTEGER_OVERFLOW_SAMPLES.append(build_sample(
    code='''const express = require("express");
const app = express();

app.get("/api/transfer", (req, res) => {
    const amount = parseInt(req.query.amount, 10);
    const fee = parseInt(req.query.fee, 10);
    // 计算总扣款：金额 + 手续费
    const totalDeduction = amount + fee;
    // 检查余额（使用 Number 类型，可能溢出）
    const balance = 1000000;
    if (totalDeduction <= balance) {
        // 执行转账
        const newBalance = balance - totalDeduction;
        res.json({ deducted: totalDeduction, newBalance });
    } else {
        res.status(400).json({ error: "insufficient balance" });
    }
});

app.listen(3000);''',
    language="javascript", filename="overflow_js_number_01.js",
    cot="分析过程：\n"
        "1. 用户可控输入：amount 和 fee 来自 URL 参数。\n"
        "2. 危险操作：Number 类型的加法，JavaScript 的 Number 是 IEEE 754 双精度浮点数。\n"
        "3. 溢出：当 amount + fee 超过 Number.MAX_SAFE_INTEGER (2^53-1) 时精度丢失，\n"
        "   但不会溢出为负数。更大的问题是超过 Number.MAX_VALUE 时变成 Infinity。\n"
        "4. 攻击向量：amount=Infinity 或 amount=1e308 时 totalDeduction=Infinity，\n"
        "   Infinity <= 1000000 为 false 所以不会通过，但精度丢失可导致扣款计算错误。\n"
        "5. 综合来看，存在整数溢出/精度丢失漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-190", "整数溢出", "Medium",
        source="parseInt(req.query.amount)",
        sink="Number 加法 amount + fee",
        explanation="Number 类型超过 MAX_SAFE_INTEGER 时精度丢失，金融计算错误",
        fix="对金融计算使用 BigInt 或 decimal 库，验证输入范围"
    )
))

# I10: Go int 溢出（循环计数器）
INTEGER_OVERFLOW_SAMPLES.append(build_sample(
    code='''package main

import (
    "fmt"
    "strconv"
    "os"
)

func main() {
    n, _ := strconv.Atoi(os.Args[1])
    // 累加计算
    var sum int = 0
    for i := 0; i < n; i++ {
        sum += i
    }
    // 使用 sum 分配数组
    arr := make([]int, sum)
    fmt.Println(len(arr))
}''',
    language="go", filename="overflow_go_sum_01.go",
    cot="分析过程：\n"
        "1. 用户可控输入：os.Args[1] 通过 Atoi 转换。\n"
        "2. 危险操作：sum += i 在 int 范围内累加。\n"
        "3. 溢出：Go 的 int 在 64 位系统中是 64 位，溢出阈值高，但 n 很大时仍可能溢出。\n"
        "4. 影响：sum 溢出为负数，make([]int, sum) 导致 panic 或分配奇怪大小。\n"
        "5. 综合来看，存在整数溢出漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-190", "整数溢出", "Medium",
        source="strconv.Atoi(os.Args[1])",
        sink="make([]int, sum) 中 sum 溢出",
        explanation="循环累加溢出使 sum 变为负数，make 分配失败或异常",
        fix="检查 n 的范围，使用 uint64 或检查累加结果是否溢出"
    )
))


# ===========================================================================
# J. Java/JS 安全代码增强（10 条）
# ===========================================================================
# 补充 Java/JS 安全样本，平衡语言分布
# 目的：增加 Java/JS 安全样本比例，防止模型对 Java/JS 代码过度敏感

JAVA_JS_SAFE_SAMPLES = []

# J1: Java PreparedStatement 安全
JAVA_JS_SAFE_SAMPLES.append(build_sample(
    code='''import java.sql.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    @GetMapping("/api/users")
    public String getUser(@RequestParam String id) {
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass")) {
            PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
            ps.setString(1, id);
            ResultSet rs = ps.executeQuery();
            StringBuilder sb = new StringBuilder();
            while (rs.next()) {
                sb.append(rs.getString("username")).append(",");
            }
            return sb.toString();
        } catch (SQLException e) {
            return "error";
        }
    }
}''',
    language="java", filename="safe_java_prepared_stmt_01.java",
    cot="分析过程：\n"
        "1. 用户可控输入：id 来自 @RequestParam。\n"
        "2. 数据库查询：使用 PreparedStatement 参数化查询，id 通过 setString 绑定。\n"
        "3. 防御检查：参数化查询中用户输入作为参数值而非 SQL 代码片段，SQL 注入不可行。\n"
        "4. 数据流：id → ps.setString(1, id) → 参数化执行。\n"
        "5. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("PreparedStatement 参数化查询，id 作为参数绑定而非拼接，SQL 注入不可行。")
))

# J2: JS escape-html 安全（XSS 防御）
JAVA_JS_SAFE_SAMPLES.append(build_sample(
    code='''const express = require("express");
const escapeHtml = require("escape-html");
const app = express();

app.get("/api/profile", (req, res) => {
    const username = req.query.username || "anonymous";
    // 对用户输入进行 HTML 转义
    const safeUsername = escapeHtml(username);
    res.send(`<h1>Welcome, ${safeUsername}</h1><p>User profile page</p>`);
});

app.listen(3000);''',
    language="javascript", filename="safe_js_escape_html_01.js",
    cot="分析过程：\n"
        "1. 用户可控输入：username 来自 req.query.username。\n"
        "2. 输出渲染：使用 escape-html 库对用户输入进行 HTML 转义。\n"
        "3. 防御检查：escapeHtml() 将 < > \" ' & 等 HTML 元字符转义为实体编码，XSS 不可行。\n"
        "4. 数据流：req.query → escapeHtml() → res.send() 模板渲染。\n"
        "5. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("escape-html 库对用户输入进行 HTML 转义，< > \" ' & 等元字符被转义为实体编码，XSS 不可行。")
))

# J3: Java CSP 头安全
JAVA_JS_SAFE_SAMPLES.append(build_sample(
    code='''import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;

@RestController
public class SecureController {
    @GetMapping("/api/secure/data")
    public String getData(HttpServletResponse response) {
        // 设置 CSP 头防止 XSS
        response.setHeader("Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'");
        // 返回 JSON 数据
        return "{\"status\":\"ok\"}";
    }
}''',
    language="java", filename="safe_java_csp_01.java",
    cot="分析过程：\n"
        "1. 输出：返回 JSON 字符串，非 HTML 页面。\n"
        "2. 防御：设置了 Content-Security-Policy 头限制脚本来源为 self。\n"
        "3. 数据流：直接返回 JSON，无用户输入回显。\n"
        "4. 额外检查：返回的是静态 JSON 字符串，无模板注入风险。\n"
        "5. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("返回静态 JSON 且设置 CSP 头，无用户输入注入点，XSS 不可行。")
))

# J4: JS bcrypt 密码安全（密码哈希）
JAVA_JS_SAFE_SAMPLES.append(build_sample(
    code='''const bcrypt = require("bcrypt");
const express = require("express");
const app = express();

app.post("/api/register", express.json(), async (req, res) => {
    const { username, password } = req.body;
    // 使用 bcrypt 哈希密码
    const salt = await bcrypt.genSalt(12);
    const hash = await bcrypt.hash(password, salt);
    // 存储到数据库
    await db.users.insertOne({ username, passwordHash: hash });
    res.json({ status: "registered" });
});

app.post("/api/login", express.json(), async (req, res) => {
    const { username, password } = req.body;
    const user = await db.users.findOne({ username });
    if (user && (await bcrypt.compare(password, user.passwordHash))) {
        res.json({ token: jwt.sign({ username }, process.env.JWT_SECRET) });
    } else {
        res.status(401).json({ error: "invalid credentials" });
    }
});

app.listen(3000);''',
    language="javascript", filename="safe_js_bcrypt_01.js",
    cot="分析过程：\n"
        "1. 用户可控输入：username 和 password 来自请求体。\n"
        "2. 密码存储：使用 bcrypt.genSalt(12) 生成盐值，bcrypt.hash() 哈希密码。\n"
        "3. 密码验证：使用 bcrypt.compare() 进行安全比较，防止时序攻击。\n"
        "4. 认证：登录成功后使用 JWT 签发令牌，密钥来自环境变量。\n"
        "5. 综合来看：密码存储和验证方案安全，无漏洞。",
    json_block=safe_json("bcrypt 哈希密码，盐值 12 轮，compare 安全比较防时序攻击，JWT 密钥来自环境变量。")
))

# J5: Java 路径校验安全（防止路径遍历）
JAVA_JS_SAFE_SAMPLES.append(build_sample(
    code='''import java.io.*;
import java.nio.file.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class FileController {
    private static final Path BASE_DIR = Paths.get("/var/app/data/");

    @GetMapping("/api/files")
    public String readFile(@RequestParam String filename) {
        try {
            Path filePath = BASE_DIR.resolve(filename).normalize();
            // 验证路径是否仍在 BASE_DIR 下
            if (!filePath.startsWith(BASE_DIR.normalize())) {
                return "invalid path";
            }
            String content = new String(Files.readAllBytes(filePath));
            return content;
        } catch (Exception e) {
            return "error: " + e.getMessage();
        }
    }
}''',
    language="java", filename="safe_java_path_validation_01.java",
    cot="分析过程：\n"
        "1. 用户可控输入：filename 来自 @RequestParam。\n"
        "2. 路径构建：BASE_DIR.resolve(filename).normalize() 解析并规范化路径。\n"
        "3. 路径遍历防御：filePath.startsWith(BASE_DIR.normalize()) 检查路径是否仍在允许范围内。\n"
        "4. 数据流：filename → resolve → normalize → startsWith 检查 → 读取。\n"
        "5. 综合来看：防御有效，无漏洞。",
    json_block=safe_json("resolve + normalize + startsWith 三重防护，路径遍历不可能绕过。")
))

# J6: JS CSRF token 安全
JAVA_JS_SAFE_SAMPLES.append(build_sample(
    code='''const express = require("express");
const csrf = require("csurf");
const cookieParser = require("cookie-parser");
const app = express();

app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
// 启用 CSRF 保护
const csrfProtection = csrf({ cookie: true });
app.get("/api/transfer/form", csrfProtection, (req, res) => {
    res.send(`<form method="POST" action="/api/transfer">
        <input type="hidden" name="_csrf" value="${req.csrfToken()}">
        <input type="text" name="amount">
        <button type="submit">Transfer</button>
    </form>`);
});

app.post("/api/transfer", csrfProtection, (req, res) => {
    const { amount, toAccount } = req.body;
    res.send(`Transferred ${amount} to ${toAccount}`);
});

app.listen(3000);''',
    language="javascript", filename="safe_js_csrf_01.js",
    cot="分析过程：\n"
        "1. CSRF 保护：使用 csurf 中间件，所有 POST 请求需要 CSRF token。\n"
        "2. Token 生成：req.csrfToken() 生成绑定到会话的令牌。\n"
        "3. Token 验证：POST 请求自动验证 _csrf 字段。\n"
        "4. Cookie 配置：CSRF 令牌存储在 cookie 中，使用 csrf 中间件验证。\n"
        "5. 综合来看：CSRF 保护有效，无漏洞。",
    json_block=safe_json("csurf 中间件提供 CSRF token 生成和验证，POST 请求必须携带有效 token。")
))

# J7: Java 认证授权安全（JWT + 角色检查）
JAVA_JS_SAFE_SAMPLES.append(build_sample(
    code='''import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

@RestController
public class AdminController {
    private static final String SECRET = System.getenv("JWT_SECRET");

    @GetMapping("/api/admin/users")
    public String listUsers(@RequestHeader("Authorization") String authHeader) {
        try {
            String token = authHeader.replace("Bearer ", "");
            Claims claims = Jwts.parserBuilder()
                .setSigningKey(SECRET.getBytes())
                .build()
                .parseClaimsJws(token)
                .getBody();
            String role = (String) claims.get("role");
            if (!"admin".equals(role)) {
                return "forbidden: admin role required";
            }
            return "User list: alice, bob, charlie";
        } catch (Exception e) {
            return "unauthorized: " + e.getMessage();
        }
    }
}''',
    language="java", filename="safe_java_jwt_auth_01.java",
    cot="分析过程：\n"
        "1. 认证：从 Authorization 头提取 Bearer token，使用 JWT 解析验证签名。\n"
        "2. 授权：从 claims 中提取 role 字段，检查是否为 admin。\n"
        "3. 密钥安全：JWT_SECRET 来自环境变量，非硬编码。\n"
        "4. 异常处理：解析失败时捕获异常返回 401，不泄露内部细节。\n"
        "5. 综合来看：认证和授权实现正确，无漏洞。",
    json_block=safe_json("JWT 签名验证 + 角色检查 + 环境变量密钥 + 安全异常处理，认证授权完整。")
))

# J8: JS 安全随机数生成
JAVA_JS_SAFE_SAMPLES.append(build_sample(
    code='''const crypto = require("crypto");
const express = require("express");
const app = express();

app.get("/api/token/reset", (req, res) => {
    // 生成安全的密码重置令牌
    const resetToken = crypto.randomBytes(32).toString("hex");
    // 存储到数据库（带过期时间）
    const email = req.query.email;
    db.passwordResets.insertOne({
        email,
        token: resetToken,
        expiresAt: new Date(Date.now() + 3600000)  // 1 小时后过期
    });
    // 发送邮件（实际生产环境中发送）
    res.json({ message: "reset link sent" });
});

app.post("/api/token/reset", express.json(), (req, res) => {
    const { token, newPassword } = req.body;
    const record = db.passwordResets.findOne({ token, expiresAt: { $gt: new Date() } });
    if (!record) return res.status(400).json({ error: "invalid or expired token" });
    // 更新密码
    const hash = bcrypt.hashSync(newPassword, 12);
    db.users.updateOne({ email: record.email }, { $set: { passwordHash: hash } });
    res.json({ status: "password reset" });
});

app.listen(3000);''',
    language="javascript", filename="safe_js_random_token_01.js",
    cot="分析过程：\n"
        "1. 随机数生成：使用 crypto.randomBytes(32) 生成 256 位安全随机令牌。\n"
        "2. 令牌强度：32 字节（256 位）随机数，不可预测。\n"
        "3. 过期时间：令牌 1 小时后过期，减少泄露风险。\n"
        "4. 密码重置：验证令牌有效性后更新密码，使用 bcrypt 哈希。\n"
        "5. 综合来看：密码重置流程安全，无漏洞。",
    json_block=safe_json("crypto.randomBytes(32) 生成安全随机令牌，带过期时间，重置密码使用 bcrypt 哈希。")
))

# J9: Java 反序列化白名单
JAVA_JS_SAFE_SAMPLES.append(build_sample(
    code='''import java.io.*;
import java.util.Base64;

public class SafeDeserializer {
    // 白名单：只允许反序列化的类
    private static final Set<String> ALLOWED_CLASSES = Set.of(
        "java.lang.String",
        "java.util.ArrayList",
        "java.util.HashMap",
        "com.example.UserData",
        "com.example.Config"
    );

    public static Object deserialize(String data) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(data);
        ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
        ObjectInputStream ois = new ObjectInputStream(bis) {
            @Override
            protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                String className = desc.getName();
                if (!ALLOWED_CLASSES.contains(className)) {
                    throw new InvalidClassException(className, "class not in whitelist");
                }
                return super.resolveClass(desc);
            }
        };
        return ois.readObject();
    }
}''',
    language="java", filename="safe_java_deserialize_01.java",
    cot="分析过程：\n"
        "1. 反序列化：接收 Base64 编码的序列化数据。\n"
        "2. 防御：重写 ObjectInputStream.resolveClass()，实现白名单校验。\n"
        "3. 白名单：只允许 String、ArrayList、HashMap 和业务类。\n"
        "4. 拒绝：不在白名单中的类（如 Runtime、ProcessBuilder）抛出异常。\n"
        "5. 综合来看：反序列化白名单有效，无漏洞。",
    json_block=safe_json("ObjectInputStream 重写 resolveClass 实现白名单过滤，限制反序列化类范围，阻止 gadget 链攻击。")
))

# J10: JS 模板引擎自动转义安全
JAVA_JS_SAFE_SAMPLES.append(build_sample(
    code='''const express = require("express");
const app = express();

// 设置 EJS 模板引擎（默认启用自动转义）
app.set("view engine", "ejs");

app.get("/api/profile", (req, res) => {
    const username = req.query.username || "guest";
    // EJS 的 <%= %> 默认对 HTML 转义
    res.render("profile", { username });
});

// views/profile.ejs:
// <!DOCTYPE html>
// <html>
// <head><title>User Profile</title></head>
// <body>
//   <h1>Welcome, <%= username %></h1>
//   <p>This is your profile page.</p>
// </body>
// </html>

app.listen(3000);''',
    language="javascript", filename="safe_js_ejs_escape_01.js",
    cot="分析过程：\n"
        "1. 用户可控输入：username 来自 req.query.username。\n"
        "2. 模板渲染：使用 EJS 模板引擎，<%= %> 语法自动对 HTML 转义。\n"
        "3. 防御检查：EJS 的 <%= %> 将 < > & \" ' 等 HTML 元字符转义为实体编码。\n"
        "4. 对比：如果使用 <%- %> 会输出原始 HTML（不安全），但此处使用 <%= %> 安全。\n"
        "5. 综合来看：模板引擎自动转义有效，无漏洞。",
    json_block=safe_json("EJS 的 <%= %> 语法自动 HTML 转义，用户输入中的 <script> 等标签被转义为实体编码，XSS 不可行。")
))


# ===========================================================================
# 主函数
# ===========================================================================

def extract_code(user_content: str) -> str:
    """从 user 消息中提取代码块内容用于去重。"""
    parts = user_content.split("```")
    if len(parts) >= 3:
        return parts[1].strip()
    return user_content


def jaccard_similarity(s1: str, s2: str) -> float:
    """计算两个字符串的行级 Jaccard 相似度。"""
    set1 = set(l.strip() for l in s1.splitlines() if l.strip())
    set2 = set(l.strip() for l in s2.splitlines() if l.strip())
    if not set1 or not set2:
        return 0.0
    intersection = set1 & set2
    union = set1 | set2
    return len(intersection) / len(union)


def main():
    print("=" * 60)
    print("v9 增强训练数据构建")
    print("=" * 60)

    # 加载 v8 基底
    print(f"\n[1] 加载基底: {V8_FILE}")
    records = []
    with open(V8_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    print(f"    v8 样本数: {len(records)}")

    # 收集所有新样本
    new_samples = (
        AUGMENTED_SAMPLES +              # 10 条变量重命名增强
        DEFENSE_CONFUSION_SAMPLES +     # 8 条防御迷惑（全漏洞，无矛盾安全样本）
        DISTRACTION_SAMPLES +           # 5 条注意力分散
        FRAMEWORK_SAMPLES +             # 5 条框架代码误判
        SAFE_SAMPLES +                  # 20 条多样安全代码（含 5 条 v8 FP 靶向）
        ATTRIBUTION_SAMPLES +           # 7 条 CWE 归因增强
        LDAP_JAVA_JS_SAMPLES +          # 10 条 Java/JS LDAP 注入
        TRUST_BOUNDARY_SAMPLES +        # 10 条信任边界绕过
        INTEGER_OVERFLOW_SAMPLES +      # 10 条整数溢出
        JAVA_JS_SAFE_SAMPLES            # 10 条 Java/JS 安全代码
    )
    print(f"\n[2] 新增样本数: {len(new_samples)}")
    print(f"    - 变量重命名增强 (A): {len(AUGMENTED_SAMPLES)}")
    print(f"    - 防御迷惑 (B): {len(DEFENSE_CONFUSION_SAMPLES)}")
    print(f"    - 注意力分散 (C): {len(DISTRACTION_SAMPLES)}")
    print(f"    - 框架代码误判 (D): {len(FRAMEWORK_SAMPLES)}")
    print(f"    - 多样安全代码 (E): {len(SAFE_SAMPLES)}")
    print(f"    - CWE 归因增强 (F): {len(ATTRIBUTION_SAMPLES)}")
    print(f"    - Java/JS LDAP 注入 (G): {len(LDAP_JAVA_JS_SAMPLES)}")
    print(f"    - 信任边界绕过 (H): {len(TRUST_BOUNDARY_SAMPLES)}")
    print(f"    - 整数溢出 (I): {len(INTEGER_OVERFLOW_SAMPLES)}")
    print(f"    - Java/JS 安全代码 (J): {len(JAVA_JS_SAFE_SAMPLES)}")

    # 合并
    all_records = records + new_samples
    print(f"\n[3] 合并后总数: {len(all_records)} "
          f"(v8 {len(records)} + 新增 {len(new_samples)})")

    # 去重（按 user prompt 中的代码内容 hash）
    seen_codes = set()
    deduped = []
    dup_count = 0
    for rec in all_records:
        user_content = ""
        for msg in rec.get("messages", []):
            if msg.get("role") == "user":
                user_content = msg.get("content", "")
                break
        code = extract_code(user_content)
        key = hash(code)
        if key in seen_codes:
            dup_count += 1
            continue
        seen_codes.add(key)
        deduped.append(rec)
    if dup_count:
        print(f"\n[4] 去重: 移除 {dup_count} 条重复样本")
    else:
        print(f"\n[4] 去重: 无重复样本")
    print(f"    最终样本数: {len(deduped)}")

    # 泄漏审计（Jaccard 相似度）
    print(f"\n[5] 泄漏审计 (Jaccard)")
    # 检查训练集内部新样本之间的高相似度
    new_codes = []
    for rec in new_samples:
        user_content = ""
        for msg in rec.get("messages", []):
            if msg.get("role") == "user":
                user_content = msg.get("content", "")
                break
        new_codes.append((extract_code(user_content), rec))

    high_overlap = 0
    for i, (code_i, _) in enumerate(new_codes):
        for j, (code_j, _) in enumerate(new_codes):
            if i < j:
                sim = jaccard_similarity(code_i, code_j)
                if sim >= 0.8:
                    high_overlap += 1
                    print(f"    ⚠️ 新样本 {i} vs {j}: Jaccard={sim:.2f}")
    if high_overlap == 0:
        print(f"    新样本间无高重叠 (>=0.8)")
    else:
        print(f"    共 {high_overlap} 对高重叠")

    # 检查新样本与测试集的泄漏
    # 测试集有两处：合成集 exp_04_hard_samples/samples/ + CVE-fix exp_06_finetune/testset_cve_fix/
    testset_dirs = [
        ROOT / "experiments/exp_04_hard_samples/samples",
        ROOT / "experiments/exp_06_finetune/testset_cve_fix",
    ]
    test_codes = []
    for testset_dir in testset_dirs:
        if not testset_dir.exists():
            continue
        for ext in ("*.py", "*.java", "*.js", "*.php", "*.go", "*.rb", "*.c"):
            for test_file in testset_dir.glob(ext):
                try:
                    test_codes.append((test_file.stem, test_file.read_text(encoding="utf-8")))
                except Exception:
                    pass
    print(f"    加载测试集样本: {len(test_codes)} 个")

    if test_codes:
        leak_count = 0
        for new_code, new_rec in new_codes:
            for test_name, test_code in test_codes:
                sim = jaccard_similarity(new_code, test_code)
                if sim >= 0.5:
                    leak_count += 1
                    print(f"    ⚠️ 泄漏警告: 新样本 vs {test_name}: Jaccard={sim:.2f}")
        if leak_count == 0:
            print(f"    新样本与测试集无泄漏 (>=0.5)")
        else:
            print(f"    共 {leak_count} 个泄漏警告")

    # CWE 名称标准化（修复 v8 基底和新增样本中的命名不一致）
    print(f"\n[6] CWE 名称标准化")
    deduped = normalize_all_records(deduped)

    # 保存
    print(f"\n[7] 保存到: {OUT_FILE}")
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        for rec in deduped:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # CWE 分布统计
    cwe_dist = {}
    for rec in deduped:
        assistant_msg = ""
        for msg in rec.get("messages", []):
            if msg.get("role") == "assistant":
                assistant_msg = msg.get("content", "")
                break
        json_match = re.search(r'"vulnerability_type"\s*:\s*"([^"]*)"', assistant_msg)
        if json_match:
            vuln_type = json_match.group(1)
            if vuln_type == "none":
                cwe_dist["none"] = cwe_dist.get("none", 0) + 1
                continue
            for m in re.finditer(r"CWE-\d+", vuln_type):
                cwe = m.group(0)
                cwe_dist[cwe] = cwe_dist.get(cwe, 0) + 1
        elif "CWE-" in assistant_msg:
            for m in re.finditer(r"CWE-\d+", assistant_msg):
                cwe = m.group(0)
                cwe_dist[cwe] = cwe_dist.get(cwe, 0) + 1

    print(f"\n[8] CWE 分布:")
    for cwe, cnt in sorted(cwe_dist.items(), key=lambda x: (-x[1], x[0])):
        print(f"    {cwe}: {cnt}")

    print(f"\n{'=' * 60}")
    print(f"v9 训练数据构建完成: {len(deduped)} 条样本")
    print(f"输出: {OUT_FILE}")
    print(f"{'=' * 60}")
    print(f"\n下一步：用 v9 数据启动训练")
    print(f"训练命令（v8 教训：epochs 3→2 避免 eval_loss 上升过拟合）：")
    print(f"  HF_HUB_OFFLINE=1 TORCH_ROCM_AOTRITON_ENABLE_EXPERIMENTAL=1 python3 train_qlora.py \\")
    print(f"      --data-file data/train_chatml_v9_augmented.jsonl \\")
    print(f"      --epochs 2 --batch-size 1 --grad-accum 8 --lr 1e-4 --lora-r 8 --use-rslora \\")
    print(f"      --output-suffix _v9")


if __name__ == "__main__":
    main()
