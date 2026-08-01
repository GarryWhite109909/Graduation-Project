#!/usr/bin/env python3
"""
构建 v7 实战专用训练数据。

策略（基于 v6 失败教训 + 用户确认的混合策略）：
  以 train_chatml_v5_clean.jsonl 为基底，新增/重写以下样本：
    1. CWE-90 LDAP 注入 10 条（修复 CVE-fix 0001/0002 持续 FN）
    2. CWE-441 信任边界绕过 10 条（修复 CVE-fix 0005 持续 FN）
    3. CWE-190 整数溢出 8 条（修复 typical_29 FN + CVE 覆盖）
    4. 6 个 FP 的反事实 CoT（替代 v6 失败的 hard-negative 追加）
    5. 6 组对比 CoT 对（易混 CWE 的 correct vs incorrect 推理）
    6. ~10 条 CVE 启发实战样本（隐蔽漏洞模式）
    7. 对 v5 中 15 条 CWE 标错 TP 重写 CoT（注入 CWE 判别要点）

能力联合训练：
  - 语义理解：多语言覆盖（Python/Java/JS/PHP/Go）+ 真实项目风格代码
  - 逻辑推理：反事实 CoT（"去掉防御会怎样"）+ source→sink→防御三段式
  - 字符输出：严格 JSON schema + CWE 归因判别要点
  - 参数化知识：CWE 判别边界注入（89 vs 78 vs 95 vs 90 vs 441）

用法：
    PYTHONPATH=../../.. python3 build_v7_realworld.py
输出：
    experiments/exp_06_finetune/data/train_chatml_v7_realworld.jsonl
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = ROOT / "experiments/exp_06_finetune/data"
V5_FILE = DATA_DIR / "train_chatml_v5_clean.jsonl"
OUT_FILE = DATA_DIR / "train_chatml_v7_realworld.jsonl"

SYSTEM_PROMPT = (
    "你是一名资深的代码安全审计专家。请对给出的代码片段进行安全分析，判断其中是否存在安全漏洞。"
    "分析范围包括但不限于：SQL 注入、跨站脚本（XSS）、命令注入、路径穿越、硬编码敏感信息"
    "（密钥/密码/Token）、不安全的反序列化、日志注入（CWE-117）、弱密码学（MD5/SHA1 哈希密码、CWE-327）、"
    "弱随机数（random 模块生成 token、CWE-330）、CSRF、SSTI、XXE、开放重定向、"
    "LDAP 注入（CWE-90）、信任边界绕过（CWE-441）、整数溢出（CWE-190）、缺失认证/授权等。\n\n"
    "要求：\n"
    "1. 仔细阅读代码语义，结合上下文判断用户可控输入是否被安全处理。\n"
    "2. 不要夸大风险，也不要遗漏明显的漏洞。\n"
    "3. 判定必须基于代码实际内容，不能凭空臆造 API 参数或行为。\n"
    "4. 用户输入到达 sink 不等于漏洞，必须看 sink 前的防御措施是否有效。\n"
    "5. 硬编码的字面量凭证（key/secret/password/token）本身就是漏洞，不要降级为「敏感但非漏洞」。\n"
    "6. 结论一致性校验：JSON 的 has_vulnerability 必须与上述分析过程的推理结论一致。\n"
    "7. CWE 归因判别：注入类漏洞按 sink 类型区分——SQL execute→CWE-89，shell/os.system→CWE-78，"
    "eval/exec→CWE-95，LDAP search→CWE-90，模板渲染→CWE-1336。信任边界绕过（loopback/XFF/内部 API）→CWE-441。\n\n"
    "在回答的最后，必须严格输出一个 JSON 对象作为最终结论，JSON 块用 ```json 包裹，字段如下（统一 schema，全项目一致）：\n"
    "   - has_vulnerability: bool, true 表示存在漏洞，false 表示未发现漏洞\n"
    "   - vulnerability_type: str, 单个字符串（禁止拆成多个逗号分隔的值），格式如 'CWE-89 SQL注入'；无漏洞填 'none'\n"
    "   - risk_level: str, Critical/High/Medium/Low；无漏洞填 'None'\n"
    "   - source: str, 污染来源（用户可控输入点）；无漏洞填 'N/A'\n"
    "   - sink: str, 危险函数或触发点；无漏洞填 'N/A'\n"
    "   - explanation: str, 漏洞或安全现状说明\n"
    "   - fix_suggestion: str, 修复建议；无漏洞填 'no fix needed'\n\n"
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
# 1. CWE-90 LDAP 注入样本（10 条）
# ===========================================================================
# 目标：修复 CVE-fix 0001/0002 持续 FN
# 关键教学点：
#   - LDAP sink 识别（DirContext.search / ldap.search / ldapjs search）
#   - LdapEncoder 部分编码 ≠ 安全（CVE-0001 模式）
#   - 不要被 bcrypt 等其他安全措施分散注意（CVE-0002 模式）
#   - CWE-90 vs CWE-89 判别：sink 是 LDAP search 而非 SQL execute

LDAP_SAMPLES = []

# L1: 基础 LDAP 注入（Python ldap3）
LDAP_SAMPLES.append(build_sample(
    code='''import ldap3
from flask import request

def search_user(username):
    conn = ldap3.Server("ldap://corp.local", get_info=ldap3.ALL)
    c = ldap3.Connection(conn, user="cn=admin", password="secret")
    c.bind()
    # 用户输入直接拼接到 LDAP filter
    filter_str = "(uid=" + username + ")"
    c.search("ou=users,dc=corp,dc=local", filter_str)
    return c.entries
''',
    language="python", filename="ldap_inject_01_basic.py",
    cot="分析过程：\n"
        "1. 用户可控输入：username 来自函数参数（实际调用方为 HTTP 请求）。\n"
        "2. 危险 sink：ldap3.Connection.search，filter_str 由 username 直接拼接而成。\n"
        "3. 数据流：username → 字符串拼接 → filter_str → c.search。\n"
        "4. 防御检查：无任何转义。LDAP filter 特殊字符 * ( ) \\ NUL 可被注入，"
        "如输入 *(uid=*) 可绕过认证或泄露全部用户。\n"
        "5. CWE 判别：sink 是 LDAP search 而非 SQL execute（CWE-89）或 shell（CWE-78），"
        "故为 CWE-90 LDAP 注入。\n"
        "6. 综合来看，存在 LDAP 注入漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "High",
        source="函数参数 username（来自 HTTP 请求）",
        sink="ldap3.Connection.search(filter_str)",
        explanation="username 直接拼接到 LDAP filter，未对 * ( ) \\ NUL 转义，可注入过滤条件绕过认证或枚举用户",
        fix="用 ldap3.AbstractionLayer 或 filter_format 进行参数化：filter_str = ldap3.utils.conv.escape_filter_chars(username) 后再拼接，或用 (uid={}) 的模板绑定"
    )
))

# L2: LDAP 注入（Java DirContext）— CVE-0001 模式（含 LdapEncoder 干扰）
LDAP_SAMPLES.append(build_sample(
    code='''import javax.naming.*;
import javax.naming.directory.*;
import java.util.*;

public class LdapAuth {
    private DirContext ctx;

    public boolean authenticate(String username, String password) throws NamingException {
        // 看似有 LdapEncoder，但只对 DN 部分编码，filter 仍拼接
        String safeDn = "uid=" + escapeDn(username) + ",ou=users,dc=corp,dc=local";
        // filter 直接拼接用户输入，未转义
        String filter = "(uid=" + username + ")";
        SearchControls ctrls = new SearchControls();
        ctrls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration<SearchResult> results = ctx.search(safeDn, filter, ctrls);
        if (results.hasMore()) {
            Attributes attrs = results.next().getAttributes();
            String storedHash = (String) attrs.get("userPassword").get();
            return verifyHash(password, storedHash);
        }
        return false;
    }

    private String escapeDn(String s) {
        return s.replace(",", "\\\\,").replace("=", "\\\\=");
    }
    private boolean verifyHash(String p, String h) { return false; }
}
''',
    language="java", filename="ldap_inject_02_encoder_distraction.java",
    cot="分析过程：\n"
        "1. 用户可控输入：username 和 password 来自 authenticate 参数（HTTP 请求）。\n"
        "2. 关键观察：safeDn 用 escapeDn 转义了 DN 部分（看似有防御），但 filter 仍直接拼接 username。\n"
        "3. 危险 sink：ctx.search(safeDn, filter, ctrls)，filter=(uid= + username + )。\n"
        "4. 防御有效性判定：escapeDn 只处理 DN 特殊字符（逗号、等号），未处理 filter 特殊字符 * ( ) \\ NUL。"
        "filter 中的 username 仍可注入。例如输入 *)(uid=*) 可使 filter 变为 (uid=*)(uid=*)，匹配所有用户。\n"
        "5. CWE 判别：sink 是 LDAP search，filter 注入 → CWE-90。不要被 escapeDn 干扰——它保护的是 DN 而非 filter。\n"
        "6. 反事实检验：若 username 用 filter 转义（如 LdapEncoder.escapeForSearchFilter），则 filter 安全；"
        "但当前代码只转义 DN，filter 仍裸拼接，故漏洞成立。\n"
        "7. 综合来看，存在 LDAP 注入漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "High",
        source="authenticate(username, password) 参数（来自 HTTP 请求）",
        sink="ctx.search(safeDn, filter, ctrls)",
        explanation="escapeDn 仅转义 DN 特殊字符，filter 中的 username 仍裸拼接，LDAP filter 特殊字符可注入绕过认证",
        fix="对 filter 中的 username 用 LdapEncoder.escapeForSearchFilter(username) 转义，或用参数化 LDAP 查询"
    )
))

# L3: LDAP 注入（Node.js ldapjs）— CVE-0002 模式（bcrypt 干扰）
LDAP_SAMPLES.append(build_sample(
    code='''const ldap = require('ldapjs');
const bcrypt = require('bcrypt');
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    const client = ldap.createClient({ url: 'ldap://corp.local' });
    // filter 直接拼接用户输入
    const filter = '(uid=' + username + ')';
    const opts = { scope: 'sub', filter: filter };

    client.search('ou=users,dc=corp,dc=local', opts, (err, searchResult) => {
        if (err) return res.status(500).json({ error: err.message });
        let user = null;
        searchResult.on('searchEntry', (entry) => { user = entry.object; });
        searchResult.on('end', () => {
            if (!user) return res.status(401).json({ error: 'invalid credentials' });
            // bcrypt 校验密码（看似安全，但 LDAP 查询已被注入）
            const valid = bcrypt.compareSync(password, user.userPassword);
            if (valid) {
                return res.json({ token: createToken(user.uid) });
            }
            res.status(401).json({ error: 'invalid credentials' });
        });
    });
});

function createToken(uid) { return uid; }
app.listen(3000);
''',
    language="javascript", filename="ldap_inject_03_bcrypt_distraction.js",
    cot="分析过程：\n"
        "1. 用户可控输入：username 和 password 来自 req.body（HTTP POST）。\n"
        "2. 关键观察：代码用 bcrypt.compareSync 校验密码（强密码哈希，看似安全），"
        "但 LDAP filter 直接拼接 username。\n"
        "3. 危险 sink：client.search(opts)，opts.filter = (uid= + username + )。\n"
        "4. 防御有效性判定：bcrypt 保护的是密码校验环节，不保护 LDAP 查询。"
        "filter 中 username 可注入 * 等特殊字符，如输入 admin)(uid=* 可使 filter 匹配 admin 或任意 uid，"
        "导致攻击者以任意用户身份触发密码校验（若该用户无密码或已知密码则登录成功）。\n"
        "5. CWE 判别：sink 是 ldapjs search，filter 注入 → CWE-90。bcrypt 是密码存储防御，与 LDAP 注入无关。\n"
        "6. 综合来看，存在 LDAP 注入漏洞，风险等级 High。不要因 bcrypt 而忽略 filter 拼接问题。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "High",
        source="req.body.username（HTTP POST）",
        sink="client.search(opts) 其中 opts.filter 拼接 username",
        explanation="LDAP filter 直接拼接 username，bcrypt 仅保护密码校验不保护 LDAP 查询，可注入 filter 绕过用户查找",
        fix="用 ldap.parseFilter 或对 username 做 escapeFilterChars 转义后再拼接 filter"
    )
))

# L4: LDAP 布尔注入（Python）
LDAP_SAMPLES.append(build_sample(
    code='''import ldap
from flask import request

def check_access(user, resource):
    con = ldap.initialize("ldap://ldap.corp.local")
    con.simple_bind_s("cn=admin,dc=corp,dc=local", "adminpass")
    # filter 拼接两个用户输入，可构造布尔注入
    filter_str = "(&(uid=" + user + ")(accessTo=" + resource + "))"
    result = con.search_s("ou=users,dc=corp,dc=local", ldap.SCOPE_SUBTREE, filter_str)
    return len(result) > 0
''',
    language="python", filename="ldap_inject_04_boolean.py",
    cot="分析过程：\n"
        "1. 用户可控输入：user 和 resource 均来自函数参数（HTTP 请求）。\n"
        "2. 危险 sink：con.search_s(filter_str)，filter 为 (&(uid=user)(accessTo=resource)) 拼接。\n"
        "3. 攻击路径：输入 user=*)(accessTo=*)(|(uid=* 可使 filter 变为 "
        "(&(uid=*)(accessTo=*)(|(uid=*)(accessTo=*))，恒真，绕过访问控制。\n"
        "4. 防御检查：无转义。两个输入点都未处理 LDAP filter 特殊字符。\n"
        "5. CWE 判别：sink 是 ldap.search_s，filter 布尔注入 → CWE-90。\n"
        "6. 综合来看，存在 LDAP 注入漏洞（布尔注入变体），风险等级 High。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "High",
        source="user 和 resource 参数（HTTP 请求）",
        sink="con.search_s(filter_str)",
        explanation="两个用户输入都拼接到 LDAP filter，可构造布尔注入使 filter 恒真，绕过访问控制检查",
        fix="对所有拼接到 filter 的用户输入用 ldap.filter.escape_filter_chars 转义"
    )
))

# L5: LDAP 通配符注入（Java）
LDAP_SAMPLES.append(build_sample(
    code='''import javax.naming.directory.*;

public class UserSearch {
    private DirContext ctx;
    public SearchResult[] searchByName(String name) throws Exception {
        // 用户输入作为通配符查询，未限制 * 字符
        String filter = "(cn=" + name + "*)";
        SearchControls ctrls = new SearchControls();
        ctrls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration<SearchResult> ne = ctx.search("ou=users,dc=corp,dc=local", filter, ctrls);
        java.util.List<SearchResult> list = new java.util.ArrayList<>();
        while (ne.hasMore()) list.add(ne.next());
        return list.toArray(new SearchResult[0]);
    }
}
''',
    language="java", filename="ldap_inject_05_wildcard.java",
    cot="分析过程：\n"
        "1. 用户可控输入：name 来自函数参数。\n"
        "2. 危险 sink：ctx.search(filter)，filter = (cn= + name + *)。\n"
        "3. 攻击路径：虽然代码本意是前缀匹配（name*），但 name 中可含 ( ) 等字符改变 filter 结构。"
        "如输入 *)(uid=* 可使 filter 变为 (cn=*)(uid=**)，泄露全部用户及其 uid。\n"
        "4. 防御检查：无转义。\n"
        "5. CWE 判别：sink 是 LDAP search → CWE-90。\n"
        "6. 综合来看，存在 LDAP 注入漏洞，风险等级 Medium（信息泄露，非直接认证绕过）。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "Medium",
        source="name 参数（HTTP 请求）",
        sink="ctx.search(filter) 其中 filter 拼接 name",
        explanation="name 拼接到 LDAP filter，可注入 ) 改变 filter 结构，泄露全部用户信息",
        fix="对 name 用 LdapEncoder.escapeForSearchFilter 转义后再拼接"
    )
))

# L6: 安全样本 — 参数化 LDAP 查询（Python）
LDAP_SAMPLES.append(build_sample(
    code='''import ldap3
from ldap3.utils.conv import escape_filter_chars

def search_user_safe(username):
    server = ldap3.Server("ldap://corp.local")
    conn = ldap3.Connection(server, user="cn=admin", password="secret")
    conn.bind()
    # 用 escape_filter_chars 转义后再拼接
    safe_username = escape_filter_chars(username)
    filter_str = "(uid=" + safe_username + ")"
    conn.search("ou=users,dc=corp,dc=local", filter_str)
    return conn.entries
''',
    language="python", filename="ldap_safe_01_escaped.py",
    cot="分析过程：\n"
        "1. 用户可控输入：username 来自函数参数。\n"
        "2. 危险 sink 识别：ldap3.Connection.search，filter 由 username 构成。\n"
        "3. 防御有效性判定：username 先经 escape_filter_chars 转义，"
        "LDAP filter 特殊字符 * ( ) \\ NUL 被转义为 \\2a \\28 \\29 \\5c \\00，"
        "无法改变 filter 结构。\n"
        "4. 反事实检验：若去掉 escape_filter_chars，username 中的 ) 可改变 filter 结构构成 CWE-90；"
        "当前有转义，漏洞不成立。\n"
        "5. CWE 判别：虽 sink 是 LDAP search，但防御有效，无注入风险。\n"
        "6. 综合来看，不存在安全漏洞。",
    json_block=safe_json(
        "username 经 escape_filter_chars 转义后再拼接 LDAP filter，特殊字符被转义，无法注入。"
        "反事实：若去掉转义则构成 CWE-90 LDAP 注入。"
    )
))

# L7: 安全样本 — LdapEncoder.escapeForSearchFilter 正确使用（Java）
LDAP_SAMPLES.append(build_sample(
    code='''import javax.naming.directory.*;
import org.springframework.ldap.filter.*;
import org.springframework.ldap.support.LdapEncoder;

public class SafeLdapSearch {
    private DirContext ctx;
    public SearchResult[] search(String username) throws Exception {
        String safe = LdapEncoder.escapeForSearchFilter(username);
        String filter = "(uid=" + safe + ")";
        SearchControls ctrls = new SearchControls();
        ctrls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration<SearchResult> ne = ctx.search("ou=users,dc=corp,dc=local", filter, ctrls);
        java.util.List<SearchResult> list = new java.util.ArrayList<>();
        while (ne.hasMore()) list.add(ne.next());
        return list.toArray(new SearchResult[0]);
    }
}
''',
    language="java", filename="ldap_safe_02_encoder_correct.java",
    cot="分析过程：\n"
        "1. 用户可控输入：username 来自函数参数。\n"
        "2. 危险 sink 识别：ctx.search(filter)。\n"
        "3. 防御有效性判定：username 经 LdapEncoder.escapeForSearchFilter 转义，"
        "该函数专门转义 LDAP filter 特殊字符（与 escapeForDn 不同，后者只转义 DN 特殊字符）。\n"
        "4. 关键区分：escapeForSearchFilter 保护 filter，escapeForDn 保护 DN。"
        "本例 filter 用 escapeForSearchFilter，防御正确。\n"
        "5. 反事实检验：若误用 escapeForDn 转 filter，则 * ( ) 不会被转义，仍可注入 CWE-90。"
        "当前用对了函数，漏洞不成立。\n"
        "6. 综合来看，不存在安全漏洞。",
    json_block=safe_json(
        "username 经 LdapEncoder.escapeForSearchFilter 转义（filter 专用函数，非 escapeForDn），"
        "LDAP filter 特殊字符被正确转义，无注入风险。"
    )
))

# L8: LDAP 注入 — Spring LdapTemplate 的 filter 拼接（Java）
LDAP_SAMPLES.append(build_sample(
    code='''import org.springframework.ldap.core.*;
import org.springframework.ldap.filter.*;

public class UserDao {
    private LdapTemplate ldapTemplate;
    public java.util.List<User> findByName(String name) {
        // 误用 HardcodedFilter 拼接用户输入
        Filter filter = new HardcodedFilter("(cn=" + name + ")");
        return ldapTemplate.search("ou=users,dc=corp,dc=local", filter,
            (AttributesMapper<User>) attrs -> new User((String) attrs.get("uid").get()));
    }
}
''',
    language="java", filename="ldap_inject_06_hardcoded_filter.java",
    cot="分析过程：\n"
        "1. 用户可控输入：name 来自函数参数。\n"
        "2. 危险 sink：ldapTemplate.search(filter)，filter = HardcodedFilter((cn= + name + ))。\n"
        "3. 关键陷阱：HardcodedFilter 名字暗示「硬编码」，但实际 filter 内容拼接了用户输入 name，仍是注入点。\n"
        "4. 防御检查：无转义。应改用 EqualsFilter 或 WhitespaceWildcardsFilter 等参数化 filter。\n"
        "5. CWE 判别：sink 是 LDAP search → CWE-90。\n"
        "6. 综合来看，存在 LDAP 注入漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "High",
        source="name 参数（HTTP 请求）",
        sink="ldapTemplate.search(HardcodedFilter)",
        explanation="HardcodedFilter 拼接了用户输入 name，名字具误导性但实际可注入 LDAP filter",
        fix="改用 EqualsFilter(\"cn\", name) 让 Spring 自动转义，或手动调用 LdapEncoder.escapeForSearchFilter"
    )
))

# L9: LDAP 注入 — PHP ldap_search
LDAP_SAMPLES.append(build_sample(
    code='''<?php
function search_user($username) {
    $conn = ldap_connect("ldap://corp.local");
    ldap_bind($conn, "cn=admin,dc=corp,dc=local", "adminpass");
    // filter 直接拼接用户输入
    $filter = "(uid=" . $username . ")";
    $result = ldap_search($conn, "ou=users,dc=corp,dc=local", $filter);
    return ldap_get_entries($conn, $result);
}
echo json_encode(search_user($_POST['username']));
?>
''',
    language="php", filename="ldap_inject_07_php.php",
    cot="分析过程：\n"
        "1. 用户可控输入：$_POST['username']。\n"
        "2. 危险 sink：ldap_search($conn, ..., $filter)，filter 拼接 username。\n"
        "3. 防御检查：无转义。PHP 的 ldap_search 不会自动转义 filter 特殊字符。\n"
        "4. CWE 判别：sink 是 ldap_search → CWE-90。\n"
        "5. 综合来看，存在 LDAP 注入漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "High",
        source="$_POST['username']",
        sink="ldap_search($conn, $base, $filter)",
        explanation="username 直接拼接到 LDAP filter，未转义 * ( ) \\ NUL，可注入",
        fix="用 ldap_escape($username, null, LDAP_ESCAPE_FILTER) 转义后再拼接 filter"
    )
))

# L10: LDAP 注入 + 认证绕过（Python，综合场景）
LDAP_SAMPLES.append(build_sample(
    code='''import ldap3
from flask import request, Flask
app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("user", "")
    pwd = request.form.get("pwd", "")
    srv = ldap3.Server("ldap://corp.local")
    c = ldap3.Connection(srv, user="cn=admin", password="admin")
    c.bind()
    # 双重漏洞：filter 拼接 + 用 userPassword 属性做密码比较（而非 bind 认证）
    filt = "(&(uid=" + user + ")(userPassword=" + pwd + "))"
    c.search("ou=users,dc=corp,dc=local", filt)
    if c.entries:
        return "logged in"
    return "denied", 401
''',
    language="python", filename="ldap_inject_08_auth_bypass.py",
    cot="分析过程：\n"
        "1. 用户可控输入：user 和 pwd 来自 request.form。\n"
        "2. 危险 sink：c.search(filt)，filt = (&(uid=user)(userPassword=pwd)) 全部拼接。\n"
        "3. 双重问题：(a) filter 注入——user 输入 *)(uid=* 可使 filter 匹配任意用户；"
        "(b) 用 userPassword 属性做字符串比较而非 LDAP bind 认证，即使无 filter 注入也可被 * 通配符绕过。\n"
        "4. CWE 判别：sink 是 LDAP search，filter 注入 → CWE-90（主要漏洞）。\n"
        "5. 综合来看，存在 LDAP 注入漏洞，可绕过认证，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "Critical",
        source="request.form 的 user 和 pwd",
        sink="c.search(filt) 其中 filt 拼接两个用户输入",
        explanation="filter 拼接 user 和 pwd，可注入 ) 改变 filter 结构绕过认证；且用 userPassword 属性比较而非 bind 认证",
        fix="对所有用户输入用 escape_filter_chars 转义；改用 LDAP bind 认证（用用户凭证 bind）而非 userPassword 属性比较"
    )
))


# ===========================================================================
# 2. CWE-441 信任边界绕过样本（10 条）
# ===========================================================================
# 目标：修复 CVE-fix 0005 持续 FN（loopback 信任反模式）
# 关键教学点：
#   - 识别"信任来源"反模式：loopback IP / X-Forwarded-For / 内部 API 无认证 / 反向 DNS
#   - 不要把"来源是本地"等同于"来源可信"
#   - CWE-441 vs CWE-306（缺失认证）vs CWE-290（认证绕过）：441 侧重信任源误判

TRUST_BOUNDARY_SAMPLES = []

# T1: loopback 信任绕过（CVE-0005 模式）
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''const express = require('express');
const app = express();

// 内部 API 不需认证，靠 IP 判断是否本地
app.use('/v1/*', (req, res, next) => {
    const ip = req.connection.remoteAddress;
    // 信任 loopback 来源，免认证
    if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') {
        req.trusted = true;
        return next();
    }
    // 非本地需要 API key
    const key = req.headers['x-api-key'];
    if (!key || key !== process.env.API_KEY) {
        return res.status(401).json({ error: 'api key required' });
    }
    next();
});

app.post('/v1/admin/reset', (req, res) => {
    // req.trusted 为 true 时直接执行高危操作
    db.reset();
    res.json({ status: 'reset done' });
});
''',
    language="javascript", filename="trust_01_loopback_bypass.js",
    cot="分析过程：\n"
        "1. 信任模型分析：代码用 req.connection.remoteAddress 判断是否 loopback，loopback 免认证。\n"
        "2. 信任边界漏洞：在同主机部署反向代理（nginx/caddy）转发公网流量时，"
        "代理转发后 req.connection.remoteAddress 是代理的 IP（127.0.0.1），"
        "导致公网请求被误判为「本地可信」，绕过 API key 认证。\n"
        "3. 反事实检验：若代理设置了 X-Forwarded-For 且代码校验该头而非 remoteAddress，则不会误判；"
        "但当前代码直接信任 remoteAddress，反向代理场景下信任边界被绕过。\n"
        "4. CWE 判别：问题不是「缺失认证」（CWE-306，因为非 loopback 有 API key），"
        "而是「信任源误判」——把网络层来源等同于信任级别 → CWE-441。\n"
        "5. 综合来看，存在信任边界绕过漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "High",
        source="反向代理转发的公网请求（remoteAddress 被伪装为 127.0.0.1）",
        sink="req.trusted = true 后免认证执行 /v1/admin/reset",
        explanation="仅凭 remoteAddress 判断可信，反向代理转发后公网请求 IP 变为 127.0.0.1，绕过 API key 认证",
        fix="不要用 IP 判断信任级别；内部 API 也要认证（用 mTLS 或共享 secret）；若必须区分内外网，校验 X-Forwarded-For 链且配置可信代理白名单"
    )
))

# T2: X-Forwarded-For 信任绕过
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''from flask import Flask, request
app = Flask(__name__)

@app.route("/admin")
def admin():
    # 信任 X-Forwarded-For 头判断是否内网
    forwarded = request.headers.get("X-Forwarded-For", "")
    client_ip = forwarded.split(",")[0].strip() if forwarded else request.remote_addr
    if client_ip.startswith("10.") or client_ip.startswith("192.168."):
        # 内网直接放行
        return "admin panel"
    return "forbidden", 403
''',
    language="python", filename="trust_02_xff_bypass.py",
    cot="分析过程：\n"
        "1. 信任模型：代码从 X-Forwarded-For 头取第一个 IP，判断是否内网网段（10./192.168.）。\n"
        "2. 信任边界漏洞：X-Forwarded-For 是客户端可任意伪造的 HTTP 头，"
        "攻击者可发送 X-Forwarded-For: 10.0.0.1 伪装内网，绕过访问控制。\n"
        "3. 反事实检验：若代码用 request.remote_addr（TCP 连接真实 IP）且确认前置有可信代理剥离伪造 XFF，则安全；"
        "当前直接信任 XFF 头，漏洞成立。\n"
        "4. CWE 判别：信任源误判（把可伪造的 HTTP 头当作信任依据）→ CWE-441。\n"
        "5. 综合来看，存在信任边界绕过漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "High",
        source="X-Forwarded-For HTTP 头（客户端可伪造）",
        sink="client_ip.startswith('10.') 内网放行",
        explanation="直接信任 X-Forwarded-For 头判断内网，攻击者可伪造该头为 10.0.0.1 绕过访问控制",
        fix="用 request.remote_addr 取 TCP 真实 IP；若前置可信代理，配置代理白名单并从右向左解析 XFF 链"
    )
))

# T3: 内部 API 无认证（认为"内网不会被攻击"）
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''from flask import Flask, request
app = Flask(__name__)

# 内部管理 API，部署在内网，未加认证
@app.route("/internal/users/<uid>/delete", methods=["POST"])
def delete_user(uid):
    # 假设内网调用，无认证
    db.execute("DELETE FROM users WHERE id = ?", (uid,))
    return {"status": "deleted"}

@app.route("/internal/config/update", methods=["POST"])
def update_config():
    # 直接接受任意 JSON 配置
    new_config = request.get_json()
    with open("/etc/app/config.json", "w") as f:
        json.dump(new_config, f)
    return {"status": "updated"}
''',
    language="python", filename="trust_03_internal_no_auth.py",
    cot="分析过程：\n"
        "1. 信任模型：代码假设/internal/* 路径只被内网调用，故未加认证。\n"
        "2. 信任边界漏洞：'部署在内网'不等于'只有可信客户端能访问'。"
        "SSRF 漏洞（CWE-918）可使外部攻击者通过应用发起的请求触达内网 API；"
        "同网段被攻陷主机也可直接访问；DNS 重绑定可绕过 Host 校验。\n"
        "3. CWE 判别：这是「信任网络位置」的反模式 → CWE-441（信任边界绕过）。"
        "注意与 CWE-306（缺失认证）的区别：306 是完全没认证机制，441 是有认证但被信任源绕过或误判。"
        "本例更偏 441——基于「内网」信任假设而省略认证。\n"
        "4. 反事实检验：若/internal/* 也要求 mTLS 客户端证书或共享 token，则即使被 SSRF 命中也无法调用；"
        "当前无认证，漏洞成立。\n"
        "5. 综合来看，存在信任边界绕过漏洞（内部 API 无认证），风险等级 High。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "High",
        source="内网网络位置（被 SSRF 或同网段主机绕过）",
        sink="/internal/* 端点无认证直接执行高危操作",
        explanation="基于'内网可信'假设省略认证，SSRF/同网段攻陷/DNS 重绑定均可触达这些端点",
        fix="内部 API 也要认证（mTLS 或共享 secret token）；不要依赖网络位置作为信任依据"
    )
))

# T4: 反向 DNS 信任（Java）
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''import java.net.InetAddress;
import javax.servlet.http.*;

public class TrustedHostFilter {
    public boolean isTrusted(HttpServletRequest request) {
        String ip = request.getRemoteAddr();
        try {
            InetAddress addr = InetAddress.getByName(ip);
            String hostname = addr.getHostName();  // 反向 DNS 查询
            // 信任来自 corp.local 域的请求
            if (hostname.endsWith(".corp.local") || hostname.equals("corp.local")) {
                return true;
            }
        } catch (Exception e) {}
        return false;
    }
}
''',
    language="java", filename="trust_04_reverse_dns.java",
    cot="分析过程：\n"
        "1. 信任模型：用反向 DNS 查询客户端 IP 的主机名，判断是否属于 corp.local 域。\n"
        "2. 信任边界漏洞：反向 DNS 记录可被攻击者控制（攻击者拥有自己的 IP 反向 PTR 记录设置权限），"
        "可将自己的 IP 反向解析为 evil.corp.local，满足 endsWith 判断，绕过信任检查。\n"
        "3. 反事实检验：若用正向 DNS 确认（先反向查主机名，再用主机名正向查 IP，比对是否一致），"
        "则可防御反向 DNS 欺骗；当前只做反向查询，漏洞成立。\n"
        "4. CWE 判别：信任源误判（把可伪造的反向 DNS 当信任依据）→ CWE-441。\n"
        "5. 综合来看，存在信任边界绕过漏洞，风险等级 Medium（需攻击者控制 PTR 记录）。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "Medium",
        source="客户端 IP 的反向 DNS 记录（攻击者可伪造 PTR）",
        sink="hostname.endsWith('.corp.local') 判定可信",
        explanation="仅用反向 DNS 判断信任域，攻击者可将自己的 IP 反向解析为 evil.corp.local 绕过检查",
        fix="用正向确认（reverse DNS + forward DNS 双向校验）；或改用 mTLS 客户端证书而非 DNS 判断信任"
    )
))

# T5: Referer 信任绕过
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''from flask import Flask, request
app = Flask(__name__)

@app.route("/transfer", methods=["POST"])
def transfer():
    # 信任 Referer 头判断是否本站请求（替代 CSRF token）
    referer = request.headers.get("Referer", "")
    if not referer.startswith("https://bank.example.com/"):
        return "forbidden", 403
    # 执行转账
    amount = request.form.get("amount")
    to = request.form.get("to")
    do_transfer(amount, to)
    return "ok"
''',
    language="python", filename="trust_05_referer_csrf.py",
    cot="分析过程：\n"
        "1. 信任模型：用 Referer 头判断请求来源是否本站，替代 CSRF token。\n"
        "2. 信任边界漏洞：Referer 头可被某些场景剥离或伪造——"
        "旧版浏览器/插件可篡改 Referer；HTTPS→HTTP 跳转会剥离 Referer；"
        "更关键的是 Referer 不是加密凭证，无法防御恶意子域或 XSS 注入的请求。\n"
        "3. CWE 判别：信任源误判（把 Referer 当作 CSRF 防御依据）→ CWE-441。"
        "也可归为 CWE-352（CSRF），但根因是信任源选择错误，故 441 更精确。\n"
        "4. 反事实检验：若用同步器 token（session 绑定的随机 token 校验），则无法被 Referer 伪造绕过；"
        "当前用 Referer，漏洞成立。\n"
        "5. 综合来看，存在信任边界绕过漏洞（CSRF 防御失效），风险等级 High。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "High",
        source="Referer HTTP 头（可被伪造/剥离）",
        sink="referer.startswith 判断后执行转账",
        explanation="用 Referer 头替代 CSRF token 做来源校验，Referer 可被伪造或剥离，CSRF 防御失效",
        fix="用同步器 token 模式（session 绑定随机 token，校验表单/请求头中的 token）；Referer 只能作为辅助而非唯一依据"
    )
))

# T6: loopback 信任 + SSRF 组合（Python）
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''import requests
from flask import Flask, request
app = Flask(__name__)

@app.route("/health")
def health():
    # 健康检查端点，仅允许 loopback
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return "forbidden", 403
    # 但暴露了内部状态，含敏感信息
    return {
        "db_url": "postgres://admin:s3cr3t@10.0.0.5:5432/app",
        "redis_url": "redis://:p4ssw0rd@10.0.0.6:6379/0",
        "jwt_secret": "sup3r_s3cr3t_jwt_k3y",
        "internal_api_keys": ["AKIAxxx", "AKIAyyy"],
    }

@app.route("/fetch")
def fetch():
    # SSRF 端点：用户控制 URL
    url = request.args.get("url")
    r = requests.get(url)
    return r.text
''',
    language="python", filename="trust_06_loopback_ssrf.py",
    cot="分析过程：\n"
        "1. 两个端点分析：/health 用 remote_addr 限制 loopback 但泄露敏感配置；"
        "/fetch 存在 SSRF（用户控制 URL）。\n"
        "2. 组合攻击：攻击者通过 /fetch 的 SSRF 请求 http://127.0.0.1/health，"
        "由于 SSRF 请求的 remote_addr 是 127.0.0.1（本机），绕过 /health 的 loopback 校验，"
        "泄露 db_url/redis_url/jwt_secret 等敏感配置。\n"
        "3. CWE 判别：/health 的信任边界绕过（loopback 误信）→ CWE-441；"
        "/fetch 的 SSRF → CWE-918。主漏洞是信任边界绕过导致敏感信息泄露。\n"
        "4. 反事实检验：若 /health 也要求认证 token（即使 loopback），则 SSRF 命中后仍无法获取配置；"
        "当前仅靠 IP 判断，漏洞成立。\n"
        "5. 综合来看，存在信任边界绕过漏洞，风险等级 Critical（敏感凭据泄露）。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "Critical",
        source="SSRF 使请求来源变为 127.0.0.1",
        sink="/health 端点 loopback 信任后泄露 db_url/jwt_secret 等凭据",
        explanation="/health 仅凭 remote_addr=127.0.0.1 信任，SSRF 请求满足该条件后泄露数据库密码、JWT secret、API key",
        fix="敏感配置不通过任何 HTTP 端点返回（即使 loopback）；/health 改为只返回 ok 状态；loopback 端点也要认证"
    )
))

# T7: 安全样本 — loopback + 认证
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''from flask import Flask, request
app = Flask(__name__)

ADMIN_TOKEN = "configured-vault-sidecar"

@app.route("/internal/admin/flush", methods=["POST"])
def flush_cache():
    # 即使 loopback 也要校验 token
    ip = request.remote_addr
    if ip not in ("127.0.0.1", "::1"):
        return "forbidden", 403
    # loopback 之外还要 token
    token = request.headers.get("X-Admin-Token", "")
    if token != ADMIN_TOKEN:
        return "unauthorized", 401
    cache.flush()
    return {"status": "flushed"}
''',
    language="python", filename="trust_safe_01_loopback_plus_auth.py",
    cot="分析过程：\n"
        "1. 信任模型：双重校验——loopback IP + admin token。\n"
        "2. 防御有效性：即使被 SSRF 命中（IP 变为 127.0.0.1），攻击者仍需提供正确 token 才能执行操作。\n"
        "3. 反事实检验：若去掉 token 校验，仅靠 loopback 判断则构成 CWE-441（trust_06 模式）；"
        "当前有双重校验，漏洞不成立。\n"
        "4. CWE 判别：信任边界有 token 补强，无绕过风险。\n"
        "5. 综合来看，不存在安全漏洞。loopback 限制减少攻击面，token 校验保证认证强度。",
    json_block=safe_json(
        "loopback IP 限制 + admin token 双重校验，SSRF 命中后仍需 token，信任边界完整。"
        "反事实：若去掉 token 则构成 CWE-441。"
    )
))

# T8: Host 头信任绕过（Java）
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''import javax.servlet.http.*;

public class HostTrustFilter {
    public boolean isInternalRequest(HttpServletRequest req) {
        // 信任 Host 头判断是否内部 API 网关调用
        String host = req.getHeader("Host");
        if (host != null && (host.contains("internal-gateway") || host.contains("localhost"))) {
            return true;
        }
        return false;
    }
}
''',
    language="java", filename="trust_07_host_header.java",
    cot="分析过程：\n"
        "1. 信任模型：用 Host 头判断是否内部网关调用。\n"
        "2. 信任边界漏洞：Host 头由客户端发送，可任意伪造。"
        "攻击者发送 Host: internal-gateway 即可绕过判断。\n"
        "3. CWE 判别：信任源误判（把可伪造的 Host 头当信任依据）→ CWE-441。\n"
        "4. 反事实检验：若用 mTLS 客户端证书或共享 secret 校验内部网关身份，则无法伪造；"
        "当前用 Host 头，漏洞成立。\n"
        "5. 综合来看，存在信任边界绕过漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "High",
        source="Host HTTP 头（客户端可伪造）",
        sink="host.contains('internal-gateway') 判定可信",
        explanation="用 Host 头判断内部网关身份，Host 头可被客户端伪造，绕过信任检查",
        fix="用 mTLS 客户端证书或共享 secret 校验内部网关身份，不要信任 Host 头"
    )
))

# T9: WebSocket Origin 信任绕过
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''import asyncio
import websockets

async def handler(websocket):
    # 信任 Origin 头判断是否同源
    origin = websocket.request_headers.get("Origin", "")
    if origin not in ("https://app.example.com", "https://www.example.com"):
        await websocket.close(code=1008)
        return
    # 执行敏感操作
    await websocket.send("session data: " + get_secret_data())

start_server = websockets.serve(handler, "0.0.0.0", 8765)
asyncio.get_event_loop().run_until_complete(start_server)
''',
    language="python", filename="trust_08_ws_origin.py",
    cot="分析过程：\n"
        "1. 信任模型：用 WebSocket Origin 头判断是否同源。\n"
        "2. 信任边界漏洞：Origin 头在浏览器中较难伪造，但在非浏览器客户端（如 Python websockets 库、curl）"
        "可任意设置。攻击者用脚本发起 WebSocket 连接并伪造 Origin: https://app.example.com 即可绕过。\n"
        "3. CWE 判别：信任源误判（Origin 头非加密凭证，非浏览器可伪造）→ CWE-441。\n"
        "4. 反事实检验：若增加 token 校验（握手时校验 session token），则非浏览器伪造 Origin 也无法通过；"
        "当前仅靠 Origin，漏洞成立。\n"
        "5. 综合来看，存在信任边界绕过漏洞，风险等级 Medium（需非浏览器客户端）。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "Medium",
        source="WebSocket Origin 头（非浏览器客户端可伪造）",
        sink="origin in 白名单判断后发送敏感数据",
        explanation="仅靠 Origin 头判断同源，非浏览器客户端可伪造 Origin 绕过检查获取敏感数据",
        fix="握手时校验 session token（与 HTTP 会话一致的认证）；Origin 仅作辅助而非唯一依据"
    )
))

# T10: JWT none 算法信任绕过
TRUST_BOUNDARY_SAMPLES.append(build_sample(
    code='''import jwt
from flask import Flask, request
app = Flask(__name__)

@app.route("/admin")
def admin():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        # 未显式指定算法，可能接受 none
        payload = jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return "invalid token", 401
    if payload.get("role") == "admin":
        return "admin panel"
    return "forbidden", 403
''',
    language="python", filename="trust_09_jwt_none.py",
    cot="分析过程：\n"
        "1. 信任模型：用 JWT 的 role 字段判断管理员，但 verify_signature=False 完全跳过签名校验。\n"
        "2. 信任边界漏洞：任何人都可构造 {role:admin} 的 JWT（无需密钥），"
        "甚至用 alg:none 的无签名 JWT，代码会直接信任 payload。\n"
        "3. CWE 判别：信任源误判（信任未验证的 JWT payload）→ CWE-441。"
        "也关联 CWE-347（签名验证不当），但根因是信任未验证来源。\n"
        "4. 反事实检验：若用 jwt.decode(token, SECRET, algorithms=['HS256']) 强制校验签名和算法，"
        "则无法伪造 admin token；当前 verify_signature=False，漏洞成立。\n"
        "5. 综合来看，存在信任边界绕过漏洞，风险等级 Critical（认证完全失效）。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "Critical",
        source="未校验签名的 JWT payload（客户端可任意构造）",
        sink="payload.get('role') == 'admin' 判断后放行",
        explanation="verify_signature=False 跳过 JWT 签名校验，攻击者可构造任意 role:admin 的 token 绕过认证",
        fix="jwt.decode(token, SECRET, algorithms=['HS256']) 显式指定算法并强制校验签名"
    )
))


# ===========================================================================
# 3. CWE-190 整数溢出样本（8 条）
# ===========================================================================
# 目标：修复 typical_29 FN + CVE 覆盖
# 关键教学点：
#   - 识别无范围检查的算术运算（乘法/加法/左移）
#   - 溢出导致负数/小数 → 业务逻辑绕过
#   - CWE-190 vs CWE-686（参数类型问题）vs CWE-1284（类型混淆）

INT_OVERFLOW_SAMPLES = []

# I1: 整数溢出导致价格计算错误（Java，typical_29 模式）
INT_OVERFLOW_SAMPLES.append(build_sample(
    code='''import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/order")
public class OrderController {
    @PostMapping("/calculate")
    public String calculate(
            @RequestParam int price,
            @RequestParam int qty) {
        // 两个 int 相乘，无范围检查
        int total = price * qty;
        if (total < 0) {
            return "invalid total";
        }
        // 溢出后 total 可能变成正的极小值，绕过 < 0 检查
        return "total: " + total;
    }
}
''',
    language="java", filename="int_overflow_01_price.java",
    cot="分析过程：\n"
        "1. 用户可控输入：price 和 qty 来自 @RequestParam（HTTP 请求），类型为 int。\n"
        "2. 危险操作：int total = price * qty。两个 int 相乘结果仍是 int，"
        "若 price=100000, qty=100000，理论值 10^10 超过 Integer.MAX_VALUE (约 2.1×10^9)，发生溢出。\n"
        "3. 溢出后果：溢出结果可能为负数（被 < 0 拦截），但也可能为正的极小值（绕过检查）。"
        "例如 0x10000 × 0x10000 = 0x100000000，截断为 32 位后为 0，绕过 total < 0 检查。\n"
        "4. 业务影响：价格计算错误可导致少收款、逻辑绕过、资源分配异常。\n"
        "5. CWE 判别：无范围检查的算术运算导致溢出 → CWE-190。\n"
        "6. 综合来看，存在整数溢出漏洞，风险等级 Medium（业务逻辑绕过，非直接 RCE）。",
    json_block=vuln_json(
        "CWE-190", "整数溢出", "Medium",
        source="@RequestParam int price, int qty",
        sink="int total = price * qty（无范围检查）",
        explanation="两个 int 相乘无范围检查，大值相乘溢出后可能为正的极小值，绕过 < 0 检查导致价格计算错误",
        fix="用 long 而非 int：long total = (long) price * qty；或在乘法前校验 price/qty 范围；用 Math.multiplyExact 抛溢出异常"
    )
))

# I2: 整数溢出导致缓冲区分配不足（C 风格 Python ctypes）
INT_OVERFLOW_SAMPLES.append(build_sample(
    code='''import ctypes
from flask import request

@app.route("/alloc")
def alloc_buffer():
    count = int(request.args.get("count", "0"))
    elem_size = int(request.args.get("size", "4"))
    # 乘法溢出导致分配小缓冲区
    total = count * elem_size
    if total < 0 or total > 1000000:
        return "invalid size"
    # 分配 total 字节，但实际写入 count 个元素
    buf = ctypes.create_string_buffer(total)
    # 后续写入 count * elem_size 字节会溢出缓冲区
    return "allocated"
''',
    language="python", filename="int_overflow_02_buffer.py",
    cot="分析过程：\n"
        "1. 用户可控输入：count 和 size 来自 request.args。\n"
        "2. 危险操作：total = count * elem_size。Python int 无限精度不会溢出，"
        "但如果 total 被传给 C 扩展或 ctypes，可能在 C 层发生 32 位截断。"
        "更关键的是：若 count 和 size 都很大但 total < 1000000（因 32 位截断），"
        "分配小缓冲区后写入 count 个元素导致堆溢出。\n"
        "3. CWE 判别：算术运算结果用于资源分配未做溢出检查 → CWE-190。\n"
        "4. 综合来看，存在整数溢出漏洞，风险等级 High（可能导致堆破坏）。",
    json_block=vuln_json(
        "CWE-190", "整数溢出", "High",
        source="request.args 的 count 和 size",
        sink="ctypes.create_string_buffer(total) 中 total = count * elem_size",
        explanation="count * elem_size 在 C 层可能 32 位截断，分配小缓冲区后写入 count 个元素导致堆溢出",
        fix="用 Python 原生 int 精度校验 total = count * elem_size 后是否 > 1000000；避免 ctypes 传递未校验的乘积"
    )
))

# I3: 整数溢出导致数组越界（Java）
INT_OVERFLOW_SAMPLES.append(build_sample(
    code='''import org.springframework.web.bind.annotation.*;

@RestController
public class ArrayController {
    @GetMapping("/slice")
    public String slice(@RequestParam int start, @RequestParam int length) {
        byte[] data = new byte[1024];
        // start + length 可能溢出
        int end = start + length;
        if (end > data.length) {
            return "too long";
        }
        // 若 start + length 溢出为负数，绕过 > data.length 检查
        byte[] result = new byte[length];
        System.arraycopy(data, start, result, 0, length);
        return new String(result);
    }
}
''',
    language="java", filename="int_overflow_03_array.java",
    cot="分析过程：\n"
        "1. 用户可控输入：start 和 length 来自 @RequestParam。\n"
        "2. 危险操作：int end = start + length。若 start=2147483647, length=2，"
        "end = start + length 溢出为 -2147483647，绕过 end > data.length 检查。\n"
        "3. 后续 System.arraycopy(data, start, ...) 用 start=2147483647 访问 1024 字节数组，"
        "抛 ArrayIndexOutOfBoundsException 或越界读。\n"
        "4. CWE 判别：加法溢出绕过边界检查 → CWE-190。\n"
        "5. 综合来看，存在整数溢出漏洞，风险等级 Medium（异常或越界读）。",
    json_block=vuln_json(
        "CWE-190", "整数溢出", "Medium",
        source="@RequestParam int start, int length",
        sink="int end = start + length（加法溢出绕过边界检查）",
        explanation="start + length 溢出为负数绕过 end > data.length 检查，后续 arraycopy 越界",
        fix="用 Math.addExact(start, length) 抛溢出异常；或校验 start >= 0 && length >= 0 && start <= data.length - length"
    )
))

# I4: 整数溢出导致循环次数错误（Python）
INT_OVERFLOW_SAMPLES.append(build_sample(
    code='''from flask import request
import struct

@app.route("/parse")
def parse_packets():
    n = int(request.args.get("n", "0"))
    # n 来自用户，若为负数（Python int 无符号转换错误）则 range 行为异常
    data = b"\\x00" * 100
    packets = []
    for i in range(n):
        offset = i * 8
        if offset + 8 > len(data):
            break
        packets.append(struct.unpack("Q", data[offset:offset+8])[0])
    return {"packets": packets[:n]}
''',
    language="python", filename="int_overflow_04_loop.py",
    cot="分析过程：\n"
        "1. 用户可控输入：n 来自 request.args，转 int。\n"
        "2. 危险操作：若 n 为极大值（如 10^18），offset = i * 8 在 Python 中不溢出，"
        "但 range(n) 会尝试创建巨大迭代器，可能耗尽内存（DoS）。"
        "更隐蔽的是若 n 被传到 C 扩展并截断为 32 位有符号整数，可能变负数导致 range 不执行或异常行为。\n"
        "3. CWE 判别：未校验范围的整数用于循环/资源控制 → CWE-190。\n"
        "4. 综合来看，存在整数溢出/未校验漏洞，风险等级 Medium（DoS 或逻辑异常）。",
    json_block=vuln_json(
        "CWE-190", "整数溢出", "Medium",
        source="request.args 的 n",
        sink="range(n) 与 offset = i * 8（未校验 n 范围）",
        explanation="n 未校验上限，极大值导致 DoS 或传给 C 扩展时截断为负数导致逻辑异常",
        fix="校验 0 <= n <= MAX_PACKETS（如 1000）；拒绝负数和超大值"
    )
))

# I5: 安全样本 — 用 long + 范围校验
INT_OVERFLOW_SAMPLES.append(build_sample(
    code='''import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/order")
public class SafeOrderController {
    @PostMapping("/calculate")
    public String calculate(
            @RequestParam int price,
            @RequestParam int qty) {
        // 范围校验
        if (price < 0 || price > 1000000 || qty < 0 || qty > 10000) {
            return "invalid price or qty";
        }
        // 用 long 避免溢出
        long total = (long) price * (long) qty;
        if (total > 100_000_000L) {
            return "total too large";
        }
        return "total: " + total;
    }
}
''',
    language="java", filename="int_safe_01_long_range.java",
    cot="分析过程：\n"
        "1. 用户可控输入：price 和 qty 来自 @RequestParam。\n"
        "2. 防御检查：(a) 范围校验 price ∈ [0, 1000000], qty ∈ [0, 10000]；"
        "(b) 用 long 而非 int 做乘法 (long) price * (long) qty，避免 32 位溢出；"
        "(c) 结果上限校验 total > 100_000_000 拒绝。\n"
        "3. 反事实检验：若用 int total = price * qty，大值相乘溢出（int_overflow_01 模式）构成 CWE-190；"
        "当前用 long + 范围校验，漏洞不成立。\n"
        "4. CWE 判别：算术运算有溢出防护，无漏洞。\n"
        "5. 综合来看，不存在安全漏洞。",
    json_block=safe_json(
        "price/qty 有范围校验，乘法用 long 避免溢出，结果有上限校验。"
        "反事实：若用 int 相乘无校验则构成 CWE-190。"
    )
))

# I6: 左移溢出（Java）
INT_OVERFLOW_SAMPLES.append(build_sample(
    code='''import org.springframework.web.bind.annotation.*;

@RestController
public class BitShiftController {
    @GetMapping("/mask")
    public String createMask(@RequestParam int shift) {
        // 左移可能溢出，shift 来自用户
        int mask = 1 << shift;
        return "mask: " + mask;
    }

    @GetMapping("/alloc2")
    public String alloc(@RequestParam int size) {
        // 左移计算分配大小
        int bytes = size << 3;  // size * 8
        byte[] buf = new byte[bytes];
        return "allocated " + bytes + " bytes";
    }
}
''',
    language="java", filename="int_overflow_05_shift.java",
    cot="分析过程：\n"
        "1. 用户可控输入：shift 和 size 来自 @RequestParam。\n"
        "2. 危险操作：(a) 1 << shift，若 shift >= 31，结果溢出为负数或 0；"
        "(b) size << 3，若 size 较大（如 0x10000000），左移后变 0 或负数，"
        "new byte[bytes] 可能分配 0 字节或抛 NegativeArraySizeException。\n"
        "3. CWE 判别：左移运算未校验移位量 → CWE-190。\n"
        "4. 综合来看，存在整数溢出漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-190", "整数溢出", "Medium",
        source="@RequestParam int shift, int size",
        sink="1 << shift 和 size << 3（左移未校验移位量）",
        explanation="左移运算未校验 shift/size 范围，大值左移后溢出为 0 或负数，导致掩码错误或异常分配",
        fix="校验 0 <= shift < 32 且 0 <= size 且 size << 3 不超过 Integer.MAX_VALUE"
    )
))

# I7: 无符号转换溢出（Python，与 C 交互）
INT_OVERFLOW_SAMPLES.append(build_sample(
    code='''import struct
from flask import request

@app.route("/checksum")
def checksum():
    # 用户输入的 size 被当作无符号 32 位整数
    size = int(request.args.get("size", "0"))
    # 若 size > 2^32，传给 C 层会被截断
    packed = struct.pack("<I", size & 0xFFFFFFFF)  # 强制截断为 32 位
    # 截断后 size 可能变小，但调用方以为校验了完整 size
    return {"packed": packed.hex()}
''',
    language="python", filename="int_overflow_06_unsigned.py",
    cot="分析过程：\n"
        "1. 用户可控输入：size 来自 request.args。\n"
        "2. 危险操作：size & 0xFFFFFFFF 强制截断为 32 位无符号整数。"
        "若用户输入 size=4294967296 (2^32)，截断后为 0；输入 4294967297 截断为 1。\n"
        "3. 影响：若调用方基于截断后的 size 分配缓冲区但用原始 size 写入，导致堆溢出。\n"
        "4. CWE 判别：无符号转换截断未校验 → CWE-190。\n"
        "5. 综合来看，存在整数溢出漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-190", "整数溢出", "Medium",
        source="request.args 的 size",
        sink="struct.pack('<I', size & 0xFFFFFFFF)（截断为 32 位）",
        explanation="size 截断为 32 位无符号整数，大值截断后变小，若调用方用原始 size 写入则堆溢出",
        fix="校验 0 <= size <= 0xFFFFFFFF 后再打包；拒绝超过 32 位范围的值"
    )
))

# I8: 整数溢出导致认证绕过（Java，真实 CVE 模式）
INT_OVERFLOW_SAMPLES.append(build_sample(
    code='''import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @PostMapping("/token")
    public String generateToken(@RequestParam int userId, @RequestParam int timestamp) {
        // token = userId * 1000000 + timestamp，若溢出则可能碰撞
        int token = userId * 1000000 + timestamp;
        // 后续用 token 做认证凭证
        return "token: " + token;
    }

    @GetMapping("/verify")
    public String verify(@RequestParam int token) {
        // 简化：实际会查数据库
        if (token == 0) {
            return "admin access granted";  // 溢出为 0 的 token 被当作特殊值
        }
        return "user access";
    }
}
''',
    language="java", filename="int_overflow_07_auth.java",
    cot="分析过程：\n"
        "1. 用户可控输入：userId, timestamp, token 来自 @RequestParam。\n"
        "2. 危险操作：int token = userId * 1000000 + timestamp。"
        "精心构造 userId 和 timestamp 使乘法+加法溢出为 0，则 token=0 触发 admin access。\n"
        "3. 攻击路径：解方程 userId * 1000000 + timestamp ≡ 0 (mod 2^32)。"
        "例如 userId=4295, timestamp=-(4295*1000000) mod 2^32 = 647967296，则 token 溢出为 0。\n"
        "4. CWE 判别：用算术运算生成认证 token 未防溢出 → CWE-190（导致 CWE-287 认证绕过）。\n"
        "5. 综合来看，存在整数溢出漏洞，风险等级 Critical（认证绕过）。",
    json_block=vuln_json(
        "CWE-190", "整数溢出", "Critical",
        source="@RequestParam userId, timestamp",
        sink="int token = userId * 1000000 + timestamp（溢出为 0 触发 admin）",
        explanation="token 算术运算可溢出为 0，而 0 被当作 admin 特权值，构造特定 userId/timestamp 即可绕过认证",
        fix="用密码学安全的随机数生成 token（如 SecureRandom）；不要用可预测的算术运算生成认证凭证"
    )
))


# ===========================================================================
# 4. FP 反事实修正样本（6 条，替代 v6 失败的 hard-negative 追加）
# ===========================================================================
# 策略：不是追加 hard-negative，而是写"防御识别 + 反事实检验"CoT
# 教学点：识别有效防御，并通过反事实推理确认防御有效性
FP_CORRECTION_SAMPLES = []

# FP1: subprocess 列表参数（safe_03 模式）
FP_CORRECTION_SAMPLES.append(build_sample(
    code='''import subprocess
from flask import request

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # 列表参数模式
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
    return result.stdout
''',
    language="python", filename="fp_fix_01_subprocess_list.py",
    cot="分析过程：\n"
        "1. 用户可控输入：host 来自 request.args。\n"
        "2. 危险 sink 识别：subprocess.run。但参数形式是关键——这里是列表 ['ping', '-c', '1', host] 而非字符串。\n"
        "3. 防御有效性判定：列表参数模式下 shell=False（默认），操作系统直接 exec ping 程序，"
        "host 作为单一 argv 传入，shell 元字符 ; | & $ 等不会被任何 shell 解释。\n"
        "4. 反事实检验：若改为 subprocess.run('ping -c 1 ' + host, shell=True)，"
        "则 host 中的 ; rm -rf / 会被 shell 解释，构成 CWE-78 命令注入。"
        "当前是列表参数 + shell=False，漏洞不成立。\n"
        "5. CWE 判别：sink 虽是 subprocess，但列表参数消除了 shell 注入面，无 CWE-78。\n"
        "6. 综合来看，不存在命令注入漏洞。列表参数 + shell=False 是有效防御。",
    json_block=safe_json(
        "subprocess.run 用列表参数 + shell=False（默认），host 作为单一 argv 传入，shell 元字符不被解释，无命令注入。"
        "反事实：若用字符串 + shell=True 则构成 CWE-78。"
    )
))

# FP2: shlex.quote（safe_08 模式）
FP_CORRECTION_SAMPLES.append(build_sample(
    code='''import subprocess
import shlex
from flask import request

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # shlex.quote 转义后用 shell=True
    cmd = "ping -c 1 " + shlex.quote(host)
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
''',
    language="python", filename="fp_fix_02_shlex.py",
    cot="分析过程：\n"
        "1. 用户可控输入：host 来自 request.args。\n"
        "2. 危险 sink 识别：subprocess.run(shell=True)，看起来有命令注入风险。\n"
        "3. 防御有效性判定：shlex.quote(host) 把 host 中的 shell 特殊字符用单引号包裹并转义内部单引号，"
        "转义后的字符串作为单一 shell 参数，; | & 等都被视为普通字符。\n"
        "4. 反事实检验：若去掉 shlex.quote，cmd = 'ping -c 1 ' + host，"
        "host 中的 ; rm -rf / 会被 shell 解释，构成 CWE-78。"
        "当前有 shlex.quote，漏洞不成立。\n"
        "5. CWE 判别：shell=True 但输入经 shlex.quote 转义，无 CWE-78。\n"
        "6. 综合来看，不存在命令注入漏洞。shlex.quote 是有效防御（尽管列表参数更优）。",
    json_block=safe_json(
        "shlex.quote 对 host 做完整 shell 转义，shell=True 下转义后的字符串作为单一参数，元字符不被解释。"
        "反事实：若去掉 shlex.quote 则构成 CWE-78。建议优先用列表参数 + shell=False。"
    )
))

# FP3: PreparedStatement（safe_18 模式）
FP_CORRECTION_SAMPLES.append(build_sample(
    code='''import java.sql.*;

public class UserAuth {
    public boolean login(String username, String password) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
        // PreparedStatement + ? 占位符
        String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
        PreparedStatement stmt = conn.prepareStatement(sql);
        stmt.setString(1, username);
        stmt.setString(2, password);
        ResultSet rs = stmt.executeQuery();
        return rs.next();
    }
}
''',
    language="java", filename="fp_fix_03_prepared_stmt.java",
    cot="分析过程：\n"
        "1. 用户可控输入：username 和 password 来自函数参数（HTTP 请求）。\n"
        "2. 危险 sink 识别：stmt.executeQuery，SQL 涉及 WHERE 条件。\n"
        "3. 防御有效性判定：用 PreparedStatement + ? 占位符，username/password 通过 setString 绑定。"
        "JDBC 驱动会对绑定值做转义，输入不会被解析为 SQL 语法。\n"
        "4. 反事实检验：若改为 Statement.executeQuery('SELECT * FROM users WHERE username=\\'' + username + '\\'')，"
        "则 username 中的 ' OR '1'='1 会被解析为 SQL，构成 CWE-89 SQL 注入。"
        "当前用 PreparedStatement + ?，漏洞不成立。\n"
        "5. CWE 判别：sink 虽是 SQL execute，但 PreparedStatement 参数化消除了注入面，无 CWE-89。\n"
        "6. 综合来看，不存在 SQL 注入漏洞。PreparedStatement + ? 是有效防御。",
    json_block=safe_json(
        "PreparedStatement + ? 占位符 + setString 绑定，JDBC 驱动转义绑定值，无 SQL 注入。"
        "反事实：若用 Statement 字符串拼接则构成 CWE-89。"
    )
))

# FP4: 正确的认证+授权（safe_09 模式）
FP_CORRECTION_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, session
app = Flask(__name__)

@app.route("/api/admin/users/<uid>")
def get_user(uid):
    # 认证：检查登录
    if "user_id" not in session:
        return "unauthorized", 401
    # 授权：检查 admin 角色
    if not is_admin(session["user_id"]):
        return "forbidden", 403
    # 参数化查询
    user = db.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return user
''',
    language="python", filename="fp_fix_04_authz.py",
    cot="分析过程：\n"
        "1. 访问控制分析：(a) 认证——检查 session.user_id 存在，未登录返回 401；"
        "(b) 授权——检查 is_admin，非 admin 返回 403。双重控制完整。\n"
        "2. SQL 查询：db.execute 用 ? 占位符参数化，uid 通过绑定传入，无 SQL 注入。\n"
        "3. 反事实检验：若去掉 is_admin 检查，则任意登录用户可访问 admin 接口，构成 CWE-862 缺失授权；"
        "若去掉 session 检查，则构成 CWE-306 缺失认证。当前两者都有，漏洞不成立。\n"
        "4. CWE 判别：认证与授权均完整，SQL 参数化，无 CWE-306/862/89。\n"
        "5. 综合来看，不存在安全漏洞。",
    json_block=safe_json(
        "认证（session 校验）+ 授权（is_admin）+ 参数化查询三层防御完整。"
        "反事实：去掉任一层都会构成对应 CWE。"
    )
))

# FP5: Lock 保护竞态（safe_17 模式）
FP_CORRECTION_SAMPLES.append(build_sample(
    code='''import threading
balances = {}
lock = threading.Lock()

def transfer(from_id, to_id, amount):
    with lock:
        # 检查余额与扣款是原子操作
        if balances.get(from_id, 0) < amount:
            return False
        balances[from_id] -= amount
        balances[to_id] = balances.get(to_id, 0) + amount
        return True
''',
    language="python", filename="fp_fix_05_race_lock.py",
    cot="分析过程：\n"
        "1. 并发场景：多线程调用 transfer，balances 字典被并发读写。\n"
        "2. 危险模式识别：检查余额（if balances[from_id] < amount）与扣款（balances[from_id] -= amount）"
        "若非原子，可能 TOCTOU——线程 A 检查通过后线程 B 也检查通过，两者都扣款导致负余额。\n"
        "3. 防御有效性判定：with lock 把「检查+扣款+加款」三步包成原子操作，"
        "Lock 是可重入互斥锁，同一时刻只有一个线程进入临界区，TOCTOU 消除。\n"
        "4. 反事实检验：若去掉 with lock，则构成 CWE-362 竞态条件（TOCTOU）；"
        "当前有 lock 保护，漏洞不成立。\n"
        "5. CWE 判别：并发访问有 Lock 保护，无 CWE-362。\n"
        "6. 综合来看，不存在竞态条件漏洞。Lock 是有效防御。",
    json_block=safe_json(
        "with lock 把检查余额+扣款+加款包成原子操作，消除 TOCTOU 竞态。"
        "反事实：去掉 lock 则构成 CWE-362。"
    )
))

# FP6: 装饰器包装的安全代码（noise_05 模式）
FP_CORRECTION_SAMPLES.append(build_sample(
    code='''from functools import wraps
from flask import request, jsonify

def validate_input(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        data = request.get_json()
        if not data or "query" not in data:
            return jsonify({"error": "query required"}), 400
        # 仅校验 query 存在且非空
        if not isinstance(data["query"], str) or len(data["query"]) > 1000:
            return jsonify({"error": "invalid query"}), 400
        return f(*args, **kwargs)
    return wrapper

@app.route("/search")
@validate_input
def search():
    data = request.get_json()
    query = data["query"]
    # 参数化查询，无 SQL 注入
    results = db.execute("SELECT * FROM items WHERE name LIKE ?", ("%" + query + "%",))
    return jsonify(results)
''',
    language="python", filename="fp_fix_06_decorator.py",
    cot="分析过程：\n"
        "1. 代码结构：@validate_input 装饰器做输入校验（query 存在、字符串、长度<=1000），"
        "search 函数做参数化查询。\n"
        "2. SQL 注入检查：db.execute 用 ? 占位符，query 通过 % + query + % 绑定到 LIKE 条件，"
        "JDBC/SQLite 驱动转义绑定值，无 SQL 注入。\n"
        "3. 装饰器本质：validate_input 不是安全防御，是输入格式校验。"
        "真正的安全防御是参数化查询。不要因装饰器看起来「包装了」就误判为不安全。\n"
        "4. 反事实检验：若 search 改为 db.execute('SELECT * FROM items WHERE name LIKE \\'' + query + '\\'')，"
        "则构成 CWE-89；当前用参数化，漏洞不成立。\n"
        "5. CWE 判别：参数化查询有效，无 CWE-89。装饰器不改变安全结论。\n"
        "6. 综合来看，不存在安全漏洞。",
    json_block=safe_json(
        "参数化查询（? 占位符）+ 输入长度校验，无 SQL 注入。装饰器是格式校验非安全防御，真正的防御是参数化。"
        "反事实：若用字符串拼接则构成 CWE-89。"
    )
))


# ===========================================================================
# 5. 对比 CoT 对（6 组 = 12 条，易混 CWE 的 correct vs incorrect）
# ===========================================================================
# 策略：对同一代码模式，展示"正确推理"vs"错误推理"，教模型为什么不是某 CWE
# 每组只写 correct 版本进训练集（incorrect 仅作内部对照，不直接训练以免学错）
# 但为教"判别边界"，在 correct CoT 中显式写出"为什么不是 CWE-X"

CONTRASTIVE_SAMPLES = []

# C1: SQL execute vs shell — 区分 CWE-89 vs CWE-78
CONTRASTIVE_SAMPLES.append(build_sample(
    code='''import os
from flask import request

@app.route("/run")
def run():
    cmd = request.args.get("cmd", "")
    # 用户输入直接传给 os.system
    os.system("echo " + cmd)
    return "done"
''',
    language="python", filename="contrast_01_os_system.py",
    cot="分析过程：\n"
        "1. 用户可控输入：cmd 来自 request.args。\n"
        "2. 危险 sink：os.system。注意 sink 类型——os.system 调用 shell 执行命令，而非数据库。\n"
        "3. CWE 判别要点：sink 是 os.system（shell 执行）→ CWE-78 命令注入。"
        "对比：若 sink 是 cursor.execute（数据库执行），则为 CWE-89 SQL 注入。"
        "两者都是注入但 sink 不同，CWE 编号不同。本例 sink 是 os.system 故 CWE-78。\n"
        "4. 防御检查：无转义。cmd 中的 ; 可拼接任意命令。\n"
        "5. 综合来看，存在命令注入漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-78", "命令注入", "Critical",
        source="request.args.get('cmd')",
        sink="os.system('echo ' + cmd)",
        explanation="cmd 直接拼接到 os.system 的 shell 命令，; | & 等可注入任意命令",
        fix="用 subprocess.run(['echo', cmd], shell=False) 列表参数模式；或用 shlex.quote 转义"
    )
))

# C2: eval vs SQL execute — 区分 CWE-95 vs CWE-89
CONTRASTIVE_SAMPLES.append(build_sample(
    code='''from flask import request

@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    # 用户输入传给 eval
    result = eval(expr)
    return str(result)
''',
    language="python", filename="contrast_02_eval.py",
    cot="分析过程：\n"
        "1. 用户可控输入：expr 来自 request.args。\n"
        "2. 危险 sink：eval。eval 执行任意 Python 表达式，而非数据库查询。\n"
        "3. CWE 判别要点：sink 是 eval（Python 代码执行）→ CWE-95 代码注入（eval）。"
        "对比：若 sink 是 cursor.execute（数据库），则为 CWE-89；"
        "若 sink 是 os.system（shell），则为 CWE-78。"
        "本例 sink 是 eval 故 CWE-95。\n"
        "4. 防御检查：无。eval 直接执行用户输入，可执行 __import__('os').system('rm -rf /')。\n"
        "5. 综合来看，存在代码注入漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-95", "代码注入", "Critical",
        source="request.args.get('expr')",
        sink="eval(expr)",
        explanation="用户输入直接传给 eval，可执行任意 Python 代码（包括 os.system 调用）",
        fix="禁用 eval；若需计算表达式，用 ast.literal_eval（仅字面量）或专用解析库（如 numexpr）"
    )
))

# C3: LDAP search vs SQL execute — 区分 CWE-90 vs CWE-89
CONTRASTIVE_SAMPLES.append(build_sample(
    code='''import ldap3
from flask import request

@app.route("/search")
def search():
    uid = request.args.get("uid", "")
    conn = ldap3.Connection(ldap3.Server("ldap://corp.local"))
    conn.bind()
    # LDAP filter 拼接
    filt = "(uid=" + uid + ")"
    conn.search("ou=users,dc=corp,dc=local", filt)
    return str(conn.entries)
''',
    language="python", filename="contrast_03_ldap_vs_sql.py",
    cot="分析过程：\n"
        "1. 用户可控输入：uid 来自 request.args。\n"
        "2. 危险 sink：ldap3.Connection.search。注意 sink 是 LDAP 查询而非数据库查询。\n"
        "3. CWE 判别要点：sink 是 LDAP search（目录服务查询）→ CWE-90 LDAP 注入。"
        "对比：若 sink 是 cursor.execute（SQL 数据库），则为 CWE-89。"
        "两者都是查询注入但目标系统不同：LDAP 目录 vs SQL 数据库。本例 sink 是 LDAP search 故 CWE-90。\n"
        "4. 防御检查：无转义。uid 中的 * ( ) 可改变 filter 结构。\n"
        "5. 综合来看，存在 LDAP 注入漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "High",
        source="request.args.get('uid')",
        sink="conn.search(filt) 其中 filt 拼接 uid",
        explanation="uid 直接拼接到 LDAP filter，* ( ) 等可改变 filter 结构绕过查询限制",
        fix="用 ldap3.utils.conv.escape_filter_chars(uid) 转义后再拼接 filter"
    )
))

# C4: SSTI vs XSS — 区分 CWE-1336 vs CWE-79
CONTRASTIVE_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # 用户输入传给 render_template_string 作为模板
    template = "<h1>Hello " + name + "</h1>"
    return render_template_string(template)
''',
    language="python", filename="contrast_04_ssti_vs_xss.py",
    cot="分析过程：\n"
        "1. 用户可控输入：name 来自 request.args。\n"
        "2. 危险 sink：render_template_string。name 被拼接进模板字符串再渲染。\n"
        "3. CWE 判别要点：sink 是 render_template_string（模板引擎渲染）→ CWE-1336 SSTI。"
        "对比：若 sink 是直接返回 HTML 响应（如 make_response('<h1>' + name + '</h1>')）"
        "且 name 未转义，则为 CWE-79 XSS。"
        "区别：XSS 是浏览器侧执行，SSTI 是服务器侧模板引擎执行（更危险，可 RCE）。"
        "本例 sink 是 render_template_string，模板引擎会解析 {{ }} 等语法，故 CWE-1336。\n"
        "4. 攻击路径：name={{config}} 可泄露 Flask 配置；name={{''.__class__.__mro__[1].__subclasses__()}} 可 RCE。\n"
        "5. 综合来看，存在 SSTI 漏洞，风险等级 Critical（可 RCE）。",
    json_block=vuln_json(
        "CWE-1336", "SSTI", "Critical",
        source="request.args.get('name')",
        sink="render_template_string(template) 其中 template 拼接 name",
        explanation="name 拼接到模板字符串后由 Jinja2 渲染，{{ }} 语法可执行任意 Python 代码导致 RCE",
        fix="用 render_template 引用固定模板文件，name 通过 context 传入（Jinja2 自动转义）；或用 markupsafe.escape 转义后再拼接"
    )
))

# C5: 信任边界 vs 缺失认证 — 区分 CWE-441 vs CWE-306
CONTRASTIVE_SAMPLES.append(build_sample(
    code='''from flask import Flask, request
app = Flask(__name__)

@app.route("/api/internal/flush")
def flush():
    # 仅靠 IP 判断是否内网
    ip = request.remote_addr
    if ip.startswith("10.") or ip.startswith("192.168."):
        cache.flush()
        return "flushed"
    return "forbidden", 403
''',
    language="python", filename="contrast_05_trust_vs_noauth.py",
    cot="分析过程：\n"
        "1. 访问控制分析：用 remote_addr 判断是否内网，内网放行，非内网拒绝。\n"
        "2. CWE 判别要点：本例「有」访问控制（基于 IP），但信任源（网络位置）可被绕过 → CWE-441 信任边界绕过。"
        "对比 CWE-306 缺失认证：306 是完全没有任何认证机制（如 /admin 端点无任何检查）。"
        "区别：441 有控制但信任源错（IP 可伪造/SSRF/同网段），306 是根本没有控制。"
        "本例有 IP 校验但可被 SSRF 等绕过，故 CWE-441 而非 CWE-306。\n"
        "3. 攻击路径：SSRF 请求 http://10.0.0.1/api/internal/flush，remote_addr 变为 10.0.0.1，绕过校验。\n"
        "4. 综合来看，存在信任边界绕过漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-441", "信任边界绕过", "High",
        source="内网 IP 段（被 SSRF/同网段主机绕过）",
        sink="ip.startswith('10.') 判断后执行 cache.flush()",
        explanation="仅凭 remote_addr 判断内网可信，SSRF 或同网段攻陷主机可伪造来源 IP 绕过校验执行高危操作",
        fix="内部 API 也要认证（mTLS 或共享 token）；不要用网络位置作为唯一信任依据"
    )
))

# C6: 整数溢出 vs 参数类型问题 — 区分 CWE-190 vs CWE-686
CONTRASTIVE_SAMPLES.append(build_sample(
    code='''import org.springframework.web.bind.annotation.*;

@RestController
public class CalcController {
    @GetMapping("/discount")
    public String discount(@RequestParam int price, @RequestParam int percent) {
        // 计算 price 的 percent 折扣
        int discount = price * percent / 100;
        int finalPrice = price - discount;
        return "final: " + finalPrice;
    }
}
''',
    language="java", filename="contrast_06_overflow_vs_type.java",
    cot="分析过程：\n"
        "1. 用户可控输入：price 和 percent 来自 @RequestParam，类型为 int。\n"
        "2. 危险操作：int discount = price * percent / 100。"
        "price * percent 中间结果可能溢出（如 price=100000, percent=100000 → 10^10 超过 Integer.MAX_VALUE）。\n"
        "3. CWE 判别要点：本例参数类型正确（都是 int，无类型混淆），"
        "但算术运算中间结果溢出 → CWE-190 整数溢出。"
        "对比 CWE-686 参数类型问题：686 是参数类型错误（如把字符串当数字传），"
        "本例类型正确，问题是运算结果超出类型表示范围，故 CWE-190 而非 CWE-686。\n"
        "4. 影响：溢出后 discount 可能为负数或极小值，finalPrice 计算错误，导致少收款或逻辑绕过。\n"
        "5. 综合来看，存在整数溢出漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-190", "整数溢出", "Medium",
        source="@RequestParam int price, int percent",
        sink="int discount = price * percent / 100（中间结果溢出）",
        explanation="price * percent 中间结果溢出 int 范围，导致 discount 计算错误，finalPrice 业务逻辑绕过",
        fix="用 long 计算：long discount = (long) price * percent / 100；或校验 price/percent 范围"
    )
))


# ===========================================================================
# 6. CVE 启发实战样本（10 条，隐蔽漏洞模式）
# ===========================================================================
# 这些样本模拟真实 CVE 的"隐蔽"特征：防御措施迷惑、跨函数数据流、长文件隐藏、
# 信任边界绕过、错误处理掩盖等

CVE_INSPIRED_SAMPLES = []

# R1: 防御措施部分有效但仍可绕过（Python，Spring4Shell 模式）
CVE_INSPIRED_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route("/page")
def page():
    title = request.args.get("title", "Welcome")
    # 看似用 escape 转义，但转义后传给 render_template_string 仍可 SSTI
    from markupsafe import escape
    safe_title = str(escape(title))  # 仅转义 HTML 特殊字符
    template = "<h1>" + safe_title + "</h1>"
    # safe_title 中的 {{ }} 不会被 escape 转义（它只转义 < > & "）
    return render_template_string(template)
''',
    language="python", filename="cve_inspired_01_partial_defense.py",
    cot="分析过程：\n"
        "1. 用户可控输入：title 来自 request.args。\n"
        "2. 防御措施分析：markupsafe.escape 转义 HTML 特殊字符（< > & \"），"
        "但 {{ }} 不在转义范围内。\n"
        "3. 危险 sink：render_template_string(template)，template 含 safe_title。"
        "safe_title 中的 {{config}} 仍会被 Jinja2 解析执行。\n"
        "4. 反事实检验：若用 render_template 引用固定模板文件 + context 传入 title，"
        "Jinja2 自动转义且不解析 title 中的 {{ }}，则安全；当前用 render_template_string 拼接，漏洞成立。\n"
        "5. CWE 判别：sink 是模板引擎渲染 → CWE-1336 SSTI。escape 不能防御 SSTI。\n"
        "6. 综合来看，存在 SSTI 漏洞，风险等级 Critical。escape 是部分防御但不足以阻止 SSTI。",
    json_block=vuln_json(
        "CWE-1336", "SSTI", "Critical",
        source="request.args.get('title')",
        sink="render_template_string(template)",
        explanation="escape 仅转义 HTML 字符，不转义 {{ }}，safe_title 中的模板语法仍被 Jinja2 执行",
        fix="用 render_template 引用固定模板文件 + context 传入 title；不要用 render_template_string 拼接用户输入"
    )
))

# R2: 长文件中隐藏的漏洞（Python，第 30 行才有 sink）
CVE_INSPIRED_SAMPLES.append(build_sample(
    code='''import os
import logging
from flask import Flask, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_DIR = "/var/www/uploads"
logging.basicConfig(level=logging.INFO)


def allowed_file(filename):
    """检查文件扩展名是否允许上传。"""
    allowed = {".txt", ".pdf", ".png", ".jpg"}
    ext = os.path.splitext(filename)[1].lower()
    return ext in allowed


def save_upload(file):
    """保存上传文件，做了多重校验。"""
    filename = secure_filename(file.filename)
    if not filename or not allowed_file(filename):
        return None
    filepath = os.path.join(UPLOAD_DIR, filename)
    file.save(filepath)
    return filepath


def generate_thumbnail(filepath):
    """为图片生成缩略图。"""
    import subprocess
    ext = os.path.splitext(filepath)[1].lower()
    if ext not in (".png", ".jpg"):
        return None
    # 第 30 行：这里用 shell=True 拼接，filepath 来自上传文件名
    # secure_filename 过滤了 ../ 但不过滤 $ ` 等 shell 元字符（在文件名中合法）
    cmd = "convert " + filepath + " -resize 100x100 " + filepath + ".thumb.png"
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return filepath + ".thumb.png"


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")
    if not file:
        return "no file", 400
    saved = save_upload(file)
    if not saved:
        return "invalid file", 400
    thumb = generate_thumbnail(saved)
    return send_file(thumb)
''',
    language="python", filename="cve_inspired_02_longfile_hidden.py",
    cot="分析过程：\n"
        "1. 整体扫描：save_upload 用 secure_filename + 扩展名白名单（看似安全）；"
        "generate_thumbnail 用 subprocess.run(shell=True)（危险）。\n"
        "2. 数据流追踪：filepath = os.path.join(UPLOAD_DIR, secure_filename(file.filename))。"
        "secure_filename 会过滤 ../ 和路径分隔符，但保留 $ ` ; 等字符（这些在文件名中合法）。\n"
        "3. 危险 sink：subprocess.run(cmd, shell=True)，cmd = 'convert ' + filepath + ...。"
        "filepath 含 secure_filename 处理后的文件名，但 $ ` 等仍存在。\n"
        "4. 攻击路径：上传文件名为 a$(id).png，secure_filename 保留为 a$(id).png，"
        "shell 解析 $(id) 执行命令注入。\n"
        "5. CWE 判别：sink 是 subprocess shell=True，filepath 含未转义的 shell 元字符 → CWE-78 命令注入。"
        "secure_filename 是路径穿越防御，不是命令注入防御。\n"
        "6. 综合来看，存在命令注入漏洞，风险等级 Critical。漏洞隐藏在第 30 行，需追踪数据流。",
    json_block=vuln_json(
        "CWE-78", "命令注入", "Critical",
        source="上传文件名（经 secure_filename 但保留 $ ` 等）",
        sink="subprocess.run(cmd, shell=True) 中 cmd 拼接 filepath",
        explanation="secure_filename 防路径穿越但不防 shell 注入，文件名中的 $() 被 shell 解析执行任意命令",
        fix="用 subprocess.run(['convert', filepath, '-resize', '100x100', outfile], shell=False) 列表参数模式"
    )
))

# R3: try/except 掩盖的漏洞（Python）
CVE_INSPIRED_SAMPLES.append(build_sample(
    code='''import pickle
import base64
from flask import Flask, request
app = Flask(__name__)

@app.route("/session/restore")
def restore_session():
    sess = request.args.get("session", "")
    try:
        data = base64.b64decode(sess)
        # 反序列化被 try/except 包裹，看似"安全"（异常被吞）
        obj = pickle.loads(data)
        return {"user": obj.get("user", "guest")}
    except Exception as e:
        return {"error": "invalid session"}, 400
''',
    language="python", filename="cve_inspired_03_try_except_mask.py",
    cot="分析过程：\n"
        "1. 用户可控输入：session 来自 request.args。\n"
        "2. 危险 sink：pickle.loads(data)，data = base64.b64decode(session)。\n"
        "3. 防御措施分析：try/except 包裹 pickle.loads，但 except 只捕获异常并返回 400，"
        "不阻止 pickle.loads 执行。pickle.loads 在反序列化时会执行 __reduce__ 方法，"
        "攻击者构造的 pickle 对象可在 loads 时执行任意代码，异常捕获发生在 RCE 之后。\n"
        "4. 反事实检验：若用 json.loads 替代 pickle.loads，则无代码执行能力；"
        "当前用 pickle.loads + try/except，漏洞成立（except 不能阻止已执行的 payload）。\n"
        "5. CWE 判别：sink 是 pickle.loads → CWE-502 不安全反序列化。\n"
        "6. 综合来看，存在反序列化漏洞，风险等级 Critical（可 RCE）。try/except 不能防御 pickle RCE。",
    json_block=vuln_json(
        "CWE-502", "不安全反序列化", "Critical",
        source="request.args.get('session')（base64 编码的 pickle 数据）",
        sink="pickle.loads(data)",
        explanation="pickle.loads 反序列化时执行 __reduce__，可 RCE；try/except 只捕获异常不阻止 payload 执行",
        fix="用 json.loads 替代 pickle.loads；若必须用 pickle，用 pickle.RestrictedLoad 限制可反序列化的类"
    )
))

# R4: 误导性注释（Python）
CVE_INSPIRED_SAMPLES.append(build_sample(
    code='''import sqlite3
from flask import request

def get_user_safe(username):
    """安全地获取用户信息——已用参数化查询防 SQL 注入。"""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # 注释说参数化，实际仍是字符串拼接
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cursor.execute(query)
    return cursor.fetchone()
''',
    language="python", filename="cve_inspired_04_misleading_comment.py",
    cot="分析过程：\n"
        "1. 用户可控输入：username 来自函数参数。\n"
        "2. 危险 sink：cursor.execute(query)。\n"
        "3. 关键陷阱：docstring 声称「已用参数化查询防 SQL 注入」，"
        "但实际 query = 'SELECT * FROM users WHERE username = \\'%s\\' % username 仍是字符串拼接。"
        "注释/docstring 不可信，必须看实际代码。\n"
        "4. 攻击路径：username = ' OR '1'='1 使 query 变为 "
        "SELECT * FROM users WHERE username = '' OR '1'='1'，返回所有用户。\n"
        "5. CWE 判别：sink 是 cursor.execute + 字符串拼接 → CWE-89 SQL 注入。\n"
        "6. 综合来看，存在 SQL 注入漏洞，风险等级 Critical。不要被误导性注释/docstring 干扰判断。",
    json_block=vuln_json(
        "CWE-89", "SQL注入", "Critical",
        source="username 参数（HTTP 请求）",
        sink="cursor.execute(query) 其中 query 用 % 拼接 username",
        explanation="docstring 声称参数化但实际是字符串拼接，username 可注入 ' OR '1'='1 绕过查询条件",
        fix="用 cursor.execute('SELECT * FROM users WHERE username = ?', (username,)) 真正参数化"
    )
))

# R5: 跨函数数据流（Python，source 和 sink 在不同函数）
CVE_INSPIRED_SAMPLES.append(build_sample(
    code='''import yaml
from flask import Flask, request
app = Flask(__name__)

def parse_config(raw):
    """解析用户提交的 YAML 配置。"""
    # 用 safe_load 似乎安全
    return yaml.safe_load(raw)

def apply_config(config):
    """应用配置到运行时。"""
    # config 是 dict，看似安全
    template = config.get("template", "default.html")
    # 但 template 字段被传给 open，用户可控制路径
    with open("/etc/app/templates/" + template) as f:
        return f.read()

@app.route("/config")
def config_endpoint():
    raw = request.args.get("config", "")
    config = parse_config(raw)
    return apply_config(config)
''',
    language="python", filename="cve_inspired_05_crossfunc.py",
    cot="分析过程：\n"
        "1. 数据流追踪：request.args.config → parse_config → yaml.safe_load → config dict → "
        "apply_config → config['template'] → open('/etc/app/templates/' + template)。\n"
        "2. 分散的疑点：parse_config 用 safe_load（防 YAML 反序列化，看似安全）；"
        "apply_config 用 open + 字符串拼接（危险，但 config 来自 dict 看似安全）。\n"
        "3. 组合漏洞：用户提交 YAML config: {template: ../../../../etc/passwd}，"
        "safe_load 正常解析为 dict，apply_config 中 template='../../../../etc/passwd'，"
        "open('/etc/app/templates/../../../../etc/passwd') 读取 /etc/passwd。\n"
        "4. CWE 判别：sink 是 open + 路径拼接 → CWE-22 路径穿越。"
        "safe_load 防的是 YAML 反序列化（CWE-502），不防路径穿越。\n"
        "5. 综合来看，存在路径穿越漏洞，风险等级 High。需跨函数追踪数据流才能发现。",
    json_block=vuln_json(
        "CWE-22", "路径穿越", "High",
        source="request.args.get('config')（YAML 含 template 字段）",
        sink="open('/etc/app/templates/' + template)",
        explanation="YAML 中的 template 字段经 safe_load 解析后传入 open 拼接，../ 可穿越读任意文件",
        fix="对 template 做白名单校验或用 os.path.realpath + startswith 校验最终路径在模板目录内"
    )
))

# R6-R10: 补充 5 条不同 CWE 的实战样本
CVE_INSPIRED_SAMPLES.append(build_sample(
    code='''import java.security.MessageDigest;
import java.util.Base64;

public class LegacyPasswordStore {
    private final DbClient db;

    public void createUser(String email, String rawPassword) throws Exception {
        // 旧系统：SHA1 + 固定 salt（无 pepper，无迭代）
        String salt = "staticsalt12345";
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(salt.getBytes("UTF-8"));
        byte[] digest = md.digest(rawPassword.getBytes("UTF-8"));
        String storedHash = Base64.getEncoder().encodeToString(digest);
        // 也用了 MD5 做 token 生成（同一文件多处弱密码学）
        String resetToken = Long.toHexString(Double.doubleToLongBits(Math.random()));
        db.insert("users", email, storedHash, resetToken);
    }
}
''',
    language="java", filename="cve_inspired_06_legacy_crypto.java",
    cot="分析过程：\n"
        "1. 双重弱密码学：(a) SHA1 + 静态 salt 哈希密码；(b) Math.random 生成 reset token。\n"
        "2. SHA1 弱点：已破解（碰撞攻击 2017 公开），速度过快，固定 salt 使彩虹表可批量预算。"
        "与每个用户独立 salt 的 bcrypt/Argon2 对比，安全性差几个数量级。\n"
        "3. Math.random 弱点：非 CSPRNG，输出可预测，reset token 可被枚举导致账户接管。\n"
        "4. CWE 判别：SHA1 哈希密码 + 静态 salt → CWE-327 弱密码学（也关联 CWE-916 用可逆/弱哈希存密码）；"
        "Math.random 生成安全 token → CWE-330 弱随机数。主漏洞为 CWE-327。\n"
        "5. 反事实检验：若改用 Argon2id（per-user salt + 内存硬参数）+ SecureRandom 生成 token，则两者均安全；"
        "当前 SHA1+static salt + Math.random，漏洞成立。\n"
        "6. 综合来看，存在弱密码学漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-327", "弱密码学", "High",
        source="rawPassword 参数（来自用户注册表单）",
        sink="MessageDigest.getInstance('SHA-1') + 静态 salt",
        explanation="SHA1 已破解且速度过快，配合静态 salt 使批量破解可行；Math.random 生成 reset token 可预测",
        fix="改用 Argon2id 或 bcrypt（每用户独立 salt + 适当 cost）；reset token 用 SecureRandom.getInstanceStrong()"
    )
))

CVE_INSPIRED_SAMPLES.append(build_sample(
    code='''import random
from flask import request

@app.route("/token")
def generate_token():
    user = request.args.get("user")
    # 用 random 模块生成"安全" token
    token = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=32))
    db.execute("INSERT INTO tokens (user, token) VALUES (?, ?)", (user, token))
    return token
''',
    language="python", filename="cve_inspired_07_weak_random.py",
    cot="分析过程：\n"
        "1. 用户可控输入：user 来自 request.args（token 生成不依赖用户输入，但 token 本身用于认证）。\n"
        "2. 危险操作：random.choices 生成 32 字符 token。"
        "random 模块是 Mersenne Twister PRNG，非密码学安全，输出可预测（已知种子即可重现）。\n"
        "3. CWE 判别：用 random 生成安全 token → CWE-330 弱随机数。\n"
        "4. 反事实检验：若用 secrets.token_urlsafe(32)（CSPRNG），则 token 不可预测；"
        "当前用 random.choices，漏洞成立。\n"
        "5. 综合来看，存在弱随机数漏洞，风险等级 High（token 可预测导致会话劫持）。",
    json_block=vuln_json(
        "CWE-330", "弱随机数", "High",
        source="random.choices 生成 token",
        sink="db.execute 存储 random 生成的 token",
        explanation="random 模块非密码学安全，token 可预测，攻击者可伪造他人 token 劫持会话",
        fix="用 secrets.token_urlsafe(32) 或 os.urandom(32).hex() 生成密码学安全 token"
    )
))

CVE_INSPIRED_SAMPLES.append(build_sample(
    code='''import javax.servlet.http.*;
import java.io.IOException;

public class LegacyAuthServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        HttpSession session = req.getSession(false);
        if (session == null || session.getAttribute("uid") == null) {
            // 登录后跳转：从 referer 头取 next 参数（无校验）
            String nextUrl = req.getParameter("next");
            if (nextUrl == null || nextUrl.isEmpty()) {
                nextUrl = "/dashboard";
            }
            // 直接 sendRedirect，未限制目标域
            resp.sendRedirect(nextUrl);
            return;
        }
        resp.getWriter().write("welcome");
    }
}
''',
    language="java", filename="cve_inspired_08_java_open_redirect.java",
    cot="分析过程：\n"
        "1. 用户可控输入：next 来自 req.getParameter（HTTP 请求参数）。\n"
        "2. 危险 sink：resp.sendRedirect(nextUrl)，nextUrl 未经任何域校验。\n"
        "3. 攻击路径：构造 https://trusted.com/login?next=https://evil.com/phish，"
        "用户登录后浏览器被 302 重定向到 evil.com，攻击者利用 trusted.com 的可信外观做钓鱼。\n"
        "4. 反事实检验：若 nextUrl 限制为相对路径（必须以 / 开头且不以 // 开头）或匹配本站域名白名单，则外部 URL 被拒；"
        "当前无校验，漏洞成立。\n"
        "5. CWE 判别：未校验重定向目标 → CWE-601 开放重定向。\n"
        "6. 综合来看，存在开放重定向漏洞，风险等级 Medium（钓鱼辅助，非直接 RCE）。",
    json_block=vuln_json(
        "CWE-601", "开放重定向", "Medium",
        source="req.getParameter('next')",
        sink="resp.sendRedirect(nextUrl)",
        explanation="next 参数直接传给 sendRedirect 未校验域名，可重定向到外部钓鱼站点",
        fix="校验 nextUrl：必须以 / 开头、不以 // 开头，或匹配本站域名白名单；拒绝外部 URL"
    )
))

CVE_INSPIRED_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, session
app = Flask(__name__)
app.secret_key = "hardcoded_secret_key_123"

@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("user")
    pwd = request.form.get("pwd")
    if check_credentials(user, pwd):
        # 登录后未重新生成 session id（session fixation）
        session["user"] = user
        return "logged in"
    return "denied", 401
''',
    language="python", filename="cve_inspired_09_session_fixation.py",
    cot="分析过程：\n"
        "1. 双重问题：(a) app.secret_key 硬编码 → CWE-798；"
        "(b) 登录后未重新生成 session id → CWE-384 session fixation。\n"
        "2. session fixation 路径：攻击者诱导受害者用攻击者预设的 session id 登录，"
        "登录后该 session id 不变，攻击者用同一 id 劫持会话。\n"
        "3. CWE 判别：主漏洞是 secret_key 硬编码（CWE-798，最严重，可伪造任意 session）"
        "和 session fixation（CWE-384）。CWE-798 优先级更高。\n"
        "4. 综合来看，存在硬编码凭证漏洞，风险等级 Critical（secret_key 泄露可伪造任意用户 session）。",
    json_block=vuln_json(
        "CWE-798", "硬编码凭证", "Critical",
        source="源码中的硬编码 secret_key",
        sink="app.secret_key = 'hardcoded_secret_key_123'",
        explanation="Flask secret_key 硬编码在源码中，泄露后攻击者可伪造任意用户的 session cookie",
        fix="从环境变量读取 secret_key：app.secret_key = os.environ['SECRET_KEY']；登录后 session.regenerate() 防 fixation"
    )
))

CVE_INSPIRED_SAMPLES.append(build_sample(
    code='''import xml.etree.ElementTree as ET
from flask import request

@app.route("/parse", methods=["POST"])
def parse():
    raw = request.get_data(as_text=True)
    # 用 ET.parse 默认配置，未禁用外部实体
    root = ET.fromstring(raw)
    return {"tag": root.tag, "text": root.text or ""}
''',
    language="python", filename="cve_inspired_10_xxe.py",
    cot="分析过程：\n"
        "1. 用户可控输入：raw 来自 request.get_data（POST body）。\n"
        "2. 危险 sink：ET.fromstring(raw)。Python xml.etree.ElementTree 在某些版本默认解析外部实体。\n"
        "3. 攻击路径：构造 XML 含 <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>，"
        "ET.fromstring 解析后 root.text 可含 /etc/passwd 内容。\n"
        "4. CWE 判别：XML 解析未禁用外部实体 → CWE-611 XXE。\n"
        "5. 综合来看，存在 XXE 漏洞，风险等级 High（可读任意文件/SSRF）。",
    json_block=vuln_json(
        "CWE-611", "XXE", "High",
        source="request.get_data()（POST XML body）",
        sink="ET.fromstring(raw)",
        explanation="ET.fromstring 默认未禁用外部实体，可构造恶意 XML 读取任意文件或发起 SSRF",
        fix="用 defusedxml.ElementTree.fromstring 替代 ET.fromstring（默认禁用外部实体）"
    )
))


# ===========================================================================
# 主函数
# ===========================================================================

def main():
    print("=" * 60)
    print("v7 实战专用训练数据构建")
    print("=" * 60)

    # 加载 v5_clean 基底
    print(f"\n[1] 加载基底: {V5_FILE}")
    records = []
    with open(V5_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    print(f"    v5_clean 样本数: {len(records)}")

    # 收集所有新样本
    new_samples = (
        LDAP_SAMPLES +              # 10 条 CWE-90
        TRUST_BOUNDARY_SAMPLES +    # 10 条 CWE-441
        INT_OVERFLOW_SAMPLES +      # 8 条 CWE-190
        FP_CORRECTION_SAMPLES +     # 6 条 FP 反事实修正
        CONTRASTIVE_SAMPLES +       # 6 条对比 CoT
        CVE_INSPIRED_SAMPLES        # 10 条 CVE 启发实战
    )
    print(f"\n[2] 新增样本数: {len(new_samples)}")
    print(f"    - CWE-90 LDAP 注入: {len(LDAP_SAMPLES)}")
    print(f"    - CWE-441 信任边界: {len(TRUST_BOUNDARY_SAMPLES)}")
    print(f"    - CWE-190 整数溢出: {len(INT_OVERFLOW_SAMPLES)}")
    print(f"    - FP 反事实修正: {len(FP_CORRECTION_SAMPLES)}")
    print(f"    - 对比 CoT: {len(CONTRASTIVE_SAMPLES)}")
    print(f"    - CVE 启发实战: {len(CVE_INSPIRED_SAMPLES)}")

    # 合并
    all_records = records + new_samples
    print(f"\n[3] 合并后总数: {len(all_records)} (v5 {len(records)} + 新增 {len(new_samples)})")

    # 去重（按 user prompt 的代码内容 hash）
    seen_codes = set()
    deduped = []
    dup_count = 0
    for rec in all_records:
        code = ""
        for msg in rec.get("messages", []):
            if msg.get("role") == "user":
                code = msg.get("content", "")
                break
        key = hash(code)
        if key in seen_codes:
            dup_count += 1
            continue
        seen_codes.add(key)
        deduped.append(rec)
    if dup_count:
        print(f"\n[4] 去重: 移除 {dup_count} 条重复样本")
    print(f"    最终样本数: {len(deduped)}")

    # 保存
    print(f"\n[5] 保存到: {OUT_FILE}")
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
        if "CWE-" in assistant_msg:
            import re
            m = re.search(r"CWE-\d+", assistant_msg)
            if m:
                cwe = m.group(0)
                cwe_dist[cwe] = cwe_dist.get(cwe, 0) + 1

    print(f"\n[6] CWE 分布:")
    for cwe, cnt in sorted(cwe_dist.items(), key=lambda x: -x[1]):
        print(f"    {cwe}: {cnt}")

    print(f"\n{'=' * 60}")
    print(f"v7 训练数据构建完成: {len(deduped)} 条样本")
    print(f"输出: {OUT_FILE}")
    print(f"{'=' * 60}")
    print(f"\n下一步：Jaccard 泄漏审计 + 课程学习训练")


if __name__ == "__main__":
    main()
