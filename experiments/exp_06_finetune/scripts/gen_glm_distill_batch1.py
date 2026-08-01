"""
按 docs/prompts/glm_prompt.md 模板分批生成 GLM 蒸馏数据。

第一批：CWE-89 SQL 注入
- distill_glm_cwe_cvss.jsonl: 12 条（3 漏洞 + 9 安全），1:3 配比
- distill_glm_web.jsonl:      12 条（3 漏洞 + 9 安全），1:3 配比

格式与现有 _archive_supplement/supplement_*.jsonl 一致（chatml messages 数组）。
assistant 内容为三段式：代码片段 / 分析过程（≤5步锚定行号）/ JSON 结论（含 cvss_vector, cvss_score）。
"""
import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[1] / "data"

# ---------- GLM 系统提示词（取自 glm_prompt.md） ----------
GLM_SYSTEM = """你是一名资深安全研究员，专精 CWE 标准化与 CVSS 评分。你正在为代码漏洞检测模型生成严格格式的训练样本。

【你的核心优势】
- 指令遵循稳定，JSON 合法性 100%
- 结构化输出强，适合标准化流水线
- SWE-bench Pro 62.1

【你的任务】
1. 生成 CWE+CVSS 严格格式样本（1500 条，漏洞 375 + 安全 1125，1:3 配比）：补 8B 模型的格式短板
2. 生成 Java/Python Web 标准样本（300 条，漏洞 75 + 安全 225，1:3 配比）：为 DeepSeek 主力的 Web 类提供格式标准锚
3. 作为格式锚：DeepSeek/K3 的输出最终改写填充为 GLM schema

【严格格式要求】
1. 每条样本的 JSON 必须包含完整字段，缺一不可
2. CVSS 3.1 向量必须符合 FIRST.org 标准
3. CWE 编号必须在 MITRE 官方列表内
4. vulnerability_type 必须以 CWE-XXX 开头
5. CoT ≤5 步，每步锚定行号

【CVSS 3.1 向量格式】
格式：CVSS:3.1/AV:{N|A|L|P}/AC:{L|H}/PR:{N|L|H}/UI:{N|R}/S:{U|C}/C:{H|L|N}/I:{H|L|N}/A:{H|L|N}

字段含义：
- AV 攻击向量：N 网络 / A 邻近 / L 本地 / P 物理
- AC 攻击复杂度：L 低 / H 高
- PR 权限要求：N 无 / L 低 / H 高
- UI 用户交互：N 无需 / R 需要
- S 影响范围：U 不变 / C 改变
- C 机密性影响：H 高 / L 低 / N 无
- I 完整性影响：H 高 / L 低 / N 无
- A 可用性影响：H 高 / L 低 / N 无

分数对照：
- 9.0-10.0 Critical
- 7.0-8.9 High
- 4.0-6.9 Medium
- 0.1-3.9 Low
- 0.0 None

示例：CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N（SQL 注入，9.1 Critical）
示例：CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N（反射型 XSS，5.4 Medium）
示例：CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H（RCE，9.8 Critical）

【CWE 归因规则】
- 注入类按 sink 区分：SQL execute → CWE-89；shell/os.system → CWE-78；eval/exec → CWE-95/94；LDAP search → CWE-90；template render → CWE-1336/CWE-94；HTTP header → CWE-113
- 访问控制类按缺陷本质区分：IDOR → CWE-639；缺失授权 → CWE-862；缺失认证 → CWE-306；信任源误判 → CWE-441
- 密码学类：硬编码 IV → CWE-329；JWT 签名不严 → CWE-347；弱算法 → CWE-327；硬编码凭证 → CWE-798；弱随机数 → CWE-330
- 并发与逻辑类：Race Condition → CWE-362；Mass Assignment → CWE-915；原型链污染 → CWE-1321
- 其他：反序列化 → CWE-502；XXE → CWE-611；SSRF → CWE-918；信息泄露 → CWE-200；开放重定向 → CWE-601；路径穿越 → CWE-22；XSS → CWE-79；CSRF → CWE-352；日志注入 → CWE-117

【输出格式】
严格三段式：
第一段：代码片段（```语言 ... ```）
第二段：分析过程（≤5 步，每步锚定行号）
第三段：结构化结论（```json ... ```）

JSON 字段（比其他模型多 cvss_vector 和 cvss_score）：
has_vulnerability / vulnerability_type / risk_level / cvss_vector / cvss_score / source / sink / explanation / fix_suggestion
负样本 has_vulnerability=false，vulnerability_type="none"，cvss_vector="N/A"，cvss_score=0.0，其余字段为 "N/A" 或 "no fix needed"。"""


def build_user_cwe_cvss(cwe, language, has_vuln, difficulty):
    flag = "是" if has_vuln else "否"
    return (
        "请生成 1 条 CWE+CVSS 严格格式样本：\n"
        f"- CWE：{cwe}\n"
        f"- 语言：{language}\n"
        f"- 是否有漏洞：{flag}\n"
        f"- 难度：{difficulty}\n\n"
        "覆盖 6 类漏洞（每类约 62 条漏洞 + 188 条安全）：\n"
        "1. 注入类：CWE-89/78/95/90/643/943/917\n"
        "2. 访问控制类：CWE-639/862/306/441/384\n"
        "3. 密码学类：CWE-327/329/347/330/798\n"
        "4. 并发与逻辑类：CWE-362/915/1321/843/208\n"
        "5. 资源管理与内存类：CWE-416/415/502/611/190\n"
        "6. 信息泄露与配置类：CWE-200/601/117/22/79/352\n\n"
        "要求：\n"
        "1. 每条漏洞样本必须含 CVSS 3.1 向量 + 分数 + 严重等级\n"
        "2. 安全样本必须包含真实有效的防御措施，CoT 显式列出已检查点\n"
        "3. 格式严格到字符级：字段顺序固定、无多余空格、无注释\n\n"
        "输出必须含 cvss_vector 和 cvss_score 字段。"
    )


def build_user_web(language, framework, scene, has_vuln, difficulty):
    flag = "是" if has_vuln else "否"
    return (
        "请生成 1 条 Web 漏洞标准格式样本：\n"
        f"- 语言：{language}\n"
        f"- 框架：{framework}\n"
        f"- 场景：{scene}\n"
        f"- 是否有漏洞：{flag}\n"
        f"- 难度：{difficulty}\n\n"
        "CWE 覆盖：CWE-89 SQLi / CWE-79 XSS / CWE-22 Path Traversal / CWE-502 反序列化 / "
        "CWE-611 XXE / CWE-352 CSRF / CWE-1336 SSTI / CWE-639 IDOR / CWE-862 缺失授权 / CWE-601 开放重定向\n\n"
        "要求：\n"
        "1. 模拟真实 Web 框架代码：Spring/Django/Flask/Express/FastAPI\n"
        "2. 漏洞样本含真实业务逻辑，不要教科书式 demo\n"
        "3. 安全样本含有效防御：参数化查询、PreparedStatement、CSRF token、bcrypt、defusedxml\n"
        "4. 作为 DeepSeek Web 类的格式标准锚，JSON 格式必须严格规范\n\n"
        "输出严格三段式格式，含 cvss_vector 和 cvss_score 字段。"
    )


def assistant_response(code_block, analysis_steps, json_obj):
    """组装三段式 assistant 回复。"""
    parts = []
    parts.append(code_block)
    parts.append("分析过程：")
    for i, step in enumerate(analysis_steps, 1):
        parts.append(f"{i}. {step}")
    parts.append("")
    parts.append("```json")
    parts.append(json.dumps(json_obj, ensure_ascii=False, indent=2))
    parts.append("```")
    return "\n".join(parts)


def write_sample(fp, system, user, assistant):
    fp.write(json.dumps({
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ]
    }, ensure_ascii=False))
    fp.write("\n")


# =====================================================================
# Batch 1: distill_glm_cwe_cvss.jsonl  ——  CWE-89 SQL 注入
# 12 条：3 漏洞 + 9 安全，覆盖 Python/Java/PHP
# =====================================================================

CWE_CVSS_BATCH1 = [
    # ----- 漏洞样本 3 条 -----
    {
        "lang": "Python", "has_vuln": True, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_001.py
from django.db import connection
from django.http import JsonResponse


def search_user(request):
    uid = request.GET.get('uid', '')
    with connection.cursor() as cur:
        cur.execute("SELECT * FROM users WHERE id = '%s'" % uid)
        row = cur.fetchone()
    return JsonResponse({'user': row})
```""",
        "steps": [
            "第 7 行 request.GET.get('uid') 获取用户输入，未做类型或白名单校验",
            "第 9 行用 Python % 格式化把 uid 拼入 SQL 文本，非参数化绑定",
            "第 9 行 cur.execute 直接执行拼接后的字符串，DB-API 不会二次转义",
            "source→sink 间无任何有效防御，攻击者传 uid=' OR 1=1 -- 可越权读取全表",
            "CWE-89 SQL 注入，Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-89 SQL注入",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cvss_score": 9.1,
            "source": "request.GET.get('uid')",
            "sink": "cur.execute(\"SELECT * FROM users WHERE id = '%s'\" % uid)",
            "explanation": "request.GET.get('uid') → uid → % 格式化拼入 SQL 文本 → cur.execute 执行拼接字符串",
            "fix_suggestion": "使用参数化查询：cur.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))",
        },
    },
    {
        "lang": "Java", "has_vuln": True, "difficulty": "中等",
        "code": """```java
// distill_glm_cwe_cvss_002.java
@RestController
public class UserController {
    @Autowired
    private JdbcTemplate jdbc;

    @GetMapping("/user")
    public Map<String, Object> findUser(@RequestParam String name) {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        return jdbc.queryForMap(sql);
    }
}
```""",
        "steps": [
            "第 8 行 @RequestParam String name 获取用户输入，未做编码或白名单",
            "第 9 行用 Java + 把 name 拼入 SQL 字符串字面量",
            "第 10 行 jdbc.queryForMap(sql) 只接收一个 SQL 字符串参数，无绑定占位符",
            "JdbcTemplate 的单参重载不会自动参数化，source→sink 间无有效防御",
            "CWE-89 SQL 注入，High",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-89 SQL注入",
            "risk_level": "High",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score": 7.5,
            "source": "@RequestParam String name",
            "sink": "jdbc.queryForMap(\"SELECT * FROM users WHERE name = '\" + name + \"'\")",
            "explanation": "@RequestParam name → 字符串拼接进 sql → jdbc.queryForMap(sql) 单参重载无参数化",
            "fix_suggestion": "使用占位符 + 参数绑定：jdbc.queryForMap(\"SELECT * FROM users WHERE name = ?\", name)",
        },
    },
    {
        "lang": "PHP", "has_vuln": True, "difficulty": "典型",
        "code": """```php
// distill_glm_cwe_cvss_003.php
<?php
$pdo = new PDO('mysql:host=localhost;dbname=app', 'user', 'pass');
$email = $_GET['email'];
$sql = "SELECT * FROM subscribers WHERE email = '" . $email . "'";
$stmt = $pdo->query($sql);
return $stmt->fetchAll();
```""",
        "steps": [
            "第 4 行 $_GET['email'] 获取用户输入，无任何过滤",
            "第 5 行用 PHP . 拼接 $email 到 SQL 文本",
            "第 6 行 $pdo->query($sql) 直接执行拼接后的 SQL，未使用 prepare",
            "PDO::query 不会做参数绑定，source→sink 间无防御",
            "CWE-89 SQL 注入，Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-89 SQL注入",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cvss_score": 9.1,
            "source": "$_GET['email']",
            "sink": "$pdo->query(\"SELECT * FROM subscribers WHERE email = '\" . $email . \"'\")",
            "explanation": "$_GET['email'] → $email → . 拼接进 $sql → $pdo->query 执行拼接字符串",
            "fix_suggestion": "使用 PDO 预处理：$stmt = $pdo->prepare(\"SELECT * FROM subscribers WHERE email = ?\"); $stmt->execute([$email]);",
        },
    },
    # ----- 安全样本 9 条 -----
    {
        "lang": "Python", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_004.py
from django.http import JsonResponse
from myapp.models import User


def search_user(request):
    uid = request.GET.get('uid', '')
    user = User.objects.filter(id=uid).values('id', 'name', 'email').first()
    return JsonResponse({'user': user})
```""",
        "steps": [
            "第 7 行 request.GET.get('uid') 获取用户输入",
            "第 8 行数据进入 Django ORM 的 filter(id=uid) 接口",
            "Django ORM 在底层将 uid 作为参数化查询绑定值传给数据库驱动，不会拼入 SQL 文本",
            "已检查：未使用 raw/extra/字符串拼接，ORM 自动参数化，source→sink 无可利用路径",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.GET.get('uid')",
            "sink": "User.objects.filter(id=uid)",
            "explanation": "uid 经 Django ORM filter 传入，底层自动参数化，无 SQL 拼接",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_005.py
from sqlalchemy import create_engine, text
from flask import Flask, request

engine = create_engine('sqlite:///app.db')


@app.route('/user')
def find_user():
    uid = request.args.get('uid', '')
    stmt = text("SELECT id, name FROM users WHERE id = :uid")
    with engine.connect() as conn:
        row = conn.execute(stmt, {"uid": uid}).fetchone()
    return {"user": dict(row) if row else None}
```""",
        "steps": [
            "第 9 行 request.args.get('uid') 获取用户输入",
            "第 10 行 SQL 使用 :uid 命名占位符，未做字符串拼接",
            "第 12 行 conn.execute(stmt, {\"uid\": uid}) 第二参数为绑定值字典",
            "已检查：text() + 命名占位符 + 绑定参数三要素齐全，SQLAlchemy 自动转义",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('uid')",
            "sink": "conn.execute(stmt, {\"uid\": uid})",
            "explanation": "uid 通过 :uid 命名参数绑定，SQLAlchemy 自动转义，无 SQL 拼接",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "has_vuln": False, "difficulty": "典型",
        "code": """```java
// distill_glm_cwe_cvss_006.java
@RestController
public class UserController {
    @Autowired
    private JdbcTemplate jdbc;

    @GetMapping("/user")
    public Map<String, Object> findUser(@RequestParam String name) {
        String sql = "SELECT * FROM users WHERE name = ?";
        return jdbc.queryForMap(sql, name);
    }
}
```""",
        "steps": [
            "第 8 行 @RequestParam String name 获取用户输入",
            "第 9 行 SQL 使用 ? 占位符，未做字符串拼接",
            "第 10 行 jdbc.queryForMap(sql, name) 第二参数为绑定值",
            "已检查：JdbcTemplate 的占位符 + 绑定参数机制使用 PreparedStatement，自动转义",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@RequestParam String name",
            "sink": "jdbc.queryForMap(sql, name)",
            "explanation": "name 作为 ? 占位符的绑定值传入，JdbcTemplate 内部使用 PreparedStatement",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_cwe_cvss_007.java
@RestController
public class OrderController {
    @PersistenceContext
    private EntityManager em;

    @GetMapping("/order")
    public Order findOrder(@RequestParam Long orderId) {
        TypedQuery<Order> q = em.createQuery(
            "SELECT o FROM Order o WHERE o.id = :oid", Order.class);
        q.setParameter("oid", orderId);
        return q.getSingleResult();
    }
}
```""",
        "steps": [
            "第 9 行 @RequestParam Long orderId 由 Spring 强制类型转换为 Long，非数字输入会被拒绝",
            "第 10-11 行 JPQL 使用 :oid 命名占位符，未做字符串拼接",
            "第 12 行 q.setParameter(\"oid\", orderId) 通过 JPA 绑定参数",
            "已检查：类型转换 + JPQL 占位符 + setParameter 三层防御，无 SQL 拼接",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@RequestParam Long orderId",
            "sink": "q.setParameter(\"oid\", orderId)",
            "explanation": "orderId 经 Spring 类型转换 + JPA 命名参数绑定，无 SQL 拼接",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "PHP", "has_vuln": False, "difficulty": "典型",
        "code": """```php
// distill_glm_cwe_cvss_008.php
<?php
$pdo = new PDO('mysql:host=localhost;dbname=app', 'user', 'pass');
$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
$email = $_GET['email'];
$stmt = $pdo->prepare("SELECT * FROM subscribers WHERE email = ?");
$stmt->execute([$email]);
return $stmt->fetchAll();
```""",
        "steps": [
            "第 5 行 $_GET['email'] 获取用户输入",
            "第 4 行 ATTR_EMULATE_PREPARES=false 强制使用真实预处理，禁用模拟模式",
            "第 6 行 $pdo->prepare 使用 ? 占位符，第 7 行 execute([$email]) 传入绑定值",
            "已检查：真实预处理 + 占位符 + 绑定参数，驱动层负责转义，无 SQL 拼接",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "$_GET['email']",
            "sink": "$stmt->execute([$email])",
            "explanation": "email 通过 PDO 真实预处理的 ? 占位符绑定，驱动层转义，无 SQL 拼接",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_009.py
import psycopg2
from flask import Flask, request

conn = psycopg2.connect("dbname=app user=api")


@app.route('/order')
def find_order():
    oid = request.args.get('oid', '')
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM orders WHERE id = %s", (oid,))
        row = cur.fetchone()
    return {"order": row}
```""",
        "steps": [
            "第 9 行 request.args.get('oid') 获取用户输入",
            "第 11 行 cur.execute 第一参数为含 %s 占位符的 SQL 模板，第二参数为元组 (oid,)",
            "psycopg2 的 %s 是参数占位符而非 Python 格式化，底层使用 PreparedStatement",
            "已检查：占位符 + 绑定元组，无字符串拼接，无 % 或 f-string 拼接",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('oid')",
            "sink": "cur.execute(\"SELECT * FROM orders WHERE id = %s\", (oid,))",
            "explanation": "oid 通过 psycopg2 的 %s 占位符绑定，底层 PreparedStatement，无 SQL 拼接",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_010.py
from django.http import JsonResponse
from myapp.models import User


def search_user(request):
    name = request.GET.get('name', '')
    users = list(User.objects
                 .extra(where=['name LIKE %s'], params=[f'%{name}%'])
                 .values('id', 'name'))
    return JsonResponse({'users': users})
```""",
        "steps": [
            "第 7 行 request.GET.get('name') 获取用户输入",
            "第 8-10 行 extra(where=[...], params=[...]) 的 where 是固定 SQL 片段含 %s 占位符",
            "params=[f'%{name}%'] 作为绑定值传入，Django 不会把 name 拼入 where 子句的 SQL 文本",
            "已检查：where 子句为固定字面量 + params 绑定，无字符串拼接进 SQL 文本",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.GET.get('name')",
            "sink": "User.objects.extra(where=['name LIKE %s'], params=[...])",
            "explanation": "name 通过 extra 的 params 列表绑定，where 为固定字面量，无 SQL 拼接",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_cwe_cvss_011.java
@Mapper
public interface UserMapper {
    @Select("SELECT * FROM users WHERE name = #{name}")
    User findByName(@Param("name") String name);
}

@RestController
public class UserController {
    @Autowired
    private UserMapper mapper;

    @GetMapping("/user")
    public User findUser(@RequestParam String name) {
        return mapper.findByName(name);
    }
}
```""",
        "steps": [
            "第 14 行 @RequestParam String name 获取用户输入",
            "第 4 行 @Select SQL 使用 #{name} 占位符（MyBatis 的 PreparedStatement 参数）",
            "MyBatis 会将 #{name} 编译为 JDBC 的 ? 占位符并调用 setParameter 绑定",
            "已检查：#{name} 是参数占位符（非 ${name} 字符串替换），底层 PreparedStatement",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@RequestParam String name",
            "sink": "mapper.findByName(name)",
            "explanation": "name 经 MyBatis #{name} 占位符绑定，编译为 JDBC ? 占位符，无 SQL 拼接",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_012.py
from sqlalchemy.orm import Session
from flask import Flask, request


@app.route('/user')
def find_user():
    name = request.args.get('name', '')
    with Session(engine) as session:
        user = session.query(User).filter_by(name=name).first()
    return {"user": user.to_dict() if user else None}
```""",
        "steps": [
            "第 6 行 request.args.get('name') 获取用户输入",
            "第 8 行 session.query(User).filter_by(name=name) 使用 SQLAlchemy ORM 查询接口",
            "filter_by 接收关键字参数，底层生成参数化 SQL，name 作为绑定值",
            "已检查：ORM 查询 + filter_by 关键字参数，无字符串拼接，无 raw SQL",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('name')",
            "sink": "session.query(User).filter_by(name=name)",
            "explanation": "name 经 SQLAlchemy ORM filter_by 关键字参数传入，底层参数化，无 SQL 拼接",
            "fix_suggestion": "no fix needed",
        },
    },
]


# =====================================================================
# Batch 1: distill_glm_web.jsonl  ——  CWE-89 SQL 注入（Web 标准样本）
# 12 条：3 漏洞 + 9 安全，覆盖 Spring/Django/Flask/Express/FastAPI
# =====================================================================

WEB_BATCH1 = [
    # ----- 漏洞样本 3 条 -----
    {
        "lang": "Python", "framework": "Flask", "scene": "订单查询", "has_vuln": True, "difficulty": "典型",
        "code": """```python
# distill_glm_web_001.py
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)


@app.route('/orders')
def list_orders():
    status = request.args.get('status', 'pending')
    conn = sqlite3.connect('app.db')
    cur = conn.execute(f"SELECT id, total FROM orders WHERE status = '{status}'")
    rows = cur.fetchall()
    return jsonify(rows)
```""",
        "steps": [
            "第 9 行 request.args.get('status') 获取用户输入，默认值仅用于空值兜底",
            "第 11 行 f-string 把 status 直接拼入 SQL 文本，非参数化绑定",
            "第 11 行 conn.execute 执行拼接后的字符串，sqlite3 不会二次转义",
            "source→sink 间无任何防御，攻击者传 status=' OR 1=1 -- 可越权读取全表订单",
            "CWE-89 SQL 注入，Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-89 SQL注入",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cvss_score": 9.1,
            "source": "request.args.get('status')",
            "sink": "conn.execute(f\"SELECT id, total FROM orders WHERE status = '{status}'\")",
            "explanation": "request.args.get('status') → status → f-string 拼接进 SQL → conn.execute",
            "fix_suggestion": "使用参数化查询：conn.execute(\"SELECT id, total FROM orders WHERE status = ?\", (status,))",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "用户认证", "has_vuln": True, "difficulty": "防御迷惑",
        "code": """```java
// distill_glm_web_002.java
@RestController
public class AuthController {
    @Autowired
    private JdbcTemplate jdbc;

    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody LoginDto dto) {
        // 防御：过滤掉单引号防止注入
        String safe = dto.getUsername().replace("'", "''");
        String sql = "SELECT id FROM users WHERE username = '" + safe + "'";
        Map<String, Object> user = jdbc.queryForMap(sql);
        if (BCrypt.checkpw(dto.getPassword(), (String) user.get("password"))) {
            return Map.of("token", issueToken(user.get("id")));
        }
        throw new UnauthorizedException();
    }
}
```""",
        "steps": [
            "第 8 行 dto.getUsername() 获取用户输入，replace(\"'\", \"''\") 看似转义但只覆盖单引号",
            "第 9 行仍用 Java + 把 safe 拼入 SQL 字面量，未使用占位符",
            "第 10 行 jdbc.queryForMap(sql) 单参重载无参数化",
            "replace 转义是脆弱防御：未覆盖反斜杠、注释符 --、UNION 等绕过手段，且依赖数据库引号语义",
            "CWE-89 SQL 注入，High",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-89 SQL注入",
            "risk_level": "High",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cvss_score": 9.1,
            "source": "dto.getUsername()",
            "sink": "jdbc.queryForMap(\"SELECT id FROM users WHERE username = '\" + safe + \"'\")",
            "explanation": "replace 转义只覆盖单引号，仍用 + 拼接 SQL 文本，JdbcTemplate 单参重载无参数化",
            "fix_suggestion": "使用占位符 + 参数绑定：jdbc.queryForMap(\"SELECT id FROM users WHERE username = ?\", dto.getUsername())",
        },
    },
    {
        "lang": "JavaScript", "framework": "Express", "scene": "订单查询", "has_vuln": True, "difficulty": "典型",
        "code": """```javascript
// distill_glm_web_003.js
const express = require('express');
const mysql = require('mysql2/promise');
const app = express();

app.get('/orders', async (req, res) => {
    const status = req.query.status || 'pending';
    const conn = await mysql.createConnection({ host: 'db', user: 'app', database: 'app' });
    const [rows] = await conn.execute(
        `SELECT id, total FROM orders WHERE status = '${status}'`
    );
    res.json(rows);
});
```""",
        "steps": [
            "第 8 行 req.query.status 获取用户输入，默认值仅空值兜底",
            "第 11 行模板字符串把 status 直接拼入 SQL 文本",
            "第 11 行 conn.execute 执行拼接后的字符串，未使用 ? 占位符",
            "source→sink 间无任何防御，攻击者传 status=' OR 1=1 -- 可越权读取全表",
            "CWE-89 SQL 注入，Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-89 SQL注入",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cvss_score": 9.1,
            "source": "req.query.status",
            "sink": "conn.execute(`SELECT id, total FROM orders WHERE status = '${status}'`)",
            "explanation": "req.query.status → status → 模板字符串拼接进 SQL → conn.execute 执行拼接字符串",
            "fix_suggestion": "使用占位符 + 参数数组：conn.execute(\"SELECT id, total FROM orders WHERE status = ?\", [status])",
        },
    },
    # ----- 安全样本 9 条 -----
    {
        "lang": "Python", "framework": "Flask", "scene": "订单查询", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_004.py
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)


@app.route('/orders')
def list_orders():
    status = request.args.get('status', 'pending')
    conn = sqlite3.connect('app.db')
    cur = conn.execute(
        "SELECT id, total FROM orders WHERE status = ?", (status,))
    rows = cur.fetchall()
    return jsonify(rows)
```""",
        "steps": [
            "第 9 行 request.args.get('status') 获取用户输入",
            "第 11-12 行 conn.execute 第一参数为含 ? 占位符的 SQL，第二参数为元组 (status,)",
            "sqlite3 的 ? 是 PreparedStatement 占位符，底层自动转义",
            "已检查：占位符 + 绑定元组，无字符串拼接，无 f-string 拼接",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('status')",
            "sink": "conn.execute(\"SELECT id, total FROM orders WHERE status = ?\", (status,))",
            "explanation": "status 通过 sqlite3 ? 占位符绑定，底层 PreparedStatement，无 SQL 拼接",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "用户认证", "has_vuln": False, "difficulty": "典型",
        "code": """```java
// distill_glm_web_005.java
@RestController
public class AuthController {
    @Autowired
    private JdbcTemplate jdbc;

    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody LoginDto dto) {
        String sql = "SELECT id, password FROM users WHERE username = ?";
        Map<String, Object> user = jdbc.queryForMap(sql, dto.getUsername());
        if (BCrypt.checkpw(dto.getPassword(), (String) user.get("password"))) {
            return Map.of("token", issueToken(user.get("id")));
        }
        throw new UnauthorizedException();
    }
}
```""",
        "steps": [
            "第 8 行 dto.getUsername() 获取用户输入",
            "第 9 行 SQL 使用 ? 占位符，无字符串拼接",
            "第 10 行 jdbc.queryForMap(sql, dto.getUsername()) 通过 PreparedStatement 绑定参数",
            "已检查：占位符 + 绑定参数 + bcrypt 密码校验，认证流程完整，无 SQL 拼接",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "dto.getUsername()",
            "sink": "jdbc.queryForMap(sql, dto.getUsername())",
            "explanation": "username 通过 ? 占位符绑定 PreparedStatement，无 SQL 拼接，密码用 bcrypt 校验",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "JavaScript", "framework": "Express", "scene": "订单查询", "has_vuln": False, "difficulty": "典型",
        "code": """```javascript
// distill_glm_web_006.js
const express = require('express');
const mysql = require('mysql2/promise');
const app = express();

app.get('/orders', async (req, res) => {
    const status = req.query.status || 'pending';
    const conn = await mysql.createConnection({ host: 'db', user: 'app', database: 'app' });
    const [rows] = await conn.execute(
        'SELECT id, total FROM orders WHERE status = ?',
        [status]
    );
    res.json(rows);
});
```""",
        "steps": [
            "第 8 行 req.query.status 获取用户输入",
            "第 11-12 行 conn.execute 第一参数为含 ? 占位符的 SQL，第二参数为 [status] 绑定数组",
            "mysql2 的 execute 内部使用 PreparedStatement，自动转义",
            "已检查：占位符 + 绑定数组，无模板字符串拼接，无字符串 + 拼接",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "req.query.status",
            "sink": "conn.execute('SELECT id, total FROM orders WHERE status = ?', [status])",
            "explanation": "status 通过 mysql2 ? 占位符绑定数组传入，底层 PreparedStatement，无 SQL 拼接",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Django", "scene": "用户认证", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_007.py
from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect


@csrf_protect
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            return JsonResponse({'token': issue_token(user.id)})
        return JsonResponse({'error': 'invalid credentials'}, status=401)
    return JsonResponse({'error': 'method not allowed'}, status=405)
```""",
        "steps": [
            "第 9-10 行 request.POST.get 获取用户输入",
            "第 11 行 authenticate(username=username, password=password) 使用 Django 内置认证后端",
            "Django auth 后端内部用 ORM 查询 + bcrypt/PBKDF2 校验，不暴露 SQL 层",
            "已检查：@csrf_protect 防 CSRF + Django auth 内置安全校验，无 SQL 拼接，无明文密码存储",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.POST.get('username')",
            "sink": "authenticate(request, username=username, password=password)",
            "explanation": "username/password 经 Django auth 后端处理，ORM 参数化 + bcrypt 校验，无 SQL 拼接",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "FastAPI", "scene": "订单查询", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_008.py
from fastapi import FastAPI, Query
from sqlalchemy import create_engine, text

engine = create_engine('sqlite:///app.db')
app = FastAPI()


@app.get('/orders')
def list_orders(status: str = Query('pending', max_length=32)):
    stmt = text("SELECT id, total FROM orders WHERE status = :status")
    with engine.connect() as conn:
        rows = conn.execute(stmt, {"status": status}).fetchall()
    return [dict(r) for r in rows]
```""",
        "steps": [
            "第 8 行 Query('pending', max_length=32) 对 status 做长度限制，超长输入被 422 拒绝",
            "第 9 行 SQL 使用 :status 命名占位符，无字符串拼接",
            "第 11 行 conn.execute(stmt, {\"status\": status}) 通过绑定值字典传入",
            "已检查：Pydantic 长度校验 + 命名占位符 + 绑定参数，无 SQL 拼接",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "status: str = Query('pending', max_length=32)",
            "sink": "conn.execute(stmt, {\"status\": status})",
            "explanation": "status 经 Pydantic 长度校验 + SQLAlchemy 命名参数绑定，无 SQL 拼接",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "订单查询", "has_vuln": False, "difficulty": "防御迷惑",
        "code": """```java
// distill_glm_web_009.java
@RestController
@RequestMapping("/orders")
public class OrderController {
    @Autowired
    private OrderRepository repo;

    @GetMapping
    public List<Order> list(@RequestParam(required = false) String status) {
        if (status == null || status.isBlank()) {
            return repo.findAll();
        }
        // 仅允许枚举值，拒绝任意字符串
        if (!Set.of("pending", "paid", "shipped", "closed").contains(status)) {
            throw new IllegalArgumentException("invalid status");
        }
        return repo.findByStatus(status);
    }
}
```""",
        "steps": [
            "第 8 行 @RequestParam String status 获取用户输入",
            "第 10-12 行白名单 Set.of(...).contains(status) 严格限制为 4 个枚举值，非法值抛异常",
            "第 14 行 repo.findByStatus(status) 使用 Spring Data JPA 派生查询，底层 PreparedStatement",
            "已检查：白名单枚举校验 + JPA 派生查询参数化，无 SQL 拼接",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@RequestParam String status",
            "sink": "repo.findByStatus(status)",
            "explanation": "status 经白名单枚举校验 + Spring Data JPA 派生查询参数化，无 SQL 拼接",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Django", "scene": "订单查询", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_010.py
from django.http import JsonResponse
from myapp.models import Order


def list_orders(request):
    status = request.GET.get('status', 'pending')
    qs = Order.objects.filter(status=status).values('id', 'total')
    return JsonResponse({'orders': list(qs)})
```""",
        "steps": [
            "第 6 行 request.GET.get('status') 获取用户输入",
            "第 7 行 Order.objects.filter(status=status) 使用 Django ORM 查询接口",
            "Django ORM filter 将 status 作为参数化查询绑定值传给数据库驱动",
            "已检查：ORM filter + .values() 字段限定，无 raw/extra/字符串拼接",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.GET.get('status')",
            "sink": "Order.objects.filter(status=status)",
            "explanation": "status 经 Django ORM filter 传入，底层参数化，无 SQL 拼接",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Flask", "scene": "用户认证", "has_vuln": False, "difficulty": "防御迷惑",
        "code": """```python
# distill_glm_web_011.py
from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash
from sqlalchemy import create_engine, text

engine = create_engine('sqlite:///app.db')
app = Flask(__name__)


@app.post('/login')
def login():
    username = request.json.get('username', '')
    password = request.json.get('password', '')
    stmt = text("SELECT id, password_hash FROM users WHERE username = :u")
    with engine.connect() as conn:
        row = conn.execute(stmt, {"u": username}).fetchone()
    if row and check_password_hash(row.password_hash, password):
        return jsonify({'token': issue_token(row.id)})
    return jsonify({'error': 'invalid credentials'}), 401
```""",
        "steps": [
            "第 10-11 行 request.json.get 获取用户输入",
            "第 12 行 SQL 使用 :u 命名占位符，第 13 行 conn.execute(stmt, {\"u\": username}) 绑定参数",
            "第 14 行 check_password_hash 使用 werkzeug 的 PBKDF2/bcrypt 校验密码",
            "已检查：命名占位符 + 绑定参数 + werkzeug 密码哈希校验 + 统一错误返回，无 SQL 拼接",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.json.get('username')",
            "sink": "conn.execute(stmt, {\"u\": username})",
            "explanation": "username 经 SQLAlchemy 命名参数绑定，密码用 werkzeug check_password_hash 校验，无 SQL 拼接",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "订单查询", "has_vuln": False, "difficulty": "典型",
        "code": """```java
// distill_glm_web_012.java
@RestController
@RequestMapping("/orders")
public class OrderController {
    @Autowired
    private JdbcTemplate jdbc;

    @GetMapping
    public List<Map<String, Object>> list(@RequestParam(required = false, defaultValue = "pending") String status) {
        String sql = "SELECT id, total FROM orders WHERE status = ?";
        return jdbc.queryForList(sql, status);
    }
}
```""",
        "steps": [
            "第 8 行 @RequestParam String status 获取用户输入，默认值 pending 仅空值兜底",
            "第 9 行 SQL 使用 ? 占位符，无字符串拼接",
            "第 10 行 jdbc.queryForList(sql, status) 通过 PreparedStatement 绑定参数",
            "已检查：占位符 + 绑定参数，JdbcTemplate 内部 PreparedStatement 自动转义",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@RequestParam String status",
            "sink": "jdbc.queryForList(sql, status)",
            "explanation": "status 通过 ? 占位符绑定 PreparedStatement，JdbcTemplate 自动转义，无 SQL 拼接",
            "fix_suggestion": "no fix needed",
        },
    },
]


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # 写 cwe_cvss batch1
    cvss_path = DATA_DIR / "distill_glm_cwe_cvss.jsonl"
    with cvss_path.open("w", encoding="utf-8") as fp:
        for s in CWE_CVSS_BATCH1:
            user = build_user_cwe_cvss("CWE-89 SQL注入", s["lang"], s["has_vuln"], s["difficulty"])
            assistant = assistant_response(s["code"], s["steps"], s["json"])
            write_sample(fp, GLM_SYSTEM, user, assistant)
    print(f"[OK] {cvss_path}: {len(CWE_CVSS_BATCH1)} samples")

    # 写 web batch1
    web_path = DATA_DIR / "distill_glm_web.jsonl"
    with web_path.open("w", encoding="utf-8") as fp:
        for s in WEB_BATCH1:
            user = build_user_web(s["lang"], s["framework"], s["scene"], s["has_vuln"], s["difficulty"])
            assistant = assistant_response(s["code"], s["steps"], s["json"])
            write_sample(fp, GLM_SYSTEM, user, assistant)
    print(f"[OK] {web_path}: {len(WEB_BATCH1)} samples")


if __name__ == "__main__":
    main()
