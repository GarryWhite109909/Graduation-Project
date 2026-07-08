"""
GLM-5.2 蒸馏数据生成器 —— 生成 400+ 多样化代码安全样本 + CoT 标注。

输出：experiments/exp_06_finetune/data/distill_corpus_annotated.jsonl
每行 JSON 含：code, language, filename, cot_analysis, has_vulnerability,
              vuln_type, risk_level, source, sink, taint_path, fix_idea

后续：用 format_distilled.py 转为 ChatML 训练格式

设计原则：
1. 不与 build_dataset.py 的 222 条样本重复 —— 全新代码模式
2. 覆盖 25+ CWE，每类 7-40 条
3. 语言分布：Python 35% / Java 20% / JS 15% / PHP 15% / Go 8% / C 7%
4. 难度梯度：典型 40% / 绕过变体 30% / CVE风格 15% / 安全对照 15%
5. CoT 按漏洞类型分模板（source_sink / missing_control / hardcoded_secret /
   integer_overflow / crypto_weakness / info_disclosure / race_condition）
"""

import json
import os
from pathlib import Path

SAMPLES = []

# ---------------------------------------------------------------------------
# CoT 生成器
# ---------------------------------------------------------------------------

def build_cot(has_vuln, vuln_type, risk_level, source, sink, taint_path,
              fix_idea, cot_type="source_sink"):
    """根据样本字段 + cot_type 生成具体的 CoT 分析文本。

    每个 CoT 引用样本特有的 source/sink/taint_path，避免泛化模板填充。
    """
    if not has_vuln:
        # 安全样本：描述具体防御措施，不用统一模板
        return (
            "分析过程：\n"
            f"1. 输入检查：识别代码中的用户输入点与处理逻辑。\n"
            f"2. sink 评估：{sink}，需判断此处是否有有效防护。\n"
            f"3. 防御确认：{taint_path}。\n"
            f"4. 综合判定：该防护措施有效，不存在可利用的安全漏洞。\n"
            f"5. 结论：代码安全，未发现漏洞。"
        )

    if cot_type == "missing_control":
        return (
            "分析过程：\n"
            f"1. 控制点检查：识别该操作应具备的安全控制（{source}）。\n"
            f"2. 控制是否缺失：代码中{taint_path}，该操作在无防护下直接执行。\n"
            f"3. 攻击面：{sink}，攻击者可绕过该控制点直接触发敏感操作。\n"
            "4. 防御检查：未发现 token校验/装饰器/归属校验 等任一有效防护。\n"
            f"5. 结论：存在 {vuln_type}（缺失安全控制），风险等级 {risk_level}。"
        )

    if cot_type == "hardcoded_secret":
        return (
            "分析过程：\n"
            "1. 凭证位置：检查源码中是否出现凭证字面量。\n"
            f"2. 是否字面量：{source}，变量名含 key/secret/password/token 且赋值为字符串字面量。\n"
            "3. 是否从环境读取：代码未通过 os.environ/配置文件/KMS 读取。\n"
            f"4. 影响范围：{taint_path}。\n"
            f"5. 结论：存在 {vuln_type}，风险等级 {risk_level}。"
        )

    if cot_type == "integer_overflow":
        return (
            "分析过程：\n"
            f"1. 运算识别：{source} 参与{sink}。\n"
            "2. 范围检查：代码未对运算结果做溢出检查。\n"
            f"3. 溢出可能：{taint_path}，当输入超出预期范围时运算结果溢出。\n"
            "4. 后果：溢出结果可绕过后续校验。\n"
            f"5. 结论：存在 {vuln_type}，风险等级 {risk_level}。"
        )

    if cot_type == "crypto_weakness":
        return (
            "分析过程：\n"
            f"1. 算法/参数识别：{sink}。\n"
            f"2. 强度评估：{taint_path}，该算法已被认为不安全。\n"
            "3. 已知攻击：存在碰撞/可预测/短密钥/固定IV等已知攻击方式。\n"
            "4. 防御检查：未使用安全替代方案。\n"
            f"5. 结论：存在 {vuln_type}，风险等级 {risk_level}。"
        )

    if cot_type == "info_disclosure":
        return (
            "分析过程：\n"
            f"1. 泄露内容：{source}。\n"
            f"2. 接收方：{sink}。\n"
            f"3. 是否敏感：{taint_path}，该信息含文件路径/库版本/堆栈/内部结构。\n"
            "4. 防御检查：未做信息过滤。\n"
            f"5. 结论：存在 {vuln_type}，风险等级 {risk_level}。"
        )

    if cot_type == "race_condition":
        return (
            "分析过程：\n"
            f"1. 共享状态：{source} 被并发访问。\n"
            f"2. 同步机制：{sink}，check-then-use 模式，代码未加锁。\n"
            f"3. 时间窗口：{taint_path}，检查与使用之间存在时间窗口。\n"
            "4. 防御检查：未发现 Lock/事务/原子操作。\n"
            f"5. 结论：存在 {vuln_type}，风险等级 {risk_level}。"
        )

    # 默认：source_sink（注入类）
    return (
        "分析过程：\n"
        f"1. 污染源：{source}。\n"
        f"2. 危险 sink：{sink}。\n"
        f"3. 数据流：{taint_path}。\n"
        "4. 防御检查：代码中无有效防御措施（无参数化、无转义、无校验）。\n"
        f"5. 结论：存在 {vuln_type}，风险等级 {risk_level}。"
    )


def add(code, language, filename, has_vulnerability, vuln_type, risk_level,
        source, sink, taint_path, fix_idea, cot_analysis=None, cot_type="source_sink"):
    """添加一条样本。cot_analysis 为 None 时自动生成。"""
    if cot_analysis is None:
        cot_analysis = build_cot(
            has_vulnerability, vuln_type, risk_level,
            source, sink, taint_path, fix_idea, cot_type
        )
    SAMPLES.append({
        "code": code.strip(),
        "language": language,
        "filename": filename,
        "has_vulnerability": has_vulnerability,
        "vuln_type": vuln_type,
        "risk_level": risk_level,
        "source": source,
        "sink": sink,
        "taint_path": taint_path,
        "fix_idea": fix_idea,
        "cot_analysis": cot_analysis.strip(),
        "cot_type": cot_type,
    })


# ===========================================================================
# 1. CWE-89 SQL 注入（40 条）
# ===========================================================================

# --- Python: Django / SQLAlchemy / Peewee / raw ---

add(
    """
from django.db import connection
from django.http import HttpResponse

def search_accounts(request):
    keyword = request.GET.get('q', '')
    with connection.cursor() as cur:
        cur.execute(f"SELECT id, name FROM accounts WHERE name LIKE '%{keyword}%'")
        rows = cur.fetchall()
    return HttpResponse(str(rows))
""",
    "python", "distill_001.py",
    True, "CWE-89 SQL注入", "Critical",
    "request.GET.get('q')", "cur.execute(f\"... {keyword} ...\")",
    "request.GET.get('q') → keyword → f-string 拼接 → cur.execute",
    "使用参数化查询：cur.execute(\"SELECT ... WHERE name LIKE %s\", [f'%{keyword}%'])",
)

add(
    """
from django.db.models import Q
from django.http import JsonResponse
from myapp.models import Account

def search_safe(request):
    keyword = request.GET.get('q', '')
    qs = Account.objects.filter(Q(name__icontains=keyword))
    return JsonResponse(list(qs.values('id', 'name')), safe=False)
""",
    "python", "distill_002.py",
    False, "none", "None",
    "request.GET.get('q')", "Account.objects.filter(Q(name__icontains=keyword))",
    "keyword 作为 ORM filter 参数传入，Django ORM 内部自动参数化",
    "no fix needed",
)

add(
    """
from sqlalchemy import create_engine, text
from flask import Flask, request

engine = create_engine('sqlite:///app.db')

@app.route('/lookup')
def lookup():
    email = request.args.get('email', '')
    with engine.connect() as conn:
        result = conn.execute(text("SELECT * FROM users WHERE email = '" + email + "'"))
        return dict(result.fetchone())
""",
    "python", "distill_003.py",
    True, "CWE-89 SQL注入", "Critical",
    "request.args.get('email')", "conn.execute(text(...))",
    "request.args.get('email') → email → 字符串拼接 → text() → conn.execute",
    "使用 SQLAlchemy 绑定参数：text(\"SELECT * FROM users WHERE email = :email\"), {\"email\": email}",
)

add(
    """
from sqlalchemy import create_engine, text

engine = create_engine('sqlite:///app.db')

@app.route('/lookup')
def lookup():
    email = request.args.get('email', '')
    stmt = text("SELECT * FROM users WHERE email = :email")
    with engine.connect() as conn:
        result = conn.execute(stmt, {"email": email})
        return dict(result.fetchone())
""",
    "python", "distill_004.py",
    False, "none", "None",
    "request.args.get('email')", "conn.execute(stmt, {\"email\": email})",
    "email 通过 :email 命名参数绑定，SQLAlchemy 自动转义",
    "no fix needed",
)

add(
    """
import peewee
from flask import request

db = peewee.SqliteDatabase('app.db')

@app.route('/users')
def users():
    role = request.args.get('role', 'user')
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE role = '%s'" % role)
    return str(cursor.fetchall())
""",
    "python", "distill_005.py",
    True, "CWE-89 SQL注入", "Critical",
    "request.args.get('role')", "cursor.execute(\"... '%s'\" % role)",
    "request.args.get('role') → role → % 格式化拼接 → cursor.execute",
    "使用参数化查询：cursor.execute(\"SELECT * FROM users WHERE role = ?\", (role,))",
)

add(
    """
@app.route('/products')
def products():
    category = request.args.get('cat', '')
    min_price = request.args.get('min', '0')
    # 动态 IN 子句拼接
    ids = request.args.get('ids', '')
    query = f"SELECT * FROM products WHERE category='{category}' AND price>={min_price} AND id IN ({ids})"
    cursor.execute(query)
    return jsonify(cursor.fetchall())
""",
    "python", "distill_006.py",
    True, "CWE-89 SQL注入", "Critical",
    "request.args.get('cat'/'min'/'ids')", "cursor.execute(query)",
    "多个用户输入通过 f-string 拼接到 SQL 的不同子句（WHERE/IN）→ SQL 注入",
    "全部使用参数化查询；IN 子句用占位符列表：cursor.execute(\"... id IN (%s,%s,%s)\", tuple(ids))",
)

add(
    """
@app.route('/delete')
def delete_record():
    table = request.args.get('table', 'logs')
    rid = request.args.get('id', '0')
    # 表名和值都从用户输入拼接
    sql = f"DELETE FROM {table} WHERE id = {rid}"
    cursor.execute(sql)
    db.commit()
    return 'deleted'
""",
    "python", "distill_007.py",
    True, "CWE-89 SQL注入", "Critical",
    "request.args.get('table') / request.args.get('id')", "cursor.execute(sql)",
    "table 和 id 通过 f-string 拼接到 DELETE 语句 → 表名注入 + 值注入",
    "表名用白名单校验；值用参数化：ALLOWED_TABLES={'logs'}; if table not in ALLOWED_TABLES: abort(400); cursor.execute(\"DELETE FROM logs WHERE id = ?\", (rid,))",
)

add(
    """
from string import Template

@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    tpl = Template("SELECT * FROM items WHERE name LIKE '%$keyword'")
    query = tpl.substitute(keyword=keyword)
    cursor.execute(query)
    return jsonify(cursor.fetchall())
""",
    "python", "distill_008.py",
    True, "CWE-89 SQL注入", "Critical",
    "request.args.get('q')", "cursor.execute(query)",
    "request.args.get('q') → keyword → Template.substitute → query → cursor.execute",
    "使用参数化查询，Template.substitute 不提供 SQL 安全转义",
)

# --- Java: Hibernate / JPA / MyBatis ---

add(
    """
@RestController
public class ProductController {
    @GetMapping("/products")
    public List<Product> search(@RequestParam String name) {
        Session session = sessionFactory.openSession();
        String hql = "from Product where name like '%" + name + "%'";
        return session.createQuery(hql, Product.class).list();
    }
}
""",
    "java", "distill_009.java",
    True, "CWE-89 SQL注入", "Critical",
    "@RequestParam name", "session.createQuery(hql)",
    "@RequestParam name → 字符串拼接 → HQL → createQuery",
    "使用 HQL 参数绑定：session.createQuery(\"from Product where name like :name\", Product.class).setParameter(\"name\", \"%\"+name+\"%\")",
)

add(
    """
@RestController
public class ProductController {
    @GetMapping("/products")
    public List<Product> search(@RequestParam String name) {
        Session session = sessionFactory.openSession();
        return session.createQuery("from Product where name like :name", Product.class)
                .setParameter("name", "%" + name + "%")
                .list();
    }
}
""",
    "java", "distill_010.java",
    False, "none", "None",
    "@RequestParam name", "createQuery().setParameter(\"name\", ...)",
    "name 通过 :name 命名参数绑定，Hibernate 自动转义",
    "no fix needed",
)

add(
    """
@Repository
public class UserDao {
    @PersistenceContext
    private EntityManager em;

    public User findByEmail(String email) {
        return (User) em.createNativeQuery("SELECT * FROM users WHERE email = '" + email + "'", User.class)
                .getSingleResult();
    }
}
""",
    "java", "distill_011.java",
    True, "CWE-89 SQL注入", "Critical",
    "email 参数", "em.createNativeQuery(拼接)",
    "email → 字符串拼接 → createNativeQuery → SQL 注入",
    "使用参数绑定：em.createNativeQuery(\"SELECT * FROM users WHERE email = :email\", User.class).setParameter(\"email\", email)",
)

add(
    """
<!-- MyBatis mapper XML — 使用 ${} 直接拼接 -->
<select id="findByOrder" resultType="Order">
    SELECT * FROM orders WHERE order_no = ${orderNo}
</select>
""",
    "java", "distill_012.xml",
    True, "CWE-89 SQL注入", "Critical",
    "${orderNo}（MyBatis 美元符号插值）", "SELECT ... ${orderNo}",
    "MyBatis ${} 将参数原样拼接到 SQL，不做转义 → SQL 注入",
    "改用 #{} 占位符：SELECT * FROM orders WHERE order_no = #{orderNo}",
)

add(
    """
<!-- MyBatis mapper XML — 使用 #{} 参数化 -->
<select id="findByOrder" resultType="Order">
    SELECT * FROM orders WHERE order_no = #{orderNo}
</select>
""",
    "java", "distill_013.xml",
    False, "none", "None",
    "#{orderNo}", "SELECT ... #{orderNo}",
    "MyBatis #{} 使用 PreparedStatement 占位符，参数自动转义",
    "no fix needed",
)

add(
    """
@RestController
public class ReportController {
    @GetMapping("/report")
    public String generateReport(@RequestParam String table, @RequestParam String column) {
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        // 表名和列名都从用户输入拼接
        return jdbc.queryForObject("SELECT " + column + " FROM " + table + " LIMIT 1", String.class);
    }
}
""",
    "java", "distill_014.java",
    True, "CWE-89 SQL注入", "Critical",
    "@RequestParam table / @RequestParam column", "jdbc.queryForObject(拼接 SQL)",
    "table 和 column 从用户输入直接拼接到 SELECT 子句 → SQL 注入",
    "表名/列名用白名单校验；值用参数化绑定",
)

# --- PHP: mysqli / PDO / Laravel ---

add(
    """
<?php
$host = $_GET['host'] ?? '';
$conn = mysqli_connect('localhost', 'root', '', 'appdb');
$sql = "SELECT * FROM servers WHERE hostname = '" . $host . "'";
$result = mysqli_query($conn, $sql);
echo json_encode(mysqli_fetch_all($result, MYSQLI_ASSOC));
""",
    "php", "distill_015.php",
    True, "CWE-89 SQL注入", "Critical",
    "$_GET['host']", "mysqli_query($conn, $sql)",
    "$_GET['host'] → $host → 字符串拼接 → mysqli_query",
    "使用 mysqli 预处理：$stmt = mysqli_prepare($conn, \"SELECT * FROM servers WHERE hostname = ?\"); mysqli_stmt_bind_param($stmt, 's', $host);",
)

add(
    """
<?php
$host = $_GET['host'] ?? '';
$conn = mysqli_connect('localhost', 'root', '', 'appdb');
$stmt = mysqli_prepare($conn, "SELECT * FROM servers WHERE hostname = ?");
mysqli_stmt_bind_param($stmt, 's', $host);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
echo json_encode(mysqli_fetch_all($result, MYSQLI_ASSOC));
""",
    "php", "distill_016.php",
    False, "none", "None",
    "$_GET['host']", "mysqli_stmt_bind_param($stmt, 's', $host)",
    "$host 通过 bind_param 绑定到预处理语句，mysqli 自动转义",
    "no fix needed",
)

add(
    """
<?php
// Laravel DB::raw 拼接
use Illuminate\\Support\\Facades\\DB;

Route::get('/search', function () {
    $keyword = request('q');
    $results = DB::select("SELECT * FROM products WHERE name LIKE '%" . $keyword . "%'");
    return response()->json($results);
});
""",
    "php", "distill_017.php",
    True, "CWE-89 SQL注入", "Critical",
    "request('q')", "DB::select(拼接 SQL)",
    "request('q') → $keyword → 字符串拼接 → DB::select",
    "使用 Laravel 查询构造器：DB::table('products')->where('name', 'like', '%'.$keyword.'%')->get()",
)

add(
    """
<?php
use Illuminate\\Support\\Facades\\DB;

Route::get('/search', function () {
    $keyword = request('q');
    $results = DB::table('products')
        ->where('name', 'like', '%' . $keyword . '%')
        ->get();
    return response()->json($results);
});
""",
    "php", "distill_018.php",
    False, "none", "None",
    "request('q')", "DB::table('products')->where(...)",
    "$keyword 作为查询构造器参数传入，Laravel 内部自动参数化",
    "no fix needed",
)

add(
    """
<?php
// PDO query（非 prepare）直接拼接
$pdo = new PDO('mysql:host=localhost;dbname=appdb', 'root', '');
$keyword = $_GET['q'] ?? '';
$stmt = $pdo->query("SELECT * FROM articles WHERE title LIKE '%" . $keyword . "%'");
echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
""",
    "php", "distill_019.php",
    True, "CWE-89 SQL注入", "Critical",
    "$_GET['q']", "$pdo->query(拼接 SQL)",
    "$_GET['q'] → $keyword → 字符串拼接 → $pdo->query",
    "使用 PDO 预处理：$stmt = $pdo->prepare(\"SELECT ... WHERE title LIKE ?\"); $stmt->execute(['%'.$keyword.'%']);",
)

# --- JavaScript: mysql / Sequelize ---

add(
    """
const mysql = require('mysql');
const conn = mysql.createConnection({host: 'localhost', user: 'root', database: 'appdb'});

app.get('/users', (req, res) => {
    const role = req.query.role;
    const sql = "SELECT * FROM users WHERE role = '" + role + "'";
    conn.query(sql, (err, rows) => {
        res.json(rows);
    });
});
""",
    "javascript", "distill_020.js",
    True, "CWE-89 SQL注入", "Critical",
    "req.query.role", "conn.query(sql)",
    "req.query.role → role → 字符串拼接 → conn.query",
    "使用 ? 占位符：conn.query(\"SELECT * FROM users WHERE role = ?\", [role], callback)",
)

add(
    """
const mysql = require('mysql');
const conn = mysql.createConnection({host: 'localhost', user: 'root', database: 'appdb'});

app.get('/users', (req, res) => {
    const role = req.query.role;
    conn.query("SELECT * FROM users WHERE role = ?", [role], (err, rows) => {
        res.json(rows);
    });
});
""",
    "javascript", "distill_021.js",
    False, "none", "None",
    "req.query.role", "conn.query(\"... ?\", [role])",
    "role 通过 ? 占位符 + 参数数组传入，mysql 驱动自动转义",
    "no fix needed",
)

add(
    """
const { Sequelize } = require('sequelize');
const sequelize = new Sequelize('sqlite::memory:');

app.get('/search', (req, res) => {
    const name = req.query.name;
    const results = sequelize.query("SELECT * FROM items WHERE name LIKE '%" + name + "%'");
    res.json(results);
});
""",
    "javascript", "distill_022.js",
    True, "CWE-89 SQL注入", "Critical",
    "req.query.name", "sequelize.query(拼接 SQL)",
    "req.query.name → name → 字符串拼接 → sequelize.query",
    "使用 Sequelize 绑定参数：sequelize.query(\"SELECT * FROM items WHERE name LIKE :name\", {replacements: {name: '%'+name+'%'}})",
)

# --- Go: database/sql / GORM ---

add(
    """
func getUser(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    query := fmt.Sprintf("SELECT name FROM users WHERE id = %s", id)
    row := db.QueryRow(query)
    var name string
    row.Scan(&name)
    fmt.Fprintf(w, name)
}
""",
    "go", "distill_023.go",
    True, "CWE-89 SQL注入", "Critical",
    "r.URL.Query().Get('id')", "db.QueryRow(query)",
    "id → fmt.Sprintf 拼接 → db.QueryRow → SQL 注入",
    "使用参数化查询：db.QueryRow(\"SELECT name FROM users WHERE id = $1\", id)",
)

add(
    """
func getUser(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    var name string
    err := db.QueryRow("SELECT name FROM users WHERE id = $1", id).Scan(&name)
    if err != nil {
        http.Error(w, "not found", 404)
        return
    }
    fmt.Fprintf(w, "%s", name)
}
""",
    "go", "distill_024.go",
    False, "none", "None",
    "r.URL.Query().Get('id')", "db.QueryRow(\"... $1\", id)",
    "id 通过 $1 占位符绑定，database/sql 自动转义",
    "no fix needed",
)

add(
    """
// GORM Raw 拼接
func searchProducts(c *gin.Context) {
    name := c.Query("name")
    var products []Product
    db.Raw("SELECT * FROM products WHERE name LIKE '%" + name + "%'").Scan(&products)
    c.JSON(200, products)
}
""",
    "go", "distill_025.go",
    True, "CWE-89 SQL注入", "Critical",
    "c.Query('name')", "db.Raw(拼接 SQL)",
    "c.Query('name') → name → 字符串拼接 → db.Raw → SQL 注入",
    "使用 GORM 参数化：db.Raw(\"SELECT * FROM products WHERE name LIKE ?\", \"%\"+name+\"%\").Scan(&products)",
)

# --- 绕过变体 ---

add(
    """
@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    # 双引号转义：仅替换单引号为双单引号
    keyword = keyword.replace("'", "''")
    query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    cursor.execute(query)
    return jsonify(cursor.fetchall())
""",
    "python", "distill_026.py",
    True, "CWE-89 SQL注入", "High",
    "request.args.get('q')", "cursor.execute(query)",
    "replace(\"'\",\"''\") 在某些编码下可被绕过（如 GBK 多字节），且 LIKE 上下文中的 % 仍可注入",
    "使用参数化查询，不要依赖手动转义",
)

add(
    """
@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    # 尝试用注释阻断后续 SQL，但用户可注入 /**/union
    keyword = keyword.replace('union', '').replace('select', '')
    query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    cursor.execute(query)
    return jsonify(cursor.fetchall())
""",
    "python", "distill_027.py",
    True, "CWE-89 SQL注入", "High",
    "request.args.get('q')", "cursor.execute(query)",
    "黑名单 replace union/select 可被大小写（UnIoN/sElEcT）或内联注释绕过",
    "使用参数化查询，黑名单过滤不可靠",
)

add(
    """
@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    # 尝试过滤分号，但注释符 -- 仍可截断查询
    if ';' in keyword:
        abort(400)
    query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    cursor.execute(query)
    return jsonify(cursor.fetchall())
""",
    "python", "distill_028.py",
    True, "CWE-89 SQL注入", "High",
    "request.args.get('q')", "cursor.execute(query)",
    "仅过滤分号，-- 注释和 UNION 注入仍可绕过",
    "使用参数化查询",
)

add(
    """
@app.route('/data')
def get_data():
    # LIMIT/OFFSET 注入
    limit = request.args.get('limit', '10')
    offset = request.args.get('offset', '0')
    query = f"SELECT * FROM records LIMIT {limit} OFFSET {offset}"
    cursor.execute(query)
    return jsonify(cursor.fetchall())
""",
    "python", "distill_029.py",
    True, "CWE-89 SQL注入", "High",
    "request.args.get('limit'/'offset')", "cursor.execute(query)",
    "limit/offset 通过 f-string 拼接到 SQL，可注入 UNION SELECT",
    "LIMIT/OFFSET 用参数化或 int() 强制转换：limit = int(limit); offset = int(offset); cursor.execute(\"... LIMIT ? OFFSET ?\", (limit, offset))",
)

add(
    """
@app.route('/data')
def get_data():
    # JSON 字段提取注入
    key = request.args.get('key', 'name')
    query = f"SELECT data->>'$.{key}' FROM json_records"
    cursor.execute(query)
    return jsonify(cursor.fetchall())
""",
    "python", "distill_030.py",
    True, "CWE-89 SQL注入", "High",
    "request.args.get('key')", "cursor.execute(query)",
    "key 通过 f-string 拼接到 JSON 路径表达式 → SQL 注入",
    "白名单校验 key 或参数化 JSON 路径",
)

# --- CVE 风格 ---

add(
    """
# CVE 风格：WordPress $wpdb->prepare 错误使用
@app.route('/wp_search')
def wp_search():
    keyword = request.args.get('s', '')
    # 模拟 WordPress $wpdb->prepare 在 LIKE 上下文中的错误用法
    like = '%' + keyword + '%'
    query = "SELECT * FROM wp_posts WHERE post_title LIKE %s" % ('%' + like + '%')
    cursor.execute(query)
    return jsonify(cursor.fetchall())
""",
    "python", "distill_031.py",
    True, "CWE-89 SQL注入", "Critical",
    "request.args.get('s')", "cursor.execute(query)",
    "keyword 经 % 格式化拼接为 LIKE 参数 → SQL 注入",
    "使用参数化查询：cursor.execute(\"SELECT ... LIKE %s\", ('%'+keyword+'%',))",
)

add(
    """
# Django extra() 注入
from django.http import JsonResponse
from myapp.models import Product

def extra_search(request):
    where = request.GET.get('where', '1=1')
    qs = Product.objects.extra(where=[where])
    return JsonResponse(list(qs.values()), safe=False)
""",
    "python", "distill_032.py",
    True, "CWE-89 SQL注入", "Critical",
    "request.GET.get('where')", "Product.objects.extra(where=[where])",
    "where 通过 extra() 直接拼接到 SQL WHERE 子句 → SQL 注入（Django extra 已废弃）",
    "不要使用 extra()；改用 ORM filter 或 raw + 参数化",
)

add(
    """
# Django extra() 安全用法
from django.http import JsonResponse
from myapp.models import Product

def extra_search(request):
    min_price = request.GET.get('min', '0')
    qs = Product.objects.extra(where=["price >= %s"], params=[min_price])
    return JsonResponse(list(qs.values()), safe=False)
""",
    "python", "distill_033.py",
    False, "none", "None",
    "request.GET.get('min')", "Product.objects.extra(where=[...], params=[min_price])",
    "min_price 通过 params 参数绑定，extra 使用 %s 占位符",
    "no fix needed",
)

add(
    """
# Spring JdbcTemplate LIKE 注入
@RestController
public class SearchController {
    @GetMapping("/search")
    public List<Map<String, Object>> search(@RequestParam String q) {
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        String sql = "SELECT * FROM products WHERE name LIKE '%" + q + "%'";
        return jdbc.queryForList(sql);
    }
}
""",
    "java", "distill_034.java",
    True, "CWE-89 SQL注入", "Critical",
    "@RequestParam q", "jdbc.queryForList(sql)",
    "q 拼接到 LIKE 子句 → SQL 注入",
    "使用 PreparedStatement：jdbc.queryForList(\"SELECT * FROM products WHERE name LIKE ?\", new Object[]{\"%\"+q+\"%\"})",
)

add(
    """
# JdbcTemplate 参数化
@RestController
public class SearchController {
    @GetMapping("/search")
    public List<Map<String, Object>> search(@RequestParam String q) {
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        return jdbc.queryForList(
            "SELECT * FROM products WHERE name LIKE ?",
            new Object[]{"%" + q + "%"}
        );
    }
}
""",
    "java", "distill_035.java",
    False, "none", "None",
    "@RequestParam q", "jdbc.queryForList(\"... ?\", new Object[]{...})",
    "q 通过 ? 占位符 + 参数数组绑定，JdbcTemplate 自动转义",
    "no fix needed",
)

add(
    """
@app.route('/update_email')
def update_email():
    uid = request.args.get('uid', '')
    email = request.args.get('email', '')
    # UPDATE 语句拼接
    query = f"UPDATE users SET email = '{email}' WHERE id = {uid}"
    cursor.execute(query)
    db.commit()
    return 'updated'
""",
    "python", "distill_036.py",
    True, "CWE-89 SQL注入", "Critical",
    "request.args.get('email'/'uid')", "cursor.execute(query)",
    "email 和 uid 通过 f-string 拼接到 UPDATE 语句 → SQL 注入",
    "使用参数化查询：cursor.execute(\"UPDATE users SET email = ? WHERE id = ?\", (email, uid))",
)

add(
    """
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    email = request.form['email']
    # INSERT 语句拼接
    query = f"INSERT INTO users (name, email) VALUES ('{username}', '{email}')"
    cursor.execute(query)
    db.commit()
    return 'registered'
""",
    "python", "distill_037.py",
    True, "CWE-89 SQL注入", "Critical",
    "request.form['username'/'email']", "cursor.execute(query)",
    "username 和 email 通过 f-string 拼接到 INSERT VALUES → SQL 注入",
    "使用参数化查询：cursor.execute(\"INSERT INTO users (name, email) VALUES (?, ?)\", (username, email))",
)

add(
    """
// Sequelize literal 注入
const { Sequelize } = require('sequelize');

app.get('/filter', (req, res) => {
    const condition = req.query.where;
    const items = await Item.findAll({
        where: Sequelize.literal(condition)
    });
    res.json(items);
});
""",
    "javascript", "distill_038.js",
    True, "CWE-89 SQL注入", "Critical",
    "req.query.where", "Sequelize.literal(condition)",
    "req.query.where → Sequelize.literal → 直接拼接到 SQL WHERE → SQL 注入",
    "不要使用 Sequelize.literal 处理用户输入；使用 Sequelize.where + Op",
)

add(
    """
// Sequelize 安全 WHERE
const { Op } = require('sequelize');

app.get('/filter', (req, res) => {
    const name = req.query.name;
    const items = await Item.findAll({
        where: { name: { [Op.like]: '%' + name + '%' } }
    });
    res.json(items);
});
""",
    "javascript", "distill_039.js",
    False, "none", "None",
    "req.query.name", "Item.findAll({ where: { name: { [Op.like]: ... } } })",
    "name 作为 Op.like 的值传入，Sequelize 内部自动参数化",
    "no fix needed",
)

add(
    """
# Python Django raw() 带 params 安全用法
from django.http import JsonResponse
from myapp.models import Product

def raw_search(request):
    keyword = request.GET.get('q', '')
    qs = Product.objects.raw("SELECT * FROM products WHERE name LIKE %s", [f'%{keyword}%'])
    return JsonResponse(list(qs.values()), safe=False)
""",
    "python", "distill_040.py",
    False, "none", "None",
    "request.GET.get('q')", "Product.objects.raw(\"... %s\", [params])",
    "keyword 通过 raw() 的 params 参数绑定，Django raw 使用占位符参数化",
    "no fix needed",
)


# ===========================================================================
# 2. CWE-79 XSS（35 条）
# ===========================================================================

add(
    """
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

app = FastAPI()

@app.get('/hello', response_class=HTMLResponse)
async def hello(request: Request):
    name = request.query_params.get('name', '')
    return f'<h1>Welcome, {name}!</h1>'
""",
    "python", "distill_041.py",
    True, "CWE-79 XSS", "High",
    "request.query_params.get('name')", "f-string HTML 响应",
    "request.query_params.get('name') → name → f-string → HTMLResponse → 浏览器",
    "使用 html.escape() 转义或使用 Jinja2 模板（autoescape=True）",
)

add(
    """
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
import html

app = FastAPI()

@app.get('/hello', response_class=HTMLResponse)
async def hello(request: Request):
    name = html.escape(request.query_params.get('name', ''))
    return f'<h1>Welcome, {name}!</h1>'
""",
    "python", "distill_042.py",
    False, "none", "None",
    "request.query_params.get('name')", "f-string HTML 响应（已转义）",
    "name 经 html.escape 转义后再拼接到 HTML，特殊字符被转为 HTML 实体",
    "no fix needed",
)

add(
    """
from django.http import HttpResponse

def greet(request):
    name = request.GET.get('name', '')
    return HttpResponse('<div>Hello, ' + name + '</div>')
""",
    "python", "distill_043.py",
    True, "CWE-79 XSS", "High",
    "request.GET.get('name')", "HttpResponse(拼接 HTML)",
    "request.GET.get('name') → name → 字符串拼接 → HttpResponse",
    "使用 django.utils.html.escape 转义或 render 模板（autoescape=True）",
)

add(
    """
from django.http import HttpResponse
from django.utils.html import escape

def greet(request):
    name = request.GET.get('name', '')
    return HttpResponse('<div>Hello, ' + escape(name) + '</div>')
""",
    "python", "distill_044.py",
    False, "none", "None",
    "request.GET.get('name')", "HttpResponse(escape(name))",
    "name 经 django.utils.html.escape 转义后拼接",
    "no fix needed",
)

add(
    """
// Laravel Blade {!! !!} 不转义输出
// resources/views/greet.blade.php
<h1>Welcome, {!! $name !!}</h1>

// routes/web.php
Route::get('/greet', function () {
    return view('greet', ['name' => request('name')]);
});
""",
    "php", "distill_045.php",
    True, "CWE-79 XSS", "High",
    "request('name')", "{!! $name !!}（Blade 不转义输出）",
    "request('name') → $name → Blade {!! !!} → 不转义输出到 HTML",
    "使用 {{ $name }}（Blade 默认转义）替代 {!! $name !!}",
)

add(
    """
// Laravel Blade {{ }} 自动转义
Route::get('/greet', function () {
    return view('greet', ['name' => request('name')]);
});

// resources/views/greet.blade.php
<h1>Welcome, {{ $name }}</h1>
""",
    "php", "distill_046.php",
    False, "none", "None",
    "request('name')", "{{ $name }}（Blade 自动转义）",
    "$name 通过 {{ }} 输出，Blade 自动调用 htmlspecialchars 转义",
    "no fix needed",
)

add(
    """
const express = require('express');
const app = express();

app.get('/profile', (req, res) => {
    const bio = req.query.bio;
    res.send('<section><h2>Bio</h2><p>' + bio + '</p></section>');
});
""",
    "javascript", "distill_047.js",
    True, "CWE-79 XSS", "High",
    "req.query.bio", "res.send(拼接 HTML)",
    "req.query.bio → bio → 字符串拼接 → res.send → 浏览器",
    "使用 escape-html 中间件转义：const escape = require('escape-html'); res.send('...<p>' + escape(bio) + '</p>...')",
)

add(
    """
const express = require('express');
const escape = require('escape-html');
const app = express();

app.get('/profile', (req, res) => {
    const bio = escape(req.query.bio);
    res.send('<section><h2>Bio</h2><p>' + bio + '</p></section>');
});
""",
    "javascript", "distill_048.js",
    False, "none", "None",
    "req.query.bio", "res.send(escape(bio) 拼接)",
    "bio 经 escape-html 转义后拼接到 HTML",
    "no fix needed",
)

add(
    """
import java.io.IOException;
import javax.servlet.http.*;

public class GreetingServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        resp.setContentType("text/html");
        resp.getWriter().println("<h1>Hello, " + name + "!</h1>");
    }
}
""",
    "java", "distill_049.java",
    True, "CWE-79 XSS", "High",
    "req.getParameter('name')", "resp.getWriter().println(拼接 HTML)",
    "req.getParameter → name → 字符串拼接 → PrintWriter → 浏览器",
    "使用 OWASP Java Encoder 编码：Encoder.forHtml(name); 或使用 JSP EL（默认转义）",
)

add(
    """
import java.io.IOException;
import javax.servlet.http.*;
import org.owasp.encoder.Encode;

public class GreetingServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        resp.setContentType("text/html");
        resp.getWriter().println("<h1>Hello, " + Encode.forHtml(name) + "!</h1>");
    }
}
""",
    "java", "distill_050.java",
    False, "none", "None",
    "req.getParameter('name')", "Encode.forHtml(name) 后拼接",
    "name 经 OWASP Encode.forHtml 编码后拼接到 HTML",
    "no fix needed",
)

add(
    """
// JSP scriptlet 不转义
<%
    String name = request.getParameter("name");
%>
<h1>Hello, <%= name %>!</h1>
""",
    "java", "distill_051.jsp",
    True, "CWE-79 XSS", "High",
    "request.getParameter('name')", "<%= name %>（JSP 不转义输出）",
    "request.getParameter → name → <%= %> → 不转义输出到 HTML",
    "使用 JSTL <c:out value=\"${param.name}\"/> 或 EL ${param.name}（默认转义）",
)

add(
    """
// JSP JSTL c:out 自动转义
<%@ taglib uri=\"http://java.sun.com/jsp/jstl/core\" prefix=\"c\" %>
<h1>Hello, <c:out value=\"${param.name}\"/>!</h1>
""",
    "java", "distill_052.jsp",
    False, "none", "None",
    "param.name", "<c:out value=\"${param.name}\"/>",
    "JSTL c:out 默认 escapeXml=true，自动转义 HTML 特殊字符",
    "no fix needed",
)

add(
    """
// Spring Thymeleaf utext 不转义
@GetMapping("/greet")
public String greet(@RequestParam String name, Model model) {
    model.addAttribute("name", name);
    return "greet";
}

// greet.html
<h1 th:utext="${name}">Default</h1>
""",
    "java", "distill_053.java",
    True, "CWE-79 XSS", "High",
    "@RequestParam name", "th:utext=\"${name}\"",
    "@RequestParam name → model → th:utext → 不转义输出到 HTML",
    "使用 th:text 替代 th:utext（Thymeleaf 默认转义）",
)

add(
    """
// Spring Thymeleaf th:text 自动转义
@GetMapping("/greet")
public String greet(@RequestParam String name, Model model) {
    model.addAttribute("name", name);
    return "greet";
}

// greet.html
<h1 th:text="${name}">Default</h1>
""",
    "java", "distill_054.java",
    False, "none", "None",
    "@RequestParam name", "th:text=\"${name}\"",
    "Thymeleaf th:text 默认转义 HTML 特殊字符",
    "no fix needed",
)

add(
    """
func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    fmt.Fprintf(w, "<h1>Hello, %s!</h1>", name)
}
""",
    "go", "distill_055.go",
    True, "CWE-79 XSS", "High",
    "r.URL.Query().Get('name')", "fmt.Fprintf(w, \"... %s ...\", name)",
    "name → fmt.Fprintf → HTTP 响应体 → 浏览器",
    "使用 html.EscapeString 转义：fmt.Fprintf(w, \"<h1>Hello, %s!</h1>\", html.EscapeString(name))",
)

add(
    """
func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    fmt.Fprintf(w, "<h1>Hello, %s!</h1>", html.EscapeString(name))
}
""",
    "go", "distill_056.go",
    False, "none", "None",
    "r.URL.Query().Get('name')", "html.EscapeString(name) 后 Fprintf",
    "name 经 html.EscapeString 转义后输出",
    "no fix needed",
)

add(
    """
# Go html/template 自动转义
func handler(w http.ResponseWriter, r *http.Request) {
    tmpl, _ := template.New("greet").Parse("<h1>Hello, {{.Name}}!</h1>")
    tmpl.Execute(w, struct{ Name string }{r.URL.Query().Get("name")})
}
""",
    "go", "distill_057.go",
    False, "none", "None",
    "r.URL.Query().Get('name')", "template.Execute（自动转义）",
    "Go html/template 包默认对模板变量做 HTML 上下文转义",
    "no fix needed",
)

add(
    """
// DOM XSS via document.write
app.get('/page', (req, res) => {
    res.send(`
        <script>
            document.write('<h1>' + '${req.query.title}' + '</h1>');
        </script>
    `);
});
""",
    "javascript", "distill_058.js",
    True, "CWE-79 XSS(DOM)", "High",
    "req.query.title", "document.write",
    "req.query.title → 模板字符串注入 → document.write → DOM 注入",
    "使用 textContent 或对 title 做 HTML 转义后再写入",
)

add(
    """
// jQuery .html() 注入
app.get('/banner', (req, res) => {
    res.send(`
        <script>
            $('#banner').html('${req.query.content}');
        </script>
    `);
});
""",
    "javascript", "distill_059.js",
    True, "CWE-79 XSS(DOM)", "High",
    "req.query.content", "$('#banner').html(...)",
    "req.query.content → jQuery .html() → DOM 注入",
    "使用 $('#banner').text(content) 替代 .html()",
)

add(
    """
// XSS via input value attribute
app.get('/form', (req, res) => {
    const email = req.query.email || '';
    res.send(`<input type="text" value="${email}">`);
});
""",
    "javascript", "distill_060.js",
    True, "CWE-79 XSS", "High",
    "req.query.email", "value=\"${email}\"",
    "email 注入到 value 属性，可通过 \" onfocus=alert(1) // 绕过属性边界",
    "对属性值做 HTML 属性转义：使用 escape-html 或双引号编码",
)

add(
    """
// XSS via textarea content
app.get('/editor', (req, res) => {
    const content = req.query.content || '';
    res.send(`<textarea>${content}</textarea>`);
});
""",
    "javascript", "distill_061.js",
    True, "CWE-79 XSS", "High",
    "req.query.content", "<textarea>${content}</textarea>",
    "content 注入到 textarea 标签内容，可通过 </textarea><script> 绕过",
    "对 < > 做 HTML 转义后输出",
)

add(
    """
# XSS via JSON response with wrong content-type
from flask import Flask, jsonify, request
app = Flask(__name__)

@app.route('/api/message')
def message():
    msg = request.args.get('msg', '')
    # Content-Type 默认 application/json，但被浏览器以 text/html 解释
    resp = app.make_response(jsonify({'msg': msg}))
    resp.headers['Content-Type'] = 'text/html'
    return resp
""",
    "python", "distill_062.py",
    True, "CWE-79 XSS", "High",
    "request.args.get('msg')", "resp.headers['Content-Type'] = 'text/html'",
    "JSON 响应被设为 text/html → 浏览器将 JSON 内容当 HTML 解析 → XSS",
    "保持 Content-Type: application/json，不要修改为 text/html",
)

add(
    """
# 存储型 XSS via 用户名
from flask import Flask, request, session
from models import User

@app.route('/profile/display')
def display_profile():
    uid = session.get('uid')
    user = User.query.get(uid)
    # 用户名从数据库读取，未转义输出
    return f'<div class="user">{user.username}</div>'
""",
    "python", "distill_063.py",
    True, "CWE-79 XSS(存储型)", "High",
    "数据库中的 user.username（用户注册时存入）", "f-string HTML 输出",
    "注册时存入恶意 username → 读取时未转义 → f-string 拼接 → XSS",
    "输出时 html.escape(user.username) 或使用 Jinja2 模板自动转义",
)

add(
    """
# 存储型 XSS via 评论
@app.route('/comments')
def comments():
    cid = request.args.get('cid')
    comment = Comment.query.get(cid)
    # 评论内容直接输出到 HTML
    return f'<div class="comment-body">{comment.body}</div>'
""",
    "python", "distill_064.py",
    True, "CWE-79 XSS(存储型)", "High",
    "数据库中的 comment.body（用户提交的评论）", "f-string HTML 输出",
    "用户提交恶意评论 → 存入数据库 → 读取时未转义 → XSS",
    "输出时 html.escape(comment.body) 或使用 Jinja2 模板自动转义",
)

add(
    """
# 反射型 XSS via 错误页面
@app.route('/404')
def not_found():
    path = request.args.get('path', '')
    return f'<h1>Page not found: {path}</h1>', 404
""",
    "python", "distill_065.py",
    True, "CWE-79 XSS(反射型)", "High",
    "request.args.get('path')", "f-string 错误页面",
    "path → f-string → 404 错误页面 → 浏览器",
    "使用 html.escape(path) 转义后输出",
)

# --- XSS 绕过变体 ---

add(
    """
@app.route('/search')
def search():
    q = request.args.get('q', '')
    # 过滤 <script 但不过滤 <img/onerror
    q = q.replace('<script', '')
    return f'<div>Results for: {q}</div>'
""",
    "python", "distill_066.py",
    True, "CWE-79 XSS", "High",
    "request.args.get('q')", "f-string HTML 输出",
    "仅过滤 <script 字面量，<img src=x onerror=alert(1)> 等向量仍可注入",
    "使用 html.escape() 对所有 HTML 特殊字符统一转义",
)

add(
    """
@app.route('/search')
def search():
    q = request.args.get('q', '')
    # 大小写不敏感过滤
    q = re.sub(r'<script', '', q, flags=re.IGNORECASE)
    return f'<div>Results for: {q}</div>'
""",
    "python", "distill_067.py",
    True, "CWE-79 XSS", "High",
    "request.args.get('q')", "f-string HTML 输出",
    "正则过滤 <script 仍不覆盖 <svg/onload、<img/onerror 等向量",
    "使用 html.escape() 统一转义",
)

add(
    """
app.get('/search', (req, res) => {
    const q = req.query.q || '';
    // 过滤 javascript: 但不过滤 JaVaScRiPt:
    const filtered = q.replace(/javascript:/gi, '');
    res.send(`<a href="${filtered}">Click</a>`);
});
""",
    "javascript", "distill_068.js",
    True, "CWE-79 XSS", "High",
    "req.query.q", "href 属性拼接",
    "过滤 javascript: 但可被 data:text/html;base64,... 或其他协议绕过",
    "校验 URL 协议白名单（http/https/相对路径）",
)

add(
    """
app.get('/render', (req, res) => {
    const color = req.query.color || '#fff';
    // style 属性注入
    res.send(`<div style="color: ${color}">Text</div>`);
});
""",
    "javascript", "distill_069.js",
    True, "CWE-79 XSS", "High",
    "req.query.color", "style 属性拼接",
    "color 注入到 style 属性，可通过 red;background:url(javascript:...) 绕过",
    "校验 color 为合法颜色值（#hex 或 rgb()），不要直接拼接到 style",
)

add(
    """
# SVG onload 注入
@app.route('/avatar')
def avatar():
    url = request.args.get('url', '/default.png')
    return f'<img src="{url}" />'
""",
    "python", "distill_070.py",
    True, "CWE-79 XSS", "High",
    "request.args.get('url')", "<img src=\"{url}\" />",
    "url 可注入 javascript: 或 data:text/html 协议 → XSS",
    "校验 URL 协议白名单（http/https/相对路径）+ html.escape",
)

add(
    """
# React JSX 自动转义（安全对照）
function Greeting({ name }) {
    return <h1>Hello, {name}!</h1>;
}

// React 默认对 {} 插值做 HTML 转义
""",
    "javascript", "distill_071.jsx",
    False, "none", "None",
    "props.name", "<h1>Hello, {name}</h1>",
    "React JSX {} 插值默认转义 HTML 特殊字符",
    "no fix needed",
)

add(
    """
# Vue v-text 自动转义（安全对照）
<template>
  <div v-text="message"></div>
</template>
<script>
export default {
  data() { return { message: this.$route.query.msg } }
}
</script>
""",
    "javascript", "distill_072.vue",
    False, "none", "None",
    "$route.query.msg", "v-text=\"message\"",
    "Vue v-text 设置 textContent，不会解析 HTML 标签",
    "no fix needed",
)

add(
    """
# Vue v-html 不安全（对照）
<template>
  <div v-html="message"></div>
</template>
<script>
export default {
  data() { return { message: this.$route.query.msg } }
}
</script>
""",
    "javascript", "distill_073.vue",
    True, "CWE-79 XSS(DOM)", "High",
    "$route.query.msg", "v-html=\"message\"",
    "v-html 直接将 message 作为 innerHTML 插入 → DOM XSS",
    "使用 v-text 替代 v-html；如需渲染 HTML 必须先做净化（DOMPurify）",
)

add(
    """
# Angular {{ }} 自动转义（安全对照）
@Component({
  selector: 'app-greet',
  template: '<h1>Hello, {{name}}!</h1>'
})
export class GreetComponent {
  name = '';
  constructor(private route: ActivatedRoute) {
    this.name = this.route.snapshot.queryParamMap.get('name');
  }
}
""",
    "javascript", "distill_074.ts",
    False, "none", "None",
    "route.snapshot.queryParamMap.get('name')", "{{name}}",
    "Angular {{ }} 插值默认转义 HTML 特殊字符",
    "no fix needed",
)

add(
    """
# Angular [innerHTML] 不安全（对照）
@Component({
  selector: 'app-greet',
  template: '<div [innerHTML]=\"name\"></div>'
})
export class GreetComponent {
  name = '';
  constructor(private route: ActivatedRoute) {
    this.name = this.route.snapshot.queryParamMap.get('name');
  }
}
""",
    "javascript", "distill_075.ts",
    True, "CWE-79 XSS(DOM)", "High",
    "route.snapshot.queryParamMap.get('name')", "[innerHTML]=\"name\"",
    "[innerHTML] 直接渲染 HTML → XSS（Angular 默认会净化，但自定义 bypassSecurityTrustHtml 会绕过）",
    "使用 {{ }} 插值或 DomSanitizer.sanitize() 净化后再绑定",
)


# ===========================================================================
# 3. CWE-78 命令注入（30 条）
# ===========================================================================

add(
    """
@app.route('/nslookup')
def nslookup():
    domain = request.args.get('domain', '')
    output = os.popen('nslookup ' + domain).read()
    return output
""",
    "python", "distill_076.py",
    True, "CWE-78 命令注入", "Critical",
    "request.args.get('domain')", "os.popen('nslookup ' + domain)",
    "request.args.get('domain') → domain → 字符串拼接 → os.popen → shell 执行",
    "使用 subprocess.run(['nslookup', domain]) 列表形式，不使用 shell",
)

add(
    """
@app.route('/convert')
def convert():
    infile = request.args.get('file', '')
    # subprocess.Popen shell=True
    proc = subprocess.Popen(f'convert {infile} output.png', shell=True)
    proc.wait()
    return 'done'
""",
    "python", "distill_077.py",
    True, "CWE-78 命令注入", "Critical",
    "request.args.get('file')", "subprocess.Popen(shell=True)",
    "request.args.get('file') → infile → f-string → Popen(shell=True) → shell 执行",
    "使用参数列表：subprocess.Popen(['convert', infile, 'output.png'])",
)

add(
    """
@app.route('/convert')
def convert():
    infile = request.args.get('file', '')
    proc = subprocess.Popen(['convert', infile, 'output.png'])
    proc.wait()
    return 'done'
""",
    "python", "distill_078.py",
    False, "none", "None",
    "request.args.get('file')", "subprocess.Popen(['convert', infile, ...])",
    "infile 作为列表参数传入，未启用 shell=True，元字符被当作普通字符",
    "no fix needed",
)

add(
    """
const { execSync } = require('child_process');

app.get('/compress', (req, res) => {
    const file = req.query.file;
    const output = execSync(`gzip ${file}`).toString();
    res.send(output);
});
""",
    "javascript", "distill_079.js",
    True, "CWE-78 命令注入", "Critical",
    "req.query.file", "execSync(`gzip ${file}`)",
    "req.query.file → file → 模板字符串 → execSync → shell 执行",
    "使用 execFileSync('gzip', [file]) 不经过 shell",
)

add(
    """
const { execFileSync } = require('child_process');

app.get('/compress', (req, res) => {
    const file = req.query.file;
    const output = execFileSync('gzip', [file]).toString();
    res.send(output);
});
""",
    "javascript", "distill_080.js",
    False, "none", "None",
    "req.query.file", "execFileSync('gzip', [file])",
    "file 作为数组参数传入 execFileSync，不经过 shell",
    "no fix needed",
)

add(
    """
const { spawn } = require('child_process');

app.get('/search', (req, res) => {
    const pattern = req.query.pattern;
    // spawn shell:true
    const child = spawn('grep', [pattern, '/var/log/app.log'], { shell: true });
    let output = '';
    child.stdout.on('data', d => output += d);
    child.on('close', () => res.send(output));
});
""",
    "javascript", "distill_081.js",
    True, "CWE-78 命令注入", "Critical",
    "req.query.pattern", "spawn(..., { shell: true })",
    "req.query.pattern → spawn(shell:true) → shell 解释 pattern",
    "移除 { shell: true }，spawn 默认不经过 shell",
)

add(
    """
const { spawn } = require('child_process');

app.get('/search', (req, res) => {
    const pattern = req.query.pattern;
    const child = spawn('grep', [pattern, '/var/log/app.log']);
    let output = '';
    child.stdout.on('data', d => output += d);
    child.on('close', () => res.send(output));
});
""",
    "javascript", "distill_082.js",
    False, "none", "None",
    "req.query.pattern", "spawn('grep', [pattern, ...])",
    "pattern 作为数组参数传入 spawn，默认不经过 shell",
    "no fix needed",
)

add(
    """
<?php
$ip = $_GET['ip'] ?? '';
$output = shell_exec("ping -c 1 $ip");
echo "<pre>$output</pre>";
""",
    "php", "distill_083.php",
    True, "CWE-78 命令注入", "Critical",
    "$_GET['ip']", "shell_exec(\"ping -c 1 $ip\")",
    "$_GET['ip'] → $ip → 双引号插值 → shell_exec → shell 执行",
    "使用 escapeshellarg 转义参数：$ip = escapeshellarg($ip); 或用 proc_open",
)

add(
    """
<?php
$ip = $_GET['ip'] ?? '';
$safe_ip = escapeshellarg($ip);
$output = shell_exec("ping -c 1 $safe_ip");
echo "<pre>$output</pre>";
""",
    "php", "distill_084.php",
    False, "none", "None",
    "$_GET['ip']", "escapeshellarg($ip) 后传入 shell_exec",
    "$ip 经 escapeshellarg 转义后传入 shell_exec，shell 元字符被引号包裹",
    "no fix needed",
)

add(
    """
<?php
$cmd = $_GET['cmd'] ?? 'ls';
$arg = $_GET['arg'] ?? '';
// system() 拼接
system($cmd . ' ' . $arg);
""",
    "php", "distill_085.php",
    True, "CWE-78 命令注入", "Critical",
    "$_GET['cmd'] / $_GET['arg']", "system($cmd . ' ' . $arg)",
    "cmd 和 arg 都用户可控 → 可执行任意命令 + 注入参数",
    "用白名单限制 cmd，用 escapeshellarg 转义 arg",
)

add(
    """
<?php
$file = $_GET['file'] ?? '';
// passthru 拼接
passthru("file " . $file);
""",
    "php", "distill_086.php",
    True, "CWE-78 命令注入", "Critical",
    "$_GET['file']", "passthru(\"file \" . $file)",
    "$_GET['file'] → 字符串拼接 → passthru → shell 执行",
    "使用 escapeshellarg 转义：passthru(\"file \" . escapeshellarg($file))",
)

add(
    """
<?php
// PHP 反引号运算符
$host = $_GET['host'] ?? '';
$output = `ping -c 1 $host`;
echo $output;
""",
    "php", "distill_087.php",
    True, "CWE-78 命令注入", "Critical",
    "$_GET['host']", "反引号 `ping -c 1 $host`",
    "$_GET['host'] → $host → 反引号插值 → shell 执行",
    "使用 escapeshellarg 转义或用 proc_open 参数化",
)

add(
    """
@RestController
public class ToolsController {
    @GetMapping("/dig")
    public String dig(@RequestParam String host) throws IOException {
        Process p = Runtime.getRuntime().exec("dig " + host);
        String output = new String(p.getInputStream().readAllBytes());
        return output;
    }
}
""",
    "java", "distill_088.java",
    True, "CWE-78 命令注入", "High",
    "@RequestParam host", "Runtime.exec(\"dig \" + host)",
    "@RequestParam host → 字符串拼接 → Runtime.exec → 可能被 shell 元字符注入",
    "使用 exec(String[]) 数组形式或 ProcessBuilder 列表形式",
)

add(
    """
@RestController
public class ToolsController {
    @GetMapping("/dig")
    public String dig(@RequestParam String host) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("dig", host);
        Process p = pb.start();
        return new String(p.getInputStream().readAllBytes());
    }
}
""",
    "java", "distill_089.java",
    False, "none", "None",
    "@RequestParam host", "ProcessBuilder(\"dig\", host)",
    "host 作为 ProcessBuilder 的独立参数传入，不经过 shell",
    "no fix needed",
)

add(
    """
func handler(w http.ResponseWriter, r *http.Request) {
    cmd := r.URL.Query().Get("cmd")
    // exec.Command("sh", "-c", cmd) → shell 执行用户输入
    out, _ := exec.Command("sh", "-c", cmd).Output()
    w.Write(out)
}
""",
    "go", "distill_090.go",
    True, "CWE-78 命令注入", "Critical",
    "r.URL.Query().Get('cmd')", "exec.Command(\"sh\", \"-c\", cmd)",
    "cmd 直接作为 sh -c 的参数 → 任意命令执行",
    "不要用 sh -c 执行用户输入；用 exec.Command(tool, args...) 列表形式 + 白名单",
)

add(
    """
func handler(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    out, err := exec.Command("ping", "-c", "1", host).Output()
    if err != nil {
        http.Error(w, "error", 500)
        return
    }
    w.Write(out)
}
""",
    "go", "distill_091.go",
    False, "none", "None",
    "r.URL.Query().Get('host')", "exec.Command(\"ping\", \"-c\", \"1\", host)",
    "host 作为 exec.Command 的独立参数传入，不经过 shell",
    "no fix needed",
)

add(
    """
#include <stdio.h>
#include <stdlib.h>

void ping_host(const char* host) {
    char cmd[256];
    sprintf(cmd, "ping -c 1 %s", host);
    system(cmd);
}
""",
    "c", "distill_092.c",
    True, "CWE-78 命令注入", "Critical",
    "host 参数", "system(cmd)",
    "host → sprintf 拼接 → system() → shell 执行",
    "使用 execv 系列函数避免 shell；或严格校验 host 为合法 IP/域名",
)

add(
    """
#include <stdio.h>
#include <stdlib.h>

void ping_host(const char* host) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", host);
    FILE* fp = popen(cmd, "r");
    // ...
    pclose(fp);
}
""",
    "c", "distill_093.c",
    True, "CWE-78 命令注入", "Critical",
    "host 参数", "popen(cmd, \"r\")",
    "host → snprintf 拼接 → popen → shell 执行",
    "使用 execv 系列函数避免 shell；或严格校验 host",
)

# --- 命令注入绕过变体 ---

add(
    """
@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    # 过滤 ; | & 但不过滤 $() 和换行
    for c in ';|&':
        host = host.replace(c, '')
    result = subprocess.run(f'ping -c 1 {host}', shell=True, capture_output=True, text=True)
    return result.stdout
""",
    "python", "distill_094.py",
    True, "CWE-78 命令注入", "High",
    "request.args.get('host')", "subprocess.run(shell=True)",
    "黑名单过滤 ;|& 但不过滤 $() 反引号 换行符 → 可绕过注入",
    "使用参数列表 subprocess.run(['ping','-c','1',host]) 不依赖 shell",
)

add(
    """
@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    # shlex.quote 转义，但 shell=True 仍非最佳实践
    result = subprocess.run(f'ping -c 1 {shlex.quote(host)}', shell=True)
    return result.stdout
""",
    "python", "distill_095.py",
    False, "none", "None",
    "request.args.get('host')", "subprocess.run(f'... {shlex.quote(host)} ...', shell=True)",
    "shlex.quote 对 host 做了 shell 转义，单引号包裹，元字符被隔离",
    "no fix needed（但最佳实践是用列表形式完全避免 shell）",
)

add(
    """
@app.route('/traceroute')
def traceroute():
    target = request.args.get('target', '')
    # 管道符注入
    result = os.system(f'traceroute {target} | head -n 5')
    return 'done'
""",
    "python", "distill_096.py",
    True, "CWE-78 命令注入", "Critical",
    "request.args.get('target')", "os.system(f'traceroute {target} | ...')",
    "target 通过 f-string 拼接 → os.system → shell 执行，可注入 ; | $() 等",
    "使用 subprocess.run(['traceroute', target]) 列表形式",
)

add(
    """
# Ruby backtick 命令注入
get '/lookup/:domain' do
  domain = params[:domain]
  `nslookup #{domain}`
end
""",
    "ruby", "distill_097.rb",
    True, "CWE-78 命令注入", "Critical",
    "params[:domain]", "反引号 `nslookup #{domain}`",
    "params[:domain] → Ruby 字符串插值 → 反引号 → shell 执行",
    "使用 Open3.capture3('nslookup', domain) 列表形式",
)

add(
    """
# Ruby system() 注入
get '/ping/:host' do
  host = params[:host]
  system("ping -c 1 #{host}")
  'done'
end
""",
    "ruby", "distill_098.rb",
    True, "CWE-78 命令注入", "Critical",
    "params[:host]", "system(\"ping -c 1 #{host}\")",
    "params[:host] → Ruby 插值 → system() → shell 执行",
    "使用 system('ping', '-c', '1', host) 列表形式",
)

add(
    """
@app.route('/git_log')
def git_log():
    repo = request.args.get('repo', '')
    # git log 命令拼接
    result = subprocess.run(f'git log --oneline {repo}', shell=True, capture_output=True, text=True)
    return result.stdout
""",
    "python", "distill_099.py",
    True, "CWE-78 命令注入", "Critical",
    "request.args.get('repo')", "subprocess.run(f'git log ... {repo}', shell=True)",
    "repo 通过 f-string 拼接到 git log 命令 → shell=True → 命令注入",
    "使用参数列表：subprocess.run(['git', 'log', '--oneline', repo])",
)

add(
    """
@app.route('/curl')
def curl():
    url = request.args.get('url', '')
    # curl 命令拼接，url 可含 shell 元字符
    result = os.system(f'curl -s {url} -o /tmp/out')
    return 'done'
""",
    "python", "distill_100.py",
    True, "CWE-78 命令注入", "Critical",
    "request.args.get('url')", "os.system(f'curl -s {url} ...')",
    "url → f-string 拼接 → os.system → shell 执行",
    "使用 requests 库替代 curl；或 subprocess.run(['curl', '-s', url, '-o', '/tmp/out'])",
)

add(
    """
# Java ProcessBuilder 命令注入
@RestController
public class GitController {
    @GetMapping("/git/log")
    public String gitLog(@RequestParam String repo) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("git log --oneline " + repo);
        Process p = pb.start();
        return new String(p.getInputStream().readAllBytes());
    }
}
""",
    "java", "distill_101.java",
    True, "CWE-78 命令注入", "High",
    "@RequestParam repo", "new ProcessBuilder(\"git log ... \" + repo)",
    "repo → 字符串拼接 → ProcessBuilder 单字符串构造 → 可能被 shell 解析",
    "使用 ProcessBuilder 数组形式：new ProcessBuilder(\"git\", \"log\", \"--oneline\", repo)",
)

add(
    """
# 环境变量注入 + 命令执行
@app.route('/run_tool')
def run_tool():
    tool = request.args.get('tool', 'ls')
    # 用户控制命令名
    result = subprocess.run([tool], capture_output=True, text=True)
    return result.stdout
""",
    "python", "distill_102.py",
    True, "CWE-78 命令注入", "High",
    "request.args.get('tool')", "subprocess.run([tool])",
    "tool 用户可控 → 可执行任意命令（虽列表形式但命令名本身可控）",
    "白名单校验 tool：ALLOWED_TOOLS={'ls','date'}; if tool not in ALLOWED_TOOLS: abort(400)",
)

add(
    """
# 安全：命令白名单 + 参数列表
@app.route('/run_tool')
def run_tool():
    tool = request.args.get('tool', 'ls')
    ALLOWED_TOOLS = {'ls': ['ls', '-la'], 'date': ['date'], 'whoami': ['whoami']}
    if tool not in ALLOWED_TOOLS:
        abort(400)
    result = subprocess.run(ALLOWED_TOOLS[tool], capture_output=True, text=True)
    return result.stdout
""",
    "python", "distill_103.py",
    False, "none", "None",
    "request.args.get('tool')", "subprocess.run(ALLOWED_TOOLS[tool])",
    "tool 经白名单校验后映射到固定命令列表，用户无法注入任意命令",
    "no fix needed",
)

add(
    """
# Java Runtime.exec 数组形式（安全对照）
@RestController
public class ToolsController {
    @GetMapping("/dig")
    public String dig(@RequestParam String host) throws IOException {
        Process p = Runtime.getRuntime().exec(new String[]{"dig", host});
        return new String(p.getInputStream().readAllBytes());
    }
}
""",
    "java", "distill_104.java",
    False, "none", "None",
    "@RequestParam host", "Runtime.exec(new String[]{\"dig\", host})",
    "host 作为 String[] 数组的独立元素传入，不经过 shell",
    "no fix needed",
)

add(
    """
# C 命令注入安全对照：execvp
#include <unistd.h>

void ping_host(const char* host) {
    char* args[] = {"ping", "-c", "1", (char*)host, NULL};
    execvp("ping", args);
}
""",
    "c", "distill_105.c",
    False, "none", "None",
    "host 参数", "execvp(\"ping\", args)",
    "host 作为 execvp 的独立参数传入，不经过 shell",
    "no fix needed",
)


# ===========================================================================
# 4. CWE-22 路径穿越（30 条）
# ===========================================================================

add(
    """
from flask import Flask, request, send_file
import os

app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('file', '')
    filepath = os.path.join('/var/uploads', filename)
    return send_file(filepath)
""",
    "python", "distill_106.py",
    True, "CWE-22 路径穿越", "High",
    "request.args.get('file')", "send_file(filepath)",
    "request.args.get('file') → filename → os.path.join → send_file，可穿越 ../",
    "使用 send_from_directory + safe=True 或校验 abspath 前缀",
)

add(
    """
from flask import Flask, request, send_from_directory

app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('file', '')
    return send_from_directory('/var/uploads', filename)
""",
    "python", "distill_107.py",
    True, "CWE-22 路径穿越", "High",
    "request.args.get('file')", "send_from_directory(directory, filename)",
    "send_from_directory 默认不启用 safe=True（Flask < 2.0），filename 含 ../ 仍可穿越",
    "Flask 2.0+ 使用 safe=True；或手动校验 abspath 前缀",
)

add(
    """
from flask import Flask, request, send_from_directory

app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('file', '')
    return send_from_directory('/var/uploads', filename, safe=True)
""",
    "python", "distill_108.py",
    False, "none", "None",
    "request.args.get('file')", "send_from_directory(..., safe=True)",
    "safe=True 启用路径安全检查，阻止 ../ 穿越",
    "no fix needed",
)

add(
    """
from django.http import FileResponse, Http404
import os

def serve_file(request):
    filename = request.GET.get('file', '')
    filepath = os.path.join('/var/data', filename)
    try:
        return FileResponse(open(filepath, 'rb'))
    except FileNotFoundError:
        raise Http404
""",
    "python", "distill_109.py",
    True, "CWE-22 路径穿越", "High",
    "request.GET.get('file')", "FileResponse(open(filepath))",
    "request.GET.get('file') → filename → os.path.join → open → 路径穿越",
    "校验 abspath 前缀：if not os.path.abspath(filepath).startswith('/var/data/'): raise Http404",
)

add(
    """
from django.http import FileResponse, Http404
import os

def serve_file(request):
    filename = request.GET.get('file', '')
    base = '/var/data'
    filepath = os.path.abspath(os.path.join(base, filename))
    if not filepath.startswith(base + os.sep):
        raise Http404
    return FileResponse(open(filepath, 'rb'))
""",
    "python", "distill_110.py",
    False, "none", "None",
    "request.GET.get('file')", "FileResponse(open(filepath))",
    "abspath 规范化后做前缀校验，阻止 ../ 穿越",
    "no fix needed",
)

add(
    """
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
import os

app = FastAPI()

@app.get('/file')
async def serve_file(request: Request):
    name = request.query_params.get('name', '')
    path = os.path.join('/var/data', name)
    return FileResponse(path)
""",
    "python", "distill_111.py",
    True, "CWE-22 路径穿越", "High",
    "request.query_params.get('name')", "FileResponse(path)",
    "name → os.path.join → FileResponse，可穿越 ../",
    "校验 abspath 前缀或使用 Path.resolve() + is_relative_to()",
)

add(
    """
# pathlib 安全校验
from pathlib import Path

@app.get('/file')
async def serve_file(request: Request):
    name = request.query_params.get('name', '')
    base = Path('/var/data').resolve()
    target = (base / name).resolve()
    if not target.is_relative_to(base):
        raise HTTPException(403)
    return FileResponse(str(target))
""",
    "python", "distill_112.py",
    False, "none", "None",
    "request.query_params.get('name')", "FileResponse(str(target))",
    "resolve() 规范化路径后 is_relative_to() 校验是否在 base 目录内",
    "no fix needed",
)

add(
    """
<?php
$file = $_GET['file'] ?? '';
$path = '/var/data/' . $file;
echo file_get_contents($path);
""",
    "php", "distill_113.php",
    True, "CWE-22 路径穿越", "High",
    "$_GET['file']", "file_get_contents($path)",
    "$_GET['file'] → $file → 字符串拼接 → file_get_contents → 路径穿越",
    "使用 realpath + basename 校验：$real = realpath($path); if ($real === false || strpos($real, '/var/data/') !== 0) die('403');",
)

add(
    """
<?php
$file = $_GET['file'] ?? '';
$base = '/var/data';
$real = realpath($base . '/' . $file);
if ($real === false || strpos($real, $base . '/') !== 0) {
    http_response_code(403);
    die('forbidden');
}
echo file_get_contents($real);
""",
    "php", "distill_114.php",
    False, "none", "None",
    "$_GET['file']", "file_get_contents($real)",
    "realpath 规范化后做前缀校验，阻止路径穿越",
    "no fix needed",
)

add(
    """
<?php
$page = $_GET['page'] ?? 'home';
// PHP 文件包含路径穿越
include('/var/www/templates/' . $page . '.php');
""",
    "php", "distill_115.php",
    True, "CWE-22 路径穿越", "High",
    "$_GET['page']", "include(拼接路径)",
    "$_GET['page'] → $page → 字符串拼接 → include → 路径穿越 + LFI",
    "白名单校验 page：$ALLOWED = ['home','about','contact']; if (!in_array($page, $ALLOWED)) die('403');",
)

add(
    """
const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

app.get('/file', (req, res) => {
    const name = req.query.name;
    const filepath = path.join('/var/data', name);
    const content = fs.readFileSync(filepath, 'utf-8');
    res.send(content);
});
""",
    "javascript", "distill_116.js",
    True, "CWE-22 路径穿越", "High",
    "req.query.name", "fs.readFileSync(filepath)",
    "req.query.name → path.join → fs.readFileSync → 路径穿越",
    "使用 path.resolve + startsWith 校验：const real = path.resolve(filepath); if (!real.startsWith('/var/data/')) return res.status(403).send('forbidden');",
)

add(
    """
const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

app.get('/file', (req, res) => {
    const name = req.query.name;
    const base = '/var/data';
    const filepath = path.resolve(base, name);
    if (!filepath.startsWith(base + path.sep)) {
        return res.status(403).send('forbidden');
    }
    const content = fs.readFileSync(filepath, 'utf-8');
    res.send(content);
});
""",
    "javascript", "distill_117.js",
    False, "none", "None",
    "req.query.name", "fs.readFileSync(filepath)",
    "path.resolve 规范化后 startsWith 校验，阻止路径穿越",
    "no fix needed",
)

add(
    """
import java.io.*;
import java.nio.file.*;

@RestController
public class FileController {
    @GetMapping("/file")
    public byte[] getFile(@RequestParam String name) throws IOException {
        Path path = Paths.get("/var/data", name);
        return Files.readAllBytes(path);
    }
}
""",
    "java", "distill_118.java",
    True, "CWE-22 路径穿越", "High",
    "@RequestParam name", "Files.readAllBytes(path)",
    "name → Paths.get 拼接 → Files.readAllBytes → 路径穿越",
    "使用 path.toAbsolutePath().normalize() + startsWith 校验",
)

add(
    """
import java.io.*;
import java.nio.file.*;

@RestController
public class FileController {
    @GetMapping("/file")
    public byte[] getFile(@RequestParam String name) throws IOException {
        Path base = Paths.get("/var/data").toAbsolutePath().normalize();
        Path path = base.resolve(name).normalize();
        if (!path.startsWith(base)) {
            throw new AccessDeniedException("path traversal");
        }
        return Files.readAllBytes(path);
    }
}
""",
    "java", "distill_119.java",
    False, "none", "None",
    "@RequestParam name", "Files.readAllBytes(path)",
    "normalize() 规范化后 startsWith(base) 校验，阻止路径穿越",
    "no fix needed",
)

add(
    """
func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("file")
    path := filepath.Join("/var/data", name)
    data, _ := os.ReadFile(path)
    w.Write(data)
}
""",
    "go", "distill_120.go",
    True, "CWE-22 路径穿越", "High",
    "r.URL.Query().Get('file')", "os.ReadFile(path)",
    "file → filepath.Join → os.ReadFile → 路径穿越",
    "使用 filepath.Clean + strings.HasPrefix 校验",
)

add(
    """
func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("file")
    base := "/var/data"
    full := filepath.Join(base, name)
    clean := filepath.Clean(full)
    if !strings.HasPrefix(clean, base+string(filepath.Separator)) {
        http.Error(w, "forbidden", 403)
        return
    }
    data, _ := os.ReadFile(clean)
    w.Write(data)
}
""",
    "go", "distill_121.go",
    False, "none", "None",
    "r.URL.Query().Get('file')", "os.ReadFile(clean)",
    "filepath.Clean 规范化后 HasPrefix 校验，阻止路径穿越",
    "no fix needed",
)

add(
    """
#include <stdio.h>
#include <string.h>

void read_config(const char* name) {
    char path[512];
    snprintf(path, sizeof(path), "/etc/app/%s", name);
    FILE* fp = fopen(path, "r");
    if (fp) {
        char buf[1024];
        while (fgets(buf, sizeof(buf), fp)) printf("%s", buf);
        fclose(fp);
    }
}
""",
    "c", "distill_122.c",
    True, "CWE-22 路径穿越", "High",
    "name 参数", "fopen(path)",
    "name → snprintf 拼接 → fopen → 路径穿越",
    "校验 name 不含 ../ 或使用 realpath + 前缀校验",
)

# --- 路径穿越绕过变体 ---

add(
    """
@app.route('/file')
def get_file():
    name = request.args.get('name', '')
    # 过滤 ../ 但不过滤 ....// （规范化后仍为 ../）
    name = name.replace('../', '')
    path = os.path.join('/var/data', name)
    return open(path).read()
""",
    "python", "distill_123.py",
    True, "CWE-22 路径穿越", "High",
    "request.args.get('name')", "open(path)",
    "replace('../','') 可被 ....// 绕过（replace 后剩余 ../）",
    "在 os.path.abspath 规范化后做前缀校验",
)

add(
    """
@app.route('/file')
def get_file():
    name = request.args.get('name', '')
    # URL 双重编码绕过：%252e%252e%252f → 解码一次为 %2e%2e%2f → 再次解码为 ../
    # 如果 Web 服务器做了两次解码，字面量过滤失效
    if '../' in name:
        abort(403)
    path = os.path.join('/var/data', name)
    return open(path).read()
""",
    "python", "distill_124.py",
    True, "CWE-22 路径穿越", "High",
    "request.args.get('name')", "open(path)",
    "字面量过滤 ../ 可被双重 URL 编码绕过",
    "在 os.path.abspath 规范化后做前缀校验",
)

add(
    """
@app.route('/file')
def get_file():
    name = request.args.get('name', '')
    # Windows UNC 路径：\\\\\\\\attacker\\\\share 可访问网络资源
    path = os.path.join('C:\\\\data', name)
    with open(path) as f:
        return f.read()
""",
    "python", "distill_125.py",
    True, "CWE-22 路径穿越", "High",
    "request.args.get('name')", "open(path)",
    "Windows UNC 路径 \\\\attacker\\share 可被用于访问网络资源或绕过本地路径限制",
    "校验 abspath 不含 UNC 前缀；在 Windows 上使用 os.path.normpath + 前缀校验",
)

add(
    """
# Zip Slip 路径穿越（解压时）
import zipfile

@app.route('/extract', methods=['POST'])
def extract():
    zf = zipfile.ZipFile(request.files['file'])
    for member in zf.namelist():
        # 成员名可能含 ../../../
        zf.extract(member, '/var/uploads')
    return 'extracted'
""",
    "python", "distill_126.py",
    True, "CWE-22 路径穿越(Zip Slip)", "High",
    "zip 文件成员名 namelist()", "zf.extract(member, dest)",
    "zip 成员名含 ../../../ → extract 时穿越目录",
    "校验每个成员的 abspath 前缀：if not os.path.abspath(os.path.join(dest, member)).startswith(dest_abs + os.sep): skip",
)

add(
    """
# Zip Slip 安全解压
import zipfile
import os

@app.route('/extract', methods=['POST'])
def extract():
    zf = zipfile.ZipFile(request.files['file'])
    dest = '/var/uploads'
    dest_abs = os.path.abspath(dest)
    for member in zf.namelist():
        target = os.path.abspath(os.path.join(dest, member))
        if not target.startswith(dest_abs + os.sep):
            abort(403)
        zf.extract(member, dest)
    return 'extracted'
""",
    "python", "distill_127.py",
    False, "none", "None",
    "zip 文件成员名", "zf.extract(member, dest)",
    "每个成员的 abspath 经前缀校验后解压，阻止 Zip Slip",
    "no fix needed",
)

add(
    """
# tarfile 路径穿越
import tarfile

@app.route('/extract_tar', methods=['POST'])
def extract_tar():
    tf = tarfile.open(fileobj=request.files['file'])
    tf.extractall('/var/uploads')  # 不校验成员路径
    return 'extracted'
""",
    "python", "distill_128.py",
    True, "CWE-22 路径穿越(tar)", "High",
    "tar 文件成员名", "tf.extractall(dest)",
    "tar 成员名含 ../../../etc/passwd → 解压穿越目录",
    "使用 Python 3.12+ 的 extractall(filter='data') 或手动校验每个成员路径",
)

add(
    """
# tarfile 安全解压
import tarfile
import os

@app.route('/extract_tar', methods=['POST'])
def extract_tar():
    dest = '/var/uploads'
    dest_abs = os.path.abspath(dest)
    tf = tarfile.open(fileobj=request.files['file'])
    for member in tf.getmembers():
        target = os.path.abspath(os.path.join(dest, member.name))
        if not target.startswith(dest_abs + os.sep):
            abort(403)
    tf.extractall(dest)
    return 'extracted'
""",
    "python", "distill_129.py",
    False, "none", "None",
    "tar 文件成员名", "tf.extractall(dest)",
    "每个成员路径经前缀校验后解压，阻止路径穿越",
    "no fix needed",
)

add(
    """
# PHP 文件包含 Null Byte 截断绕过（PHP < 5.3.4）
<?php
$page = $_GET['page'] ?? 'home';
// 传入 page=../../etc/passwd%00 可截断 .php 后缀
include('/var/www/templates/' . $page . '.php');
""",
    "php", "distill_130.php",
    True, "CWE-22 路径穿越(Null Byte)", "Critical",
    "$_GET['page']（含 %00 null byte）", "include(拼接路径)",
    "Null Byte 截断 .php 后缀 → 包含任意文件（PHP < 5.3.4）",
    "升级 PHP 5.3.4+；白名单校验 page；使用 basename() 过滤路径分隔符",
)

add(
    """
# PHP 文件包含安全：白名单
<?php
$ALLOWED_PAGES = ['home', 'about', 'contact', 'help'];
$page = $_GET['page'] ?? 'home';
if (!in_array($page, $ALLOWED_PAGES, true)) {
    http_response_code(403);
    die('invalid page');
}
include('/var/www/templates/' . $page . '.php');
""",
    "php", "distill_131.php",
    False, "none", "None",
    "$_GET['page']", "include(白名单校验后路径)",
    "page 经白名单严格校验后才拼接路径",
    "no fix needed",
)

add(
    """
# Path Traversal via Symlink
import os

@app.route('/file')
def get_file():
    name = request.args.get('name', '')
    base = '/var/data'
    path = os.path.join(base, name)
    # 仅检查字面量前缀，不检查 symlink 目标
    if not path.startswith(base):
        abort(403)
    return open(path).read()
""",
    "python", "distill_132.py",
    True, "CWE-22 路径穿越(Symlink)", "High",
    "request.args.get('name')", "open(path)",
    "字面量前缀校验不检查 symlink 目标 → 攻击者可创建指向 /etc/passwd 的 symlink",
    "使用 os.path.realpath 解析 symlink 后再做前缀校验",
)

add(
    """
# Path Traversal via Symlink 安全校验
import os

@app.route('/file')
def get_file():
    name = request.args.get('name', '')
    base = '/var/data'
    base_abs = os.path.realpath(base)
    path = os.path.realpath(os.path.join(base, name))
    if not path.startswith(base_abs + os.sep):
        abort(403)
    return open(path).read()
""",
    "python", "distill_133.py",
    False, "none", "None",
    "request.args.get('name')", "open(path)",
    "realpath 解析 symlink 后做前缀校验，阻止 symlink 穿越",
    "no fix needed",
)

add(
    """
# C 缓冲区溢出 + 路径穿越
#include <stdio.h>
#include <string.h>

void read_file(const char* name) {
    char path[64];
    // name 过长导致缓冲区溢出 + 路径穿越
    sprintf(path, "/var/data/%s", name);
    FILE* fp = fopen(path, "r");
    // ...
}
""",
    "c", "distill_134.c",
    True, "CWE-22 路径穿越", "High",
    "name 参数", "fopen(path)",
    "name → sprintf 拼接（无长度限制）→ 缓冲区溢出 + 路径穿越",
    "使用 snprintf 限制长度；校验 name 不含 ../ 且长度合理",
)

add(
    """
# 文件下载 send_file 路径穿越
from flask import Flask, request, send_file
import os

app = Flask(__name__)

@app.route('/avatar')
def avatar():
    uid = request.args.get('uid', '')
    filename = f'{uid}.png'
    filepath = os.path.join('/var/avatars', filename)
    return send_file(filepath)
""",
    "python", "distill_135.py",
    True, "CWE-22 路径穿越", "High",
    "request.args.get('uid')", "send_file(filepath)",
    "uid → f-string → os.path.join → send_file，uid 含 ../../../ 可穿越",
    "校验 uid 为纯数字：if not uid.isdigit(): abort(400)",
)


# ===========================================================================
# 5. CWE-502 不安全反序列化（15 条）
# ===========================================================================

add(
    """
import shelve
from flask import request

@app.route('/cache')
def cache():
    key = request.args.get('key', '')
    with shelve.open('cache.db') as db:
        # shelve 底层使用 pickle，不安全
        value = db.get(key)
    return str(value)
""",
    "python", "distill_136.py",
    True, "CWE-502 不安全反序列化", "Critical",
    "shelve 底层 pickle", "shelve.open().get(key)",
    "shelve 底层使用 pickle 反序列化 → 数据库内容被篡改时可触发 __reduce__ RCE",
    "不要用 shelve 存储不可信数据；改用 json + 键值存储",
)

add(
    """
import marshal
from flask import request

@app.route('/load')
def load_data():
    raw = request.get_data()
    # marshal 反序列化不安全
    data = marshal.loads(raw)
    return str(data)
""",
    "python", "distill_137.py",
    True, "CWE-502 不安全反序列化", "Critical",
    "request.get_data()", "marshal.loads(raw)",
    "request.get_data() → raw → marshal.loads → 可执行任意代码",
    "不要用 marshal 反序列化不可信数据；改用 json.loads",
)

add(
    """
# Jackson 多态反序列化
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
public class ApiController {
    private ObjectMapper mapper = new ObjectMapper();
    
    @PostMapping("/api/object")
    public Object handle(@RequestBody String body) throws Exception {
        // 启用默认类型解析 → 允许任意类反序列化
        mapper.enableDefaultTyping();
        return mapper.readValue(body, Object.class);
    }
}
""",
    "java", "distill_138.java",
    True, "CWE-502 不安全反序列化", "Critical",
    "@RequestBody body", "mapper.readValue(body, Object.class)",
    "enableDefaultTyping 允许 @type 指定任意类 → gadget chain RCE",
    "禁用默认类型解析：mapper.disableDefaultTyping()；或使用 activateDefaultTyping(LaissezFaireSubTypeValidator.instance) 限制",
)

add(
    """
# Jackson 安全反序列化
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
public class ApiController {
    private ObjectMapper mapper = new ObjectMapper();
    
    @PostMapping("/api/object")
    public Object handle(@RequestBody String body) throws Exception {
        // 不启用 default typing，仅反序列化为 Map
        return mapper.readValue(body, Map.class);
    }
}
""",
    "java", "distill_139.java",
    False, "none", "None",
    "@RequestBody body", "mapper.readValue(body, Map.class)",
    "Jackson 不启用 default typing 时，readValue 到 Map.class 不会触发多态反序列化",
    "no fix needed",
)

add(
    """
# SnakeYAML 不安全反序列化
import org.yaml.snakeyaml.Yaml;

@RestController
public class ConfigController {
    @PostMapping("/config")
    public Object loadConfig(@RequestBody String body) {
        Yaml yaml = new Yaml();
        // SnakeYAML 会构造任意 Java 对象
        return yaml.load(body);
    }
}
""",
    "java", "distill_140.java",
    True, "CWE-502 不安全反序列化", "Critical",
    "@RequestBody body", "yaml.load(body)",
    "yaml.load 会构造 !!javax.script.ScriptEngine 等任意对象 → RCE",
    "使用 SafeConstructor：new Yaml(new SafeConstructor()) 或 yaml.loadAs(body, Map.class)",
)

add(
    """
# SnakeYAML 安全反序列化
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

@RestController
public class ConfigController {
    @PostMapping("/config")
    public Object loadConfig(@RequestBody String body) {
        Yaml yaml = new Yaml(new SafeConstructor());
        return yaml.load(body);
    }
}
""",
    "java", "distill_141.java",
    False, "none", "None",
    "@RequestBody body", "yaml.load(body)（SafeConstructor）",
    "SafeConstructor 限制只能构造基本类型（Map/List/String/Number），不构造任意 Java 对象",
    "no fix needed",
)

add(
    """
// Node.js node-serialize 不安全反序列化
const serialize = require('node-serialize');

app.post('/session', (req, res) => {
    const data = req.body.data;
    // unserialize 会执行 IIFE 中的代码
    const obj = serialize.unserialize(data);
    res.json(obj);
});
""",
    "javascript", "distill_142.js",
    True, "CWE-502 不安全反序列化", "Critical",
    "req.body.data", "serialize.unserialize(data)",
    "node-serialize.unserialize 会执行 _$$ND_FUNC$$_ 前缀的函数体 → RCE",
    "不要使用 node-serialize 反序列化不可信数据；改用 JSON.parse",
)

add(
    """
// PHP unserialize 不安全（不同场景）
<?php
class Logger {
    public $file;
    public $content;
    function __destruct() {
        file_put_contents($this->file, $this->content);
    }
}
$data = $_COOKIE['session'];
$obj = unserialize($data);
""",
    "php", "distill_143.php",
    True, "CWE-502 不安全反序列化", "Critical",
    "$_COOKIE['session']", "unserialize($data)",
    "cookie → unserialize → __destruct 写入任意文件 → webshell",
    "禁止 unserialize 不可信数据；改用 json_decode + schema 校验",
)

add(
    """
// PHP json_decode 安全对照
<?php
$data = $_COOKIE['session'];
$obj = json_decode($data, true);
if ($obj === null || !isset($obj['user_id'])) {
    http_response_code(403);
    die('invalid session');
}
echo $obj['user_id'];
""",
    "php", "distill_144.php",
    False, "none", "None",
    "$_COOKIE['session']", "json_decode($data)",
    "json_decode 仅解析 JSON 字面量，不构造 PHP 对象，不触发魔术方法",
    "no fix needed",
)

add(
    """
# Python pickle RestrictedPickler 绕过
import pickle
import io

class RestrictedUnpickler(pickle.Unpickler):
    SAFE_CLASSES = {'builtins.dict': dict, 'builtins.list': list}
    
    def find_class(self, module, name):
        if f'{module}.{name}' in self.SAFE_CLASSES:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f'forbidden: {module}.{name}')

@app.route('/load')
def load():
    raw = request.get_data()
    # RestrictedPickler 看似安全，但若白名单含 os.system 等则仍危险
    obj = RestrictedUnpickler(io.BytesIO(raw)).load()
    return str(obj)
""",
    "python", "distill_145.py",
    False, "none", "None",
    "request.get_data()", "RestrictedUnpickler(raw).load()",
    "RestrictedUnpickler 限制 find_class 仅允许白名单类，阻止 __reduce__ RCE",
    "no fix needed（但仍建议改用 json.loads）",
)

add(
    """
# Java XMLDecoder 反序列化
import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;

@RestController
public class XmlController {
    @PostMapping(value = "/xml", consumes = "application/xml")
    public void handle(@RequestBody byte[] body) {
        XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(body));
        Object obj = decoder.readObject();
        decoder.close();
    }
}
""",
    "java", "distill_146.java",
    True, "CWE-502 不安全反序列化", "Critical",
    "@RequestBody body", "XMLDecoder.readObject()",
    "XMLDecoder 可反序列化任意 Java 对象 → 通过 <object> 标签触发 Runtime.exec",
    "不要使用 XMLDecoder 处理不可信数据；改用 JAXB + 白名单",
)

add(
    """
# Python yaml.safe_load 安全对照
import yaml
from flask import request

@app.route('/config')
def load_config():
    body = request.get_data()
    config = yaml.safe_load(body)
    return jsonify(config)
""",
    "python", "distill_147.py",
    False, "none", "None",
    "request.get_data()", "yaml.safe_load(body)",
    "yaml.safe_load 仅解析 YAML 字面量（dict/list/str/int），不构造 Python 对象",
    "no fix needed",
)

add(
    """
# Java ObjectInputStream 白名单过滤
import java.io.*;

@RestController
public class DeserializeController {
    @PostMapping("/deserialize")
    public Object handle(@RequestBody byte[] body) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(body));
        // 设置白名单过滤器（Java 9+）
        ois.setObjectInputFilter(info -> {
            if (info.serialClass() != null && 
                info.serialClass().getName().startsWith("com.myapp.")) {
                return ObjectInputFilter.Status.ALLOWED;
            }
            return ObjectInputFilter.Status.REJECTED;
        });
        return ois.readObject();
    }
}
""",
    "java", "distill_148.java",
    False, "none", "None",
    "@RequestBody body", "ois.readObject()（白名单过滤）",
    "ObjectInputFilter 限制仅允许 com.myapp 包下的类反序列化",
    "no fix needed（但最佳实践是完全避免 Java 原生序列化）",
)

add(
    """
# Python PyYAML 全量加载不安全
import yaml
from flask import request

@app.route('/config')
def load_config():
    body = request.get_data()
    # yaml.unsafe_load 会构造任意 Python 对象
    config = yaml.unsafe_load(body)
    return jsonify(config)
""",
    "python", "distill_149.py",
    True, "CWE-502 不安全反序列化", "Critical",
    "request.get_data()", "yaml.unsafe_load(body)",
    "yaml.unsafe_load 会构造 !!python/object/apply 等标签 → 任意代码执行",
    "使用 yaml.safe_load(body) 替代 yaml.unsafe_load",
)

add(
    """
# .NET BinaryFormatter 不安全反序列化（C# 伪代码风格）
// [HttpPost]
// public IActionResult Deserialize(byte[] body) {
//     var formatter = new BinaryFormatter();
//     var obj = formatter.Deserialize(new MemoryStream(body));
//     return Ok(obj);
// }
# 用 Python 模拟同样模式
import pickle
from flask import request

@app.route('/binary')
def binary():
    body = request.get_data()
    # 等价于 .NET BinaryFormatter，反序列化不可信数据
    obj = pickle.loads(body)
    return str(obj)
""",
    "python", "distill_150.py",
    True, "CWE-502 不安全反序列化", "Critical",
    "request.get_data()", "pickle.loads(body)",
    "request.get_data() → body → pickle.loads → __reduce__ RCE",
    "禁止 pickle 反序列化不可信数据；改用 json.loads + schema 校验",
)


# ===========================================================================
# 6. CWE-611 XXE（14 条）
# ===========================================================================

add(
    """
from xml.dom import minidom
from flask import request

@app.route('/parse')
def parse_xml():
    body = request.get_data()
    # minidom 默认解析外部实体
    doc = minidom.parseString(body)
    return doc.documentElement.tagName
""",
    "python", "distill_151.py",
    True, "CWE-611 XXE", "High",
    "request.get_data()", "minidom.parseString(body)",
    "request.get_data() → body → minidom.parseString（默认解析外部实体）→ XXE",
    "使用 defusedxml：from defusedxml.minidom import parseString",
)

add(
    """
from xml.sax import parseString
from xml.sax.handler import ContentHandler
from flask import request

class MyHandler(ContentHandler):
    pass

@app.route('/parse')
def parse_xml():
    body = request.get_data()
    # sax parseString 默认解析外部实体
    parseString(body, MyHandler())
    return 'parsed'
""",
    "python", "distill_152.py",
    True, "CWE-611 XXE", "High",
    "request.get_data()", "xml.sax.parseString(body)",
    "request.get_data() → body → sax.parseString（默认解析外部实体）→ XXE",
    "使用 defusedxml：from defusedxml.sax import parseString",
)

add(
    """
from defusedxml.minidom import parseString
from flask import request

@app.route('/parse')
def parse_xml():
    body = request.get_data()
    doc = parseString(body)
    return doc.documentElement.tagName
""",
    "python", "distill_153.py",
    False, "none", "None",
    "request.get_data()", "defusedxml.minidom.parseString(body)",
    "defusedxml 禁用外部实体解析，阻止 XXE",
    "no fix needed",
)

add(
    """
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.w3c.dom.Document;
import java.io.ByteArrayInputStream;

@RestController
public class XmlController {
    @PostMapping("/parse")
    public String parse(@RequestBody byte[] body) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(body));
        return doc.getDocumentElement().getTagName();
    }
}
""",
    "java", "distill_154.java",
    True, "CWE-611 XXE", "High",
    "@RequestBody body", "builder.parse(body)",
    "DocumentBuilderFactory 默认解析外部实体 → XXE",
    "禁用 DTD 和外部实体：factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);",
)

add(
    """
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;

@RestController
public class XmlController {
    @PostMapping("/parse")
    public String parse(@RequestBody byte[] body) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // 禁用 DTD
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(body)).getDocumentElement().getTagName();
    }
}
""",
    "java", "distill_155.java",
    False, "none", "None",
    "@RequestBody body", "builder.parse(body)（禁用 DTD）",
    "DocumentBuilderFactory 禁用 DTD 和外部实体后，阻止 XXE",
    "no fix needed",
)

add(
    """
import javax.xml.parsers.SAXParserFactory;
import javax.xml.parsers.SAXParser;
import org.xml.sax.helpers.DefaultHandler;

@RestController
public class SaxController {
    @PostMapping("/parse")
    public void parse(@RequestBody byte[] body) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser parser = factory.newSAXParser();
        parser.parse(new ByteArrayInputStream(body), new DefaultHandler());
    }
}
""",
    "java", "distill_156.java",
    True, "CWE-611 XXE", "High",
    "@RequestBody body", "parser.parse(body, handler)",
    "SAXParserFactory 默认解析外部实体 → XXE",
    "禁用外部实体：factory.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);",
)

add(
    """
<?php
$xml = file_get_contents('php://input');
$doc = new DOMDocument();
$doc->loadXML($xml);
echo $doc->getElementsByTagName('title')->item(0)->nodeValue;
""",
    "php", "distill_157.php",
    True, "CWE-611 XXE", "High",
    "php://input", "$doc->loadXML($xml)",
    "DOMDocument 默认解析外部实体 → XXE",
    "禁用外部实体加载：libxml_disable_entity_loader(true); 或在 loadXML 前设置 LIBXML_NOENT",
)

add(
    """
<?php
libxml_disable_entity_loader(true);
$xml = file_get_contents('php://input');
$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NONET | LIBXML_DTDLOAD);
echo $doc->getElementsByTagName('title')->item(0)->nodeValue;
""",
    "php", "distill_158.php",
    False, "none", "None",
    "php://input", "$doc->loadXML($xml, LIBXML_NONET)",
    "libxml_disable_entity_loader(true) 禁用外部实体加载",
    "no fix needed",
)

add(
    """
<?php
$xml = file_get_contents('php://input');
// simplexml_load_string 默认解析外部实体
$data = simplexml_load_string($xml);
echo $data->title;
""",
    "php", "distill_159.php",
    True, "CWE-611 XXE", "High",
    "php://input", "simplexml_load_string($xml)",
    "simplexml_load_string 默认解析外部实体 → XXE",
    "libxml_disable_entity_loader(true); 或 simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET);",
)

add(
    """
# Python lxml 不安全
from lxml import etree
from flask import request

@app.route('/parse')
def parse_xml():
    body = request.get_data()
    # lxml 默认解析外部实体（resolve_entities=True）
    tree = etree.fromstring(body)
    return etree.tostring(tree)
""",
    "python", "distill_160.py",
    True, "CWE-611 XXE", "High",
    "request.get_data()", "etree.fromstring(body)",
    "lxml etree.fromstring 默认 resolve_entities=True → XXE",
    "创建安全 parser：parser = etree.XMLParser(resolve_entities=False, no_network=True); tree = etree.fromstring(body, parser)",
)

add(
    """
# Python lxml 安全
from lxml import etree
from flask import request

@app.route('/parse')
def parse_xml():
    body = request.get_data()
    parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False)
    tree = etree.fromstring(body, parser)
    return etree.tostring(tree)
""",
    "python", "distill_161.py",
    False, "none", "None",
    "request.get_data()", "etree.fromstring(body, parser)",
    "XMLParser(resolve_entities=False, no_network=True) 禁用外部实体和网络访问",
    "no fix needed",
)

add(
    """
# XXE 参数实体绕过
# 攻击 payload: <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
from xml.etree import ElementTree as ET
from flask import request

@app.route('/parse')
def parse_xml():
    body = request.get_data()
    # ET.fromstring 虽然不解析一般外部实体，但可能解析参数实体
    root = ET.fromstring(body)
    return ET.tostring(root)
""",
    "python", "distill_162.py",
    True, "CWE-611 XXE", "Medium",
    "request.get_data()", "ET.fromstring(body)",
    "ET.fromstring 可能解析参数实体 → 信息泄露/SSRF",
    "使用 defusedxml：from defusedxml.ElementTree import fromstring",
)

add(
    """
# Java StAX XXE
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import java.io.ByteArrayInputStream;

@RestController
public class StaxController {
    @PostMapping("/parse")
    public void parse(@RequestBody byte[] body) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newFactory();
        XMLStreamReader reader = factory.createXMLStreamReader(new ByteArrayInputStream(body));
        while (reader.hasNext()) reader.next();
    }
}
""",
    "java", "distill_163.java",
    True, "CWE-611 XXE", "High",
    "@RequestBody body", "factory.createXMLStreamReader(body)",
    "XMLInputFactory 默认 IS_SUPPORTING_EXTERNAL_ENTITIES=true → XXE",
    "factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false); factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);",
)

add(
    """
# Java StAX 安全
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import java.io.ByteArrayInputStream;

@RestController
public class StaxController {
    @PostMapping("/parse")
    public void parse(@RequestBody byte[] body) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newFactory();
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader reader = factory.createXMLStreamReader(new ByteArrayInputStream(body));
        while (reader.hasNext()) reader.next();
    }
}
""",
    "java", "distill_164.java",
    False, "none", "None",
    "@RequestBody body", "factory.createXMLStreamReader(body)（禁用实体）",
    "XMLInputFactory 禁用外部实体和 DTD → 阻止 XXE",
    "no fix needed",
)


# ===========================================================================
# 7. CWE-94 代码注入（18 条）
# ===========================================================================

add(
    """
@app.route('/exec')
def exec_code():
    code = request.args.get('code', '')
    # exec 执行用户输入
    exec(code)
    return 'done'
""",
    "python", "distill_165.py",
    True, "CWE-94 代码注入", "Critical",
    "request.args.get('code')", "exec(code)",
    "request.args.get('code') → code → exec(code) → 任意代码执行",
    "禁用 exec；如需执行表达式用 ast.literal_eval（仅字面量）",
)

add(
    """
@app.route('/compile')
def compile_code():
    code = request.args.get('code', '')
    # compile + exec
    compiled = compile(code, '<string>', 'exec')
    exec(compiled)
    return 'done'
""",
    "python", "distill_166.py",
    True, "CWE-94 代码注入", "Critical",
    "request.args.get('code')", "exec(compile(code))",
    "request.args.get('code') → compile → exec → 任意代码执行",
    "禁用 compile + exec；改用安全解析器",
)

add(
    """
import importlib
@app.route('/import')
def import_module():
    mod_name = request.args.get('module', '')
    # 动态导入用户指定模块
    mod = importlib.import_module(mod_name)
    return str(mod)
""",
    "python", "distill_167.py",
    True, "CWE-94 代码注入", "High",
    "request.args.get('module')", "importlib.import_module(mod_name)",
    "用户可控模块名 → 可导入任意模块（os/sys/subprocess）→ 代码执行",
    "白名单校验模块名：ALLOWED_MODULES = {'math','json'}; if mod_name not in ALLOWED_MODULES: abort(400)",
)

add(
    """
import importlib
ALLOWED_MODULES = {'math', 'json', 'datetime'}

@app.route('/import')
def import_module():
    mod_name = request.args.get('module', '')
    if mod_name not in ALLOWED_MODULES:
        abort(400)
    mod = importlib.import_module(mod_name)
    return str(mod)
""",
    "python", "distill_168.py",
    False, "none", "None",
    "request.args.get('module')", "importlib.import_module(mod_name)（白名单）",
    "module 经白名单校验后才导入，阻止导入危险模块",
    "no fix needed",
)

add(
    """
<?php
$code = $_GET['code'] ?? '';
// PHP eval
eval($code);
""",
    "php", "distill_169.php",
    True, "CWE-94 代码注入", "Critical",
    "$_GET['code']", "eval($code)",
    "$_GET['code'] → eval → 任意 PHP 代码执行",
    "禁用 eval；改用安全的模板引擎或表达式解析器",
)

add(
    """
<?php
$assertion = $_GET['assert'] ?? '';
// PHP assert 在 PHP 7 前可执行代码
assert($assertion);
""",
    "php", "distill_170.php",
    True, "CWE-94 代码注入", "Critical",
    "$_GET['assert']", "assert($assertion)",
    "$_GET['assert'] → assert → 在 PHP 7 前相当于 eval → 代码执行",
    "禁用 assert 执行用户输入；PHP 7+ 使用 assert($condition) 仅做断言",
)

add(
    """
<?php
$expr = $_GET['expr'] ?? '';
// create_function 已废弃，等价于 eval
$fn = create_function('$x', "return $expr;");
echo $fn(42);
""",
    "php", "distill_171.php",
    True, "CWE-94 代码注入", "Critical",
    "$_GET['expr']", "create_function",
    "$_GET['expr'] → create_function → 任意代码执行",
    "使用匿名函数替代：$fn = function($x) use ($expr) { return /* safe eval */; };",
)

add(
    """
<?php
$pattern = $_GET['pattern'] ?? '';
$subject = 'hello world';
// preg_replace /e 修饰符执行代码（PHP < 7.0）
$result = preg_replace('/' . $pattern . '/e', 'strtoupper("\\\\1")', $subject);
echo $result;
""",
    "php", "distill_172.php",
    True, "CWE-94 代码注入", "Critical",
    "$_GET['pattern']", "preg_replace('/.../e')",
    "preg_replace /e 修饰符将替换字符串作为 PHP 代码执行 → 代码注入",
    "PHP 7.0+ 移除了 /e 修饰符；使用 preg_replace_callback 替代",
)

add(
    """
app.get('/eval', (req, res) => {
    const expr = req.query.expr;
    // JS eval
    const result = eval(expr);
    res.send(String(result));
});
""",
    "javascript", "distill_173.js",
    True, "CWE-94 代码注入", "Critical",
    "req.query.expr", "eval(expr)",
    "req.query.expr → eval → 任意 JS 代码执行",
    "禁用 eval；改用 JSON.parse 或安全表达式解析器",
)

add(
    """
app.get('/func', (req, res) => {
    const body = req.query.body;
    // Function 构造器等价于 eval
    const fn = new Function('x', 'return ' + body);
    res.send(String(fn(42)));
});
""",
    "javascript", "distill_174.js",
    True, "CWE-94 代码注入", "Critical",
    "req.query.body", "new Function('return ' + body)",
    "req.query.body → new Function → 任意 JS 代码执行",
    "禁用 Function 构造器处理用户输入；改用安全表达式解析器",
)

add(
    """
const vm = require('vm');

app.get('/run', (req, res) => {
    const code = req.query.code;
    // vm.runInNewContext 并非安全沙箱
    const result = vm.runInNewContext(code, {});
    res.send(String(result));
});
""",
    "javascript", "distill_175.js",
    True, "CWE-94 代码注入", "Critical",
    "req.query.code", "vm.runInNewContext(code)",
    "vm 模块不是安全沙箱 → 可通过 escape 逃逸获取主进程对象 → RCE",
    "使用 vm2 或 isolated-vm 替代 vm；或完全不执行用户代码",
)

add(
    """
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

@RestController
public class ScriptController {
    @GetMapping("/eval")
    public String eval(@RequestParam String expr) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        Object result = engine.eval(expr);
        return result.toString();
    }
}
""",
    "java", "distill_176.java",
    True, "CWE-94 代码注入", "Critical",
    "@RequestParam expr", "engine.eval(expr)",
    "@RequestParam expr → ScriptEngine.eval → 任意 JS 代码执行",
    "不要用 ScriptEngine 执行用户输入；改用安全表达式引擎",
)

add(
    """
# Python getattr + 用户输入
@app.route('/call')
def call_method():
    obj = SomeClass()
    method_name = request.args.get('method', '')
    # 用户可控方法名
    method = getattr(obj, method_name)
    result = method()
    return str(result)
""",
    "python", "distill_177.py",
    True, "CWE-94 代码注入", "High",
    "request.args.get('method')", "getattr(obj, method_name)()",
    "用户可控方法名 → getattr 可获取 __init__、__subclasses__ 等危险方法 → 代码执行",
    "白名单校验方法名：ALLOWED = {'get_name','get_id'}; if method_name not in ALLOWED: abort(400)",
)

add(
    """
# Python getattr 安全
@app.route('/call')
def call_method():
    obj = SomeClass()
    method_name = request.args.get('method', '')
    ALLOWED_METHODS = {'get_name', 'get_id', 'get_email'}
    if method_name not in ALLOWED_METHODS:
        abort(400)
    method = getattr(obj, method_name)
    return str(method())
""",
    "python", "distill_178.py",
    False, "none", "None",
    "request.args.get('method')", "getattr(obj, method_name)()（白名单）",
    "method 经白名单校验后才 getattr，阻止调用危险方法",
    "no fix needed",
)

add(
    """
# Python ast.literal_eval 安全对照
import ast
from flask import request

@app.route('/parse')
def parse_value():
    raw = request.args.get('value', 'None')
    # ast.literal_eval 仅解析字面量（数字/字符串/列表/字典/None/True/False）
    value = ast.literal_eval(raw)
    return str(value)
""",
    "python", "distill_179.py",
    False, "none", "None",
    "request.args.get('value')", "ast.literal_eval(raw)",
    "ast.literal_eval 仅解析 Python 字面量，不执行表达式或函数调用",
    "no fix needed",
)

add(
    """
# Python Jinja2 SSTI
from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route('/render')
def render():
    template = request.args.get('tpl', 'Hello')
    # 用户输入直接作为模板 → SSTI
    return render_template_string(template)
""",
    "python", "distill_180.py",
    True, "CWE-94 代码注入(SSTI)", "Critical",
    "request.args.get('tpl')", "render_template_string(template)",
    "用户输入作为 Jinja2 模板 → {{ config }} / {{ ''.__class__.__mro__[1].__subclasses__() }} → RCE",
    "不要渲染用户输入为模板；使用预定义模板 + 参数：render_template_string('Hello {{ name }}', name=tpl)",
)

add(
    """
# Jinja2 安全模板渲染
from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route('/render')
def render():
    name = request.args.get('name', '')
    return render_template_string('Hello {{ name }}', name=name)
""",
    "python", "distill_181.py",
    False, "none", "None",
    "request.args.get('name')", "render_template_string('Hello {{ name }}', name=name)",
    "name 作为模板变量传入，Jinja2 自动转义 HTML，且不将用户输入作为模板语法解析",
    "no fix needed",
)

add(
    """
# Python eval with __builtins__ 限制（仍不安全）
from flask import request

@app.route('/calc')
def calc():
    expr = request.args.get('expr', '')
    # 尝试限制 __builtins__，但仍可绕过
    result = eval(expr, {"__builtins__": {}}, {})
    return str(result)
""",
    "python", "distill_182.py",
    True, "CWE-94 代码注入", "Critical",
    "request.args.get('expr')", "eval(expr, {\"__builtins__\": {}}, {})",
    "限制 __builtins__ 仍可通过 ()\\n.__class__.__bases__[0].__subclasses__() 绕过 → RCE",
    "禁用 eval；改用 ast.literal_eval 或专用安全表达式解析器",
)


# ===========================================================================
# 8. CWE-352 CSRF（15 条）— missing_control
# ===========================================================================

add(
    """
from flask import Flask, request, session
app = Flask(__name__)

@app.route('/change_password', methods=['POST'])
def change_password():
    # 修改密码无 CSRF token
    new_pwd = request.form['new_password']
    user = User.query.get(session['user_id'])
    user.set_password(new_pwd)
    user.save()
    return 'changed'
""",
    "python", "distill_183.py",
    True, "CWE-352 CSRF", "Medium",
    "POST 表单无 CSRF token", "user.set_password(new_pwd)",
    "修改密码 POST 无 CSRF token → 跨站可代为修改密码",
    "引入 Flask-WTF CSRFProtect 或在表单中加入 csrf_token 校验",
    cot_type="missing_control",
)

add(
    """
from flask import Flask, request, session
from flask_wtf.csrf import CSRFProtect
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
csrf = CSRFProtect(app)

@app.route('/change_password', methods=['POST'])
def change_password():
    new_pwd = request.form['new_password']
    user = User.query.get(session['user_id'])
    user.set_password(new_pwd)
    user.save()
    return 'changed'
""",
    "python", "distill_184.py",
    False, "none", "None",
    "CSRFProtect(app) 全局启用 CSRF", "user.set_password(new_pwd)",
    "Flask-WTF CSRFProtect 全局校验所有 POST 请求的 CSRF token",
    "no fix needed",
)

add(
    """
@app.route('/delete_account', methods=['POST'])
def delete_account():
    # 删除账号无 CSRF token
    user = User.query.get(session['user_id'])
    db.session.delete(user)
    db.session.commit()
    return 'deleted'
""",
    "python", "distill_185.py",
    True, "CWE-352 CSRF", "High",
    "POST 表单无 CSRF token", "db.session.delete(user)",
    "删除账号 POST 无 CSRF token → 跨站可触发账号删除",
    "加入 CSRF token 校验：validate_csrf_token(request.form.get('csrf_token'))",
    cot_type="missing_control",
)

add(
    """
@app.route('/update_settings', methods=['POST'])
def update_settings():
    # 设置更新无 CSRF token
    settings = Settings.query.get(session['user_id'])
    settings.email_notifications = request.form.get('email_notifications') == 'on'
    settings.language = request.form.get('language', 'en')
    db.session.commit()
    return 'updated'
""",
    "python", "distill_186.py",
    True, "CWE-352 CSRF", "Medium",
    "POST 表单无 CSRF token", "settings.email_notifications = ...",
    "更新设置 POST 无 CSRF token → 跨站可代为修改设置",
    "加入 CSRF token 校验",
    cot_type="missing_control",
)

add(
    """
const express = require('express');
const app = express();
app.use(express.urlencoded({extended: true}));

app.post('/profile/update', (req, res) => {
    // 无 CSRF 中间件
    const {display_name, bio} = req.body;
    db.updateProfile(req.session.userId, {display_name, bio});
    res.send('updated');
});
""",
    "javascript", "distill_187.js",
    True, "CWE-352 CSRF", "Medium",
    "POST body 无 CSRF token", "db.updateProfile(...)",
    "/profile/update POST 无 csurf 中间件 → 跨站可代为修改资料",
    "引入 csurf 中间件并在表单中渲染 csrfToken",
    cot_type="missing_control",
)

add(
    """
const express = require('express');
const csurf = require('csurf');
const app = express();
app.use(express.urlencoded({extended: true}));
app.use(csurf({cookie: true}));

app.post('/profile/update', (req, res) => {
    const {display_name, bio} = req.body;
    db.updateProfile(req.session.userId, {display_name, bio});
    res.send('updated');
});
""",
    "javascript", "distill_188.js",
    False, "none", "None",
    "csurf 中间件全局启用", "db.updateProfile(...)",
    "csurf 中间件自动校验 _csrf token",
    "no fix needed",
)

add(
    """
<?php
// Laravel 路由无 @csrf 指令
Route::post('/profile/update', function (Request $request) {
    $user = Auth::user();
    $user->display_name = $request->input('display_name');
    $user->save();
    return response('updated');
});
""",
    "php", "distill_189.php",
    True, "CWE-352 CSRF", "Medium",
    "POST 表单无 @csrf 指令", "$user->save()",
    "Laravel POST 路由表单无 @csrf → 跨站可代为修改资料",
    "在 Blade 表单中加入 @csrf 指令，依赖 VerifyCsrfToken 中间件校验",
    cot_type="missing_control",
)

add(
    """
// routes/web.php — 依赖 VerifyCsrfToken 中间件
Route::post('/profile/update', function (Request $request) {
    $user = Auth::user();
    $user->display_name = $request->input('display_name');
    $user->save();
    return response('updated');
});

// Blade 模板
// <form method="POST" action="/profile/update">
//   @csrf
//   <input name="display_name">
// </form>
""",
    "php", "distill_190.php",
    False, "none", "None",
    "Blade @csrf 指令 + VerifyCsrfToken 中间件", "$user->save()",
    "Laravel VerifyCsrfToken 中间件校验 _token 字段",
    "no fix needed",
)

add(
    """
@RestController
public class SettingsController {
    @PutMapping("/settings/email")
    public String updateEmail(@RequestParam String email) {
        // Spring Security 未启用 CSRF 过滤
        currentUser().setEmail(email);
        return "updated";
    }
}
""",
    "java", "distill_191.java",
    True, "CWE-352 CSRF", "Medium",
    "PUT 表单无 CSRF token", "currentUser().setEmail(email)",
    "Spring PUT 路由无 CsrfFilter → 跨站可代为修改邮箱",
    "在 Spring Security 配置中启用 CSRF：http.csrf().csrfTokenRepository(...)",
    cot_type="missing_control",
)

add(
    """
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().csrfTokenRepository(new HttpSessionCsrfTokenRepository())
            .and().authorizeRequests()
            .antMatchers("/settings/**").authenticated();
    }
}

@RestController
public class SettingsController {
    @PutMapping("/settings/email")
    public String updateEmail(@RequestParam String email) {
        currentUser().setEmail(email);
        return "updated";
    }
}
""",
    "java", "distill_192.java",
    False, "none", "None",
    "Spring Security CsrfFilter 启用", "currentUser().setEmail(email)",
    "Spring Security CsrfFilter 自动校验 X-CSRF-Token 头",
    "no fix needed",
)

add(
    """
# Django 视图未启用 CSRF
from django.views import View
from django.http import HttpResponse

class UpdateEmailView(View):
    def post(self, request):
        # @csrf_exempt 或 CsrfViewMiddleware 被禁用
        email = request.POST['email']
        request.user.email = email
        request.user.save()
        return HttpResponse('updated')
""",
    "python", "distill_193.py",
    True, "CWE-352 CSRF", "Medium",
    "Django 视图未启用 CSRF", "request.user.save()",
    "Django POST 视图无 csrf_protect → 跨站可代为修改邮箱",
    "启用 CsrfViewMiddleware 或加 @method_decorator(csrf_protect)",
    cot_type="missing_control",
)

add(
    """
# Django 视图安全 CSRF
from django.views import View
from django.views.decorators.csrf import csrf_protect
from django.utils.decorators import method_decorator
from django.http import HttpResponse

@method_decorator(csrf_protect, name='dispatch')
class UpdateEmailView(View):
    def post(self, request):
        email = request.POST['email']
        request.user.email = email
        request.user.save()
        return HttpResponse('updated')
""",
    "python", "distill_194.py",
    False, "none", "None",
    "@method_decorator(csrf_protect)", "request.user.save()",
    "Django csrf_protect 装饰器自动校验 csrfmiddlewaretoken",
    "no fix needed",
)

add(
    """
# CSRF token 校验逻辑缺陷：空值绕过
@app.route('/transfer', methods=['POST'])
def transfer():
    token = request.form.get('csrf_token', '')
    expected = session.get('csrf_token', '')
    # 使用 == 比较，且空值时通过
    if token == expected:
        db.transfer(session['user_id'], request.form['to'], request.form['amount'])
        return 'done'
    return 'forbidden', 403
""",
    "python", "distill_195.py",
    True, "CWE-352 CSRF", "Medium",
    "CSRF token 空值绕过", "db.transfer(...)",
    "攻击者不发送 csrf_token → token='' 和 expected=''（若 session 无 token）→ == 通过",
    "初始化 session csrf_token 为非空随机值；用 hmac.compare_digest 校验",
    cot_type="missing_control",
)

add(
    """
# CSRF token 安全校验（hmac.compare_digest）
import hmac

@app.route('/transfer', methods=['POST'])
def transfer():
    token = request.form.get('csrf_token', '')
    expected = session.get('csrf_token', '')
    if not expected or not hmac.compare_digest(token, expected):
        return 'forbidden', 403
    db.transfer(session['user_id'], request.form['to'], request.form['amount'])
    return 'done'
""",
    "python", "distill_196.py",
    False, "none", "None",
    "hmac.compare_digest(token, expected)", "db.transfer(...)",
    "session csrf_token 初始化为非空随机值，hmac.compare_digest 防时序攻击",
    "no fix needed",
)

# ===========================================================================
# 9. CWE-862 缺失授权（12 条）
# ===========================================================================

add(
    """
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/users/<int:user_id>/profile', methods=['GET'])
def get_profile(user_id):
    profile = db.get_user_profile(user_id)
    return jsonify(profile)
""",
    "python", "distill_197.py",
    True, "CWE-862 缺失授权", "High",
    "GET /api/users/<id>/profile 无授权检查", "db.get_user_profile(user_id)",
    "路由直接用 URL 参数 user_id 查询，未对比 session['user_id'] 或角色",
    "校验 user_id == session['user_id'] 或当前用户为管理员",
    cot_type="missing_control",
)

add(
    """
from flask import Flask, request, jsonify, session

app = Flask(__name__)

@app.route('/api/users/<int:user_id>/profile', methods=['GET'])
def get_profile(user_id):
    if 'user_id' not in session or (session['user_id'] != user_id and not session.get('is_admin')):
        return jsonify({'error': 'forbidden'}), 403
    profile = db.get_user_profile(user_id)
    return jsonify(profile)
""",
    "python", "distill_198.py",
    False, "none", "None",
    "session['user_id'] != user_id 校验", "db.get_user_profile(user_id)",
    "比较 session user_id 与 URL user_id，非管理员且非本人则 403",
    "no fix needed",
)

add(
    """
@RestController
@RequestMapping("/api/admin")
public class AdminController {
    @GetMapping("/users/{id}")
    public User getUser(@PathVariable Long id) {
        return userRepository.findById(id);
    }
}
""",
    "java", "distill_199.java",
    True, "CWE-862 缺失授权", "High",
    "@GetMapping /api/admin/users/{id} 无 @PreAuthorize", "userRepository.findById(id)",
    "Spring 控制器未加 @PreAuthorize，任何登录用户可访问 /api/admin/*",
    "加 @PreAuthorize(\"hasRole('ADMIN')\") 或在 SecurityConfig 限制 /api/admin/**",
    cot_type="missing_control",
)

add(
    """
@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    @GetMapping("/users/{id}")
    public User getUser(@PathVariable Long id) {
        return userRepository.findById(id);
    }
}
""",
    "java", "distill_200.java",
    False, "none", "None",
    "@PreAuthorize(\"hasRole('ADMIN')\")", "userRepository.findById(id)",
    "类级 @PreAuthorize 强制 ADMIN 角色，非管理员返回 403",
    "no fix needed",
)

add(
    """
const express = require('express');
const app = express();

app.get('/api/orders/:id', (req, res) => {
    const orderId = req.params.id;
    db.query('SELECT * FROM orders WHERE id = ?', [orderId], (err, rows) => {
        res.json(rows[0]);
    });
});
""",
    "javascript", "distill_201.js",
    True, "CWE-862 缺失授权", "High",
    "GET /api/orders/:id 无归属校验", "db.query(...)",
    "路由直接用 URL orderId 查询，未对比 req.session.userId 与订单的 user_id",
    "查询条件加 AND user_id = ? 并传入 req.session.userId",
    cot_type="missing_control",
)

add(
    """
const express = require('express');
const app = express();

app.get('/api/orders/:id', (req, res) => {
    const orderId = req.params.id;
    const userId = req.session.userId;
    if (!userId) return res.status(401).json({error: 'unauthorized'});
    db.query('SELECT * FROM orders WHERE id = ? AND user_id = ?', [orderId, userId], (err, rows) => {
        if (!rows[0]) return res.status(403).json({error: 'forbidden'});
        res.json(rows[0]);
    });
});
""",
    "javascript", "distill_202.js",
    False, "none", "None",
    "AND user_id = ? 归属校验", "db.query(...)",
    "SQL 加 user_id 过滤，非本人订单返回 403",
    "no fix needed",
)

add(
    """
<?php
// /api/account.php?id=123
$accountId = $_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM accounts WHERE id = :id");
$stmt->execute([':id' => $accountId]);
echo json_encode($stmt->fetch());
""",
    "php", "distill_203.php",
    True, "CWE-862 缺失授权", "High",
    "$_GET['id'] 直接查询无授权", "$stmt->execute(...)",
    "PHP 脚本用 GET 参数 id 查询账户，未校验 $_SESSION['user_id'] 是否拥有该账户",
    "查询条件加 AND owner_id = :uid 并传入 $_SESSION['user_id']",
    cot_type="missing_control",
)

add(
    """
<?php
session_start();
$accountId = $_GET['id'];
$userId = $_SESSION['user_id'] ?? 0;
$stmt = $pdo->prepare("SELECT * FROM accounts WHERE id = :id AND owner_id = :uid");
$stmt->execute([':id' => $accountId, ':uid' => $userId]);
$account = $stmt->fetch();
if (!$account) {
    http_response_code(403);
    echo json_encode(['error' => 'forbidden']);
    exit;
}
echo json_encode($account);
""",
    "php", "distill_204.php",
    False, "none", "None",
    "AND owner_id = :uid 归属校验", "$stmt->execute(...)",
    "SQL 加 owner_id 过滤，非本人账户返回 403",
    "no fix needed",
)

add(
    """
package main

import (
    "encoding/json"
    "net/http"
)

func getUserHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.URL.Query().Get("id")
    var user User
    db.Get(&user, "SELECT * FROM users WHERE id = $1", userID)
    json.NewEncoder(w).Encode(user)
}
""",
    "go", "distill_205.go",
    True, "CWE-862 缺失授权", "High",
    "/api/user?id= 无授权中间件", "db.Get(...)",
    "Go HTTP handler 直接用 query id 查询，无 session 校验或 auth 中间件",
    "加 auth 中间件并校验 session user_id 与 query id 一致",
    cot_type="missing_control",
)

add(
    """
package main

import (
    "encoding/json"
    "net/http"
    "strconv"
)

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        session := getSession(r)
        if session == nil || session.UserID == 0 {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        next(w, r)
    }
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
    session := getSession(r)
    userID := r.URL.Query().Get("id")
    if userID != strconv.Itoa(session.UserID) {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    var user User
    db.Get(&user, "SELECT * FROM users WHERE id = $1", userID)
    json.NewEncoder(w).Encode(user)
}
""",
    "go", "distill_206.go",
    False, "none", "None",
    "authMiddleware + session.UserID 校验", "db.Get(...)",
    "auth 中间件校验登录，handler 内比较 session user_id 与 query id",
    "no fix needed",
)

add(
    """
# Django UpdateView 缺失归属校验
from django.views.generic import UpdateView
from django.http import HttpResponse

class DocumentUpdateView(UpdateView):
    model = Document
    fields = ['title', 'content']
    pk_url_kwarg = 'doc_id'

    def form_valid(self, form):
        # 未校验 self.object.owner_id == self.request.user.id
        form.save()
        return HttpResponse('ok')
""",
    "python", "distill_207.py",
    True, "CWE-862 缺失授权", "High",
    "UpdateView 无 get_queryset 过滤", "form.save()",
    "Django UpdateView 默认按 pk 查询，未用 get_queryset 过滤 owner，任何登录用户可改任意文档",
    "重写 get_queryset 返回 super().get_queryset().filter(owner=self.request.user)",
    cot_type="missing_control",
)

add(
    """
// Spring Boot Actuator 端点未授权访问（CVE-2022-22965 类似模式）
// application.properties:
// management.endpoints.web.exposure.include=*
// management.endpoint.env.post.enabled=true
@RestController
@RequestMapping("/actuator")
public class EnvEndpoint {
    @PostMapping("/env")
    public String updateEnv(@RequestBody String body) {
        System.setProperty("app.config", body);
        return "updated";
    }
}
""",
    "java", "distill_208.java",
    True, "CWE-862 缺失授权", "Critical",
    "/actuator/env 无授权暴露", "System.setProperty(...)",
    "Spring Actuator 端点默认无鉴权，攻击者可读写环境变量、修改日志级别、触发 shutdown",
    "management.endpoints.web.exposure.include=health,info；启用 Spring Security 限制 /actuator/**",
    cot_type="missing_control",
)

# ===========================================================================
# 10. CWE-306 缺失认证（10 条）
# ===========================================================================

add(
    """
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/admin/users', methods=['GET'])
def list_users():
    # 无任何认证检查
    users = db.query('SELECT id, username FROM users')
    return jsonify(users)
""",
    "python", "distill_209.py",
    True, "CWE-306 缺失认证", "Critical",
    "/admin/users 路由无认证", "db.query(...)",
    "Flask 路由未加 login_required 或自定义认证装饰器，任何人均可访问 /admin/*",
    "加 @login_required 装饰器或自定义 @admin_required 检查 session 登录状态",
    cot_type="missing_control",
)

add(
    """
from flask import Flask, request, jsonify, session
from functools import wraps

app = Flask(__name__)

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'unauthorized'}), 401
        return f(*args, **kwargs)
    return wrapper

@app.route('/admin/users', methods=['GET'])
@login_required
def list_users():
    if not session.get('is_admin'):
        return jsonify({'error': 'forbidden'}), 403
    users = db.query('SELECT id, username FROM users')
    return jsonify(users)
""",
    "python", "distill_210.py",
    False, "none", "None",
    "@login_required + is_admin 检查", "db.query(...)",
    "装饰器校验 session 登录状态，handler 内校验管理员角色",
    "no fix needed",
)

add(
    """
// Spring SecurityConfig 未配置认证
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeRequests().anyRequest().permitAll();
    }
}

@RestController
@RequestMapping("/api/admin")
public class AdminController {
    @DeleteMapping("/users/{id}")
    public String deleteUser(@PathVariable Long id) {
        userRepository.deleteById(id);
        return "deleted";
    }
}
""",
    "java", "distill_211.java",
    True, "CWE-306 缺失认证", "Critical",
    "anyRequest().permitAll() 无认证", "userRepository.deleteById(id)",
    "Spring Security 配置 permitAll，删除用户接口无认证",
    "改 anyRequest().authenticated() 并配置 formLogin/httpBasic",
    cot_type="missing_control",
)

add(
    """
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeRequests()
                .antMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            .and().httpBasic();
    }
}
""",
    "java", "distill_212.java",
    False, "none", "None",
    "antMatchers(/api/admin/**).hasRole(ADMIN)", "userRepository.deleteById(...)",
    "/api/admin/** 要求 ADMIN 角色，其他接口要求已认证",
    "no fix needed",
)

add(
    """
const express = require('express');
const app = express();

// 无任何认证中间件
app.delete('/api/admin/users/:id', (req, res) => {
    db.query('DELETE FROM users WHERE id = ?', [req.params.id], (err) => {
        res.json({status: 'deleted'});
    });
});
""",
    "javascript", "distill_213.js",
    True, "CWE-306 缺失认证", "Critical",
    "DELETE 路由无 auth 中间件", "db.query('DELETE ...')",
    "Express 路由未挂载认证中间件，任何人均可调用删除用户接口",
    "app.use('/api/admin', authMiddleware) 校验 JWT/session",
    cot_type="missing_control",
)

add(
    """
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

function authMiddleware(req, res, next) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({error: 'no token'});
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        if (!req.user.isAdmin) return res.status(403).json({error: 'forbidden'});
        next();
    } catch (e) {
        res.status(401).json({error: 'invalid token'});
    }
}

app.delete('/api/admin/users/:id', authMiddleware, (req, res) => {
    db.query('DELETE FROM users WHERE id = ?', [req.params.id], (err) => {
        res.json({status: 'deleted'});
    });
});
""",
    "javascript", "distill_214.js",
    False, "none", "None",
    "authMiddleware 校验 JWT + isAdmin", "db.query('DELETE ...')",
    "中间件校验 Bearer token 并检查 isAdmin 角色",
    "no fix needed",
)

add(
    """
<?php
// admin/delete_user.php —— 无 session 检查
$userId = $_GET['id'];
$pdo->exec("DELETE FROM users WHERE id = " . (int)$userId);
echo "deleted";
""",
    "php", "distill_215.php",
    True, "CWE-306 缺失认证", "Critical",
    "admin 脚本无 session_start/检查", "$pdo->exec(...)",
    "PHP 脚本未 session_start 也未校验 $_SESSION['is_admin']，任何人可直接访问",
    "session_start 并校验 $_SESSION['is_admin'] === true",
    cot_type="missing_control",
)

add(
    """
<?php
session_start();
if (empty($_SESSION['is_admin']) || $_SESSION['is_admin'] !== true) {
    http_response_code(403);
    echo json_encode(['error' => 'forbidden']);
    exit;
}
$userId = (int)$_GET['id'];
$stmt = $pdo->prepare("DELETE FROM users WHERE id = :id");
$stmt->execute([':id' => $userId]);
echo "deleted";
""",
    "php", "distill_216.php",
    False, "none", "None",
    "$_SESSION['is_admin'] === true 校验", "$stmt->execute(...)",
    "session_start 后校验管理员标识，非管理员返回 403",
    "no fix needed",
)

add(
    """
package main

import (
    "net/http"
)

func main() {
    // /admin/* 无认证中间件
    http.HandleFunc("/admin/delete_user", func(w http.ResponseWriter, r *http.Request) {
        userID := r.URL.Query().Get("id")
        db.Exec("DELETE FROM users WHERE id = $1", userID)
        w.Write([]byte("deleted"))
    })
    http.ListenAndServe(":8080", nil)
}
""",
    "go", "distill_217.go",
    True, "CWE-306 缺失认证", "Critical",
    "/admin/* 无认证中间件", "db.Exec(...)",
    "Go HTTP handler 直接暴露 /admin/* 路径，无 session/JWT 校验",
    "挂载 auth 中间件并校验管理员角色",
    cot_type="missing_control",
)

add(
    """
package main

import (
    "net/http"
)

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        c, err := r.Cookie("session_id")
        if err != nil || !isValidAdminSession(c.Value) {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        next(w, r)
    }
}

func main() {
    http.HandleFunc("/admin/delete_user", requireAuth(func(w http.ResponseWriter, r *http.Request) {
        userID := r.URL.Query().Get("id")
        db.Exec("DELETE FROM users WHERE id = $1", userID)
        w.Write([]byte("deleted"))
    }))
    http.ListenAndServe(":8080", nil)
}
""",
    "go", "distill_218.go",
    False, "none", "None",
    "requireAuth 中间件校验 session", "db.Exec(...)",
    "中间件校验 session_id cookie 是否为有效管理员会话",
    "no fix needed",
)

# ===========================================================================
# 11. CWE-384 Session Fixation（10 条）
# ===========================================================================

add(
    """
from flask import Flask, request, session, redirect

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        # 登录后未重新生成 session
        session['user_id'] = user.id
        return redirect('/dashboard')
    return 'invalid', 401
""",
    "python", "distill_219.py",
    True, "CWE-384 Session Fixation", "High",
    "登录后未 regenerate session", "session['user_id'] = user.id",
    "Flask 登录后复用现有 session id，攻击者可预先设置 session_id 再诱导受害者登录",
    "登录成功后调用 session.clear() + session.regenerate() 或 Flask-Login 的 _user_id 重置",
    cot_type="missing_control",
)

add(
    """
from flask import Flask, request, session, redirect
import secrets

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        session.clear()  # 清除旧 session
        app.session_interface.regenerate(app, request)  # 生成新 session id
        session['user_id'] = user.id
        return redirect('/dashboard')
    return 'invalid', 401
""",
    "python", "distill_220.py",
    False, "none", "None",
    "session.clear() + regenerate", "session['user_id'] = user.id",
    "登录成功后清除旧 session 并生成新 session id，防止 fixation",
    "no fix needed",
)

add(
    """
// Java Servlet 登录后未 invalidate 旧 session
protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String username = req.getParameter("username");
    String password = req.getParameter("password");
    if (authService.login(username, password)) {
        HttpSession session = req.getSession(false);
        if (session == null) session = req.getSession();
        session.setAttribute("user", username);
        resp.sendRedirect("/dashboard");
    }
}
""",
    "java", "distill_221.java",
    True, "CWE-384 Session Fixation", "High",
    "登录后未 invalidate session", "session.setAttribute(\"user\", username)",
    "Servlet 登录后未调用 session.invalidate()，攻击者预设 JSESSIONID 可劫持登录后会话",
    "登录成功后 req.getSession(false).invalidate() 再 req.getSession(true) 创建新 session",
    cot_type="missing_control",
)

add(
    """
protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String username = req.getParameter("username");
    String password = req.getParameter("password");
    if (authService.login(username, password)) {
        HttpSession oldSession = req.getSession(false);
        if (oldSession != null) oldSession.invalidate();
        HttpSession newSession = req.getSession(true);
        newSession.setAttribute("user", username);
        resp.sendRedirect("/dashboard");
    }
}
""",
    "java", "distill_222.java",
    False, "none", "None",
    "invalidate() + getSession(true)", "newSession.setAttribute(...)",
    "登录成功后销毁旧 session 并创建新 session，防止 fixation",
    "no fix needed",
)

add(
    """
const express = require('express');
const session = require('express-session');
const app = express();

app.use(session({secret: 'key', resave: false, saveUninitialized: false}));

app.post('/login', (req, res) => {
    if (authenticate(req.body.username, req.body.password)) {
        // 未 regenerate session id
        req.session.userId = user.id;
        res.redirect('/dashboard');
    }
});
""",
    "javascript", "distill_223.js",
    True, "CWE-384 Session Fixation", "High",
    "登录后未 req.session.regenerate()", "req.session.userId = user.id",
    "Express 登录后复用现有 session id，易受 fixation 攻击",
    "登录成功后调用 req.session.regenerate(callback) 生成新 session id",
    cot_type="missing_control",
)

add(
    """
const express = require('express');
const session = require('express-session');
const app = express();

app.use(session({secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false}));

app.post('/login', (req, res) => {
    if (authenticate(req.body.username, req.body.password)) {
        const oldData = {userId: user.id, role: user.role};
        req.session.regenerate(() => {
            req.session.userId = oldData.userId;
            req.session.role = oldData.role;
            res.redirect('/dashboard');
        });
    }
});
""",
    "javascript", "distill_224.js",
    False, "none", "None",
    "req.session.regenerate()", "req.session.userId = ...",
    "登录成功后 regenerate 生成新 session id，再迁移必要数据",
    "no fix needed",
)

add(
    """
<?php
// 攻击者诱导受害者访问 ?PHPSESSID=evil
session_id($_GET['PHPSESSID']);
session_start();
if ($auth->login($_POST['username'], $_POST['password'])) {
    $_SESSION['user_id'] = $user->id;
    header('Location: /dashboard');
}
""",
    "php", "distill_225.php",
    True, "CWE-384 Session Fixation", "High",
    "session_id() 接受 GET 参数", "$_SESSION['user_id'] = ...",
    "PHP 用 GET 参数设置 session id，攻击者可预设会话 id 诱导受害者登录",
    "禁用 session.use_trans_sid=0，登录后 session_regenerate_id(true)",
    cot_type="missing_control",
)

add(
    """
<?php
session_start();
if ($auth->login($_POST['username'], $_POST['password'])) {
    session_regenerate_id(true);  // 删除旧 session 文件，生成新 id
    $_SESSION['user_id'] = $user->id;
    header('Location: /dashboard');
}
""",
    "php", "distill_226.php",
    False, "none", "None",
    "session_regenerate_id(true)", "$_SESSION['user_id'] = ...",
    "登录后调用 session_regenerate_id(true) 生成新 session id 并删除旧文件",
    "no fix needed",
)

add(
    """
# Django 登录视图未调用 cycle_key
from django.contrib.auth import authenticate, login
from django.http import HttpResponseRedirect

def custom_login(request):
    user = authenticate(request, username=request.POST['username'], password=request.POST['password'])
    if user is not None:
        login(request, user)  # Django 默认 cycle_key，但被自定义中间件绕过
        return HttpResponseRedirect('/dashboard')
""",
    "python", "distill_227.py",
    True, "CWE-384 Session Fixation", "Medium",
    "自定义中间件禁用 cycle_key", "login(request, user)",
    "Django 默认 login 会调用 request.session.cycle_key()，但被 SESSION_ENGINE 配置或中间件绕过",
    "确保 Django 默认 cycle_key 生效，或登录后手动 request.session.cycle_key()",
    cot_type="missing_control",
)

add(
    """
// Spring Session 配置未禁用 session fixation
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.sessionManagement()
            .sessionFixation().migrateSession()  // 登录时迁移 session
            .and()
            .formLogin().and().csrf().disable();
    }
}
""",
    "java", "distill_228.java",
    False, "none", "None",
    "sessionFixation().migrateSession()", "formLogin()",
    "Spring Security 配置 migrateSession 在登录时创建新 session 并迁移数据",
    "no fix needed",
)

# ===========================================================================
# 12. CWE-1333 ReDoS（14 条）
# ===========================================================================

add(
    """
import re

def validate_email(email):
    # 嵌套量词 + . 结尾 → 灾难性回溯
    pattern = r'^([a-zA-Z0-9_.+\\-]+)+@([a-zA-Z0-9\\-]+\\.)+[a-zA-Z0-9\\-]+$'
    return re.match(pattern, email) is not None
""",
    "python", "distill_229.py",
    True, "CWE-1333 ReDoS", "High",
    "嵌套量词正则 + 用户输入", "re.match(pattern, email)",
    "正则含 ([a-zA-Z0-9_.+\\-]+)+ 嵌套量词，恶意输入可触发 O(2^n) 回溯",
    "去除嵌套量词，用 ^[^@]+@[^@]+\\.[^@]+$ 或专用 email 校验库",
    cot_type="source_sink",
)

add(
    """
import re

EMAIL_RE = re.compile(r'^[a-zA-Z0-9_.+\\-]+@[a-zA-Z0-9\\-]+\\.[a-zA-Z0-9\\-.]+$')

def validate_email(email):
    return EMAIL_RE.match(email) is not None
""",
    "python", "distill_230.py",
    False, "none", "None",
    "无嵌套量词的线性正则", "EMAIL_RE.match(email)",
    "正则无嵌套量词，回溯复杂度为 O(n)，安全",
    "no fix needed",
)

add(
    """
function validatePhone(phone) {
    // 嵌套量词导致灾难性回溯
    const re = /^(\\d+\\s*)+\\d+$/;
    return re.test(phone);
}
""",
    "javascript", "distill_231.js",
    True, "CWE-1333 ReDoS", "High",
    "JS 嵌套量词正则", "re.test(phone)",
    "正则含 (\\d+\\s*)+ 嵌套量词，输入 '1' + 大量空格 + 'a' 触发回溯",
    "用 ^(\\d[\\s\\d]*){8,15}$ 或专用 phone 校验库",
    cot_type="source_sink",
)

add(
    """
function validatePhone(phone) {
    const re = /^\\d[\\d\\s]{7,14}\\d$/;
    return re.test(phone);
}
""",
    "javascript", "distill_232.js",
    False, "none", "None",
    "无嵌套量词的线性正则", "re.test(phone)",
    "正则用单层量词 [\\d\\s]{7,14}，无灾难性回溯",
    "no fix needed",
)

add(
    """
import java.util.regex.*;

public class Validator {
    private static final Pattern DATE = Pattern.compile(
        "^([0-9]{4})[-/]([0-9]{2})[-/]([0-9]{2}([0-9]{2})?)?$"
    );

    public boolean isValidDate(String input) {
        return DATE.matcher(input).matches();
    }
}
""",
    "java", "distill_233.java",
    True, "CWE-1333 ReDoS", "High",
    "Java Pattern 含嵌套可选组", "DATE.matcher(input).matches()",
    "正则含 ([0-9]{2}([0-9]{2})?)? 嵌套可选组，可被特殊输入触发回溯",
    "拆分为多个候选正则或用 DateTimeFormatter.parse",
    cot_type="source_sink",
)

add(
    """
import java.util.regex.Pattern;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

public class Validator {
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd");

    public boolean isValidDate(String input) {
        try {
            LocalDate.parse(input, FMT);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
""",
    "java", "distill_234.java",
    False, "none", "None",
    "LocalDate.parse 替代正则", "LocalDate.parse(input, FMT)",
    "用 DateTimeFormatter 解析日期，避免正则回溯",
    "no fix needed",
)

add(
    """
<?php
function isHexColor($input) {
    // 嵌套量词
    return preg_match('/^#?([0-9a-fA-F]+)+$/', $input) === 1;
}
""",
    "php", "distill_235.php",
    True, "CWE-1333 ReDoS", "Medium",
    "PHP preg_match 嵌套量词", "preg_match(...)",
    "正则含 ([0-9a-fA-F]+)+ 嵌套量词，输入 '#xxx' + 非 hex 字符触发回溯",
    "用 /^#?[0-9a-fA-F]{6}$/ 或 filter_var(..., FILTER_VALIDATE_REGEXP)",
    cot_type="source_sink",
)

add(
    """
<?php
function isHexColor($input) {
    return preg_match('/^#?[0-9a-fA-F]{6}$/', $input) === 1;
}
""",
    "php", "distill_236.php",
    False, "none", "None",
    "无嵌套量词正则", "preg_match(...)",
    "正则用 [0-9a-fA-F]{6} 固定量词，无回溯风险",
    "no fix needed",
)

add(
    """
package main

import (
    "regexp"
)

func isValidUsername(username string) bool {
    // Go regexp 不支持反向引用，但嵌套量词仍有回溯
    re := regexp.MustCompile(`^([a-zA-Z0-9_]+)+$`)
    return re.MatchString(username)
}
""",
    "go", "distill_237.go",
    True, "CWE-1333 ReDoS", "Medium",
    "Go regexp 嵌套量词", "re.MatchString(username)",
    "Go regexp 使用 RE2 但嵌套量词仍有性能问题，恶意输入可造成高 CPU",
    "用 ^[a-zA-Z0-9_]+$ 去除嵌套量词",
    cot_type="source_sink",
)

add(
    """
package main

import (
    "regexp"
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_]{3,32}$`)

func isValidUsername(username string) bool {
    return usernameRe.MatchString(username)
}
""",
    "go", "distill_238.go",
    False, "none", "None",
    "固定量词正则", "usernameRe.MatchString(username)",
    "正则用 {3,32} 固定量词，无嵌套",
    "no fix needed",
)

add(
    """
# 复杂邮件正则变体（常见开源代码模式）
import re

COMPLEX_EMAIL = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

def check_email(s):
    return COMPLEX_EMAIL.match(s) is not None
""",
    "python", "distill_239.py",
    True, "CWE-1333 ReDoS", "Medium",
    "复杂多分组正则", "COMPLEX_EMAIL.match(s)",
    "正则含多个 (?:...)? 可选组串联，构造特殊输入触发指数回溯",
    "用 email_validator 库或简单 ^[^@]+@[^@]+\\.[^@]+$ 后再做 DNS 校验",
    cot_type="source_sink",
)

add(
    """
// URL 校验正则 CVE 类（常见于旧版 npm 包）
function isValidURL(url) {
    // 嵌套量词 + 多个 .* 联合
    const re = /^((https?:\\/\\/)?([a-zA-Z0-9\\-]+\\.)+[a-zA-Z]{2,})(\\/.*)?$/;
    return re.test(url);
}
""",
    "javascript", "distill_240.js",
    True, "CWE-1333 ReDoS", "High",
    "URL 正则多量词串联", "re.test(url)",
    "正则含 ([a-zA-Z0-9\\-]+\\.)+ 与 (\\/.*)? 串联，特殊输入触发回溯",
    "用 URL构造函数 try { new URL(url) } 或专用 validator 库",
    cot_type="source_sink",
)

add(
    """
// CVE-2021-27268: log4j SimplizePatternConverter 正则 DoS
// 模式：使用含嵌套量词的正则解析用户输入的格式字符串
import java.util.regex.*;

public class LogFormat {
    // 嵌套量词正则解析 %格式
    private static final Pattern P = Pattern.compile(
        "%(-?\\d+)?(\\.\\d+)?([a-zA-Z]+(\\{.*?\\})?)+"
    );

    public String convert(String pattern) {
        Matcher m = P.matcher(pattern);
        return m.replaceAll("");
    }
}
""",
    "java", "distill_241.java",
    True, "CWE-1333 ReDoS", "Critical",
    "log4j 风格正则解析用户格式", "P.matcher(pattern).replaceAll(...)",
    "CVE-2021-27268 类似：正则 ([a-zA-Z]+(\\{.*?\\})?)+ 含嵌套量词，攻击者构造格式串触发 DoS",
    "升级 log4j 到 2.17+，避免用嵌套量词正则解析用户格式串",
    cot_type="source_sink",
)

add(
    """
# Python 使用 signal 超时保护正则
import re
import signal

class TimeoutError(Exception):
    pass

def regex_with_timeout(pattern, string, timeout=1.0):
    def handler(signum, frame):
        raise TimeoutError("regex timeout")
    signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        return re.match(pattern, string)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
""",
    "python", "distill_242.py",
    False, "none", "None",
    "signal.setitimer 正则超时", "re.match(pattern, string)",
    "用 SIGALRM 为正则匹配设置超时，避免 ReDoS 拖垮进程",
    "no fix needed",
)

# ===========================================================================
# 13. CWE-190 整数溢出（10 条）
# ===========================================================================

add(
    """
#include <stdlib.h>
#include <string.h>

int copy_buffer(char *user_data, unsigned int user_len) {
    // user_len * sizeof(char) 可溢出
    char *buf = malloc(user_len * sizeof(char));
    if (!buf) return -1;
    memcpy(buf, user_data, user_len);
    free(buf);
    return 0;
}
""",
    "c", "distill_243.c",
    True, "CWE-190 整数溢出", "Critical",
    "user_len * sizeof(char) 溢出", "malloc(user_len * sizeof(char))",
    "user_len 为 unsigned int，乘法可回绕为小值，malloc 分配小缓冲，memcpy 写入大量数据 → 堆溢出",
    "用 size_t + 溢出检查 if (user_len > MAX) return -1; 或 ckd_mul",
    cot_type="integer_overflow",
)

add(
    """
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_LEN (1u << 20)

int copy_buffer(char *user_data, size_t user_len) {
    if (user_len == 0 || user_len > MAX_LEN) return -1;
    char *buf = malloc(user_len);  // sizeof(char) == 1, 无需乘法
    if (!buf) return -1;
    memcpy(buf, user_data, user_len);
    free(buf);
    return 0;
}
""",
    "c", "distill_244.c",
    False, "none", "None",
    "size_t + MAX_LEN 上界检查", "malloc(user_len)",
    "用 size_t 避免符号问题，显式上界检查防止溢出，sizeof(char)==1 无需乘法",
    "no fix needed",
)

add(
    """
#include <stdint.h>

int32_t compute_total(int32_t a, int32_t b) {
    int32_t sum = a + b;  // 两个 int32 相加可溢出
    return sum;
}
""",
    "c", "distill_245.c",
    True, "CWE-190 整数溢出", "High",
    "a + b int32 相加溢出", "int32_t sum = a + b",
    "两个 int32 相加，结果超过 INT32_MAX 时回绕为负数，下游用 sum 做长度/索引不安全",
    "用 __builtin_add_overflow 或 ckd_add 检查溢出",
    cot_type="integer_overflow",
)

add(
    """
#include <stdint.h>
#include <stdbool.h>

bool compute_total(int32_t a, int32_t b, int32_t *out) {
    #if defined(__GNUC__)
    return __builtin_add_overflow(a, b, out) == false;
    #else
    if (((b > 0) && (a > INT32_MAX - b)) || ((b < 0) && (a < INT32_MIN - b))) {
        return false;
    }
    *out = a + b;
    return true;
    #endif
}
""",
    "c", "distill_246.c",
    False, "none", "None",
    "__builtin_add_overflow 检查", "*out = a + b",
    "用编译器内置函数或手动范围检查，溢出时返回 false",
    "no fix needed",
)

add(
    """
public class OrderService {
    public long computeTotal(int quantity, int unitPrice) {
        return quantity * unitPrice;  // int * int 溢出后转 long
    }
}
""",
    "java", "distill_247.java",
    True, "CWE-190 整数溢出", "High",
    "quantity * unitPrice int 相乘", "return quantity * unitPrice",
    "两个 int 相乘在 int 范围内计算后才转 long，溢出后结果错误（如 100000 * 100000 = 1410065408）",
    "用 Math.multiplyExact 或先转 long 再相乘：((long)quantity) * unitPrice",
    cot_type="integer_overflow",
)

add(
    """
import java.math.BigInteger;

public class OrderService {
    public long computeTotal(int quantity, int unitPrice) {
        try {
            return Math.multiplyExact(quantity, unitPrice);
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException("total overflow");
        }
    }
}
""",
    "java", "distill_248.java",
    False, "none", "None",
    "Math.multiplyExact 检查溢出", "Math.multiplyExact(quantity, unitPrice)",
    "Math.multiplyExact 溢出时抛 ArithmeticException，调用方可捕获处理",
    "no fix needed",
)

add(
    """
#include <string.h>
#include <stdint.h>

// 16-bit 嵌入式场景：len 是 uint16_t
int copy_region(char *dst, uint16_t offset, uint16_t len, const char *src) {
    // offset + len 在 uint16_t 内可能回绕
    if (offset + len > BUFFER_SIZE) return -1;
    memcpy(dst + offset, src, len);
    return 0;
}
""",
    "c", "distill_249.c",
    True, "CWE-190 整数溢出", "High",
    "offset + len uint16 回绕", "memcpy(dst + offset, src, len)",
    "offset=60000, len=10000 → offset+len 回绕为 4464 < BUFFER_SIZE 通过检查，memcpy 越界写",
    "用 if (len > BUFFER_SIZE || offset > BUFFER_SIZE - len) 做安全减法检查",
    cot_type="integer_overflow",
)

add(
    """
#include <stdint.h>

// 用户输入的 index 直接用作数组索引
int get_item(int32_t user_index, int32_t *arr, int32_t arr_len) {
    if (user_index < arr_len) {  // 负 index 通过检查
        return arr[user_index];  // 负索引读越界
    }
    return -1;
}
""",
    "c", "distill_250.c",
    True, "CWE-190 整数溢出", "High",
    "user_index 负数绕过 < arr_len", "arr[user_index]",
    "user_index 为 int32，负数 < arr_len 通过检查，arr[负数] 读栈/堆越界",
    "if (user_index < 0 || user_index >= arr_len) return -1; 用无符号或显式下界",
    cot_type="integer_overflow",
)

add(
    """
// CVE-2021-22555: Linux kernel netfilter 整数溢出
// set_elem->aligned_size = elem->target_offset + nla_len(nla)
// nla_len 返回 int，与 target_offset 相加后转 size_t，可绕过下界检查
struct nf_conntrack_help {
    int target_offset;
    int elem_len;
    char data[0];
};

void *ct_help_alloc(int target_offset, int elem_len) {
    int total = target_offset + elem_len;  // 溢出为小值
    struct nf_conntrack_help *h = malloc(sizeof(*h) + total);
    // 后续 memcpy 写入 elem_len 字节 → 堆溢出
    memcpy(h->data, src, elem_len);
    return h;
}
""",
    "c", "distill_251.c",
    True, "CWE-190 整数溢出", "Critical",
    "target_offset + elem_len 溢出", "malloc(sizeof(*h) + total)",
    "CVE-2021-22555 模式：两个 int 相加溢出后 malloc 分配小缓冲，memcpy 写入 elem_len 字节 → 堆溢出 → LPE",
    "用 size_t 做加法并显式溢出检查；用 ckd_add",
    cot_type="integer_overflow",
)

add(
    """
package main

import "errors"

func allocateBuffer(n uint32) ([]byte, error) {
    // n 是 uint32，n*4 在 uint32 范围内可回绕
    size := n * 4
    if size > (1 << 28) {
        return nil, errors.New("too large")
    }
    return make([]byte, size), nil
}
""",
    "go", "distill_252.go",
    True, "CWE-190 整数溢出", "High",
    "n * 4 uint32 回绕", "make([]byte, size)",
    "n=0x40000001 → n*4 = 4，分配 4 字节但调用方按 n 个元素写入 → 越界",
    "用 if n > (1<<28)/4 做乘法前检查，或用 math/bits.Mul32 检查溢出",
    cot_type="integer_overflow",
)

# ===========================================================================
# 14. CWE-798 硬编码凭证（16 条）
# ===========================================================================

add(
    """
import requests

STRIPE_API_KEY = "sk_live_51H8xYc2eZvK..."

def charge_customer(amount, customer_id):
    resp = requests.post("https://api.stripe.com/v1/charges",
        headers={"Authorization": f"Bearer {STRIPE_API_KEY}"},
        data={"amount": amount, "customer": customer_id})
    return resp.json()
""",
    "python", "distill_253.py",
    True, "CWE-798 硬编码凭证", "Critical",
    "STRIPE_API_KEY = 'sk_live_...'", "requests.post(..., headers=Bearer)",
    "Stripe live key 直接硬编码在源码，泄露后攻击者可发起任意支付",
    "用 os.environ['STRIPE_API_KEY'] 或从 secrets manager 读取",
    cot_type="hardcoded_secret",
)

add(
    """
import os
import requests

def charge_customer(amount, customer_id):
    api_key = os.environ.get("STRIPE_API_KEY")
    if not api_key:
        raise RuntimeError("STRIPE_API_KEY not configured")
    resp = requests.post("https://api.stripe.com/v1/charges",
        headers={"Authorization": f"Bearer {api_key}"},
        data={"amount": amount, "customer": customer_id})
    return resp.json()
""",
    "python", "distill_254.py",
    False, "none", "None",
    "os.environ.get('STRIPE_API_KEY')", "requests.post(...)",
    "API key 从环境变量读取，源码不含字面量凭证",
    "no fix needed",
)

add(
    """
public class DatabaseConfig {
    private static final String DB_URL = "jdbc:mysql://prod-db:3306/app";
    private static final String DB_USER = "app_user";
    private static final String DB_PASSWORD = "P@ssw0rd!2024";

    public Connection connect() throws SQLException {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
    }
}
""",
    "java", "distill_255.java",
    True, "CWE-798 硬编码凭证", "Critical",
    "DB_PASSWORD = 'P@ssw0rd!2024'", "DriverManager.getConnection(...)",
    "数据库密码硬编码为字符串字面量，源码或反编译即可泄露",
    "用 Spring @Value 注入或从 Vault/KMS 读取",
    cot_type="hardcoded_secret",
)

add(
    """
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.sql.*;

@Component
public class DatabaseConfig {
    @Value("${db.url}")
    private String dbUrl;
    @Value("${db.user}")
    private String dbUser;
    @Value("${db.password}")
    private String dbPassword;

    public Connection connect() throws SQLException {
        return DriverManager.getConnection(dbUrl, dbUser, dbPassword);
    }
}
""",
    "java", "distill_256.java",
    False, "none", "None",
    "@Value(\"${db.password}\") 注入", "DriverManager.getConnection(...)",
    "Spring 从外部配置文件/environment 注入凭证，源码无字面量",
    "no fix needed",
)

add(
    """
const jwt = require('jsonwebtoken');

const JWT_SECRET = "supersecretkey123";

function signToken(user) {
    return jwt.sign({userId: user.id, role: user.role}, JWT_SECRET, {expiresIn: '1h'});
}
""",
    "javascript", "distill_257.js",
    True, "CWE-798 硬编码凭证", "Critical",
    "JWT_SECRET = 'supersecretkey123'", "jwt.sign(..., JWT_SECRET)",
    "JWT 签名密钥硬编码，泄露后攻击者可伪造任意 token",
    "用 process.env.JWT_SECRET，并用 crypto.randomBytes(32) 生成强密钥",
    cot_type="hardcoded_secret",
)

add(
    """
const jwt = require('jsonwebtoken');

function signToken(user) {
    const secret = process.env.JWT_SECRET;
    if (!secret || secret.length < 32) {
        throw new Error('JWT_SECRET must be set and >= 32 chars');
    }
    return jwt.sign({userId: user.id, role: user.role}, secret, {expiresIn: '1h'});
}
""",
    "javascript", "distill_258.js",
    False, "none", "None",
    "process.env.JWT_SECRET", "jwt.sign(..., secret)",
    "JWT 密钥从环境变量读取并校验长度",
    "no fix needed",
)

add(
    """
<?php
// config/db.php
$DB_HOST = 'prod-db';
$DB_USER = 'app_user';
$DB_PASS = 'mysql_password_2024';
$DB_NAME = 'app';

$pdo = new PDO("mysql:host=$DB_HOST;dbname=$DB_NAME", $DB_USER, $DB_PASS);
""",
    "php", "distill_259.php",
    True, "CWE-798 硬编码凭证", "Critical",
    "$DB_PASS = 'mysql_password_2024'", "new PDO(...)",
    "MySQL 密码硬编码在 PHP 配置文件，源码泄露即暴露数据库",
    "用 getenv('DB_PASS') 或 .env 文件 + phpdotenv",
    cot_type="hardcoded_secret",
)

add(
    """
<?php
$DB_HOST = getenv('DB_HOST');
$DB_USER = getenv('DB_USER');
$DB_PASS = getenv('DB_PASS');
$DB_NAME = getenv('DB_NAME');

if (!$DB_PASS) {
    http_response_code(500);
    exit('DB credentials not configured');
}
$pdo = new PDO("mysql:host=$DB_HOST;dbname=$DB_NAME", $DB_USER, $DB_PASS);
""",
    "php", "distill_260.php",
    False, "none", "None",
    "getenv('DB_PASS')", "new PDO(...)",
    "数据库凭证从环境变量读取，缺失时报错",
    "no fix needed",
)

add(
    """
package main

import (
    "database/sql"
    "fmt"
    _ "github.com/lib/pq"
)

const DBConnStr = "host=prod-db user=app_user password=hardcoded_pg_pass dbname=app sslmode=disable"

func connectDB() (*sql.DB, error) {
    return sql.Open("postgres", DBConnStr)
}
""",
    "go", "distill_261.go",
    True, "CWE-798 硬编码凭证", "Critical",
    "password=hardcoded_pg_pass", "sql.Open(...)",
    "PG 连接串含明文密码硬编码在 const",
    "用 os.Getenv('DATABASE_URL') 从环境变量读取",
    cot_type="hardcoded_secret",
)

add(
    """
package main

import (
    "database/sql"
    "os"
    _ "github.com/lib/pq"
)

func connectDB() (*sql.DB, error) {
    connStr := os.Getenv("DATABASE_URL")
    if connStr == "" {
        return nil, fmt.Errorf("DATABASE_URL not set")
    }
    return sql.Open("postgres", connStr)
}
""",
    "go", "distill_262.go",
    False, "none", "None",
    "os.Getenv('DATABASE_URL')", "sql.Open(...)",
    "连接串从环境变量读取",
    "no fix needed",
)

add(
    """
import boto3

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

s3 = boto3.client('s3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
s3.download_file('my-bucket', 'data.csv', '/tmp/data.csv')
""",
    "python", "distill_263.py",
    True, "CWE-798 硬编码凭证", "Critical",
    "AWS_SECRET_ACCESS_KEY = 'wJalr...'", "boto3.client(...)",
    "AWS 凭证硬编码，泄露后攻击者可访问 S3/EC2 等资源",
    "用 IAM Role（EC2/ECS）或 ~/.aws/credentials 配置",
    cot_type="hardcoded_secret",
)

add(
    """
import boto3

# 在 EC2/ECS 上使用 IAM Role，无需硬编码凭证
s3 = boto3.client('s3')  # 自动从 instance metadata 获取临时凭证
s3.download_file('my-bucket', 'data.csv', '/tmp/data.csv')
""",
    "python", "distill_264.py",
    False, "none", "None",
    "IAM Role 自动获取凭证", "boto3.client('s3')",
    "EC2/ECS 挂载 IAM Role，boto3 自动从 metadata 获取临时凭证",
    "no fix needed",
)

add(
    """
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtil {
    // 硬编码 AES 密钥
    private static final byte[] KEY = "0123456789abcdef".getBytes();

    public byte[] encrypt(byte[] data) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES");
        c.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec);
        return c.doFinal(data);
    }
}
""",
    "java", "distill_265.java",
    True, "CWE-798 硬编码凭证", "Critical",
    "KEY = '0123456789abcdef'.getBytes()", "new SecretKeySpec(KEY, 'AES')",
    "AES 密钥硬编码为字面量字节数组，且只有 16 字节（弱）",
    "用 KeyStore 加载密钥或从 KMS 派生",
    cot_type="hardcoded_secret",
)

add(
    """
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyStore;
import java.security.Key;

public class CryptoUtil {
    public byte[] encrypt(byte[] data) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (var fis = new java.io.FileInputStream(System.getenv("KEYSTORE_PATH"))) {
            ks.load(fis, System.getenv("KEYSTORE_PASS").toCharArray());
        }
        Key key = ks.getKey("app-aes-key", System.getenv("KEY_PASS").toCharArray());
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        c.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }
}
""",
    "java", "distill_266.java",
    False, "none", "None",
    "KeyStore 加载密钥", "ks.getKey('app-aes-key', ...)",
    "AES 密钥从 KeyStore 加载，KeyStore 路径/密码从环境变量读取",
    "no fix needed",
)

add(
    """
// OAuth client secret 硬编码在前端 JS（绕过变体）
const OAUTH_CLIENT_SECRET = "GOCSPX-client_secret_value";
const OAUTH_CLIENT_ID = "123456-app.apps.googleusercontent.com";

function exchangeCodeForToken(code) {
    return fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        body: new URLSearchParams({
            code,
            client_id: OAUTH_CLIENT_ID,
            client_secret: OAUTH_CLIENT_SECRET,  // 前端泄露
            grant_type: 'authorization_code'
        })
    });
}
""",
    "javascript", "distill_267.js",
    True, "CWE-798 硬编码凭证", "Critical",
    "OAUTH_CLIENT_SECRET = 'GOCSPX-...'", "fetch(...token, body=client_secret)",
    "OAuth client secret 硬编码在前端 JS，浏览器可查看源码获取",
    "前端用 PKCE flow，secret 仅在后端持有；或用 Google Identity Services",
    cot_type="hardcoded_secret",
)

add(
    """
// CVE-2023-xxxxx: IoT 设备固件硬编码 root 凭证
package main

import "crypto/sha256"

const firmwareRootPasswordHash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"

func authenticate(username, password string) bool {
    if username != "root" {
        return false
    }
    h := sha256.Sum256([]byte(password))
    return hex(h[:]) == firmwareRootPasswordHash  // "password"
}
""",
    "go", "distill_268.go",
    True, "CWE-798 硬编码凭证", "Critical",
    "firmwareRootPasswordHash = '5e88...'", "hex(h[:]) == firmwareRootPasswordHash",
    "IoT 固件硬编码 root 密码哈希（明文 'password'），所有设备同密码，逆向固件即得",
    "每台设备出厂时生成随机密码并烧录安全区，强制首次登录改密",
    cot_type="hardcoded_secret",
)

# ===========================================================================
# 15. CWE-327 弱密码学（20 条）
# ===========================================================================

add(
    """
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
""",
    "python", "distill_269.py",
    True, "CWE-327 弱密码学", "High",
    "hashlib.md5(password)", "hexdigest()",
    "MD5 已被破解，存在碰撞攻击，且无 salt，rainbow table 可秒破",
    "用 bcrypt/hashlib.scrypt(PBKDF2) 加随机 salt",
    cot_type="crypto_weakness",
)

add(
    """
import bcrypt

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())
""",
    "python", "distill_270.py",
    False, "none", "None",
    "bcrypt.hashpw + gensalt(12)", "bcrypt.checkpw(...)",
    "bcrypt 自动加 salt 且 rounds=12 提供 work factor，抗 rainbow table 和 GPU 暴破",
    "no fix needed",
)

add(
    """
import javax.crypto.Cipher;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.SecretKeyFactory;

public class Crypto {
    public byte[] encrypt(byte[] data) throws Exception {
        DESKeySpec keySpec = new DESKeySpec("hardkey!".getBytes());
        var key = SecretKeyFactory.getInstance("DES").generateSecret(keySpec);
        Cipher c = Cipher.getInstance("DES");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }
}
""",
    "java", "distill_271.java",
    True, "CWE-327 弱密码学", "High",
    "DES 加密 + 56-bit key", "c.doFinal(data)",
    "DES 仅 56-bit key，1998 年 EFF 22 小时可破；已禁用",
    "用 AES-256-GCM，密钥从 KeyStore/KMS 加载",
    cot_type="crypto_weakness",
)

add(
    """
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class Crypto {
    public byte[] encrypt(byte[] data, byte[] key) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
               new GCMParameterSpec(128, iv));
        byte[] cipherText = c.doFinal(data);
        return concatenate(iv, cipherText);
    }
}
""",
    "java", "distill_272.java",
    False, "none", "None",
    "AES/GCM/NoPadding + SecureRandom IV", "c.doFinal(data)",
    "AES-256-GCM 提供机密性 + 完整性，IV 用 SecureRandom 生成",
    "no fix needed",
)

add(
    """
const crypto = require('crypto');

function hashPassword(password) {
    return crypto.createHash('sha1').update(password).digest('hex');
}
""",
    "javascript", "distill_273.js",
    True, "CWE-327 弱密码学", "High",
    "crypto.createHash('sha1')", "digest('hex')",
    "SHA-1 已被碰撞攻击破解，且无 salt，不适用于密码存储",
    "用 bcrypt 或 crypto.scryptSync(password, salt, 64)",
    cot_type="crypto_weakness",
)

add(
    """
const bcrypt = require('bcrypt');

async function hashPassword(password) {
    return bcrypt.hash(password, 12);
}

async function checkPassword(password, hash) {
    return bcrypt.compare(password, hash);
}
""",
    "javascript", "distill_274.js",
    False, "none", "None",
    "bcrypt.hash(password, 12)", "bcrypt.compare(...)",
    "bcrypt 加 salt 并提供 work factor，抗 GPU/ASIC 暴破",
    "no fix needed",
)

add(
    """
<?php
function hashPassword($password) {
    return md5($password);
}
""",
    "php", "distill_275.php",
    True, "CWE-327 弱密码学", "High",
    "md5($password)", "return md5(...)",
    "PHP md5() 无 salt 且算法已被破解，rainbow table 可秒破",
    "用 password_hash($password, PASSWORD_BCRYPT 或 PASSWORD_ARGON2ID)",
    cot_type="crypto_weakness",
)

add(
    """
<?php
function hashPassword($password) {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

function checkPassword($password, $hash) {
    return password_verify($password, $hash);
}
""",
    "php", "distill_276.php",
    False, "none", "None",
    "password_hash(..., PASSWORD_BCRYPT)", "password_verify(...)",
    "password_hash 自动加 salt 并用 bcrypt，PHP 内置安全 API",
    "no fix needed",
)

add(
    """
#include <stdlib.h>
#include <stdio.h>

char *gen_token() {
    // rand() 种子小且可预测
    srand(time(NULL));
    static char token[17];
    for (int i = 0; i < 16; i++) {
        token[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[rand() % 36];
    }
    token[16] = '\\0';
    return token;
}
""",
    "c", "distill_277.c",
    True, "CWE-327 弱密码学", "Critical",
    "srand(time(NULL)) + rand()", "token[i] = ...[rand() % 36]",
    "rand() 输出空间小且 time(NULL) 种子可预测，攻击者可枚举所有 token",
    "用 /dev/urandom 或 getrandom() 系统调用",
    cot_type="crypto_weakness",
)

add(
    """
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

char *gen_token() {
    static char token[33];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return NULL;
    unsigned char buf[16];
    if (read(fd, buf, sizeof(buf)) != sizeof(buf)) {
        close(fd);
        return NULL;
    }
    close(fd);
    for (int i = 0; i < 16; i++) {
        sprintf(token + i * 2, "%02x", buf[i]);
    }
    token[32] = '\\0';
    return token;
}
""",
    "c", "distill_278.c",
    False, "none", "None",
    "/dev/urandom 读取", "sprintf(token + i*2, '%02x', buf[i])",
    "从 /dev/urandom 读取 16 字节随机数（128 bit），转 hex 为 32 字符 token",
    "no fix needed",
)

add(
    """
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

KEY = b'0123456789abcdef'

def encrypt(data):
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(data.encode(), AES.block_size))
""",
    "python", "distill_279.py",
    True, "CWE-327 弱密码学", "High",
    "AES.MODE_ECB 模式", "cipher.encrypt(...)",
    "ECB 模式相同明文产生相同密文，泄露模式信息（如企鹅图），无完整性保护",
    "用 AES-GCM 或 AES-CBC + HMAC，IV 随机",
    cot_type="crypto_weakness",
)

add(
    """
from Crypto.Cipher import AES
import os

KEY = b'0123456789abcdef0123456789abcdef'

def encrypt(data):
    iv = os.urandom(12)
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(data.encode())
    return iv + ct + tag
""",
    "python", "distill_280.py",
    False, "none", "None",
    "AES.MODE_GCM + os.urandom IV", "cipher.encrypt_and_digest(...)",
    "GCM 模式提供机密性 + 完整性，IV 用 os.urandom 生成",
    "no fix needed",
)

add(
    """
import java.util.Random;

public class TokenGen {
    public String genToken() {
        Random r = new Random();  // 非安全随机
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            sb.append((char) ('a' + r.nextInt(26)));
        }
        return sb.toString();
    }
}
""",
    "java", "distill_281.java",
    True, "CWE-327 弱密码学", "Critical",
    "new Random() 非安全随机", "r.nextInt(26)",
    "java.util.Random 用 LCG 算法，种子可推断；token 可预测",
    "用 SecureRandom.getInstanceStrong()",
    cot_type="crypto_weakness",
)

add(
    """
import java.security.SecureRandom;

public class TokenGen {
    private static final SecureRandom RNG = new SecureRandom();

    public String genToken() {
        byte[] buf = new byte[32];
        RNG.nextBytes(buf);
        StringBuilder sb = new StringBuilder();
        for (byte b : buf) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
""",
    "java", "distill_282.java",
    False, "none", "None",
    "SecureRandom.nextBytes", "RNG.nextBytes(buf)",
    "SecureRandom 用 OS 提供的熵源，输出不可预测",
    "no fix needed",
)

add(
    """
package main

import (
    "crypto/md5"
    "encoding/hex"
)

func hashPassword(password string) string {
    h := md5.Sum([]byte(password))
    return hex.EncodeToString(h[:])
}
""",
    "go", "distill_283.go",
    True, "CWE-327 弱密码学", "High",
    "md5.Sum(password)", "hex.EncodeToString(...)",
    "MD5 无 salt 且已被破解，不适用于密码存储",
    "用 golang.org/x/crypto/bcrypt 或 argon2id",
    cot_type="crypto_weakness",
)

add(
    """
package main

import (
    "crypto/sha256"
    "encoding/hex"
    "crypto/rand"
)

func hashPassword(password string) string {
    salt := make([]byte, 16)
    rand.Read(salt)
    h := sha256.New()
    h.Write(salt)
    h.Write([]byte(password))
    return hex.EncodeToString(salt) + ":" + hex.EncodeToString(h.Sum(nil))
}
""",
    "go", "distill_284.go",
    False, "none", "None",
    "sha256 + crypto/rand salt", "h.Sum(nil)",
    "SHA-256 加随机 salt（注意：仍应优先用 bcrypt/argon2 抗 GPU 暴破）",
    "no fix needed",
)

add(
    """
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

KEY = b'0123456789abcdef'
IV = b'fixediv012345678'  # 固定 IV

def encrypt(data):
    cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)
    return cipher.encrypt(pad(data.encode(), AES.block_size))
""",
    "python", "distill_285.py",
    True, "CWE-327 弱密码学", "High",
    "IV = b'fixediv012345678' 固定", "cipher.encrypt(...)",
    "CBC 模式固定 IV，相同明文产生相同首块密文，可被频率分析",
    "每次加密用 os.urandom(16) 生成随机 IV",
    cot_type="crypto_weakness",
)

add(
    """
const jwt = require('jsonwebtoken');

// alg=none 绕过签名校验
function verifyToken(token) {
    return jwt.verify(token, null, {algorithms: ['none']});
}
""",
    "javascript", "distill_286.js",
    True, "CWE-327 弱密码学", "Critical",
    "algorithms: ['none']", "jwt.verify(token, null, ...)",
    "JWT 允许 alg=none 时签名段为空，攻击者可伪造任意 payload",
    "明确指定 algorithms: ['HS256', 'RS256']，禁止 'none'",
    cot_type="crypto_weakness",
)

add(
    """
// CVE-2020-28061: 旧版 Java BC 库 RSA/ECDH 弱曲线
import java.security.*;
import java.security.spec.*;

public class KeyUtil {
    public PublicKey loadKey(String pem) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        // 旧版 BC 接受 512-bit RSA 密钥
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decodeBase64(pem));
        return kf.generatePublic(spec);
    }
}
""",
    "java", "distill_287.java",
    True, "CWE-327 弱密码学", "Critical",
    "KeyFactory RSA 接受 512-bit", "kf.generatePublic(spec)",
    "旧版 BouncyCastle 接受 512-bit RSA 密钥，已可被 GNFS 在数小时内分解",
    "升级 BC 到最新版；强制 RSA >= 2048-bit；优先用 ECDSA P-256",
    cot_type="crypto_weakness",
)

add(
    """
# RSA 密钥过短（512-bit）
from Crypto.PublicKey import RSA

key = RSA.generate(512)  # 512-bit 已可被分解
cipher = PKCS1_v1_5.new(key)
""",
    "python", "distill_288.py",
    True, "CWE-327 弱密码学", "Critical",
    "RSA.generate(512)", "PKCS1_v1_5.new(key)",
    "512-bit RSA 已可在数小时内分解，不安全",
    "用 RSA.generate(2048) 或更高；优先用 ECDSA",
    cot_type="crypto_weakness",
)

# ===========================================================================
# 16. CWE-209 信息泄露（16 条）
# ===========================================================================

add(
    """
from flask import Flask
app = Flask(__name__)

@app.route('/api/users/<id>')
def get_user(id):
    try:
        user = db.get_user(id)
    except Exception as e:
        return str(e), 500  # 完整异常堆栈返回给客户端
""",
    "python", "distill_289.py",
    True, "CWE-209 信息泄露", "Medium",
    "str(e) 异常信息", "return str(e), 500",
    "异常字符串含数据库表名、SQL 语句、文件路径等内部信息，泄露给客户端便于攻击者侦察",
    "log.exception(e) + 返回 'internal error'",
    cot_type="info_disclosure",
)

add(
    """
from flask import Flask
import logging
app = Flask(__name__)
logger = logging.getLogger(__name__)

@app.route('/api/users/<id>')
def get_user(id):
    try:
        user = db.get_user(id)
    except Exception as e:
        logger.exception("get_user failed")
        return 'internal error', 500
""",
    "python", "distill_290.py",
    False, "none", "None",
    "logger.exception + 通用错误消息", "return 'internal error', 500",
    "异常详情记日志，客户端只看到通用错误",
    "no fix needed",
)

add(
    """
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    @GetMapping("/api/users/{id}")
    public User getUser(@PathVariable Long id) {
        try {
            return userService.findById(id);
        } catch (Exception e) {
            throw new ResponseStatusException(500, e.getMessage());  // 异常消息泄露
        }
    }
}
""",
    "java", "distill_291.java",
    True, "CWE-209 信息泄露", "Medium",
    "e.getMessage() 返回客户端", "throw new ResponseStatusException(500, e.getMessage())",
    "异常 message 含数据库错误/内部路径，泄露给客户端",
    "logger.error(e) + throw new ResponseStatusException(500, \"internal error\")",
    cot_type="info_disclosure",
)

add(
    """
import org.springframework.web.bind.annotation.*;
import org.slf4j.*;

@RestController
public class UserController {
    private static final Logger log = LoggerFactory.getLogger(UserController.class);

    @GetMapping("/api/users/{id}")
    public User getUser(@PathVariable Long id) {
        try {
            return userService.findById(id);
        } catch (Exception e) {
            log.error("getUser failed for id={}", id, e);
            throw new ResponseStatusException(500, "internal error");
        }
    }
}
""",
    "java", "distill_292.java",
    False, "none", "None",
    "log.error + 通用错误消息", "throw new ResponseStatusException(500, 'internal error')",
    "异常详情记日志，客户端只看到 'internal error'",
    "no fix needed",
)

add(
    """
const express = require('express');
const app = express();

app.get('/api/users/:id', (req, res) => {
    db.query('SELECT * FROM users WHERE id = ?', [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({error: err.stack});
        res.json(rows[0]);
    });
});
""",
    "javascript", "distill_293.js",
    True, "CWE-209 信息泄露", "Medium",
    "err.stack 返回客户端", "res.json({error: err.stack})",
    "err.stack 含文件路径、行号、SQL 语句，泄露内部结构",
    "console.error(err) + res.status(500).json({error: 'internal error'})",
    cot_type="info_disclosure",
)

add(
    """
const express = require('express');
const app = express();

app.get('/api/users/:id', (req, res) => {
    db.query('SELECT * FROM users WHERE id = ?', [req.params.id], (err, rows) => {
        if (err) {
            console.error('query failed:', err);
            return res.status(500).json({error: 'internal error'});
        }
        res.json(rows[0]);
    });
});
""",
    "javascript", "distill_294.js",
    False, "none", "None",
    "console.error + 通用错误", "res.json({error: 'internal error'})",
    "err 记控制台，客户端只看到 'internal error'",
    "no fix needed",
)

add(
    """
<?php
// php.ini: display_errors = On
ini_set('display_errors', 1);
error_reporting(E_ALL);

$conn = mysqli_connect('localhost', 'app_user', 'pass', 'app');
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());  // 暴露 DB 信息
}
""",
    "php", "distill_295.php",
    True, "CWE-209 信息泄露", "High",
    "display_errors=On + mysqli_connect_error()", "die(...)",
    "PHP 错误直接输出到页面，含数据库主机名、用户名、错误细节",
    "display_errors=Off（生产）+ error_log 记日志 + 返回通用错误",
    cot_type="info_disclosure",
)

add(
    """
<?php
ini_set('display_errors', 0);
error_reporting(E_ALL);
ini_set('error_log', '/var/log/php_errors.log');

$conn = mysqli_connect('localhost', 'app_user', getenv('DB_PASS'), 'app');
if (!$conn) {
    error_log("DB connect failed: " . mysqli_connect_error());
    http_response_code(500);
    echo json_encode(['error' => 'internal error']);
    exit;
}
""",
    "php", "distill_296.php",
    False, "none", "None",
    "display_errors=Off + error_log", "echo json_encode(['error' => 'internal error'])",
    "错误记日志，客户端只看到 'internal error'",
    "no fix needed",
)

add(
    """
package main

import (
    "encoding/json"
    "net/http"
)

func getUserHandler(w http.ResponseWriter, r *http.Request) {
    // panic 直接暴露给客户端
    user := db.GetUser(r.URL.Query().Get("id"))
    json.NewEncoder(w).Encode(user)
}

func main() {
    http.HandleFunc("/api/user", getUserHandler)
    http.ListenAndServe(":8080", nil)
}
""",
    "go", "distill_297.go",
    True, "CWE-209 信息泄露", "Medium",
    "panic 未 recover", "json.NewEncoder(w).Encode(user)",
    "Go HTTP handler 未 recover panic，net/http 默认输出堆栈到响应，泄露文件路径和行号",
    "用 middleware recover panic 并返回 500 通用错误",
    cot_type="info_disclosure",
)

add(
    """
package main

import (
    "encoding/json"
    "log"
    "net/http"
)

func recoverMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if rec := recover(); rec != nil {
                log.Printf("panic: %v", rec)
                http.Error(w, "internal error", http.StatusInternalServerError)
            }
        }()
        next(w, r)
    }
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
    user := db.GetUser(r.URL.Query().Get("id"))
    json.NewEncoder(w).Encode(user)
}

func main() {
    http.HandleFunc("/api/user", recoverMiddleware(getUserHandler))
    http.ListenAndServe(":8080", nil)
}
""",
    "go", "distill_298.go",
    False, "none", "None",
    "recoverMiddleware + log.Printf", "http.Error(w, 'internal error', 500)",
    "中间件 recover panic 并记日志，客户端只看到 'internal error'",
    "no fix needed",
)

add(
    """
# Flask 生产环境开 debug
from flask import Flask
app = Flask(__name__)
app.config['DEBUG'] = True  # 生产环境开 debug

@app.route('/api/users/<id>')
def get_user(id):
    return db.get_user(id)
""",
    "python", "distill_299.py",
    True, "CWE-209 信息泄露", "Critical",
    "app.config['DEBUG'] = True", "db.get_user(id)",
    "Flask DEBUG 模式下，异常会触发 Werkzeug debugger，攻击者可执行任意代码（需 PIN）",
    "生产环境 DEBUG=False，用 app.run(debug=False)",
    cot_type="info_disclosure",
)

add(
    """
from flask import Flask
import logging
app = Flask(__name__)
app.config['DEBUG'] = False
app.config['PROPAGATE_EXCEPTIONS'] = False
logging.basicConfig(level=logging.INFO)

@app.route('/api/users/<id>')
def get_user(id):
    try:
        return db.get_user(id)
    except Exception as e:
        app.logger.exception("get_user failed")
        return 'internal error', 500
""",
    "python", "distill_300.py",
    False, "none", "None",
    "DEBUG=False + logger.exception", "return 'internal error', 500",
    "DEBUG=False 关闭 Werkzeug debugger，异常记日志",
    "no fix needed",
)

add(
    """
// SQL 异常细节直接返回（绕过变体）
import java.sql.*;

@RestController
public class SearchController {
    @GetMapping("/search")
    public String search(@RequestParam String q) {
        try (Connection c = dataSource.getConnection();
             Statement s = c.createStatement()) {
            ResultSet rs = s.executeQuery("SELECT * FROM products WHERE name LIKE '%" + q + "%'");
            // ...
        } catch (SQLException e) {
            return "DB error: " + e.getMessage();  // 泄露表名/列名
        }
    }
}
""",
    "java", "distill_301.java",
    True, "CWE-209 信息泄露", "High",
    "SQLException.getMessage() 返回客户端", "return 'DB error: ' + e.getMessage()",
    "SQLException message 含表名、列名、SQL 语法错误细节，便于 SQL 注入侦察",
    "logger.error(e) + return 'internal error'",
    cot_type="info_disclosure",
)

add(
    """
// API 返回详细字段级错误（绕过变体）
const express = require('express');
const app = express();

app.post('/api/register', (req, res) => {
    const {username, email, password} = req.body;
    const errors = [];
    if (!username) errors.push({field: 'username', msg: 'required', db_column: 'users.username'});
    if (!email) errors.push({field: 'email', msg: 'required', regex: '^[^@]+@[^@]+$'});
    if (!password) errors.push({field: 'password', msg: 'required', min_length: 8});
    if (errors.length) return res.status(400).json({errors, internal_query: 'INSERT INTO users...'});
    // ...
});
""",
    "javascript", "distill_302.js",
    True, "CWE-209 信息泄露", "Medium",
    "internal_query + db_column 返回客户端", "res.json({errors, internal_query})",
    "API 错误返回数据库列名和内部 SQL，便于攻击者构造注入",
    "只返回 {field, msg} 通用错误，internal 信息记日志",
    cot_type="info_disclosure",
)

add(
    """
<?php
// phpinfo.php —— 生产环境暴露
phpinfo();
""",
    "php", "distill_303.php",
    True, "CWE-209 信息泄露", "Critical",
    "phpinfo() 输出到页面", "phpinfo()",
    "phpinfo() 暴露 PHP 版本、扩展、配置路径、$_SERVER 环境变量，便于攻击者侦察",
    "删除 phpinfo.php 或限制 IP 访问；生产环境禁用",
    cot_type="info_disclosure",
)

add(
    """
# 异常消息含文件路径（绕过变体）
import os
from flask import Flask, send_file
app = Flask(__name__)

@app.route('/download/<filename>')
def download(filename):
    path = '/var/www/app/files/' + filename
    if not os.path.exists(path):
        return f"File not found: {path}", 404  # 泄露服务器绝对路径
    return send_file(path)
""",
    "python", "distill_304.py",
    True, "CWE-209 信息泄露", "Medium",
    "f'File not found: {path}'", "return f'File not found: {path}', 404",
    "404 错误返回服务器绝对路径 /var/www/app/files/，便于攻击者构造路径遍历",
    "log.warning(path) + return 'file not found', 404",
    cot_type="info_disclosure",
)

# ===========================================================================
# 17. CWE-362 竞态条件（10 条）
# ===========================================================================

add(
    """
import os

def use_temp_file(path):
    if not os.path.exists(path):  # check
        with open(path, 'w') as f:  # use
            f.write('temp data')
""",
    "python", "distill_305.py",
    True, "CWE-362 竞态条件", "High",
    "os.path.exists + open(path, 'w')", "open(path, 'w').write(...)",
    "TOCTOU：检查与打开之间存在时间窗口，攻击者可创建符号链接指向敏感文件",
    "用 os.open(path, O_CREAT|O_EXCL, 0o600) 原子创建",
    cot_type="race_condition",
)

add(
    """
import os
import fcntl

def use_temp_file(path):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with os.fdopen(fd, 'w') as f:
            f.write('temp data')
    except OSError:
        # 文件已存在
        pass
""",
    "python", "distill_306.py",
    False, "none", "None",
    "O_CREAT|O_EXCL 原子创建 + flock", "f.write('temp data')",
    "O_EXCL 保证原子创建，flock 加文件锁防并发写",
    "no fix needed",
)

add(
    """
// Java check-then-act：余额检查与扣款之间无锁
public class TransferService {
    public boolean transfer(Account from, Account to, BigDecimal amount) {
        if (from.getBalance().compareTo(amount) >= 0) {
            from.debit(amount);
            to.credit(amount);
            return true;
        }
        return false;
    }
}
""",
    "java", "distill_307.java",
    True, "CWE-362 竞态条件", "High",
    "getBalance 检查 + debit 扣款（无锁）", "from.debit(amount)",
    "并发转账时两线程都通过余额检查，双双 debit → 透支/双重消费",
    "用 synchronized 或显式 Lock 锁 from+to 账户，或用 DB 事务 SELECT FOR UPDATE",
    cot_type="race_condition",
)

add(
    """
import java.util.concurrent.locks.ReentrantLock;
import java.math.BigDecimal;

public class TransferService {
    private final ReentrantLock lock = new ReentrantLock();

    public boolean transfer(Account from, Account to, BigDecimal amount) {
        lock.lock();
        try {
            if (from.getBalance().compareTo(amount) >= 0) {
                from.debit(amount);
                to.credit(amount);
                return true;
            }
            return false;
        } finally {
            lock.unlock();
        }
    }
}
""",
    "java", "distill_308.java",
    False, "none", "None",
    "ReentrantLock.lock()", "from.debit(amount)",
    "显式锁保护 check-then-act，避免并发转账竞态",
    "no fix needed",
)

add(
    """
// JS 异步竞态：两次请求同时读取再更新库存
const express = require('express');
const app = express();

app.post('/api/order/:id', async (req, res) => {
    const product = await db.getProduct(req.params.id);
    if (product.stock > 0) {
        // 并发下两请求都进入此分支
        await db.updateStock(req.params.id, product.stock - 1);
        res.json({status: 'ordered'});
    } else {
        res.status(400).json({error: 'out of stock'});
    }
});
""",
    "javascript", "distill_309.js",
    True, "CWE-362 竞态条件", "High",
    "getProduct + updateStock（无事务）", "db.updateStock(..., product.stock - 1)",
    "并发下单：两请求同时读 stock=1，都通过检查，updateStock 写 0 而非 -1，超卖",
    "用 DB 原子 UPDATE stock = stock - 1 WHERE stock > 0 或 SELECT FOR UPDATE 事务",
    cot_type="race_condition",
)

add(
    """
const express = require('express');
const app = express();

app.post('/api/order/:id', async (req, res) => {
    const result = await db.query(
        'UPDATE products SET stock = stock - 1 WHERE id = ? AND stock > 0',
        [req.params.id]
    );
    if (result.affectedRows > 0) {
        res.json({status: 'ordered'});
    } else {
        res.status(400).json({error: 'out of stock'});
    }
});
""",
    "javascript", "distill_310.js",
    False, "none", "None",
    "原子 UPDATE ... WHERE stock > 0", "db.query('UPDATE ...')",
    "DB 原子 UPDATE 在 WHERE 中检查 stock > 0，避免 TOCTOU",
    "no fix needed",
)

add(
    """
package main

import (
    "net/http"
)

var couponUsed = make(map[string]bool)

func useCouponHandler(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    if !couponUsed[code] {  // check
        couponUsed[code] = true  // use
        // 发放优惠
        w.Write([]byte("coupon applied"))
    } else {
        http.Error(w, "already used", http.StatusBadRequest)
    }
}
""",
    "go", "distill_311.go",
    True, "CWE-362 竞态条件", "High",
    "map 读写无锁（check-then-set）", "couponUsed[code] = true",
    "并发请求读取 couponUsed[code]=false 都通过检查，重复发放优惠",
    "用 sync.Mutex 或 sync.Map.LoadOrStore 原子操作",
    cot_type="race_condition",
)

add(
    """
package main

import (
    "net/http"
    "sync"
)

var (
    couponUsed = make(map[string]bool)
    mu         sync.Mutex
)

func useCouponHandler(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    mu.Lock()
    defer mu.Unlock()
    if !couponUsed[code] {
        couponUsed[code] = true
        w.Write([]byte("coupon applied"))
    } else {
        http.Error(w, "already used", http.StatusBadRequest)
    }
}
""",
    "go", "distill_312.go",
    False, "none", "None",
    "sync.Mutex.Lock()", "couponUsed[code] = true",
    "Mutex 保护 map 读写，避免 check-then-set 竞态",
    "no fix needed",
)

add(
    """
# Django ORM select 相关竞态（绕过变体）
from django.db import models

class Coupon(models.Model):
    code = models.CharField(unique=True)
    used = models.BooleanField(default=False)

def use_coupon(request, code):
    coupon = Coupon.objects.get(code=code)
    if not coupon.used:  # check
        coupon.used = True  # use
        coupon.save()  # 默认 save 不带 WHERE used=False
        return HttpResponse('applied')
    return HttpResponse('used', status=400)
""",
    "python", "distill_313.py",
    True, "CWE-362 竞态条件", "High",
    "get + save（无 select_for_update）", "coupon.save()",
    "Django 默认 save() 不带乐观锁，并发请求都读到 used=False 后都 save，重复使用",
    "用 Coupon.objects.select_for_update().get(code=code) 或 filter(used=False).update(used=True)",
    cot_type="race_condition",
)

add(
    """
// CVE-2019-xxxx: Java 并发 HashMap 导致死循环
import java.util.*;

public class Cache {
    private static final Map<String, String> CACHE = new HashMap<>();

    public static String get(String key) {
        String val = CACHE.get(key);
        if (val == null) {
            val = loadFromDB(key);
            CACHE.put(key, val);  // 并发 put 触发 resize → 死循环
        }
        return val;
    }
}
""",
    "java", "distill_314.java",
    True, "CWE-362 竞态条件", "Critical",
    "HashMap 并发 put（无锁）", "CACHE.put(key, val)",
    "JDK7 HashMap 多线程 put 触发 resize 死循环；JDK8+ 数据丢失；均不安全",
    "用 ConcurrentHashMap 或 Collections.synchronizedMap",
    cot_type="race_condition",
)

# ===========================================================================
# 18. CWE-918 SSRF（16 条）
# ===========================================================================

add(
    """
import requests
from flask import Flask, request, Response

app = Flask(__name__)

@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    resp = requests.get(url)
    return Response(resp.content, status=resp.status_code)
""",
    "python", "distill_315.py",
    True, "CWE-918 SSRF", "Critical",
    "request.args.get('url') 直接代理", "requests.get(url)",
    "用户控制的 URL 直接由服务端请求，可访问 169.254.169.254 元数据、127.0.0.1 内网、file://",
    "校验 URL scheme/host，禁止内网 IP 和 file/gopher 协议",
    cot_type="source_sink",
)

add(
    """
import requests
from flask import Flask, request, Response
from urllib.parse import urlparse
import ipaddress

app = Flask(__name__)

ALLOWED_SCHEMES = {'http', 'https'}

def is_safe_url(url):
    p = urlparse(url)
    if p.scheme not in ALLOWED_SCHEMES or not p.hostname:
        return False
    try:
        ip = ipaddress.ip_address(p.hostname)
        if ip.is_private or ip.is_loopback or ip.is_reserved:
            return False
    except ValueError:
        pass  # 域名，做 DNS 解析后再次校验
    return True

@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    if not is_safe_url(url):
        return 'forbidden', 403
    resp = requests.get(url, timeout=5, allow_redirects=False)
    return Response(resp.content, status=resp.status_code)
""",
    "python", "distill_316.py",
    False, "none", "None",
    "is_safe_url 校验 scheme + 内网 IP", "requests.get(url, allow_redirects=False)",
    "校验 scheme 白名单 + 私网/回环 IP 拒绝 + 禁用重定向",
    "no fix needed",
)

add(
    """
import java.net.*;
import java.io.*;

public class ProxyService {
    public String fetch(String targetUrl) throws Exception {
        URL url = new URL(targetUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(5000);
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            return sb.toString();
        }
    }
}
""",
    "java", "distill_317.java",
    True, "CWE-918 SSRF", "Critical",
    "new URL(targetUrl) 无校验", "url.openConnection()",
    "Java HttpURLConnection 直接用用户 URL，可访问内网/元数据",
    "校验 URL host 白名单 + InetAddress.getByName 检查非内网",
    cot_type="source_sink",
)

add(
    """
import java.net.*;
import java.io.*;
import java.util.*;

public class ProxyService {
    private static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com", "cdn.example.com");

    public String fetch(String targetUrl) throws Exception {
        URL url = new URL(targetUrl);
        if (!url.getProtocol().matches("https?") || !ALLOWED_HOSTS.contains(url.getHost())) {
            throw new IllegalArgumentException("URL not allowed");
        }
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(5000);
        conn.setInstanceFollowRedirects(false);
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            return sb.toString();
        }
    }
}
""",
    "java", "distill_318.java",
    False, "none", "None",
    "ALLOWED_HOSTS 白名单 + 禁用重定向", "url.openConnection()",
    "host 白名单 + scheme 校验 + 禁用重定向",
    "no fix needed",
)

add(
    """
const axios = require('axios');
const express = require('express');
const app = express();

app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    const resp = await axios.get(url);
    res.json(resp.data);
});
""",
    "javascript", "distill_319.js",
    True, "CWE-918 SSRF", "Critical",
    "req.query.url 直接 axios.get", "axios.get(url)",
    "用户控制的 URL 直接被 axios 请求，可访问内网/元数据",
    "校验 URL scheme/host 白名单 + DNS 解析检查私网 IP",
    cot_type="source_sink",
)

add(
    """
const axios = require('axios');
const express = require('express');
const dns = require('dns').promises;
const net = require('net');
const app = express();

async function isSafeUrl(url) {
    const u = new URL(url);
    if (!['http:', 'https:'].includes(u.protocol)) return false;
    const addrs = await dns.resolve4(u.hostname);
    for (const ip of addrs) {
        if (net.isIP(ip) && (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.') || ip.startsWith('169.254.'))) {
            return false;
        }
    }
    return true;
}

app.get('/fetch', async (req, res) => {
    try {
        if (!await isSafeUrl(req.query.url)) return res.status(403).json({error: 'forbidden'});
        const resp = await axios.get(req.query.url, {maxRedirects: 0, timeout: 5000});
        res.json(resp.data);
    } catch (e) {
        res.status(500).json({error: 'internal error'});
    }
});
""",
    "javascript", "distill_320.js",
    False, "none", "None",
    "isSafeUrl + DNS 解析检查私网", "axios.get(url, {maxRedirects:0})",
    "校验 scheme + DNS 解析后检查非私网 IP + 禁用重定向",
    "no fix needed",
)

add(
    """
<?php
$url = $_GET['url'];
$data = file_get_contents($url);
echo $data;
""",
    "php", "distill_321.php",
    True, "CWE-918 SSRF", "Critical",
    "$_GET['url'] 直接 file_get_contents", "file_get_contents($url)",
    "PHP file_get_contents 支持 http/https/file/ftp 协议封装，可读内网/本地文件",
    "校验 URL scheme/host 白名单，禁用 file:// 和 gopher://",
    cot_type="source_sink",
)

add(
    """
<?php
$ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com'];
$url = $_GET['url'];
$parsed = parse_url($url);
if (!in_array($parsed['scheme'] ?? '', ['http', 'https']) ||
    !in_array($parsed['host'] ?? '', $ALLOWED_HOSTS)) {
    http_response_code(403);
    echo 'forbidden';
    exit;
}
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
curl_setopt($ch, CURLOPT_TIMEOUT, 5);
curl_exec($ch);
curl_close($ch);
""",
    "php", "distill_322.php",
    False, "none", "None",
    "host 白名单 + curl 禁用重定向", "curl_exec($ch)",
    "校验 scheme + host 白名单 + curl 禁用重定向",
    "no fix needed",
)

add(
    """
package main

import (
    "io"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    target := r.URL.Query().Get("url")
    resp, err := http.Get(target)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    defer resp.Body.Close()
    io.Copy(w, resp.Body)
}
""",
    "go", "distill_323.go",
    True, "CWE-918 SSRF", "Critical",
    "http.Get(target) 无校验", "io.Copy(w, resp.Body)",
    "Go http.Get 直接用用户 URL，可访问内网/元数据",
    "校验 URL scheme/host + 自定义 Dialer 拦截内网 IP",
    cot_type="source_sink",
)

add(
    """
package main

import (
    "io"
    "net"
    "net/http"
    "time"
)

var safeClient = &http.Client{
    Timeout: 5 * time.Second,
    Transport: &http.Transport{
        DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
            host, port, _ := net.SplitHostPort(addr)
            ips, _ := net.LookupIP(host)
            for _, ip := range ips {
                if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
                    return nil, fmt.Errorf("blocked: %s", ip)
                }
            }
            return (&net.Dialer{}).DialContext(ctx, network, addr)
        },
    },
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
        return http.ErrUseLastResponse  // 禁用重定向
    },
}
""",
    "go", "distill_324.go",
    False, "none", "None",
    "DialContext 拦截内网 IP + 禁用重定向", "safeClient.Get(url)",
    "自定义 Dialer 在建立连接前检查目标 IP，拒绝内网/回环",
    "no fix needed",
)

add(
    """
# AWS EC2 metadata SSRF（绕过变体）
import requests
from flask import Flask, request, Response

app = Flask(__name__)

@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    # 即使 host 白名单也易被 DNS rebinding 绕过
    resp = requests.get(url, allow_redirects=False)
    # 攻击者传 http://169.254.169.254/latest/meta-data/iam/security-credentials/
    return Response(resp.content)
""",
    "python", "distill_325.py",
    True, "CWE-918 SSRF", "Critical",
    "169.254.169.254 元数据服务", "requests.get(url)",
    "AWS/阿里云元数据服务可通过 SSRF 直接访问，泄露 IAM 临时凭证",
    "校验目标 IP 非链路本地段 169.254.0.0/16 + IMDSv2 强制 token",
    cot_type="source_sink",
)

add(
    """
// Java HTTP 重定向 SSRF（绕过变体）
import java.net.*;

public class ProxyService {
    public String fetch(String targetUrl) throws Exception {
        URL url = new URL(targetUrl);
        // 校验了初始 host，但 HttpURLConnection 默认跟随重定向
        if (!url.getHost().equals("api.example.com")) {
            throw new IllegalArgumentException("forbidden");
        }
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(true);  // 默认 true
        // 攻击者用 api.example.com → 302 → http://169.254.169.254/
        return readAll(conn.getInputStream());
    }
}
""",
    "java", "distill_326.java",
    True, "CWE-918 SSRF", "Critical",
    "setInstanceFollowRedirects(true) 跟随重定向", "conn.getInputStream()",
    "校验初始 host 但跟随重定向，攻击者用 302 重定向到内网/元数据",
    "setInstanceFollowRedirects(false) + 手动校验每个重定向目标",
    cot_type="source_sink",
)

add(
    """
// DNS rebinding SSRF（绕过变体）
const axios = require('axios');
const express = require('express');
const app = express();

async function fetchUrl(url) {
    const u = new URL(url);
    // 第一次 DNS 解析返回公网 IP（通过校验）
    const ips = await dns.resolve4(u.hostname);
    if (ips.some(ip => ip.startsWith('10.') || ip.startsWith('127.'))) {
        throw new Error('forbidden');
    }
    // 但 axios 发请求时再次 DNS 解析，TTL 过期后返回内网 IP
    return axios.get(url);
}
""",
    "javascript", "distill_327.js",
    True, "CWE-918 SSRF", "Critical",
    "校验与请求之间 DNS rebinding", "axios.get(url)",
    "校验时 DNS 返回公网 IP，请求时 DNS 返回内网 IP（TTL=0 rebinding）",
    "解析 DNS 后用 IP 直连，禁止 axios 再次 DNS；或用自定义 lookup 缓存",
    cot_type="source_sink",
)

add(
    """
# CVE-2021-3178: Python urllib 本地文件读取 SSRF
from urllib.request import urlopen
from flask import Flask, request, Response

app = Flask(__name__)

@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    # urllib 支持 file:// 协议
    with urlopen(url) as resp:
        return Response(resp.read())
""",
    "python", "distill_328.py",
    True, "CWE-918 SSRF", "Critical",
    "urlopen(url) 支持 file://", "resp.read()",
    "Python urllib.urlopen 默认支持 file:// 协议，攻击者可读 /etc/passwd 等本地文件",
    "校验 URL scheme 仅允许 http/https，禁用 file/ftp/gopher",
    cot_type="source_sink",
)

add(
    """
// Java Webhook SSRF（典型变体）
@RestController
@RequestMapping("/api/webhook")
public class WebhookController {
    @PostMapping("/register")
    public String register(@RequestBody WebhookConfig config) {
        // config.url 由用户提供，用于事件回调
        // 注册时立即 ping 一次
        URL url = new URL(config.getUrl());
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.getResponseCode();
        webhookRepository.save(config);
        return "registered";
    }
}
""",
    "java", "distill_329.java",
    True, "CWE-918 SSRF", "Critical",
    "Webhook URL 用户可控 + 服务端 ping", "url.openConnection()",
    "Webhook 注册功能允许用户指定 URL，服务端主动 ping 验证可达性，可被用于 SSRF",
    "Webhook URL 加白名单 + DNS 解析校验 + 用户验证（如 challenge token）",
    cot_type="source_sink",
)

add(
    """
# Python SSRF 安全版：DNS 解析后用 IP 直连
import requests
from urllib.parse import urlparse
import socket
import ipaddress

def safe_get(url):
    p = urlparse(url)
    if p.scheme not in ('http', 'https'):
        raise ValueError('scheme not allowed')
    # 解析 DNS
    addrs = socket.getaddrinfo(p.hostname, None)
    for family, _, _, _, sockaddr in addrs:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError('internal IP blocked')
    # 用解析的 IP 直连，Host 头保留原域名
    ip = addrs[0][4][0]
    target = url.replace(p.hostname, ip)
    return requests.get(target, headers={'Host': p.hostname},
                       timeout=5, allow_redirects=False)
""",
    "python", "distill_330.py",
    False, "none", "None",
    "getaddrinfo + IP 直连防 rebinding", "requests.get(target, ...)",
    "DNS 解析后用 IP 直连 + Host 头保留域名，避免 DNS rebinding",
    "no fix needed",
)

# ===========================================================================
# 19. CWE-73 外部控制文件名/路径（10 条）
# ===========================================================================

add(
    """
import pickle

def load_template(request):
    path = request.GET.get('template', 'default.pkl')
    with open('/srv/templates/' + path, 'rb') as f:
        return pickle.load(f)
""",
    "python", "distill_331.py",
    True, "CWE-73 外部控制文件路径", "Critical",
    "request.GET.get('template') 拼接路径 + pickle.load", "pickle.load(f)",
    "用户控制 template 路径，可加载任意 .pkl 文件触发 pickle 反序列化 RCE",
    "用白名单 {name: file_path} 映射，禁止用户直接控制路径",
    cot_type="source_sink",
)

add(
    """
import pickle

TEMPLATE_MAP = {
    'welcome': '/srv/templates/welcome.pkl',
    'invoice': '/srv/templates/invoice.pkl',
}

def load_template(request):
    name = request.GET.get('template', 'welcome')
    path = TEMPLATE_MAP.get(name)
    if not path:
        raise ValueError('unknown template')
    with open(path, 'rb') as f:
        return pickle.load(f)
""",
    "python", "distill_332.py",
    False, "none", "None",
    "TEMPLATE_MAP 白名单映射", "pickle.load(f)",
    "用预定义映射表，用户只能选 name 不能直接控制路径",
    "no fix needed",
)

add(
    """
import java.io.*;

public class TemplateLoader {
    public Object load(String path) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(path))) {
            return ois.readObject();
        }
    }
}
""",
    "java", "distill_333.java",
    True, "CWE-73 外部控制文件路径", "Critical",
    "new FileInputStream(path) 用户控制", "ois.readObject()",
    "Java ObjectInputStream 从用户指定路径加载，可反序列化任意类触发 RCE",
    "用白名单 Path.normalize() + 起始目录校验 + ObjectInputFilter",
    cot_type="source_sink",
)

add(
    """
import java.io.*;
import java.nio.file.*;

public class TemplateLoader {
    private static final Path BASE = Paths.get("/srv/templates").normalize().toAbsolutePath();

    public Object load(String name) throws Exception {
        Path resolved = BASE.resolve(name).normalize();
        if (!resolved.startsWith(BASE)) {
            throw new SecurityException("path traversal");
        }
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(resolved.toFile()))) {
            return ois.readObject();
        }
    }
}
""",
    "java", "distill_334.java",
    False, "none", "None",
    "BASE.resolve + startsWith 校验", "ois.readObject()",
    "Path.normalize + startsWith 防止路径遍历，限制在 BASE 目录内",
    "no fix needed",
)

add(
    """
const fs = require('fs');
const path = require('path');

app.get('/api/module', (req, res) => {
    const modName = req.query.module;
    // require 用户控制的模块路径
    const mod = require(path.join('/srv/modules', modName));
    res.json(mod.getInfo());
});
""",
    "javascript", "distill_335.js",
    True, "CWE-73 外部控制文件路径", "Critical",
    "require(path.join(..., modName))", "require(...)",
    "用户控制 modName，可 require 任意 JS 文件执行代码",
    "用白名单映射 {name: require(path)}，禁止用户直接控制 require 路径",
    cot_type="source_sink",
)

add(
    """
const fs = require('fs');
const path = require('path');

const MODULE_MAP = {
    'user': './modules/user',
    'order': './modules/order',
};

app.get('/api/module', (req, res) => {
    const modName = req.query.module;
    const modPath = MODULE_MAP[modName];
    if (!modPath) return res.status(400).json({error: 'unknown module'});
    const mod = require(modPath);
    res.json(mod.getInfo());
});
""",
    "javascript", "distill_336.js",
    False, "none", "None",
    "MODULE_MAP 白名单 + require(modPath)", "require(modPath)",
    "用预定义映射表，用户只能选 name 不能直接控制 require 路径",
    "no fix needed",
)

add(
    """
# Python importlib 动态导入用户模块
import importlib

def run_plugin(request):
    plugin_name = request.GET.get('plugin')
    mod = importlib.import_module('plugins.' + plugin_name)
    return mod.run()
""",
    "python", "distill_337.py",
    True, "CWE-73 外部控制文件路径", "Critical",
    "importlib.import_module(用户控制)", "mod.run()",
    "用户控制 plugin_name，可导入任意 Python 模块并执行 run()",
    "用白名单 {name: module_path} 或 importlib.import_module 固定前缀 + 校验",
    cot_type="source_sink",
)

add(
    """
# Python yaml.load 用户指定配置文件
import yaml

def load_config(request):
    config_path = request.GET.get('config', 'default.yml')
    with open('/srv/config/' + config_path) as f:
        return yaml.load(f, Loader=yaml.Loader)  # Loader 允许任意 Python 对象
""",
    "python", "distill_338.py",
    True, "CWE-73 外部控制文件路径", "Critical",
    "open('/srv/config/' + config_path) + yaml.Loader", "yaml.load(f, Loader=yaml.Loader)",
    "用户控制配置文件路径 + yaml.Loader 允许任意 Python 对象反序列化 → RCE",
    "用 yaml.safe_load + 白名单文件路径",
    cot_type="source_sink",
)

add(
    """
// C dlopen 用户指定共享库
#include <dlfcn.h>
#include <stdio.h>

int run_plugin(const char *plugin_path) {
    void *handle = dlopen(plugin_path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "%s\\n", dlerror());
        return -1;
    }
    void (*init)() = dlsym(handle, "plugin_init");
    if (init) init();
    return 0;
}
""",
    "c", "distill_339.c",
    True, "CWE-73 外部控制文件路径", "Critical",
    "dlopen(plugin_path) 用户控制", "dlsym(handle, 'plugin_init')()",
    "用户控制 plugin_path，可加载恶意 .so 执行 plugin_init() → RCE",
    "用白名单目录 + 校验 .so 文件签名/hash",
    cot_type="source_sink",
)

add(
    """
package main

import (
    "plugin"
)

func runPlugin(path string) error {
    p, err := plugin.Open(path)
    if err != nil {
        return err
    }
    sym, err := p.Lookup("Run")
    if err != nil {
        return err
    }
    sym.(func())()
    return nil
}
""",
    "go", "distill_340.go",
    True, "CWE-73 外部控制文件路径", "Critical",
    "plugin.Open(path) 用户控制", "sym.(func())()",
    "Go plugin.Open 加载用户指定 .so，执行 Run 函数 → RCE",
    "用白名单目录 + 校验 .so 文件签名",
    cot_type="source_sink",
)


# ===========================================================================
# CWE-98 PHP 文件包含 / LFI（10 条）
# ===========================================================================

add(
    """
<?php
$page = $_GET['page'];
include($page);
?>
""",
    "php", "distill_341.php",
    True, "CWE-98 文件包含(LFI)", "Critical",
    "$_GET['page'] 用户控制", "include($page)",
    "用户传入 page=../../etc/passwd → include 直接加载该文件 → 任意文件读取/RCE",
    "用白名单：$allowed=['home','about']; if(in_array($page,$allowed)){include($page.'.php');}",
    cot_type="source_sink",
)

add(
    """
<?php
$page = $_GET['page'] ?? 'home';
$allowed = ['home', 'about', 'contact'];
if (in_array($page, $allowed, true)) {
    include(__DIR__ . '/pages/' . $page . '.php');
} else {
    include(__DIR__ . '/pages/404.php');
}
?>
""",
    "php", "distill_342.php",
    False, "CWE-98 文件包含(LFI)", "None",
    "$_GET['page'] 用户输入", "include(固定目录+白名单名+'.php')",
    "白名单严格校验 + 固定目录 + 强制后缀，无法穿越",
    "无需修复",
    cot_type="source_sink",
)

add(
    """
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'guest')
    template = '<h1>Hello ' + name + '</h1>'
    return render_template_string(template)
""",
    "python", "distill_343.py",
    True, "CWE-98 SSTI/模板注入", "Critical",
    "request.args.get('name') 用户控制", "render_template_string(template)",
    "name 拼入模板字符串 → render_template_string 渲染 → {{7*7}} 等模板表达式被执行 → SSTI/RCE",
    "用 render_template 加载固定模板文件 + 通过 context 传变量，禁止拼接模板字符串",
    cot_type="source_sink",
)

add(
    """
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'guest')
    return render_template('greet.html', name=name)
""",
    "python", "distill_344.py",
    False, "CWE-98 SSTI/模板注入", "None",
    "request.args.get('name') 用户输入", "render_template('greet.html', name=name)",
    "name 作为 context 变量传入固定模板，模板引擎自动转义，无法注入模板表达式",
    "无需修复",
    cot_type="source_sink",
)

add(
    """
<?php
$module = $_REQUEST['module'];
$file = '/modules/' . $module . '.php';
require_once($file);
?>
""",
    "php", "distill_345.php",
    True, "CWE-98 文件包含(LFI)", "Critical",
    "$_REQUEST['module'] 用户控制", "require_once($file)",
    "module=../../etc/passwd%00 → require_once 加载任意文件 → LFI",
    "basename 过滤 + 白名单 + 关闭空字节（PHP 5.3+ 已禁用）",
    cot_type="source_sink",
)

add(
    """
<?php
$module = $_REQUEST['module'] ?? 'default';
$module = basename($module);
$allowed = ['default', 'user', 'admin'];
if (in_array($module, $allowed, true)) {
    require_once(__DIR__ . '/modules/' . $module . '.php');
}
?>
""",
    "php", "distill_346.php",
    False, "CWE-98 文件包含(LFI)", "None",
    "$_REQUEST['module'] 用户输入", "require_once(固定目录+basename+白名单+'.php')",
    "basename 去除路径 + 白名单 + 固定目录，无法穿越或空字节绕过",
    "无需修复",
    cot_type="source_sink",
)

add(
    """
const express = require('express');
const app = express();

app.get('/view', (req, res) => {
    const name = req.query.name;
    res.render(name);
});
""",
    "javascript", "distill_347.js",
    True, "CWE-98 路径穿越/模板注入", "High",
    "req.query.name 用户控制", "res.render(name)",
    "name=../secret/admin → res.render 加载 views 目录外模板 → 模板/文件泄露",
    "用白名单：const allowed=['home','about']; if(allowed.includes(name)) res.render(name)",
    cot_type="source_sink",
)

add(
    """
const express = require('express');
const app = express();

app.get('/view', (req, res) => {
    const name = req.query.name;
    const allowed = ['home', 'about', 'contact'];
    if (allowed.includes(name)) {
        res.render(name);
    } else {
        res.status(404).send('Not found');
    }
});
""",
    "javascript", "distill_348.js",
    False, "CWE-98 路径穿越/模板注入", "None",
    "req.query.name 用户输入", "res.render(白名单内 name)",
    "白名单校验，仅允许预定义模板名，无法穿越",
    "无需修复",
    cot_type="source_sink",
)

add(
    """
<?php
// CVE-style: 空字节截断绕过（PHP < 5.3.4）
$lang = $_GET['lang'];
$file = '/lang/' . $lang . '.php';
// 攻击者传入 lang=../../etc/passwd%00
include($file);
?>
""",
    "php", "distill_349.php",
    True, "CWE-98 文件包含(LFI)空字节绕过", "Critical",
    "$_GET['lang'] 用户控制（含 %00 空字节）", "include($file)",
    "lang=../../etc/passwd%00 → include 拼接后 .php 后缀被空字节截断 → 读取 /etc/passwd",
    "升级 PHP 版本 + basename + 白名单校验（旧版 PHP 空字节截断已知缺陷）",
    cot_type="source_sink",
)

add(
    """
import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PageServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        String page = req.getParameter("page");
        RequestDispatcher rd = req.getRequestDispatcher(page);
        try {
            rd.include(req, resp);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
""",
    "java", "distill_350.java",
    True, "CWE-98 服务端包含(LFI)", "High",
    "req.getParameter('page') 用户控制", "rd.include(req, resp)",
    "page=/WEB-INF/../../etc/passwd → RequestDispatcher 加载任意资源 → 信息泄露",
    "白名单：if(ALLOWED.contains(page)) rd.include(...)",
    cot_type="source_sink",
)


# ===========================================================================
# CWE-434 任意文件上传（14 条）
# ===========================================================================

add(
    """
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    save_path = os.path.join('/var/uploads', f.filename)
    f.save(save_path)
    return 'ok'
""",
    "python", "distill_351.py",
    True, "CWE-434 任意文件上传", "Critical",
    "request.files['file'].filename 用户控制", "f.save(save_path)",
    "filename=shell.php → 保存到 /var/uploads/shell.php → 访问执行 → RCE",
    "白名单后缀 + 重命名（uuid）+ 禁止执行权限",
    cot_type="source_sink",
)

add(
    """
from flask import Flask, request
import os
import uuid

app = Flask(__name__)
ALLOWED_EXT = {'.jpg', '.png', '.gif'}

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in ALLOWED_EXT:
        return 'invalid', 400
    save_name = uuid.uuid4().hex + ext
    f.save(os.path.join('/var/uploads', save_name))
    return 'ok'
""",
    "python", "distill_352.py",
    False, "CWE-434 任意文件上传", "None",
    "request.files['file'].filename 用户输入", "f.save(uuid + 白名单后缀)",
    "后缀白名单 + uuid 重命名 + 禁止原文件名，无法上传可执行文件",
    "无需修复",
    cot_type="source_sink",
)

add(
    """
import javax.servlet.http.*;
import javax.servlet.*;
import java.io.*;
import org.apache.commons.fileupload.*;
import org.apache.commons.fileupload.disk.*;
import org.apache.commons.fileupload.servlet.*;

public class UploadServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        boolean isMultipart = ServletFileUpload.isMultipartContent(req);
        if (isMultipart) {
            DiskFileItemFactory factory = new DiskFileItemFactory();
            ServletFileUpload upload = new ServletFileUpload(factory);
            try {
                java.util.List items = upload.parseRequest(req);
                for (Object o : items) {
                    FileItem item = (FileItem) o;
                    if (!item.isFormField()) {
                        String name = item.getName();
                        item.write(new File("/uploads/" + name));
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
""",
    "java", "distill_353.java",
    True, "CWE-434 任意文件上传", "Critical",
    "item.getName() 用户控制", "item.write(new File('/uploads/' + name))",
    "name=shell.jsp → 写入 /uploads/shell.jsp → 访问执行 → RCE",
    "白名单后缀 + UUID 重命名 + 禁止 .jsp/.war",
    cot_type="source_sink",
)

add(
    """
import javax.servlet.http.*;
import java.io.*;
import java.util.UUID;

public class SafeUploadServlet extends HttpServlet {
    private static final java.util.Set<String> ALLOWED =
        new java.util.HashSet<>(java.util.Arrays.asList(".jpg", ".png", ".gif"));

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        javax.servlet.http.Part part = req.getPart("file");
        String submitted = part.getSubmittedFileName();
        String ext = submitted.substring(submitted.lastIndexOf(".")).toLowerCase();
        if (!ALLOWED.contains(ext)) {
            resp.sendError(400, "invalid ext");
            return;
        }
        String safeName = UUID.randomUUID().toString() + ext;
        part.write("/uploads/" + safeName);
    }
}
""",
    "java", "distill_354.java",
    False, "CWE-434 任意文件上传", "None",
    "part.getSubmittedFileName() 用户输入", "part.write('/uploads/' + UUID + 白名单后缀)",
    "后缀白名单 + UUID 重命名，无法上传可执行文件",
    "无需修复",
    cot_type="source_sink",
)

add(
    """
const express = require('express');
const multer = require('multer');
const app = express();

const storage = multer.diskStorage({
    destination: '/var/uploads',
    filename: (req, file, cb) => cb(null, file.originalname)
});
const upload = multer({ storage });

app.post('/upload', upload.single('file'), (req, res) => {
    res.send('ok');
});
""",
    "javascript", "distill_355.js",
    True, "CWE-434 任意文件上传", "Critical",
    "file.originalname 用户控制", "cb(null, file.originalname) 保存原文件名",
    "originalname=shell.js → 保存到 /var/uploads/shell.js → require 执行 → RCE",
    "multer fileFilter 白名单 + 重命名",
    cot_type="source_sink",
)

add(
    """
const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const app = express();

const ALLOWED = ['.jpg', '.png', '.gif'];
const storage = multer.diskStorage({
    destination: '/var/uploads',
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        if (!ALLOWED.includes(ext)) return cb(new Error('invalid'));
        cb(null, crypto.randomUUID() + ext);
    }
});
const upload = multer({ storage, fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, ALLOWED.includes(ext));
}});
app.post('/upload', upload.single('file'), (req, res) => res.send('ok'));
""",
    "javascript", "distill_356.js",
    False, "CWE-434 任意文件上传", "None",
    "file.originalname 用户输入", "cb(null, crypto.randomUUID() + 白名单后缀)",
    "fileFilter 白名单 + UUID 重命名，无法上传可执行文件",
    "无需修复",
    cot_type="source_sink",
)

add(
    """
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $tmp = $_FILES['file']['tmp_name'];
    $name = $_FILES['file']['name'];
    move_uploaded_file($tmp, '/var/uploads/' . $name);
    echo 'ok';
}
?>
""",
    "php", "distill_357.php",
    True, "CWE-434 任意文件上传", "Critical",
    "$_FILES['file']['name'] 用户控制", "move_uploaded_file($tmp, '/var/uploads/'.$name)",
    "name=shell.php → 上传 PHP 文件 → 访问执行 → RCE",
    "白名单后缀 + 重命名（uniqid）+ 检查 MIME",
    cot_type="source_sink",
)

add(
    """
<?php
$allowed = ['jpg', 'png', 'gif'];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $tmp = $_FILES['file']['tmp_name'];
    $name = $_FILES['file']['name'];
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if (!in_array($ext, $allowed, true)) {
        http_response_code(400);
        exit('invalid');
    }
    $newName = bin2hex(random_bytes(8)) . '.' . $ext;
    move_uploaded_file($tmp, '/var/uploads/' . $newName);
    echo 'ok';
}
?>
""",
    "php", "distill_358.php",
    False, "CWE-434 任意文件上传", "None",
    "$_FILES['file']['name'] 用户输入", "move_uploaded_file($tmp, 随机名.'.'.白名单后缀)",
    "pathinfo 取后缀 + 白名单 + 随机重命名，无法上传可执行文件",
    "无需修复",
    cot_type="source_sink",
)

add(
    """
package main

import (
    "io"
    "net/http"
    "os"
    "path/filepath"
)

func uploadHandler(w http.ResponseWriter, r *http.Request) {
    r.ParseMultipartForm(32 << 20)
    file, handler, err := r.FormFile("file")
    if err != nil {
        http.Error(w, err.Error(), 400)
        return
    }
    defer file.Close()
    f, err := os.Create("/var/uploads/" + handler.Filename)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    defer f.Close()
    io.Copy(f, file)
}

func main() {
    http.HandleFunc("/upload", uploadHandler)
    http.ListenAndServe(":8080", nil)
}
""",
    "go", "distill_359.go",
    True, "CWE-434 任意文件上传", "High",
    "handler.Filename 用户控制", "os.Create('/var/uploads/' + handler.Filename)",
    "Filename=shell.go / shell.sh → 保存后可被访问执行",
    "filepath.Ext 白名单 + uuid 重命名",
    cot_type="source_sink",
)

add(
    """
# CVE-style: Content-Type 绕过 —— 只检查 MIME 而不检查后缀
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    # 仅检查 Content-Type，攻击者可伪造 header
    if f.mimetype not in ('image/jpeg', 'image/png'):
        return 'invalid', 400
    f.save(os.path.join('/var/uploads', f.filename))
    return 'ok'
""",
    "python", "distill_360.py",
    True, "CWE-434 Content-Type 绕过", "High",
    "f.filename 用户控制（f.mimetype 可伪造）", "f.save(f.filename)",
    "攻击者伪造 Content-Type: image/jpeg，filename=shell.php → 绕过 MIME 检查上传 PHP 文件",
    "始终检查后缀白名单，不能只信 Content-Type",
    cot_type="source_sink",
)

add(
    """
# 绕过变体：双扩展名绕过
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    # 仅检查最后一个扩展名
    name = f.filename
    if name.endswith('.jpg'):
        f.save(os.path.join('/var/uploads', name))
        return 'ok'
    return 'invalid', 400
""",
    "python", "distill_361.py",
    True, "CWE-434 双扩展名绕过", "High",
    "f.filename 用户控制", "f.save(name)",
    "filename=shell.php.jpg → endswith('.jpg') 通过 → Apache 解析为 PHP 执行",
    "取最后一个 . 后做白名单 + 重命名（不使用原文件名）",
    cot_type="source_sink",
)

add(
    """
# 绕过变体：filename 中的路径穿越
const express = require('express');
const multer = require('multer');
const path = require('path');
const app = express();

const storage = multer.diskStorage({
    destination: '/var/uploads',
    filename: (req, file, cb) => {
        // 未过滤 originalname 中的路径
        cb(null, file.originalname);
    }
});
const upload = multer({ storage });
app.post('/upload', upload.single('file'), (req, res) => res.send('ok'));
""",
    "javascript", "distill_362.js",
    True, "CWE-434 路径穿越上传", "Critical",
    "file.originalname 用户控制（含路径）", "cb(null, file.originalname)",
    "originalname=../../etc/cron.d/x → 写入系统目录 → 提权/RCE",
    "path.basename 过滤 + 重命名 + 白名单后缀",
    cot_type="source_sink",
)

add(
    """
// CVE-style: Apache Struts2 文件上传漏洞（Content-Type 伪造 + OGNL）
// 简化：上传时 Content-Type 为 application/octet-stream 但后缀为 .jsp
import javax.servlet.http.*;
import java.io.*;

public class StrutStyleUpload extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Part part = req.getPart("file");
        // 无任何校验直接保存
        part.write("/uploads/" + part.getSubmittedFileName());
    }
}
""",
    "java", "distill_363.java",
    True, "CWE-434 CVE风格上传", "Critical",
    "part.getSubmittedFileName() 用户控制", "part.write('/uploads/' + name)",
    "上传 .jsp/.war → 容器加载执行 → RCE（参考 CVE-2017-5638 类模式）",
    "白名单后缀 + UUID 重命名 + 拒绝可执行类型",
    cot_type="source_sink",
)

add(
    """
<?php
// 安全：随机名 + 后缀白名单 + MIME 二次校验
$allowed = ['jpg', 'png', 'gif'];
$allowedMime = ['image/jpeg', 'image/png', 'image/gif'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $tmp = $_FILES['file']['tmp_name'];
    $name = $_FILES['file']['name'];
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    $mime = mime_content_type($tmp);
    if (!in_array($ext, $allowed, true) || !in_array($mime, $allowedMime, true)) {
        http_response_code(400);
        exit('invalid');
    }
    $newName = bin2hex(random_bytes(16)) . '.' . $ext;
    move_uploaded_file($tmp, '/var/uploads/' . $newName);
}
?>
""",
    "php", "distill_364.php",
    False, "CWE-434 任意文件上传", "None",
    "$_FILES['file']['name'] 用户输入", "move_uploaded_file($tmp, 随机名.'.'.白名单后缀)",
    "后缀白名单 + 服务端 MIME 校验（基于文件内容）+ 随机重命名，无法上传可执行文件",
    "无需修复",
    cot_type="source_sink",
)


# ===========================================================================
# CWE-95 eval 注入（10 条）
# ===========================================================================

add(
    """
<?php
$code = $_GET['code'];
eval($code);
?>
""",
    "php", "distill_365.php",
    True, "CWE-95 eval 注入", "Critical",
    "$_GET['code'] 用户控制", "eval($code)",
    "code=system('id') → eval 执行 → RCE",
    "禁止 eval 用户输入；改用白名单函数或专用 DSL 解析器",
    cot_type="source_sink",
)

add(
    """
<?php
// 安全：固定表达式，不接收用户输入
$expr = '1 + 2 * 3';
$result = eval('return ' . $expr . ';');
echo $result;
?>
""",
    "php", "distill_366.php",
    False, "CWE-95 eval 注入", "None",
    "无用户输入（表达式为代码字面量）", "eval('return ' . $expr . ';')",
    "表达式为硬编码字符串，不含用户输入，无法注入",
    "无需修复（但建议用算术解析器替代 eval）",
    cot_type="source_sink",
)

add(
    """
def calc():
    expr = input('Enter expression: ')
    return eval(expr)
""",
    "python", "distill_367.py",
    True, "CWE-95 eval 注入", "Critical",
    "input() 用户控制", "eval(expr)",
    "expr=__import__('os').system('id') → eval 执行 → RCE",
    "用 ast.literal_eval（仅字面量）或专用算术库",
    cot_type="source_sink",
)

add(
    """
import ast

def calc():
    expr = input('Enter expression: ')
    # 仅允许字面量：数字/字符串/列表/字典
    return ast.literal_eval(expr)
""",
    "python", "distill_368.py",
    False, "CWE-95 eval 注入", "None",
    "input() 用户输入", "ast.literal_eval(expr)",
    "ast.literal_eval 仅解析字面量，不执行表达式/函数调用，安全",
    "无需修复",
    cot_type="source_sink",
)

add(
    """
<?php
// CVE-style: preg_replace /e 修饰符（PHP < 7.0）
$pattern = $_GET['pattern'];
$subject = $_GET['subject'];
echo preg_replace('/' . $pattern . '/e', 'strtolower', $subject);
?>
""",
    "php", "distill_369.php",
    True, "CWE-95 preg_replace /e 注入", "Critical",
    "$_GET['pattern'] 用户控制", "preg_replace('/'.$pattern.'/e', 'strtolower', $subject)",
    "/e 修饰符使 replacement 作为 PHP 代码执行 → pattern 注入触发代码执行",
    "移除 /e 修饰符 + 用 preg_replace_callback",
    cot_type="source_sink",
)

add(
    """
<?php
// assert 在 PHP 中也会执行代码
$cond = $_GET['cond'];
assert($cond);
?>
""",
    "php", "distill_370.php",
    True, "CWE-95 assert 代码执行", "High",
    "$_GET['cond'] 用户控制", "assert($cond)",
    "cond=phpinfo() 或 system('id') 字符串 → assert 执行 → RCE",
    "用 if 调试判断替代 assert；PHP 7.2+ assert 不再执行代码",
    cot_type="source_sink",
)

add(
    """
const express = require('express');
const app = express();

app.get('/calc', (req, res) => {
    const expr = req.query.expr;
    const result = eval(expr);
    res.send(String(result));
});
""",
    "javascript", "distill_371.js",
    True, "CWE-95 eval 注入", "Critical",
    "req.query.expr 用户控制", "eval(expr)",
    "expr=require('child_process').execSync('id').toString() → RCE",
    "用 mathjs/express 等安全算术库，禁止 eval 用户输入",
    cot_type="source_sink",
)

add(
    """
// 绕过变体：用 Function 构造器替代 eval
const expr = req.query.expr;
const fn = new Function('return ' + expr);
const result = fn();
""",
    "javascript", "distill_372.js",
    True, "CWE-95 Function 构造器注入", "Critical",
    "req.query.expr 用户控制", "new Function('return ' + expr)()",
    "Function 构造器等价于 eval，expr=require('os').system(...) → RCE",
    "禁止用 Function 构造器拼接用户输入，用专用解析器",
    cot_type="source_sink",
)

add(
    """
def run_plugin():
    code = request.args.get('code')
    exec(code)
""",
    "python", "distill_373.py",
    True, "CWE-95 exec 注入", "Critical",
    "request.args.get('code') 用户控制", "exec(code)",
    "code=__import__('os').system('id') → exec 执行 → RCE",
    "禁止 exec 用户输入；改用受限沙箱或预定义函数分派",
    cot_type="source_sink",
)

add(
    """
import ast
import operator

OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub,
    ast.Mult: operator.mul, ast.Div: operator.truediv,
}

def safe_calc(expr: str) -> float:
    # 仅允许数字与四则运算的安全算术解析
    tree = ast.parse(expr, mode='eval')
    def _eval(node):
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        if isinstance(node, ast.BinOp):
            op = OPS.get(type(node.op))
            if op is None:
                raise ValueError('unsupported op')
            return op(_eval(node.left), _eval(node.right))
        if isinstance(node, ast.Num):
            return node.n
        raise ValueError('unsupported node')
    return _eval(tree)
""",
    "python", "distill_374.py",
    False, "CWE-95 eval 注入", "None",
    "expr 用户输入（仅算术）", "ast.parse + 白名单 BinOp 递归求值",
    "仅允许数字与四则运算节点，函数调用/属性访问/名称节点均被拒，安全",
    "无需修复",
    cot_type="source_sink",
)


# ===========================================================================
# CWE-123 Write-What-Where（8 条，C/Go 为主）
# ===========================================================================

add(
    """
#include <string.h>
#include <stdlib.h>

void write_data(char *user_buf, size_t len, char *user_dst) {
    // user_dst 来自用户，可指向任意地址
    memcpy(user_dst, user_buf, len);
}
""",
    "c", "distill_375.c",
    True, "CWE-123 任意地址写", "Critical",
    "user_dst 用户控制（任意指针）", "memcpy(user_dst, user_buf, len)",
    "user_dst 指向 GOT/堆管理结构/返回地址 → 覆盖关键指针 → 劫持控制流",
    "禁止用户控制目标地址；用固定缓冲区 + 边界检查",
    cot_type="source_sink",
)

add(
    """
#include <string.h>

#define BUF_SIZE 256
static char buffer[BUF_SIZE];

void safe_write(char *user_buf, size_t len) {
    if (len > BUF_SIZE) {
        return;
    }
    memcpy(buffer, user_buf, len);
}
""",
    "c", "distill_376.c",
    False, "CWE-123 任意地址写", "None",
    "user_buf 用户输入（仅数据）", "memcpy(固定 buffer, user_buf, len)",
    "目标地址为固定 buffer + 长度边界检查，无法写任意地址",
    "无需修复",
    cot_type="source_sink",
)

add(
    """
#include <stdlib.h>

int *g_table[64];

void set_entry(int idx, int *ptr) {
    // idx 无边界检查，可越界写
    g_table[idx] = ptr;
}
""",
    "c", "distill_377.c",
    True, "CWE-123 数组越界写(Write-What-Where)", "Critical",
    "idx 用户控制（无边界）", "g_table[idx] = ptr",
    "idx 超出 64 → 覆盖相邻全局变量/函数指针 → 控制流劫持",
    "if (idx < 0 || idx >= 64) return; 边界检查",
    cot_type="integer_overflow",
)

add(
    """
#include <stdlib.h>

#define TABLE_SIZE 64
int *g_table[TABLE_SIZE];

void set_entry(int idx, int *ptr) {
    if (idx < 0 || idx >= TABLE_SIZE) {
        return;
    }
    g_table[idx] = ptr;
}
""",
    "c", "distill_378.c",
    False, "CWE-123 数组越界写", "None",
    "idx 用户输入（已边界检查）", "g_table[已检查 idx] = ptr",
    "idx 经过 0..TABLE_SIZE-1 边界检查，无法越界写",
    "无需修复",
    cot_type="integer_overflow",
)

add(
    """
#include <string.h>

void copy_name(char *user_name) {
    char buf[32];
    // strcpy 无长度限制，user_name 可超过 32 字节
    strcpy(buf, user_name);
}
""",
    "c", "distill_379.c",
    True, "CWE-123 栈缓冲区写越界", "High",
    "user_name 用户控制（长度任意）", "strcpy(buf, user_name)",
    "user_name 超过 32 字节 → 覆盖栈上返回地址 → ROP/RCE",
    "用 strncpy(buf, user_name, sizeof(buf)-1); buf[sizeof(buf)-1]='\\\\0';",
    cot_type="source_sink",
)

add(
    """
package main

import (
    "unsafe"
)

func writeAt(addr uintptr, val uint32) {
    // 直接写任意地址，极度危险
    ptr := (*uint32)(unsafe.Pointer(addr))
    *ptr = val
}
""",
    "go", "distill_380.go",
    True, "CWE-123 任意地址写(unsafe)", "Critical",
    "addr 用户控制（uintptr）", "*ptr = val",
    "addr 指向任意内存 → 写入 val 覆盖关键数据 → 内存破坏",
    "禁止 unsafe.Pointer + 用受控切片/结构体字段",
    cot_type="source_sink",
)

add(
    """
// CVE-style: 内核驱动 ioctl 任意地址写
#include <linux/kernel.h>
#include <linux/uaccess.h>

struct write_req {
    unsigned long addr;
    unsigned long val;
};

long dev_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    struct write_req req;
    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;
    // 未校验 req.addr，直接写内核地址
    *(unsigned long *)req.addr = req.val;
    return 0;
}
""",
    "c", "distill_381.c",
    True, "CWE-123 内核任意地址写(CVE风格)", "Critical",
    "req.addr 用户控制（来自用户态）", "*(unsigned long *)req.addr = req.val",
    "用户态传入 addr 指向内核关键结构 → 覆盖 cred/modprobe_path → 提权",
    "校验 addr 属于合法内核区域 + 用 set_memory_ro/校验所有权",
    cot_type="source_sink",
)

add(
    """
#include <string.h>

void safe_copy_name(char *user_name, size_t user_len) {
    char buf[32];
    if (user_len >= sizeof(buf)) {
        user_len = sizeof(buf) - 1;
    }
    memcpy(buf, user_name, user_len);
    buf[user_len] = '\\\\0';
}
""",
    "c", "distill_382.c",
    False, "CWE-123 栈缓冲区写越界", "None",
    "user_name 用户输入（长度已检查）", "memcpy(buf, user_name, 已截断 user_len)",
    "长度检查 + 截断 + 显式 NUL 终止，无法越界写",
    "无需修复",
    cot_type="source_sink",
)


# ===========================================================================
# CWE-134 格式化字符串漏洞（10 条）
# ===========================================================================

add(
    """
#include <stdio.h>

void greet(char *user) {
    printf(user);
}
""",
    "c", "distill_383.c",
    True, "CWE-134 格式化字符串", "Critical",
    "user 用户控制（作为格式串）", "printf(user)",
    "user=%n%n%n → printf 将已写字节数写入栈/寄存器指针 → 任意地址写 → 控制流劫持",
    "printf('%s', user) 固定格式串 + 用户数据作为参数",
    cot_type="source_sink",
)

add(
    """
#include <stdio.h>

void greet(const char *user) {
    printf("%s", user);
}
""",
    "c", "distill_384.c",
    False, "CWE-134 格式化字符串", "None",
    "user 用户输入（作为 %s 参数）", "printf('%s', user)",
    "格式串固定为 '%s'，user 仅作为数据参数，无法注入 %n/%x",
    "无需修复",
    cot_type="source_sink",
)

add(
    """
#include <syslog.h>

void log_msg(char *msg) {
    syslog(LOG_INFO, msg);
}
""",
    "c", "distill_385.c",
    True, "CWE-134 syslog 格式化字符串", "High",
    "msg 用户控制（作为格式串）", "syslog(LOG_INFO, msg)",
    "msg=%n → syslog 解析格式 → 任意地址写",
    "syslog(LOG_INFO, '%s', msg)",
    cot_type="source_sink",
)

add(
    """
#include <stdio.h>

void log_err(char *user_msg) {
    // 误用：用户输入作为格式串的一部分
    char fmt[256];
    snprintf(fmt, sizeof(fmt), "Error: ");
    snprintf(fmt + 7, sizeof(fmt) - 7, user_msg);
    fprintf(stderr, fmt);
}
""",
    "c", "distill_386.c",
    True, "CWE-134 格式串拼接", "High",
    "user_msg 用户控制（拼入 fmt）", "fprintf(stderr, fmt)",
    "user_msg 含 %n/%x → fprintf 解析 → 任意读写",
    "fprintf(stderr, '%s', fmt) 或固定格式串",
    cot_type="source_sink",
)

add(
    """
class User:
    def __init__(self, name, email):
        self.name = name
        self.email = email

def render(template, user):
    # template 来自用户
    return template.format(user=user)

u = User('Alice', 'alice@x.com')
t = input('Template: ')
print(render(t, u))
""",
    "python", "distill_387.py",
    True, "CWE-134 Python format 注入", "High",
    "template 用户控制（input）", "template.format(user=user)",
    "t={user.__class__.__init__.__globals__} → 泄露全局命名空间 → 敏感信息泄露",
    "禁止用户控制模板；用 string.Template + safe_substitute",
    cot_type="source_sink",
)

add(
    """
from string import Template

def render(name):
    # 固定模板，用户仅作为数据
    t = Template('Hello $name')
    return t.safe_substitute(name=name)
""",
    "python", "distill_388.py",
    False, "CWE-134 Python format 注入", "None",
    "name 用户输入（仅作为 $name 数据）", "Template('Hello $name').safe_substitute(name=name)",
    "Template 用 $ 占位符 + safe_substitute，不解析属性访问/表达式，安全",
    "无需修复",
    cot_type="source_sink",
)

add(
    """
import java.util.Scanner;

public class FormatVuln {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        String fmt = sc.nextLine();
        // 用户控制格式串
        System.out.format(fmt);
    }
}
""",
    "java", "distill_389.java",
    True, "CWE-134 Java 格式化字符串", "Medium",
    "fmt 用户控制（Scanner 输入）", "System.out.format(fmt)",
    "fmt=%1$tm/%1$td 等读取参数 → 信息泄露（Java 无 %n 写，但可泄露参数）",
    "System.out.format('%s', fmt) 固定格式",
    cot_type="source_sink",
)

add(
    """
public class SafeFormat {
    public static void greet(String name) {
        // 格式串固定，name 仅作为参数
        System.out.format("Hello %s%n", name);
    }
}
""",
    "java", "distill_390.java",
    False, "CWE-134 Java 格式化字符串", "None",
    "name 用户输入（作为 %s 参数）", "System.out.format('Hello %s%n', name)",
    "格式串固定为 'Hello %s%n'，name 仅作为数据，无法注入格式符",
    "无需修复",
    cot_type="source_sink",
)

add(
    """
def log_error(err_code, user_msg):
    # 误用：用户输入作为 % 格式串
    return user_msg % err_code
""",
    "python", "distill_391.py",
    True, "CWE-134 Python % 格式化注入", "Medium",
    "user_msg 用户控制（作为 % 格式串）", "user_msg % err_code",
    "user_msg=%(name)s 等可读取字典键；与 locals()/globals 结合可泄露信息",
    "用固定格式串：'error %d' % err_code，不让用户控制模板",
    cot_type="source_sink",
)

add(
    """
// CVE-style: Sudo 1.8.0-1.8.3p1 (CVE-2012-0809) sudo_debug 格式串漏洞
// 简化：argv[0] 被当作格式串传递给 fprintf
#include <stdio.h>

void debug_log(char *argv0) {
    fprintf(stderr, argv0);
    fprintf(stderr, "\\n");
}

int main(int argc, char **argv) {
    debug_log(argv[0]);
    return 0;
}
""",
    "c", "distill_392.c",
    True, "CWE-134 CVE风格格式串(sudo)", "Critical",
    "argv[0] 用户控制（进程名可被设置）", "fprintf(stderr, argv0)",
    "攻击者设置进程名为 %n%n... → fprintf 写栈 → 提权（参考 CVE-2012-0809）",
    "fprintf(stderr, '%s', argv0) 固定格式",
    cot_type="source_sink",
)


# ===========================================================================
# CWE-409 数据放大 / 解压炸弹（8 条）
# ===========================================================================

add(
    """
import zipfile

def extract_all(zip_path, dest):
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest)
""",
    "python", "distill_393.py",
    True, "CWE-409 解压炸弹(zip bomb)", "High",
    "zip_path 用户上传（含高压缩比 zip）", "zf.extractall(dest)",
    "小 zip 解压成超大文件 → 磁盘耗尽 → DoS",
    "解压前累计 uncompressed size + 设阈值（如 100MB）",
    cot_type="source_sink",
)

add(
    """
import zipfile
import os

MAX_TOTAL = 100 * 1024 * 1024  # 100MB

def safe_extract(zip_path, dest):
    with zipfile.ZipFile(zip_path) as zf:
        total = sum(info.file_size for info in zf.infolist())
        if total > MAX_TOTAL:
            raise ValueError('zip too large after decompress')
        for info in zf.infolist():
            # 防路径穿越
            target = os.path.realpath(os.path.join(dest, info.filename))
            if not target.startswith(os.path.realpath(dest)):
                raise ValueError('path traversal detected')
        zf.extractall(dest)
""",
    "python", "distill_394.py",
    False, "CWE-409 解压炸弹", "None",
    "zip_path 用户上传", "zf.extractall(dest)（已校验总大小）",
    "解压前累计 file_size + 阈值检查 + 路径穿越校验，无法引爆 zip bomb",
    "无需修复",
    cot_type="source_sink",
)

add(
    """
import java.util.zip.*;
import java.io.*;

public class ZipExtractor {
    public static void extract(File zipFile, File destDir) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                File out = new File(destDir, entry.getName());
                try (FileOutputStream fos = new FileOutputStream(out)) {
                    byte[] buf = new byte[1024];
                    int len;
                    while ((len = zis.read(buf)) != -1) {
                        fos.write(buf, 0, len);
                    }
                }
            }
        }
    }
}
""",
    "java", "distill_395.java",
    True, "CWE-409 解压炸弹(Java)", "High",
    "zipFile 用户上传（高压缩比）", "zis.read/write 循环（无累计限制）",
    "高压缩比 zip → 解压耗尽磁盘/内存 → DoS",
    "累计写入字节数 + 阈值检查 + 检查 entry.getName 路径穿越",
    cot_type="source_sink",
)

add(
    """
package main

import (
    "compress/gzip"
    "io"
    "os"
)

func decompress(src string) error {
    f, err := os.Open(src)
    if err != nil {
        return err
    }
    defer f.Close()
    gr, err := gzip.NewReader(f)
    if err != nil {
        return err
    }
    defer gr.Close()
    // 无大小限制，直接拷贝到 stdout
    io.Copy(os.Stdout, gr)
    return nil
}
""",
    "go", "distill_396.go",
    True, "CWE-409 gzip 炸弹", "High",
    "src 用户上传（高压缩 gzip）", "io.Copy(os.Stdout, gr)（无限制）",
    "高压缩比 gzip → io.Copy 持续输出 → 内存/带宽耗尽 → DoS",
    "用 io.LimitReader 限制最大解压字节数",
    cot_type="source_sink",
)

add(
    """
# CWE-409 变体：XML Billion Laughs（实体爆炸）
from xml.dom import minidom

def parse_xml(xml_str):
    # 默认 minidom 解析器会展开实体
    return minidom.parseString(xml_str)
""",
    "python", "distill_397.py",
    True, "CWE-409 XML 实体爆炸(Billion Laughs)", "Critical",
    "xml_str 用户控制（含嵌套实体定义）", "minidom.parseString(xml_str)",
    "嵌套 <!ENTITY a '&b;&b;&b;...'> 递归展开 → 内存爆炸 → DoS",
    "用 defusedxml.minidom（默认禁用实体展开）",
    cot_type="source_sink",
)

add(
    """
# 安全：使用 defusedxml 防御 XXE 与实体爆炸
import defusedxml.minidom as minidom

def parse_xml(xml_str):
    return minidom.parseString(xml_str)
""",
    "python", "distill_398.py",
    False, "CWE-409 XML 实体爆炸", "None",
    "xml_str 用户输入", "defusedxml.minidom.parseString(xml_str)",
    "defusedxml 默认禁用 DTD/外部实体/嵌套实体展开，安全",
    "无需修复",
    cot_type="source_sink",
)

add(
    """
const zlib = require('zlib');
const fs = require('fs');

app.get('/decompress', (req, res) => {
    const file = req.query.file;
    const input = fs.createReadStream(file);
    const gunzip = zlib.createGunzip();
    // 无大小限制
    input.pipe(gunzip).pipe(res);
});
""",
    "javascript", "distill_399.js",
    True, "CWE-409 Node.js gzip 炸弹", "High",
    "req.query.file 用户控制（高压缩 gzip）", "input.pipe(gunzip).pipe(res)",
    "高压缩比 gzip → 持续解压输出 → 内存/带宽耗尽 → DoS",
    "用 stream.Transform 累计字节数 + 超阈值中断",
    cot_type="source_sink",
)

add(
    """
import zipfile
import os

MAX_TOTAL = 100 * 1024 * 1024
MAX_RATIO = 100  # 压缩比上限

def safe_extract_with_ratio(zip_path, dest):
    # 安全解压：校验总大小 + 压缩比 + 路径穿越
    with zipfile.ZipFile(zip_path) as zf:
        total_uncompressed = 0
        total_compressed = 0
        for info in zf.infolist():
            total_uncompressed += info.file_size
            total_compressed += info.compress_size
            # 防路径穿越
            target = os.path.realpath(os.path.join(dest, info.filename))
            if not target.startswith(os.path.realpath(dest) + os.sep):
                raise ValueError('path traversal: ' + info.filename)
        if total_uncompressed > MAX_TOTAL:
            raise ValueError('uncompressed too large')
        if total_compressed > 0 and total_uncompressed / total_compressed > MAX_RATIO:
            raise ValueError('compression ratio too high (zip bomb suspected)')
        zf.extractall(dest)
""",
    "python", "distill_400.py",
    False, "CWE-409 解压炸弹", "None",
    "zip_path 用户上传", "zf.extractall(dest)（已校验大小+压缩比+路径）",
    "总大小阈值 + 压缩比阈值 + 路径穿越校验，三层防御阻止 zip bomb",
    "无需修复",
    cot_type="source_sink",
)


# ===========================================================================
# 主流程：写出 JSONL + 打印统计
# ===========================================================================

def main():
    output_dir = Path(__file__).resolve().parents[1] / "data"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "distill_corpus_annotated.jsonl"

    with open(output_file, "w", encoding="utf-8") as f:
        for s in SAMPLES:
            out = {k: v for k, v in s.items() if k != "cot_type"}
            f.write(json.dumps(out, ensure_ascii=False) + "\n")

    # 统计
    total = len(SAMPLES)
    vuln = sum(1 for s in SAMPLES if s["has_vulnerability"])
    safe = total - vuln

    lang_dist = {}
    cwe_dist = {}
    cot_type_dist = {}
    risk_dist = {}
    for s in SAMPLES:
        lang_dist[s["language"]] = lang_dist.get(s["language"], 0) + 1
        # 取 CWE 编号（如 "CWE-89 SQL 注入" -> "CWE-89"）
        vt = s["vuln_type"]
        cwe_key = vt.split(" ", 1)[0] if vt.startswith("CWE-") else ("safe" if not s["has_vulnerability"] else "other")
        cwe_dist[cwe_key] = cwe_dist.get(cwe_key, 0) + 1
        cot_type_dist[s["cot_type"]] = cot_type_dist.get(s["cot_type"], 0) + 1
        risk_dist[s["risk_level"]] = risk_dist.get(s["risk_level"], 0) + 1

    print(f"已写入 {total} 条样本到 {output_file}")
    print(f"漏洞 / 安全：{vuln} / {safe}（漏洞占比 {vuln/total*100:.1f}%）")
    print(f"\n语言分布：")
    for lang, n in sorted(lang_dist.items(), key=lambda x: -x[1]):
        print(f"  {lang:12s}: {n:3d} ({n/total*100:.1f}%)")
    print(f"\nCWE 分布：")
    for cwe, n in sorted(cwe_dist.items(), key=lambda x: -x[1]):
        print(f"  {cwe:10s}: {n:3d}")
    print(f"\nCoT 模板分布：")
    for ct, n in sorted(cot_type_dist.items(), key=lambda x: -x[1]):
        print(f"  {ct:18s}: {n:3d}")
    print(f"\n风险等级分布：")
    for r, n in sorted(risk_dist.items(), key=lambda x: -x[1]):
        print(f"  {r:10s}: {n:3d}")
    print(f"\n后续：用 format_distilled.py 转为 ChatML 训练格式")
    print(f"  python experiments/exp_06_finetune/scripts/format_distilled.py")


if __name__ == "__main__":
    main()
