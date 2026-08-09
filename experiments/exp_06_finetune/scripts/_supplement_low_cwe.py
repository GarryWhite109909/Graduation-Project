#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""补齐 3 个偏低 CWE：CWE-312 明文存储 / CWE-434 任意文件上传 / CWE-367 TOCTOU。

复用 generate_ssti_auth_samples.py 的 _spec / make_verdict / make_sample /
validate_spec（自动按代码解析行号），为新样本生成统一 ChatML 格式。

目标（基于 v3 现状）：
  CWE-312  5  -> +30  (到 ~35)
  CWE-434 27  -> +6   (到 ~33)
  CWE-367 29  -> +4   (到 ~33)

输出: data/supplement_low_cwe.jsonl
"""
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT / "experiments/exp_06_finetune/scripts"))

from generate_ssti_auth_samples import (  # noqa: E402
    _spec, make_sample, validate_spec,
)

OUTPUT_FILE = Path(__file__).resolve().parents[1] / "data" / "supplement_low_cwe.jsonl"


# ===========================================================================
# CWE-312 Cleartext Storage（30 条：多语言 × 多场景，含防御迷惑）
# ===========================================================================
def gen_cleartext():
    S = []

    # --- Python: 明文密码写入日志 ---
    S.append(_spec("python", r'''import logging
from flask import Flask, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    logging.info(f"login attempt user={username} password={password}")
    return "ok"
''',
        "分析过程：\n1. line 9: password 从请求体获取明文。\n2. line 11: logging.info 将明文密码写入日志文件。\n3. 日志可能被运维/第三方访问，密码明文暴露。\n4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker='password = data.get("password"', source_desc="data.get('password') 用户提交的明文密码",
        sink_marker="logging.info(f\"login attempt", sink_desc="logging.info 将明文密码写入日志",
        explanation="line 9 明文密码 -> line 11 logging.info 写入日志 -> 日志泄露密码明文 -> CWE-312 明文存储",
        fix_marker="logging.info(f\"login attempt", fix_desc="日志中不记录密码，只记录 username 与时间戳，如 logging.info(f\"login attempt user={username}\")"))

    # --- Python: 明文密码存入 SQLite（无日志） ---
    S.append(_spec("python", r'''import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/signup", methods=["POST"])
def signup():
    body = request.get_json()
    name = body.get("name")
    pwd = body.get("pwd")
    conn = sqlite3.connect("users.db")
    conn.execute("INSERT INTO accounts (name, pwd) VALUES (?, ?)", (name, pwd))
    conn.commit()
    conn.close()
    return "created"
''',
        "分析过程：\n1. line 8: pwd 从请求体获取明文密码。\n2. line 11: conn.execute 将明文 pwd 写入 SQLite。\n3. 数据库文件泄露时密码全部暴露。\n4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker='pwd = body.get("pwd")', source_desc="body.get('pwd') 用户提交的明文密码",
        sink_marker="INSERT INTO accounts (name, pwd)", sink_desc="conn.execute 将明文 pwd 写入账户表",
        explanation="line 8 明文密码 -> line 11 写入 SQLite -> 数据库泄露密码全部暴露 -> CWE-312 明文存储",
        fix_marker="INSERT INTO accounts (name, pwd)", fix_desc="存储前用 bcrypt 哈希密码：hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())，再存入 pwd 字段"))

    # --- Python: 明文 token 存环境感知文件（防御迷惑：简单 XOR） ---
    S.append(_spec("python", r'''import os

def persist_token(token):
    # 防御迷惑：用固定的 XOR key "混淆"，但这不是加密
    key = 0x5A
    obfuscated = "".join(chr(ord(c) ^ key) for c in token)
    with open("/var/lib/app/token", "w") as f:
        f.write(obfuscated)

def issue_token():
    tok = "s3cr3t-token-abc123"
    persist_token(tok)
    return tok
''',
        "分析过程：\n1. line 12: tok 为硬编码敏感 token。\n2. line 5-6: 用固定 XOR 对 token 做'混淆'。\n3. line 7: 写入磁盘文件。\n4. 防御迷惑：XOR 固定 key 不是加密，可轻易还原。\n5. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker='tok = "s3cr3t-token-abc123"', source_desc="硬编码的敏感 token 字面量",
        sink_marker='with open("/var/lib/app/token"', sink_desc="将 XOR 混淆(非加密)后的 token 写入磁盘文件",
        explanation="硬编码 token -> 固定 XOR 混淆(非加密) -> 写入磁盘 -> 可还原明文 -> CWE-312 明文存储",
        fix_marker='with open("/var/lib/app/token"', fix_desc="不要硬编码 token；用 AES-GCM 加密后存储，密钥从 KMS/环境变量读取"))

    # --- Python: 明文信用卡号（CVV）入库 ---
    S.append(_spec("python", r'''import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/charge", methods=["POST"])
def charge():
    body = request.get_json()
    card = body.get("card_number")
    cvv = body.get("cvv")
    conn = sqlite3.connect("billing.db")
    conn.execute("INSERT INTO payments (card, cvv) VALUES (?, ?)", (card, cvv))
    conn.commit()
    conn.close()
    return "ok"
''',
        "分析过程：\n1. line 8-9: card/cvv 从请求体获取。\n2. line 11: 明文信用卡号与 CVV 写入数据库。\n3. 违反 PCI-DSS，数据库泄露导致银行卡信息暴露。\n4. 结论：CWE-312 明文存储敏感信息，风险 Critical。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="Critical",
        source_marker='cvv = body.get("cvv")', source_desc="body.get('cvv') 用户提交的信用卡 CVV",
        sink_marker="INSERT INTO payments (card, cvv)", sink_desc="将明文卡号与 CVV 写入数据库",
        explanation="card/cvv 明文 -> 写入 payments 表 -> 数据库泄露银行卡信息 -> CWE-312 明文存储",
        fix_marker="INSERT INTO payments (card, cvv)", fix_desc="敏感支付数据不落库或使用加密+token化（PCI-DSS），CVV 不应持久化"))

    # --- JavaScript: 明文 token 存 localStorage ---
    S.append(_spec("javascript", r'''function storeSession(token) {
    localStorage.setItem("session_token", token);
}

function onLogin() {
    // token 从登录响应获取
    const token = apiLogin();
    storeSession(token);
}
''',
        "分析过程：\n1. line 7: token 从登录接口获取。\n2. line 2: localStorage.setItem 将明文 token 存到浏览器本地存储。\n3. localStorage 对 XSS 开放，token 明文易被窃取。\n4. 结论：CWE-312 明文存储敏感信息，风险 Medium。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="Medium",
        source_marker="const token = apiLogin()", source_desc="从登录接口获取的 token",
        sink_marker='localStorage.setItem("session_token"', sink_desc="将明文 token 存入 localStorage",
        explanation="token 明文 -> localStorage.setItem -> XSS 可窃取 -> CWE-312 明文存储",
        fix_marker='localStorage.setItem("session_token"', fix_desc="不要将敏感 token 存 localStorage；优先用 HttpOnly+Secure cookie"))

    # --- JavaScript: 明文密码存 MongoDB ---
    S.append(_spec("javascript", r'''const express = require('express');
const { MongoClient } = require('mongodb');
const app = express();
app.use(express.json());

const client = new MongoClient('mongodb://localhost:27017');
const db = client.db('store');

app.post('/api/register', async (req, res) => {
    const { user, pass, mail } = req.body;
    await db.collection('users').insertOne({ user, pass, mail });
    res.json({ ok: true });
});
app.listen(3000);
''',
        "分析过程：\n1. line 11: pass 从请求体解构获取明文密码。\n2. line 12: insertOne 将明文密码存入 MongoDB。\n3. 无哈希无加密，数据库泄露密码全部暴露。\n4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker="const { user, pass, mail } = req.body", source_desc="req.body 解构获取明文密码",
        sink_marker="insertOne({ user, pass, mail })", sink_desc="将明文密码写入 MongoDB users 集合",
        explanation="pass 明文 -> insertOne 写入 MongoDB -> 无哈希 -> 泄露全部暴露 -> CWE-312 明文存储",
        fix_marker="insertOne({ user, pass, mail })", fix_desc="存储前用 bcrypt.hash(pass, 10) 哈希密码"))

    # --- JavaScript: 明文 API Key 写配置文件（防御迷惑：URL 编码） ---
    S.append(_spec("javascript", r'''const fs = require('fs');

function saveKey(apiKey) {
    // 防御迷惑：URL 编码不是加密
    const encoded = encodeURIComponent(apiKey);
    fs.writeFileSync('/etc/app/keys.conf', 'apikey=' + encoded);
}

function register(clientKey) {
    saveKey(clientKey);
}
''',
        "分析过程：\n1. line 8: clientKey 为敏感 API Key。\n2. line 4: encodeURIComponent 对 Key 做 URL 编码。\n3. line 5: 写入配置文件。\n4. 防御迷惑：URL 编码可轻易还原，非加密。\n5. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker="function register(clientKey)", source_desc="函数参数 clientKey（敏感 API Key）",
        sink_marker="fs.writeFileSync('/etc/app/keys.conf'", sink_desc="将 URL 编码(非加密)的 API Key 写入配置文件",
        explanation="API Key -> URL 编码(非加密) -> 写入配置文件 -> 可还原 -> CWE-312 明文存储",
        fix_marker="fs.writeFileSync('/etc/app/keys.conf'", fix_desc="使用加密(如 AES-256-GCM) 存储密钥，密钥从环境变量/密钥管理服务读取"))

    # --- Java: 明文密码写入 Properties 文件 ---
    S.append(_spec("java", r'''import java.io.FileOutputStream;
import java.util.Properties;

public class StoreConfig {
    public void saveDbPassword(String dbPassword) throws Exception {
        Properties props = new Properties();
        props.setProperty("db.password", dbPassword);
        props.store(new FileOutputStream("config/db.properties"), null);
    }
}
''',
        "分析过程：\n1. line 6: dbPassword 为数据库明文密码参数。\n2. line 8: props.store 将明文密码写入 properties 文件。\n3. 配置文件可能随代码库/容器分发，密码明文泄露。\n4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker="public void saveDbPassword(String dbPassword)", source_desc="方法参数 dbPassword（数据库明文密码）",
        sink_marker='props.setProperty("db.password", dbPassword)', sink_desc="将明文密码写入 properties 文件",
        explanation="dbPassword 明文 -> props.store 写入配置文件 -> 随分发泄露 -> CWE-312 明文存储",
        fix_marker='props.setProperty("db.password", dbPassword)', fix_desc="从环境变量/配置服务读取数据库密码，不写入源码文件"))

    # --- Java: 明文 token 存 Session（非 HttpOnly cookie） ---
    S.append(_spec("java", r'''import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuthServlet {
    public void issueToken(HttpServletRequest req, HttpServletResponse resp) {
        String token = generateToken();
        resp.addCookie(new javax.servlet.http.Cookie("auth", token));
    }
    private String generateToken() { return "tok-abcdef-123"; }
}
''',
        "分析过程：\n1. line 6: token 为认证凭证。\n2. line 7: 将明文 token 写入 Cookie（未设置 HttpOnly/Secure）。\n3. 明文 Cookie 可被 XSS 脚本读取，无 HttpOnly 保护。\n4. 结论：CWE-312 明文存储敏感信息，风险 Medium。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="Medium",
        source_marker="String token = generateToken()", source_desc="生成的认证 token",
        sink_marker='new javax.servlet.http.Cookie("auth", token)', sink_desc="将明文 token 写入 Cookie（无 HttpOnly/Secure）",
        explanation="token 明文 -> Cookie 无 HttpOnly -> XSS 可窃取 -> CWE-312 明文存储",
        fix_marker='new javax.servlet.http.Cookie("auth", token)', fix_desc="Cookie 设置 HttpOnly 与 Secure 属性，并考虑签名/加密"))

    # --- Java: 明文密码插到 JDBC URL ---
    S.append(_spec("java", r'''import java.sql.DriverManager;
import java.sql.Connection;

public class DbConnect {
    public Connection connect() throws Exception {
        String user = "root";
        String pass = "SuperSecret123";
        String url = "jdbc:mysql://localhost/mydb?user=" + user + "&password=" + pass;
        return DriverManager.getConnection(url);
    }
}
''',
        "分析过程：\n1. line 6-7: 硬编码数据库账号密码。\n2. line 8: 明文密码拼入 JDBC URL。\n3. 连接串/日志/监控中会暴露明文密码。\n4. 结论：CWE-312 明文存储敏感信息，风险 Critical。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="Critical",
        source_marker='String pass = "SuperSecret123"', source_desc="硬编码的数据库明文密码",
        sink_marker="String url = \"jdbc:mysql", sink_desc="明文密码拼入 JDBC 连接串",
        explanation="硬编码密码 -> 拼入 JDBC URL -> 连接串/日志暴露 -> CWE-312 明文存储",
        fix_marker='String url = "jdbc:mysql', fix_desc="密码从环境变量读取，连接串中不内嵌明文密码"))

    # --- Go: 明文密码写 JSON 配置 ---
    S.append(_spec("go", r'''package main

import (
    "encoding/json"
    "os"
)

type Config struct {
    DBPassword string `json:"db_password"`
}

func SaveConfig(pwd string) error {
    cfg := Config{DBPassword: pwd}
    data, _ := json.Marshal(cfg)
    return os.WriteFile("app.conf", data, 0644)
}
''',
        "分析过程：\n1. line 12: pwd 为数据库明文密码。\n2. line 13-14: 将明文密码序列化写入配置文件。\n3. 配置文件明文保存密码，泄露即暴露。\n4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker="func SaveConfig(pwd string)", source_desc="函数参数 pwd（数据库明文密码）",
        sink_marker='cfg := Config{DBPassword: pwd}', sink_desc="将明文密码写入 JSON 配置文件",
        explanation="pwd 明文 -> json.Marshal -> os.WriteFile 写入配置 -> CWE-312 明文存储",
        fix_marker='cfg := Config{DBPassword: pwd}', fix_desc="密码从环境变量/密钥管理服务读取，不写入配置文件"))

    # --- Go: 明文密钥写日志（防御迷惑：无） ---
    S.append(_spec("go", r'''package main

import (
    "log"
    "net/http"
)

func Handler(w http.ResponseWriter, r *http.Request) {
    token := r.Header.Get("X-Auth-Token")
    log.Printf("processing request with token %s", token)
    w.WriteHeader(200)
}
''',
        "分析过程：\n1. line 8: token 从请求头获取。\n2. line 9: log.Printf 将明文 token 写入日志。\n3. 日志集中存储，token 明文被记录暴露。\n4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker='token := r.Header.Get("X-Auth-Token")', source_desc="从请求头获取的认证 token",
        sink_marker='log.Printf("processing request with token', sink_desc="将明文 token 写入日志",
        explanation="token 明文 -> log.Printf -> 日志暴露 -> CWE-312 明文存储",
        fix_marker='log.Printf("processing request with token', fix_desc="日志中不记录 token，只记录请求ID或脱敏值"))

    # --- PHP: 明文密码存 MySQL ---
    S.append(_spec("php", r'''<?php
$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '');
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = $_POST['user'] ?? '';
    $pass = $_POST['pass'] ?? '';
    $stmt = $pdo->prepare("INSERT INTO accounts (user, pass) VALUES (?, ?)");
    $stmt->execute([$user, $pass]);
    echo 'ok';
}
''',
        "分析过程：\n1. line 5: $pass 从 POST 获取明文密码。\n2. line 6: execute 将明文密码写入 MySQL。\n3. 无哈希，数据库泄露密码全部暴露。\n4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker="$pass = $_POST['pass']", source_desc="$_POST['pass'] 用户提交的明文密码",
        sink_marker="$stmt->execute([$user, $pass])", sink_desc="将明文密码写入 MySQL accounts 表",
        explanation="$pass 明文 -> execute 写入 MySQL -> 无哈希 -> CWE-312 明文存储",
        fix_marker="$stmt->execute([$user, $pass])", fix_desc="存储前用 password_hash($pass, PASSWORD_BCRYPT) 哈希密码"))

    # --- PHP: 明文 token 写会话文件（防御迷惑：base64） ---
    S.append(_spec("php", r'''<?php
function saveToken($token) {
    // 防御迷惑：base64 是编码不是加密
    $encoded = base64_encode($token);
    file_put_contents('/tmp/user_token', $encoded);
}
saveToken('tok-session-9f8e');
''',
        "分析过程：\n1. line 6: 硬编码敏感 token。\n2. line 3: base64_encode 编码。\n3. line 4: 写入会话文件。\n4. 防御迷惑：base64 可解码还原，非加密。\n5. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker="saveToken('tok-session-9f8e')", source_desc="硬编码的敏感 token",
        sink_marker="file_put_contents('/tmp/user_token'", sink_desc="将 base64 编码(非加密)的 token 写入文件",
        explanation="token -> base64 编码(非加密) -> 写入文件 -> 可解码 -> CWE-312 明文存储",
        fix_marker="file_put_contents('/tmp/user_token'", fix_desc="使用 openssl_encrypt + 密钥加密 token 后再存储"))

    # --- C: 明文密码硬编码到结构体 ---
    S.append(_spec("c", r'''#include <stdio.h>
#include <string.h>

typedef struct {
    char username[32];
    char password[64];
} Account;

void init_account(Account* a) {
    strcpy(a->username, "admin");
    strcpy(a->password, "hardcoded_pw_123");
}

int main() {
    Account a;
    init_account(&a);
    printf("user=%s\n", a.username);
    return 0;
}
''',
        "分析过程：\n1. line 10: 硬编码明文密码。\n2. line 11-12: 密码明文存入结构体。\n3. 反汇编/字符串提取即可获得密码。\n4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker='strcpy(a->password, "hardcoded_pw_123")', source_desc="硬编码的明文密码",
        sink_marker="strcpy(a->username, \"admin\")", sink_desc="明文密码硬编码进程序结构体",
        explanation="硬编码密码 -> 明文存于二进制 -> 可提取 -> CWE-312 明文存储",
        fix_marker='strcpy(a->password, "hardcoded_pw_123")', fix_desc="不要硬编码密码；从环境变量/密钥管理读取"))

    # --- Ruby: 明文密码存 SQLite ---
    S.append(_spec("ruby", r'''require 'sqlite3'
require 'sinatra'

post '/signup' do
  db = SQLite3::Database.new("app.db")
  pass = params[:pass]
  db.execute("INSERT INTO users (pass) VALUES (?)", [pass])
  "ok"
end
''',
        "分析过程：\n1. line 6: pass 从参数获取明文密码。\n2. line 7: execute 将明文密码写入 SQLite。\n3. 无哈希，数据库泄露密码全部暴露。\n4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker="pass = params[:pass]", source_desc="params[:pass] 用户提交的明文密码",
        sink_marker='INSERT INTO users (pass) VALUES', sink_desc="将明文密码写入 SQLite users 表",
        explanation="pass 明文 -> execute 写入 SQLite -> 无哈希 -> CWE-312 明文存储",
        fix_marker='INSERT INTO users (pass) VALUES', fix_desc="存储前用 BCrypt::Password.create(pass) 哈希密码"))

    # --- Python: 明文 SMTP 密码写入 ini ---
    S.append(_spec("python", r'''import configparser

def save_mail_config(smtp_password):
    config = configparser.ConfigParser()
    config["smtp"] = {"host": "smtp.example.com", "password": smtp_password}
    with open("mail.ini", "w") as f:
        config.write(f)

def setup():
    save_mail_config("MailPass_987")
''',
        "分析过程：\n1. line 9: 硬编码 SMTP 明文密码。\n2. line 4: 明文密码写入 mail.ini。\n3. 配置文件明文存密码，泄露即暴露。\n4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker='save_mail_config("MailPass_987")', source_desc="硬编码的 SMTP 明文密码",
        sink_marker='config["smtp"] = {"host"', sink_desc="将明文 SMTP 密码写入 ini 配置文件",
        explanation="SMTP 密码硬编码 -> 写入 mail.ini -> CWE-312 明文存储",
        fix_marker='config["smtp"] = {"host"', fix_desc="SMTP 密码从环境变量读取，不写入配置文件"))

    # --- Python: 明文 Redis 密码硬编码到连接 ---
    S.append(_spec("python", r'''import redis

def get_redis():
    return redis.Redis(
        host="localhost",
        port=6379,
        password="redis_secret_456",
    )

def main():
    r = get_redis()
    r.set("key", "value")
''',
        "分析过程：\n1. line 5: 硬编码 Redis 明文密码。\n2. line 3-6: 密码明文用于连接初始化。\n3. 源码泄露即密码暴露。\n4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker='password="redis_secret_456"', source_desc="硬编码的 Redis 明文密码",
        sink_marker='return redis.Redis(', sink_desc="明文密码硬编码在 Redis 连接初始化中",
        explanation="Redis 密码硬编码 -> 连接初始化明文使用 -> 源码泄露暴露 -> CWE-312 明文存储",
        fix_marker='password="redis_secret_456"', fix_desc="Redis 密码从环境变量读取，不硬编码"))

    # --- JavaScript: 明文密码存会话文件（Node） ---
    S.append(_spec("javascript", r'''const fs = require('fs');

function saveSession(user, password) {
    fs.writeFileSync(`/tmp/session_${user}`, password);
}

function login(user, pass) {
    saveSession(user, pass);
}
''',
        "分析过程：\n1. line 7: pass 为明文密码参数。\n2. line 3: 将明文密码写入会话文件。\n3. 会话文件明文存密码，泄露即暴露。\n4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker="function login(user, pass)", source_desc="函数参数 pass（明文密码）",
        sink_marker="fs.writeFileSync(`/tmp/session_", sink_desc="将明文密码写入会话文件",
        explanation="pass 明文 -> 写入会话文件 -> CWE-312 明文存储",
        fix_marker="fs.writeFileSync(`/tmp/session_", fix_desc="会话文件只存会话ID，不存密码；密码用哈希存储"))

    # --- Java: 明文密码存 CSV ---
    S.append(_spec("java", r'''import java.io.FileWriter;

public class ExportUsers {
    public void export(String username, String password) throws Exception {
        FileWriter fw = new FileWriter("users.csv", true);
        fw.write(username + "," + password + "\n");
        fw.close();
    }
}
''',
        "分析过程：\n1. line 4: password 为明文密码参数。\n2. line 5: 明文密码写入 CSV 文件。\n3. CSV 可被随意导出分发，密码明文泄露。\n4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker="export(String username, String password)", source_desc="方法参数 password（明文密码）",
        sink_marker='fw.write(username + "," + password', sink_desc="将明文密码写入 CSV 导出文件",
        explanation="password 明文 -> 写入 CSV -> 导出分发泄露 -> CWE-312 明文存储",
        fix_marker='fw.write(username + "," + password', fix_desc="导出时对密码字段脱敏/加密，不输出明文"))

    # --- Python: 明文 AWS 密钥写环境变量文件 ---
    S.append(_spec("python", r'''import os

def configure_aws():
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    aws_secret = "wJalrXUtnFEMI/K7MDP2EXAMPLE"
    with open("/app/.env", "w") as f:
        f.write(f"AWS_ACCESS_KEY_ID={aws_key}\n")
        f.write(f"AWS_SECRET_ACCESS_KEY={aws_secret}\n")

def main():
    configure_aws()
    os.environ["AWS_ACCESS_KEY_ID"] = "AKIAIOSFODNN7EXAMPLE"
''',
        "分析过程：\n1. line 4-5: 硬编码 AWS 访问密钥。\n2. line 6-8: 明文密钥写入 .env 文件。\n3. .env 常被误提交，密钥明文泄露。\n4. 结论：CWE-312 明文存储敏感信息，风险 Critical。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="Critical",
        source_marker='aws_secret = "wJalrXUtnFEMI/K7MDP2EXAMPLE"', source_desc="硬编码的 AWS 明文密钥",
        sink_marker='open("/app/.env", "w")', sink_desc="将明文 AWS 密钥写入 .env 文件",
        explanation="AWS 密钥硬编码 -> 写入 .env -> 误提交泄露 -> CWE-312 明文存储",
        fix_marker='open("/app/.env", "w")', fix_desc="使用 AWS Secrets Manager / IAM 角色获取凭证，不硬编码不落文件"))

    # --- Go: 明文密码写 Redis（硬编码） ---
    S.append(_spec("go", r'''package main

import "fmt"

func main() {
    host := "localhost:6379"
    pass := "redis_pass_789"
    fmt.Printf("connecting redis %s with password %s\n", host, pass)
}
''',
        "分析过程：\n1. line 6: 硬编码 Redis 明文密码。\n2. line 7: 明文密码被打印/使用。\n3. 密码明文出现在源码与输出中。\n4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker='pass := "redis_pass_789"', source_desc="硬编码的 Redis 明文密码",
        sink_marker='fmt.Printf("connecting redis', sink_desc="明文密码被打印暴露",
        explanation="Redis 密码硬编码 -> 打印暴露 -> CWE-312 明文存储",
        fix_marker='pass := "redis_pass_789"', fix_desc="密码从环境变量读取，不硬编码不打印"))

    # --- PHP: 明文 token 存 Cookie ---
    S.append(_spec("php", r'''<?php
function issueToken() {
    $token = bin2hex(random_bytes(16));
    setcookie('auth_token', $token, 0, '/');
    return $token;
}
$t = issueToken();
''',
        "分析过程：\n1. line 3: 生成 token。\n2. line 4: setcookie 将明文 token 存 Cookie（无 HttpOnly）。\n3. 明文 Cookie 可被 XSS 读取。\n4. 结论：CWE-312 明文存储敏感信息，风险 Medium。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="Medium",
        source_marker="setcookie('auth_token'", source_desc="生成的 token 明文存入 Cookie",
        sink_marker="setcookie('auth_token'", sink_desc="明文 token 存 Cookie（无 HttpOnly）",
        explanation="token 明文 -> setcookie 无 HttpOnly -> XSS 窃取 -> CWE-312 明文存储",
        fix_marker="setcookie('auth_token'", fix_desc="Cookie 设置 HttpOnly 与 Secure，敏感 token 不落前端存储"))

    # --- Python: 明文密码存 pickle 文件（防御迷惑：打包非加密） ---
    S.append(_spec("python", r'''import pickle

def persist_credentials(user, password):
    # 防御迷惑：pickle 序列化不是加密
    with open("/var/storage/creds.pkl", "wb") as f:
        pickle.dump({"user": user, "password": password}, f)

def register(u, p):
    persist_credentials(u, p)
''',
        "分析过程：\n1. line 7: p 为明文密码参数。\n2. line 4: pickle.dump 序列化。\n3. line 3: 写入文件。\n4. 防御迷惑：pickle 序列化可轻易反序列化还原明文。\n5. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker="def register(u, p)", source_desc="函数参数 p（明文密码）",
        sink_marker="pickle.dump({\"user\": user, \"password\": password}", sink_desc="将明文密码以 pickle 序列化存文件（非加密）",
        explanation="密码明文 -> pickle.dump 序列化(非加密) -> 写文件 -> 可反序列化还原 -> CWE-312 明文存储",
        fix_marker="pickle.dump({\"user\": user, \"password\": password}", fix_desc="密码用哈希后存储，不用明文序列化持久化"))

    # --- JavaScript: 明文密码存 IndexedDB ---
    S.append(_spec("javascript", r'''function storeCredential(user, password) {
    const req = indexedDB.open('creds', 1);
    req.onsuccess = (e) => {
        const db = e.target.result;
        const tx = db.transaction('accounts', 'readwrite');
        tx.objectStore('accounts').put({ user, password });
    };
}

function login(u, p) {
    storeCredential(u, p);
}
''',
        "分析过程：\n1. line 9: p 为明文密码参数。\n2. line 5: 将明文密码存入 IndexedDB。\n3. IndexedDB 明文存密码，XSS 可读取。\n4. 结论：CWE-312 明文存储敏感信息，风险 Medium。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="Medium",
        source_marker="function login(u, p)", source_desc="函数参数 p（明文密码）",
        sink_marker="tx.objectStore('accounts').put", sink_desc="将明文密码存入浏览器 IndexedDB",
        explanation="密码明文 -> IndexedDB 存储 -> XSS 可读 -> CWE-312 明文存储",
        fix_marker="tx.objectStore('accounts').put", fix_desc="不要在客户端存储明文密码；密码只在服务端哈希后存储"))

    # --- Java: 明文密码 Hardcode 到常量 ---
    S.append(_spec("java", r'''public class AppConfig {
    public static final String DB_PASSWORD = "root_secret_000";
    public static final String API_SECRET = "api_secret_111";

    public void connect() {
        // 使用明文 DB_PASSWORD 连接
        System.out.println("connecting with " + DB_PASSWORD);
    }
}
''',
        "分析过程：\n1. line 2-3: 硬编码 DB 密码与 API 密钥。\n2. line 6: 明文密码被使用。\n3. 常量明文存源码，反编译/源码泄露即暴露。\n4. 结论：CWE-312 明文存储敏感信息，风险 Critical。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="Critical",
        source_marker='DB_PASSWORD = "root_secret_000"', source_desc="硬编码的数据库明文密码常量",
        sink_marker='System.out.println("connecting with " + DB_PASSWORD', sink_desc="明文密码常量被使用/打印",
        explanation="DB 密码硬编码常量 -> 使用/打印 -> 源码泄露暴露 -> CWE-312 明文存储",
        fix_marker='DB_PASSWORD = "root_secret_000"', fix_desc="密码从环境变量/密钥管理读取，不定义为源码常量"))

    # --- Go: 明文密码写 PostgreSQL（硬编码连接串） ---
    S.append(_spec("go", r'''package main

import "fmt"

func main() {
    connStr := "postgres://admin:Secr3tPass!@localhost/mydb"
    fmt.Println("opening db with connstr")
    _ = connStr
}
''',
        "分析过程：\n1. line 5: 连接串内嵌明文密码。\n2. line 6-7: 明文连接串被使用。\n3. 连接串常出现在日志/监控中，密码暴露。\n4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker='connStr := "postgres://admin:Secr3tPass!@', source_desc="连接串内嵌的数据库明文密码",
        sink_marker='fmt.Println("opening db with connstr")', sink_desc="含明文密码的连接串被使用",
        explanation="连接串明文密码 -> 使用/日志暴露 -> CWE-312 明文存储",
        fix_marker='connStr := "postgres://admin:Secr3tPass!@', fix_desc="连接串中密码从环境变量注入，不内嵌明文"))

    # --- C#: 明文密码存 XML 配置 ---
    S.append(_spec("csharp", r'''using System;
using System.Xml;

class AppConfig
{
    public static void Save(string dbPassword)
    {
        var doc = new XmlDocument();
        var root = doc.CreateElement("config");
        var pwd = doc.CreateElement("dbPassword");
        pwd.InnerText = dbPassword;
        root.AppendChild(pwd);
        doc.AppendChild(root);
        doc.Save("app.config");
    }
}
''',
        "分析过程：\n1. line 6: dbPassword 为明文密码参数。\n2. line 11: 明文密码写入 XML 配置。\n3. 配置文件明文存密码，泄露即暴露。\n4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker="public static void Save(string dbPassword)", source_desc="方法参数 dbPassword（明文密码）",
        sink_marker="pwd.InnerText = dbPassword", sink_desc="将明文密码写入 XML 配置文件",
        explanation="dbPassword 明文 -> XML 配置 -> 泄露暴露 -> CWE-312 明文存储",
        fix_marker="pwd.InnerText = dbPassword", fix_desc="使用受保护配置/密钥管理，密码不明文写入 XML"))

    # --- Python: 明文密码存环境文件（无注释） ---
    S.append(_spec("python", r'''import os

def write_env():
    api_key = "sk-live-abcdef2024"
    with open(".env", "a") as f:
        f.write(api_key + "\n")

write_env()
''',
        "分析过程：\n1. line 4: 硬编码 API Key。\n2. line 5: 明文 Key 写入 .env 文件。\n3. .env 常被误提交到仓库，密钥泄露。\n4. 结论：CWE-312 明文存储敏感信息，风险 High。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="High",
        source_marker='api_key = "sk-live-abcdef2024"', source_desc="硬编码的 API Key",
        sink_marker='open(".env", "a")', sink_desc="将明文 API Key 追加写入 .env 文件",
        explanation="API Key 硬编码 -> 写入 .env -> 误提交泄露 -> CWE-312 明文存储",
        fix_marker='open(".env", "a")', fix_desc="API Key 从环境变量/密钥管理读取，不硬编码不落文件"))

    # --- JavaScript: 明文密码存内存（全局变量） ---
    S.append(_spec("javascript", r'''let globalPassword = null;

function authenticate(user, password) {
    // 明文密码保存在全局变量
    globalPassword = password;
    return verify(user);
}

function verify(user) { return true; }
''',
        "分析过程：\n1. line 4: password 为明文密码参数。\n2. line 5: 明文密码存入全局变量。\n3. 全局变量可被任意代码/堆dump读取，密码常驻内存明文。\n4. 结论：CWE-312 明文存储敏感信息，风险 Medium。",
        has_vuln=True, vuln_type="CWE-312 Cleartext Storage of Sensitive Information", risk="Medium",
        source_marker="function authenticate(user, password)", source_desc="函数参数 password（明文密码）",
        sink_marker="globalPassword = password", sink_desc="明文密码存入全局变量常驻内存",
        explanation="password 明文 -> 全局变量 -> 内存/堆泄露 -> CWE-312 明文存储",
        fix_marker="globalPassword = password", fix_desc="不要将明文密码保存在全局变量；用后立即清除引用"))

    return S


# ===========================================================================
# CWE-434 任意文件上传（6 条）
# ===========================================================================
def gen_file_upload():
    S = []

    # --- PHP: 无校验上传 ---
    S.append(_spec("php", r'''<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $target = '/var/www/uploads/' . basename($_FILES['file']['name']);
    if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
        echo 'upload ok';
    }
}
''',
        "分析过程：\n1. line 3: 文件名直接拼入上传路径。\n2. line 4: move_uploaded_file 保存文件。\n3. 未校验扩展名/MIME，可上传 .php webshell。\n4. 结论：CWE-434 任意文件上传，风险 Critical。",
        has_vuln=True, vuln_type="CWE-434 Unrestricted Upload of File with Dangerous Type", risk="Critical",
        source_marker="basename($_FILES['file']['name'])", source_desc="用户上传的文件名未校验",
        sink_marker="move_uploaded_file(", sink_desc="未校验类型即保存上传文件",
        explanation="文件名未校验 -> move_uploaded_file 保存 -> 可上传 webshell -> CWE-434 任意文件上传",
        fix_marker="move_uploaded_file(", fix_desc="校验扩展名白名单 + 随机重命名 + 校验 MIME/内容嗅探，禁止可执行类型"))

    # --- Java: 无校验上传 ---
    S.append(_spec("java", r'''import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.io.File;

@RestController
public class UploadController {
    @PostMapping("/upload")
    public String upload(@RequestParam("file") MultipartFile file) throws Exception {
        String target = "/tmp/uploads/" + file.getOriginalFilename();
        file.transferTo(new File(target));
        return "ok";
    }
}
''',
        "分析过程：\n1. line 9: 原始文件名直接拼入路径。\n2. line 10: transferTo 保存上传文件。\n3. 未校验类型，可上传 jsp/class webshell。\n4. 结论：CWE-434 任意文件上传，风险 Critical。",
        has_vuln=True, vuln_type="CWE-434 Unrestricted Upload of File with Dangerous Type", risk="Critical",
        source_marker="file.getOriginalFilename()", source_desc="用户上传的原始文件名未校验",
        sink_marker="file.transferTo(new File(target))", sink_desc="未校验类型即保存上传文件",
        explanation="原始文件名未校验 -> transferTo 保存 -> 可上传 webshell -> CWE-434 任意文件上传",
        fix_marker="file.transferTo(new File(target))", fix_desc="扩展名白名单 + 随机重命名 + 校验 MIME/内容，禁止可执行类型"))

    # --- Go: 无校验上传 ---
    S.append(_spec("go", r'''package main

import (
    "io"
    "net/http"
    "os"
)

func UploadHandler(w http.ResponseWriter, r *http.Request) {
    r.ParseMultipartForm(10 << 20)
    file, _, err := r.FormFile("file")
    if err != nil { return }
    defer file.Close()
    dst, _ := os.Create("/tmp/uploads/" + "whatever.bin")
    io.Copy(dst, file)
    w.Write([]byte("ok"))
}
''',
        "分析过程：\n1. line 12: 上传文件名未使用/未校验。\n2. line 15: os.Create 保存上传内容。\n3. 未校验类型即落盘，可上传可执行文件。\n4. 结论：CWE-434 任意文件上传，风险 Critical。",
        has_vuln=True, vuln_type="CWE-434 Unrestricted Upload of File with Dangerous Type", risk="Critical",
        source_marker="r.FormFile(\"file\")", source_desc="用户上传的文件对象",
        sink_marker="os.Create(\"/tmp/uploads/", sink_desc="未校验类型即保存上传文件",
        explanation="上传文件未校验 -> os.Create 落盘 -> 可上传可执行文件 -> CWE-434 任意文件上传",
        fix_marker="os.Create(\"/tmp/uploads/", fix_desc="校验扩展名白名单 + 随机重命名 + 校验内容类型，禁止可执行类型"))

    # --- Python: Content-Type 绕过（只校验 Content-Type 头） ---
    S.append(_spec("python", r'''from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    # 只校验 Content-Type 头，可被伪造
    if file.content_type not in ("image/png", "image/jpeg"):
        return "bad type", 400
    file.save(os.path.join("/var/uploads", file.filename))
    return "ok"
''',
        "分析过程：\n1. line 8: 上传文件。\n2. line 10: 只校验 Content-Type 头。\n3. line 12: 原文件名直接保存。\n4. 漏洞：Content-Type 头可被客户端伪造，且未校验扩展名/内容，可上传 .php 但 Content-Type 伪装成 image/png。\n5. 结论：CWE-434 任意文件上传，风险 Critical。",
        has_vuln=True, vuln_type="CWE-434 Unrestricted Upload of File with Dangerous Type", risk="Critical",
        source_marker='file.content_type not in', source_desc="仅校验可伪造的 Content-Type 头",
        sink_marker='file.save(os.path.join("/var/uploads"', sink_desc="未校验扩展名/内容即保存上传文件",
        explanation="Content-Type 可伪造 -> 未校验扩展名 -> 原文件名保存 -> 可上传 webshell -> CWE-434 任意文件上传",
        fix_marker='file.save(os.path.join("/var/uploads"', fix_desc="校验扩展名白名单 + 随机重命名 + 校验文件内容签名，不依赖 Content-Type"))

    # --- Python: 双扩展名绕过（.jpg.php） ---
    S.append(_spec("python", r'''from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    name = file.filename
    # 只检查是否以 .jpg 结尾，可被 .jpg.php 绕过
    if name.endswith(".jpg"):
        file.save(os.path.join("/var/uploads", name))
        return "ok"
    return "bad", 400
''',
        "分析过程：\n1. line 8: 上传文件。\n2. line 10: 只检查文件名是否以 .jpg 结尾。\n3. line 11: 原文件名直接保存。\n4. 漏洞：.jpg.php 以 .jpg 结尾但实际是 PHP，可被服务端执行。\n5. 结论：CWE-434 任意文件上传，风险 Critical。",
        has_vuln=True, vuln_type="CWE-434 Unrestricted Upload of File with Dangerous Type", risk="Critical",
        source_marker="if name.endswith(\".jpg\")", source_desc="仅检查文件名后缀（双扩展名可绕过）",
        sink_marker='file.save(os.path.join("/var/uploads"', sink_desc="仅按 .jpg 结尾判断即保存上传文件",
        explanation=".jpg.php 以 .jpg 结尾 -> 绕过检查 -> 保存为可执行 PHP -> CWE-434 任意文件上传",
        fix_marker='file.save(os.path.join("/var/uploads"', fix_desc="用扩展名白名单校验最终后缀 + 随机重命名，禁止可执行类型"))

    # --- Python: 路径穿越上传（文件名含 ../） ---
    S.append(_spec("python", r'''from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    name = file.filename          # 未净化
    target = os.path.join("/var/uploads", name)
    file.save(target)
    return "ok"
''',
        "分析过程：\n1. line 9: 上传文件名未净化。\n2. line 10: 文件名直接拼入保存路径。\n3. line 11: 保存文件。\n4. 漏洞：文件名含 ../ 可目录穿越写任意可执行文件。\n5. 结论：CWE-434 任意文件上传，风险 Critical。",
        has_vuln=True, vuln_type="CWE-434 Unrestricted Upload of File with Dangerous Type", risk="Critical",
        source_marker="name = file.filename", source_desc="上传文件名未净化",
        sink_marker="file.save(target)", sink_desc="文件名含路径穿越，保存到任意目录",
        explanation="文件名未净化 -> os.path.join 拼接 -> 含 ../ 可穿越目录 -> 写可执行文件 -> CWE-434 任意文件上传",
        fix_marker="file.save(target)", fix_desc="使用 basename 取出文件名 + 随机重命名，限制保存目录，校验最终路径"))

    return S


# ===========================================================================
# CWE-367 TOCTOU（4 条）
# ===========================================================================
def gen_toctou():
    S = []

    # --- Python: os.path.exists + open TOCTOU ---
    S.append(_spec("python", r'''import os

def read_user_file(path):
    # 先检查存在再打开，存在 TOCTOU 窗口
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return f.read()

def main():
    usr = input("path: ")
    print(read_user_file(usr))
''',
        "分析过程：\n1. line 4: os.path.exists 检查文件存在。\n2. line 6: open 读取文件。\n3. 漏洞：exists 与 open 之间攻击者可把 path 替换为符号链接指向敏感文件。\n4. 结论：CWE-367 TOCTOU 竞争条件，风险 High。",
        has_vuln=True, vuln_type="CWE-367 Time-of-check Time-of-use (TOCTOU) Race Condition", risk="High",
        source_marker='input("path:', source_desc="用户可控的文件路径",
        sink_marker='open(path, "r")', sink_desc="exists 检查后打开文件（可被符号链接替换）",
        explanation="用户路径 -> os.path.exists 检查通过 -> 窗口内替换为符号链接 -> open 读取敏感文件 -> CWE-367 TOCTOU",
        fix_marker='open(path, "r")', fix_desc="直接 open 后基于文件描述符/内容校验，避免检查后使用；或使用 O_NOFOLLOW 拒绝符号链接"))

    # --- Go: os.Stat + os.Open TOCTOU ---
    S.append(_spec("go", r'''package main

import (
    "os"
)

func ReadIfRegular(path string) ([]byte, error) {
    info, err := os.Stat(path)
    if err != nil { return nil, err }
    if !info.Mode().IsRegular() {
        return nil, os.ErrInvalid
    }
    return os.ReadFile(path)
}

func main() {
    p := os.Args[1]
    ReadIfRegular(p)
}
''',
        "分析过程：\n1. line 8: os.Stat 检查文件属性。\n2. line 12: os.ReadFile 读取文件。\n3. 漏洞：Stat 与 ReadFile 之间攻击者可替换 path 为符号链接。\n4. 结论：CWE-367 TOCTOU 竞争条件，风险 High。",
        has_vuln=True, vuln_type="CWE-367 Time-of-check Time-of-use (TOCTOU) Race Condition", risk="High",
        source_marker="p := os.Args[1]", source_desc="用户可控的文件路径",
        sink_marker="os.ReadFile(path)", sink_desc="Stat 检查后读取文件（可被符号链接替换）",
        explanation="用户路径 -> os.Stat 检查 -> 窗口内替换符号链接 -> os.ReadFile 读敏感文件 -> CWE-367 TOCTOU",
        fix_marker="os.ReadFile(path)", fix_desc="直接打开后用 fstat 校验已打开描述符，避免检查后使用；或使用 O_NOFOLLOW"))

    # --- Java: File.isFile + FileInputStream TOCTOU ---
    S.append(_spec("java", r'''import java.io.File;
import java.io.FileInputStream;

public class ReadFile {
    public static String readIfFile(String path) throws Exception {
        File f = new File(path);
        if (!f.isFile()) { return null; }
        try (FileInputStream in = new FileInputStream(f)) {
            byte[] b = in.readAllBytes();
            return new String(b);
        }
    }
    public static void main(String[] a) throws Exception {
        readIfFile(a[0]);
    }
}
''',
        "分析过程：\n1. line 6: new File + f.isFile 检查。\n2. line 7: FileInputStream 打开文件。\n3. 漏洞：isFile 与打开之间攻击者可替换为符号链接。\n4. 结论：CWE-367 TOCTOU 竞争条件，风险 High。",
        has_vuln=True, vuln_type="CWE-367 Time-of-check Time-of-use (TOCTOU) Race Condition", risk="High",
        source_marker='readIfFile(a[0])', source_desc="用户可控的文件路径参数",
        sink_marker="new FileInputStream(f)", sink_desc="isFile 检查后打开文件（可被符号链接替换）",
        explanation="用户路径 -> f.isFile 检查 -> 窗口内替换符号链接 -> FileInputStream 读敏感文件 -> CWE-367 TOCTOU",
        fix_marker="new FileInputStream(f)", fix_desc="直接打开后基于已打开句柄校验，避免检查后使用；Java 使用 NIO 的 NOFOLLOW"))

    # --- PHP: file_exists + file_get_contents TOCTOU ---
    S.append(_spec("php", r'''<?php
function safeRead($path) {
    if (!file_exists($path)) {
        return null;
    }
    return file_get_contents($path);
}
$p = $_GET['path'] ?? '';
echo safeRead($p);
''',
        "分析过程：\n1. line 3: file_exists 检查文件存在。\n2. line 6: file_get_contents 读取。\n3. 漏洞：检查与使用之间攻击者可替换为符号链接。\n4. 结论：CWE-367 TOCTOU 竞争条件，风险 High。",
        has_vuln=True, vuln_type="CWE-367 Time-of-check Time-of-use (TOCTOU) Race Condition", risk="High",
        source_marker="$_GET['path']", source_desc="用户可控的文件路径参数",
        sink_marker="file_get_contents($path)", sink_desc="file_exists 检查后读取（可被符号链接替换）",
        explanation="用户路径 -> file_exists 检查 -> 窗口内替换符号链接 -> file_get_contents 读敏感文件 -> CWE-367 TOCTOU",
        fix_marker="file_get_contents($path)", fix_desc="用 realpath 解析并校验规范路径，或直接打开后基于句柄校验，避免检查后使用"))

    return S


# ===========================================================================
# 主函数
# ===========================================================================
def main():
    generators = [
        ("CWE-312 明文存储", gen_cleartext),
        ("CWE-434 任意文件上传", gen_file_upload),
        ("CWE-367 TOCTOU", gen_toctou),
    ]
    all_specs = []
    for name, gen in generators:
        specs = gen()
        print(f"  [{name}] 生成 {len(specs)} 条")
        all_specs.extend(specs)

    total = len(all_specs)
    print(f"\n总样本数: {total}")

    # 校验
    errors = 0
    for i, spec in enumerate(all_specs, 1):
        e = validate_spec(spec)
        if e:
            errors += 1
            print(f"  [FAIL] #{i}: {e}")
    if errors:
        print(f"\n[错误] 校验失败 {errors} 条")
        return 1
    print("  所有样本校验通过。")

    # 写入
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for spec in all_specs:
            rec = make_sample(spec["lang"], spec["code"], spec["analysis"], spec["verdict"])
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"\n输出: {OUTPUT_FILE} ({total} 条)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())