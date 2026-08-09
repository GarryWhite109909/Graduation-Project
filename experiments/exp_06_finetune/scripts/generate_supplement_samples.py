#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""为量级偏低的 CWE 生成补充训练样本。

覆盖 31 个 CWE（18 个最优先 + 13 个次优先），共 654 条样本。
每条样本为 ChatML JSONL 格式，包含 system/user/assistant 三条消息。
约 20% 样本含"防御迷惑"代码（看似有防护但可被绕过）。

用法:
  cd experiments/exp_06_finetune
  python scripts/generate_supplement_samples.py

输出:
  data/supplement_samples.jsonl
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path

# === 导入项目统一 system prompt ===
PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))
from graduation_project.prompts import BASE_PROMPT as SYSTEM_PROMPT

OUTPUT_FILE = Path(__file__).resolve().parents[1] / "data" / "supplement_samples.jsonl"

# === 目标补充数量 ===
TARGETS = {
    "CWE-295": 25, "CWE-329": 22, "CWE-843": 21, "CWE-347": 21,
    "CWE-1321": 23, "CWE-287": 27, "CWE-113": 26, "CWE-319": 28,
    "CWE-400": 28, "CWE-532": 28, "CWE-770": 28, "CWE-91": 28,
    "CWE-610": 28, "CWE-797": 28, "CWE-93": 29, "CWE-759": 29,
    "CWE-401": 26, "CWE-204": 27, "CWE-915": 17, "CWE-208": 12,
    "CWE-476": 17, "CWE-200": 17, "CWE-73": 15, "CWE-98": 16,
    "CWE-409": 17, "CWE-917": 18, "CWE-123": 18, "CWE-613": 14,
    "CWE-122": 5, "CWE-362": 8, "CWE-1333": 8,
}

# ===========================================================================
# 名称池（通过循环索引生成多样化变体）
# ===========================================================================
PF = ["fetch_data","get_info","retrieve","process_req","handle_call","load_data","fetch_api","query_svc","pull_info","call_ep"]
PP = ["url","endpoint","target","source","path","input","req_url","api_target","data_src","remote"]
PN = ["api_client.py","service.py","handler.py","utils.py","client.py","gateway.py","proxy.py","fetcher.py","adapter.py","connector.py"]
PS = ["获取外部API数据","调用webhook回调","爬取页面","集成第三方服务","数据管道拉取","微服务通信","CI/CD触发","运维自动化","配置同步","监控上报"]

JF = ["fetchData","getInfo","retrieve","processReq","handleCall","loadData","fetchApi","querySvc","pullInfo","callEp"]
JP = ["url","endpoint","target","source","path","input","reqUrl","apiTarget","dataSrc","remote"]
JN = ["api_client.js","service.js","handler.js","utils.js","client.js","gateway.js","proxy.js","fetcher.js","adapter.js","connector.js"]
JS = ["获取外部API数据","调用webhook回调","爬取页面","集成第三方服务","数据管道拉取","微服务通信","CI/CD触发","运维自动化","配置同步","监控上报"]

AF = ["fetchData","getInfo","retrieve","processReq","handleCall","loadData","fetchApi","querySvc","pullInfo","callEp"]
AP = ["url","endpoint","target","source","path","input","reqUrl","apiTarget","dataSrc","remote"]
AN = ["ApiClient.java","Service.java","Handler.java","Utils.java","Client.java","Gateway.java","Proxy.java","Fetcher.java","Adapter.java","Connector.java"]
AS = ["获取外部API数据","调用webhook回调","爬取页面","集成第三方服务","数据管道拉取","微服务通信","CI/CD触发","运维自动化","配置同步","监控上报"]

GF = ["FetchURL","GetData","Retrieve","ProcessReq","HandleCall","LoadData","FetchAPI","QuerySvc","PullInfo","CallEp"]
GP = ["url","endpoint","target","source","path","input","reqURL","apiTarget","dataSrc","remote"]
GN = ["api_client.go","service.go","handler.go","utils.go","client.go","gateway.go","proxy.go","fetcher.go","adapter.go","connector.go"]
GS = ["获取外部API数据","调用webhook回调","爬取页面","集成第三方服务","数据管道拉取","微服务通信","CI/CD触发","运维自动化","配置同步","监控上报"]

CF = ["fetch_data","get_data","retrieve","process_req","handle_call","load_data"]
CP = ["url","endpoint","target","source","path","input"]
CN = ["api_client.c","service.c","handler.c","utils.c","client.c","gateway.c"]
CS = ["网络请求处理","数据获取","资源检索","请求处理","调用处理","数据加载"]

HF = ["fetch_data","get_info","retrieve","process_req","handle_call","load_data"]
HP = ["url","endpoint","target","source","path","input"]
HN = ["api_client.php","service.php","handler.php","utils.php","client.php","gateway.php"]
HS = ["获取外部API数据","调用webhook回调","爬取页面","集成第三方服务","数据管道拉取","微服务通信"]

BF = ["fetch_data","get_info","retrieve","process_req","handle_call","load_data"]
BP = ["url","endpoint","target","source","path","input"]
BN = ["api_client.sh","service.sh","handler.sh","utils.sh","client.sh","gateway.sh"]
BS = ["获取外部API数据","调用webhook回调","爬取页面","集成第三方服务","数据管道拉取","微服务通信"]


def pv(n, o=0):
    """Python 变体生成器: n=数量, o=偏移"""
    return [{"func": PF[(i+o)%10], "param": PP[(i+o)%10], "fname": PN[(i+o)%10], "scene": PS[(i+o)%10]} for i in range(n)]

def jv(n, o=0):
    return [{"func": JF[(i+o)%10], "param": JP[(i+o)%10], "fname": JN[(i+o)%10], "scene": JS[(i+o)%10]} for i in range(n)]

def av(n, o=0):
    return [{"func": AF[(i+o)%10], "param": AP[(i+o)%10], "fname": AN[(i+o)%10], "scene": AS[(i+o)%10]} for i in range(n)]

def gv(n, o=0):
    return [{"func": GF[(i+o)%10], "param": GP[(i+o)%10], "fname": GN[(i+o)%10], "scene": GS[(i+o)%10]} for i in range(n)]

def cv(n, o=0):
    return [{"func": CF[(i+o)%6], "param": CP[(i+o)%6], "fname": CN[(i+o)%6], "scene": CS[(i+o)%6]} for i in range(n)]

def hv(n, o=0):
    return [{"func": HF[(i+o)%6], "param": HP[(i+o)%6], "fname": HN[(i+o)%6], "scene": HS[(i+o)%6]} for i in range(n)]

def bv(n, o=0):
    return [{"func": BF[(i+o)%6], "param": BP[(i+o)%6], "fname": BN[(i+o)%6], "scene": BS[(i+o)%6]} for i in range(n)]


# ===========================================================================
# 辅助函数
# ===========================================================================

def fmt(tpl, **kw):
    """安全字符串替换: 将 {key} 替换为对应值。使用 str.replace 避免 format 的花括号转义问题。"""
    r = tpl
    for k, v in kw.items():
        r = r.replace("{" + k + "}", str(v))
    return r


def expand(lang, code_tpl, analysis_tpl, verdict_tpl, variants, dc=False):
    """将模板 + 变体列表展开为样本列表。"""
    out = []
    for v in variants:
        v = dict(v)  # copy to avoid mutating shared dicts
        if "fname" in v:
            v["cls"] = v["fname"].split(".")[0]
        code = fmt(code_tpl, **v)
        analysis = fmt(analysis_tpl, **v)
        verdict = {}
        for k, val in verdict_tpl.items():
            verdict[k] = fmt(val, **v) if isinstance(val, str) else val
        out.append({"lang": lang, "code": code, "analysis": analysis, "verdict": verdict, "dc": dc})
    return out


def build_user(lang, code):
    if not code.endswith("\n"):
        code += "\n"
    return f"代码片段（语言: {lang}）：\n```{lang}\n{code}```\n请先给出分析过程，然后在最后给出 JSON 结论。"


def build_assistant(analysis, verdict):
    return f"{analysis}\n\n```json\n{json.dumps(verdict, ensure_ascii=False)}\n```"


def build_chatml(sample):
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user(sample["lang"], sample["code"])},
            {"role": "assistant", "content": build_assistant(sample["analysis"], sample["verdict"])},
        ]
    }


# ===========================================================================
# CWE 生成器
# ===========================================================================

def g_295():
    """CWE-295 Improper Certificate Validation (25)"""
    R = []
    # T1: Python requests verify=False (5)
    R += expand("python",
        "# {fname}\nimport requests\ndef {func}({param}):\n    resp = requests.get({param}, verify=False)  # line 4\n    return resp.json()\n",
        "分析过程：\n1. line 3 定义 {func}({param})，{param} 来自外部调用，场景：{scene}。\n2. line 4 requests.get({param}, verify=False) 中 verify=False 禁用 TLS 证书验证。\n3. 攻击者可中间人攻击伪造证书，截获或篡改通信内容。\n4. 结论：CWE-295 证书验证缺失，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-295 Improper Certificate Validation", "risk_level": "High",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部调用", "sink": "line 4: requests.get({param}, verify=False) 禁用证书验证",
         "explanation": "line 3 {param} 来自外部 -> line 4 requests.get(verify=False) 不校验证书 -> 中间人可伪造证书截获通信",
         "fix_suggestion": "line 4: 应改为 requests.get(param, verify=True) 启用证书验证或指定 CA bundle 路径"},
        pv(5))
    # T2: Python ssl CERT_NONE (4)
    R += expand("python",
        "# {fname}\nimport ssl\nimport urllib.request\ndef {func}({param}):\n    ctx = ssl.create_default_context()  # line 4\n    ctx.check_hostname = False  # line 5\n    ctx.verify_mode = ssl.CERT_NONE  # line 6\n    return urllib.request.urlopen({param}, context=ctx).read()\n",
        "分析过程：\n1. line 4 创建 SSL 上下文，line 5 关闭主机名检查，line 6 设为 CERT_NONE 完全禁用证书验证。\n2. line 7 使用不安全上下文发起请求，{param} 来自外部，场景：{scene}。\n3. 攻击者可伪造证书进行中间人攻击。\n4. 结论：CWE-295 证书验证缺失，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-295 Improper Certificate Validation", "risk_level": "High",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部调用", "sink": "line 6: ctx.verify_mode = ssl.CERT_NONE 禁用证书验证",
         "explanation": "line 5 check_hostname=False -> line 6 CERT_NONE -> line 7 urlopen 使用不安全上下文 -> MITM 可伪造证书",
         "fix_suggestion": "line 5-6: 应改为使用默认 ssl.create_default_context() 不修改 check_hostname 和 verify_mode"},
        pv(4, o=5))
    # T3: Java TrustManager (4)
    R += expand("java",
        "// {fname}\nimport javax.net.ssl.*;\nimport java.net.URL;\npublic class {cls} {{\n    public String {func}(String {param}) throws Exception {{\n        TrustManager[] tm = {{ new X509TrustManager() {{\n            public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {{}}\n            public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {{}}\n            public java.security.cert.X509Certificate[] getAcceptedIssuers() {{ return null; }}  // line 9\n        }}}};\n        SSLContext ctx = SSLContext.getInstance(\"TLS\");\n        ctx.init(null, tm, null);  // line 12: 传入空 TrustManager\n        return new URL({param}).openConnection().getInputStream().toString();\n    }}\n}}\n",
        "分析过程：\n1. line 7-10 实现 X509TrustManager 但所有方法为空，checkServerTrusted 不做任何校验。\n2. line 12 将空 TrustManager 传入 SSLContext，line 13 使用不安全上下文连接 {param}。\n3. 攻击者可使用任意证书，服务端证书不被验证。\n4. 结论：CWE-295 证书验证缺失，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-295 Improper Certificate Validation", "risk_level": "High",
         "source": "line 4: {func}({param}) 参数 {param} 来自外部调用", "sink": "line 12: ctx.init(null, tm, null) 使用不校验证书的 TrustManager",
         "explanation": "line 7-10 空 TrustManager -> line 12 init -> line 13 连接不校验证书 -> MITM 可伪造证书",
         "fix_suggestion": "line 7-12: 应改为使用系统默认 SSLContext.getInstance(\"TLS\") 不传入自定义 TrustManager"},
        av(4))
    # T4: Node.js rejectUnauthorized (4)
    R += expand("javascript",
        "// {fname}\nconst https = require('https');\nfunction {func}({param}) {{\n    return new Promise((resolve, reject) => {{\n        https.get({param}, {{ rejectUnauthorized: false }}, (res) => {{  // line 5\n            let data = '';\n            res.on('data', (chunk) => data += chunk);\n            res.on('end', () => resolve(data));\n        }}).on('error', reject);\n    }});\n}}\n",
        "分析过程：\n1. line 5 https.get({param}, {{ rejectUnauthorized: false }}) 禁用证书验证。\n2. {param} 来自外部调用，场景：{scene}。\n3. 攻击者可使用自签名证书进行中间人攻击。\n4. 结论：CWE-295 证书验证缺失，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-295 Improper Certificate Validation", "risk_level": "High",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部调用", "sink": "line 5: https.get({param}, {{ rejectUnauthorized: false }}) 禁用证书验证",
         "explanation": "line 5 rejectUnauthorized=false -> https 连接不校验证书 -> MITM 可伪造证书截获通信",
         "fix_suggestion": "line 5: 应改为移除 rejectUnauthorized: false 选项，使用默认的证书验证"},
        jv(4, o=5))
    # T5: Go InsecureSkipVerify (4)
    R += expand("go",
        "// {fname}\nimport (\n    \"crypto/tls\"\n    \"net/http\"\n)\nfunc {func}({param} string) (string, error) {\n    tr := &http.Transport{\n        TLSClientConfig: &tls.Config{{InsecureSkipVerify: true}},  // line 8\n    }\n    client := &http.Client{{Transport: tr}}\n    resp, err := client.Get({param})  // line 11\n    if err != nil {\n        return \"\", err\n    }\n    defer resp.Body.Close()\n    return resp.Status, nil\n}\n",
        "分析过程：\n1. line 8 TLSClientConfig 设 InsecureSkipVerify: true 禁用证书验证。\n2. line 11 client.Get({param}) 使用不安全传输发起请求，{param} 来自外部，场景：{scene}。\n3. 攻击者可伪造证书进行中间人攻击。\n4. 结论：CWE-295 证书验证缺失，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-295 Improper Certificate Validation", "risk_level": "High",
         "source": "line 6: {func}({param} string) 参数 {param} 来自外部调用", "sink": "line 8: InsecureSkipVerify: true 禁用证书验证",
         "explanation": "line 8 InsecureSkipVerify=true -> line 11 client.Get 使用不安全传输 -> MITM 可伪造证书",
         "fix_suggestion": "line 8: 应改为移除 InsecureSkipVerify: true 或设为 false，使用系统 CA 证书池"},
        gv(4))
    # T6: DC hostname whitelist but verify=False (4)
    R += expand("python",
        "# {fname}\nimport requests\nTRUSTED = [\"api.trusted.com\", \"cdn.trusted.com\", \"hook.trusted.com\"]\ndef {func}({param}):\n    host = {param}.split(\"//\")[1].split(\"/\")[0]\n    if host not in TRUSTED:  # line 6: hostname whitelist\n        raise ValueError(\"untrusted host\")\n    resp = requests.get({param}, verify=False)  # line 8: still no cert validation\n    return resp.text\n",
        "分析过程：\n1. line 6 检查 hostname 白名单，看似有防护，但 line 8 仍用 verify=False。\n2. 白名单只校验域名，不校验证书，攻击者在同一网络可 DNS 劫持 + 伪造证书。\n3. hostname 白名单无法替代证书验证，MITM 仍可截获通信。\n4. 结论：CWE-295 证书验证缺失（防御可绕过），风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-295 Improper Certificate Validation", "risk_level": "High",
         "source": "line 4: {func}({param}) 参数 {param} 来自外部调用", "sink": "line 8: requests.get({param}, verify=False) 禁用证书验证",
         "explanation": "line 6 hostname 白名单看似防护 -> line 8 verify=False 不校验证书 -> DNS 劫持 + 伪造证书可绕过",
         "fix_suggestion": "line 8: 应改为 requests.get(param, verify=True)，hostname 白名单不能替代证书验证"},
        pv(4, o=2), dc=True)
    return R


def g_329():
    """CWE-329 Not Using a Random IV (22)"""
    R = []
    # T1: Python AES hardcoded IV (5)
    R += expand("python",
        "# {fname}\nfrom Crypto.Cipher import AES\nimport base64\nKEY = b'16bytesecretkey!'\nIV = b'1234567890123456'  # line 6: hardcoded IV\ndef {func}({param}):\n    cipher = AES.new(KEY, AES.MODE_CBC, IV)  # line 8\n    ct = cipher.encrypt({param}.encode().ljust(16, b'\\0'))\n    return base64.b64encode(ct).decode()\n",
        "分析过程：\n1. line 6 IV 为硬编码固定值 b'1234567890123456'，非随机生成。\n2. line 8 AES.new 使用固定 IV 加密，{param} 来自外部，场景：{scene}。\n3. 固定 IV 导致相同明文产生相同密文，攻击者可通过密文模式推断明文规律。\n4. 结论：CWE-329 未使用随机 IV，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-329 Not Using a Random IV", "risk_level": "Medium",
         "source": "line 7: {func}({param}) 参数 {param} 来自外部调用", "sink": "line 8: AES.new(KEY, AES.MODE_CBC, IV) 使用硬编码 IV",
         "explanation": "line 6 IV 硬编码 -> line 8 AES.new 使用固定 IV -> 相同明文产生相同密文 -> 密文模式可推断明文",
         "fix_suggestion": "line 6: 应改为 IV = os.urandom(16) 每次加密生成随机 IV，并将 IV 与密文一同传输"},
        pv(5))
    # T2: Java fixed IV (4)
    R += expand("java",
        "// {fname}\nimport javax.crypto.*;\nimport javax.crypto.spec.*;\nimport java.util.Base64;\npublic class {cls} {{\n    static byte[] KEY = \"16bytesecretkey!\".getBytes();\n    static byte[] IV = \"fixediv123456789\".getBytes();  // line 6\n    public static String {func}(String {param}) throws Exception {{\n        Cipher cipher = Cipher.getInstance(\"AES/CBC/PKCS5Padding\");\n        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, \"AES\"), new IvParameterSpec(IV));  // line 9\n        return Base64.getEncoder().encodeToString(cipher.doFinal({param}.getBytes()));\n    }}\n}}\n",
        "分析过程：\n1. line 6 IV 为固定字节串 \"fixediv123456789\"，非随机生成。\n2. line 9 cipher.init 使用固定 IV 加密 {param}，场景：{scene}。\n3. 固定 IV 导致相同明文产生相同密文，破坏 CBC 模式的语义安全。\n4. 结论：CWE-329 未使用随机 IV，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-329 Not Using a Random IV", "risk_level": "Medium",
         "source": "line 8: {func}(String {param}) 参数 {param} 来自外部", "sink": "line 9: cipher.init 使用固定 IvParameterSpec(IV)",
         "explanation": "line 6 固定 IV -> line 9 init 使用固定 IV -> 相同明文产生相同密文 -> 语义安全被破坏",
         "fix_suggestion": "line 6: 应改为 SecureRandom 生成随机 IV，每次加密使用不同 IV"},
        av(4))
    # T3: Node.js static IV (4)
    R += expand("javascript",
        "// {fname}\nconst crypto = require('crypto');\nconst KEY = Buffer.from('16bytesecretkey!', 'utf8');\nconst IV = Buffer.from('staticiv12345678', 'utf8');  // line 5\nfunction {func}({param}) {{\n    const cipher = crypto.createCipheriv('aes-128-cbc', KEY, IV);  // line 7\n    let encrypted = cipher.update({param}, 'utf8', 'base64');\n    encrypted += cipher.final('base64');\n    return encrypted;\n}}\n",
        "分析过程：\n1. line 5 IV 为静态字符串 'staticiv12345678'，非随机生成。\n2. line 7 createCipheriv 使用静态 IV 加密 {param}，场景：{scene}。\n3. 静态 IV 导致相同明文产生相同密文，攻击者可识别重复明文。\n4. 结论：CWE-329 未使用随机 IV，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-329 Not Using a Random IV", "risk_level": "Medium",
         "source": "line 6: {func}({param}) 参数 {param} 来自外部", "sink": "line 7: crypto.createCipheriv 使用静态 IV",
         "explanation": "line 5 静态 IV -> line 7 createCipheriv 使用静态 IV -> 相同明文产生相同密文 -> 语义安全被破坏",
         "fix_suggestion": "line 5: 应改为 crypto.randomBytes(16) 每次生成随机 IV"},
        jv(4, o=5))
    # T4: Go fixed IV (4)
    R += expand("go",
        "// {fname}\nimport (\n    \"crypto/aes\"\n    \"crypto/cipher\"\n    \"encoding/base64\"\n)\nvar key = []byte(\"16bytesecretkey!\")\nvar iv = []byte(\"fixediv12345678\")  // line 8\nfunc {func}({param} string) string {\n    block, _ := aes.NewCipher(key)\n    mode := cipher.NewCBCEncrypter(block, iv)  // line 11\n    ct := make([]byte, len({param}))\n    mode.CryptBlocks(ct, []byte({param}))\n    return base64.StdEncoding.EncodeToString(ct)\n}\n",
        "分析过程：\n1. line 8 iv 为固定字节串，非随机生成。\n2. line 11 NewCBCEncrypter 使用固定 iv 加密 {param}，场景：{scene}。\n3. 固定 IV 破坏 CBC 语义安全，相同明文产生相同密文。\n4. 结论：CWE-329 未使用随机 IV，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-329 Not Using a Random IV", "risk_level": "Medium",
         "source": "line 9: {func}({param} string) 参数 {param} 来自外部", "sink": "line 11: cipher.NewCBCEncrypter(block, iv) 使用固定 iv",
         "explanation": "line 8 固定 iv -> line 11 NewCBCEncrypter 使用固定 iv -> 相同明文产生相同密文 -> 语义安全被破坏",
         "fix_suggestion": "line 8: 应改为使用 crypto/rand 生成随机 IV，每次加密使用不同 IV"},
        gv(4))
    # T5: DC seed-based IV (5)
    R += expand("python",
        "# {fname}\nfrom Crypto.Cipher import AES\nimport base64\nimport random\nKEY = b'16bytesecretkey!'\ndef {func}({param}):\n    random.seed(42)  # line 6: fixed seed\n    iv = bytes([random.randint(0, 255) for _ in range(16)])  # line 7: deterministic IV\n    cipher = AES.new(KEY, AES.MODE_CBC, iv)\n    ct = cipher.encrypt({param}.encode().ljust(16, b'\\0'))\n    return base64.b64encode(ct).decode()\n",
        "分析过程：\n1. line 6 random.seed(42) 使用固定种子，line 7 生成的 IV 看似随机但实际确定。\n2. 每次调用生成相同 IV，等价于硬编码 IV，{param} 来自外部，场景：{scene}。\n3. 攻击者可复现种子推导 IV，相同明文产生相同密文。\n4. 结论：CWE-329 未使用随机 IV（伪随机），风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-329 Not Using a Random IV", "risk_level": "Medium",
         "source": "line 5: {func}({param}) 参数 {param} 来自外部", "sink": "line 7: bytes([random.randint...]) 使用确定种子的伪随机 IV",
         "explanation": "line 6 seed(42) 固定种子 -> line 7 生成确定性 IV -> 每次相同 IV -> 等价硬编码 IV",
         "fix_suggestion": "line 6-7: 应改为使用 os.urandom(16) 生成密码学安全随机 IV，不用 random 模块"},
        pv(5, o=5), dc=True)
    return R


def g_843():
    """CWE-843 Type Confusion (21)"""
    R = []
    # T1: C++ union wrong member (4)
    R += expand("cpp",
        "// {fname}\n#include <iostream>\nunion Value {\n    int as_int;\n    float as_float;\n    char* as_str;\n};\nvoid {func}(int {param}) {\n    Value v;\n    v.as_int = {param};  // line 10: stored as int\n    std::cout << v.as_float << std::endl;  // line 11: read as float - type confusion\n}\n",
        "分析过程：\n1. line 10 将 {param} 作为 int 存入 union，line 11 作为 float 读取。\n2. union 成员共享内存，以错误类型读取导致类型混淆。\n3. int 的位模式被解释为 float，产生未定义行为。\n4. 结论：CWE-843 类型混淆，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-843 Type Confusion", "risk_level": "Medium",
         "source": "line 9: {func}(int {param}) 参数 {param} 来自外部", "sink": "line 11: v.as_float 读取 int 类型的 union 成员",
         "explanation": "line 10 v.as_int 存储 int -> line 11 v.as_float 读取 float -> union 类型混淆 -> 未定义行为",
         "fix_suggestion": "line 11: 应改为使用正确类型 v.as_int 读取，或用 tagged union 记录当前活跃成员"},
        cv(4))
    # T2: C++ reinterpret_cast (4)
    R += expand("cpp",
        "// {fname}\n#include <cstring>\n#include <cstdio>\nvoid {func}(char* {param}) {\n    int* ptr = reinterpret_cast<int*>({param});  // line 5: type confusion\n    *ptr = 0x41414141;  // line 6: write as int\n    printf(\"%s\\n\", {param});  // line 7: read as string\n}\n",
        "分析过程：\n1. line 5 将 char* {param} 通过 reinterpret_cast 强转为 int*，类型混淆。\n2. line 6 通过 int* 写入 4 字节，line 7 仍作为字符串读取。\n3. 类型不兼容的指针转换导致内存解释错误，可能破坏数据。\n4. 结论：CWE-843 类型混淆，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-843 Type Confusion", "risk_level": "High",
         "source": "line 4: {func}(char* {param}) 参数 {param} 来自外部", "sink": "line 5: reinterpret_cast<int*>({param}) 类型混淆",
         "explanation": "line 5 char* 强转 int* -> line 6 写入 int -> line 7 读取 char* -> 类型混淆破坏内存",
         "fix_suggestion": "line 5: 应改为使用 memcpy 安全复制，避免不兼容类型的指针转换"},
        cv(4, o=2))
    # T3: Java unchecked cast (4)
    R += expand("java",
        "// {fname}\nimport java.util.*;\npublic class {cls} {{\n    @SuppressWarnings(\"unchecked\")\n    public static String {func}(Object {param}) {{\n        List<String> list = (List<String>) {param};  // line 6: unchecked cast\n        return list.get(0);\n    }}\n}}\n",
        "分析过程：\n1. line 6 将 Object {param} 未检查类型直接强转为 List<String>。\n2. 若 {param} 实际非 List，运行时抛 ClassCastException；若为 List 但含非 String 元素，延迟到 get 时出错。\n3. 泛型擦除导致编译期无法检测类型不匹配，场景：{scene}。\n4. 结论：CWE-843 类型混淆，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-843 Type Confusion", "risk_level": "Medium",
         "source": "line 5: {func}(Object {param}) 参数 {param} 来自外部", "sink": "line 6: (List<String>) {param} 未检查类型转换",
         "explanation": "line 6 Object 强转 List<String> -> 泛型擦除无法检测 -> 运行时 ClassCastException",
         "fix_suggestion": "line 6: 应改为先 instanceof 检查类型再转换，或使用 Class.cast 配合类型令牌"},
        av(4, o=2))
    # T4: Python type confusion (4)
    R += expand("python",
        "# {fname}\ndef {func}({param}):\n    result = {param} + 42  # line 3: assumes int\n    return result\n\ndef handler(req):\n    val = req.get('value')  # line 7: user-controlled\n    return {func}(val)  # line 8: may pass string\n",
        "分析过程：\n1. line 3 {param} + 42 假设 {param} 为 int，但 line 7 从请求获取的值类型不确定。\n2. 若传入字符串，+ 42 变为字符串拼接而非算术运算，类型混淆。\n3. 场景：{scene}，攻击者可传入非数字类型导致意外行为。\n4. 结论：CWE-843 类型混淆，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-843 Type Confusion", "risk_level": "Medium",
         "source": "line 7: req.get('value') 用户可控输入", "sink": "line 3: {param} + 42 假设类型为 int",
         "explanation": "line 7 用户输入类型不确定 -> line 8 传入 {func} -> line 3 + 运算符行为因类型不同而异 -> 类型混淆",
         "fix_suggestion": "line 3: 应改为在运算前做类型检查 int({param}) 并处理转换异常"},
        pv(4, o=4))
    # T5: JavaScript type assumption (5)
    R += expand("javascript",
        "// {fname}\nfunction {func}({param}) {{\n    const num = {param}.length;  // line 3: assumes string/array\n    return num * 2;\n}}\nfunction handler(req) {{\n    const val = req.body.value;  // line 7: user-controlled\n    return {func}(val);  // line 8: may pass number\n}}\n",
        "分析过程：\n1. line 3 访问 {param}.length 假设为 string 或 array。\n2. line 7 从请求体获取的值类型不确定，line 8 直接传入 {func}。\n3. 若传入 number，.length 为 undefined，undefined * 2 = NaN，类型混淆。\n4. 结论：CWE-843 类型混淆，风险 Low。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-843 Type Confusion", "risk_level": "Low",
         "source": "line 7: req.body.value 用户可控输入", "sink": "line 3: {param}.length 假设类型为 string/array",
         "explanation": "line 7 用户输入类型不确定 -> line 8 传入 -> line 3 .length 在非 string/array 上返回 undefined -> 类型混淆",
         "fix_suggestion": "line 3: 应改为先检查 typeof {param} === 'string' 或 Array.isArray({param})"},
        jv(5))
    return R


def g_347():
    """CWE-347 Improper Verification of Cryptographic Signature (21)"""
    R = []
    # T1: Python jwt.decode verify=False (4)
    R += expand("python",
        "# {fname}\nimport jwt\ndef {func}({param}):\n    payload = jwt.decode({param}, verify=False)  # line 4: no signature verification\n    return payload\n",
        "analysis_tpl_placeholder",
        {"has_vulnerability": True, "vulnerability_type": "CWE-347 Improper Verification of Cryptographic Signature", "risk_level": "High",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部", "sink": "line 4: jwt.decode({param}, verify=False) 禁用签名验证",
         "explanation": "line 4 verify=False -> JWT 签名不验证 -> 攻击者可伪造任意 payload",
         "fix_suggestion": "line 4: 应改为 jwt.decode({param}, key=SECRET_KEY, algorithms=['HS256']) 启用签名验证"},
        pv(4))
    # Fix T1 analysis (placeholder was used above, set correct analysis per variant)
    for i, s in enumerate(R[-4:]):
        s["analysis"] = fmt("分析过程：\n1. line 4 jwt.decode({param}, verify=False) 中 verify=False 禁用签名验证。\n2. {param} 为用户提供的 JWT token，场景：{scene}。\n3. 攻击者可构造任意 payload 的未签名 token，完全绕过认证。\n4. 结论：CWE-347 签名验证缺失，风险 High。", **pv(4)[i])

    # T2: Node.js jwt.verify algorithms none (4)
    R += expand("javascript",
        "// {fname}\nconst jwt = require('jsonwebtoken');\nfunction {func}({param}) {{\n    const payload = jwt.verify({param}, 'secret', {{ algorithms: ['none'] }});  // line 4\n    return payload;\n}}\n",
        "分析过程：\n1. line 4 jwt.verify({param}, 'secret', {{ algorithms: ['none'] }}) 允许 none 算法。\n2. none 算法不需要签名，攻击者可将 token 算法改为 none 并移除签名。\n3. {param} 来自外部，场景：{scene}，攻击者可伪造任意 token。\n4. 结论：CWE-347 签名验证缺失，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-347 Improper Verification of Cryptographic Signature", "risk_level": "High",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部", "sink": "line 4: jwt.verify algorithms: ['none'] 允许无签名算法",
         "explanation": "line 4 algorithms 包含 'none' -> 攻击者改 token 算法为 none -> 移除签名 -> 绕过验证",
         "fix_suggestion": "line 4: 应改为 jwt.verify({param}, 'secret', {{ algorithms: ['HS256'] }}) 限定安全算法"},
        jv(4, o=5))
    # T3: Python HMAC wrong compare (4)
    R += expand("python",
        "# {fname}\nimport hmac\nimport hashlib\nSECRET = b'supersecret'\ndef {func}({param}, signature):\n    expected = hmac.new(SECRET, {param}.encode(), hashlib.sha256).hexdigest()\n    if expected == signature:  # line 7: non-constant-time compare\n        return True\n    return False\n",
        "分析过程：\n1. line 7 使用 == 比较 HMAC 签名，非恒定时间比较。\n2. == 比较在首个不匹配字节即返回，攻击者可计时逐字节推导正确签名。\n3. {param} 和 signature 来自外部，场景：{scene}。\n4. 结论：CWE-347 签名验证不当（计时攻击），风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-347 Improper Verification of Cryptographic Signature", "risk_level": "Medium",
         "source": "line 5: {func}({param}, signature) 参数来自外部", "sink": "line 7: expected == signature 非恒定时间比较",
         "explanation": "line 7 == 比较非恒定时间 -> 攻击者计时逐字节推导 -> 伪造签名绕过验证",
         "fix_suggestion": "line 7: 应改为 hmac.compare_digest(expected, signature) 使用恒定时间比较"},
        pv(4, o=2))
    # T4: Java JWT no verify (4)
    R += expand("java",
        "// {fname}\nimport io.jsonwebtoken.*;\npublic class {cls} {{\n    public static Claims {func}(String {param}) {{\n        return Jwts.parser().setSigningKey(\"secret\").parseClaimsJwt({param}).getBody();  // line 5\n    }}\n}}\n",
        "分析过程：\n1. line 5 parseClaimsJwt 解析 JWT 但不验证签名（应使用 parseClaimsJws）。\n2. {param} 来自外部，攻击者可修改 payload 后重新编码无签名 token。\n3. 场景：{scene}，签名验证被完全绕过。\n4. 结论：CWE-347 签名验证缺失，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-347 Improper Verification of Cryptographic Signature", "risk_level": "High",
         "source": "line 4: {func}(String {param}) 参数 {param} 来自外部", "sink": "line 5: parseClaimsJwt 不验证签名",
         "explanation": "line 5 parseClaimsJwt 不验证签名 -> 攻击者篡改 payload -> 绕过认证",
         "fix_suggestion": "line 5: 应改为 Jwts.parser().setSigningKey(\"secret\").parseClaimsJws({param}).getBody() 验证签名"},
        av(4, o=4))
    # T5: DC checks sig but allows none (5)
    R += expand("python",
        "# {fname}\nimport jwt\nALLOWED = ['HS256', 'none']  # line 3: allows none\ndef {func}({param}):\n    try:\n        payload = jwt.decode({param}, key='secret', algorithms=ALLOWED)  # line 6\n        return payload\n    except jwt.InvalidTokenError:\n        return None\n",
        "分析过程：\n1. line 3 ALLOWED 列表包含 'none' 算法，看似限定算法但允许无签名。\n2. line 6 jwt.decode 使用 ALLOWED 算法列表，{param} 来自外部。\n3. 攻击者将 token 算法改为 none 并移除签名，可伪造任意 payload。\n4. 结论：CWE-347 签名验证缺失（防御可绕过），风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-347 Improper Verification of Cryptographic Signature", "risk_level": "High",
         "source": "line 5: {func}({param}) 参数 {param} 来自外部", "sink": "line 6: jwt.decode algorithms 包含 'none'",
         "explanation": "line 3 ALLOWED 含 'none' -> line 6 decode 允许 none 算法 -> 攻击者改算法为 none 绕过签名",
         "fix_suggestion": "line 3: 应改为 ALLOWED = ['HS256'] 移除 'none' 算法"},
        pv(5, o=3), dc=True)
    return R


def g_1321():
    """CWE-1321 Prototype Pollution (23)"""
    R = []
    # T1: JS object merge __proto__ (5)
    R += expand("javascript",
        "// {fname}\nfunction {func}(target, source) {{\n    for (const key in source) {{  // line 3\n        target[key] = source[key];  // line 4: no prototype check\n    }}\n    return target;\n}}\nfunction handler(req) {{\n    const config = {{ admin: false }};\n    {func}(config, req.body);  // line 9: user-controlled source\n    return config;\n}}\n",
        "分析过程：\n1. line 3-4 遍历 source 的所有属性并赋值到 target，未检查 __proto__。\n2. line 9 用户请求体作为 source 传入 {func}，场景：{scene}。\n3. 攻击者传入 {{\"__proto__\":{{\"admin\":true}}}} 污染 Object.prototype，所有对象继承 admin=true。\n4. 结论：CWE-1321 原型链污染，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-1321 Prototype Pollution", "risk_level": "Critical",
         "source": "line 9: req.body 用户可控输入", "sink": "line 4: target[key] = source[key] 无原型检查",
         "explanation": "line 9 用户输入 -> line 3 遍历含 __proto__ -> line 4 赋值污染原型 -> 所有对象继承恶意属性",
         "fix_suggestion": "line 4: 应改为 if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;"},
        jv(5))
    # T2: Node.js recursive merge (5)
    R += expand("javascript",
        "// {fname}\nfunction deepMerge(target, source) {{\n    for (const key in source) {{\n        if (typeof source[key] === 'object' && source[key] !== null) {{\n            if (!target[key]) target[key] = {{}};\n            deepMerge(target[key], source[key]);  // line 6: recursive\n        }} else {{\n            target[key] = source[key];  // line 8\n        }}\n    }}\n}}\nfunction {func}(req) {{\n    const obj = {{}};\n    deepMerge(obj, req.body);  // line 13: user input\n    return obj;\n}}\n",
        "分析过程：\n1. line 6 deepMerge 递归合并对象，line 8 赋值属性，均未检查 __proto__/constructor。\n2. line 13 用户请求体传入 deepMerge，场景：{scene}。\n3. 攻击者构造嵌套 {{\"__proto__\":{{\"isAdmin\":true}}}} 递归污染原型。\n4. 结论：CWE-1321 原型链污染，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-1321 Prototype Pollution", "risk_level": "Critical",
         "source": "line 13: req.body 用户可控输入", "sink": "line 8: target[key] = source[key] 无原型检查",
         "explanation": "line 13 用户输入 -> line 6 递归合并 -> line 8 __proto__ 赋值 -> 原型链污染",
         "fix_suggestion": "line 3: 应改为 for (const key of Object.keys(source)) 并过滤 __proto__/constructor"},
        jv(5, o=5))
    # T3: JS Object.assign with user input (4)
    R += expand("javascript",
        "// {fname}\nfunction {func}(req) {{\n    const defaults = {{ role: 'user', admin: false }};\n    const config = Object.assign({{}}, defaults, req.body);  // line 4: user input\n    return config;\n}}\n",
        "分析过程：\n1. line 4 Object.assign 将 req.body 合并到 config，Object.assign 不复制 __proto__ 但会复制 constructor.prototype。\n2. {param} 来自外部，场景：{scene}，攻击者可通过 constructor 属性间接污染。\n3. 虽然 Object.assign 跳过 __proto__，但某些 polyfill 或旧引擎可能不同。\n4. 结论：CWE-1321 原型链污染，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-1321 Prototype Pollution", "risk_level": "High",
         "source": "line 3: {func}(req) 中 req.body 用户可控", "sink": "line 4: Object.assign 合并用户输入",
         "explanation": "line 4 Object.assign 合并 req.body -> constructor 属性可被利用 -> 间接原型链污染",
         "fix_suggestion": "line 4: 应改为使用 Object.create(null) 创建无原型对象，或手动过滤危险属性"},
        jv(4, o=2))
    # T4: DC hasOwnProperty check but wrong target (5)
    R += expand("javascript",
        "// {fname}\nfunction {func}(target, source) {{\n    for (const key in source) {{\n        if (source.hasOwnProperty(key)) {{  // line 4: checks source own props\n            target[key] = source[key];  // line 5: but assigns to target\n        }}\n    }}\n}}\nfunction handler(req) {{\n    const obj = {{}};\n    {func}(obj, JSON.parse(req.body));  // line 10\n}}\n",
        "分析过程：\n1. line 4 hasOwnProperty 检查 source 的自有属性，看似有防护。\n2. 但 __proto__ 是 source 的自有属性（通过 JSON.parse 设置），检查通过后 line 5 仍赋值到 target。\n3. line 10 用户输入 JSON.parse 后传入，场景：{scene}。\n4. 结论：CWE-1321 原型链污染（防御可绕过），风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-1321 Prototype Pollution", "risk_level": "Critical",
         "source": "line 10: JSON.parse(req.body) 用户可控输入", "sink": "line 5: target[key] = source[key]",
         "explanation": "line 4 hasOwnProperty 通过 __proto__ 检查 -> line 5 赋值 -> JSON.parse 设置的 __proto__ 污染原型",
         "fix_suggestion": "line 4: 应改为 if (key === '__proto__' || key === 'constructor') continue; 过滤危险属性"},
        jv(5, o=3), dc=True)
    # T5: JS query string parse (4)
    R += expand("javascript",
        "// {fname}\nconst qs = require('qs');\nfunction {func}(req) {{\n    const params = qs.parse(req.query);  // line 4: parses __proto__\n    const config = {{}};\n    for (const k in params) {{\n        config[k] = params[k];  // line 7\n    }}\n    return config;\n}}\n",
        "分析过程：\n1. line 4 qs.parse 解析查询字符串，旧版 qs 默认允许 __proto__ 键。\n2. line 7 遍历 params 赋值到 config，未过滤危险属性。\n3. {param} 来自外部查询参数，场景：{scene}。\n4. 结论：CWE-1321 原型链污染，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-1321 Prototype Pollution", "risk_level": "Critical",
         "source": "line 3: {func}(req) 中 req.query 用户可控", "sink": "line 7: config[k] = params[k]",
         "explanation": "line 4 qs.parse 解析 __proto__ -> line 7 赋值 -> 原型链污染",
         "fix_suggestion": "line 4: 应改为 qs.parse(req.query, {{ allowPrototypes: false }}) 禁止原型属性"},
        jv(4, o=6))
    return R


def g_287():
    """CWE-287 Improper Authentication (27)"""
    R = []
    # T1: Python role string check no session (5)
    R += expand("python",
        "# {fname}\ndef {func}({param}):\n    if {param} == 'admin':  # line 3: string check only\n        return {'role': 'admin', 'access': 'full'}\n    return {'role': 'user', 'access': 'limited'}\n",
        "分析过程：\n1. line 3 仅检查 {param} 是否等于 'admin' 字符串，无会话/Token 验证。\n2. {param} 来自外部请求参数，场景：{scene}。\n3. 攻击者直接传入 {param}='admin' 即可获取管理员权限。\n4. 结论：CWE-287 认证不当，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-287 Improper Authentication", "risk_level": "Critical",
         "source": "line 2: {func}({param}) 参数 {param} 来自外部", "sink": "line 3: if {param} == 'admin' 字符串比较无认证",
         "explanation": "line 3 字符串比较 'admin' -> 无会话/Token 验证 -> 攻击者直接传 admin 绕过认证",
         "fix_suggestion": "line 3: 应改为从已验证的会话中获取用户角色 session.get('role')，不信任客户端输入"},
        pv(5))
    # T2: Java hardcoded password (5)
    R += expand("java",
        "// {fname}\npublic class {cls} {{\n    public static boolean {func}(String {param}) {{\n        if ({param}.equals(\"admin123\")) {{  // line 4: hardcoded password\n            return true;\n        }}\n        return false;\n    }}\n}}\n",
        "分析过程：\n1. line 4 使用硬编码密码 \"admin123\" 进行认证，无数据库查询。\n2. {param} 来自外部输入，场景：{scene}。\n3. 密码硬编码在源码中，可从反编译/源码泄露获取，且无法按用户区分。\n4. 结论：CWE-287 认证不当，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-287 Improper Authentication", "risk_level": "High",
         "source": "line 3: {func}(String {param}) 参数 {param} 来自外部", "sink": "line 4: {param}.equals(\"admin123\") 硬编码密码",
         "explanation": "line 4 硬编码密码 -> 无数据库/用户区分 -> 密码泄露后所有认证失效",
         "fix_suggestion": "line 4: 应改为从数据库查询用户密码哈希并使用 bcrypt/argon2 验证"},
        av(5))
    # T3: Node.js JWT no expiry (4)
    R += expand("javascript",
        "// {fname}\nconst jwt = require('jsonwebtoken');\nfunction {func}(userId) {{\n    const token = jwt.sign({{ userId }}, 'secret');  // line 4: no expiresIn\n    return token;\n}}\nfunction verify(token) {{\n    return jwt.verify(token, 'secret');  // line 8: no expiry check\n}}\n",
        "分析过程：\n1. line 4 jwt.sign 未设置 expiresIn，token 永不过期。\n2. line 8 jwt.verify 未检查过期时间，场景：{scene}。\n3. token 泄露后攻击者可永久使用，无法通过过期机制失效。\n4. 结论：CWE-287 认证不当（无过期），风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-287 Improper Authentication", "risk_level": "High",
         "source": "line 3: {func}(userId) 参数来自外部", "sink": "line 4: jwt.sign 未设置 expiresIn",
         "explanation": "line 4 无 expiresIn -> token 永不过期 -> 泄露后攻击者永久使用",
         "fix_suggestion": "line 4: 应改为 jwt.sign({{ userId }}, 'secret', {{ expiresIn: '1h' }}) 设置过期时间"},
        jv(4, o=5))
    # T4: Python auth bypass via parameter (5)
    R += expand("python",
        "# {fname}\ndef check_auth(request):\n    user = request.args.get('user', 'guest')  # line 3\n    if user == 'admin':  # line 4\n        return True\n    return False\ndef {func}(request):\n    if check_auth(request):\n        return 'welcome admin'\n    return 'access denied'\n",
        "分析过程：\n1. line 3 从请求参数获取 user，默认 'guest'，line 4 检查是否 'admin'。\n2. 认证完全依赖客户端参数，无服务端会话验证，场景：{scene}。\n3. 攻击者传入 ?user=admin 即可绕过认证。\n4. 结论：CWE-287 认证不当，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-287 Improper Authentication", "risk_level": "Critical",
         "source": "line 3: request.args.get('user') 用户可控参数", "sink": "line 4: if user == 'admin' 无服务端认证",
         "explanation": "line 3 客户端参数 -> line 4 字符串比较 -> 攻击者传 user=admin 绕过认证",
         "fix_suggestion": "line 3-4: 应改为从服务端会话 session['user'] 获取用户身份，不信任请求参数"},
        pv(5, o=2))
    # T5: DC checks password but not user (4)
    R += expand("python",
        "# {fname}\nimport hashlib\ndef {func}(username, password):\n    hashed = hashlib.md5(password.encode()).hexdigest()  # line 4\n    if hashed == '5f4dcc3b5aa765d61d8327deb882cf99':  # line 5: md5 of 'password'\n        return True  # line 6\n    return False\n",
        "分析过程：\n1. line 4 使用 MD5 哈希密码（弱哈希），line 5 与硬编码哈希比较。\n2. 看似验证密码，但不检查 username 是否存在，任意用户名 + 正确密码即通过。\n3. 场景：{scene}，且 MD5 可通过彩虹表快速破解。\n4. 结论：CWE-287 认证不当（防御可绕过），风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-287 Improper Authentication", "risk_level": "High",
         "source": "line 3: {func}(username, password) 参数来自外部", "sink": "line 5: hashed == 硬编码 MD5 不检查用户存在性",
         "explanation": "line 4 MD5 弱哈希 -> line 5 不查 username -> 任意用户名 + 通用密码通过 -> 认证绕过",
         "fix_suggestion": "line 4-5: 应改为按 username 查询数据库密码哈希并用 bcrypt 验证"},
        pv(4, o=4), dc=True)
    # T6: Java basic auth hardcoded (4)
    R += expand("java",
        "// {fname}\nimport java.util.Base64;\npublic class {cls} {{\n    public static boolean {func}(String authHeader) {{\n        String decoded = new String(Base64.getDecoder().decode(authHeader.replace(\"Basic \", \"\")));\n        String[] parts = decoded.split(\":\");\n        if (parts[0].equals(\"admin\") && parts[1].equals(\"pass123\")) {{  // line 7\n            return true;\n        }}\n        return false;\n    }}\n}}\n",
        "分析过程：\n1. line 7 硬编码用户名密码 'admin':'pass123' 进行 Basic Auth 验证。\n2. authHeader 来自外部请求头，场景：{scene}。\n3. 凭证硬编码在源码中，且无用户管理/数据库查询。\n4. 结论：CWE-287 认证不当，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-287 Improper Authentication", "risk_level": "High",
         "source": "line 4: {func}(String authHeader) 参数来自外部", "sink": "line 7: parts[0].equals(\"admin\") && parts[1].equals(\"pass123\")",
         "explanation": "line 7 硬编码凭证 -> 无用户管理 -> 凭证泄露后认证失效",
         "fix_suggestion": "line 7: 应改为从数据库查询用户凭证并使用安全哈希验证"},
        av(4, o=4))
    return R


def g_113():
    """CWE-113 CRLF Injection (26)"""
    R = []
    # T1: Python Flask header injection (5)
    R += expand("python",
        "# {fname}\nfrom flask import Flask, request, Response\napp = Flask(__name__)\n@app.route('/{func}')\ndef {func}():\n    val = request.args.get('val', '')  # line 6\n    resp = Response('ok')\n    resp.headers['X-Custom'] = val  # line 8: CRLF injection\n    return resp\n",
        "分析过程：\n1. line 6 从请求参数获取 val，line 8 直接设入 HTTP 响应头。\n2. val 含 \\r\\n 可注入额外头部，场景：{scene}。\n3. 攻击者传入 val='ok\\r\\nSet-Cookie: admin=true' 可注入恶意 Cookie。\n4. 结论：CWE-113 CRLF 注入，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-113 CRLF Injection", "risk_level": "High",
         "source": "line 6: request.args.get('val') 用户可控输入", "sink": "line 8: resp.headers['X-Custom'] = val",
         "explanation": "line 6 用户输入 -> line 8 写入响应头 -> \\r\\n 注入额外头部 -> CRLF 注入",
         "fix_suggestion": "line 8: 应改为 val = val.replace('\\r', '').replace('\\n', '') 过滤 CRLF 字符后再设入头部"},
        pv(5))
    # T2: Java response.setHeader (5)
    R += expand("java",
        "// {fname}\nimport javax.servlet.*;\nimport javax.servlet.http.*;\npublic class {cls} extends HttpServlet {{\n    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {{\n        String val = req.getParameter(\"val\");  // line 6\n        resp.setHeader(\"X-Custom\", val);  // line 7: CRLF injection\n    }}\n}}\n",
        "分析过程：\n1. line 6 从请求参数获取 val，line 7 直接设入响应头。\n2. val 含 \\r\\n 可注入额外 HTTP 头，场景：{scene}。\n3. 攻击者可注入 Set-Cookie 或 Location 头进行攻击。\n4. 结论：CWE-113 CRLF 注入，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-113 CRLF Injection", "risk_level": "High",
         "source": "line 6: req.getParameter(\"val\") 用户可控输入", "sink": "line 7: resp.setHeader(\"X-Custom\", val)",
         "explanation": "line 6 用户输入 -> line 7 setHeader -> \\r\\n 注入额外头部 -> CRLF 注入",
         "fix_suggestion": "line 7: 应改为 val = val.replaceAll(\"[\\\\r\\\\n]\", \"\") 过滤 CRLF 字符"},
        av(5))
    # T3: Node.js res.set (5)
    R += expand("javascript",
        "// {fname}\nconst express = require('express');\nconst app = express();\napp.get('/{func}', (req, res) => {{\n    const val = req.query.val;  // line 5\n    res.set('X-Custom', val);  // line 6: CRLF injection\n    res.send('ok');\n}});\n",
        "分析过程：\n1. line 5 从查询参数获取 val，line 6 直接设入响应头。\n2. val 含 \\r\\n 可注入额外头部，场景：{scene}。\n3. 攻击者可注入 Set-Cookie 等恶意头部。\n4. 结论：CWE-113 CRLF 注入，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-113 CRLF Injection", "risk_level": "High",
         "source": "line 5: req.query.val 用户可控输入", "sink": "line 6: res.set('X-Custom', val)",
         "explanation": "line 5 用户输入 -> line 6 res.set -> \\r\\n 注入额外头部 -> CRLF 注入",
         "fix_suggestion": "line 6: 应改为 val.replace(/[\\r\\n]/g, '') 过滤 CRLF 字符"},
        jv(5))
    # T4: Go header.Set (5)
    R += expand("go",
        "// {fname}\nimport (\n    \"net/http\"\n)\nfunc {func}(w http.ResponseWriter, r *http.Request) {\n    val := r.URL.Query().Get(\"val\")  // line 6\n    w.Header().Set(\"X-Custom\", val)  // line 7: CRLF injection\n    w.Write([]byte(\"ok\"))\n}\n",
        "分析过程：\n1. line 6 从查询参数获取 val，line 7 直接设入响应头。\n2. val 含 \\r\\n 可注入额外 HTTP 头，场景：{scene}。\n3. 攻击者可注入恶意头部进行响应拆分。\n4. 结论：CWE-113 CRLF 注入，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-113 CRLF Injection", "risk_level": "High",
         "source": "line 6: r.URL.Query().Get(\"val\") 用户可控输入", "sink": "line 7: w.Header().Set(\"X-Custom\", val)",
         "explanation": "line 6 用户输入 -> line 7 Header.Set -> \\r\\n 注入额外头部 -> CRLF 注入",
         "fix_suggestion": "line 7: 应改为 strings.NewReplacer(\"\\r\", \"\", \"\\n\", \"\").Replace(val) 过滤 CRLF"},
        gv(5))
    # T5: DC strips \n but not \r (3)
    R += expand("python",
        "# {fname}\nfrom flask import Flask, request, Response\napp = Flask(__name__)\n@app.route('/{func}')\ndef {func}():\n    val = request.args.get('val', '').replace('\\n', '')  # line 6: only strips \\n\n    resp = Response('ok')\n    resp.headers['X-Custom'] = val  # line 9: \\r still injectable\n    return resp\n",
        "分析过程：\n1. line 6 只过滤 \\n 未过滤 \\r，看似有防护但可绕过。\n2. line 9 仍可将含 \\r 的值设入响应头，\\r 可用于头部注入。\n3. 场景：{scene}，攻击者使用 \\r 单独注入。\n4. 结论：CWE-113 CRLF 注入（防御可绕过），风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-113 CRLF Injection", "risk_level": "High",
         "source": "line 6: request.args.get('val') 用户可控输入", "sink": "line 9: resp.headers['X-Custom'] = val",
         "explanation": "line 6 只过滤 \\n -> \\r 未过滤 -> line 9 \\r 注入响应头 -> CRLF 注入绕过",
         "fix_suggestion": "line 6: 应改为 .replace('\\r', '').replace('\\n', '') 同时过滤 \\r 和 \\n"},
        pv(3, o=2), dc=True)
    # T6: Python redirect injection (3)
    R += expand("python",
        "# {fname}\nfrom flask import Flask, request, redirect\napp = Flask(__name__)\n@app.route('/{func}')\ndef {func}():\n    url = request.args.get('next', '/')  # line 6\n    resp = redirect(url)  # line 7: Location header injection\n    return resp\n",
        "分析过程：\n1. line 6 从请求参数获取 next URL，line 7 直接用于重定向。\n2. url 含 \\r\\n 可注入额外 HTTP 头到 Location 响应中。\n3. 场景：{scene}，攻击者注入 Set-Cookie 等头部。\n4. 结论：CWE-113 CRLF 注入，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-113 CRLF Injection", "risk_level": "High",
         "source": "line 6: request.args.get('next') 用户可控输入", "sink": "line 7: redirect(url) Location 头注入",
         "explanation": "line 6 用户输入 URL -> line 7 redirect 设 Location -> \\r\\n 注入额外头部",
         "fix_suggestion": "line 7: 应改为过滤 url 中的 \\r\\n 字符，或使用 urljoin 限制重定向目标"},
        pv(3, o=5))
    return R


def g_319():
    """CWE-319 Cleartext Transmission (28)"""
    R = []
    # T1: Python HTTP for password (5)
    R += expand("python",
        "# {fname}\nimport requests\ndef {func}({param}):\n    resp = requests.get('http://' + {param})  # line 4: HTTP not HTTPS\n    return resp.json()\n",
        "分析过程：\n1. line 4 使用 http:// 明文协议传输数据，{param} 来自外部。\n2. 场景：{scene}，数据在传输中可被窃听。\n3. 攻击者可嗅探网络流量截获数据。\n4. 结论：CWE-319 明文传输，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-319 Cleartext Transmission", "risk_level": "Medium",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部", "sink": "line 4: requests.get('http://' + {param}) 明文传输",
         "explanation": "line 4 http:// 明文协议 -> 数据传输不加密 -> 网络嗅探可截获",
         "fix_suggestion": "line 4: 应改为 requests.get('https://' + {param}) 使用 HTTPS 加密传输"},
        pv(5))
    # T2: Java Socket for credentials (5)
    R += expand("java",
        "// {fname}\nimport java.net.*;\nimport java.io.*;\npublic class {cls} {{\n    public static String {func}(String {param}) throws Exception {{\n        Socket socket = new Socket({param}, 80);  // line 6: plain socket\n        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);\n        out.println(\"GET /api?key=secret123 HTTP/1.1\");  // line 8: sends secret over plaintext\n        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));\n        return in.readLine();\n    }}\n}}\n",
        "分析过程：\n1. line 6 使用明文 Socket 连接端口 80，非 SSLSocket。\n2. line 8 通过明文连接发送含 API key 的请求，{param} 来自外部。\n3. 场景：{scene}，攻击者可嗅探截获 secret123。\n4. 结论：CWE-319 明文传输，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-319 Cleartext Transmission", "risk_level": "High",
         "source": "line 5: {func}(String {param}) 参数来自外部", "sink": "line 6: new Socket({param}, 80) 明文连接",
         "explanation": "line 6 明文 Socket -> line 8 发送 API key -> 网络嗅探可截获凭证",
         "fix_suggestion": "line 6: 应改为 SSLSocketFactory.getDefault().createSocket({param}, 443) 使用 TLS 加密"},
        av(5))
    # T3: Node.js http.get for token (5)
    R += expand("javascript",
        "// {fname}\nconst http = require('http');\nfunction {func}({param}) {{\n    http.get({{ hostname: {param}, path: '/auth', headers: {{ 'Authorization': 'Bearer token123' }} }}, (res) => {{  // line 4\n        let data = '';\n        res.on('data', (chunk) => data += chunk);\n        res.on('end', () => console.log(data));\n    }});\n}}\n",
        "分析过程：\n1. line 4 使用 http.get（非 https）发送含 Bearer token 的请求。\n2. {param} 来自外部，场景：{scene}。\n3. token 通过明文 HTTP 传输，攻击者可嗅探截获。\n4. 结论：CWE-319 明文传输，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-319 Cleartext Transmission", "risk_level": "High",
         "source": "line 3: {func}({param}) 参数来自外部", "sink": "line 4: http.get 明文传输 Bearer token",
         "explanation": "line 4 http.get 明文 -> Authorization 头含 token -> 嗅探截获凭证",
         "fix_suggestion": "line 4: 应改为 const https = require('https'); 使用 https.get 加密传输"},
        jv(5, o=2))
    # T4: Go http.Get no TLS (5)
    R += expand("go",
        "// {fname}\nimport (\n    \"net/http\"\n    \"io/ioutil\"\n)\nfunc {func}({param} string) (string, error) {\n    resp, err := http.Get(\"http://\" + {param} + \"/api?token=abc123\")  // line 7\n    if err != nil {\n        return \"\", err\n    }\n    defer resp.Body.Close()\n    body, _ := ioutil.ReadAll(resp.Body)\n    return string(body), nil\n}\n",
        "分析过程：\n1. line 7 使用 http.Get 通过 HTTP 明文发送含 token 的请求。\n2. {param} 来自外部，场景：{scene}。\n3. token 在 URL 中明文传输，可被嗅探/日志记录。\n4. 结论：CWE-319 明文传输，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-319 Cleartext Transmission", "risk_level": "High",
         "source": "line 6: {func}({param} string) 参数来自外部", "sink": "line 7: http.Get 使用 HTTP 明文传 token",
         "explanation": "line 7 http:// 明文 -> URL 含 token -> 嗅探/日志截获凭证",
         "fix_suggestion": "line 7: 应改为 http.Get(\"https://\" + {param} + \"/api\") 使用 HTTPS 并将 token 放入 Header"},
        gv(5, o=2))
    # T5: Python SMTP no TLS (4)
    R += expand("python",
        "# {fname}\nimport smtplib\ndef {func}({param}, msg):\n    server = smtplib.SMTP({param}, 25)  # line 4: no TLS\n    server.login('user', 'pass123')  # line 5: sends credentials in plaintext\n    server.sendmail('from@x.com', 'to@x.com', msg)\n    server.quit()\n",
        "分析过程：\n1. line 4 使用 SMTP 端口 25 明文连接，未启用 TLS。\n2. line 5 通过明文连接发送登录凭证，{param} 来自外部。\n3. 场景：{scene}，凭证可被网络嗅探截获。\n4. 结论：CWE-319 明文传输，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-319 Cleartext Transmission", "risk_level": "High",
         "source": "line 3: {func}({param}, msg) 参数来自外部", "sink": "line 4: smtplib.SMTP({param}, 25) 无 TLS",
         "explanation": "line 4 SMTP 明文 -> line 5 login 发送凭证 -> 嗅探截获密码",
         "fix_suggestion": "line 4: 应改为 server = smtplib.SMTP_SSL({param}, 465) 或 server.starttls() 启用 TLS"},
        pv(4, o=4))
    # T6: DC HTTPS for auth but HTTP for data (4)
    R += expand("python",
        "# {fname}\nimport requests\ndef {func}({param}):\n    token = requests.get('https://auth.example.com/login', verify=True).json()['token']  # line 4: HTTPS for auth\n    data = requests.get('http://api.example.com/data?token=' + token)  # line 5: HTTP for data\n    return data.json()\n",
        "分析过程：\n1. line 4 使用 HTTPS 获取 token，看似安全。\n2. line 5 使用 HTTP 明文传输 token 获取数据，token 泄露。\n3. {param} 来自外部，场景：{scene}，认证 token 在明文传输中泄露。\n4. 结论：CWE-319 明文传输（防御不完整），风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-319 Cleartext Transmission", "risk_level": "High",
         "source": "line 3: {func}({param}) 参数来自外部", "sink": "line 5: requests.get('http://...') 明文传 token",
         "explanation": "line 4 HTTPS 获取 token -> line 5 HTTP 明文传 token -> 认证凭证泄露",
         "fix_suggestion": "line 5: 应改为 requests.get('https://api.example.com/data', headers={{'Authorization': token}})"},
        pv(4, o=6), dc=True)
    return R


def g_400():
    """CWE-400 Uncontrolled Resource Consumption (28)"""
    R = []
    # T1: Python unbounded list (5)
    R += expand("python",
        "# {fname}\ndef {func}({param}):\n    items = []\n    for i in range(int({param})):  # line 4: user-controlled size\n        items.append('x' * 1024)  # line 5: 1KB per item\n    return len(items)\n",
        "分析过程：\n1. line 4 range(int({param})) 循环次数由用户输入控制，无上限。\n2. line 5 每次追加 1KB 数据到列表，{param} 过大时耗尽内存。\n3. 场景：{scene}，攻击者传入超大值导致 OOM。\n4. 结论：CWE-400 资源耗尽，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-400 Uncontrolled Resource Consumption", "risk_level": "Medium",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部", "sink": "line 4: range(int({param})) 无上限循环",
         "explanation": "line 4 用户控制循环次数 -> line 5 追加数据 -> 无上限 -> OOM",
         "fix_suggestion": "line 4: 应改为 for i in range(min(int({param}), 1000)): 设置上限"},
        pv(5))
    # T2: Java HashMap collision (5)
    R += expand("java",
        "// {fname}\nimport java.util.*;\npublic class {cls} {{\n    public static Map<String, String> {func}(List<String> {param}) {{\n        Map<String, String> map = new HashMap<>();  // line 5\n        for (String item : {param}) {{\n            map.put(item, \"value\");  // line 7: no size limit\n        }}\n        return map;\n    }}\n}}\n",
        "分析过程：\n1. line 5 创建 HashMap，line 7 循环将用户输入放入 map，无大小限制。\n2. {param} 来自外部列表，攻击者发送大量哈希碰撞的键导致 CPU 耗尽。\n3. 场景：{scene}，哈希碰撞攻击使 HashMap 退化为链表。\n4. 结论：CWE-400 资源耗尽，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-400 Uncontrolled Resource Consumption", "risk_level": "Medium",
         "source": "line 4: {func}(List<String> {param}) 参数来自外部", "sink": "line 7: map.put(item, \"value\") 无大小限制",
         "explanation": "line 7 无限制 put -> 哈希碰撞键 -> HashMap 退化 -> CPU 耗尽",
         "fix_suggestion": "line 5: 应改为 new HashMap<>(Math.min({param}.size(), 1000)) 或在循环中检查 map.size()"},
        av(5))
    # T3: Node.js recursive parse (5)
    R += expand("javascript",
        "// {fname}\nfunction {func}({param}) {{\n    const obj = JSON.parse({param});  // line 3\n    function traverse(node) {{\n        for (const key in node) {{\n            if (typeof node[key] === 'object') {{\n                traverse(node[key]);  // line 7: recursive, no depth limit\n            }}\n        }}\n    }}\n    traverse(obj);\n}}\n",
        "分析过程：\n1. line 3 解析用户提供的 JSON，line 7 递归遍历无深度限制。\n2. 攻击者构造深度嵌套 JSON 导致栈溢出，{param} 来自外部。\n3. 场景：{scene}，深嵌套对象导致调用栈耗尽。\n4. 结论：CWE-400 资源耗尽，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-400 Uncontrolled Resource Consumption", "risk_level": "Medium",
         "source": "line 2: {func}({param}) 参数 {param} 来自外部", "sink": "line 7: traverse(node[key]) 无深度限制递归",
         "explanation": "line 3 用户 JSON -> line 7 无限递归 -> 深嵌套 -> 栈溢出",
         "fix_suggestion": "line 7: 应改为增加 depth 参数 if (depth > 100) return; 限制递归深度"},
        jv(5, o=2))
    # T4: Go unbounded goroutine (5)
    R += expand("go",
        "// {fname}\nfunc {func}(targets []string) {\n    for _, t := range targets {  // line 3\n        go func(target string) {  // line 4: unbounded goroutines\n            fetch(target)\n        }(t)\n    }\n}\n",
        "分析过程：\n1. line 3 遍历用户提供的 targets 列表，line 4 为每个目标创建 goroutine。\n2. 无并发上限，大量 targets 导致 goroutine 爆炸耗尽内存。\n3. 场景：{scene}，攻击者发送大量目标地址。\n4. 结论：CWE-400 资源耗尽，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-400 Uncontrolled Resource Consumption", "risk_level": "Medium",
         "source": "line 2: {func}(targets []string) 参数来自外部", "sink": "line 4: go func 无并发限制",
         "explanation": "line 3 遍历用户列表 -> line 4 每个创建 goroutine -> 无上限 -> goroutine 爆炸",
         "fix_suggestion": "line 4: 应改为使用 semaphore 或 worker pool 限制并发 goroutine 数量"},
        gv(5, o=4))
    # T5: Python regex catastrophic (4)
    R += expand("python",
        "# {fname}\nimport re\ndef {func}({param}):\n    pattern = re.compile(r'(a+)+b')  # line 4: catastrophic backtracking\n    return bool(pattern.match({param}))  # line 5\n",
        "分析过程：\n1. line 4 正则 (a+)+b 存在灾难性回溯，line 5 匹配用户输入。\n2. 攻击者传入 'a' * 30 可导致指数级回溯，CPU 耗尽。\n3. 场景：{scene}，ReDoS 攻击。\n4. 结论：CWE-400 资源耗尽，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-400 Uncontrolled Resource Consumption", "risk_level": "Medium",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部", "sink": "line 5: pattern.match({param}) 灾难性回溯正则",
         "explanation": "line 4 (a+)+b 灾难性回溯 -> line 5 匹配长字符串 -> 指数级 CPU 消耗 -> DoS",
         "fix_suggestion": "line 4: 应改为使用非回溯正则 r'a+b' 或设置匹配超时"},
        pv(4, o=4))
    # T6: DC has limit but too high (4)
    R += expand("python",
        "# {fname}\ndef {func}({param}):\n    n = int({param})\n    if n > 1000000:  # line 4: limit too high\n        n = 1000000\n    data = [b'x' * 1024 for _ in range(n)]  # line 6: up to 1GB\n    return len(data)\n",
        "分析过程：\n1. line 4 限制上限 1000000，看似有防护，但 line 6 最多分配 1GB 内存。\n2. 1GB 远超正常请求所需，仍可导致 OOM。\n3. {param} 来自外部，场景：{scene}。\n4. 结论：CWE-400 资源耗尽（防御不充分），风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-400 Uncontrolled Resource Consumption", "risk_level": "Medium",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部", "sink": "line 6: [b'x'*1024 for _ in range(n)] 上限过高",
         "explanation": "line 4 上限 1000000 -> line 6 最多 1GB -> 仍可 OOM -> 防御不充分",
         "fix_suggestion": "line 4: 应改为 if n > 1000: 降低到合理上限"},
        pv(4, o=6), dc=True)
    return R


def g_532():
    """CWE-532 Insertion of Sensitive Info into Log File (28)"""
    R = []
    # T1: Python logging password (5)
    R += expand("python",
        "# {fname}\nimport logging\nlogging.basicConfig(level=logging.INFO)\ndef {func}(username, password):\n    logging.info(f'Login attempt: user={username}, password={password}')  # line 5: logs password\n    return authenticate(username, password)\n",
        "分析过程：\n1. line 5 将密码明文写入日志，password 来自用户输入。\n2. 场景：{scene}，日志文件可能被运维人员或攻击者访问。\n3. 密码泄露到日志后可被用于横向攻击。\n4. 结论：CWE-532 日志泄露敏感信息，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-532 Insertion of Sensitive Info into Log File", "risk_level": "High",
         "source": "line 4: {func}(username, password) 参数来自外部", "sink": "line 5: logging.info 记录密码",
         "explanation": "line 5 密码写入日志 -> 日志文件可被访问 -> 凭证泄露",
         "fix_suggestion": "line 5: 应改为 logging.info(f'Login attempt: user={username}') 不记录密码"},
        pv(5))
    # T2: Java log.info credentials (5)
    R += expand("java",
        "// {fname}\nimport org.slf4j.*;\npublic class {cls} {{\n    static Logger log = LoggerFactory.getLogger({cls}.class);\n    public static boolean {func}(String user, String pass) {{\n        log.info(\"Auth: user={}, pass={}\", user, pass);  // line 6: logs password\n        return check(user, pass);\n    }}\n}}\n",
        "分析过程：\n1. line 6 将密码写入日志，pass 来自用户输入。\n2. 场景：{scene}，日志可能被未授权人员访问。\n3. 密码明文泄露到日志文件。\n4. 结论：CWE-532 日志泄露敏感信息，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-532 Insertion of Sensitive Info into Log File", "risk_level": "High",
         "source": "line 5: {func}(String user, String pass) 参数来自外部", "sink": "line 6: log.info 记录密码",
         "explanation": "line 6 密码写入日志 -> 日志文件泄露 -> 凭证暴露",
         "fix_suggestion": "line 6: 应改为 log.info(\"Auth: user={}\", user) 不记录密码"},
        av(5))
    # T3: Node.js console.log token (5)
    R += expand("javascript",
        "// {fname}\nfunction {func}(req) {{\n    const token = req.headers['authorization'];  // line 3\n    console.log('Auth token:', token);  // line 4: logs token\n    return verifyToken(token);\n}}\n",
        "分析过程：\n1. line 3 从请求头获取 Authorization token，line 4 打印到日志。\n2. 场景：{scene}，console.log 输出到 stdout 可能被收集到日志系统。\n3. 认证 token 泄露后可被用于冒充用户。\n4. 结论：CWE-532 日志泄露敏感信息，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-532 Insertion of Sensitive Info into Log File", "risk_level": "High",
         "source": "line 3: req.headers['authorization'] 用户可控", "sink": "line 4: console.log 记录 token",
         "explanation": "line 3 获取 token -> line 4 console.log -> 日志泄露 -> token 被盗用",
         "fix_suggestion": "line 4: 应改为 console.log('Auth request received') 不记录 token 内容"},
        jv(5, o=2))
    # T4: Go log.Printf secrets (5)
    R += expand("go",
        "// {fname}\nimport (\n    \"log\"\n    \"net/http\"\n)\nfunc {func}(w http.ResponseWriter, r *http.Request) {\n    apiKey := r.URL.Query().Get(\"key\")  // line 7\n    log.Printf(\"API call with key=%s\", apiKey)  // line 8: logs API key\n    w.Write([]byte(\"ok\"))\n}\n",
        "分析过程：\n1. line 7 从查询参数获取 API key，line 8 打印到日志。\n2. 场景：{scene}，API key 泄露到日志文件。\n3. 攻击者获取日志后可使用 API key 进行未授权访问。\n4. 结论：CWE-532 日志泄露敏感信息，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-532 Insertion of Sensitive Info into Log File", "risk_level": "High",
         "source": "line 7: r.URL.Query().Get(\"key\") 用户可控", "sink": "line 8: log.Printf 记录 API key",
         "explanation": "line 7 获取 API key -> line 8 log.Printf -> 日志泄露 -> 未授权访问",
         "fix_suggestion": "line 8: 应改为 log.Printf(\"API call received\") 不记录 key 值"},
        gv(5, o=2))
    # T5: Python logging credit card (4)
    R += expand("python",
        "# {fname}\nimport logging\nlogger = logging.getLogger(__name__)\ndef {func}(order):\n    cc = order.get('credit_card')  # line 5\n    logger.info(f'Processing payment for card: {cc}')  # line 6: logs full card number\n    return process_payment(cc)\n",
        "分析过程：\n1. line 5 获取信用卡号，line 6 将完整卡号写入日志。\n2. 场景：{scene}，违反 PCI-DSS 标准。\n3. 完整卡号泄露可导致金融欺诈。\n4. 结论：CWE-532 日志泄露敏感信息，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-532 Insertion of Sensitive Info into Log File", "risk_level": "Critical",
         "source": "line 5: order.get('credit_card') 用户可控", "sink": "line 6: logger.info 记录完整卡号",
         "explanation": "line 5 获取卡号 -> line 6 完整记录 -> 日志泄露 -> 金融欺诈风险",
         "fix_suggestion": "line 6: 应改为 logger.info(f'Processing payment for card: ****{cc[-4:]}') 只记录后四位"},
        pv(4, o=4))
    # T6: DC masks partial but leaks enough (4)
    R += expand("python",
        "# {fname}\nimport logging\nlogger = logging.getLogger(__name__)\ndef {func}(token):\n    masked = token[:8] + '****'  # line 5: masks tail\n    logger.info(f'Token: {masked}')  # line 6: but first 8 chars leaked\n    return verify(token)\n",
        "分析过程：\n1. line 5 只掩码 token 尾部，前 8 字符明文。\n2. line 6 将部分明文 token 写入日志，场景：{scene}。\n3. 短 token 的前 8 字符可能足以恢复完整值或进行暴力破解。\n4. 结论：CWE-532 日志泄露（掩码不充分），风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-532 Insertion of Sensitive Info into Log File", "risk_level": "Medium",
         "source": "line 4: {func}(token) 参数来自外部", "sink": "line 6: logger.info 记录部分明文 token",
         "explanation": "line 5 只掩码尾部 -> line 6 前 8 字符明文 -> 短 token 可恢复 -> 泄露不充分掩码",
         "fix_suggestion": "line 5: 应改为 masked = '****' + token[-4:] 只显示后四位，掩码前缀"},
        pv(4, o=6), dc=True)
    return R


def g_770():
    """CWE-770 Allocation without Limits (28)"""
    R = []
    # T1: C malloc user size (5)
    R += expand("c",
        "// {fname}\n#include <stdlib.h>\n#include <string.h>\nchar* {func}(int {param}) {\n    char* buf = malloc({param});  // line 5: user-controlled size, no limit\n    if (!buf) return NULL;\n    memset(buf, 0, {param});\n    return buf;\n}\n",
        "分析过程：\n1. line 5 malloc({param}) 分配大小由用户输入控制，无上限检查。\n2. {param} 过大导致内存分配失败或 OOM，场景：{scene}。\n3. 攻击者传入超大值耗尽系统内存。\n4. 结论：CWE-770 无限制分配，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-770 Allocation without Limits", "risk_level": "Medium",
         "source": "line 4: {func}(int {param}) 参数 {param} 来自外部", "sink": "line 5: malloc({param}) 无大小限制",
         "explanation": "line 5 用户控制 malloc 大小 -> 无上限 -> 超大分配 -> OOM",
         "fix_suggestion": "line 5: 应改为 if ({param} > MAX_SIZE) return NULL; 检查上限后再 malloc"},
        cv(5))
    # T2: Python list multiply (5)
    R += expand("python",
        "# {fname}\ndef {func}({param}):\n    n = int({param})\n    data = [0] * n  # line 5: user-controlled size\n    return data\n",
        "分析过程：\n1. line 5 [0] * n 列表大小由用户输入控制，无上限。\n2. {param} 过大导致内存耗尽，场景：{scene}。\n3. 攻击者传入超大值导致 OOM。\n4. 结论：CWE-770 无限制分配，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-770 Allocation without Limits", "risk_level": "Medium",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部", "sink": "line 5: [0] * n 无大小限制",
         "explanation": "line 5 用户控制列表大小 -> 无上限 -> 超大分配 -> OOM",
         "fix_suggestion": "line 5: 应改为 if n > MAX_ITEMS: n = MAX_ITEMS 限制最大大小"},
        pv(5))
    # T3: Java new byte[user] (5)
    R += expand("java",
        "// {fname}\npublic class {cls} {{\n    public static byte[] {func}(int {param}) {{\n        byte[] buf = new byte[{param}];  // line 5: no size limit\n        return buf;\n    }}\n}}\n",
        "分析过程：\n1. line 5 new byte[{param}] 分配大小由用户控制，无上限。\n2. {param} 过大导致 OutOfMemoryError，场景：{scene}。\n3. 攻击者传入超大值使 JVM 崩溃。\n4. 结论：CWE-770 无限制分配，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-770 Allocation without Limits", "risk_level": "Medium",
         "source": "line 4: {func}(int {param}) 参数来自外部", "sink": "line 5: new byte[{param}] 无大小限制",
         "explanation": "line 5 用户控制数组大小 -> 无上限 -> OutOfMemoryError -> DoS",
         "fix_suggestion": "line 5: 应改为 if ({param} > 1048576) throw new IllegalArgumentException(); 检查上限"},
        av(5, o=2))
    # T4: Go make user size (5)
    R += expand("go",
        "// {fname}\nfunc {func}({param} int) []byte {\n    buf := make([]byte, {param})  // line 4: no size limit\n    return buf\n}\n",
        "分析过程：\n1. line 4 make([]byte, {param}) 分配大小由用户控制，无上限。\n2. {param} 过大导致内存耗尽，场景：{scene}。\n3. 攻击者传入超大值导致 OOM。\n4. 结论：CWE-770 无限制分配，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-770 Allocation without Limits", "risk_level": "Medium",
         "source": "line 3: {func}({param} int) 参数来自外部", "sink": "line 4: make([]byte, {param}) 无大小限制",
         "explanation": "line 4 用户控制 make 大小 -> 无上限 -> 超大分配 -> OOM",
         "fix_suggestion": "line 4: 应改为 if {param} > maxLen { return nil } 检查上限后再分配"},
        gv(5, o=2))
    # T5: Python string multiply (4)
    R += expand("python",
        "# {fname}\ndef {func}({param}):\n    n = int({param})\n    s = 'A' * n  # line 5: user-controlled string size\n    return s\n",
        "分析过程：\n1. line 5 'A' * n 字符串大小由用户输入控制，无上限。\n2. {param} 过大导致大量内存分配，场景：{scene}。\n3. 攻击者传入超大值导致 OOM。\n4. 结论：CWE-770 无限制分配，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-770 Allocation without Limits", "risk_level": "Medium",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部", "sink": "line 5: 'A' * n 无大小限制",
         "explanation": "line 5 用户控制字符串大小 -> 无上限 -> 超大分配 -> OOM",
         "fix_suggestion": "line 5: 应改为 if n > 10000: n = 10000 限制最大长度"},
        pv(4, o=4))
    # T6: DC has max but too large (4)
    R += expand("python",
        "# {fname}\ndef {func}({param}):\n    n = int({param})\n    if n > 100000000:  # line 4: limit too high (100MB)\n        n = 100000000\n    data = bytearray(n)  # line 6: up to 100MB\n    return data\n",
        "分析过程：\n1. line 4 限制上限 100000000（100MB），看似有防护但上限过高。\n2. line 6 最多分配 100MB，仍可导致 OOM。\n3. {param} 来自外部，场景：{scene}。\n4. 结论：CWE-770 无限制分配（上限过高），风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-770 Allocation without Limits", "risk_level": "Medium",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部", "sink": "line 6: bytearray(n) 上限过高",
         "explanation": "line 4 上限 100MB -> line 6 仍可分配 100MB -> OOM -> 防御不充分",
         "fix_suggestion": "line 4: 应改为 if n > 1024: n = 1024 降低到合理上限"},
        pv(4, o=6), dc=True)
    return R


def g_91():
    """CWE-91 XML Injection (28)"""
    R = []
    # T1: Python XML string concat (5)
    R += expand("python",
        "# {fname}\nfrom xml.etree import ElementTree as ET\ndef {func}({param}):\n    xml = f'<user><name>{param}</name></user>'  # line 4: no escaping\n    return ET.fromstring(xml)\n",
        "分析过程：\n1. line 4 将 {param} 直接拼入 XML 字符串，未转义特殊字符。\n2. {param} 含 < > & 可破坏 XML 结构或注入恶意节点，场景：{scene}。\n3. 攻击者传入 'x</name><admin>true</admin><name>x' 注入 admin 节点。\n4. 结论：CWE-91 XML 注入，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-91 XML Injection", "risk_level": "High",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部", "sink": "line 4: f'<user><name>{param}</name></user>' 未转义",
         "explanation": "line 4 用户输入拼入 XML -> 未转义 < > & -> 注入恶意 XML 节点 -> XML 注入",
         "fix_suggestion": "line 4: 应改为使用 ET.SubElement 安全构建 XML，或 xml.sax.saxutils.escape 转义"},
        pv(5))
    # T2: Java XML string build (5)
    R += expand("java",
        "// {fname}\nimport javax.xml.parsers.*;\nimport org.w3c.dom.*;\npublic class {cls} {{\n    public static String {func}(String {param}) throws Exception {{\n        String xml = \"<user><name>\" + {param} + \"</name></user>\";  // line 6\n        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(new InputSource(new StringReader(xml)));\n        return doc.getElementsByTagName(\"name\").item(0).getTextContent();\n    }}\n}}\n",
        "分析过程：\n1. line 6 将 {param} 直接拼入 XML 字符串，未转义。\n2. 攻击者注入 </name> 关闭标签并注入恶意节点，场景：{scene}。\n3. 可导致 XML 结构篡改或 XXE 信息泄露。\n4. 结论：CWE-91 XML 注入，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-91 XML Injection", "risk_level": "High",
         "source": "line 5: {func}(String {param}) 参数来自外部", "sink": "line 6: \"<user><name>\" + {param} 拼接 XML",
         "explanation": "line 6 用户输入拼入 XML -> 未转义 -> 注入恶意节点 -> XML 注入",
         "fix_suggestion": "line 6: 应改为使用 DOM API createElement/setTextContent 安全构建 XML"},
        av(5))
    # T3: Node.js XML string (5)
    R += expand("javascript",
        "// {fname}\nfunction {func}({param}) {{\n    const xml = '<user><name>' + {param} + '</name></user>';  // line 3: no escaping\n    return parseXml(xml);\n}}\n",
        "分析过程：\n1. line 3 将 {param} 直接拼入 XML 字符串，未转义特殊字符。\n2. {param} 来自外部，场景：{scene}，攻击者可注入 XML 节点。\n3. 攻击者传入 'x</name><role>admin</role>' 篡改 XML 结构。\n4. 结论：CWE-91 XML 注入，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-91 XML Injection", "risk_level": "High",
         "source": "line 2: {func}({param}) 参数来自外部", "sink": "line 3: '<user><name>' + {param} 拼接 XML",
         "explanation": "line 3 用户输入拼入 XML -> 未转义 -> 注入恶意节点 -> XML 注入",
         "fix_suggestion": "line 3: 应改为使用 xml-escape 库转义 {param} 后再拼接，或使用 DOM API"},
        jv(5, o=2))
    # T4: Python ElementTree attr (5)
    R += expand("python",
        "# {fname}\nfrom xml.etree import ElementTree as ET\ndef {func}({param}):\n    xml = f'<user name=\"{param}\"/>'  # line 4: attribute injection\n    return ET.fromstring(xml)\n",
        "分析过程：\n1. line 4 将 {param} 拼入 XML 属性值，未转义引号。\n2. {param} 含 \" 可关闭属性并注入新属性，场景：{scene}。\n3. 攻击者传入 'x\" admin=\"true' 注入 admin 属性。\n4. 结论：CWE-91 XML 注入，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-91 XML Injection", "risk_level": "High",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部", "sink": "line 4: f'<user name=\"{param}\"/>' 属性注入",
         "explanation": "line 4 用户输入拼入属性 -> 未转义引号 -> 注入新属性 -> XML 注入",
         "fix_suggestion": "line 4: 应改为使用 ET.Element + set('name', {param}) 安全设置属性"},
        pv(5, o=2))
    # T5: Java SAX handler (4)
    R += expand("java",
        "// {fname}\nimport java.io.*;\nimport javax.xml.parsers.*;\npublic class {cls} {{\n    public static String {func}(String {param}) throws Exception {{\n        String xml = \"<filter>\" + {param} + \"</filter>\";  // line 6\n        SAXParserFactory factory = SAXParserFactory.newInstance();\n        factory.newSAXParser().parse(new ByteArrayInputStream(xml.getBytes()), new MyHandler());\n        return \"ok\";\n    }}\n}}\n",
        "分析过程：\n1. line 6 将 {param} 拼入 XML 字符串，未转义。\n2. {param} 来自外部，场景：{scene}，可注入 XML 节点。\n3. 攻击者注入 </filter><data>敏感信息</data> 篡改解析结果。\n4. 结论：CWE-91 XML 注入，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-91 XML Injection", "risk_level": "High",
         "source": "line 5: {func}(String {param}) 参数来自外部", "sink": "line 6: \"<filter>\" + {param} 拼接 XML",
         "explanation": "line 6 用户输入拼入 XML -> 未转义 -> 注入恶意节点 -> XML 注入",
         "fix_suggestion": "line 6: 应改为使用 SAXBuilder 安全构建 XML 或 escapeXml({param}) 转义"},
        av(4, o=2))
    # T6: DC escapes < > but not & (4)
    R += expand("python",
        "# {fname}\nfrom xml.etree import ElementTree as ET\ndef {func}({param}):\n    val = {param}.replace('<', '&lt;').replace('>', '&gt;')  # line 4: partial escape\n    xml = f'<user><name>{val}</name></user>'  # line 5: & not escaped\n    return ET.fromstring(xml)\n",
        "分析过程：\n1. line 4 只转义 < > 未转义 &，看似有防护但可绕过。\n2. line 5 拼入 XML，{param} 含 & 可导致 XML 解析错误或实体注入。\n3. 场景：{scene}，攻击者使用 &amp; 等实体绕过。\n4. 结论：CWE-91 XML 注入（防御不完整），风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-91 XML Injection", "risk_level": "High",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部", "sink": "line 5: f'<user><name>{val}</name>' 转义不完整",
         "explanation": "line 4 只转义 < > -> & 未转义 -> line 5 & 破坏 XML -> 实体注入绕过",
         "fix_suggestion": "line 4: 应改为使用 xml.sax.saxutils.escape({param}) 转义所有 XML 特殊字符"},
        pv(4, o=4), dc=True)
    return R


def g_610():
    """CWE-610 Externally Controlled Reference (28)"""
    R = []
    # T1: Python dynamic import (5)
    R += expand("python",
        "# {fname}\nimport importlib\ndef {func}({param}):\n    mod = importlib.import_module({param})  # line 4: user-controlled module\n    return mod\n",
        "analysis_tpl_placeholder",
        {"has_vulnerability": True, "vulnerability_type": "CWE-610 Externally Controlled Reference", "risk_level": "High",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部", "sink": "line 4: importlib.import_module({param}) 用户控制模块",
         "explanation": "line 4 用户控制导入模块 -> 可加载任意模块 -> 代码执行",
         "fix_suggestion": "line 4: 应改为使用白名单 ALLOWED = ['mod1','mod2'] 校验 {param} 后再导入"},
        pv(5))
    for i, s in enumerate(R[-5:]):
        s["analysis"] = fmt("分析过程：\n1. line 4 importlib.import_module({param}) 导入用户指定模块，无白名单限制。\n2. {param} 来自外部，场景：{scene}，攻击者可加载任意 Python 模块。\n3. 可导入 os/subprocess 等危险模块执行任意代码。\n4. 结论：CWE-610 外部控制引用，风险 High。", **pv(5)[i])

    # T2: Java Class.forName (5)
    R += expand("java",
        "// {fname}\npublic class {cls} {{\n    public static Object {func}(String {param}) throws Exception {{\n        Class<?> clazz = Class.forName({param});  // line 5\n        return clazz.newInstance();\n    }}\n}}\n",
        "分析过程：\n1. line 5 Class.forName({param}) 加载用户指定的类，无白名单。\n2. {param} 来自外部，场景：{scene}，可加载任意类并实例化。\n3. 攻击者加载危险类执行任意代码。\n4. 结论：CWE-610 外部控制引用，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-610 Externally Controlled Reference", "risk_level": "High",
         "source": "line 4: {func}(String {param}) 参数来自外部", "sink": "line 5: Class.forName({param}) 用户控制类加载",
         "explanation": "line 5 用户控制类名 -> Class.forName 加载任意类 -> newInstance 执行代码",
         "fix_suggestion": "line 5: 应改为使用白名单 Set<String> ALLOWED 校验 {param} 后再 forName"},
        av(5, o=2))
    # T3: Node.js require (5)
    R += expand("javascript",
        "// {fname}\nfunction {func}({param}) {{\n    const mod = require({param});  // line 3: user-controlled require\n    return mod;\n}}\n",
        "分析过程：\n1. line 3 require({param}) 加载用户指定模块，无限制。\n2. {param} 来自外部，场景：{scene}，可加载任意 Node.js 模块。\n3. 攻击者加载 child_process 等模块执行任意命令。\n4. 结论：CWE-610 外部控制引用，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-610 Externally Controlled Reference", "risk_level": "High",
         "source": "line 2: {func}({param}) 参数来自外部", "sink": "line 3: require({param}) 用户控制模块加载",
         "explanation": "line 3 用户控制 require -> 加载任意模块 -> 代码执行",
         "fix_suggestion": "line 3: 应改为使用白名单 const ALLOWED = ['mod1','mod2'] 校验后 require"},
        jv(5, o=2))
    # T4: Python eval file path (5)
    R += expand("python",
        "# {fname}\ndef {func}({param}):\n    with open({param}, 'r') as f:  # line 4: user-controlled path\n        code = f.read()\n    exec(code)  # line 6: executes loaded code\n    return 'done'\n",
        "分析过程：\n1. line 4 open({param}) 打开用户指定路径文件，line 6 exec 执行文件内容。\n2. {param} 来自外部，场景：{scene}，可加载任意路径的代码。\n3. 攻击者指定恶意文件路径执行任意代码。\n4. 结论：CWE-610 外部控制引用，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-610 Externally Controlled Reference", "risk_level": "Critical",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部", "sink": "line 6: exec(code) 执行外部加载的代码",
         "explanation": "line 4 用户控制文件路径 -> line 6 exec 文件内容 -> 任意代码执行",
         "fix_suggestion": "line 4-6: 应改为使用白名单路径校验，且禁止 exec 加载的代码"},
        pv(5, o=2))
    # T5: Java URLClassLoader (4)
    R += expand("java",
        "// {fname}\nimport java.net.*;\npublic class {cls} {{\n    public static Class<?> {func}(String {param}) throws Exception {{\n        URL[] urls = {{ new URL({param}) }};  // line 5\n        URLClassLoader cl = new URLClassLoader(urls);  // line 6\n        return cl.loadClass(\"Plugin\");\n    }}\n}}\n",
        "分析过程：\n1. line 5-6 从用户指定的 URL 创建 URLClassLoader 加载类。\n2. {param} 来自外部，场景：{scene}，可加载远程恶意 JAR。\n3. 攻击者托管恶意 JAR 并指定 URL 加载执行。\n4. 结论：CWE-610 外部控制引用，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-610 Externally Controlled Reference", "risk_level": "Critical",
         "source": "line 4: {func}(String {param}) 参数来自外部", "sink": "line 6: new URLClassLoader(urls) 加载用户指定 URL",
         "explanation": "line 5 用户控制 URL -> line 6 URLClassLoader 加载 -> 远程恶意类执行",
         "fix_suggestion": "line 5: 应改为使用白名单 URL 校验，或仅从受信任的本地路径加载"},
        av(4, o=4))
    # T6: DC whitelist but bypassable (4)
    R += expand("python",
        "# {fname}\nimport importlib\nALLOWED = ['utils', 'helpers', 'config']\ndef {func}({param}):\n    name = {param}.split('.')[0]  # line 5: extracts top-level\n    if name in ALLOWED:  # line 6: whitelist check\n        return importlib.import_module({param})  # line 7: but full path used\n    return None\n",
        "分析过程：\n1. line 5-6 只检查模块名前缀是否在白名单，看似有防护。\n2. line 7 导入完整 {param}，攻击者可传 'utils.malicious' 绕过检查。\n3. 场景：{scene}，白名单只检查顶层模块名。\n4. 结论：CWE-610 外部控制引用（防御可绕过），风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-610 Externally Controlled Reference", "risk_level": "High",
         "source": "line 4: {func}({param}) 参数 {param} 来自外部", "sink": "line 7: importlib.import_module({param}) 白名单可绕过",
         "explanation": "line 5 只检查顶层名 -> line 7 导入完整路径 -> utils.malicious 绕过白名单",
         "fix_suggestion": "line 6: 应改为 if {param} in ALLOWED: 完整匹配而非只检查前缀"},
        pv(4, o=4), dc=True)
    return R


def g_797():
    """CWE-797 Conversion of Numeric Data to String (28)"""
    R = []
    # T1: Python str(huge_number) (5)
    R += expand("python",
        "# {fname}\ndef {func}({param}):\n    n = int({param})\n    result = str(10 ** n)  # line 5: exponential string size\n    return len(result)\n",
        "分析过程：\n1. line 5 计算 10**n 并转为字符串，n 由用户输入控制。\n2. n=1000000 时生成 100 万字符的字符串，耗尽内存。\n3. {param} 来自外部，场景：{scene}，数值转字符串无上限。\n4. 结论：CWE-797 数值转字符串 DoS，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-797 Conversion of Numeric Data to String", "risk_level": "Medium",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部", "sink": "line 5: str(10 ** n) 指数级字符串生成",
         "explanation": "line 5 10**n 转字符串 -> n 控制大小 -> 无上限 -> OOM",
         "fix_suggestion": "line 5: 应改为 if n > 1000: return -1 限制指数大小后再转换"},
        pv(5))
    # T2: C sprintf large number (5)
    R += expand("c",
        "// {fname}\n#include <stdio.h>\n#include <stdlib.h>\nchar* {func}(int {param}) {\n    char* buf = malloc(32);  // line 6: fixed small buffer\n    sprintf(buf, \"%d\", {param} * 1000000);  // line 7: overflow if large\n    return buf;\n}\n",
        "分析过程：\n1. line 6 分配 32 字节缓冲区，line 7 sprintf 将大数转为字符串。\n2. {param} 较大时 %d 的字符串表示超过 32 字节导致缓冲区溢出。\n3. {param} 来自外部，场景：{scene}。\n4. 结论：CWE-797 数值转字符串导致溢出，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-797 Conversion of Numeric Data to String", "risk_level": "High",
         "source": "line 5: {func}(int {param}) 参数 {param} 来自外部", "sink": "line 7: sprintf(buf, \"%d\", {param}*1000000) 缓冲区溢出",
         "explanation": "line 6 固定 32 字节 -> line 7 大数转字符串溢出 -> 缓冲区溢出",
         "fix_suggestion": "line 7: 应改为 snprintf(buf, 32, \"%d\", {param}) 限制写入长度"},
        cv(5, o=2))
    # T3: Java BigInteger toString (5)
    R += expand("java",
        "// {fname}\nimport java.math.BigInteger;\npublic class {cls} {{\n    public static String {func}(String {param}) {{\n        BigInteger num = new BigInteger({param});  // line 5\n        return num.toString();  // line 6: huge string for huge number\n    }}\n}}\n",
        "分析过程：\n1. line 5 从用户输入创建 BigInteger，line 6 转为字符串。\n2. {param} 为极大整数时，toString 生成超长字符串耗尽内存。\n3. 场景：{scene}，无大小限制的数值转字符串。\n4. 结论：CWE-797 数值转字符串 DoS，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-797 Conversion of Numeric Data to String", "risk_level": "Medium",
         "source": "line 4: {func}(String {param}) 参数来自外部", "sink": "line 6: num.toString() 超大数字转字符串",
         "explanation": "line 5 用户输入大数 -> line 6 toString 生成超长字符串 -> OOM",
         "fix_suggestion": "line 6: 应改为 if (num.bitLength() > 10000) return \"too large\" 限制位数后再转换"},
        av(5, o=2))
    # T4: JavaScript BigInt string (5)
    R += expand("javascript",
        "// {fname}\nfunction {func}({param}) {{\n    const n = BigInt({param});  // line 3\n    const s = (10n ** n).toString();  // line 4: exponential string\n    return s.length;\n}}\n",
        "分析过程：\n1. line 3 从用户输入创建 BigInt，line 4 计算 10**n 并转字符串。\n2. n 较大时生成超长字符串，{param} 来自外部。\n3. 场景：{scene}，指数级字符串增长导致 OOM。\n4. 结论：CWE-797 数值转字符串 DoS，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-797 Conversion of Numeric Data to String", "risk_level": "Medium",
         "source": "line 2: {func}({param}) 参数来自外部", "sink": "line 4: (10n ** n).toString() 指数级字符串",
         "explanation": "line 3 用户控制 n -> line 4 10**n 转字符串 -> 无上限 -> OOM",
         "fix_suggestion": "line 4: 应改为 if (n > 1000n) return -1 限制指数大小"},
        jv(5, o=2))
    # T5: Python format huge (4)
    R += expand("python",
        "# {fname}\ndef {func}({param}):\n    n = int({param})\n    s = '{:d}'.format(2 ** n)  # line 5: exponential number to string\n    return s\n",
        "分析过程：\n1. line 5 计算 2**n 并用 format 转字符串，n 由用户控制。\n2. n=1000000 时生成超长字符串，{param} 来自外部。\n3. 场景：{scene}，数值转字符串无上限导致 OOM。\n4. 结论：CWE-797 数值转字符串 DoS，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-797 Conversion of Numeric Data to String", "risk_level": "Medium",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部", "sink": "line 5: '{:d}'.format(2 ** n) 超大数转字符串",
         "explanation": "line 5 2**n 转 format 字符串 -> n 控制大小 -> 无上限 -> OOM",
         "fix_suggestion": "line 5: 应改为 if n > 1000: return '' 限制指数大小"},
        pv(4, o=4))
    # T6: DC has limit but off-by-one (4)
    R += expand("python",
        "# {fname}\ndef {func}({param}):\n    n = int({param})\n    if n < 100000:  # line 4: limit check, but boundary wrong\n        return str(10 ** n)  # line 5: n=99999 still huge\n    return ''\n",
        "分析过程：\n1. line 4 检查 n < 100000，看似有防护但 99999 仍生成超大字符串。\n2. line 5 str(10**99999) 生成约 10 万字符，仍消耗大量内存。\n3. {param} 来自外部，场景：{scene}，上限过高。\n4. 结论：CWE-797 数值转字符串 DoS（上限过高），风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-797 Conversion of Numeric Data to String", "risk_level": "Medium",
         "source": "line 3: {func}({param}) 参数 {param} 来自外部", "sink": "line 5: str(10 ** n) 上限过高",
         "explanation": "line 4 上限 99999 -> line 5 仍生成超长字符串 -> OOM -> 防御不充分",
         "fix_suggestion": "line 4: 应改为 if n > 1000: return '' 降低到合理上限"},
        pv(4, o=6), dc=True)
    return R


def g_93():
    """CWE-93 CRLF Injection / HTTP Response Splitting (29)"""
    R = []
    # T1: Python Flask response split (5)
    R += expand("python",
        "# {fname}\nfrom flask import Flask, request, redirect\napp = Flask(__name__)\n@app.route('/{func}')\ndef {func}():\n    url = request.args.get('url', '/')  # line 6\n    return redirect(url)  # line 7: response splitting\n",
        "分析过程：\n1. line 6 从请求参数获取 url，line 7 直接用于 redirect。\n2. url 含 \\r\\n\\r\\n 可注入 HTTP 响应体，实现响应拆分。\n3. {param} 来自外部，场景：{scene}，攻击者注入额外 HTTP 响应。\n4. 结论：CWE-93 HTTP 响应拆分，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-93 CRLF Injection", "risk_level": "High",
         "source": "line 6: request.args.get('url') 用户可控输入", "sink": "line 7: redirect(url) 响应拆分",
         "explanation": "line 6 用户输入 URL -> line 7 redirect 设 Location -> \\r\\n 注入额外响应 -> 响应拆分",
         "fix_suggestion": "line 7: 应改为 url = url.replace('\\r', '').replace('\\n', '') 过滤 CRLF 后再 redirect"},
        pv(5))
    # T2: Java response header CRLF (5)
    R += expand("java",
        "// {fname}\nimport javax.servlet.*;\nimport javax.servlet.http.*;\npublic class {cls} extends HttpServlet {{\n    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {{\n        String loc = req.getParameter(\"loc\");  // line 6\n        resp.sendRedirect(loc);  // line 7: response splitting\n    }}\n}}\n",
        "分析过程：\n1. line 6 从请求参数获取 loc，line 7 直接用于 sendRedirect。\n2. loc 含 \\r\\n 可注入额外 HTTP 头/响应体。\n3. 场景：{scene}，攻击者实现响应拆分攻击。\n4. 结论：CWE-93 HTTP 响应拆分，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-93 CRLF Injection", "risk_level": "High",
         "source": "line 6: req.getParameter(\"loc\") 用户可控输入", "sink": "line 7: resp.sendRedirect(loc) 响应拆分",
         "explanation": "line 6 用户输入 -> line 7 sendRedirect -> \\r\\n 注入额外响应 -> 响应拆分",
         "fix_suggestion": "line 7: 应改为 loc = loc.replaceAll(\"[\\\\r\\\\n]\", \"\") 过滤 CRLF 后再 sendRedirect"},
        av(5))
    # T3: Node.js res.set CRLF (5)
    R += expand("javascript",
        "// {fname}\nconst express = require('express');\nconst app = express();\napp.get('/{func}', (req, res) => {{\n    const loc = req.query.loc;  // line 5\n    res.redirect(loc);  // line 6: response splitting\n}});\n",
        "分析过程：\n1. line 5 从查询参数获取 loc，line 6 直接用于 redirect。\n2. loc 含 \\r\\n 可注入额外 HTTP 响应。\n3. 场景：{scene}，攻击者实现响应拆分。\n4. 结论：CWE-93 HTTP 响应拆分，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-93 CRLF Injection", "risk_level": "High",
         "source": "line 5: req.query.loc 用户可控输入", "sink": "line 6: res.redirect(loc) 响应拆分",
         "explanation": "line 5 用户输入 -> line 6 res.redirect -> \\r\\n 注入额外响应 -> 响应拆分",
         "fix_suggestion": "line 6: 应改为 loc.replace(/[\\r\\n]/g, '') 过滤 CRLF 后再 redirect"},
        jv(5, o=2))
    # T4: Go header.Set CRLF (5)
    R += expand("go",
        "// {fname}\nimport (\n    \"net/http\"\n)\nfunc {func}(w http.ResponseWriter, r *http.Request) {\n    loc := r.URL.Query().Get(\"loc\")  // line 6\n    http.Redirect(w, r, loc, 302)  // line 7: response splitting\n}\n",
        "分析过程：\n1. line 6 从查询参数获取 loc，line 7 用于 http.Redirect。\n2. loc 含 \\r\\n 可注入额外 HTTP 头/响应体。\n3. 场景：{scene}，攻击者实现响应拆分攻击。\n4. 结论：CWE-93 HTTP 响应拆分，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-93 CRLF Injection", "risk_level": "High",
         "source": "line 6: r.URL.Query().Get(\"loc\") 用户可控输入", "sink": "line 7: http.Redirect 响应拆分",
         "explanation": "line 6 用户输入 -> line 7 Redirect -> \\r\\n 注入额外响应 -> 响应拆分",
         "fix_suggestion": "line 7: 应改为 strings.NewReplacer(\"\\r\", \"\", \"\\n\", \"\").Replace(loc) 过滤后重定向"},
        gv(5, o=2))
    # T5: Python redirect CRLF (5)
    R += expand("python",
        "# {fname}\nfrom flask import Flask, request, make_response\napp = Flask(__name__)\n@app.route('/{func}')\ndef {func}():\n    val = request.args.get('val', '')  # line 6\n    resp = make_response('ok')\n    resp.headers['Location'] = val  # line 9: CRLF in Location\n    return resp\n",
        "分析过程：\n1. line 6 从请求参数获取 val，line 9 直接设入 Location 响应头。\n2. val 含 \\r\\n 可注入额外 HTTP 头/响应体，场景：{scene}。\n3. 攻击者注入额外响应实现响应拆分。\n4. 结论：CWE-93 HTTP 响应拆分，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-93 CRLF Injection", "risk_level": "High",
         "source": "line 6: request.args.get('val') 用户可控输入", "sink": "line 9: resp.headers['Location'] = val 响应拆分",
         "explanation": "line 6 用户输入 -> line 9 写入 Location -> \\r\\n 注入额外响应 -> 响应拆分",
         "fix_suggestion": "line 9: 应改为 val = val.replace('\\r', '').replace('\\n', '') 过滤 CRLF 后再设入"},
        pv(5, o=2))
    # T6: DC strips \\r\\n in URL but allows %0d%0a (4)
    R += expand("python",
        "# {fname}\nfrom flask import Flask, request, redirect\napp = Flask(__name__)\n@app.route('/{func}')\ndef {func}():\n    url = request.args.get('url', '/').replace('\\r', '').replace('\\n', '')  # line 6: strips raw CRLF\n    return redirect(url)  # line 7: but %0d%0a still decoded by some proxies\n",
        "分析过程：\n1. line 6 过滤原始 \\r\\n 字符，看似有防护。\n2. line 7 redirect 仍接受 URL 编码的 %0d%0a，部分代理/客户端会解码后注入 CRLF。\n3. {param} 来自外部，场景：{scene}，编码绕过。\n4. 结论：CWE-93 HTTP 响应拆分（防御可绕过），风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-93 CRLF Injection", "risk_level": "High",
         "source": "line 6: request.args.get('url') 用户可控输入", "sink": "line 7: redirect(url) %0d%0a 编码绕过",
         "explanation": "line 6 只过滤原始 CRLF -> line 7 %0d%0a 未解码 -> 代理解码后注入 -> 响应拆分",
         "fix_suggestion": "line 6: 应改为 url = urllib.parse.unquote(url).replace('\\r', '').replace('\\n', '') 先解码再过滤"},
        pv(4, o=4), dc=True)
    return R


def g_759():
    """CWE-759 Use of a One-Way Hash without a Salt (29)"""
    R = []
    # T1: Python hashlib MD5 no salt (5)
    R += expand("python",
        "# {fname}\nimport hashlib\ndef {func}(password):\n    return hashlib.md5(password.encode()).hexdigest()  # line 4: no salt\n",
        "分析过程：\n1. line 4 使用 MD5 哈希密码且无盐值，password 来自用户输入。\n2. 无盐值导致相同密码产生相同哈希，可通过彩虹表快速反推。\n3. 场景：{scene}，MD5 已被证明不安全。\n4. 结论：CWE-759 无盐哈希，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-759 Use of a One-Way Hash without a Salt", "risk_level": "High",
         "source": "line 3: {func}(password) 参数来自外部", "sink": "line 4: hashlib.md5(password.encode()) 无盐哈希",
         "explanation": "line 4 MD5 无盐 -> 相同密码相同哈希 -> 彩虹表反推 -> 密码泄露",
         "fix_suggestion": "line 4: 应改为 bcrypt.hashpw(password.encode(), bcrypt.gensalt()) 使用带盐的 bcrypt"},
        pv(5))
    # T2: Java MessageDigest no salt (5)
    R += expand("java",
        "// {fname}\nimport java.security.MessageDigest;\npublic class {cls} {{\n    public static String {func}(String password) throws Exception {{\n        MessageDigest md = MessageDigest.getInstance(\"SHA-256\");  // line 5\n        byte[] hash = md.digest(password.getBytes());  // line 6: no salt\n        StringBuilder sb = new StringBuilder();\n        for (byte b : hash) sb.append(String.format(\"%02x\", b));\n        return sb.toString();\n    }}\n}}\n",
        "分析过程：\n1. line 5 创建 SHA-256 MessageDigest，line 6 直接对 password 哈希无盐值。\n2. 相同密码产生相同哈希，可建彩虹表，password 来自外部。\n3. 场景：{scene}，无盐哈希易受预计算攻击。\n4. 结论：CWE-759 无盐哈希，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-759 Use of a One-Way Hash without a Salt", "risk_level": "Medium",
         "source": "line 4: {func}(String password) 参数来自外部", "sink": "line 6: md.digest(password.getBytes()) 无盐哈希",
         "explanation": "line 6 SHA-256 无盐 -> 相同密码相同哈希 -> 彩虹表攻击 -> 密码反推",
         "fix_suggestion": "line 6: 应改为使用 SecureRandom 生成盐值，digest((salt + password).getBytes())"},
        av(5))
    # T3: Node.js crypto SHA256 no salt (5)
    R += expand("javascript",
        "// {fname}\nconst crypto = require('crypto');\nfunction {func}(password) {{\n    return crypto.createHash('sha256').update(password).digest('hex');  // line 4: no salt\n}}\n",
        "分析过程：\n1. line 4 使用 sha256 哈希密码且无盐值，password 来自用户输入。\n2. 无盐哈希可通过彩虹表反推，场景：{scene}。\n3. 攻击者预计算常见密码哈希表后批量比对。\n4. 结论：CWE-759 无盐哈希，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-759 Use of a One-Way Hash without a Salt", "risk_level": "Medium",
         "source": "line 3: {func}(password) 参数来自外部", "sink": "line 4: createHash('sha256').update(password) 无盐",
         "explanation": "line 4 SHA-256 无盐 -> 相同密码相同哈希 -> 彩虹表攻击 -> 密码泄露",
         "fix_suggestion": "line 4: 应改为 crypto.randomBytes(16) 生成盐后 update(salt + password)"},
        jv(5, o=2))
    # T4: Go sha256 no salt (5)
    R += expand("go",
        "// {fname}\nimport (\n    \"crypto/sha256\"\n    \"encoding/hex\"\n)\nfunc {func}(password string) string {\n    h := sha256.Sum256([]byte(password))  // line 7: no salt\n    return hex.EncodeToString(h[:])\n}\n",
        "分析过程：\n1. line 7 sha256.Sum256 直接对 password 哈希无盐值。\n2. password 来自外部，场景：{scene}，相同密码产生相同哈希。\n3. 攻击者可建彩虹表反推密码。\n4. 结论：CWE-759 无盐哈希，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-759 Use of a One-Way Hash without a Salt", "risk_level": "Medium",
         "source": "line 6: {func}(password string) 参数来自外部", "sink": "line 7: sha256.Sum256([]byte(password)) 无盐",
         "explanation": "line 7 SHA-256 无盐 -> 相同密码相同哈希 -> 彩虹表攻击 -> 密码反推",
         "fix_suggestion": "line 7: 应改为使用 crypto/rand 生成盐后 sha256.Sum256([]byte(salt + password))"},
        gv(5, o=2))
    # T5: Python hashlib SHA1 (5)
    R += expand("python",
        "# {fname}\nimport hashlib\ndef {func}(password):\n    return hashlib.sha1(password.encode()).hexdigest()  # line 4: SHA1 no salt\n",
        "分析过程：\n1. line 4 使用 SHA-1 哈希密码且无盐值，SHA-1 已被证明不安全。\n2. password 来自外部，场景：{scene}，相同密码产生相同哈希。\n3. SHA-1 + 无盐双重弱点，彩虹表攻击高效。\n4. 结论：CWE-759 无盐哈希，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-759 Use of a One-Way Hash without a Salt", "risk_level": "High",
         "source": "line 3: {func}(password) 参数来自外部", "sink": "line 4: hashlib.sha1(password.encode()) 无盐",
         "explanation": "line 4 SHA-1 无盐 -> 弱哈希算法 + 无盐 -> 彩虹表快速反推 -> 密码泄露",
         "fix_suggestion": "line 4: 应改为 bcrypt.hashpw(password.encode(), bcrypt.gensalt()) 使用带盐的强哈希"},
        pv(5, o=2))
    # T6: DC uses salt but hardcoded (4)
    R += expand("python",
        "# {fname}\nimport hashlib\nSALT = 'staticsalt123'  # line 3: hardcoded salt\ndef {func}(password):\n    return hashlib.sha256((SALT + password).encode()).hexdigest()  # line 5\n",
        "分析过程：\n1. line 3 SALT 为硬编码固定值，看似有盐但所有用户共用。\n2. line 5 使用固定盐 + SHA-256，攻击者获取盐后可建彩虹表。\n3. password 来自外部，场景：{scene}，固定盐无法防御预计算攻击。\n4. 结论：CWE-759 无盐哈希（固定盐无效），风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-759 Use of a One-Way Hash without a Salt", "risk_level": "Medium",
         "source": "line 4: {func}(password) 参数来自外部", "sink": "line 5: sha256(SALT + password) 硬编码盐",
         "explanation": "line 3 固定盐 -> line 5 所有用户共用盐 -> 获取盐后建彩虹表 -> 密码反推",
         "fix_suggestion": "line 3: 应改为 SALT = os.urandom(16) 每个用户生成独立随机盐并存储"},
        pv(4, o=4), dc=True)
    return R


def g_401():
    """CWE-401 Missing Release of Memory after Effective Lifetime (26)"""
    R = []
    # T1: C malloc no free (5)
    R += expand("c",
        "// {fname}\n#include <stdlib.h>\n#include <string.h>\nchar* {func}(int {param}) {\n    char* buf = malloc({param});  // line 5\n    if (!buf) return NULL;\n    strcpy(buf, \"data\");\n    return buf;  // line 9: caller may not free\n}\n",
        "分析过程：\n1. line 5 malloc 分配内存，line 9 返回指针但调用方可能不释放。\n2. {param} 来自外部，场景：{scene}，内存泄漏。\n3. 长期运行导致内存耗尽。\n4. 结论：CWE-401 内存泄漏，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-401 Missing Release of Memory after Effective Lifetime", "risk_level": "Medium",
         "source": "line 4: {func}(int {param}) 参数来自外部", "sink": "line 9: return buf 调用方未释放",
         "explanation": "line 5 malloc 分配 -> line 9 返回 -> 调用方不 free -> 内存泄漏",
         "fix_suggestion": "line 9: 应改为文档约定调用方必须 free，或使用引用计数/智能指针管理"},
        cv(5))
    # T2: Python open no close (5)
    R += expand("python",
        "# {fname}\ndef {func}({param}):\n    f = open({param}, 'r')  # line 3: no close\n    data = f.read()\n    return data\n",
        "分析过程：\n1. line 3 open 打开文件但未调用 close，依赖 GC 回收。\n2. {param} 来自外部，场景：{scene}，文件描述符泄漏。\n3. 大量未关闭文件导致 fd 耗尽。\n4. 结论：CWE-401 资源泄漏，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-401 Missing Release of Memory after Effective Lifetime", "risk_level": "Medium",
         "source": "line 2: {func}({param}) 参数来自外部", "sink": "line 3: open({param}) 未关闭",
         "explanation": "line 3 open 未 close -> 依赖 GC -> fd 泄漏 -> 文件描述符耗尽",
         "fix_suggestion": "line 3: 应改为 with open({param}, 'r') as f: 使用上下文管理器自动关闭"},
        pv(5))
    # T3: Java connection no close (5)
    R += expand("java",
        "// {fname}\nimport java.sql.*;\npublic class {cls} {{\n    public static String {func}(String {param}) throws Exception {{\n        Connection conn = DriverManager.getConnection({param});  // line 5\n        Statement stmt = conn.createStatement();  // line 6\n        ResultSet rs = stmt.executeQuery(\"SELECT 1\");  // line 7\n        return rs.getString(1);  // line 8: no close\n    }}\n}}\n",
        "分析过程：\n1. line 5-7 创建 Connection/Statement/ResultSet 但均未 close。\n2. {param} 来自外部，场景：{scene}，数据库连接泄漏。\n3. 连接池耗尽导致服务不可用。\n4. 结论：CWE-401 资源泄漏，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-401 Missing Release of Memory after Effective Lifetime", "risk_level": "Medium",
         "source": "line 4: {func}(String {param}) 参数来自外部", "sink": "line 8: return 未 close 资源",
         "explanation": "line 5-7 创建资源 -> line 8 未 close -> 连接泄漏 -> 连接池耗尽",
         "fix_suggestion": "line 5-7: 应改为 try-with-resources 自动关闭 conn/stmt/rs"},
        av(5, o=2))
    # T4: Node.js stream no end (5)
    R += expand("javascript",
        "// {fname}\nconst fs = require('fs');\nfunction {func}({param}) {{\n    const stream = fs.createReadStream({param});  // line 4\n    let data = '';\n    stream.on('data', (chunk) => data += chunk);  // line 6: no end/close\n    return data;\n}}\n",
        "分析过程：\n1. line 4 createReadStream 创建流，line 6 监听 data 但未处理 end/close。\n2. {param} 来自外部，场景：{scene}，流资源泄漏。\n3. 未关闭的流导致文件描述符耗尽。\n4. 结论：CWE-401 资源泄漏，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-401 Missing Release of Memory after Effective Lifetime", "risk_level": "Medium",
         "source": "line 3: {func}({param}) 参数来自外部", "sink": "line 6: stream.on 无 end/close 处理",
         "explanation": "line 4 创建流 -> line 6 无 end 处理 -> 流未关闭 -> fd 泄漏",
         "fix_suggestion": "line 6: 应改为 stream.on('end', () => {{...}}); stream.on('error', ...); 并在结束时销毁流"},
        jv(5, o=2))
    # T5: C++ new no delete (3)
    R += expand("cpp",
        "// {fname}\n#include <cstring>\nchar* {func}(char* {param}) {\n    char* buf = new char[256];  // line 4: new[]\n    strcpy(buf, {param});\n    return buf;  // line 7: no delete[]\n}\n",
        "分析过程：\n1. line 4 new[] 分配内存，line 7 返回指针但调用方可能不 delete[]。\n2. {param} 来自外部，场景：{scene}，堆内存泄漏。\n3. 长期运行导致内存耗尽。\n4. 结论：CWE-401 内存泄漏，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-401 Missing Release of Memory after Effective Lifetime", "risk_level": "Medium",
         "source": "line 3: {func}(char* {param}) 参数来自外部", "sink": "line 7: return buf 未 delete[]",
         "explanation": "line 4 new[] 分配 -> line 7 返回 -> 未 delete[] -> 内存泄漏",
         "fix_suggestion": "line 4: 应改为使用 std::unique_ptr<char[]> 或 std::string 自动管理生命周期"},
        cv(3, o=2))
    # T6: DC has close but in wrong branch (3)
    R += expand("python",
        "# {fname}\ndef {func}({param}):\n    f = open({param}, 'r')  # line 3\n    try:\n        data = f.read()\n        if not data:\n            f.close()  # line 6: only closes on empty\n        return data\n    except Exception:\n        return ''  # line 9: f not closed on exception\n",
        "分析过程：\n1. line 6 仅在 data 为空时 close，正常路径和异常路径均未关闭。\n2. line 9 异常分支直接 return，f 未关闭，{param} 来自外部。\n3. 场景：{scene}，资源泄漏在多数路径发生。\n4. 结论：CWE-401 资源泄漏（防御不完整），风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-401 Missing Release of Memory after Effective Lifetime", "risk_level": "Medium",
         "source": "line 2: {func}({param}) 参数来自外部", "sink": "line 9: 异常路径未 close f",
         "explanation": "line 6 仅空数据 close -> line 9 异常未 close -> 多数路径泄漏 -> 资源泄漏",
         "fix_suggestion": "line 3: 应改为 with open({param}, 'r') as f: 使用上下文管理器确保所有路径关闭"},
        pv(3, o=4), dc=True)
    return R


def g_204():
    """CWE-204 Observable Response Discrepancy (27)"""
    R = []
    # T1: Python login error message (5)
    R += expand("python",
        "# {fname}\ndef {func}(username, password):\n    user = db.find(username)  # line 3\n    if not user:\n        return 'user not found'  # line 5: reveals user existence\n    if user.password != password:\n        return 'wrong password'  # line 7: reveals password wrong\n    return 'ok'\n",
        "分析过程：\n1. line 5 返回 'user not found' 暴露用户是否存在，line 7 返回 'wrong password' 区分错误。\n2. 攻击者通过不同响应枚举有效用户名，{param} 来自外部。\n3. 场景：{scene}，用户名枚举攻击。\n4. 结论：CWE-204 响应差异可观察，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-204 Observable Response Discrepancy", "risk_level": "Medium",
         "source": "line 2: {func}(username, password) 参数来自外部", "sink": "line 5/7: 不同错误消息暴露用户存在性",
         "explanation": "line 5 'user not found' vs line 7 'wrong password' -> 响应差异 -> 用户名枚举",
         "fix_suggestion": "line 5/7: 应改为统一返回 'invalid credentials' 不区分用户不存在与密码错误"},
        pv(5))
    # T2: Java login timing (5)
    R += expand("java",
        "// {fname}\npublic class {cls} {{\n    public static String {func}(String user, String pass) {{\n        User u = db.findUser(user);  // line 4\n        if (u == null) return \"user not found\";  // line 5: fast path\n        if (!u.checkPassword(pass)) return \"wrong password\";  // line 7: slow path\n        return \"ok\";\n    }}\n}}\n",
        "分析过程：\n1. line 5 用户不存在直接返回（快），line 7 密码错误需哈希比较（慢）。\n2. 响应时间差异可枚举用户名，user 来自外部。\n3. 场景：{scene}，计时攻击枚举用户。\n4. 结论：CWE-204 响应差异可观察（计时），风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-204 Observable Response Discrepancy", "risk_level": "Medium",
         "source": "line 3: {func}(String user, String pass) 参数来自外部", "sink": "line 5/7: 响应时间差异",
         "explanation": "line 5 快速返回 vs line 7 哈希比较慢 -> 计时差异 -> 用户名枚举",
         "fix_suggestion": "line 5: 应改为对不存在的用户也执行一次 dummy 哈希比较，统一响应时间"},
        av(5))
    # T3: Node.js login status code (5)
    R += expand("javascript",
        "// {fname}\nfunction {func}(req, res) {{\n    const {{ user, pass }} = req.body;\n    const u = db.find(user);\n    if (!u) return res.status(404).json({{ error: 'user not found' }});  // line 6\n    if (u.password !== pass) return res.status(401).json({{ error: 'wrong password' }});  // line 7\n    res.json({{ ok: true }});\n}}\n",
        "分析过程：\n1. line 6 返回 404 'user not found'，line 7 返回 401 'wrong password'，状态码与消息均不同。\n2. 攻击者通过状态码枚举用户，user 来自外部。\n3. 场景：{scene}，用户名枚举。\n4. 结论：CWE-204 响应差异可观察，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-204 Observable Response Discrepancy", "risk_level": "Medium",
         "source": "line 3: req.body 用户可控输入", "sink": "line 6/7: 不同状态码与消息",
         "explanation": "line 6 404 vs line 7 401 -> 状态码差异 -> 用户名枚举",
         "fix_suggestion": "line 6/7: 应改为统一 res.status(401).json({ error: 'invalid credentials' })"},
        jv(5, o=2))
    # T4: Python register error (4)
    R += expand("python",
        "# {fname}\ndef {func}(email):\n    if db.exists(email):\n        return 'email already registered'  # line 4: reveals registration\n    db.create(email)\n    return 'registered'\n",
        "分析过程：\n1. line 4 返回 'email already registered' 暴露邮箱是否已注册。\n2. 攻击者枚举邮箱判断是否为用户，email 来自外部。\n3. 场景：{scene}，用户隐私泄露。\n4. 结论：CWE-204 响应差异可观察，风险 Low。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-204 Observable Response Discrepancy", "risk_level": "Low",
         "source": "line 2: {func}(email) 参数来自外部", "sink": "line 4: 'email already registered' 暴露注册状态",
         "explanation": "line 4 暴露邮箱注册状态 -> 攻击者枚举 -> 用户隐私泄露",
         "fix_suggestion": "line 4: 应改为统一返回 'registration processed' 并对已注册邮箱发送重置链接"},
        pv(4, o=2))
    # T5: Go password reset (4)
    R += expand("go",
        "// {fname}\nfunc {func}(email string) string {\n    u := db.FindUser(email)\n    if u == nil {\n        return \"user not found\"  // line 5: reveals existence\n    }\n    sendResetEmail(u)\n    return \"reset email sent\"\n}\n",
        "分析过程：\n1. line 5 返回 'user not found' 暴露邮箱是否注册。\n2. 攻击者枚举邮箱，email 来自外部，场景：{scene}。\n3. 用户隐私泄露。\n4. 结论：CWE-204 响应差异可观察，风险 Low。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-204 Observable Response Discrepancy", "risk_level": "Low",
         "source": "line 2: {func}(email string) 参数来自外部", "sink": "line 5: 'user not found' 暴露存在性",
         "explanation": "line 5 暴露用户存在性 -> 枚举邮箱 -> 隐私泄露",
         "fix_suggestion": "line 5: 应改为统一返回 'if the email exists, a reset link has been sent'"},
        gv(4, o=2))
    # T6: DC same message but different timing (4)
    R += expand("python",
        "# {fname}\nimport hashlib\ndef {func}(username, password):\n    user = db.find(username)\n    if not user:\n        hashlib.sha512(b'dummy').hexdigest()  # line 5: dummy hash to equalize\n        return 'invalid credentials'\n    if hashlib.sha512(password.encode()).hexdigest() != user.password_hash:  # line 7\n        return 'invalid credentials'\n    return 'ok'\n",
        "分析过程：\n1. line 5 对不存在用户执行 dummy 哈希，line 7 对存在用户执行真实哈希比较。\n2. 看似统一消息但 line 5 的 dummy 与 line 7 的比较耗时仍有差异。\n3. {param} 来自外部，场景：{scene}，计时差异可枚举。\n4. 结论：CWE-204 响应差异可观察（计时不充分），风险 Low。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-204 Observable Response Discrepancy", "risk_level": "Low",
         "source": "line 2: {func}(username, password) 参数来自外部", "sink": "line 5/7: dummy 与真实哈希计时差异",
         "explanation": "line 5 dummy 哈希 vs line 7 真实比较 -> 计时仍有差异 -> 用户名枚举",
         "fix_suggestion": "line 5: 应改为使用恒定时间比较 hmac.compare_digest 并预计算固定耗时哈希"},
        pv(4, o=4), dc=True)
    return R


# ===========================================================================
# 次优先 CWE 生成器
# ===========================================================================

def g_915():
    """CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes (17)"""
    R = []
    # T1: Python setattr user input (5)
    R += expand("python",
        "# {fname}\nclass User:\n    def __init__(self):\n        self.role = 'user'\ndef {func}(user, attrs):\n    for k, v in attrs.items():  # line 6\n        setattr(user, k, v)  # line 7: arbitrary attr set\n    return user\n",
        "分析过程：\n1. line 6 遍历用户提供的 attrs 字典，line 7 setattr 任意设置属性。\n2. attrs 来自外部，场景：{scene}，攻击者传入 {{'role':'admin'}} 提权。\n3. 无属性白名单导致任意属性可被修改。\n4. 结论：CWE-915 对象属性不当修改，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes", "risk_level": "High",
         "source": "line 5: {func}(user, attrs) 参数 attrs 来自外部", "sink": "line 7: setattr(user, k, v) 任意属性设置",
         "explanation": "line 6 遍历用户 attrs -> line 7 setattr 无白名单 -> 攻击者设 role=admin -> 提权",
         "fix_suggestion": "line 7: 应改为使用白名单 ALLOWED = {'name','email'} 校验 k 后再 setattr"},
        pv(5))
    # T2: JS Object.assign user attrs (4)
    R += expand("javascript",
        "// {fname}\nclass User {{\n    constructor() {{ this.role = 'user'; }}\n}}\nfunction {func}(user, attrs) {{\n    Object.assign(user, attrs);  // line 6: arbitrary attr\n    return user;\n}}\n",
        "分析过程：\n1. line 6 Object.assign 将用户提供的 attrs 合并到 user 对象。\n2. attrs 来自外部，场景：{scene}，攻击者传入 {{role:'admin'}} 提权。\n3. 无属性过滤导致任意属性可修改。\n4. 结论：CWE-915 对象属性不当修改，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes", "risk_level": "High",
         "source": "line 5: {func}(user, attrs) 参数来自外部", "sink": "line 6: Object.assign(user, attrs) 任意合并",
         "explanation": "line 6 Object.assign 无过滤 -> 攻击者设 role=admin -> 提权",
         "fix_suggestion": "line 6: 应改为先过滤 attrs 仅保留白名单属性再 assign"},
        jv(4, o=2))
    # T3: Python update dict (4)
    R += expand("python",
        "# {fname}\ndef {func}(config, updates):\n    config.update(updates)  # line 3: arbitrary key\n    return config\n",
        "分析过程：\n1. line 3 config.update 将用户提供的 updates 合并到 config。\n2. updates 来自外部，场景：{scene}，攻击者覆盖安全配置。\n3. 无键过滤导致任意配置可被修改。\n4. 结论：CWE-915 对象属性不当修改，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes", "risk_level": "High",
         "source": "line 2: {func}(config, updates) 参数来自外部", "sink": "line 3: config.update(updates) 任意键更新",
         "explanation": "line 3 update 无过滤 -> 攻击者覆盖安全配置 -> 配置篡改",
         "fix_suggestion": "line 3: 应改为 for k in updates: if k in ALLOWED: config[k] = updates[k]"},
        pv(4, o=4))
    # T4: DC filters some but not role (4)
    R += expand("python",
        "# {fname}\nBLOCKED = ['password', 'id']\ndef {func}(user, attrs):\n    for k, v in attrs.items():\n        if k in BLOCKED:  # line 5: partial blocklist\n            continue\n        setattr(user, k, v)  # line 7: role still settable\n    return user\n",
        "分析过程：\n1. line 5 仅阻止 password/id，line 7 仍可设置 role 等敏感属性。\n2. attrs 来自外部，场景：{scene}，攻击者传 role=admin 绕过。\n3. 黑名单不完整导致敏感属性可被修改。\n4. 结论：CWE-915 对象属性不当修改（防御不完整），风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes", "risk_level": "High",
         "source": "line 4: {func}(user, attrs) 参数来自外部", "sink": "line 7: setattr 黑名单不完整",
         "explanation": "line 5 黑名单缺 role -> line 7 仍可设 role=admin -> 提权",
         "fix_suggestion": "line 5: 应改为使用白名单 ALLOWED = {'name','email'} 仅允许安全属性"},
        pv(4, o=6), dc=True)
    return R


def g_208():
    """CWE-208 Observable Timing Discrepancy (12)"""
    R = []
    # T1: Python string compare secret (4)
    R += expand("python",
        "# {fname}\nSECRET = 'admin_token_12345'\ndef {func}(token):\n    if token == SECRET:  # line 4: non-constant-time\n        return True\n    return False\n",
        "分析过程：\n1. line 4 使用 == 比较密钥，非恒定时间比较。\n2. == 在首个不匹配字符即返回，攻击者计时逐字节推导。\n3. token 来自外部，场景：{scene}，计时攻击。\n4. 结论：CWE-208 计时差异可观察，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-208 Observable Timing Discrepancy", "risk_level": "Medium",
         "source": "line 3: {func}(token) 参数来自外部", "sink": "line 4: token == SECRET 非恒定时间比较",
         "explanation": "line 4 == 非恒定时间 -> 首字符不匹配即返回 -> 计时逐字节推导密钥",
         "fix_suggestion": "line 4: 应改为 hmac.compare_digest(token, SECRET) 使用恒定时间比较"},
        pv(4))
    # T2: Java String.equals (4)
    R += expand("java",
        "// {fname}\npublic class {cls} {{\n    static String SECRET = \"admin_token_12345\";\n    public static boolean {func}(String token) {{\n        return token.equals(SECRET);  // line 5: non-constant-time\n    }}\n}}\n",
        "分析过程：\n1. line 5 String.equals 非恒定时间比较，首个不匹配字符即返回。\n2. token 来自外部，场景：{scene}，计时攻击逐字节推导。\n3. 攻击者测量响应时间推导密钥。\n4. 结论：CWE-208 计时差异可观察，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-208 Observable Timing Discrepancy", "risk_level": "Medium",
         "source": "line 4: {func}(String token) 参数来自外部", "sink": "line 5: token.equals(SECRET) 非恒定时间",
         "explanation": "line 5 equals 非恒定时间 -> 计时差异 -> 逐字节推导密钥",
         "fix_suggestion": "line 5: 应改为 MessageDigest.isEqual(token.getBytes(), SECRET.getBytes()) 恒定时间比较"},
        av(4, o=2))
    # T3: JS === compare (4)
    R += expand("javascript",
        "// {fname}\nconst SECRET = 'admin_token_12345';\nfunction {func}(token) {{\n    return token === SECRET;  // line 4: non-constant-time\n}}\n",
        "分析过程：\n1. line 4 使用 === 比较密钥，非恒定时间。\n2. token 来自外部，场景：{scene}，计时攻击。\n3. 攻击者计时逐字节推导密钥。\n4. 结论：CWE-208 计时差异可观察，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-208 Observable Timing Discrepancy", "risk_level": "Medium",
         "source": "line 3: {func}(token) 参数来自外部", "sink": "line 4: token === SECRET 非恒定时间",
         "explanation": "line 4 === 非恒定时间 -> 计时差异 -> 逐字节推导",
         "fix_suggestion": "line 4: 应改为使用 crypto.timingSafeEqual(Buffer.from(token), Buffer.from(SECRET))"},
        jv(4, o=2))
    return R


def g_476():
    """CWE-476 NULL Pointer Dereference (17)"""
    R = []
    # T1: C deref without check (4)
    R += expand("c",
        "// {fname}\n#include <stdlib.h>\nchar* {func}(char* {param}) {\n    char* p = malloc(64);  // line 4\n    strcpy(p, {param});  // line 5: deref without NULL check\n    return p;\n}\n",
        "分析过程：\n1. line 4 malloc 可能返回 NULL，line 5 直接 strcpy 解引用未检查。\n2. {param} 来自外部，场景：{scene}，内存不足时 NULL 解引用。\n3. NULL 指针解引用导致程序崩溃。\n4. 结论：CWE-476 NULL 指针解引用，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-476 NULL Pointer Dereference", "risk_level": "Medium",
         "source": "line 3: {func}(char* {param}) 参数来自外部", "sink": "line 5: strcpy(p, {param}) 未检查 NULL",
         "explanation": "line 4 malloc 返回 NULL -> line 5 strcpy 解引用 NULL -> 程序崩溃",
         "fix_suggestion": "line 5: 应改为 if (!p) return NULL; 检查后再 strcpy"},
        cv(4))
    # T2: Python None deref (4)
    R += expand("python",
        "# {fname}\ndef {func}({param}):\n    obj = db.find({param})  # line 3: may return None\n    return obj.name  # line 4: deref None\n",
        "分析过程：\n1. line 3 db.find 可能返回 None，line 4 直接访问 obj.name。\n2. {param} 来自外部，场景：{scene}，None 解引用。\n3. 触发 AttributeError 程序崩溃。\n4. 结论：CWE-476 NULL 指针解引用，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-476 NULL Pointer Dereference", "risk_level": "Medium",
         "source": "line 2: {func}({param}) 参数来自外部", "sink": "line 4: obj.name 未检查 None",
         "explanation": "line 3 返回 None -> line 4 obj.name 解引用 None -> AttributeError",
         "fix_suggestion": "line 4: 应改为 if obj is None: return None; return obj.name"},
        pv(4, o=2))
    # T3: Java deref without check (5)
    R += expand("java",
        "// {fname}\npublic class {cls} {{\n    public static String {func}(String {param}) {{\n        User u = db.find({param});  // line 4: may return null\n        return u.getName();  // line 5: deref null\n    }}\n}}\n",
        "分析过程：\n1. line 4 db.find 可能返回 null，line 5 直接调用 u.getName()。\n2. {param} 来自外部，场景：{scene}，null 解引用。\n3. 触发 NullPointerException 程序崩溃。\n4. 结论：CWE-476 NULL 指针解引用，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-476 NULL Pointer Dereference", "risk_level": "Medium",
         "source": "line 3: {func}(String {param}) 参数来自外部", "sink": "line 5: u.getName() 未检查 null",
         "explanation": "line 4 返回 null -> line 5 u.getName() 解引用 null -> NullPointerException",
         "fix_suggestion": "line 5: 应改为 if (u == null) return null; return u.getName()"},
        av(5, o=2))
    # T4: DC checks but wrong var (4)
    R += expand("c",
        "// {fname}\n#include <stdlib.h>\n#include <string.h>\nchar* {func}(char* {param}) {\n    char* p = malloc(64);\n    char* q = malloc(32);\n    if (!p) return NULL;  // line 6: checks p\n    strcpy(q, {param});  // line 7: but derefs q without check\n    return q;\n}\n",
        "分析过程：\n1. line 6 检查 p 是否为 NULL，但 line 7 解引用 q 未检查。\n2. {param} 来自外部，场景：{scene}，q 为 NULL 时崩溃。\n3. 检查了错误的变量，防御无效。\n4. 结论：CWE-476 NULL 指针解引用（防御错误），风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-476 NULL Pointer Dereference", "risk_level": "Medium",
         "source": "line 3: {func}(char* {param}) 参数来自外部", "sink": "line 7: strcpy(q, {param}) 未检查 q",
         "explanation": "line 6 检查 p -> line 7 解引用 q 未检查 -> q=NULL 时崩溃 -> 防御错误变量",
         "fix_suggestion": "line 7: 应改为 if (!q) return NULL; 检查 q 后再 strcpy"},
        cv(4, o=2), dc=True)
    return R


def g_200():
    """CWE-200 Exposure of Sensitive Information to an Unauthorized Actor (17)"""
    R = []
    # T1: Python error stack trace (4)
    R += expand("python",
        "# {fname}\nfrom flask import Flask\napp = Flask(__name__)\n@app.route('/{func}')\ndef {func}():\n    try:\n        1/0\n    except Exception as e:\n        return str(e), 500  # line 7: exposes stack trace\n",
        "分析过程：\n1. line 7 将异常信息 str(e) 返回给客户端，暴露内部实现细节。\n2. 场景：{scene}，攻击者获取堆栈信息推导代码结构。\n3. 异常细节泄露文件路径、函数名等敏感信息。\n4. 结论：CWE-200 敏感信息暴露，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-200 Exposure of Sensitive Information to an Unauthorized Actor", "risk_level": "Medium",
         "source": "line 6: 异常捕获", "sink": "line 7: str(e) 返回堆栈给客户端",
         "explanation": "line 7 str(e) -> 异常细节返回客户端 -> 泄露内部实现 -> 信息收集",
         "fix_suggestion": "line 7: 应改为 return 'internal error', 500 并将详细错误记录到服务端日志"},
        pv(4))
    # T2: Java stack trace to response (4)
    R += expand("java",
        "// {fname}\nimport javax.servlet.*;\nimport javax.servlet.http.*;\nimport java.io.*;\npublic class {cls} extends HttpServlet {{\n    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {{\n        try {{\n            int x = 1/0;\n        }} catch (Exception e) {{\n            PrintWriter w = resp.getWriter();\n            e.printStackTrace(w);  // line 9: exposes stack trace\n        }}\n    }}\n}}\n",
        "分析过程：\n1. line 9 e.printStackTrace(w) 将堆栈跟踪写入 HTTP 响应。\n2. 场景：{scene}，攻击者获取完整堆栈推导代码结构。\n3. 堆栈泄露类名、行号、依赖版本等信息。\n4. 结论：CWE-200 敏感信息暴露，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-200 Exposure of Sensitive Information to an Unauthorized Actor", "risk_level": "Medium",
         "source": "line 7: 异常捕获", "sink": "line 9: e.printStackTrace(w) 暴露堆栈",
         "explanation": "line 9 printStackTrace -> 堆栈写入响应 -> 泄露类名行号 -> 信息收集",
         "fix_suggestion": "line 9: 应改为 resp.getWriter().write('internal error') 并用 logger 记录堆栈"},
        av(4, o=2))
    # T3: Python debug mode (5)
    R += expand("python",
        "# {fname}\nfrom flask import Flask\napp = Flask(__name__)\napp.config['DEBUG'] = True  # line 4: debug mode in prod\napp.run()\n",
        "分析过程：\n1. line 4 启用 DEBUG 模式，生产环境暴露 Werkzeug 调试器。\n2. 场景：{scene}，攻击者可触发错误获取交互式调试控制台。\n3. 调试控制台允许执行任意 Python 代码。\n4. 结论：CWE-200 敏感信息暴露（DEBUG 模式），风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-200 Exposure of Sensitive Information to an Unauthorized Actor", "risk_level": "Critical",
         "source": "line 4: app.config['DEBUG'] = True", "sink": "line 4: DEBUG 模式暴露调试器",
         "explanation": "line 4 DEBUG=True -> Werkzeug 调试器暴露 -> 攻击者获取交互式控制台 -> RCE",
         "fix_suggestion": "line 4: 应改为 app.config['DEBUG'] = False 生产环境禁用调试模式"},
        pv(5, o=2))
    # T4: DC custom error but leaks version (4)
    R += expand("python",
        "# {fname}\nfrom flask import Flask\napp = Flask(__name__)\n@app.route('/{func}')\ndef {func}():\n    try:\n        db.query()\n    except Exception:\n        return 'DB error: PostgreSQL 12.3 on port 5432', 500  # line 7: leaks version\n",
        "分析过程：\n1. line 7 自定义错误消息但仍泄露数据库类型与版本。\n2. 场景：{scene}，攻击者针对 PostgreSQL 12.3 查找已知漏洞。\n3. 版本信息帮助攻击者选择攻击载荷。\n4. 结论：CWE-200 敏感信息暴露（版本泄露），风险 Low。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-200 Exposure of Sensitive Information to an Unauthorized Actor", "risk_level": "Low",
         "source": "line 6: 异常捕获", "sink": "line 7: 错误消息泄露数据库版本",
         "explanation": "line 7 自定义错误含版本 -> 攻击者针对版本查漏洞 -> 信息泄露",
         "fix_suggestion": "line 7: 应改为 return 'internal error', 500 不泄露任何技术细节"},
        pv(4, o=4), dc=True)
    return R


def g_73():
    """CWE-73 External Control of File Name or Path (15)"""
    R = []
    # T1: Python open user path (4)
    R += expand("python",
        "# {fname}\ndef {func}({param}):\n    with open('/var/data/' + {param}, 'r') as f:  # line 3: path concat\n        return f.read()\n",
        "分析过程：\n1. line 3 将 {param} 拼接到文件路径，未过滤 ../。\n2. {param} 来自外部，场景：{scene}，攻击者传入 ../../etc/passwd 读取任意文件。\n3. 路径遍历导致敏感文件泄露。\n4. 结论：CWE-73 外部控制文件路径，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-73 External Control of File Name or Path", "risk_level": "High",
         "source": "line 2: {func}({param}) 参数来自外部", "sink": "line 3: open('/var/data/' + {param}) 路径拼接",
         "explanation": "line 3 路径拼接 -> ../ 未过滤 -> 攻击者读取任意文件 -> 路径遍历",
         "fix_suggestion": "line 3: 应改为 path = os.path.realpath('/var/data/' + {param}); if not path.startswith('/var/data/'): raise"},
        pv(4))
    # T2: Java FileInputStream user path (4)
    R += expand("java",
        "// {fname}\nimport java.io.*;\npublic class {cls} {{\n    public static String {func}(String {param}) throws Exception {{\n        File f = new File(\"/var/data/\" + {param});  // line 5\n        FileInputStream fis = new FileInputStream(f);\n        byte[] buf = new byte[1024];\n        fis.read(buf);\n        return new String(buf);\n    }}\n}}\n",
        "分析过程：\n1. line 5 将 {param} 拼接到文件路径，未过滤 ../。\n2. {param} 来自外部，场景：{scene}，攻击者传入 ../../etc/passwd。\n3. 路径遍历导致任意文件读取。\n4. 结论：CWE-73 外部控制文件路径，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-73 External Control of File Name or Path", "risk_level": "High",
         "source": "line 4: {func}(String {param}) 参数来自外部", "sink": "line 5: new File(\"/var/data/\" + {param}) 路径拼接",
         "explanation": "line 5 路径拼接 -> ../ 未过滤 -> 任意文件读取 -> 路径遍历",
         "fix_suggestion": "line 5: 应改为 Path resolved = Paths.get(\"/var/data/\").resolve({param}).normalize().toAbsolutePath(); 校验是否在 base 目录内"},
        av(4, o=2))
    # T3: Node.js fs.readFile user path (4)
    R += expand("javascript",
        "// {fname}\nconst fs = require('fs');\nconst path = require('path');\nfunction {func}({param}) {{\n    const filePath = path.join('/var/data/', {param});  // line 5\n    return fs.readFileSync(filePath, 'utf8');\n}}\n",
        "分析过程：\n1. line 5 path.join 将 {param} 拼接到路径，path.join 会规范化但仍允许 ../。\n2. {param} 来自外部，场景：{scene}，攻击者传入 ../../etc/passwd。\n3. 路径遍历导致任意文件读取。\n4. 结论：CWE-73 外部控制文件路径，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-73 External Control of File Name or Path", "risk_level": "High",
         "source": "line 4: {func}({param}) 参数来自外部", "sink": "line 5: path.join('/var/data/', {param}) 路径拼接",
         "explanation": "line 5 path.join -> ../ 规范化但仍允许 -> 任意文件读取 -> 路径遍历",
         "fix_suggestion": "line 5: 应改为 resolved = path.resolve('/var/data/', {param}); if (!resolved.startsWith('/var/data/')) throw"},
        jv(4, o=2))
    # T4: DC checks . but not .. (3)
    R += expand("python",
        "# {fname}\nimport os\ndef {func}({param}):\n    if '.' in {param}:  # line 3: only checks single dot\n        return 'invalid'\n    with open('/var/data/' + {param}, 'r') as f:  # line 5: .. bypasses\n        return f.read()\n",
        "分析过程：\n1. line 3 检查是否含 '.'，但 '..' 含 '.' 应被阻止，但若用 '..%2f' 编码可绕过。\n2. 实际 line 3 的 '.' 检查会阻止 '..'，但攻击者可传 URL 编码绕过部分场景。\n3. 场景：{scene}，{param} 来自外部，黑名单不完整。\n4. 结论：CWE-73 外部控制文件路径（黑名单不充分），风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-73 External Control of File Name or Path", "risk_level": "High",
         "source": "line 2: {func}({param}) 参数来自外部", "sink": "line 5: open 路径拼接黑名单不充分",
         "explanation": "line 3 '.' 检查 -> 编码绕过 -> line 5 路径遍历 -> 黑名单不充分",
         "fix_suggestion": "line 3: 应改为使用 os.path.realpath + startswith 白名单校验，不依赖字符黑名单"},
        pv(3, o=4), dc=True)
    return R


def g_98():
    """CWE-98 Improper Control of Filename for Include/Require Statement (16)"""
    R = []
    # T1: PHP include user input (4)
    R += expand("php",
        "<?php\n// {fname}\nfunction {func}(${param}) {\n    include(${param});  // line 4: file inclusion\n}\n?>",
        "分析过程：\n1. line 4 include 直接包含用户提供的 {param}，无过滤。\n2. {param} 来自外部，场景：{scene}，LFI/RFI 攻击。\n3. 攻击者包含 /etc/passwd 或远程恶意文件执行代码。\n4. 结论：CWE-98 文件包含漏洞，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-98 Improper Control of Filename for Include/Require Statement", "risk_level": "Critical",
         "source": "line 3: {func}(${param}) 参数来自外部", "sink": "line 4: include(${param}) 文件包含",
         "explanation": "line 4 include 用户输入 -> 无过滤 -> LFI/RFI -> 任意代码执行",
         "fix_suggestion": "line 4: 应改为使用白名单 ALLOWED = ['header.php','footer.php'] 校验后再 include"},
        hv(4))
    # T2: Python exec user file (4)
    R += expand("python",
        "# {fname}\ndef {func}({param}):\n    with open({param}) as f:\n        exec(f.read())  # line 4: exec included code\n",
        "分析过程：\n1. line 4 exec 执行用户指定文件的内容，{param} 来自外部。\n2. 场景：{scene}，攻击者指定恶意文件路径执行任意代码。\n3. 等价于文件包含漏洞。\n4. 结论：CWE-98 文件包含漏洞，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-98 Improper Control of Filename for Include/Require Statement", "risk_level": "Critical",
         "source": "line 2: {func}({param}) 参数来自外部", "sink": "line 4: exec(f.read()) 执行包含文件",
         "explanation": "line 4 exec 文件内容 -> 用户控制路径 -> 任意代码执行",
         "fix_suggestion": "line 4: 应改为禁止 exec 加载的文件内容，使用白名单模块导入"},
        pv(4, o=2))
    # T3: Node.js require user path (4)
    R += expand("javascript",
        "// {fname}\nfunction {func}({param}) {{\n    const mod = require('./plugins/' + {param});  // line 3: require user path\n    return mod;\n}}\n",
        "分析过程：\n1. line 3 require 将 {param} 拼接到路径加载模块。\n2. {param} 来自外部，场景：{scene}，攻击者加载任意 JS 文件执行。\n3. require 会执行加载的文件代码。\n4. 结论：CWE-98 文件包含漏洞，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-98 Improper Control of Filename for Include/Require Statement", "risk_level": "Critical",
         "source": "line 2: {func}({param}) 参数来自外部", "sink": "line 3: require('./plugins/' + {param}) 文件包含",
         "explanation": "line 3 require 用户路径 -> 加载执行任意 JS -> 代码执行",
         "fix_suggestion": "line 3: 应改为使用白名单 const ALLOWED = ['a','b']; if (!ALLOWED.includes({param})) throw"},
        jv(4, o=2))
    # T4: DC filters .. but not absolute path (4)
    R += expand("php",
        "<?php\n// {fname}\nfunction {func}(${param}) {\n    if (strpos(${param}, '..') !== false) {  // line 4: blocks ..\n        return 'invalid';\n    }\n    include(${param});  // line 7: but absolute path bypasses\n}\n?>",
        "分析过程：\n1. line 4 检查 .. 但 line 7 include 仍接受绝对路径。\n2. {param} 来自外部，场景：{scene}，攻击者传 /etc/passwd 或 /tmp/malicious.php。\n3. 黑名单只阻止相对遍历，绝对路径不受限。\n4. 结论：CWE-98 文件包含漏洞（防御不完整），风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-98 Improper Control of Filename for Include/Require Statement", "risk_level": "Critical",
         "source": "line 3: {func}(${param}) 参数来自外部", "sink": "line 7: include(${param}) 绝对路径绕过",
         "explanation": "line 4 只阻止 .. -> line 7 绝对路径绕过 -> include 任意文件 -> RCE",
         "fix_suggestion": "line 4: 应改为使用白名单 in_array(${param}, ALLOWED) 校验后再 include"},
        hv(4, o=2), dc=True)
    return R


def g_409():
    """CWE-409 Improper Handling of Highly Compressed Data (17)"""
    R = []
    # T1: Python zipfile bomb (5)
    R += expand("python",
        "# {fname}\nimport zipfile\ndef {func}({param}):\n    with zipfile.ZipFile({param}) as z:  # line 4\n        z.extractall('/tmp/')  # line 5: no size check\n",
        "分析过程：\n1. line 4 打开用户提供的 zip，line 5 extractall 解压无大小检查。\n2. {param} 来自外部，场景：{scene}，zip bomb 攻击。\n3. 小 zip 解压后产生超大文件导致磁盘耗尽。\n4. 结论：CWE-409 解压炸弹，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-409 Improper Handling of Highly Compressed Data", "risk_level": "Medium",
         "source": "line 3: {func}({param}) 参数来自外部", "sink": "line 5: z.extractall 无大小检查",
         "explanation": "line 5 extractall -> zip bomb 解压 -> 超大文件 -> 磁盘耗尽",
         "fix_suggestion": "line 5: 应改为遍历 z.infolist() 检查 file_size 总和上限后再解压"},
        pv(5))
    # T2: Python gzip bomb (4)
    R += expand("python",
        "# {fname}\nimport gzip\ndef {func}({param}):\n    with gzip.open({param}, 'rb') as f:  # line 4\n        data = f.read()  # line 5: reads all into memory\n    return data\n",
        "分析过程：\n1. line 4 打开用户提供的 gzip，line 5 read() 全部读入内存。\n2. {param} 来自外部，场景：{scene}，gzip bomb 攻击。\n3. 小 gzip 解压后超大导致 OOM。\n4. 结论：CWE-409 解压炸弹，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-409 Improper Handling of Highly Compressed Data", "risk_level": "Medium",
         "source": "line 3: {func}({param}) 参数来自外部", "sink": "line 5: f.read() 全部读入内存",
         "explanation": "line 5 read() -> gzip bomb -> 解压后超大 -> OOM",
         "fix_suggestion": "line 5: 应改为分块读取并检查累计大小上限 while chunk := f.read(8192): total += len(chunk); if total > MAX: break"},
        pv(4, o=2))
    # T3: Java GZIPInputStream (4)
    R += expand("java",
        "// {fname}\nimport java.util.zip.*;\nimport java.io.*;\npublic class {cls} {{\n    public static byte[] {func}(String {param}) throws Exception {{\n        GZIPInputStream gz = new GZIPInputStream(new FileInputStream({param}));  // line 6\n        ByteArrayOutputStream out = new ByteArrayOutputStream();\n        byte[] buf = new byte[1024];\n        int n;\n        while ((n = gz.read(buf)) != -1) out.write(buf, 0, n);  // line 9: no size limit\n        return out.toByteArray();\n    }}\n}}\n",
        "分析过程：\n1. line 6 创建 GZIPInputStream，line 9 循环读取无大小限制。\n2. {param} 来自外部，场景：{scene}，gzip bomb 导致 OOM。\n3. 解压后数据全部写入 ByteArrayOutputStream。\n4. 结论：CWE-409 解压炸弹，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-409 Improper Handling of Highly Compressed Data", "risk_level": "Medium",
         "source": "line 5: {func}(String {param}) 参数来自外部", "sink": "line 9: out.write 无大小限制",
         "explanation": "line 9 无限制写入 -> gzip bomb -> 解压后超大 -> OOM",
         "fix_suggestion": "line 9: 应改为 if (out.size() > MAX_SIZE) throw new IOException('too large')"},
        av(4, o=2))
    # T4: DC checks file size but not decompressed (4)
    R += expand("python",
        "# {fname}\nimport zipfile, os\ndef {func}({param}):\n    if os.path.getsize({param}) > 1024 * 1024:  # line 4: checks compressed size\n        return 'too large'\n    with zipfile.ZipFile({param}) as z:\n        z.extractall('/tmp/')  # line 7: but decompressed size unbounded\n",
        "分析过程：\n1. line 4 检查压缩文件大小，但 line 7 解压后大小未检查。\n2. {param} 来自外部，场景：{scene}，小压缩文件解压后仍可超大。\n3. 压缩比可达 1000:1，1MB 压缩解压后 1GB。\n4. 结论：CWE-409 解压炸弹（防御不完整），风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-409 Improper Handling of Highly Compressed Data", "risk_level": "Medium",
         "source": "line 3: {func}({param}) 参数来自外部", "sink": "line 7: extractall 未检查解压后大小",
         "explanation": "line 4 只检查压缩大小 -> line 7 解压后超大 -> zip bomb -> 防御不完整",
         "fix_suggestion": "line 7: 应改为遍历 infolist 检查 file_size 总和上限后再解压"},
        pv(4, o=4), dc=True)
    return R


def g_917():
    """CWE-917 Expression Language Injection (18)"""
    R = []
    # T1: Python eval user input (5)
    R += expand("python",
        "# {fname}\ndef {func}({param}):\n    return eval({param})  # line 3: eval injection\n",
        "分析过程：\n1. line 3 eval 直接执行用户提供的表达式，{param} 来自外部。\n2. 场景：{scene}，攻击者传入 __import__('os').system('id') 执行任意命令。\n3. eval 允许任意 Python 表达式执行。\n4. 结论：CWE-917 表达式注入，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement", "risk_level": "Critical",
         "source": "line 2: {func}({param}) 参数来自外部", "sink": "line 3: eval({param}) 表达式执行",
         "explanation": "line 3 eval 用户输入 -> 任意表达式执行 -> __import__ RCE -> 代码执行",
         "fix_suggestion": "line 3: 应改为使用 ast.literal_eval({param}) 仅支持字面量，或禁止 eval"},
        pv(5))
    # T2: Java SpEL injection (5)
    R += expand("java",
        "// {fname}\nimport org.springframework.expression.*;\nimport org.springframework.expression.spel.standard.*;\npublic class {cls} {{\n    public static Object {func}(String {param}) {{\n        ExpressionParser parser = new SpelExpressionParser();\n        Expression exp = parser.parseExpression({param});  // line 7\n        return exp.getValue();\n    }}\n}}\n",
        "分析过程：\n1. line 7 SpelExpressionParser 解析用户提供的表达式并执行。\n2. {param} 来自外部，场景：{scene}，攻击者传入 T(java.lang.Runtime).getRuntime().exec('id')。\n3. SpEL 注入允许执行任意 Java 代码。\n4. 结论：CWE-917 表达式注入，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement", "risk_level": "Critical",
         "source": "line 6: {func}(String {param}) 参数来自外部", "sink": "line 7: parser.parseExpression({param}) SpEL 执行",
         "explanation": "line 7 SpEL 解析用户输入 -> T(Runtime).exec -> 任意命令执行",
         "fix_suggestion": "line 7: 应改为使用 SimpleEvaluationContext 限制 SpEL 能力，禁止类型引用与方法调用"},
        av(5, o=2))
    # T3: JS eval user input (4)
    R += expand("javascript",
        "// {fname}\nfunction {func}({param}) {{\n    return eval({param});  // line 3: eval injection\n}}\n",
        "分析过程：\n1. line 3 eval 执行用户提供的表达式，{param} 来自外部。\n2. 场景：{scene}，攻击者传入 require('child_process').execSync('id')。\n3. eval 允许任意 JS 代码执行。\n4. 结论：CWE-917 表达式注入，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement", "risk_level": "Critical",
         "source": "line 2: {func}({param}) 参数来自外部", "sink": "line 3: eval({param}) 表达式执行",
         "explanation": "line 3 eval 用户输入 -> 任意 JS 执行 -> require RCE -> 代码执行",
         "fix_suggestion": "line 3: 应改为使用 JSON.parse({param}) 或 Function 构造器受限执行"},
        jv(4, o=2))
    # T4: DC uses literal_eval but falls back (4)
    R += expand("python",
        "# {fname}\nimport ast\ndef {func}({param}):\n    try:\n        return ast.literal_eval({param})  # line 4: safe\n    except (ValueError, SyntaxError):\n        return eval({param})  # line 6: unsafe fallback\n",
        "分析过程：\n1. line 4 使用 ast.literal_eval 限制字面量，但 line 6 异常时回退到 eval。\n2. {param} 来自外部，场景：{scene}，攻击者构造非常量表达式触发异常后 eval 执行。\n3. 回退到 eval 完全绕过防护。\n4. 结论：CWE-917 表达式注入（回退绕过），风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement", "risk_level": "Critical",
         "source": "line 2: {func}({param}) 参数来自外部", "sink": "line 6: eval({param}) 不安全回退",
         "explanation": "line 4 literal_eval -> line 6 异常回退 eval -> 攻击者触发异常 -> RCE",
         "fix_suggestion": "line 6: 应改为 return None 异常时返回 None，不回退到 eval"},
        pv(4, o=4), dc=True)
    return R


def g_123():
    """CWE-123 Write-what-where Condition (18)"""
    R = []
    # T1: C arbitrary write via index (5)
    R += expand("c",
        "// {fname}\n#include <stdlib.h>\nint* buf = NULL;\nint buf_size = 0;\nvoid {func}(int idx, int val) {\n    if (!buf) { buf = malloc(1024); buf_size = 1024; }\n    buf[idx] = val;  // line 7: no bounds check\n}\n",
        "分析过程：\n1. line 7 buf[idx] = val 无边界检查，idx 来自外部可负可超大。\n2. 场景：{scene}，攻击者传入任意 idx 写任意内存地址。\n3. 写任意内存可覆盖函数指针等实现代码执行。\n4. 结论：CWE-123 任意写，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-123 Write-what-where Condition", "risk_level": "Critical",
         "source": "line 5: {func}(idx, val) 参数 idx 来自外部", "sink": "line 7: buf[idx] = val 无边界检查",
         "explanation": "line 7 无边界检查 -> 任意 idx 写任意地址 -> 覆盖函数指针 -> RCE",
         "fix_suggestion": "line 7: 应改为 if (idx < 0 || idx >= buf_size) return; 检查边界后再写"},
        cv(5))
    # T2: C memcpy user offset (5)
    R += expand("c",
        "// {fname}\n#include <string.h>\n#include <stdlib.h>\nchar* buf;\nvoid {func}(int offset, char* data, int len) {\n    memcpy(buf + offset, data, len);  // line 6: arbitrary write\n}\n",
        "分析过程：\n1. line 6 memcpy(buf + offset, data, len) offset 来自外部，无边界检查。\n2. 场景：{scene}，攻击者控制 offset 写任意内存位置。\n3. 任意地址写入实现代码执行。\n4. 结论：CWE-123 任意写，风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-123 Write-what-where Condition", "risk_level": "Critical",
         "source": "line 5: {func}(offset, data, len) 参数 offset 来自外部", "sink": "line 6: memcpy(buf + offset, data, len) 任意写",
         "explanation": "line 6 用户控制 offset -> buf+offset 任意地址 -> memcpy 写入 -> RCE",
         "fix_suggestion": "line 6: 应改为 if (offset < 0 || offset + len > BUF_SIZE) return; 检查边界"},
        cv(5, o=2))
    # T3: C++ array user index (4)
    R += expand("cpp",
        "// {fname}\nint arr[256];\nvoid {func}(int idx, int val) {\n    arr[idx] = val;  // line 4: no bounds check\n}\n",
        "分析过程：\n1. line 4 arr[idx] = val 无边界检查，idx 来自外部。\n2. 场景：{scene}，越界写覆盖相邻内存。\n3. 负 idx 或超大 idx 实现任意内存写。\n4. 结论：CWE-123 任意写，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-123 Write-what-where Condition", "risk_level": "High",
         "source": "line 3: {func}(idx, val) 参数 idx 来自外部", "sink": "line 4: arr[idx] = val 无边界检查",
         "explanation": "line 4 无边界检查 -> 越界写 -> 覆盖相邻内存 -> 任意写",
         "fix_suggestion": "line 4: 应改为 if (idx >= 0 && idx < 256) arr[idx] = val; 检查边界"},
        cv(4, o=2))
    # T4: DC checks upper but not lower (4)
    R += expand("c",
        "// {fname}\n#include <stdlib.h>\nint* buf;\nint buf_size = 1024;\nvoid {func}(int idx, int val) {\n    if (idx < buf_size)  // line 6: only checks upper bound\n        buf[idx] = val;  // line 7: negative idx bypasses\n}\n",
        "分析过程：\n1. line 6 只检查 idx < buf_size，未检查 idx >= 0。\n2. 负 idx 绕过检查，line 7 写入 buf 之前的内存，{param} 来自外部。\n3. 场景：{scene}，负索引实现向前任意写。\n4. 结论：CWE-123 任意写（边界检查不完整），风险 Critical。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-123 Write-what-where Condition", "risk_level": "Critical",
         "source": "line 5: {func}(idx, val) 参数 idx 来自外部", "sink": "line 7: buf[idx] = val 负索引绕过",
         "explanation": "line 6 只检查上界 -> 负 idx 绕过 -> line 7 向前写 -> 任意写",
         "fix_suggestion": "line 6: 应改为 if (idx >= 0 && idx < buf_size) 检查上下界"},
        cv(4, o=4), dc=True)
    return R


def g_613():
    """CWE-613 Insufficient Session Expiration (14)"""
    R = []
    # T1: Python session no expiry (4)
    R += expand("python",
        "# {fname}\nfrom flask import Flask, session\napp = Flask(__name__)\napp.secret_key = 'key'\n@app.route('/{func}')\ndef {func}():\n    session['user'] = 'admin'  # line 7: no expiry set\n    return 'logged in'\n",
        "分析过程：\n1. line 7 设置 session['user'] 但未设置过期时间。\n2. 场景：{scene}，session 永不过期，泄露后攻击者永久使用。\n3. 无过期机制导致会话劫持风险。\n4. 结论：CWE-613 会话过期不足，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-613 Insufficient Session Expiration", "risk_level": "Medium",
         "source": "line 7: session['user'] = 'admin'", "sink": "line 7: 无过期时间设置",
         "explanation": "line 7 session 无 expiry -> 永不过期 -> 泄露后永久劫持",
         "fix_suggestion": "line 7: 应改为 app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1) 设置过期"},
        pv(4))
    # T2: Java session long timeout (5)
    R += expand("java",
        "// {fname}\nimport javax.servlet.*;\nimport javax.servlet.http.*;\npublic class {cls} extends HttpServlet {{\n    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {{\n        HttpSession s = req.getSession();\n        s.setMaxInactiveInterval(60 * 60 * 24 * 365);  // line 6: 1 year\n        s.setAttribute(\"user\", \"admin\");\n    }}\n}}\n",
        "分析过程：\n1. line 6 setMaxInactiveInterval 设为 1 年，会话几乎永不过期。\n2. 场景：{scene}，session 泄露后攻击者长期使用。\n3. 过长过期时间无法有效防御会话劫持。\n4. 结论：CWE-613 会话过期不足，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-613 Insufficient Session Expiration", "risk_level": "Medium",
         "source": "line 5: req.getSession()", "sink": "line 6: setMaxInactiveInterval(1 年)",
         "explanation": "line 6 1 年过期 -> 会话长期有效 -> 泄露后长期劫持",
         "fix_suggestion": "line 6: 应改为 setMaxInactiveInterval(30 * 60) 设置 30 分钟过期"},
        av(5, o=2))
    # T3: Node.js JWT no expiry (3)
    R += expand("javascript",
        "// {fname}\nconst jwt = require('jsonwebtoken');\nfunction {func}(userId) {{\n    return jwt.sign({{ userId }}, 'secret');  // line 4: no expiresIn\n}}\n",
        "分析过程：\n1. line 4 jwt.sign 未设置 expiresIn，token 永不过期。\n2. 场景：{scene}，token 泄露后攻击者永久使用。\n3. 无过期机制无法失效已泄露 token。\n4. 结论：CWE-613 会话过期不足，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-613 Insufficient Session Expiration", "risk_level": "Medium",
         "source": "line 3: {func}(userId) 参数来自外部", "sink": "line 4: jwt.sign 无 expiresIn",
         "explanation": "line 4 无 expiresIn -> token 永不过期 -> 泄露后永久使用",
         "fix_suggestion": "line 4: 应改为 jwt.sign({ userId }, 'secret', { expiresIn: '1h' })"},
        jv(3, o=2))
    # T4: DC has expiry but on client (2)
    R += expand("python",
        "# {fname}\nfrom flask import Flask, request\napp = Flask(__name__)\n@app.route('/{func}')\ndef {func}():\n    expiry = request.args.get('expiry', '3600')  # line 5: client-controlled\n    return f'session expires in {expiry}s'\n",
        "分析过程：\n1. line 5 从请求参数获取 expiry，过期时间由客户端控制。\n2. 场景：{scene}，攻击者传入超大 expiry 使会话永不过期。\n3. 客户端控制过期时间无效。\n4. 结论：CWE-613 会话过期不足（客户端控制），风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-613 Insufficient Session Expiration", "risk_level": "Medium",
         "source": "line 5: request.args.get('expiry') 客户端可控", "sink": "line 5: expiry 由客户端控制",
         "explanation": "line 5 客户端控制 expiry -> 攻击者设超大值 -> 会话永不过期",
         "fix_suggestion": "line 5: 应改为服务端固定过期时间，不读取客户端参数"},
        pv(2, o=4), dc=True)
    return R


def g_122():
    """CWE-122 Heap-based Buffer Overflow (5)"""
    R = []
    # T1: C heap overflow strcpy (3)
    R += expand("c",
        "// {fname}\n#include <stdlib.h>\n#include <string.h>\nchar* {func}(char* {param}) {\n    char* buf = malloc(16);  // line 5\n    strcpy(buf, {param});  // line 6: heap overflow\n    return buf;\n}\n",
        "分析过程：\n1. line 5 malloc(16) 分配 16 字节，line 6 strcpy 复制 {param} 无长度限制。\n2. {param} 来自外部，场景：{scene}，超过 16 字节导致堆溢出。\n3. 堆溢出可覆盖相邻堆元数据实现代码执行。\n4. 结论：CWE-122 堆缓冲区溢出，风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-122 Heap-based Buffer Overflow", "risk_level": "High",
         "source": "line 4: {func}(char* {param}) 参数来自外部", "sink": "line 6: strcpy(buf, {param}) 堆溢出",
         "explanation": "line 5 malloc(16) -> line 6 strcpy 无长度限制 -> 堆溢出 -> 代码执行",
         "fix_suggestion": "line 6: 应改为 strncpy(buf, {param}, 15); buf[15] = '\\0'; 限制复制长度"},
        cv(3))
    # T2: DC checks length but off-by-one (2)
    R += expand("c",
        "// {fname}\n#include <stdlib.h>\n#include <string.h>\nchar* {func}(char* {param}) {\n    char* buf = malloc(16);\n    if (strlen({param}) <= 16)  // line 6: should be < 16\n        strcpy(buf, {param});  // line 7: off-by-one overflow\n    return buf;\n}\n",
        "分析过程：\n1. line 6 检查 strlen <= 16，但 line 7 strcpy 会写入 16 字节 + '\\0' 共 17 字节。\n2. off-by-one 溢出覆盖下一个堆块 size 字段，{param} 来自外部。\n3. 场景：{scene}，off-by-one 堆溢出可被利用。\n4. 结论：CWE-122 堆缓冲区溢出（off-by-one），风险 High。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-122 Heap-based Buffer Overflow", "risk_level": "High",
         "source": "line 4: {func}(char* {param}) 参数来自外部", "sink": "line 7: strcpy off-by-one 溢出",
         "explanation": "line 6 <= 16 -> line 7 写入 17 字节 -> off-by-one -> 堆元数据破坏",
         "fix_suggestion": "line 6: 应改为 if (strlen({param}) < 16) 严格小于 16"},
        cv(2, o=2), dc=True)
    return R


def g_362():
    """CWE-362 Race Condition (8)"""
    R = []
    # T1: Python TOCTOU check then use (3)
    R += expand("python",
        "# {fname}\nimport os\ndef {func}({param}):\n    if os.path.exists({param}):  # line 4: check\n        with open({param}, 'r') as f:  # line 5: use\n            return f.read()\n",
        "分析过程：\n1. line 4 检查文件存在，line 5 打开文件，之间存在 TOCTOU 窗口。\n2. {param} 来自外部，场景：{scene}，攻击者在检查后替换文件为符号链接。\n3. 竞态条件导致读取非预期文件。\n4. 结论：CWE-362 竞态条件，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-362 Race Condition", "risk_level": "Medium",
         "source": "line 3: {func}({param}) 参数来自外部", "sink": "line 5: open TOCTOU 窗口",
         "explanation": "line 4 exists 检查 -> line 5 open 使用 -> 中间窗口可替换文件 -> 竞态",
         "fix_suggestion": "line 5: 应改为使用 os.open + fstat 检查文件而非 exists，或 try/except 直接 open"},
        pv(3))
    # T2: C check then write (3)
    R += expand("c",
        "// {fname}\n#include <unistd.h>\n#include <fcntl.h>\nvoid {func}(char* {param}) {\n    if (access({param}, W_OK) == 0) {  // line 5: check\n        int fd = open({param}, O_WRONLY);  // line 6: use\n        write(fd, \"data\", 4);\n        close(fd);\n    }\n}\n",
        "分析过程：\n1. line 5 access 检查权限，line 6 open 打开文件，TOCTOU 窗口。\n2. {param} 来自外部，场景：{scene}，攻击者在检查后替换文件。\n3. 竞态条件导致写入非预期文件。\n4. 结论：CWE-362 竞态条件，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-362 Race Condition", "risk_level": "Medium",
         "source": "line 4: {func}(char* {param}) 参数来自外部", "sink": "line 6: open TOCTOU 窗口",
         "explanation": "line 5 access 检查 -> line 6 open 使用 -> 中间窗口可替换 -> 竞态",
         "fix_suggestion": "line 6: 应改为直接 open 并检查 errno，或使用 fstat 在 fd 上检查权限"},
        cv(3, o=2))
    # T3: DC uses lock but wrong scope (2)
    R += expand("python",
        "# {fname}\nimport os\ndef {func}({param}):\n    if os.path.exists({param}):\n        # no lock between check and use\n        with open({param}, 'r') as f:\n            return f.read()\n",
        "分析过程：\n1. exists 检查与 open 使用之间无锁保护，TOCTOU 窗口。\n2. {param} 来自外部，场景：{scene}，攻击者替换文件。\n3. 缺少原子操作或锁导致竞态。\n4. 结论：CWE-362 竞态条件（无锁），风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-362 Race Condition", "risk_level": "Medium",
         "source": "line 3: {func}({param}) 参数来自外部", "sink": "line 5: open 无锁 TOCTOU",
         "explanation": "exists 与 open 之间无锁 -> 攻击者替换文件 -> 竞态条件",
         "fix_suggestion": "line 4: 应改为使用 os.open + os.fstat 原子操作，或 try/except 直接 open"},
        pv(2, o=4), dc=True)
    return R


def g_1333():
    """CWE-1333 Inefficient Regular Expression (8)"""
    R = []
    # T1: Python catastrophic backtracking (3)
    R += expand("python",
        "# {fname}\nimport re\ndef {func}({param}):\n    pattern = re.compile(r'(a+)+b')  # line 4\n    return bool(pattern.match({param}))  # line 5\n",
        "分析过程：\n1. line 4 正则 (a+)+b 存在灾难性回溯，line 5 匹配用户输入。\n2. {param} 来自外部，场景：{scene}，'a'*30 触发指数级回溯。\n3. ReDoS 攻击导致 CPU 耗尽。\n4. 结论：CWE-1333 低效正则，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-1333 Inefficient Regular Expression", "risk_level": "Medium",
         "source": "line 3: {func}({param}) 参数来自外部", "sink": "line 5: pattern.match 灾难性回溯",
         "explanation": "line 4 (a+)+b -> line 5 长字符串 -> 指数级回溯 -> CPU 耗尽",
         "fix_suggestion": "line 4: 应改为 r'a+b' 移除嵌套量词，或设置匹配超时"},
        pv(3))
    # T2: JS regex DoS (3)
    R += expand("javascript",
        "// {fname}\nfunction {func}({param}) {{\n    const re = /(a+)+b/;  // line 3\n    return re.test({param});  // line 4\n}}\n",
        "分析过程：\n1. line 3 正则 (a+)+b 灾难性回溯，line 4 test 匹配用户输入。\n2. {param} 来自外部，场景：{scene}，长字符串触发 ReDoS。\n3. 事件循环阻塞导致服务不可用。\n4. 结论：CWE-1333 低效正则，风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-1333 Inefficient Regular Expression", "risk_level": "Medium",
         "source": "line 2: {func}({param}) 参数来自外部", "sink": "line 4: re.test 灾难性回溯",
         "explanation": "line 3 (a+)+b -> line 4 长字符串 -> 指数级回溯 -> 事件循环阻塞",
         "fix_suggestion": "line 3: 应改为 /a+b/ 移除嵌套量词"},
        jv(3, o=2))
    # T3: DC uses timeout but JS regex no timeout (2)
    R += expand("javascript",
        "// {fname}\nfunction {func}({param}) {{\n    const re = new RegExp('(a+)+b');  // line 3: dynamic regex\n    return re.test({param});  // line 4: no timeout in JS\n}}\n",
        "分析过程：\n1. line 3 动态构造正则 (a+)+b，line 4 test 无超时保护。\n2. {param} 来自外部，场景：{scene}，JS RegExp 无原生超时机制。\n3. ReDoS 攻击阻塞事件循环。\n4. 结论：CWE-1333 低效正则（无超时），风险 Medium。",
        {"has_vulnerability": True, "vulnerability_type": "CWE-1333 Inefficient Regular Expression", "risk_level": "Medium",
         "source": "line 2: {func}({param}) 参数来自外部", "sink": "line 4: re.test 无超时",
         "explanation": "line 3 动态正则 -> line 4 无超时 -> ReDoS 阻塞 -> 服务不可用",
         "fix_suggestion": "line 3: 应改为使用安全正则 /a+b/，或在 worker 线程执行设超时"},
        jv(2, o=4), dc=True)
    return R


# ===========================================================================
# CWE 编号 -> 生成器映射
# ===========================================================================
GENERATORS = {
    # 最优先 (18)
    "CWE-295": g_295, "CWE-329": g_329, "CWE-843": g_843, "CWE-347": g_347,
    "CWE-1321": g_1321, "CWE-287": g_287, "CWE-113": g_113, "CWE-319": g_319,
    "CWE-400": g_400, "CWE-532": g_532, "CWE-770": g_770, "CWE-91": g_91,
    "CWE-610": g_610, "CWE-797": g_797, "CWE-93": g_93, "CWE-759": g_759,
    "CWE-401": g_401, "CWE-204": g_204,
    # 次优先 (13)
    "CWE-915": g_915, "CWE-208": g_208, "CWE-476": g_476, "CWE-200": g_200,
    "CWE-73": g_73, "CWE-98": g_98, "CWE-409": g_409, "CWE-917": g_917,
    "CWE-123": g_123, "CWE-613": g_613, "CWE-122": g_122, "CWE-362": g_362,
    "CWE-1333": g_1333,
}


# ===========================================================================
# 校验
# ===========================================================================
REQUIRED_FIELDS = ["has_vulnerability", "vulnerability_type", "risk_level",
                   "source", "sink", "explanation", "fix_suggestion"]
VALID_RISKS = {"Critical", "High", "Medium", "Low", "None"}


def validate_sample(sample, cwe_key):
    """校验单条样本，返回 (ok, reason)。"""
    # 基本字段
    if "code" not in sample or not sample["code"].strip():
        return False, "code 为空"
    if "analysis" not in sample or not sample["analysis"].strip():
        return False, "analysis 为空"
    v = sample.get("verdict")
    if not isinstance(v, dict):
        return False, "verdict 非 dict"

    # 必填字段
    missing = [f for f in REQUIRED_FIELDS if f not in v]
    if missing:
        return False, f"verdict 缺字段: {missing}"

    # has_vulnerability
    if not isinstance(v["has_vulnerability"], bool):
        return False, f"has_vulnerability 非布尔: {type(v['has_vulnerability'])}"
    if not v["has_vulnerability"]:
        return False, "has_vulnerability 应为 True（本批均为漏洞样本）"

    # risk_level
    if v["risk_level"] not in VALID_RISKS:
        return False, f"risk_level 非法: {v['risk_level']}"

    # vulnerability_type 前缀
    vt = v["vulnerability_type"]
    if not vt or not vt.startswith("CWE-"):
        return False, f"vulnerability_type 格式错: {vt}"

    # CWE 编号一致性
    cwe_num = cwe_key.split("-")[1]
    if f"CWE-{cwe_num}" not in vt:
        return False, f"vulnerability_type '{vt}' 与目标 {cwe_key} 不一致"

    # source/sink 锚定行号
    for f in ["source", "sink"]:
        if not re.search(r"line\s+\d+|第\s*\d+\s*行", v[f]):
            return False, f"{f} 未锚定行号: {v[f]}"

    # fix_suggestion 锚定行号
    if not re.search(r"line\s+\d+|第\s*\d+\s*行", v["fix_suggestion"]):
        return False, f"fix_suggestion 未锚定行号: {v['fix_suggestion']}"

    # 非空
    for f in ["explanation"]:
        if not v[f].strip():
            return False, f"{f} 为空"

    # JSON 可序列化
    try:
        json.dumps(v, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        return False, f"verdict JSON 序列化失败: {e}"

    return True, ""


# ===========================================================================
# 主函数
# ===========================================================================
def main():
    all_samples = []
    cwe_counts = Counter()
    dc_counts = Counter()
    lang_counts = Counter()
    fail_log = []

    print("=" * 70)
    print("生成补充训练样本")
    print("=" * 70)

    for cwe_key in sorted(GENERATORS.keys(), key=lambda x: (0 if x in TARGETS and TARGETS[x] >= 20 else 1, x)):
        gen = GENERATORS[cwe_key]
        target = TARGETS.get(cwe_key, 0)
        try:
            samples = gen()
        except Exception as e:
            fail_log.append(f"{cwe_key}: 生成异常 {e}")
            print(f"  [FAIL] {cwe_key}: 生成异常 {e}")
            continue

        ok_count = 0
        for i, s in enumerate(samples):
            ok, reason = validate_sample(s, cwe_key)
            if not ok:
                fail_log.append(f"{cwe_key} #{i}: {reason}")
                continue
            chatml = build_chatml(s)
            all_samples.append(chatml)
            cwe_counts[cwe_key] += 1
            lang_counts[s["lang"]] += 1
            if s.get("dc"):
                dc_counts[cwe_key] += 1
            ok_count += 1

        dc_n = sum(1 for s in samples if s.get("dc"))
        status = "OK" if ok_count >= target else "LESS"
        print(f"  [{status}] {cwe_key}: {ok_count}/{len(samples)} (target {target}, DC {dc_n})")

    # 写入文件
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for s in all_samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    # 统计
    total = len(all_samples)
    total_dc = sum(dc_counts.values())
    dc_ratio = (total_dc / total * 100) if total else 0

    print()
    print("=" * 70)
    print("统计")
    print("=" * 70)
    print(f"总样本数: {total}")
    print(f"防御迷惑 (DC) 样本: {total_dc} ({dc_ratio:.1f}%)")
    print(f"输出文件: {OUTPUT_FILE}")
    print()
    print("CWE 分布:")
    for cwe in sorted(cwe_counts.keys()):
        print(f"  {cwe}: {cwe_counts[cwe]} (DC {dc_counts.get(cwe, 0)})")
    print()
    print("语言分布:")
    for lang, n in sorted(lang_counts.items(), key=lambda x: -x[1]):
        print(f"  {lang}: {n}")
    print()
    if fail_log:
        print(f"校验失败 ({len(fail_log)} 条):")
        for msg in fail_log[:20]:
            print(f"  - {msg}")
        if len(fail_log) > 20:
            print(f"  ... 还有 {len(fail_log) - 20} 条")
    else:
        print("校验失败: 0 条")
    print()
    print("完成。")


if __name__ == "__main__":
    main()
