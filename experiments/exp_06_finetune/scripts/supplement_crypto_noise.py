"""
补充训练样本 —— Crypto 漏洞盲区 + Noise/Source 误报修复。

背景：微调后的 Qwen2.5-Coder-3B 在评估中有两类失败案例：
  1. FN（漏洞漏报）：MD5/SHA1 密码哈希、硬编码 IV/key、ECB 模式、弱随机数
  2. FP（安全误报）：参数化查询被 try-except/注释误导、硬编码常量被当用户输入

样本设计：
  - 类别 1：Crypto 漏洞样本（6 vuln + 6 safe 对照）
  - 类别 2：Noise 负样本（12 safe，含误导性特征）
  - system prompt 使用 SYSTEM_PROMPT_LITE（exp_06 微调专用精简版）
  - user prompt 使用 build_user_prompt(code, language, filename)
  - assistant 包含 CoT 分析 + ```json 结论块

用法：
  cd /home/zane/文档/code/毕业设计
  PYTHONPATH=. /home/zane/miniconda3/envs/AI/bin/python \
      experiments/exp_06_finetune/scripts/supplement_crypto_noise.py
"""

import json
import os
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import SYSTEM_PROMPT_LITE, build_user_prompt

OUTPUT_FILE = PROJECT_ROOT / "experiments/exp_06_finetune/data/supplement_crypto_noise.jsonl"

SAMPLES = []


def add(code, language, filename, has_vulnerability, vuln_type, risk_level,
        source, sink, explanation, fix_suggestion, cot_analysis):
    """添加一条样本。"""
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
        "cot_analysis": cot_analysis,
    })


# ===========================================================================
# 类别 1：Crypto 漏洞样本（6 vuln + 6 safe 对照）
# ===========================================================================

# --- CWE-327 MD5 密码哈希 ---

add(
    """
import hashlib
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    password_hash = hashlib.md5(password.encode()).hexdigest()
    conn = sqlite3.connect('app.db')
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                 (username, password_hash))
    conn.commit()
    conn.close()
    return {'status': 'registered'}
""",
    "python", "crypto_md5_password_vuln.py",
    True, "CWE-327 弱密码学", "High",
    "request.form.get('password')（用户密码）",
    "hashlib.md5(password.encode()).hexdigest()",
    "使用 MD5 对密码做哈希，MD5 已被证明不安全：无 salt、无迭代、可被彩虹表和 GPU 暴力破解在秒级内还原",
    "改用 bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))，bcrypt 自带随机 salt 和自适应 cost factor",
    """分析过程：
1. 污染源：request.form.get('password') 获取用户密码（预期输入，但需要安全存储）。
2. 危险 sink：hashlib.md5(password.encode()).hexdigest() 对密码做 MD5 哈希后存入数据库。
3. 弱点分析：MD5 是消息摘要算法，设计目标是快速计算——这正是密码存储的反面需求。
   - 无 salt：相同密码的 MD5 值相同，攻击者可用预计算彩虹表批量破解。
   - 无迭代：单次 MD5 计算极快，现代 GPU 每秒可计算数十亿次 MD5。
   - MD5 已存在碰撞攻击，不适用于任何安全场景。
4. 修复方向：密码哈希应使用 bcrypt/scrypt/argon2 等专用算法，自带 salt 和可调迭代次数。
5. 结论：存在弱密码学漏洞，MD5 不适合密码存储。"""
)

add(
    """
import bcrypt
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    salt = bcrypt.gensalt(rounds=12)
    password_hash = bcrypt.hashpw(password.encode(), salt)
    conn = sqlite3.connect('app.db')
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                 (username, password_hash))
    conn.commit()
    conn.close()
    return {'status': 'registered'}
""",
    "python", "crypto_md5_password_safe.py",
    False, "none", "None", "N/A", "N/A",
    "使用 bcrypt.gensalt(rounds=12) 生成随机 salt 并以 2^12=4096 次迭代做密码哈希，bcrypt 自适应 cost factor 使 GPU 暴力破解成本不可接受",
    "no fix needed",
    """分析过程：
1. 污染源：request.form.get('password') 获取用户密码。
2. 安全 sink：bcrypt.hashpw(password.encode(), salt) 使用 bcrypt 算法做密码哈希。
3. 防御分析：
   - bcrypt.gensalt(rounds=12) 生成随机 salt，每次注册的 salt 不同，阻止彩虹表攻击。
   - rounds=12 意味着 2^12=4096 轮迭代，增加单次哈希计算时间，使暴力破解成本急剧上升。
   - bcrypt 是专为密码存储设计的算法，与 MD5/SHA 不同，它有意降低计算速度。
4. 参数化查询（? 占位符）防 SQL 注入，与密码哈希安全正交。
5. 结论：无漏洞，bcrypt + rounds=12 是密码存储的正确方案。"""
)

# --- CWE-327 SHA1 密码哈希 ---

add(
    """
import hashlib

def hash_password(password):
    return hashlib.sha1(password.encode()).hexdigest()

def verify_password(password, stored_hash):
    computed = hashlib.sha1(password.encode()).hexdigest()
    return computed == stored_hash
""",
    "python", "crypto_sha1_password_vuln.py",
    True, "CWE-327 弱密码学", "High",
    "password 参数（用户密码）",
    "hashlib.sha1(password.encode()).hexdigest()",
    "使用 SHA1 对密码做哈希，SHA1 无 salt 无迭代，且已被 Google 碰撞攻击攻破，不适合密码存储",
    "改用 argon2-cffi 的 PasswordHasher，argon2 是 2015 年密码哈希竞赛冠军，抗 GPU/ASIC 破解",
    """分析过程：
1. 污染源：password 参数是用户密码（预期输入，需安全存储）。
2. 危险 sink：hashlib.sha1(password.encode()).hexdigest() 用 SHA1 哈希密码。
3. 弱点分析：
   - SHA1 与 MD5 同属快速摘要算法，设计目标是快速计算，不适合密码存储。
   - 无 salt：相同密码哈希值相同，彩虹表可直接查询。
   - 无迭代：单次 SHA1 计算极快，GPU 每秒可计算数十亿次。
   - SHA1 已被证明存在碰撞（SHAttered 攻击，2017），安全性进一步降低。
4. verify_password 用 == 比较——虽然此处不是时序攻击的主要场景（密码哈希比较），
   但最佳实践应使用恒定时间比较。
5. 结论：存在弱密码学漏洞，SHA1 不适合密码存储。"""
)

add(
    """
from argon2 import PasswordHasher, exceptions

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
)

def hash_password(password):
    return ph.hash(password)

def verify_password(password, stored_hash):
    try:
        return ph.verify(stored_hash, password)
    except exceptions.VerifyMismatchError:
        return False
    except exceptions.InvalidHashError:
        return False
""",
    "python", "crypto_sha1_password_safe.py",
    False, "none", "None", "N/A", "N/A",
    "使用 argon2 PasswordHasher 做密码哈希，memory_cost=64MB + time_cost=3 + parallelism=4 三维参数抗 GPU/ASIC 破解，argon2 是 PHC 大赛冠军算法",
    "no fix needed",
    """分析过程：
1. 污染源：password 参数是用户密码（预期输入）。
2. 安全 sink：ph.hash(password) 使用 argon2 算法做密码哈希。
3. 防御分析：
   - argon2 是 2015 年 Password Hashing Competition 冠军，专为密码存储设计。
   - memory_cost=65536（64MB）：要求每次哈希消耗 64MB 内存，阻止 GPU 并行破解
     （GPU 显存有限，无法大规模并行）。
   - time_cost=3：3 轮迭代增加计算时间。
   - parallelism=4：利用 4 线程并行计算，进一步调整资源消耗。
   - argon2 自带随机 salt，编码在哈希字符串中，无需单独管理。
4. verify 使用 ph.verify，内部做恒定时间比较。
5. 结论：无漏洞，argon2 是当前最强的密码哈希算法。"""
)

# --- CWE-329 硬编码 IV ---

add(
    """
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

SECRET_KEY = b"this_is_a_hardcoded_secret_key_32"
STATIC_IV = b"fixed_iv_value_16"

def encrypt_data(plaintext):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, STATIC_IV)
    padded = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return base64.b64encode(ciphertext).decode()

def decrypt_data(b64_ciphertext):
    raw = base64.b64decode(b64_ciphertext)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, STATIC_IV)
    decrypted = cipher.decrypt(raw)
    return decrypted.rstrip(b'\\x00').decode()
""",
    "python", "crypto_hardcoded_iv_vuln.py",
    True, "CWE-329 硬编码 IV", "High",
    "SECRET_KEY = b'this_is_a_hardcoded...' / STATIC_IV = b'fixed_iv_value_16'",
    "AES.new(SECRET_KEY, AES.MODE_CBC, STATIC_IV)",
    "AES-CBC 使用硬编码的 32 字节密钥和固定 IV，固定 IV 导致相同明文产生相同密文，攻击者可检测明文模式；密钥硬编码在源码中泄露",
    "密钥从 os.environ 读取，每次加密用 os.urandom(16) 生成随机 IV 并与密文一起存储",
    """分析过程：
1. 污染源：SECRET_KEY 和 STATIC_IV 都是硬编码的字节字面量，直接写在源码中。
2. 危险 sink：AES.new(SECRET_KEY, AES.MODE_CBC, STATIC_IV) 使用硬编码的 key 和 IV 做 AES-CBC 加密。
3. 弱点分析（IV）：
   - CBC 模式下，IV 的作用是使相同明文产生不同密文。固定 IV 意味着相同明文块
     总是产生相同密文块，攻击者可检测明文模式（如密码字段的重复）。
   - IV 应该是每次加密随机生成的，不需要保密但必须不可预测。
4. 弱点分析（密钥）：
   - SECRET_KEY 硬编码在源码中，任何能访问源码的人都能获取密钥解密所有数据。
   - 密钥应从环境变量、KMS 或配置文件读取。
5. decrypt_data 中 rstrip(b'\\x00') 不是正确的去填充方式（应使用 unpad），
   但主要漏洞是硬编码 key/IV。
6. 结论：存在硬编码 IV 和硬编码密钥两个密码学漏洞。"""
)

add(
    """
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def get_secret_key():
    key = os.environ.get("AES_SECRET_KEY")
    if not key or len(key.encode()) != 32:
        raise RuntimeError("AES_SECRET_KEY must be 32 bytes")
    return key.encode()

def encrypt_data(plaintext):
    key = get_secret_key()
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_data(b64_ciphertext):
    key = get_secret_key()
    raw = base64.b64decode(b64_ciphertext)
    iv, ciphertext = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode()
""",
    "python", "crypto_hardcoded_iv_safe.py",
    False, "none", "None", "N/A", "N/A",
    "密钥从 os.environ 读取且校验长度，每次加密用 os.urandom(16) 生成随机 IV 并与密文拼接存储，解密时正确使用 unpad 去填充",
    "no fix needed",
    """分析过程：
1. 污染源：函数接受 plaintext 参数（预期输入，需要加密保护）。
2. 安全 sink：AES.new(key, AES.MODE_CBC, iv) 做 AES-CBC 加密。
3. 防御分析（密钥）：get_secret_key() 从 os.environ 读取 AES_SECRET_KEY，
   并校验长度为 32 字节，密钥不在源码中硬编码。
4. 防御分析（IV）：os.urandom(16) 每次加密生成密码学安全的随机 IV，
   IV 与密文拼接后一起存储（iv + ciphertext），解密时分离使用。
   随机 IV 确保相同明文每次加密产生不同密文。
5. 防御分析（填充）：使用 pad/unpad 做 PKCS#7 填充和去填充，正确处理边界。
6. 结论：无漏洞，密钥从环境变量读取 + 随机 IV + 正确填充是 AES-CBC 的安全用法。"""
)

# --- CWE-329 硬编码密钥 ---

add(
    """
from Crypto.Cipher import AES
import base64

SECRET_KEY = b"hardcoded_secret_key_32_bytes_!!"

def decrypt_token(encrypted_token):
    raw = base64.b64decode(encrypted_token)
    iv = raw[:16]
    ciphertext = raw[16:]
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8', errors='ignore')

def verify_token(token):
    decrypted = decrypt_token(token)
    return decrypted == 'valid_session'
""",
    "python", "crypto_hardcoded_key_vuln.py",
    True, "CWE-329 硬编码密钥", "High",
    "SECRET_KEY = b'hardcoded_secret_key_32_bytes_!!'",
    "AES.new(SECRET_KEY, AES.MODE_CBC, iv)",
    "AES 密钥以字节字面量硬编码在源码中，任何能访问源码或字节码的人都能提取密钥解密所有 token",
    "从 os.environ 或 KMS 读取密钥，源码中不存储任何密钥字面量",
    """分析过程：
1. 污染源：SECRET_KEY = b'hardcoded_secret_key_32_bytes_!!' 是硬编码的 AES 密钥字面量。
2. 危险 sink：AES.new(SECRET_KEY, AES.MODE_CBC, iv) 使用硬编码密钥解密 token。
3. 弱点分析：
   - 密钥直接写在源码中，任何能访问源码仓库的人（包括离职员工、代码审计员）
     都能获取密钥，进而解密所有 token。
   - 即使密钥在 .pyc 字节码中也以明文存在，反编译即可获取。
   - 密钥无法轮换（修改密钥需要改代码重新部署）。
4. decrypt_token 用 errors='ignore' 处理解码错误可能掩盖攻击痕迹，但主要漏洞是硬编码密钥。
5. 结论：存在硬编码密钥漏洞，密钥必须从外部安全来源读取。"""
)

add(
    """
import os
from Crypto.Cipher import AES
import base64

_KEY_CACHE = None

def get_secret_key():
    global _KEY_CACHE
    if _KEY_CACHE is None:
        key = os.environ.get("AES_SECRET_KEY")
        if not key:
            raise RuntimeError("AES_SECRET_KEY not configured")
        key_bytes = key.encode()
        if len(key_bytes) != 32:
            raise RuntimeError("AES_SECRET_KEY must be 32 bytes")
        _KEY_CACHE = key_bytes
    return _KEY_CACHE

def decrypt_token(encrypted_token):
    raw = base64.b64decode(encrypted_token)
    iv = raw[:16]
    ciphertext = raw[16:]
    cipher = AES.new(get_secret_key(), AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8', errors='ignore')
""",
    "python", "crypto_hardcoded_key_safe.py",
    False, "none", "None", "N/A", "N/A",
    "AES 密钥从 os.environ 读取并缓存，校验长度为 32 字节，源码中无任何密钥字面量，部署时通过环境变量注入",
    "no fix needed",
    """分析过程：
1. 污染源：函数接受 encrypted_token 参数（预期输入，需要解密）。
2. 安全 sink：AES.new(get_secret_key(), AES.MODE_CBC, iv) 做 AES-CBC 解密。
3. 防御分析（密钥来源）：get_secret_key() 从 os.environ 读取 AES_SECRET_KEY，
   源码中无任何密钥字面量。密钥在部署时通过环境变量注入（如 K8s Secret、Docker env）。
4. 防御分析（密钥校验）：校验密钥长度为 32 字节（AES-256），不匹配时抛异常。
5. 防御分析（缓存）：_KEY_CACHE 缓存密钥避免重复读取环境变量，但首次读取后不可变。
6. 结论：无漏洞，密钥从环境变量读取是正确的密钥管理实践。"""
)

# --- CWE-327 ECB 模式 ---

add(
    """
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

KEY = b"16bytesecretkey!!"

def encrypt_config(config_text):
    cipher = AES.new(KEY, AES.MODE_ECB)
    padded = pad(config_text.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return base64.b64encode(ciphertext).decode()

def decrypt_config(b64_ciphertext):
    cipher = AES.new(KEY, AES.MODE_ECB)
    raw = base64.b64decode(b64_ciphertext)
    decrypted = cipher.decrypt(raw)
    return decrypted.decode('utf-8').rstrip('\\x00')
""",
    "python", "crypto_ecb_mode_vuln.py",
    True, "CWE-327 弱密码学", "High",
    "KEY = b'16bytesecretkey!!'（硬编码密钥）",
    "AES.new(KEY, AES.MODE_ECB)",
    "使用 AES-ECB 模式加密，ECB 模式对相同明文块产生相同密文块，不隐藏明文模式（如重复的密码字段）；同时密钥硬编码",
    "改用 AES-GCM 模式（自带认证），密钥从环境变量读取，每次用随机 nonce",
    """分析过程：
1. 污染源：KEY = b'16bytesecretkey!!' 是硬编码的 AES 密钥。
2. 危险 sink：AES.new(KEY, AES.MODE_ECB) 使用 ECB 模式加密。
3. 弱点分析（ECB 模式）：
   - ECB（Electronic Codebook）模式将明文分块独立加密，相同明文块产生相同密文块。
   - 攻击者可观察密文块的重复模式推断明文结构（如密码字段、模板文本的重复）。
   - 经典示例：ECB 模式加密位图图片后，密文仍能看出图片轮廓。
4. 弱点分析（密钥）：KEY 硬编码在源码中，泄露后所有加密数据可被解密。
5. ECB 模式不需要 IV（这也是它不安全的原因之一），缺少随机性。
6. 结论：存在弱密码学漏洞，ECB 模式不应在任何安全场景中使用。"""
)

add(
    """
import os
from Crypto.Cipher import AES
import base64

def get_key():
    key = os.environ.get("AES_KEY")
    if not key or len(key.encode()) != 16:
        raise RuntimeError("AES_KEY must be 16 bytes")
    return key.encode()

def encrypt_config(config_text):
    key = get_key()
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(config_text.encode())
    return base64.b64encode(nonce + tag + ciphertext).decode()

def decrypt_config(b64_data):
    key = get_key()
    raw = base64.b64decode(b64_data)
    nonce = raw[:12]
    tag = raw[12:28]
    ciphertext = raw[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')
""",
    "python", "crypto_ecb_mode_safe.py",
    False, "none", "None", "N/A", "N/A",
    "使用 AES-GCM 模式（AEAD 认证加密），随机 nonce 防止明文模式泄露，tag 做完整性校验防篡改，密钥从环境变量读取",
    "no fix needed",
    """分析过程：
1. 污染源：函数接受 config_text 参数（预期输入，需要加密）。
2. 安全 sink：AES.new(key, AES.MODE_GCM, nonce=nonce) 做 AES-GCM 加密。
3. 防御分析（GCM 模式）：
   - GCM（Galois/Counter Mode）是 AEAD 认证加密模式，同时提供机密性和完整性。
   - nonce（number used once）每次随机生成（os.urandom(12)），确保相同明文产生不同密文。
   - GCM 使用计数器模式，无 ECB 的明文模式泄露问题。
   - tag 是认证标签，decrypt_and_verify 会校验 tag，若密文被篡改则抛异常。
4. 防御分析（密钥）：密钥从 os.environ 读取，校验 16 字节长度。
5. nonce + tag + ciphertext 一起存储，解密时分离使用。
6. 结论：无漏洞，AES-GCM 是当前推荐的对称加密模式。"""
)

# --- CWE-338 弱随机数 ---

add(
    """
import random
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/api/reset_token')
def generate_reset_token():
    user_id = request.args.get('uid')
    token = str(random.randint(100000, 999999))
    conn = sqlite3.connect('app.db')
    conn.execute("UPDATE users SET reset_token = ? WHERE id = ?", (token, user_id))
    conn.commit()
    conn.close()
    return {'reset_token': token}
""",
    "python", "crypto_weak_random_vuln.py",
    True, "CWE-338 弱随机数", "High",
    "random.randint(100000, 999999) 生成 token",
    "conn.execute('UPDATE users SET reset_token = ?', (token,))",
    "使用 random.randint 生成 6 位密码重置 token，random 模块的 Mersenne Twister PRNG 可预测，且 6 位数字空间仅 90 万种可暴力枚举",
    "改用 secrets.token_hex(32) 生成密码学安全的 256 位随机 token",
    """分析过程：
1. 污染源：user_id 来自 request.args.get('uid')（用户可控）。
2. 危险 sink：random.randint(100000, 999999) 生成密码重置 token。
3. 弱点分析（PRNG）：
   - random 模块使用 Mersenne Twister 伪随机数生成器，设计目标是统计随机性而非密码学安全。
   - MT 的内部状态可通过观察 624 个连续输出反推，进而预测后续输出。
   - 如果攻击者能触发多次 token 生成并观察输出，可预测下一个 token。
4. 弱点分析（空间）：
   - 6 位数字 token 只有 900,000 种可能（100000-999999）。
   - 攻击者可在数小时内暴力枚举所有可能的 token 重置任意用户密码。
5. 结论：存在弱随机数漏洞，安全 token 必须使用 secrets 模块生成。"""
)

add(
    """
import secrets
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/api/reset_token')
def generate_reset_token():
    user_id = request.args.get('uid')
    token = secrets.token_hex(32)
    conn = sqlite3.connect('app.db')
    conn.execute("UPDATE users SET reset_token = ? WHERE id = ?", (token, user_id))
    conn.commit()
    conn.close()
    return {'reset_token': token}
""",
    "python", "crypto_weak_random_safe.py",
    False, "none", "None", "N/A", "N/A",
    "使用 secrets.token_hex(32) 生成 256 位密码学安全随机 token，secrets 底层调用 os.urandom（/dev/urandom），不可预测且空间为 2^256",
    "no fix needed",
    """分析过程：
1. 污染源：user_id 来自 request.args.get('uid')（用户可控）。
2. 安全 sink：secrets.token_hex(32) 生成密码重置 token。
3. 防御分析：
   - secrets 模块是 Python 3.6+ 专门为密码学安全设计的随机数模块。
   - 底层调用 os.urandom()，使用操作系统提供的 CSPRNG（/dev/urandom 或 CryptGenRandom）。
   - token_hex(32) 生成 32 字节（256 位）随机数，输出为 64 字符十六进制字符串。
   - 256 位随机空间（2^256 ≈ 10^77）使暴力枚举完全不可行。
   - CSPRNG 的输出不可预测，即使攻击者观察大量 token 也无法推断下一个。
4. 参数化查询（? 占位符）防 SQL 注入。
5. 结论：无漏洞，secrets.token_hex 是生成安全 token 的正确方式。"""
)


# ===========================================================================
# 类别 2：Noise 负样本（12 safe，含误导性特征）
# ===========================================================================

# --- 2.1 参数化查询 + 噪音包裹 ---

add(
    """
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM users WHERE name = ? AND pass = ?", (username, password))
        user = cursor.fetchone()
        if user:
            return {'status': 'logged in'}
        return {'error': 'invalid credentials'}, 401
    except sqlite3.Error as e:
        conn.rollback()
        return {'error': 'database error'}, 500
    finally:
        conn.close()
""",
    "python", "noise_try_catch_param_query.py",
    False, "none", "None", "N/A", "N/A",
    "SQL 使用 ? 占位符 + 参数元组 (username, password) 做参数化查询，数据库驱动自动转义；try-except-finally 是异常处理和资源管理，不影响安全性",
    "no fix needed",
    """分析过程：
1. 污染源：username 和 password 来自 request.form.get，用户完全可控。
2. sink 评估：cursor.execute 执行 SQL。
3. 防御确认：SQL 语句使用 ? 占位符，参数通过元组 (username, password) 传入。
   这是标准参数化查询——数据库驱动会自动转义参数值，确保用户输入只作为数据
   而非 SQL 语法的一部分。攻击者输入 ' OR 1=1 -- 只会被当作 name 字段的值查找。
4. try-except-finally 分析：try 块包裹了查询逻辑，except 捕获 sqlite3.Error
   做回滚和错误响应，finally 关闭连接。这是正常的异常处理和资源管理模式，
   不会引入安全漏洞，也不影响参数化查询的防护效果。
5. 结论：代码安全。参数化查询有效防护 SQL 注入，try-except 是正常的工程实践。"""
)

add(
    """
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    # TODO: 注意：这里可能存在 SQL 注入风险！
    # 但实际上使用参数化查询是安全的，待 review 确认
    # review: 已确认安全，? 占位符防注入
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM products WHERE name LIKE ?", (f'%{keyword}%',))
    results = cursor.fetchall()
    conn.close()
    return {'results': results}
""",
    "python", "noise_misleading_comment.py",
    False, "none", "None", "N/A", "N/A",
    "注释虽声称'可能存在 SQL 注入风险'，但实际代码使用 ? 占位符参数化查询，用户输入只作为 LIKE 模式的数据值传入，注释是错误的",
    "no fix needed",
    """分析过程：
1. 污染源：keyword 来自 request.args.get('q')，用户完全可控。
2. sink 评估：cursor.execute 执行 SQL。
3. 防御确认：SQL 语句使用 ? 占位符，参数 f'%{keyword}%' 通过元组传入。
   f'%{keyword}%' 是 Python 字符串格式化生成 LIKE 搜索模式（如 '%apple%'），
   然后这个字符串作为参数值传给 ?。数据库驱动会转义其中的特殊字符。
   关键区分：f-string 在这里是构造搜索模式字符串，不是 SQL 拼接——
   最终这个字符串通过 ? 参数传入，而非拼进 SQL 语句。
4. 注释分析：注释说"可能存在 SQL 注入风险"，但这是开发者的误判或遗留 TODO。
   判定必须基于代码实际语义，不能因为注释声称有风险就判漏洞。
   实际上 ? 占位符 + 参数元组就是参数化查询的标准写法。
5. 结论：代码安全。注释是误导性的，但参数化查询实际有效。"""
)

# --- 2.2 硬编码常量 + 危险模式（source 不可控）---

add(
    """
import sqlite3

def init_schema():
    table_name = "users"
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS " + table_name + " (id INTEGER PRIMARY KEY, name TEXT)")
    conn.commit()
    conn.close()
""",
    "python", "noise_harden_string_concat.py",
    False, "none", "None", "N/A", "N/A",
    "SQL 语句虽用字符串拼接 (+ table_name +)，但 table_name 是硬编码常量 'users'，无任何用户输入参与，攻击者无法影响 SQL 语句内容",
    "no fix needed",
    """分析过程：
1. 污染源检查：函数 init_schema() 无入参，不从 request/argv/环境变量读取任何输入。
   table_name = 'users' 是硬编码的字符串常量。
2. sink 评估：cursor.execute 执行拼接后的 SQL。
   "CREATE TABLE IF NOT EXISTS " + table_name + " (id ...)" 使用 + 拼接。
3. source 可控性分析：虽然字符串拼接 SQL 通常是不安全模式，但此处 table_name
   是开发者硬编码的常量 'users'，没有任何外部输入路径到达它。
   SQL 注入的前提是"用户可控输入进入 SQL 语法层"，此处不存在该条件。
4. 字符串拼接 SQL 是不良实践（可维护性差），但在 source 完全不可控的情况下
   不构成安全漏洞。
5. 结论：代码安全。硬编码常量拼接 SQL 不构成 SQL 注入。"""
)

add(
    """
import subprocess

def backup_files():
    cmd = "tar -czf /tmp/backup.tar.gz /var/www/uploads"
    subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return "backup complete"
""",
    "python", "noise_shell_true_hardcoded.py",
    False, "none", "None", "N/A", "N/A",
    "subprocess.run(shell=True) 但命令是硬编码字符串 'tar -czf /tmp/backup.tar.gz /var/www/uploads'，无任何用户输入或变量参与拼接，攻击者无法影响命令内容",
    "no fix needed",
    """分析过程：
1. 污染源检查：函数 backup_files() 无入参，不读取 request/argv/环境变量。
   cmd = "tar -czf /tmp/backup.tar.gz /var/www/uploads" 是硬编码字符串字面量。
2. sink 评估：subprocess.run(cmd, shell=True) 会经过 shell 解释器。
3. source 可控性分析：shell=True 的风险在于"用户输入拼接进命令字符串"，
   此处 cmd 是固定字符串，不含任何变量、函数返回值或用户输入。
   攻击者无法影响 cmd 的内容，无法注入 ; rm -rf / 等命令。
4. 函数不接受任何参数，不存在外部输入到达 sink 的路径。
5. 结论：代码安全。shell=True + 硬编码命令不构成命令注入。"""
)

add(
    """
def compute_formula():
    formula = "3.14159 * 2 * 10"
    result = eval(formula)
    return result
""",
    "python", "noise_eval_hardcoded.py",
    False, "none", "None", "N/A", "N/A",
    "eval 调用的表达式是硬编码字符串 '3.14159 * 2 * 10'，纯数学常量无变量引用，函数无入参不接受外部输入，攻击者无法影响 eval 的内容",
    "no fix needed",
    """分析过程：
1. 污染源检查：函数 compute_formula() 无入参，不读取任何外部输入。
   formula = "3.14159 * 2 * 10" 是硬编码的数学表达式字符串。
2. sink 评估：eval(formula) 执行字符串作为 Python 表达式。
3. source 可控性分析：eval 是危险函数，但危险在于"用户输入进入 eval"。
   此处 formula 是固定数学表达式，不含变量名、__import__、os.system 等。
   攻击者无法影响 formula 的内容，无法注入 __import__('os').system('rm -rf /')。
4. 函数不接受参数，不存在外部输入到达 eval 的路径。
5. 结论：代码安全。eval + 硬编码数学表达式不构成代码注入。"""
)

# --- 2.3 参数化查询 + 装饰器/框架包裹 ---

add(
    """
import sqlite3
from functools import wraps
from flask import Flask, request

app = Flask(__name__)

def with_db(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        conn = sqlite3.connect('app.db')
        try:
            result = f(conn, *args, **kwargs)
            return result
        finally:
            conn.close()
    return wrapper

@app.route('/user/<int:user_id>')
@with_db
def get_user(conn, user_id):
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if row:
        return {'id': row[0], 'name': row[1], 'email': row[2]}
    return {'error': 'not found'}, 404
""",
    "python", "noise_decorator_param_query.py",
    False, "none", "None", "N/A", "N/A",
    "装饰器 with_db 管理数据库连接生命周期，视图函数内使用 ? 占位符参数化查询，Flask 路由 <int:user_id> 强制整数类型，三层防护确保无注入",
    "no fix needed",
    """分析过程：
1. 污染源：user_id 来自 Flask 路由 <int:user_id>，用户可控但被强制转为整数。
2. sink 评估：cursor.execute 执行 SQL。
3. 防御确认（第一层）：Flask 路由用 <int:user_id>，只匹配整数路径段。
   /user/abc 返回 404，/user/1 OR 1=1 也返回 404（含空格不匹配 int）。
4. 防御确认（第二层）：SQL 用 ? 占位符，参数 (user_id,) 通过元组传入，
   数据库驱动自动转义。即使 user_id 含特殊字符也只作为数据值。
5. 装饰器分析：with_db 装饰器在函数执行前创建连接，finally 中关闭连接。
   这是资源管理模式，不影响 SQL 查询的安全性。
6. 结论：代码安全。路由类型强制 + 参数化查询 + 装饰器资源管理是安全的组合。"""
)

# --- 2.4 输入验证 + 危险模式 ---

add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)
ALLOWED_ACTIONS = {'list', 'count'}

@app.route('/files')
def list_files():
    action = request.args.get('action', 'list')
    if action not in ALLOWED_ACTIONS:
        return {'error': 'invalid action'}, 400
    if action == 'list':
        result = subprocess.run(['ls', '/var/uploads'], capture_output=True, text=True, shell=False)
    else:
        result = subprocess.run(['wc', '-l', '/var/uploads/*'], capture_output=True, text=True, shell=False)
    return {'output': result.stdout}
""",
    "python", "noise_input_validation_whitelist.py",
    False, "none", "None", "N/A", "N/A",
    "action 参数经白名单 ALLOWED_ACTIONS 校验（只允许 'list'/'count'），通过后映射到固定的 subprocess 列表参数，shell=False 不经 shell 解释，攻击者无法注入命令",
    "no fix needed",
    """分析过程：
1. 污染源：action 来自 request.args.get('action')，用户可控。
2. sink 评估：subprocess.run 执行命令。
3. 防御确认（第一层）：action 必须在 ALLOWED_ACTIONS = {'list', 'count'} 白名单中。
   不在白名单的值返回 400，不进入后续逻辑。白名单是精确匹配，不可绕过。
4. 防御确认（第二层）：通过白名单后，action 只映射到固定的命令列表
   (['ls', '/var/uploads'] 或 ['wc', '-l', ...])，不参与命令构造。
5. 防御确认（第三层）：subprocess.run 用列表形式传参，shell=False（默认），
   参数直接传递给程序，不经过 shell 解释器。
6. 结论：代码安全。白名单校验 + 固定命令映射 + 列表形式 shell=False，三重防护。"""
)

# --- 2.5 subprocess 列表形式 ---

add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    if not host or not host.replace('.', '').replace('-', '').isalnum():
        return {'error': 'invalid hostname'}, 400
    if len(host) > 253:
        return {'error': 'hostname too long'}, 400
    result = subprocess.run(['ping', '-c', '1', '-W', '2', host],
                            capture_output=True, text=True, timeout=5)
    return {'output': result.stdout, 'returncode': result.returncode}
""",
    "python", "noise_subprocess_list_form.py",
    False, "none", "None", "N/A", "N/A",
    "subprocess.run 使用列表形式 ['ping', '-c', '1', '-W', '2', host]，shell 默认 False 不经 shell 解释；host 经 isalnum 白名单校验只允许字母数字点号连字符",
    "no fix needed",
    """分析过程：
1. 污染源：host 来自 request.args.get('host')，用户可控。
2. sink 评估：subprocess.run 执行 ping 命令。
3. 防御确认（第一层）：host.replace('.','').replace('-','').isalnum() 白名单校验，
   只允许字母、数字、点号、连字符。阻止了 ; | & $ ` 等 shell 元字符。
   额外校验 len(host) <= 253（DNS 最大长度）防止缓冲区问题。
4. 防御确认（第二层）：subprocess.run 用列表形式 ['ping', '-c', '1', '-W', '2', host]，
   shell 参数默认 False。列表形式下每个元素作为独立参数传给 ping 程序，
   不经过 shell 解释器，即使 host 含特殊字符也不会被 shell 解释。
5. timeout=5 防止命令挂起。
6. 结论：代码安全。白名单校验 + 列表形式 + shell=False 是命令执行的安全模式。"""
)

# --- 2.6 shlex.quote 转义 ---

add(
    """
import subprocess
import shlex
from flask import Flask, request

app = Flask(__name__)

@app.route('/lookup')
def lookup():
    domain = request.args.get('domain', '')
    if not domain or not domain.replace('.', '').replace('-', '').isalnum():
        return {'error': 'invalid domain'}, 400
    safe_domain = shlex.quote(domain)
    result = subprocess.run(f'dig +short {safe_domain}',
                            shell=True, capture_output=True, text=True, timeout=5)
    return {'result': result.stdout.strip()}
""",
    "python", "noise_shlex_quote.py",
    False, "none", "None", "N/A", "N/A",
    "domain 先经 isalnum 白名单校验（只允许字母数字点号连字符），再经 shlex.quote 做 shell 转义，双重防护下 shell=True 无法被注入",
    "no fix needed",
    """分析过程：
1. 污染源：domain 来自 request.args.get('domain')，用户可控。
2. sink 评估：subprocess.run(shell=True) 经过 shell 解释器。
3. 防御确认（第一层）：domain.replace('.','').replace('-','').isalnum() 白名单校验，
   只允许字母、数字、点号、连字符。这是 DNS 域名的合法字符集。
4. 防御确认（第二层）：shlex.quote(domain) 对 domain 做 shell 转义，
   将特殊字符用单引号包裹，确保 domain 作为单个参数传递给 dig 命令。
   即使 domain 含 ; | & 等字符（第一层已阻止），shlex.quote 也会转义。
5. 双重防护下，攻击者无法注入 shell 元字符。
6. timeout=5 防止命令挂起。
7. 结论：代码安全。白名单 + shlex.quote 双重转义有效防护命令注入。"""
)

# --- 2.7 escape 函数转义 XSS ---

add(
    """
import html
from flask import Flask, request

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    safe_name = html.escape(name, quote=True)
    message = f'<div class="greeting">Hello, {safe_name}! Welcome back.</div>'
    return message, 200, {'Content-Type': 'text/html; charset=utf-8'}
""",
    "python", "noise_escape_xss.py",
    False, "none", "None", "N/A", "N/A",
    "用户输入 name 经 html.escape(quote=True) 转义，将 < > & \" ' 转为 HTML 实体，阻止 <script> 标签和属性注入；quote=True 确保引号也被转义",
    "no fix needed",
    """分析过程：
1. 污染源：name 来自 request.args.get('name')，用户完全可控。
2. sink 评估：用户输入进入 HTML 响应（Content-Type: text/html）。
3. 防御确认：html.escape(name, quote=True) 将以下字符转为 HTML 实体：
   - < → &lt;  > → &gt;  & → &amp;
   - " → &quot;  ' → &#x27;（quote=True 确保引号也被转义）
   攻击者输入 <script>alert(1)</script> 会被转义为
   &lt;script&gt;alert(1)&lt;/script&gt;，浏览器显示为文本而非执行脚本。
4. quote=True 的重要性：如果用户输入进入 HTML 属性（如 value="{name}"），
   引号转义防止攻击者闭合属性注入新属性（如 onclick=...）。
5. 虽然 f-string 把 safe_name 拼入 HTML 字符串，但拼接的是已转义的值，
   不是原始用户输入。
6. 结论：代码安全。html.escape 是 XSS 防护的标准方案。"""
)

# --- 2.8 ORM 查询 ---

add(
    """
from django.http import JsonResponse
from myapp.models import Product

def search_products(request):
    keyword = request.GET.get('q', '')
    if len(keyword) > 100:
        return JsonResponse({'error': 'keyword too long'}, status=400)
    products = (Product.objects
                .filter(name__icontains=keyword)
                .values('id', 'name', 'price')[:20])
    return JsonResponse({'results': list(products)})
""",
    "python", "noise_django_orm.py",
    False, "none", "None", "N/A", "N/A",
    "使用 Django ORM 的 filter(name__icontains=keyword) 查询，Django ORM 内部自动参数化，用户输入只作为查询条件值而非 SQL 语法；values() 限定返回字段防止信息泄露",
    "no fix needed",
    """分析过程：
1. 污染源：keyword 来自 request.GET.get('q')，用户可控。
2. sink 评估：Product.objects.filter(...) 执行数据库查询。
3. 防御确认：Django ORM 的 filter(name__icontains=keyword) 在底层自动转为
   参数化 SQL（WHERE name LIKE %keyword%），keyword 作为参数值传入而非 SQL 拼接。
   Django 的 QuerySet API 在所有查询方法中都使用参数绑定，不存在 SQL 注入风险。
4. 额外防护：len(keyword) > 100 限制查询长度，防止超长输入导致性能问题。
5. values('id', 'name', 'price') 只查询需要的字段，不返回敏感字段（如 password），
   遵循最小信息暴露原则。
6. [:20] 限制返回结果数量（LIMIT 20），防止大量数据查询。
7. 结论：代码安全。Django ORM 自动参数化是防 SQL 注入的有效方案。"""
)

# --- 2.9 prepared statement (Java) ---

add(
    """
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class UserRepository {
    private static final String DB_URL = "jdbc:postgresql://localhost:5432/appdb";

    public User findByUsername(String username) throws Exception {
        String sql = "SELECT id, username, email FROM users WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return new User(rs.getInt("id"),
                                    rs.getString("username"),
                                    rs.getString("email"));
                }
            }
        }
        return null;
    }
}
""",
    "java", "noise_prepared_statement.java",
    False, "none", "None", "N/A", "N/A",
    "使用 Java PreparedStatement + setString(1, username) 参数绑定，JDBC 驱动自动转义参数值；SQL 模板预编译在先，用户输入只作为数据传入",
    "no fix needed",
    """分析过程：
1. 污染源：username 是方法参数，可能来自用户输入。
2. sink 评估：stmt.executeQuery() 执行 SQL 查询。
3. 防御确认：使用 PreparedStatement 而非 Statement。
   - SQL 模板 "SELECT ... WHERE username = ?" 在 prepareStatement 时预编译，
     ? 是占位符，SQL 语法结构已固定。
   - stmt.setString(1, username) 将 username 绑定到第一个占位符，
     JDBC 驱动会自动转义特殊字符（如 ' → ''），确保 username 只作为数据值。
   - 攻击者输入 ' OR '1'='1 会被当作 username 的字面值查找，不会改变 SQL 语义。
4. try-with-resources 确保连接和语句正确关闭，防止资源泄露。
5. 查询只返回 id/username/email 字段，不返回 password。
6. 结论：代码安全。PreparedStatement 是 Java 防 SQL 注入的标准方案。"""
)


# ===========================================================================
# 构建逻辑
# ===========================================================================

def build_json_verdict(sample):
    """构造 JSON 结论块。"""
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
    """转为 ChatML。"""
    user_content = build_user_prompt(
        code=sample["code"], language=sample["language"],
        filename=sample["filename"],
    )
    json_block = build_json_verdict(sample)
    assistant_content = f"{sample['cot_analysis']}\n\n{json_block}"
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_LITE},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ]
    }


def validate(samples_jsonl):
    """验证生成的样本。"""
    errors = []
    safe_explanations = []
    vuln_count = 0
    safe_count = 0

    for i, sample in enumerate(samples_jsonl):
        msgs = sample["messages"]
        # 检查 messages 结构
        if len(msgs) != 3:
            errors.append(f"样本 {i}: messages 应有 3 条，实际 {len(msgs)}")
            continue
        if msgs[0]["role"] != "system" or msgs[1]["role"] != "user" or msgs[2]["role"] != "assistant":
            errors.append(f"样本 {i}: role 顺序错误")
            continue

        # 检查 system prompt 是 SYSTEM_PROMPT_LITE（不是硬编码占位符）
        if msgs[0]["content"] != SYSTEM_PROMPT_LITE:
            errors.append(f"样本 {i}: system prompt 不匹配 SYSTEM_PROMPT_LITE")

        # 检查 user prompt 格式
        if "代码片段" not in msgs[1]["content"]:
            errors.append(f"样本 {i}: user prompt 缺少 '代码片段' 头")
        if "```" not in msgs[1]["content"]:
            errors.append(f"样本 {i}: user prompt 缺少代码块")

        # 提取 assistant 中的 JSON 结论
        assistant = msgs[2]["content"]
        json_match = re.search(r'```json\s*(\{.*?\})\s*```', assistant, re.DOTALL)
        if not json_match:
            errors.append(f"样本 {i}: assistant 缺少 ```json``` 块")
            continue

        try:
            verdict = json.loads(json_match.group(1))
        except json.JSONDecodeError as e:
            errors.append(f"样本 {i}: JSON 解析失败: {e}")
            continue

        # 检查 schema 合规
        required_fields = {"has_vulnerability", "vulnerability_type", "risk_level",
                          "source", "sink", "explanation", "fix_suggestion"}
        missing = required_fields - set(verdict.keys())
        if missing:
            errors.append(f"样本 {i}: 缺少字段 {missing}")

        has_vuln = verdict.get("has_vulnerability")
        if has_vuln:
            vuln_count += 1
            # 漏洞样本检查
            if verdict.get("vulnerability_type") in ("none", ""):
                errors.append(f"样本 {i}: 漏洞样本 vulnerability_type 不能为 none")
            if verdict.get("risk_level") in ("None", ""):
                errors.append(f"样本 {i}: 漏洞样本 risk_level 不能为 None")
            if verdict.get("fix_suggestion") == "no fix needed":
                errors.append(f"样本 {i}: 漏洞样本 fix_suggestion 不能为 'no fix needed'")
        else:
            safe_count += 1
            # 安全样本检查
            if verdict.get("vulnerability_type") != "none":
                errors.append(f"样本 {i}: 安全样本 vulnerability_type 应为 'none'，实际 '{verdict.get('vulnerability_type')}'")
            if verdict.get("source") != "N/A":
                errors.append(f"样本 {i}: 安全样本 source 应为 'N/A'，实际 '{verdict.get('source')}'")
            if verdict.get("sink") != "N/A":
                errors.append(f"样本 {i}: 安全样本 sink 应为 'N/A'，实际 '{verdict.get('sink')}'")
            if verdict.get("risk_level") != "None":
                errors.append(f"样本 {i}: 安全样本 risk_level 应为 'None'，实际 '{verdict.get('risk_level')}'")
            if verdict.get("fix_suggestion") != "no fix needed":
                errors.append(f"样本 {i}: 安全样本 fix_suggestion 应为 'no fix needed'")

            safe_explanations.append(verdict.get("explanation", ""))

    # 检查安全样本 explanation 多样性
    unique_explanations = set(safe_explanations)
    if len(unique_explanations) < len(safe_explanations):
        # 找出重复的
        from collections import Counter
        counts = Counter(safe_explanations)
        duplicates = {k: v for k, v in counts.items() if v > 1}
        errors.append(f"安全样本 explanation 有重复: {len(duplicates)} 种重复（共 {sum(duplicates.values())} 条）")
        for expl, cnt in duplicates.items():
            errors.append(f"  重复 {cnt} 次: '{expl[:80]}...'")

    # 检查是否有模板话术
    template_phrases = [
        "代码中未发现可利用的安全漏洞",
        "未发现明显漏洞",
        "代码整体安全",
    ]
    for expl in safe_explanations:
        for phrase in template_phrases:
            if phrase in expl:
                errors.append(f"安全样本 explanation 含模板话术 '{phrase}': '{expl[:80]}...'")

    return errors, vuln_count, safe_count, len(unique_explanations) if safe_explanations else 0


def main():
    print("=" * 60)
    print("补充训练样本：Crypto 漏洞盲区 + Noise/Source 误报修复")
    print("=" * 60)

    print(f"\n共 {len(SAMPLES)} 条补充样本")
    vuln = sum(1 for s in SAMPLES if s["has_vulnerability"])
    safe = len(SAMPLES) - vuln
    print(f"  漏洞样本: {vuln}  安全样本: {safe}")

    # 构建 ChatML
    jsonl_records = [build_messages(s) for s in SAMPLES]

    # 验证
    print("\n[验证] 检查 schema 合规性和 explanation 多样性...")
    errors, v_count, s_count, unique_expl = validate(jsonl_records)
    print(f"  漏洞: {v_count}  安全: {s_count}  安全 explanation 唯一值: {unique_expl}/{s_count}")

    if errors:
        print(f"\n[!] 发现 {len(errors)} 个验证错误：")
        for e in errors:
            print(f"  - {e}")
        print("\n仍会写入文件，但请检查上述错误。")
    else:
        print("\n[OK] 所有验证通过。")

    # 写入文件
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for record in jsonl_records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"\n已写入: {OUTPUT_FILE}")

    # 统计
    print(f"\n[统计]")
    print(f"  文件: {OUTPUT_FILE.name}")
    print(f"  样本数: {len(jsonl_records)}")
    print(f"  system prompt: SYSTEM_PROMPT_LITE ({len(SYSTEM_PROMPT_LITE)} 字符)")

    # CoT 多样性
    cot_texts = [s["cot_analysis"] for s in SAMPLES]
    print(f"  CoT 唯一文本: {len(set(cot_texts))}/{len(cot_texts)}")

    # 分类统计
    crypto_samples = SAMPLES[:12]
    noise_samples = SAMPLES[12:]
    print(f"\n  类别 1 - Crypto 漏洞样本: {len(crypto_samples)} 条")
    print(f"    漏洞: {sum(1 for s in crypto_samples if s['has_vulnerability'])}")
    print(f"    安全: {sum(1 for s in crypto_samples if not s['has_vulnerability'])}")
    print(f"  类别 2 - Noise 负样本: {len(noise_samples)} 条")
    print(f"    安全: {sum(1 for s in noise_samples if not s['has_vulnerability'])}")

    # 估计 token 数
    total_chars = 0
    for record in jsonl_records:
        for msg in record["messages"]:
            total_chars += len(msg["content"])
    print(f"\n  总字符数: {total_chars}  估计 token: ~{total_chars // 4}")


if __name__ == "__main__":
    main()
