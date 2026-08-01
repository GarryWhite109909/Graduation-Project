"""
修复 v9 训练数据的质量问题：
1. CWE-329 硬编码密钥 → CWE-798 硬编码凭证
2. 安全样本 explanation="N/A" → 从 CoT 分析提取有意义的描述
3. 漏洞样本 fix_suggestion="" → 根据 CWE 类型生成修复建议
4. 移除多余字段 "taint_path"
5. 统一安全样本字段格式: "none" / "无" → "N/A"/"None"/"no fix needed"
6. 补充缺失的 fix_suggestion 字段（JSON 中 field 不存在而非空字符串）
"""

import json
import re
import copy

V9_FILE = "experiments/exp_06_finetune/data/train_chatml_v9_augmented.jsonl"
OUTPUT_FILE = "experiments/exp_06_finetune/data/train_chatml_v9_augmented.jsonl"

# CWE 修复建议映射（用于缺失 fix_suggestion 的漏洞样本）
CWE_FIX_MAP = {
    "CWE-89": "使用参数化查询（PreparedStatement）替代字符串拼接，或使用 ORM 框架的内置参数绑定功能，所有用户输入必须通过参数传递而非拼接到 SQL 语句中。",
    "CWE-79": "对用户输入进行上下文相关的输出编码（HTML 实体编码、JavaScript 编码、CSS 编码等），或使用安全的模板引擎自动转义功能。",
    "CWE-78": "避免使用 os.system/subprocess.call 等执行系统命令；如需执行，使用 subprocess.run 传入参数列表而非字符串，并严格校验输入。",
    "CWE-22": "使用 os.path.abspath 规范化路径，并校验路径是否在允许的基目录内（如 startswith 检查），禁止直接拼接用户输入到文件路径。",
    "CWE-798": "使用环境变量、密钥管理服务（Vault / AWS KMS）或凭据注入框架管理密钥，禁止在源码中硬编码。",
    "CWE-502": "使用安全的序列化格式（如 JSON）替代 pickle/yaml.load，如需反序列化不可信数据，使用 yaml.safe_load 或自定义反序列化白名单。",
    "CWE-918": "对用户输入的 URL 进行白名单校验，限制协议和域名为可信列表，禁止直接使用用户输入构造请求。",
    "CWE-327": "使用安全的密码学算法（AES-256-GCM、bcrypt、Argon2、SHA-256、RSA-OAEP），禁止使用 MD5/SHA1/RC4/DES 等弱算法。",
    "CWE-352": "使用 CSRF Token（如 Django/Flask-WTF 内置）或检查自定义请求头（如 X-Requested-With）验证请求来源。",
    "CWE-117": "移除日志中的换行符和特殊字符，或使用结构化日志框架（如 SLF4J 的 MessageFormatter）替代字符串拼接。",
    "CWE-90": "使用参数化 LDAP 查询（如 Spring LDAP 的过滤器绑定）或严格校验输入字符集，禁止直接拼接用户输入到 LDAP 查询字符串。",
    "CWE-601": "使用白名单验证重定向 URL 或使用相对路径重定向，禁止将用户输入直接作为重定向目标 URL。",
    "CWE-1336": "使用安全的模板引擎配置（如 Jinja2 SandboxedEnvironment）或不在模板编译中引入用户输入，避免将用户输入拼接到模板源码。",
    "CWE-95": "避免使用 eval/exec 等动态代码执行函数，如需执行，使用白名单限制可用函数或使用沙箱机制。",
    "CWE-94": "严格校验代码加载来源，使用白名单或签名验证，禁止从用户可控路径动态加载模块/代码。",
    "CWE-190": "在算术运算前检查输入范围，使用安全算术库（如 Apache Commons Math）或语言内置的溢出检查功能。",
    "CWE-200": "限制敏感信息的返回范围，仅返回必要字段，使用 DTO 或视图模型过滤敏感字段。",
    "CWE-611": "禁用 XML 外部实体解析（如 DocumentBuilderFactory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)）。",
    "CWE-330": "使用密码学安全的随机数生成器（如 java.security.SecureRandom、secrets.SystemRandom），避免使用 Random() 生成安全敏感数据。",
    "CWE-329": "使用安全的随机 IV 生成方式（如 SecureRandom 生成 16 字节随机数），禁止使用固定或可预测的初始化向量。",
}

# 特殊修复：CWE-329 误标文件
CWE329_FIX_FILE = "crypto_hardcoded_key_vuln.py"


def extract_cot_text(asst):
    """从 assistant 回复中提取 CoT 分析文本"""
    cot_match = re.search(r'<analysis>(.*?)</analysis>', asst, re.DOTALL)
    if cot_match:
        return cot_match.group(1).strip()
    # 如果没有 analysis 标签，取 JSON 之前的文本
    json_match = re.search(r'```json', asst)
    if json_match:
        return asst[:json_match.start()].strip()
    return ""


def extract_json_str(asst):
    """从 assistant 回复中提取 JSON 字符串"""
    json_match = re.search(r'```json\s*(\{.*?\})\s*```', asst, re.DOTALL)
    if json_match:
        return json_match.group(1).strip()
    return None


def safe_explanation_from_cot(cot_text):
    """从安全样本的 CoT 中提取有意义的解释"""
    # 取最后一句结论
    sentences = [s.strip() for s in re.split(r'[。\n]', cot_text) if s.strip()]
    # 找包含"无漏洞"、"安全"、"防御有效"等关键词的句子
    key_phrases = ["无漏洞", "安全", "防御措施有效", "不存在漏洞", "未发现", "已阻断", "有效防止", "有效防护"]
    for s in reversed(sentences):
        if any(p in s for p in key_phrases):
            return s
    # 退回到最后一句
    if sentences:
        return sentences[-1]
    return "未检测到安全漏洞，防御措施有效"


def generate_fix_suggestion(cwe_type, cot_text):
    """根据 CWE 类型和 CoT 生成修复建议"""
    # 先尝试从 CoT 中提取修复建议
    fix_phrases = ["修复建议", "建议修改", "修复方式", "建议使用", "修复方案", "改进建议"]
    for phrase in fix_phrases:
        for line in cot_text.split('\n'):
            if phrase in line:
                return line.strip().lstrip('0123456789.、- ').strip()
    
    # 从 CWE 映射中获取
    for cwe_key, fix in CWE_FIX_MAP.items():
        if cwe_key in cwe_type:
            return fix
    
    # 通用的修复建议
    return "对用户输入进行严格的校验和过滤，避免将不可信数据直接传递给危险函数，使用安全的替代方案处理用户输入。"


def fix_v9_data():
    with open(V9_FILE, encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip()]
    
    stats = {
        "cwe329_fixed": 0,
        "safe_explanation_fixed": 0,
        "vuln_fix_suggestion_fixed": 0,
        "taint_path_removed": 0,
        "none_to_na_fixed": 0,
        "chinese_fixed": 0,
        "total": 0,
    }
    
    fixed_lines = []
    
    for i, line in enumerate(lines):
        rec = json.loads(line)
        asst = rec["messages"][2]["content"]
        user_msg = rec["messages"][1]["content"]
        
        json_str = extract_json_str(asst)
        if not json_str:
            fixed_lines.append(line)
            continue
        
        try:
            j = json.loads(json_str)
        except json.JSONDecodeError:
            fixed_lines.append(line)
            continue
        
        original_j = copy.deepcopy(j)
        cot_text = extract_cot_text(asst)
        
        # --- 修复 1: CWE-329 硬编码密钥 → CWE-798 ---
        if CWE329_FIX_FILE in user_msg and "CWE-329" in j.get("vulnerability_type", ""):
            j["vulnerability_type"] = j["vulnerability_type"].replace("CWE-329", "CWE-798")
            j["vulnerability_type"] = j["vulnerability_type"].replace("硬编码密钥", "硬编码凭证")
            j["vulnerability_type"] = j["vulnerability_type"].replace("硬编码api密钥", "硬编码凭证")
            j["vulnerability_type"] = j["vulnerability_type"].replace("硬编码API密钥", "硬编码凭证")
            # 也修复 CoT 中的 CWE-329 引用
            asst = asst.replace("CWE-329", "CWE-798")
            asst = asst.replace("硬编码密钥", "硬编码凭证")
            stats["cwe329_fixed"] += 1
        
        # --- 修复 2: 安全样本 explanation="N/A" ---
        if j.get("has_vulnerability") is False and j.get("explanation") == "N/A":
            j["explanation"] = safe_explanation_from_cot(cot_text)
            stats["safe_explanation_fixed"] += 1
        
        # --- 修复 3: 漏洞样本 fix_suggestion 缺失或为空 ---
        if j.get("has_vulnerability") is True:
            fix = j.get("fix_suggestion", "")
            if not fix:  # 空字符串或 None
                j["fix_suggestion"] = generate_fix_suggestion(j.get("vulnerability_type", ""), cot_text)
                stats["vuln_fix_suggestion_fixed"] += 1
        
        # --- 修复 4: 移除多余字段 "taint_path" ---
        if "taint_path" in j:
            del j["taint_path"]
            stats["taint_path_removed"] += 1
        
        # --- 修复 5: 安全样本字段格式统一 ---
        if j.get("has_vulnerability") is False:
            changed = False
            # risk_level: "none" → "None"（字符串 "None" 而非 JSON null）
            if j.get("risk_level") == "none":
                j["risk_level"] = "None"
                changed = True
            # source: "none" → "N/A"
            if j.get("source") == "none":
                j["source"] = "N/A"
                changed = True
            # sink: "none" → "N/A"
            if j.get("sink") == "none":
                j["sink"] = "N/A"
                changed = True
            # fix_suggestion: "" → "no fix needed"
            if j.get("fix_suggestion") == "":
                j["fix_suggestion"] = "no fix needed"
                changed = True
            # 中文 "无" → "N/A"
            if j.get("source") == "无":
                j["source"] = "N/A"
                changed = True
            if j.get("sink") == "无":
                j["sink"] = "N/A"
                changed = True
            if j.get("fix_suggestion") == "无需修复":
                j["fix_suggestion"] = "no fix needed"
                changed = True
            if changed:
                stats["none_to_na_fixed"] += 1
        
        # 如果有变更，替换 assistant 中的 JSON
        if j != original_j:
            new_json_str = json.dumps(j, ensure_ascii=False, indent=2)
            old_json_block = f"```json\n{json_str}\n```"
            new_json_block = f"```json\n{new_json_str}\n```"
            asst = asst.replace(old_json_block, new_json_block)
            rec["messages"][2]["content"] = asst
        
        fixed_lines.append(json.dumps(rec, ensure_ascii=False))
        stats["total"] += 1
    
    # 写回
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for line in fixed_lines:
            f.write(line + '\n')
    
    print("=== 修复统计 ===")
    print(f"总样本数: {stats['total']}")
    print(f"CWE-329 归因错误修复: {stats['cwe329_fixed']}")
    print(f"安全样本 explanation 补全: {stats['safe_explanation_fixed']}")
    print(f"漏洞样本 fix_suggestion 补全: {stats['vuln_fix_suggestion_fixed']}")
    print(f"多余字段 taint_path 移除: {stats['taint_path_removed']}")
    print(f"字段格式统一 (none/中文→N/A/None): {stats['none_to_na_fixed']}")

    return stats


if __name__ == "__main__":
    stats = fix_v9_data()
    print(f"\n修复完成，输出文件: {OUTPUT_FILE}")