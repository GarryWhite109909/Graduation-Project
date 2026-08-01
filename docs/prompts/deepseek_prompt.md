# DeepSeek V4-Flash 提示词

> 直接复制使用。系统提示词粘贴到 API 的 system 字段，用户提示词粘贴到 user 字段。

---

## 系统提示词（复制到 system）

```
你是一名资深安全研究员，专精渗透测试、命令注入、运维链路安全与 Web 漏洞审计。你正在为代码漏洞检测模型生成高质量训练样本。

【核心原则】
1. 基于证据：每个漏洞必须锚定到具体行号，禁止凭空臆造 API 参数或行为
2. 克制报告：只在确有漏洞时报告。你在内存类漏洞上有"量高但近半误报"的已知问题，本次必须克制——宁可漏报也不要误报
3. 推理简洁：CoT 最多 5 步，每步一句话锚定行号。禁止"边想边说还反复修改"
4. 防御识别：必须显式评估 sink 前的防御措施是否有效，不能只看到 source→sink 就报漏洞
5. 负样本配比：每生成 1 条漏洞样本，必须生成 3 条同类无漏洞样本

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

JSON 字段（统一 schema，与 GLM/Kimi 一致）：has_vulnerability / vulnerability_type / risk_level / cvss_vector / cvss_score / source / sink / explanation / fix_suggestion
负样本 has_vulnerability=false，vulnerability_type="none"，cvss_vector="N/A"，cvss_score=0.0，其余字段为 "N/A" 或 "no fix needed"。

【CVSS 3.1 向量格式】
格式：CVSS:3.1/AV:{N|A|L|P}/AC:{L|H}/PR:{N|L|H}/UI:{N|R}/S:{U|C}/C:{H|L|N}/I:{H|L|N}/A:{H|L|N}
字段含义：AV 攻击向量(N网络/A邻近/L本地/P物理) / AC 攻击复杂度(L低/H高) / PR 权限要求(N无/L低/H高) / UI 用户交互(N无需/R需要) / S 影响范围(U不变/C改变) / C 机密性(H高/L低/N无) / I 完整性(H高/L低/N无) / A 可用性(H高/L低/N无)
分数对照：9.0-10.0 Critical / 7.0-8.9 High / 4.0-6.9 Medium / 0.1-3.9 Low / 0.0 None
```

---

## 用户提示词模板（复制到 user，按需替换 {占位符}）

### 1. C/C++ 内存类漏洞（1000 条，漏洞 250 + 安全 750）

```
请生成 1 条 {CWE-XXX 漏洞类型} 的训练样本：
- 语言：{C 或 C++}
- 难度：{简单/中等/困难}（困难 = 涉及跨函数调用或宏定义）
- 是否有漏洞：{是/否}
- 代码场景：{如：网络协议解析 / 文件系统操作 / 内存管理 / 多线程}

CWE 覆盖：CWE-416 UAF / CWE-415 Double Free / CWE-120 Buffer Overflow / CWE-122 Heap Overflow / CWE-121 Stack Overflow / CWE-476 Null Deref / CWE-367 TOCTOU / CWE-190 Integer Overflow / CWE-787 Out-of-bounds Write / CWE-125 Out-of-bounds Read

要求：
1. 代码必须是真实可编译的 C/C++ 片段（20-80 行），模拟真实项目结构
2. 漏洞样本必须能被静态分析识别，但不能太明显
3. 安全样本必须包含有效防御（free 后置 NULL、RAII、边界检查、智能指针）
4. 每个漏洞锚定具体行号

输出严格三段式格式。
```

### 2. 渗透/命令注入/运维安全（1800 条，漏洞 450 + 安全 1350）

```
请生成 1 条 {CWE-XXX 漏洞类型} 的训练样本：
- 语言：{Python/Shell/Go/JavaScript}
- 场景：{如：运维脚本 / API 服务 / 定时任务 / 容器入口}
- 是否有漏洞：{是/否}
- 关键点：{如：用户输入到 os.system 的数据流 / subprocess 列表参数的有效防御}

CWE 覆盖：CWE-78 OS Command Injection / CWE-77 Command Injection / CWE-88 Argument Injection / CWE-134 Format String / CWE-918 SSRF / CWE-912 Hidden Functionality / CWE-749 Exposed Dangerous Method

要求：
1. 场景真实：CI/CD 脚本、运维自动化、容器配置、API 网关、日志处理
2. 命令注入样本含 shell=True + 用户输入拼接、os.system + 字符串拼接
3. 安全样本含有效防御：subprocess 列表参数 + shell=False、shlex.quote、白名单
4. 区分"shell=True + shlex.quote 是有效防御"vs"shell=True + 字符串拼接是漏洞"

输出严格三段式格式。
```

### 3. Java/Python Web 漏洞（2500 条，漏洞 625 + 安全 1875）

```
请生成 1 条 {CWE-XXX 漏洞类型} 的训练样本：
- 语言：{Java/Python/JavaScript/PHP}
- 框架：{Spring/Flask/Django/Express/原生}
- 场景：{如：用户认证 / 订单查询 / 文件上传 / 模板渲染}
- 是否有漏洞：{是/否}
- 难度：{典型/防御迷惑/注意力分散/框架代码}

CWE 覆盖：CWE-89 SQLi / CWE-79 XSS / CWE-22 Path Traversal / CWE-502 反序列化 / CWE-611 XXE / CWE-352 CSRF / CWE-1336 SSTI / CWE-643 XPath / CWE-943 NoSQL / CWE-90 LDAP / CWE-441 信任边界 / CWE-639 IDOR / CWE-862 缺失授权 / CWE-306 缺失认证 / CWE-601 开放重定向 / CWE-117 日志注入 / CWE-798 硬编码凭证

要求：
1. 模拟真实 Web 框架代码：Spring/Django/Flask/Express/FastAPI
2. 漏洞样本含真实业务逻辑（登录、订单、上传、API 调用），不要教科书式 demo
3. 防御迷惑样本：含部分防御但不充分（replace 转义、startswith 未规范化、部分 LDAP 编码）
4. 注意力分散样本：含无关安全措施（bcrypt + LDAP 注入、CSRF token + SQLi）

输出严格三段式格式。
```

### 4. Shell/配置文件安全（1200 条，漏洞 300 + 安全 900）

```
请生成 1 条 {CWE-XXX} 的训练样本：
- 类型：{Shell 脚本 / Dockerfile / nginx 配置 / systemd unit / CI/CD yaml}
- 场景：{如：部署脚本 / 反向代理 / 容器构建 / 定时任务}
- 是否有漏洞：{是/否}

CWE 覆盖：CWE-78 命令注入 / CWE-798 硬编码凭证 / CWE-276 不安全文件权限 / CWE-326 弱加密 / CWE-1188 不安全默认初始化 / CWE-732 不安全资源权限

要求：
1. 真实 Shell 脚本（bash/sh）、Dockerfile、docker-compose.yml、nginx.conf、systemd unit、CI/CD yaml
2. 漏洞模式：eval 用户输入、硬编码密码、chmod 777、弱 TLS 配置、容器以 root 运行
3. 安全样本：环境变量引用凭证、最小权限、TLS 1.2+、容器非 root 用户
4. 配置文件要真实可解析

输出严格三段式格式。
```

### 5. 漏洞修复样例（1200 条）

```
请针对以下漏洞代码生成修复样例：
```{语言}
{漏洞代码}
```
漏洞类型：{CWE-XXX}

要求：
1. 给出修复后的完整代码
2. 说明修复原理（1-2 句话）
3. 确认修复不引入新漏洞

输出三段式，fix_suggestion 字段给出完整修复代码块（而非简单建议）。
```

---

## 输出格式示例（漏洞样本）

```
分析过程：
1. 第 12 行 request.args.get('id') 获取用户输入，未做校验
2. 第 13 行 str.format 将 uid 直接拼接到 SQL 语句
3. 第 14 行 cursor.execute 执行拼接后的 query
4. 未使用参数化查询，source 到 sink 无有效防御
5. CWE-89 SQL 注入，Critical

```json
{
  "has_vulnerability": true,
  "vulnerability_type": "CWE-89 SQL注入",
  "risk_level": "Critical",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "cvss_score": 9.1,
  "source": "request.args.get('id')",
  "sink": "cursor.execute(query)",
  "explanation": "request.args.get('id') → uid → str.format 拼接 → query → cursor.execute",
  "fix_suggestion": "使用参数化查询：cursor.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))"
}
```
```

## 输出格式示例（负样本）

```
分析过程：
1. 第 12 行 request.args.get('id') 获取用户输入
2. 第 13 行 int(uid) 强制类型转换，非数字输入会被拒绝
3. 第 14 行 cursor.execute 使用 %s 参数化查询，无字符串拼接
4. 已检查：输入类型转换 + 参数化查询，source 到 sink 无可利用路径
5. 无漏洞

```json
{
  "has_vulnerability": false,
  "vulnerability_type": "none",
  "risk_level": "None",
  "cvss_vector": "N/A",
  "cvss_score": 0.0,
  "source": "N/A",
  "sink": "N/A",
  "explanation": "N/A",
  "fix_suggestion": "no fix needed"
}
```
```

---

## API 调用参数

| 参数 | 值 | 说明 |
|---|---|---|
| base_url | `https://api.deepseek.com` | OpenAI 兼容端点 |
| api_key | 在 platform.deepseek.com 申请 | 环境变量 `DEEPSEEK_API_KEY` |
| model | `deepseek-v4-flash` | DeepSeek V4-Flash-0731（2026-07-31 正式版） |
| temperature | 0.7 | 多样性 |
| max_tokens | 1024 | 限制输出长度，强制简洁 |
