# DeepSeek 蒸馏提示词

## 设计理念：三阶段三层提示词，各司其职

蒸馏、训练、推理三个阶段目的不同，提示词也不同。**有且只有一个约束：学生侧的 system 在训练和推理间必须一致**（同一学生的考试规则不能变）。

| 阶段 | 角色 | system | user | assistant |
|---|---|---|---|---|
| **蒸馏** | 教师（DeepSeek） | 教师 system：「为模型生成训练样本」 | 出题指令：「生成 CWE-416 的 UAF 样本」 | 代码 + CoT + JSON（教师手写标准答案） |
| **训练** | 学生（8B） | 学生 system：「分析代码漏洞」 | 代码（从教师输出提取） | CoT + JSON（标准答案，学生看着学） |
| **推理** | 学生（8B） | 学生 system：「分析代码漏洞」 | 代码（用户待测代码） | （模型自己生成） |

用考试比喻：
- **蒸馏 = 教师备课**：教师 system 告诉 DeepSeek「你是出题人，出一道 UAF 题并写标准答案」
- **训练 = 学生刷真题**：学生 system 告诉 8B「你是考生，分析代码」；user 是题目，assistant 是标准答案，学生对照着学
- **推理 = 学生高考**：同一个学生 system（考试规则不变），user 是新题，assistant 学生自己写

### 三条不可违反的规则

1. **教师 system ≠ 学生 system**：教师"出题 + 写答案"，学生"只答题"。目的不同，提示词不同。
2. **训练 system = 推理 system**：同一个学生的同一门考试，规则不能变。否则模型推理时困惑（"训练时我是 X 角色，怎么推理变成 Y 角色"）。
3. **user / assistant 各阶段不同**：
   - user：蒸馏是"出题指令"，训练/推理是"代码"（内容不同，但训练和推理的格式相同）
   - assistant：训练有（标准答案），推理无（学生自己答）

---

## ① 教师 system（蒸馏专用，~450 token）

只在调 DeepSeek API 时使用，**不进训练数据**。目的是让教师既出题又写标准答案。

```
你是一名资深安全研究员，为漏洞检测模型生成高质量训练样本。

【生成要求】
1. 生成真实可编译的代码片段（20-80行），模拟真实项目结构
2. 漏洞样本必须能被静态分析识别，但不能太明显
3. 安全样本必须包含有效防御，并用否定推理说明为何安全
4. 每个漏洞锚定具体行号

【输出格式】
三段式：
第一段：代码片段（```语言 ... ```）
第二段：分析过程（用 1. 2. 3. 编号，≤5 步，每步以"第X行"或"line X"锚定行号）
第三段：结构化结论（```json ... ```）

【推理路径多样化】
A 数据流优先（注入类）：source→sink→数据流→防御→结论
B 模式识别（密码学/配置/硬编码）：CWE模式匹配→行号验证→排除反例→结论
C 假设验证（负样本/防御迷惑）：假设恶意输入→追踪→防御是否阻断→结论
交替使用，禁止每条都用路径 A

【长度原则】
以完整覆盖"代码+分析+结论"为准，按复杂度自然伸缩，禁止注水凑长度：
- 低（直接注入/硬编码）：简短代码 + 2-3 步分析
- 中（带防御/单函数UAF）：适中代码 + 3-4 步分析
- 高（跨函数/TOCTOU/整数溢出链）：允许更长代码 + 4-5 步分析
每步必须有信息增量，禁止重复同一结论、禁止"换句话说/也就是说/需要注意的是"式啰嗦

【JSON 字段】
has_vulnerability / vulnerability_type / risk_level / cvss_vector / cvss_score / source / sink / explanation / fix_suggestion
risk_level 取值：Critical / High / Medium / Low / None（首字母大写）
负样本：has_vulnerability=false, vulnerability_type="none", risk_level="None", cvss_vector="N/A", cvss_score=0.0, 其余字段 "N/A" 或 "no fix needed"
```

**为什么教师 system 有"推理路径多样化"和"长度控制"，学生 system 没有？**
这些是"出题指令"——告诉教师生成多样化的样本。学生不需要在 system 里被告知这些，因为学生是从标准答案（assistant）里直接学到多样化和长度变化的。

---

## ② 学生 system（训练 + 推理一致，~180 token）

训练数据和推理时共用，定义学生的"答题角色"。

```
你是一名安全研究员，分析给定代码的安全漏洞。

【输出格式】
分析过程（用 1. 2. 3. 编号，≤5 步，每步以"第X行"或"line X"锚定行号）
结构化结论（```json ... ```）

【分析要求】
1. 基于证据：每个漏洞必须锚定到具体行号
2. 防御识别：必须评估 sink 前的防御是否有效
3. 克制报告：宁可漏报不要误报
4. 负样本否定推理：安全代码必须假设验证说明为何安全

【JSON 字段】
has_vulnerability / vulnerability_type / risk_level / cvss_vector / cvss_score / source / sink / explanation / fix_suggestion
risk_level 取值：Critical / High / Medium / Low / None（首字母大写）
负样本：has_vulnerability=false, vulnerability_type="none", risk_level="None", cvss_vector="N/A", cvss_score=0.0
```

**训练和推理必须用同一个 system**：这是 SFT 的基本要求。模型在训练时学到"在这个 system 定义的角色下，给定代码 → 输出 CoT+JSON"；推理时如果换 system，模型会困惑。

---

## ③ user prompt

### 蒸馏时（出题指令，给 DeepSeek）

user 是"出题指令"，告诉教师出什么题。含 CWE 归因 + CVSS 格式（按需出现，不占 system token）。

通用引用片段：

```
CWE 归因：注入类按 sink 区分（SQL→CWE-89, shell→CWE-78, eval→CWE-95, LDAP→CWE-90）；
内存类（UAF→CWE-416, Double Free→CWE-415, 栈溢出→CWE-121, NPD→CWE-476, 越界写→CWE-787）；
密码学类（硬编码IV→CWE-329, JWT→CWE-347, 凭证→CWE-798）；
其他（反序列化→CWE-502, XXE→CWE-611, SSRF→CWE-918, XSS→CWE-79, 路径穿越→CWE-22, IDOR→CWE-639）。

CVSS 3.1：CVSS:3.1/AV:{N|A|L|P}/AC:{L|H}/PR:{N|L|H}/UI:{N|R}/S:{U|C}/C:{H|L|N}/I:{H|L|N}/A:{H|L|N}
（9.0-10 Critical / 7.0-8.9 High / 4.0-6.9 Medium / 0.1-3.9 Low / 0.0 None）

输出：```代码块``` + 分析过程（≤5步，每步锚定行号） + ```json结论```
```

5 个模板（cc_memory / pentest / web / shell / fix），每个格式：
`请生成 1 条 {cwe} 漏洞样本并分析其安全性：\n- 语言/场景/难度...\n- 要求...\n{CWE归因}\n{CVSS格式}\n{输出格式}`

详见 [deepseek.py](../../experiments/exp_06_finetune/scripts/distill_v2/prompts/deepseek.py)。

### 训练时（代码，给 8B）

user 是"待测代码"，从教师输出中提取：

```
分析以下代码的安全漏洞：
```c
void process(char *buf) {
    char *p = malloc(64);
    free(p);
    return *p;
}
```
```

### 推理时（代码，给 8B）

user 格式与训练时完全相同，只是代码换成用户真实待测代码。

---

## 训练数据结构（8B 学到的）

```json
{
  "messages": [
    {
      "role": "system",
      "content": "你是一名安全研究员，分析给定代码的安全漏洞..."
    },
    {
      "role": "user",
      "content": "分析以下代码的安全漏洞：\n```c\nvoid process(char *buf) {\n    char *p = malloc(64);\n    free(p);\n    return *p;\n}\n```"
    },
    {
      "role": "assistant",
      "content": "1. 第3行 malloc(64) 分配内存给 p\n2. 第4行 free(p) 释放内存\n3. 第5行 return *p 解引用已释放的 p\n4. free 后未置 NULL\n5. CWE-416 UAF，Critical\n\n```json\n{...}\n```"
    }
  ]
}
```

**关键**：
- system = 学生 system（训练 = 推理）
- user = 代码（推理时用户给代码）
- assistant = CoT + JSON（推理时模型只输出这两段，不含代码）

---

## Token 预算

| 部分 | token | 说明 |
|---|---|---|
| 学生 system | ~180 | 训练+推理共用 |
| user（含代码） | ~100-250 | 代码 15-35 行 |
| assistant（CoT+JSON） | 300-1000 | 按复杂度弹性伸缩（非硬约束） |
| **序列总长** | **580-1330** | 远在 max_seq_length=2048 内 |

---

## 常见误解澄清

| 误解 | 事实 |
|---|---|
| "蒸馏和训练用同一个 system" | ❌ 教师 system（出题）≠ 学生 system（答题），代码里已分开 |
| "训练和推理 system 也该不同" | ❌ 学生 system 训练=推理，这是 SFT 要求（考试规则不能变） |
| "训练-推理零 mismatch = 所有提示词都一样" | ❌ 只是 system 一样；user（题目）不同，assistant 训练有/推理无 |
| "教师 system 的指令也要进学生 system" | ❌ "生成要求/推理路径/长度控制"是出题指令，学生从标准答案学，不用写进 system |

---

## 代码位置

- 教师/学生 system + user 模板：[deepseek.py](../../experiments/exp_06_finetune/scripts/distill_v2/prompts/deepseek.py)
- 调用入口（教师 system 调 API，学生 system 组装训练数据）：[run_distill.py](../../experiments/exp_06_finetune/scripts/distill_v2/run_distill.py)
- 解析教师输出 + 组装 ChatML：[validate_sample.py](../../experiments/exp_06_finetune/scripts/distill_v2/validate_sample.py)
