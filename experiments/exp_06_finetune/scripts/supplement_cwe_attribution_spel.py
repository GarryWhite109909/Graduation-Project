"""
表达式注入（CWE-917）CWE 归因推理补充样本生成。

背景：
  微调后模型把 SpEL/OGNL 表达式注入误标为 CWE-89（SQL 注入），根因是训练数据
  CoT 缺少 "CWE 归因推理" 步骤——模型没学到如何区分 CWE-917 与 CWE-89。本脚本
  生成 8 条高质量表达式注入样本（6 漏洞 + 2 安全），CoT 第 5 步显式推理"为什么
  是 CWE-917 而不是 CWE-89/78/94"，覆盖 Spring SpEL / Apache OGNL / Commons JEXL /
  GroovyShell / MVEL 等主流表达式引擎。

  漏洞样本的 CoT 必须包含 6 步，第 5 步"CWE 归因"显式排除 CWE-89、CWE-78 和
  CWE-94，确定 CWE-917；安全样本的 CoT 第 5 步显式说明为何不构成 CWE-917。

输出：
  data/supplement_cwe_attribution_spel.jsonl（8 条 ChatML 样本）

用法：
  cd /home/zane/文档/code/毕业设计
  PYTHONPATH=. /home/zane/miniconda3/envs/graproj/bin/python \
      experiments/exp_06_finetune/scripts/supplement_cwe_attribution_spel.py
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import build_user_prompt

OUTPUT_FILE = PROJECT_ROOT / "experiments/exp_06_finetune/data/supplement_cwe_attribution_spel.jsonl"

# ---------------------------------------------------------------------------
# SYSTEM_PROMPT_LITE（固定，每条样本通用）
# ---------------------------------------------------------------------------
SYSTEM_PROMPT_LITE = (
    "你是一名资深的代码安全审计专家。请对给出的代码片段进行安全分析，"
    "判断其中是否存在安全漏洞。分析范围包括但不限于："
    "SQL 注入、跨站脚本（XSS）、命令注入、路径穿越、"
    "硬编码敏感信息（密钥/密码/Token）、不安全的反序列化、"
    "日志注入（CWE-117）、弱密码学（MD5/SHA1 哈希密码、CWE-327）、"
    "弱随机数（random 模块生成 token、CWE-330）、CSRF、"
    "SSTI、XXE、SSRF、未授权访问、安全配置错误、文件上传、"
    "会话固定、LDAP 注入、NoSQL 注入、XPath 注入、表达式注入（SpEL/OGNL）。\n\n"
    "要求：\n"
    "1. 仔细阅读代码语义，结合上下文判断用户可控输入是否被安全处理。\n"
    "2. 不要夸大风险，也不要遗漏明显的漏洞。\n"
    "3. 判定必须基于代码实际内容，不能凭空臆造 API 参数或行为。\n"
    "4. 用户输入到达 sink 不等于漏洞，必须看 sink 前的防御措施是否有效。\n"
    "5. 硬编码的字面量凭证（key/secret/password/token）本身就是漏洞，"
    "不要降级为“敏感但非漏洞”。\n"
    "6. 结论一致性校验：JSON 的 has_vulnerability 必须与上述分析过程的推理结论一致。"
    "若分析过程中识别出风险（如“弱随机”“不安全”“存在漏洞”），JSON 不得标 false；"
    "若分析过程未识别出风险，JSON 不得标 true。\n\n"
    "在回答的最后，必须严格输出一个 JSON 对象作为最终结论，"
    "JSON 块用 ```json 包裹，字段如下（统一 schema，全项目一致）：\n"
    "- has_vulnerability: boolean\n"
    "- vulnerability_type: string（如 \"CWE-89 SQL注入\" 或 \"none\"）\n"
    "- risk_level: string（\"Critical\"/\"High\"/\"Medium\"/\"Low\"/\"none\"）\n"
    "- source: string（污染源，如 \"request.args.get('id')\"）\n"
    "- sink: string（危险 sink）\n"
    "- taint_path: string（数据流路径）\n"
    "- explanation: string（简要说明）\n\n"
    "请先给出分析过程，然后在最后给出 JSON 结论。"
)


# ===========================================================================
# 样本定义：8 条（6 漏洞 + 2 安全）
# 每条含 code / language / filename / cot / verdict
# CoT 第 5 步为 CWE 归因，显式区分 CWE-917 与 CWE-89/78/94
# ===========================================================================
SAMPLES = [
    # =====================================================================
    # 漏洞样本 1: Spring SpelExpressionParser.parseExpression(expr).getValue()
    # =====================================================================
    {
        "filename": "spel_01_spring_parse.java",
        "language": "java",
        "code": '''import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class EvalController {
    private final SpelExpressionParser parser = new SpelExpressionParser();

    @GetMapping("/eval")
    @ResponseBody
    public String eval(@RequestParam String expr) {
        Expression expression = parser.parseExpression(expr);
        return expression.getValue(String.class);
    }
}''',
        "cot": """分析过程：
1. 污染源：@RequestParam String expr 获取用户输入。
2. 危险 sink：parser.parseExpression(expr).getValue(String.class) 将用户输入作为 SpEL 表达式解析并求值。
3. 数据流：expr → parser.parseExpression 解析为 Expression → getValue 执行表达式。
4. 防御检查：未指定 EvaluationContext，默认使用无限制的上下文，未限制可访问的类和方法，未对 expr 做白名单校验。
5. CWE 归因：
   - 漏洞类型：表达式注入（SpEL）
   - 排除 CWE-89（SQL 注入）：不涉及 SQL 语句和关系型数据库，用户输入未进入 JDBC/ORM 查询
   - 排除 CWE-78（命令注入）：不直接执行系统命令，而是通过表达式引擎执行代码
   - 排除 CWE-94（代码注入）：不是通过模板引擎或 eval 执行，而是通过表达式语言（EL）引擎
   - 确定 CWE-917（表达式语言注入）：用户输入进入 SpEL 表达式语言引擎，可构造 T(java.lang.Runtime).getRuntime().exec('id') 访问任意类和方法实现 RCE
6. 结论：用户输入直接作为 SpEL 表达式解析求值，无 EvaluationContext 限制，可构造恶意表达式访问任意类实现 RCE，存在表达式注入漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 表达式注入（SpEL）",
            "risk_level": "Critical",
            "source": "@RequestParam String expr",
            "sink": "parser.parseExpression(expr).getValue(String.class)",
            "taint_path": "expr → parser.parseExpression 解析 → getValue 执行表达式",
            "explanation": "用户输入直接作为 SpEL 表达式解析求值，默认无 EvaluationContext 限制，攻击者可注入 T(java.lang.Runtime).getRuntime().exec('id') 实现 RCE",
        },
    },
    # =====================================================================
    # 漏洞样本 2: Spring SpEL getValue + StandardEvaluationContext
    # =====================================================================
    {
        "filename": "spel_02_spring_getvalue.java",
        "language": "java",
        "code": '''import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class EvalController {
    private final SpelExpressionParser parser = new SpelExpressionParser();

    @GetMapping("/compute")
    @ResponseBody
    public String compute(@RequestParam String input) {
        StandardEvaluationContext context = new StandardEvaluationContext();
        Expression expression = parser.parseExpression(input);
        return expression.getValue(context, String.class);
    }
}''',
        "cot": """分析过程：
1. 污染源：@RequestParam String input 获取用户输入。
2. 危险 sink：parser.parseExpression(input).getValue(context, String.class) 将用户输入作为 SpEL 表达式在指定上下文求值。
3. 数据流：input → parser.parseExpression 解析为 Expression → getValue(context) 在 StandardEvaluationContext 中执行。
4. 防御检查：使用了 StandardEvaluationContext，但该上下文默认不限制可访问的类和方法（允许 T() 类型引用、方法调用、反射访问），未启用 SimpleEvaluationContext，未对 input 做白名单校验。
5. CWE 归因：
   - 漏洞类型：表达式注入（SpEL）
   - 排除 CWE-89（SQL 注入）：不涉及 SQL 语句和关系型数据库，用户输入未进入 JDBC/ORM 查询
   - 排除 CWE-78（命令注入）：不直接执行系统命令，而是通过表达式引擎执行代码
   - 排除 CWE-94（代码注入）：不是通过模板引擎或 eval 执行，而是通过表达式语言（EL）引擎
   - 确定 CWE-917（表达式语言注入）：用户输入进入 SpEL 表达式语言引擎，StandardEvaluationContext 默认无限制，可构造 T(java.lang.Runtime).getRuntime().exec('id') 实现任意方法调用与 RCE
6. 结论：用户输入作为 SpEL 表达式求值，StandardEvaluationContext 默认无限制访问任意类和方法，可构造恶意表达式实现 RCE，存在表达式注入漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 表达式注入（SpEL）",
            "risk_level": "Critical",
            "source": "@RequestParam String input",
            "sink": "parser.parseExpression(input).getValue(context, String.class)",
            "taint_path": "input → parser.parseExpression 解析 → getValue(StandardEvaluationContext) 执行",
            "explanation": "用户输入作为 SpEL 表达式求值，StandardEvaluationContext 默认允许 T() 类型引用和方法调用，攻击者可注入 T(java.lang.Runtime).getRuntime().exec('id') 实现 RCE",
        },
    },
    # =====================================================================
    # 漏洞样本 3: Apache OGNL getValue
    # =====================================================================
    {
        "filename": "spel_03_ognl.java",
        "language": "java",
        "code": '''import ognl.Ognl;
import ognl.OgnlContext;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class EvalController {
    @GetMapping("/ognl")
    @ResponseBody
    public String ognl(@RequestParam String expr) throws Exception {
        OgnlContext context = Ognl.createDefaultContext(null);
        Object result = Ognl.getValue(expr, context, null);
        return result.toString();
    }
}''',
        "cot": """分析过程：
1. 污染源：@RequestParam String expr 获取用户输入。
2. 危险 sink：Ognl.getValue(expr, context, null) 将用户输入作为 OGNL 表达式求值。
3. 数据流：expr → Ognl.getValue 解析并执行 OGNL 表达式 → 返回结果 toString。
4. 防御检查：使用 Ognl.createDefaultContext 创建默认上下文，未启用 OgnlContext 的成员访问限制（setMemberAccess），未启用安全成员访问器，未对 expr 做白名单校验。
5. CWE 归因：
   - 漏洞类型：表达式注入（OGNL）
   - 排除 CWE-89（SQL 注入）：不涉及 SQL 语句和关系型数据库，用户输入未进入 JDBC/ORM 查询
   - 排除 CWE-78（命令注入）：不直接执行系统命令，而是通过表达式引擎执行代码
   - 排除 CWE-94（代码注入）：不是通过模板引擎或 eval 执行，而是通过表达式语言（EL）引擎
   - 确定 CWE-917（表达式语言注入）：用户输入进入 OGNL 表达式语言引擎，默认上下文无限制，可构造 @java.lang.Runtime@getRuntime().exec('id') 访问任意类的静态方法实现 RCE
6. 结论：用户输入直接作为 OGNL 表达式求值，默认上下文无安全限制，可构造恶意表达式调用任意类方法实现 RCE，存在表达式注入漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 表达式注入（OGNL）",
            "risk_level": "Critical",
            "source": "@RequestParam String expr",
            "sink": "Ognl.getValue(expr, context, null)",
            "taint_path": "expr → Ognl.getValue 解析执行 OGNL 表达式 → result.toString",
            "explanation": "用户输入直接作为 OGNL 表达式求值，默认上下文无安全成员访问限制，攻击者可注入 @java.lang.Runtime@getRuntime().exec('id') 实现 RCE",
        },
    },
    # =====================================================================
    # 漏洞样本 4: Apache Commons JEXL createExpression
    # =====================================================================
    {
        "filename": "spel_04_jexl.java",
        "language": "java",
        "code": '''import org.apache.commons.jexl2.JexlEngine;
import org.apache.commons.jexl2.JexlExpression;
import org.apache.commons.jexl2.MapContext;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class EvalController {
    private final JexlEngine jexl = new JexlEngine();

    @GetMapping("/jexl")
    @ResponseBody
    public String jexl(@RequestParam String expr) throws Exception {
        JexlExpression expression = jexl.createExpression(expr);
        return expression.evaluate(new MapContext()).toString();
    }
}''',
        "cot": """分析过程：
1. 污染源：@RequestParam String expr 获取用户输入。
2. 危险 sink：jexl.createExpression(expr).evaluate(new MapContext()) 将用户输入作为 JEXL 表达式编译并求值。
3. 数据流：expr → jexl.createExpression 编译为 JexlExpression → evaluate 在 MapContext 中执行。
4. 防御检查：JexlEngine 为默认配置，未启用沙箱（JexlSandbox），未限制可访问的类和方法，未对 expr 做白名单校验。
5. CWE 归因：
   - 漏洞类型：表达式注入（JEXL）
   - 排除 CWE-89（SQL 注入）：不涉及 SQL 语句和关系型数据库，用户输入未进入 JDBC/ORM 查询
   - 排除 CWE-78（命令注入）：不直接执行系统命令，而是通过表达式引擎执行代码
   - 排除 CWE-94（代码注入）：不是通过模板引擎或 eval 执行，而是通过表达式语言（EL）引擎
   - 确定 CWE-917（表达式语言注入）：用户输入进入 JEXL 表达式语言引擎，默认无沙箱限制，可构造 ' '.class.forName('java.lang.Runtime').getMethod('exec',...).invoke(...) 访问任意类和方法实现 RCE
6. 结论：用户输入直接作为 JEXL 表达式编译求值，默认无沙箱限制，可构造恶意表达式访问任意类实现 RCE，存在表达式注入漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 表达式注入（JEXL）",
            "risk_level": "Critical",
            "source": "@RequestParam String expr",
            "sink": "jexl.createExpression(expr).evaluate(new MapContext())",
            "taint_path": "expr → jexl.createExpression 编译 → evaluate 执行 JEXL 表达式",
            "explanation": "用户输入直接作为 JEXL 表达式编译求值，JexlEngine 默认无沙箱限制，攻击者可通过反射表达式访问任意类和方法实现 RCE",
        },
    },
    # =====================================================================
    # 漏洞样本 5: GroovyShell evaluate
    # =====================================================================
    {
        "filename": "spel_05_groovy.java",
        "language": "java",
        "code": '''import groovy.lang.GroovyShell;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class EvalController {
    @GetMapping("/groovy")
    @ResponseBody
    public String groovy(@RequestParam String script) {
        GroovyShell shell = new GroovyShell();
        Object result = shell.evaluate(script);
        return result.toString();
    }
}''',
        "cot": """分析过程：
1. 污染源：@RequestParam String script 获取用户输入。
2. 危险 sink：shell.evaluate(script) 将用户输入作为 Groovy 脚本/表达式解析并执行。
3. 数据流：script → GroovyShell.evaluate 编译并执行 Groovy 脚本 → 返回结果 toString。
4. 防御检查：GroovyShell 为默认配置，未使用 GroovyCodeSource 限制脚本来源，未启用 SecureASTCustomizer（AST 安全限制器）限制可调用的类和方法，未对 script 做白名单校验。
5. CWE 归因：
   - 漏洞类型：表达式注入（Groovy）
   - 排除 CWE-89（SQL 注入）：不涉及 SQL 语句和关系型数据库，用户输入未进入 JDBC/ORM 查询
   - 排除 CWE-78（命令注入）：不直接通过 Runtime.exec 执行系统命令，而是通过表达式引擎执行代码
   - 排除 CWE-94（代码注入）：不是通过模板引擎执行，而是通过表达式语言（EL）引擎（Groovy 作为动态表达式引擎使用）
   - 确定 CWE-917（表达式语言注入）：用户输入进入 Groovy 表达式语言引擎，未启用 AST 安全限制，可构造 'id'.execute() 或 Runtime.getRuntime().exec('id') 访问任意类和方法实现 RCE
6. 结论：用户输入直接作为 Groovy 脚本执行，未启用 SecureASTCustomizer 限制，可构造恶意表达式调用任意类方法实现 RCE，存在表达式注入漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 表达式注入（Groovy）",
            "risk_level": "Critical",
            "source": "@RequestParam String script",
            "sink": "shell.evaluate(script)",
            "taint_path": "script → GroovyShell.evaluate 编译执行 → result.toString",
            "explanation": "用户输入直接作为 Groovy 脚本执行，未启用 SecureASTCustomizer 安全限制，攻击者可注入 'id'.execute() 或 Runtime.getRuntime().exec('id') 实现 RCE",
        },
    },
    # =====================================================================
    # 漏洞样本 6: MVEL eval
    # =====================================================================
    {
        "filename": "spel_06_mvel.java",
        "language": "java",
        "code": '''import org.mvel2.MVEL;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class EvalController {
    @GetMapping("/mvel")
    @ResponseBody
    public String mvel(@RequestParam String expr) {
        Object result = MVEL.eval(expr);
        return result.toString();
    }
}''',
        "cot": """分析过程：
1. 污染源：@RequestParam String expr 获取用户输入。
2. 危险 sink：MVEL.eval(expr) 将用户输入作为 MVEL 表达式直接求值。
3. 数据流：expr → MVEL.eval 编译并执行 MVEL 表达式 → 返回结果 toString。
4. 防御检查：MVEL.eval 使用默认配置，未启用沙箱限制可访问的类和方法，未对 expr 做白名单校验。
5. CWE 归因：
   - 漏洞类型：表达式注入（MVEL）
   - 排除 CWE-89（SQL 注入）：不涉及 SQL 语句和关系型数据库，用户输入未进入 JDBC/ORM 查询
   - 排除 CWE-78（命令注入）：不直接执行系统命令，而是通过表达式引擎执行代码
   - 排除 CWE-94（代码注入）：不是通过模板引擎或 eval 执行，而是通过表达式语言（EL）引擎
   - 确定 CWE-917（表达式语言注入）：用户输入进入 MVEL 表达式语言引擎，默认无沙箱限制，可构造 Runtime.getRuntime().exec('id') 访问任意类和方法实现 RCE
6. 结论：用户输入直接作为 MVEL 表达式求值，默认无安全限制，可构造恶意表达式调用任意类方法实现 RCE，存在表达式注入漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-917 表达式注入（MVEL）",
            "risk_level": "Critical",
            "source": "@RequestParam String expr",
            "sink": "MVEL.eval(expr)",
            "taint_path": "expr → MVEL.eval 编译执行 MVEL 表达式 → result.toString",
            "explanation": "用户输入直接作为 MVEL 表达式求值，默认无沙箱限制，攻击者可注入 Runtime.getRuntime().exec('id') 实现 RCE",
        },
    },
    # =====================================================================
    # 安全样本 7: SpEL SimpleEvaluationContext
    # =====================================================================
    {
        "filename": "safe_spel_01_simple_context.java",
        "language": "java",
        "code": '''import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class EvalController {
    private final SpelExpressionParser parser = new SpelExpressionParser();

    @GetMapping("/compute")
    @ResponseBody
    public String compute(@RequestParam String input) {
        SimpleEvaluationContext context = SimpleEvaluationContext
                .forReadOnlyDataBinding().build();
        Expression expression = parser.parseExpression(input);
        return expression.getValue(context, String.class);
    }
}''',
        "cot": """分析过程：
1. 污染源：@RequestParam String input 获取用户输入。
2. 危险 sink：parser.parseExpression(input).getValue(context, String.class) 将用户输入作为 SpEL 表达式在 SimpleEvaluationContext 中求值。
3. 数据流：input → parser.parseExpression 解析为 Expression → getValue(context) 在 SimpleEvaluationContext 中执行。
4. 防御检查：使用了 SimpleEvaluationContext.forReadOnlyDataBinding().build()，该上下文限制了可访问的类和方法——禁止 T() 类型引用、禁止反射方法调用、禁止写操作，仅允许只读数据绑定和属性访问。
5. CWE 归因：
   - 不构成 CWE-917（表达式注入）：使用了 SimpleEvaluationContext 限制了可访问的类和方法，禁止 T() 类型引用和反射方法调用，表达式引擎无法访问任意类
   - 即使表达式文本由用户控制，也无法构造 T(java.lang.Runtime) 等危险表达式，攻击面被限制为只读属性访问
6. 结论：安全，使用了 SimpleEvaluationContext 限制了可访问的类和方法，禁止类型引用和反射调用，表达式引擎无法访问任意类，未发现漏洞。""",
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "none",
            "source": "none",
            "sink": "none",
            "taint_path": "none",
            "explanation": "使用了 SimpleEvaluationContext.forReadOnlyDataBinding() 限制了可访问的类和方法，禁止 T() 类型引用和反射方法调用，表达式引擎无法访问任意类实现 RCE",
        },
    },
    # =====================================================================
    # 安全样本 8: SpEL + 白名单校验
    # =====================================================================
    {
        "filename": "safe_spel_02_whitelist.java",
        "language": "java",
        "code": '''import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import java.util.regex.Pattern;

@Controller
public class EvalController {
    private final SpelExpressionParser parser = new SpelExpressionParser();
    private static final Pattern SAFE_EXPR =
            Pattern.compile("^[a-zA-Z0-9_+\\\\-*/.() ]+$");

    @GetMapping("/compute")
    @ResponseBody
    public String compute(@RequestParam String input) {
        if (!SAFE_EXPR.matcher(input).matches()) {
            return "invalid expression";
        }
        Expression expression = parser.parseExpression(input);
        return expression.getValue(String.class);
    }
}''',
        "cot": """分析过程：
1. 污染源：@RequestParam String input 获取用户输入。
2. 危险 sink：parser.parseExpression(input).getValue(String.class) 将用户输入作为 SpEL 表达式解析并求值。
3. 数据流：input → SAFE_EXPR.matcher(input).matches() 白名单校验 → 通过后 parser.parseExpression 解析 → getValue 执行。
4. 防御检查：在进入表达式引擎前使用正则白名单 ^[a-zA-Z0-9_+\\-*/.() ]+$ 校验输入，仅允许字母、数字、下划线和算术运算符，禁止 T()、点号链接的类路径外的特殊字符（如单引号、分号、冒号），阻断了 T(java.lang.Runtime) 这类类型引用表达式。
5. CWE 归因：
   - 不构成 CWE-917（表达式注入）：对用户输入做了白名单校验，仅允许算术运算和属性访问字符，禁止 T() 类型引用所需的关键字和特殊字符
   - 表达式引擎虽默认无 EvaluationContext 限制，但白名单校验在 sink 前已阻断危险表达式构造，攻击者无法注入访问任意类的恶意表达式
6. 结论：安全，在进入表达式引擎前对用户输入做了白名单校验，仅允许算术运算和属性访问字符，阻断了类型引用和方法调用表达式，未发现漏洞。""",
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "none",
            "source": "none",
            "sink": "none",
            "taint_path": "none",
            "explanation": "在进入 SpEL 引擎前使用正则白名单校验输入，仅允许算术运算和属性访问字符，禁止 T() 类型引用和反射调用所需的特殊字符，阻断了恶意表达式构造",
        },
    },
]


# ===========================================================================
# 构建与写入逻辑
# ===========================================================================
def build_sample(sample: dict) -> dict:
    """构建一条 ChatML 样本。"""
    user_prompt = build_user_prompt(
        code=sample["code"], language=sample["language"], filename=sample["filename"]
    )
    json_str = json.dumps(sample["verdict"], ensure_ascii=False, indent=2)
    assistant_content = f"{sample['cot']}\n\n```json\n{json_str}\n```"
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_LITE},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": assistant_content},
        ]
    }


def verify_output(filepath: Path) -> None:
    """验证输出文件：合法 JSON、3 条消息、json 块可解析、CWE 归因正确。"""
    print("\n=== 验证输出文件 ===")
    with open(filepath, encoding="utf-8") as f:
        lines = [l for l in f if l.strip()]

    errors = []
    cwe_counter = Counter()

    for i, line in enumerate(lines, 1):
        # 1. 合法 JSON
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            errors.append(f"行 {i}: JSON 解析失败 - {e}")
            continue

        # 2. messages 有 3 条
        messages = obj.get("messages", [])
        if len(messages) != 3:
            errors.append(f"行 {i}: messages 数量为 {len(messages)}，期望 3")
            continue

        roles = [m["role"] for m in messages]
        if roles != ["system", "user", "assistant"]:
            errors.append(f"行 {i}: roles 为 {roles}，期望 [system, user, assistant]")
            continue

        # 3. assistant content 包含可解析的 ```json 块
        assistant_content = messages[2]["content"]
        json_blocks = re.findall(r"```json\s*(\{.*?\})\s*```", assistant_content, re.DOTALL)
        if not json_blocks:
            errors.append(f"行 {i}: assistant content 中未找到 ```json 块")
            continue

        verdict = None
        for block in json_blocks:
            try:
                verdict = json.loads(block)
                break
            except json.JSONDecodeError:
                continue
        if verdict is None:
            errors.append(f"行 {i}: JSON 块无法解析")
            continue

        has_vuln = verdict.get("has_vulnerability")
        vuln_type = verdict.get("vulnerability_type", "")

        # 4. 漏洞样本的 vulnerability_type 包含 "CWE-917"
        if has_vuln is True:
            if "CWE-917" not in vuln_type:
                errors.append(f"行 {i}: 漏洞样本 vulnerability_type 为 '{vuln_type}'，缺少 'CWE-917'")
            cwe_counter[vuln_type] += 1
        # 5. 安全样本的 has_vulnerability 为 false
        elif has_vuln is False:
            if vuln_type != "none":
                errors.append(f"行 {i}: 安全样本 vulnerability_type 为 '{vuln_type}'，期望 'none'")
            cwe_counter["none（安全）"] += 1
        else:
            errors.append(f"行 {i}: has_vulnerability 为 {has_vuln}，非布尔值")

    if errors:
        print(f"发现 {len(errors)} 个错误：")
        for e in errors:
            print(f"  [ERROR] {e}")
    else:
        print("所有验证通过：")
        print(f"  - {len(lines)} 条样本均为合法 JSON")
        print(f"  - 每条 messages 数组有 3 条（system/user/assistant）")
        print(f"  - assistant content 的 ```json 块均可解析")
        print(f"  - 漏洞样本 vulnerability_type 均包含 'CWE-917'")
        print(f"  - 安全样本 has_vulnerability 均为 false")

    print(f"\nCWE 分布统计：")
    for k, v in cwe_counter.most_common():
        print(f"  {v}  {k}")


def main():
    print(f"生成 {len(SAMPLES)} 条表达式注入（CWE-917）CWE 归因推理补充样本")
    vuln_count = sum(1 for s in SAMPLES if s["verdict"]["has_vulnerability"])
    safe_count = len(SAMPLES) - vuln_count
    print(f"  漏洞样本: {vuln_count} 条")
    print(f"  安全样本: {safe_count} 条")
    print(f"输出: {OUTPUT_FILE}")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for s in SAMPLES:
            chatml = build_sample(s)
            f.write(json.dumps(chatml, ensure_ascii=False) + "\n")

    # 确认写入数量
    with open(OUTPUT_FILE, encoding="utf-8") as f:
        lines = [l for l in f if l.strip()]
    print(f"\n已写入 {len(lines)} 条样本")

    # CWE 分布统计
    cwe_counter = Counter()
    for s in SAMPLES:
        v = s["verdict"]
        if v["has_vulnerability"]:
            cwe_counter[v["vulnerability_type"]] += 1
        else:
            cwe_counter["none（安全）"] += 1
    print(f"\nCWE 分布统计：")
    for k, v in cwe_counter.most_common():
        print(f"  {v}  {k}")

    # 验证
    verify_output(OUTPUT_FILE)


if __name__ == "__main__":
    main()
