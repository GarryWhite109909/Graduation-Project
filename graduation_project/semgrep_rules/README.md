# Semgrep Taint 规则目录

两阶段架构 Stage 1（工具召回）使用的 Semgrep taint 规则。
`ExternalScanner.scan_taint()` 会对**整文件**运行本目录下所有规则，
返回带完整污点路径的候选 finding，供 Stage 2 LLM 裁决层判定真伪。

## 为什么用 taint mode

长文件切片后，chunk A 的 source 与 chunk B 的 sink 会被割裂。正确解法不是
缝合 chunk，而是对原始整文件跑一次 Semgrep taint，把完整 source→sink 路径
注入裁决上下文。

## 如何新增一个 CWE 的 taint 规则

1. 在本目录新建 `<cwe>_taint.yaml`。
2. 结构：

   ```yaml
   rules:
     - id: python-<name>-taint
       mode: taint
       message: "污点命中：用户可控输入流入 <危险操作>，疑似 <漏洞名>（待 LLM 裁决）"
       severity: ERROR
       languages: [python]
       metadata:
         cwe: "CWE-<编号>"   # 显式标注 CWE，供裁决层归因
       pattern-sources:
         - pattern: request.GET.get(...)
         - pattern: input(...)          # 按该语言的实际输入点补充
       pattern-sinks:
         - pattern: <危险函数>(...)      # 该 CWE 的危险点
       options:
         taint_assume_safe_functions: false   # 必须 false，否则库函数会切断污点链
   ```

3. 运行方式（无需改代码）：

   ```bash
   semgrep --json --quiet --config graduation_project/semgrep_rules <file>
   ```

   `ExternalScanner.scan_taint()` 已自动加载本目录全部规则。

## 规则语义约定

- **只召回，不终判**：规则命中只是"候选"，不直接判漏洞。有效防御（参数化
  查询、列表参数 subprocess、转义等）会命中造成召回误报，这是设计使然——
  Stage 2 裁决层负责识别并放行。
- **message 不用 $SOURCE / $SINK**：实测 semgrep OSS（1.172）taint 结果的 JSON
  不注入 metavar、也不含 dataflow_trace——message 里的 `$SOURCE` 会原样打印。
  finding 的 start 行即 sink 行；source 位置由 `TaintTracker`（AST 轻量污点）
  或 Stage 2 裁决层补全。
- **taint_assume_safe_functions 必须 false**：实测 true 会把 `os.path.join`
  等库函数当成消毒点切断污点链（cve_fix_0012 的 request.form.get →
  os.path.join → subprocess.run(shell=True) 曾漏报）。真实消毒函数用
  `pattern-sanitizers` 显式声明（如 shlex.quote / int 类型收敛）。
- **sources 必须含路由路径参数**：`@app.route("/x/<id>")` 绑定的形参是用户
  可控输入（cve_fix_0009 的 charge_id SQLi 曾因缺此 source 漏报）。

## 现有规则

- `sqli_taint.yaml`（python-sqli-taint）：SQL 注入，CWE-89
- `cmdi_taint.yaml`（python-cmdi-taint）：命令注入，CWE-78
- `codei_taint.yaml`（python-codei-taint）：代码注入（eval/exec），CWE-95
  —— 从 cmdi 拆出；eval/exec 是代码注入而非命令注入，混归会污染裁决层 CWE 归因

## 局限

- 目前仅 SQLi / Cmdi / Codei 三条规则，覆盖度有限。缺的 CWE 由 `TaintTracker`
  （AST 轻量污点）兜底召回，且后续抽样复核（P2）会把漏报案例回流为新的
  taint 规则。
