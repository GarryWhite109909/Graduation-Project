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
       message: "用户可控输入($SOURCE)流入 <危险操作>($SINK)，疑似 <漏洞名>（待 LLM 裁决）"
       severity: ERROR
       languages: [python]
       pattern-sources:
         - pattern: request.GET.get(...)
         - pattern: input(...)          # 按该语言的实际输入点补充
       pattern-sinks:
         - pattern: <危险函数>(...)      # 该 CWE 的危险点
       options:
         taint_assume_safe_functions: true
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
- **message 用 $SOURCE / $SINK**：semgrep 会向 `extra.metavars` 自动注入
  这两个 metavar（source/sink 的实际表达式与位置），
  `scan_taint()` 据此填充 `ToolFinding.source/sink/path`。

## 局限

- 初始仅 SQLi / Cmdi 两条规则，覆盖度有限。缺的 CWE 由 `TaintTracker`
  （AST 轻量污点）兜底召回，且后续抽样复核（P2）会把漏报案例回流为新的
  taint 规则。
