## 最终成果
格式对齐 —— 核心目标达成：

- 模型不再输出 fix_code （0/20），回归 fix_suggestion 围栏代码（18/20）
- fix_extracted 从 0 → 17 ，评估脚本能正确抽取并校验修复代码了
- 改动： schema.py + vllm_client.py + llm_client.py 删 fix_code ；prompts.py / evaluate.py 动态渲染自动对齐
检测指标维持： recall 0.95、strict_recall 0.65

fix_usable 仍 0，但瓶颈已转移： 不再是"抽不到代码"，而是 FixVerifier 的 tests_passed 判定——11 个 null（危险模式检测覆盖不足）、3 个危险模式仍在、2 个语法错误。要提升需改 FixVerifier，与数据格式无关。

FN 翻转（recall 不变）： 0006（CWE-441）从 FN→TP（真漏洞现在检出了），0003（CWE-95 eval via A2A RPC）从 TP→FN（模型把 eval() 合理化 为安全）。两个都是真漏洞、都是"被上下文迷惑"类。

v9max.md 已完整记录：根因、对齐工作、重评估结果、FN 分析。

## 后续可选方向（需要时再说）
1. 提升 fix_usable ：改进 FixVerifier 危险模式检测覆盖面，或用 fix_extracted + fix_syntax_ok （17/15）作代理指标
2. 攻克 0003 类 FN ：训练数据补"eval 封装在函数但仍远程可控"的反模式