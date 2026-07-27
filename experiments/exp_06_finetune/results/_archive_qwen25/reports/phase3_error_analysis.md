# Phase 3 KnItLM 错题分析与 Phase 1 回归检查

> 自动生成：对比 Phase 1 baseline (exp_06_eval.phase1_lr1e-5_base.20260718_151305.json) vs Phase 3 KnItLM (exp_06_eval.knitlm_merged.20260719_070818.json)
> 共有样本 87 个，Phase 3 残留错题 23 个，Phase 1→3 回归 4 个，Phase 1→3 修复 20 个

## 1. Phase 3 KnItLM 残留错题（论文错误分析章节素材）

| file | category | outcome | expected_cwe | model_cwe | 类别提示 |
|------|----------|---------|--------------|-----------|----------|
| hard_bypass_06_auth_string_compare.py | timing_attack | TP (CWE错) | CWE-208 | CWE-798 | 未分类 |
| hard_bypass_07_ssti_attr_chain.py | ssti | TP (CWE错) | CWE-1336 | CWE-94 | SSTI概念混淆 |
| hard_bypass_08_jwt_none_alg.py | jwt_confusion | TP (CWE错) | CWE-347 | CWE-306 | 未分类 |
| hard_crossfile_02_sink.py | path_traversal | FN  | CWE-22 |  | 跨文件认知 |
| hard_crossfile_03_input.py | cross_file_helper | FP  | N/A | CWE-209 | 未分类 |
| hard_crossfile_03_sink.py | idor | TP (CWE错) | CWE-639 | CWE-862 | missing_feature |
| hard_cve_03_tarfile_2025_4517.py | path_traversal | FN  | CWE-22 |  | 未分类 |
| hard_cve_05_spring4shell.java | cve_real | TP (CWE错) | CWE-915 | CWE-94 | 未分类 |
| hard_cve_06_struts2_ognl.java | cve_real | TP (CWE错) | CWE-917 | CWE-94 | 未分类 |
| hard_longfile_01_hidden_sql.py | sql_injection | FN  | CWE-89 |  | 未分类 |
| hard_longfile_03_hidden_ssti.py | ssti | TP (CWE错) | CWE-1336 | CWE-94 | SSTI概念混淆, missing_feature |
| hard_owasp_01_file_upload.py | unrestricted_upload | FN  | CWE-434; CWE-22 |  | 未分类 |
| hard_owasp_02_dvwa_sql.py | sql_injection | FN  | CWE-89 |  | 未分类 |
| typical_13_auth_bypass.py | missing_authentication | TP (CWE错) | CWE-306 | CWE-862 | 未分类 |
| typical_14_idor.py | idor | TP (CWE错) | CWE-639 | CWE-611 | 结论漂移, missing_feature |
| typical_18_hardcoded_iv.py | weak_cryptography | TP (CWE错) | CWE-329 | CWE-327 | 未分类 |
| typical_20_insecure_tls.py | insecure_tls | TP (CWE错) | CWE-295 | CWE-89 | CWE-89错标SSTI |
| typical_23_ssti.py | ssti | TP (CWE错) | CWE-1336 | CWE-94 | SSTI概念混淆 |
| typical_24_ldap_injection.py | ldap_injection | TP (CWE错) | CWE-90 | CWE-918 | 未分类 |
| typical_25_nosql_injection.py | nosql_injection | FN  | CWE-943 |  | 未分类 |
| typical_30_mass_assignment.py | mass_assignment | TP (CWE错) | CWE-915 | CWE-918 | 未分类 |
| typical_32_proto_pollution.js | prototype_pollution | TP (CWE错) | CWE-1321 | CWE-948 | 未分类 |
| typical_33_php_type_juggling.php | type_juggling | TP (CWE错) | CWE-843 | CWE-89 | CWE-89错标SSTI |

### 1.1 错题类别分布

| 类别 | 数量 |
|------|------|
| 未分类 | 15 |
| SSTI概念混淆 | 3 |
| missing_feature | 3 |
| CWE-89错标SSTI | 2 |
| 跨文件认知 | 1 |
| 结论漂移 | 1 |

## 2. Phase 1 答对、Phase 3 答错的样本（KnItLM 回归）

⚠️ 共 4 个回归样本。需检查是否 KnItLM CPT 引入了保守化倾向。

| file | category | P1→P3 outcome | expected_cwe | 类别提示 |
|------|----------|---------------|--------------|----------|
| hard_crossfile_02_sink.py | path_traversal | TP→FN | CWE-22 | 跨文件认知 |
| hard_crossfile_03_input.py | cross_file_helper | TN→FP | N/A | 未分类 |
| hard_longfile_01_hidden_sql.py | sql_injection | TP→FN | CWE-89 | 未分类 |
| hard_owasp_02_dvwa_sql.py | sql_injection | TP→FN | CWE-89 | 未分类 |

### 2.1 回归样本 raw_output 摘录（人工审阅）

#### hard_crossfile_02_sink.py（TP→FN）
- expected_present: True, expected_cwe: CWE-22
- P3 model_vulnerability_type: none
- 类别提示: 跨文件认知

```
### 分析过程

1. **输入源**：`filename` 来自 `request.args.get("file", "")`，是用户可控输入。
2. **处理逻辑**：`safe_read_file` 函数使用 `os.path.join(base_dir, filename)` 将 `base_dir` 和 `filename` 组合成完整路径，然后打开并读取文件。
3. **sink**：`with open(filepath, "r") as f: return f.read()` 执行文件读取操作。
4. **路径穿越检查**：
   - `os.path.join(base_dir, filename)` 会将 `filename` 与 `base_dir` 连接，形成绝对路径。
   - 如果 `filename` 包含 `../`，`os.path.join` 会将其转换为相对路径，但由于 `base_dir` 是 `/var/www/files`，最终路径仍然指向 `/var/www/files` 目录下的某个文件。
   - 例如，如果 `filename` 是 `../../etc/passwd`，`os.path.join("/var/www/files", "../../etc/passwd")` 会变成 `/var/www/files/../etc/passwd`，简化后仍然是 `/etc/passwd`，但由于 `base_dir` 已经限制了目录，实际路径不会越界到系统目录。
5. **安全措施**：
   - `os.path.join` 通过规范化路径确保路径在 `base_dir` 内部。
   - 即使 `filename` 包含 `../`，最终路径也不会越界到系统目录。
   - 这种路径拼接方式是 Python 标准库推荐的
```

#### hard_crossfile_03_input.py（TN→FP）
- expected_present: False, expected_cwe: N/A
- P3 model_vulnerability_type: CWE-209 数据泄露
- 类别提示: 未分类

```
### 分析过程

1. **输入源**：`user_id` 是从 `request` 中获取的参数。
2. **处理逻辑**：`get_user_by_id` 函数直接将 `user_id` 用于构建返回的用户对象。
3. **sink**：函数返回一个包含 `user_id` 的字典。
4. **检查防御措施**：
   - `user_id` 直接拼接到用户名和电子邮件中。
   - 没有对 `user_id` 进行任何转义或验证。
   - 数据库查询是通过 `return {"id": user_id, ...}` 实现的，而不是通过 SQL 执行。
5. **风险评估**：
   - 虽然没有 SQL 注入的风险，但 `user_id` 直接进入响应体可能暴露内部结构。
   - 如果 `user_id` 是敏感信息（如信用卡号），泄露后可能导致进一步攻击。
   - 由于 `user_id` 在响应中可见，这属于数据泄露风险。

### 结论

```json
{
  "has_vulnerability": true,
  "vulnerability_type": "CWE-209 数据泄露",
  "risk_level": "Medium",
  "source": "request.args.get('user_id')",
  "sink": "return {'id': user_id, ...}",
  "explanation": "user_id 直接拼接到用户名和电子邮件中，并通过 HTTP 响应返回。虽然没有 SQL 注入，但泄露了内部结构，特别是如果 user_id 包含敏感信息",
  "fix_suggestion": "避免将敏感信息直接暴露在响应中。使用脱敏处理，只返回必要的公共信息"
}
```
```

#### hard_longfile_01_hidden_sql.py（TP→FN）
- expected_present: True, expected_cwe: CWE-89
- P3 model_vulnerability_type: none
- 类别提示: 未分类

```
### 分析过程

1. **代码结构**：
   - 代码分为多个模块：用户管理、会话管理、输入校验、用户仓储、通知服务、审计日志和统计报表。
   - 使用了 `sqlite3` 进行数据库操作，所有 SQL 查询都通过参数化查询执行。

2. **SQL 注入防护**：
   - 所有 SQL 查询都使用了 `?` 占位符，并通过元组传递参数。
   - 例如：
     ```python
     cur.execute("SELECT * FROM users WHERE username = ?", (username,))
     ```
   - 即使是动态表名或列名，也通过预编译查询实现：
     ```python
     query = "SELECT * FROM " + table + " ORDER BY id DESC LIMIT 100"
     cur.execute(query)
     ```

3. **输入校验**：
   - 用户输入（如用户名、邮箱、角色）经过正则表达式校验，确保符合预期格式。
   - 例如：
     ```python
     def validate_username(username: str) -> bool:
         return bool(username and USERNAME_RE.match(username))
     ```

4. **密码存储**：
   - 密码使用 `hashlib.pbkdf2_hmac` 进行哈希存储，而不是明文存储。
   - 例如：
     ```python
     def hash_password(password: str) -> str:
         digest = hashlib.pbkdf2_hmac(
```

#### hard_owasp_02_dvwa_sql.py（TP→FN）
- expected_present: True, expected_cwe: CWE-89
- P3 model_vulnerability_type: none
- 类别提示: 未分类

```
### 分析过程

1. **污染源**：`request.args.get("id", "")` 获取用户输入 `id_param`。
2. **危险 sink**：`cursor.execute(query)` 执行 SQL 查询。
3. **数据流**：`id_param` 直接拼接到 SQL 字符串中，形成 `f"SELECT first_name, last_name FROM users WHERE user_id = {id_param}"`。
4. **安全检查**：
   - 代码使用了参数化查询（`?` 占位符），而不是字符串拼接。
   - `cursor.execute(query)` 中的 `query` 是包含占位符的字符串，`id_param` 作为单独的参数传递给 `execute` 方法。
   - 这是正确的做法，因为即使 `id_param` 包含 SQL 关键字，也会被当作普通字符处理，不会改变 SQL 语法结构。
5. **结论**：虽然代码使用了字符串拼接，但由于使用了参数化查询，不存在 SQL 注入漏洞。

### 最终结论

```json
{
  "has_vulnerability": false,
  "vulnerability_type": "none",
  "risk_level": "None",
  "source": "request.args.get('id', '')",
  "sink": "cursor.execute(query)",
  "explanation": "尽管代码使用了字符串拼接，但通过使用参数化查询（? 占位符），用户输入被正确转义，无法改变 SQL 语法结构，因此不存在 SQL 注入漏洞。",
  "fix_suggestion": "no fix needed"
}
```
```

## 3. Phase 1 答错、Phase 3 答对的样本（KnItLM 修复）

共 20 个修复样本——验证 KnItLM CPT 的价值。

| file | category | P1→P3 outcome | expected_cwe |
|------|----------|---------------|--------------|
| hard_cve_01_samba_2017_7494.py | command_injection | FN→TP | CWE-78 |
| hard_cve_02_python_log_injection.py | log_injection | FN→TP | CWE-117 |
| hard_cve_04_ssrf_urllib.py | ssrf | TP→TP | CWE-918 |
| hard_longfile_02_hidden_cmd.py | command_injection | FN→TP | CWE-78 |
| noise_03_harden_string_concat.py | noise | FP→TN | N/A |
| safe_03_subprocess_list.py | safe_control | FP→TN | N/A |
| safe_17_race_with_lock.py | safe_control | FP→TN | N/A |
| typical_02_xss.py | xss | TP→TP | CWE-79 |
| typical_05_pickle.py | insecure_deserialization | TP→TP | CWE-502 |
| typical_06_secret.py | hardcoded_secret | TP→TP | CWE-798 |
| typical_11_yaml.py | insecure_deserialization | TP→TP | CWE-502 |
| typical_12_open_redirect.py | open_redirect | TP→TP | CWE-601 |
| typical_15_missing_authz.py | missing_authorization | TP→TP | CWE-862 |
| typical_16_session_fixation.py | session_fixation | TP→TP | CWE-384 |
| typical_19_weak_random.py | weak_cryptography | TP→TP | CWE-330 |
| typical_26_xpath_injection.py | xpath_injection | TP→TP | CWE-643 |
| typical_27_race_condition.py | race_condition | TP→TP | CWE-362 |
| typical_28_info_disclosure.py | information_disclosure | TP→TP | CWE-209 |
| typical_31_open_redirect_glob.py | open_redirect | TP→TP | CWE-601 |
| typical_36_java_spel.java | code_injection | TP→TP | CWE-94 |

## 4. 总结

- **Phase 3 残留错题**：23 个
- **Phase 1→3 回归**：4 个（KnItLM 是否保守化的关键证据）
- **Phase 1→3 修复**：20 个（KnItLM CPT 价值的直接证据）

**下一步行动**：
1. 逐个审阅 §2.1 的回归样本 raw_output，判断是否为保守化倾向
2. 若回归集中某类漏洞（如 SSTI/CSRF），需 supplement_*.py 针对性补强
3. Phase 4 PD 完成后，用本脚本对比 Phase 3 vs Phase 4，检查 PD 是否修复回归
