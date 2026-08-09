#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把人工手写的 75 条 fix_suggestion 应用到正式输出文件，覆盖失败样本。

读取 final_train_chatml_quality_final_fix.jsonl，对 MAPPING 中的 idx 改写
assistant JSON 块里的 fix_suggestion，并打上 fix_distill 溯源 tag。
"""
import json, re
from pathlib import Path

BASE = Path(__file__).resolve().parents[1] / "data"
OUT = BASE / "final_train_chatml_quality_final_fix.jsonl"

_JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)

def extract_verdict(assistant):
    for raw in reversed(_JSON_BLOCK_RE.findall(assistant or "")):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            continue
    return None

def apply(rec, suggestion):
    msgs = rec.get("messages", [])
    asst = msgs[2].get("content", "")
    m = _JSON_BLOCK_RE.search(asst)
    if m is None:
        return False
    verdict = extract_verdict(asst)
    if verdict is None:
        return False
    verdict = dict(verdict)
    verdict["fix_suggestion"] = suggestion
    new_json = json.dumps(verdict, ensure_ascii=False)
    new_asst = asst.rsplit("```json", 1)[0] + "```json\n" + new_json + "\n```"
    rec["messages"] = [msgs[0], msgs[1], {"role": "assistant", "content": new_asst}]
    rec["fix_distill"] = {"teacher": "manual", "generated_at": "2026-08-09"}
    return True

MAPPING = {
    150: "line 26: 应改为删除该行 mutex_unlock(&dev_lock)，将 temp_buf 分配与 copy_from_user 放入首次加锁的临界区内，考完后再统一解锁，消除 TOCTOU 窗口",
    191: "line 38: 应改为在检查 global_buf 至交换指针之间加锁（如 mutex_lock），并在 QUERY 分支读取 global_buf 时用同一把锁，避免释放与读取竞态导致 use-after-free",
    299: "line 13: 应改为用列表参数构造命令 cmd=[\"docker\",\"images\",\"--format\",\"{{.Tag}}\",f\"{self.registry}/{self.project}/{image}\"]；line 17: 应改为 result=subprocess.run(cmd,capture_output=True,text=True) 并保持 shell=False",
    313: "line 16: 应改为使用 subprocess.run 列表参数并保持 shell=False，且先对 repo_url/branch 做白名单校验，禁止字符串拼接进 shell",
    341: "line 29: 应改为在发起 curl 前精确校验 FULL_URL 的 host 属于 ALLOWED_HOSTS 且 scheme 仅为 https，再执行请求，避免子串匹配被绕过造成 SSRF",
    353: "line 16: 应改为用 subprocess.run 列表参数（shell=False）执行 docker pull/run，并对 service/version 做白名单校验，禁止拼接进 shell",
    451: "line 25: 应改为去掉 eval，直接执行 find 命令，并对 RETENTION_DAYS 做纯数字校验、对 LOG_DIR 做白名单校验，避免命令注入",
    438: "line 29: 应改为 execSync 使用列表参数并 shell:false，或对 serviceName 做白名单校验后再拼接，避免命令注入",
    453: "line 28: 应改为移除 eval，改用参数化 net.connect(port, host) 调用，禁止将外部可控的 targetHost/targetPort 拼入代码字符串",
    484: "line 14: 应改为用 shlex.quote 包裹 db_name 与 backup_dir，并将 subprocess.run 改为列表参数且 shell=False，避免命令注入",
    509: "line 24: 应改为对 script_path/extra_args 做白名单校验，并用 subprocess.run 列表参数且 shell=False，禁止拼接进 shell",
    517: "line 30: 应改为在请求前校验 parsed.Scheme 仅为 http 且 parsed.Host 精确命中白名单，禁止用户控制 path 逃逸造成 SSRF",
    579: "line 37: 应改为用 exec.CommandContext(ctx, \"tar\", \"-czf\", job.TargetPath+\".tar.gz\", job.TargetPath, \"--remove-files\") 列表参数，避免 shell 拼接注入",
    586: "line 26: 应改为禁止将环境变量 INIT_CMD 拼入 shell，改用 spawn 传参或对 userInput 做白名单校验，避免命令注入",
    614: "line 39: 应改为 exec.Command(\"rsync\",\"-avz\",\"--delete\",job.BackupPath,\"backup@\"+job.TargetHost+\":/data/backups/\") 列表参数，避免 shell 拼接注入",
    630: "line 16: 应改为用 subprocess.run([\"docker\",\"logs\",container_name,\"--tail\",\"100\"]) 列表参数，并对 container_name 做白名单校验，避免命令注入",
    658: "line 40: 应改为用 exec.Command(\"git\",\"fetch\",\"origin\",req.Branch) 列表参数，禁用 shell，并对 req.Branch 做白名单校验，避免命令注入",
    719: "line 42: 应改为移除 pickle.loads，改用安全的 JSON 解析处理客户端数据，禁止反序列化不可信输入",
    876: "line 14: 应改为在 getProfile/updateEmail 前校验认证与授权，使用当前登录用户身份而非请求参数 userId，避免 CWE-306",
    872: "line 18: 应改为使用 LDAP 转义工具或参数化绑定构造过滤器，禁止直接拼接用户输入，避免 LDAP 注入",
    901: "line 17: 应改为使用参数化查询（prepared statement）替换字符串拼接的 $sql，避免 SQL 注入；line 24 日志写入同样参数化",
    904: "line 45: 应改为在 /upload 端点校验客户端携带的 CSRF token（与 /csrf-token 下发的一致），避免 CSRF",
    918: "line 21: 应改为移除 pickle.loads，改用 JSON 等安全格式反序列化用户输入，禁止反序列化不可信数据",
    912: "line 25: 应改为用带签名校验的 JWT/会话中间件解析当前用户，禁止仅从可伪造的 authorization header 解析身份",
    968: "line 18: 应改为使用 XPath 参数绑定或转义函数构造表达式，禁止直接拼接用户输入，避免 XPath 注入",
    1012: "line 13: 应改为在 DocumentBuilderFactory 上禁用 DTD 与外部实体（设置 FEATURE_SECURE_PROCESSING、disallow-doctype-decl），避免 XXE",
    1041: "line 8: 应改为使用参数化查询（prepared statement）替换拼接 token 的 SQL，避免 SQL 注入",
    1145: "line 14: 应改为设置 DocumentBuilderFactory 禁用外部实体与 DTD（FEATURE_SECURE_PROCESSING、disallow-doctype-decl），避免 XXE",
    1148: "line 39: 应改为对模板名做严格白名单映射，禁止用户控制路径，并移除可执行 PHP 标签的编译，避免 LFI/代码执行",
    1204: "line 11: 应改为使用 Spring Security 认证与授权注解校验真实登录态，禁止仅凭 X-Admin-Role 请求头放行管理员接口",
    1274: "line 16: 应改为从认证上下文获取当前登录用户，禁止使用请求头 X-User-Id 直接定位并执行敏感操作",
    1295: "line 19: 应改为 UMask=0027，并对 /etc/ci-agent 等敏感目录收紧写权限，避免权限过宽",
    1300: "line 14: 应改为 ssl_protocols TLSv1.2 TLSv1.3；line 15: 应改为 ssl_ciphers 使用强密码套件，移除 RC4/3DES 等弱套件",
    1338: "line 9: 应改为 chmod 750 /var/workspace，避免 777 全局可写",
    1343: "line 14: 应改为移除硬编码的 DB_PASSWORD/API_KEY/REDIS_URL，改用构建时 secret 或运行时机密注入，避免镜像层泄露凭据",
    1450: "line 20: 应改为以非 root 专用用户运行并启用 ProtectSystem=strict、ProtectHome=true、PrivateTmp=true 等安全加固，避免权限过大",
    1451: "line 11: 应改为容器内以非 root 用户运行并以最小权限访问证书目录，限制 /tmp 文件权限，避免凭据泄露",
    1481: "line 14: 应改为仅绑定 127.0.0.1:3000:3000 或限制来源网络，避免内部服务暴露到外部接口",
    1486: "line 8: 应改为以非 root 专用用户运行，并收紧 /var/tmp/ci-builds 工作目录权限，避免权限提升",
    1526: "line 7: 应改为 chmod 750 并移除写入 ~/.bashrc 的明文凭证，避免构建被劫持与凭据泄露",
    1532: "line 12: 应改为 ssl_protocols TLSv1.2 TLSv1.3；line 13: 应改为 ssl_ciphers 使用强密码套件，移除 RC4/3DES 等弱套件",
    1583: "line 12: 应改为移除硬编码 API_KEY，改用运行时 secret，并避免挂载 /var/run/docker.sock 与 /etc/passwd、/etc/shadow 敏感文件",
    1644: "line 14: 应改为在 /update-email 与 /change-password 端点校验 CSRF token（配合 Spring Security CSRF），避免 CSRF",
    1664: "line 11: 应改为在 xml2js 解析时禁用外部实体（如 sax 配置禁止 DTD/external entities），避免 XXE",
    1679: "line 36: 应改为对 name/bio/website 做 HTML 转义后再插入模板，避免存储型 XSS",
    1809: "line 19: 应改为在所有查询完成后再 close 连接（删除提前的 conn.close() 与重复 close），可用 with 语句管理连接，避免 use-after-free",
    1876: "line 39: 应改为对 theme/name/bio 做 HTML 转义后再拼接进页面，避免反射/存储型 XSS",
    1894: "line 39: 应改为用数组参数构建 ssh 命令并对 build_server 做白名单精确匹配，禁止拼接用户可控主机名，避免命令注入",
    1911: "line 6: 应改为使用参数化查询（游标占位符）替换 f-string 拼接的 SQL，避免 SQL 注入",
    1942: "line 7: 应改为仅返回通用错误信息，将 traceback 写入服务端日志而不返回给用户，避免信息泄露",
    2013: "line 2: 应改为移除该调试路由或加认证中间件，禁止将环境变量返回给客户端",
    2121: "line 5: 应改为对 $cmd/$arg 做白名单校验并用列表参数执行，禁止拼接进 system()，避免命令注入",
    2120: "line 4: 应改为校验 $file 为真实存在的文件路径并做白名单，禁止拼接进 passthru，避免命令注入",
    2132: "line 5: 应改为 subprocess.run 使用列表参数且 shell=False，并对 repo 做白名单校验，避免命令注入",
    2142: "line 4: 应改为将 $page 映射到白名单页面列表，并校验规范化后的路径，避免路径穿越",
    2152: "line 5: 应改为将 $page 做白名单映射并禁止 %00 与 ../，避免路径穿越与文件包含",
    2175: "line 4: 应改为移除 eval，用白名单逻辑处理输入，禁止执行用户可控代码",
    2176: "line 4: 应改为移除 assert 执行代码，改用严格的布尔校验，禁止执行用户可控字符串",
    2181: "line 5: 应改为移除 /e 修饰符，改用 preg_replace_callback 处理，禁止执行用户可控代码",
    2180: "line 4: 应改为移除 create_function，改用普通命名的回调函数，禁止动态执行用户输入",
    2254: "line 11: 应改为仅返回字段与错误消息，移除 internal_query 等内部字段，避免泄露数据库结构",
    2345: "line 15: 应改为移除 $where JS 表达式，改用普通字段查询（如 username 精确匹配），避免 NoSQL 注入",
    2762: "line 5: 应改为在写入 Location 头前清除 target_url_val 中的 CR/LF 字符，避免 HTTP 响应拆分",
    2806: "line 8: 应改为先规范化路径并校验其位于允许目录内，再 open 读取，避免路径穿越",
    2890: "line 4: 应改为每个用户使用随机独立 salt（如 secrets），避免硬编码静态 salt 导致凭据可预计算",
    2922: "line 5: 应改为对 tag_name 做 HTML 转义后再拼接输出，避免反射型 XSS",
    2937: "line 8: 应改为仅允许站内相对路径重定向，校验 url 属于白名单域名，避免开放重定向",
    2997: "line 6: 应改为对 tag_name 做 HTML 转义后再输出，避免反射型 XSS",
    3037: "line 4: 应改为校验 $attachment 为白名单文件并禁止拼接进 passthru，避免命令注入",
    3035: "line 5: 应改为对 $shell_cmd/$arg 做白名单校验并用列表参数执行，禁止拼接进 system()，避免命令注入",
    3125: "line 5: 应改为移除 eval，用白名单逻辑处理输入，禁止执行用户可控代码",
    3129: "line 4: 应改为移除 eval，改用白名单逻辑处理 expr，禁止执行用户可控代码",
    3228: "line 10: 应改为仅返回字段与消息，移除 internal_query 等内部字段，避免泄露数据库结构",
    3297: "line 4: 应改为移除 new Function 动态执行，改用白名单逻辑处理 expression，禁止执行用户输入",
    3375: "line 8: 应改为禁止解析用户输入，改用白名单 SimpleEvaluationContext 或预编译安全表达式解析，避免 SpEL 注入",
}

def main() -> int:
    lines = OUT.read_text(encoding="utf-8").splitlines()
    recs = [json.loads(l) for l in lines if l.strip()]
    applied = skipped = not_found = 0
    for idx, sug in MAPPING.items():
        if idx >= len(recs):
            not_found += 1
            print(f"  idx {idx} 超出范围，跳过")
            continue
        rec = recs[idx]
        if apply(rec, sug):
            applied += 1
        else:
            skipped += 1
            print(f"  idx {idx} 改写失败（无 assistant JSON 块）")
    # 写回
    with OUT.open("w", encoding="utf-8") as f:
        for rec in recs:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"完成: 应用 {applied} | 改写失败 {skipped} | 越界 {not_found}")
    return 0

if __name__ == "__main__":
    main()