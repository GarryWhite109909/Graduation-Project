/**
 * AI 漏洞扫描器 VSCode 插件
 *
 * 功能：右键编辑器 → "AI 漏洞扫描: 分析当前文件" → 调用后端 API → Webview 面板展示结果
 *
 * 依赖：仅用 Node.js 内置模块（http），无需 npm install
 * 调试：在 VSCode 中打开本目录，按 F5 启动扩展开发宿主
 */

const vscode = require("vscode");
const http = require("http");
const url = require("url");

// 语言 ID 映射
const LANG_MAP = {
  python: "python",
  javascript: "javascript",
  typescript: "typescript",
  java: "java",
  php: "php",
  go: "go",
  html: "html",
};

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
  const command = vscode.commands.registerCommand(
    "vulnScanner.analyzeFile",
    async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("请先打开一个文件");
        return;
      }

      const config = vscode.workspace.getConfiguration("vulnScanner");
      const backendUrl = config.get("backendUrl", "http://localhost:8765");
      const useRag = config.get("useRag", false);

      const code = editor.document.getText();
      const filename = vscode.workspace.asRelativePath(editor.document.uri);
      const language = LANG_MAP[editor.document.languageId] || "text";

      if (!code.trim()) {
        vscode.window.showWarningMessage("文件为空");
        return;
      }

      // 进度提示
      const result = await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: `AI 漏洞扫描: ${filename}`,
          cancellable: false,
        },
        async () => {
          return await analyzeCode(backendUrl, {
            code,
            language,
            filename,
            use_rag: useRag || null,
          });
        }
      );

      if (result.error) {
        vscode.window.showErrorMessage(`扫描失败: ${result.error}`);
        return;
      }

      showResultPanel(result, context);
    }
  );

  context.subscriptions.push(command);
}

/**
 * 调用后端 /api/analyze
 */
function analyzeCode(backendUrl, payload) {
  return new Promise((resolve) => {
    const endpoint = url.resolve(backendUrl, "/api/analyze");
    const parsed = new URL(endpoint);
    const body = JSON.stringify(payload);

    const req = http.request(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
        timeout: 300000, // 5 分钟超时（大文件+RAG 可能慢）
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            resolve({ error: `JSON 解析失败: ${e.message}` });
          }
        });
      }
    );

    req.on("error", (e) => {
      resolve({
        error: `无法连接后端 (${backendUrl})。请确保后端服务已启动。详情: ${e.message}`,
      });
    });

    req.on("timeout", () => {
      req.destroy();
      resolve({ error: "请求超时（5分钟）" });
    });

    req.write(body);
    req.end();
  });
}

/**
 * 用 Webview 面板展示结果
 */
function showResultPanel(result, context) {
  const panel = vscode.window.createWebviewPanel(
    "vulnResult",
    `扫描结果: ${result.filename}`,
    vscode.ViewColumn.Two,
    { enableScripts: false }
  );

  const isVuln = result.has_vulnerability === true;
  const isSafe = result.has_vulnerability === false;
  const isError = result.has_vulnerability === null;

  panel.webview.html = renderHtml(result, isVuln, isSafe, isError);
}

function renderHtml(r, isVuln, isSafe, isError) {
  const riskClass = (r.risk_level || "").toLowerCase();
  const statusColor = isVuln ? "#ff6b6b" : isSafe ? "#40db88" : "#ffa657";
  const statusText = isVuln ? "发现漏洞" : isSafe ? "未发现漏洞" : "无法判定";

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<style>
body { font-family: -apple-system, "Microsoft YaHei", sans-serif; padding: 20px; color: #333; max-width: 800px; }
.header { border-left: 4px solid ${statusColor}; padding-left: 16px; margin-bottom: 20px; }
.header h1 { font-size: 18px; margin: 0 0 4px 0; }
.header .status { color: ${statusColor}; font-weight: 600; }
.meta { background: #f6f8fa; padding: 12px; border-radius: 6px; margin-bottom: 16px; font-size: 13px; }
.meta div { margin: 4px 0; }
.field { margin-bottom: 12px; }
.field-label { font-weight: 600; color: #555; margin-bottom: 4px; }
.field-value { line-height: 1.6; }
.fix { background: #f0fff4; border: 1px solid #abf7c8; padding: 12px; border-radius: 6px; }
.fix .label { color: #1a7f37; font-weight: 600; }
details { margin-top: 16px; }
summary { cursor: pointer; color: #0969da; }
pre { background: #f6f8fa; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; background: ${statusColor}; color: #fff; }
</style>
</head>
<body>
<div class="header">
  <h1>${r.filename}</h1>
  <div class="status">${statusText} ${r.risk_level ? `<span class="badge">${r.risk_level}</span>` : ""} <span style="color:#999;font-size:12px">${r.duration || 0}s</span></div>
</div>

${isError ? `<div style="color:#ff6b6b">错误: ${r.error || "未知"}</div>` : ""}

<div class="meta">
  <div>语言: ${r.language}</div>
  ${r.vulnerability_type && r.vulnerability_type !== "none" ? `<div>漏洞类型: ${r.vulnerability_type}</div>` : ""}
  ${r.source && r.source !== "N/A" ? `<div>污染来源: ${r.source}</div>` : ""}
  ${r.sink && r.sink !== "N/A" ? `<div>触发点: ${r.sink}</div>` : ""}
</div>

${r.explanation ? `<div class="field"><div class="field-label">分析说明</div><div class="field-value">${escapeHtml(r.explanation)}</div></div>` : ""}

${isVuln && r.fix_suggestion ? `<div class="fix"><div class="label">修复建议</div><div>${escapeHtml(r.fix_suggestion)}</div></div>` : ""}

${r.raw_output ? `<details><summary>查看模型分析过程</summary><pre>${escapeHtml(r.raw_output)}</pre></details>` : ""}
</body>
</html>`;
}

function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function deactivate() {}

module.exports = { activate, deactivate };
