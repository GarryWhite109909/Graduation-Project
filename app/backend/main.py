"""
FastAPI 后端入口 —— 漏洞扫描器 API。

路由：
  GET  /api/health          健康检查（Ollama 连接 + 模型可用性）
  POST /api/analyze         单文件分析（JSON body: code/language/filename）
  POST /api/batch           批量扫描（multipart 文件上传）
  POST /api/url-scan        URL 抓取扫描
  POST /api/github-scan     GitHub 仓库扫描
  GET  /api/report/{format} 下载报告（markdown）

启动：
  uvicorn app.backend.main:app --host 127.0.0.1 --port 8765 --reload
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.backend.services.fetcher import fetch_url
from app.backend.services.reporter import render_batch_markdown, render_single_markdown
from app.backend.services.scanner import DEFAULT_MODEL, BatchResult, Scanner

# ---------------------------------------------------------------------------
# 全局 Scanner 实例（单例，避免重复初始化 Chroma/OllamaClient）
# ---------------------------------------------------------------------------
scanner = Scanner(
    model=os.environ.get("VULN_SCANNER_MODEL", DEFAULT_MODEL),
    use_rag=os.environ.get("VULN_SCANNER_RAG", "0") == "1",
    use_lite_prompt=True,  # SFT v5 必须用 LITE
)

# ---------------------------------------------------------------------------
# 文件扩展名 → 语言映射
# ---------------------------------------------------------------------------
EXT_TO_LANG = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript",
    ".java": "java", ".php": "php", ".go": "go",
    ".html": "html", ".htm": "html",
    ".vue": "javascript", ".svelte": "javascript",
}

# ---------------------------------------------------------------------------
# Pydantic 请求模型
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    code: str
    language: str = "python"
    filename: str = "pasted_code.py"
    use_rag: Optional[bool] = None


class UrlScanRequest(BaseModel):
    url: str
    use_rag: Optional[bool] = None


class GithubScanRequest(BaseModel):
    repo_url: str
    use_rag: Optional[bool] = None
    max_files: int = 50  # 限制扫描文件数，避免大仓库超时


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AI 漏洞扫描器",
    description="基于 LLM 的代码安全审计系统 API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 本地开发；生产环境应限制
    allow_methods=["*"],
    allow_headers=["*"],
)

# 最近一次批量扫描结果（供 /api/report 下载）
_last_batch: Optional[BatchResult] = None


# ---------------------------------------------------------------------------
# 健康检查
# ---------------------------------------------------------------------------
@app.get("/api/health")
async def health():
    return scanner.check_health()


# ---------------------------------------------------------------------------
# 单文件分析（代码粘贴）
# ---------------------------------------------------------------------------
@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    # 同步路由（非 async）：FastAPI 自动放线程池，避免阻塞事件循环
    result = scanner.scan_code(
        code=req.code,
        language=req.language,
        filename=req.filename,
        use_rag=req.use_rag,
    )
    return result.to_dict()


# ---------------------------------------------------------------------------
# 批量扫描（文件上传）+ SSE 进度推送
# ---------------------------------------------------------------------------
@app.post("/api/batch")
async def batch_scan(
    files: list[UploadFile] = File(...),
    use_rag: str = Form("0"),
):
    """批量扫描上传的文件。

    返回 NDJSON 流（每行一个文件的结果），前端可逐行解析显示进度。
    """
    rag = use_rag == "1"
    file_list = []
    for f in files:
        ext = Path(f.filename).suffix.lower()
        lang = EXT_TO_LANG.get(ext, "text")
        content = (await f.read()).decode("utf-8", errors="replace")
        file_list.append((f.filename, lang, content))

    def generate():
        global _last_batch
        batch = BatchResult(total_files=len(file_list))
        batch_start = time.time()

        for filename, lang, code in file_list:
            r = scanner.scan_code(code, lang, filename, use_rag=rag)
            batch.results.append(r)
            batch.scanned += 1
            if r.has_vulnerability is True:
                batch.vulnerable += 1
            elif r.has_vulnerability is False:
                batch.safe += 1
            else:
                batch.errors += 1

            # 推送单文件结果（NDJSON）
            yield json.dumps({
                "type": "progress",
                "scanned": batch.scanned,
                "total": batch.total_files,
                "result": r.to_dict(),
            }, ensure_ascii=False) + "\n"

        batch.total_duration = time.time() - batch_start
        _last_batch = batch
        yield json.dumps({
            "type": "done",
            "summary": batch.to_dict(),
        }, ensure_ascii=False) + "\n"

    return StreamingResponse(generate(), media_type="application/x-ndjson")


# ---------------------------------------------------------------------------
# URL 抓取扫描
# ---------------------------------------------------------------------------
@app.post("/api/url-scan")
def url_scan(req: UrlScanRequest):
    """抓取目标 URL 的所有脚本，逐个扫描。"""
    fetch_result = fetch_url(req.url)

    if fetch_result.error:
        return JSONResponse(
            {"error": fetch_result.error, "url": req.url},
            status_code=502,
        )

    if not fetch_result.scripts:
        return {"url": req.url, "title": fetch_result.title, "results": [], "message": "未找到可分析的脚本"}

    files = [
        (s.source if s.source != "inline" else "inline_script",
         s.language, s.content)
        for s in fetch_result.scripts
    ]
    batch = scanner.scan_files(files, use_rag=req.use_rag)

    return {
        "url": req.url,
        "title": fetch_result.title,
        "total_scripts": fetch_result.total_scripts,
        "summary": batch.to_dict(),
    }


# ---------------------------------------------------------------------------
# GitHub 仓库扫描
# ---------------------------------------------------------------------------
@app.post("/api/github-scan")
def github_scan(req: GithubScanRequest):
    """clone GitHub 仓库 → 遍历代码文件 → 批量扫描。"""
    # 浅克隆到临时目录
    tmp_dir = tempfile.mkdtemp(prefix="vuln_scan_")
    repo_name = req.repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    clone_target = os.path.join(tmp_dir, repo_name)

    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", req.repo_url, clone_target],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            return JSONResponse(
                {"error": f"git clone 失败: {result.stderr[:500]}"},
                status_code=502,
            )
    except subprocess.TimeoutExpired:
        return JSONResponse({"error": "git clone 超时（120s）"}, status_code=504)
    except FileNotFoundError:
        return JSONResponse({"error": "系统未安装 git"}, status_code=500)

    # 遍历代码文件
    code_files = []
    for root, _dirs, fnames in os.walk(clone_target):
        # 跳过 .git / node_modules / vendor 等
        if any(skip in root for skip in [".git", "node_modules", "vendor", "__pycache__"]):
            continue
        for fname in fnames:
            ext = Path(fname).suffix.lower()
            if ext not in EXT_TO_LANG:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fp:
                    content = fp.read()
                rel_path = os.path.relpath(fpath, clone_target)
                code_files.append((rel_path, EXT_TO_LANG[ext], content))
            except Exception:
                continue
            if len(code_files) >= req.max_files:
                break
        if len(code_files) >= req.max_files:
            break

    if not code_files:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return {"repo": req.repo_url, "message": "仓库中未找到支持的代码文件"}

    batch = scanner.scan_files(code_files, use_rag=req.use_rag)
    global _last_batch
    _last_batch = batch

    # 清理临时目录
    shutil.rmtree(tmp_dir, ignore_errors=True)

    return {
        "repo": req.repo_url,
        "scanned_files": len(code_files),
        "summary": batch.to_dict(),
    }


# ---------------------------------------------------------------------------
# 报告下载
# ---------------------------------------------------------------------------
@app.get("/api/report")
async def download_report():
    """下载最近一次批量扫描的 Markdown 报告。"""
    if _last_batch is None:
        return JSONResponse({"error": "暂无扫描结果，请先扫描"}, status_code=404)
    md = render_batch_markdown(_last_batch)
    return StreamingResponse(
        iter([md.encode("utf-8")]),
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=vuln_scan_report.md"},
    )


@app.post("/api/report/single")
def download_single_report(req: AnalyzeRequest):
    """分析并返回单文件 Markdown 报告。"""
    r = scanner.scan_code(
        code=req.code, language=req.language,
        filename=req.filename, use_rag=req.use_rag,
    )
    md = render_single_markdown(r)
    return StreamingResponse(
        iter([md.encode("utf-8")]),
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=single_report.md"},
    )


# ---------------------------------------------------------------------------
# 静态资源托管（Vue 构建产物，开发时不存在则跳过）
# ---------------------------------------------------------------------------
_static_dir = Path(__file__).resolve().parent / "static"
if _static_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(_static_dir), html=True), name="static")
else:
    @app.get("/", response_class=HTMLResponse)
    async def index():
        return """
        <html><body>
        <h1>AI 漏洞扫描器 API</h1>
        <p>后端已启动。前端静态资源未构建（app/backend/static/ 不存在）。</p>
        <p>API 文档：<a href="/docs">/docs</a></p>
        </body></html>
        """


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.backend.main:app",
        host="127.0.0.1",
        port=8765,
        reload=False,
    )
