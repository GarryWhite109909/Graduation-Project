"""
网页抓取服务 —— 抓取目标 URL 的所有 <script> 标签内容（内联 + 外链），
用于 URL 扫描入口。

策略：
- 内联 <script>...</script> 直接提取
- 外链 <script src="..."> 用 requests 拉取（同源优先，跨域看情况）
- 简单 HTML 也要分析（含 onclick= 等事件处理器）
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

import requests


@dataclass
class FetchedScript:
    """抓取到的单个脚本片段。"""
    source: str  # "inline" | 外链 URL
    language: str  # "javascript" | "html"
    content: str
    char_count: int = 0

    def __post_init__(self):
        self.char_count = len(self.content)


@dataclass
class FetchResult:
    """URL 抓取结果。"""
    url: str
    title: str = ""
    scripts: list[FetchedScript] = field(default_factory=list)
    inline_html: str = ""  # 含事件处理器的 HTML 片段
    error: str | None = None

    @property
    def total_scripts(self) -> int:
        return len(self.scripts)


def fetch_url(url: str, timeout: int = 15) -> FetchResult:
    """抓取目标 URL，提取所有 JS 脚本和可疑 HTML 片段。

    Args:
        url: 目标网页 URL
        timeout: 请求超时秒数

    Returns:
        FetchResult，scripts 至少含 0 个元素
    """
    result = FetchResult(url=url)

    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (compatible; VulnScanner/1.0)"},
        )
        resp.raise_for_status()
        html = resp.text
    except Exception as e:
        result.error = f"{type(e).__name__}: {e}"
        return result

    # 提取 title
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if m:
        result.title = m.group(1).strip()

    # 提取内联 <script>...</script>
    inline_pattern = re.compile(
        r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>",
        re.IGNORECASE | re.DOTALL,
    )
    for m in inline_pattern.finditer(html):
        content = m.group(1).strip()
        if content:
            result.scripts.append(FetchedScript(
                source="inline",
                language="javascript",
                content=content,
            ))

    # 提取外链 <script src="...">
    src_pattern = re.compile(
        r'<script[^>]*\bsrc=["\']([^"\']+)["\'][^>]*>',
        re.IGNORECASE,
    )
    for m in src_pattern.finditer(html):
        src_url = m.group(1)
        full_url = urljoin(url, src_url)
        try:
            js_resp = requests.get(
                full_url,
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (compatible; VulnScanner/1.0)"},
            )
            js_resp.raise_for_status()
            result.scripts.append(FetchedScript(
                source=full_url,
                language="javascript",
                content=js_resp.text,
            ))
        except Exception:
            # 外链失败不阻塞，跳过
            continue

    # 提取含事件处理器的 HTML 片段（onclick=, onload= 等）
    event_pattern = re.compile(
        r"<[^>]+\bon\w+\s*=\s*[\"'][^\"']+[\"'][^>]*>",
        re.IGNORECASE,
    )
    event_matches = event_pattern.findall(html)
    if event_matches:
        result.inline_html = "\n".join(event_matches[:20])  # 限制数量
        result.scripts.append(FetchedScript(
            source="inline-html-events",
            language="html",
            content=result.inline_html,
        ))

    return result


if __name__ == "__main__":
    # 自检
    import sys
    if len(sys.argv) < 2:
        print("用法: python fetcher.py <url>")
        sys.exit(1)
    r = fetch_url(sys.argv[1])
    print(f"URL: {r.url}")
    print(f"Title: {r.title}")
    print(f"脚本数: {r.total_scripts}")
    for i, s in enumerate(r.scripts, 1):
        print(f"  [{i}] {s.source[:60]} ({s.language}, {s.char_count} 字符)")
    if r.error:
        print(f"错误: {r.error}")
