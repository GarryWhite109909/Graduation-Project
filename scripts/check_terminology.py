#!/usr/bin/env python3
"""检查仓库 Markdown 文件中的术语与日期格式一致性。"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MD_FILES = [
    p for p in ROOT.rglob('*.md')
    if '/_archive' not in str(p) and '/.trae' not in str(p) and '/outputs/' not in str(p)
]

# 要检查的模式：(描述, 不规范正则, 建议)
CHECKS = [
    ('模型名大小写不一致', r'Qwen2\.5-Coder-7B', 'qwen2.5-coder:7b 或 Qwen/Qwen2.5-Coder-7B-Instruct'),
    ('CWE 格式缺连字符', r'CWE\s+\d{2,3}(?!\d)', 'CWE-NNN'),
    ('日期格式非 ISO', r'(?<!\d)\d{4}/\d{2}/\d{2}(?!\d)', 'YYYY-MM-DD'),
    ('日期格式非 ISO（点分隔）', r'(?<!\d)\d{4}\.\d{2}\.\d{2}(?!\d)', 'YYYY-MM-DD'),
    ('召回率与 recall 混用可疑', r'召回率\s*[（\(]recall', '统一为"召回率 (recall)"'),
]


def main():
    issues = []
    for path in MD_FILES:
        text = path.read_text(encoding='utf-8')
        for desc, pattern, suggestion in CHECKS:
            for m in re.finditer(pattern, text):
                # 排除代码块内的匹配
                line_no = text[:m.start()].count('\n') + 1
                line = text.splitlines()[line_no - 1]
                if line.strip().startswith('```'):
                    continue
                issues.append((path.relative_to(ROOT), line_no, desc, m.group(0), suggestion, line.strip()))

    if not issues:
        print('未发现明显术语/日期格式问题。')
        return 0

    print(f'发现 {len(issues)} 处潜在不一致：\n')
    current_file = None
    for rel, line_no, desc, matched, suggestion, line in issues:
        if rel != current_file:
            print(f'\n{rel}')
            current_file = rel
        print(f'  行 {line_no}: [{desc}] "{matched}" → 建议: {suggestion}')
        print(f'    {line[:100]}')
    return 1


if __name__ == '__main__':
    sys.exit(main())
