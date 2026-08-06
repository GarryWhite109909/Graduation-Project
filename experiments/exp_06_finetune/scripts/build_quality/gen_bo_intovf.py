#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成缓冲区溢出与整数溢出（CWE-787/125/122/190）高质量训练样本。

覆盖：
  - CWE-787 Out-of-bounds Write   (6 条 = 5 vuln + 1 safe)
  - CWE-125 Out-of-bounds Read    (4 条 = 3 vuln + 1 safe)
  - CWE-122 Heap-based Buffer Overflow (4 条 = 3 vuln + 1 safe)
  - CWE-190 Integer Overflow or Wraparound (6 条 = 4 vuln + 2 safe)

合计 20 条（15 正 + 5 负/hard negative）。代码模式覆盖图像解码器、网络协议解析、
内核驱动缓存、认证限流等真实场景；安全样本为对应漏洞的 hard negative（相同结构 +
有效防御）。每条正样本含完整可运行 fix_code。

输出：data/quality/hard_samples_bo_intovf.jsonl

用法：
  cd experiments/exp_06_finetune
  python3 scripts/build_quality/gen_bo_intovf.py
"""
import json
import re
import sys
from pathlib import Path
from collections import Counter

PROJECT_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(PROJECT_ROOT))
from graduation_project.schema import parse_verdict

EXP_DIR = Path(__file__).resolve().parents[2]
OUTPUT_FILE = EXP_DIR / "data" / "quality" / "hard_samples_bo_intovf.jsonl"

SYSTEM_PROMPT = (
    "你是一名安全研究员，分析给定代码的安全漏洞。\n\n"
    "在回答的最后，必须严格输出一个 JSON 对象作为最终结论，"
    "JSON 块用 ```json 包裹，字段如下（统一 schema，全项目一致）：\n"
    "   - has_vulnerability: bool, true 表示存在漏洞，false 表示未发现漏洞\n"
    "   - vulnerability_type: str, 单个字符串（禁止拆成多个逗号分隔的值），"
    "格式如 'CWE-89 SQL注入'；无漏洞填 'none'\n"
    "   - risk_level: str, Critical/High/Medium/Low；无漏洞填 'None'\n"
    "   - source: str, 污染来源（用户可控输入点）。必须锚定行号，"
    "如 'line 12: request.args.get(\"id\")'；无漏洞填 'N/A'\n"
    "   - sink: str, 危险函数或触发点。必须锚定行号，"
    "如 'line 18: cursor.execute(query)'；无漏洞填 'N/A'\n"
    "   - explanation: str, 漏洞或安全现状说明（数据流/成因，用 -> 箭头描述）\n"
    "   - fix_suggestion: str, 可执行的修复建议：必须给出具体改法（含行号+改成什么），"
    "建议给出完整可运行补丁；无漏洞填 'no fix needed'\n"
    "   - fix_code: str, 可选。完整、可运行、最小化的修复版代码"
    "（纯代码字符串，不含 ``` 围栏）；无漏洞填 'N/A'\n\n"
    "请先给出分析过程，然后在最后给出 JSON 结论。"
)


# ===========================================================================
# 20 条样本定义
# ===========================================================================
SAMPLES = [

    # =====================================================================
    # CWE-787 Out-of-bounds Write (6 条 = 5 vuln + 1 safe)
    # =====================================================================

    # ----- 1. vuln: 图像解码器行写入越界 (C) -----
    {
        "filename": "vuln_787_image_decode.c",
        "language": "c",
        "code": r'''// 文件: image_decode.c
#include <stdlib.h>
#include <string.h>

typedef struct { int w, h; unsigned char *px; } Image;

// 解码一行像素到 img->px
int decode_row(Image *img, int row, const unsigned char *src, int src_len) {  // line 8: src/src_len 污染源
    unsigned char *dst = img->px + (row * img->w * 3);  // line 9: 行偏移
    memcpy(dst, src, src_len);  // line 10: 危险 sink，未校验 src_len
    return 0;
}

int main(void) {
    Image img = { .w = 64, .h = 64 };
    img.px = malloc((size_t)img.w * img.h * 3);  // 12288 字节
    unsigned char payload[8192];
    memset(payload, 'A', sizeof(payload));
    decode_row(&img, 0, payload, 8192);  // line 19: 8192 > 192 触发越界写
    free(img.px);
    return 0;
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 8 函数参数 src 和 src_len 来自调用方，"
            "在 main 中 payload 长度 8192 直接传入（line 19），用户可控。\n"
            "2. 危险 sink 定位：line 10 memcpy(dst, src, src_len)，写入长度由 src_len 决定。\n"
            "3. 数据流追踪：src_len=8192 -> line 9 计算 dst=img->px+0 -> line 10 memcpy 写入 8192 字节。\n"
            "4. 缺陷分析：img->px 按 width*height*3 = 64*64*3 = 12288 分配，单行仅需 64*3 = 192 字节，"
            "但 line 10 写入 8192 字节远超单行容量，导致越过当前行写入后续行乃至缓冲区末尾之外。\n"
            "5. 防御检查：decode_row 内无任何对 src_len 与 img->w*3 的比较，main 也未校验。\n"
            "6. 结论：存在 CWE-787 Out-of-bounds Write，风险等级 High。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-787 Out-of-bounds Write",
            "risk_level": "High",
            "source": "line 8: src/src_len 函数参数（main 中传入 8192）",
            "sink": "line 10: memcpy(dst, src, src_len) 未校验写入长度",
            "explanation": "src_len=8192 -> line 10 memcpy 写入 8192 字节到单行 192 字节缓冲区 -> 越过行边界写入后续内存",
            "fix_suggestion": "line 10 前增加校验：if (src_len < 0 || (size_t)src_len > (size_t)img->w * 3) return -1; 并校验 row 范围",
            "fix_code": (
                "// 文件: image_decode.c\n"
                "#include <stdlib.h>\n"
                "#include <string.h>\n"
                "\n"
                "typedef struct { int w, h; unsigned char *px; } Image;\n"
                "\n"
                "int decode_row(Image *img, int row, const unsigned char *src, int src_len) {\n"
                "    if (row < 0 || row >= img->h) return -1;\n"
                "    size_t row_bytes = (size_t)img->w * 3;\n"
                "    if (src_len < 0 || (size_t)src_len > row_bytes) return -1;\n"
                "    unsigned char *dst = img->px + (size_t)row * row_bytes;\n"
                "    memcpy(dst, src, (size_t)src_len);\n"
                "    return 0;\n"
                "}\n"
                "\n"
                "int main(void) {\n"
                "    Image img = { .w = 64, .h = 64 };\n"
                "    img.px = malloc((size_t)img.w * img.h * 3);\n"
                "    unsigned char payload[8192];\n"
                "    memset(payload, 'A', sizeof(payload));\n"
                "    decode_row(&img, 0, payload, img.w * 3);\n"
                "    free(img.px);\n"
                "    return 0;\n"
                "}"
            ),
        },
    },

    # ----- 2. vuln: 网络报文解析写入固定数组 (C) -----
    {
        "filename": "vuln_787_packet_parse.c",
        "language": "c",
        "code": r'''// 文件: packet_parse.c
#include <stdint.h>
#include <string.h>

#define MAX_ENTRIES 32

typedef struct { uint32_t id; uint32_t value; } Entry;

// 解析网络报文中的 entry 列表
int parse_entries(const uint8_t *pkt, size_t pkt_len) {  // line 10: pkt 污染源
    Entry entries[MAX_ENTRIES];  // line 11: 固定 32 项栈数组
    if (pkt_len < 4) return -1;
    uint32_t count = *(uint32_t *)pkt;  // line 13: 用户可控 count
    if (pkt_len < 4 + count * 8) return -1;  // 仅校验报文长度
    for (uint32_t i = 0; i < count; i++) {
        entries[i].id    = *(uint32_t *)(pkt + 4 + i*8);  // line 16: 越界写
        entries[i].value = *(uint32_t *)(pkt + 8 + i*8);  // line 17: 越界写
    }
    return 0;
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 10 pkt 来自网络，line 13 count = *(uint32_t *)pkt 完全由攻击者控制。\n"
            "2. 危险 sink 定位：line 16-17 entries[i] 写入，i 遍历 [0, count)。\n"
            "3. 数据流追踪：pkt -> line 13 count=0xFFFFFFFF -> line 14 仅校验 pkt_len >= 4+count*8（count*8 可能溢出为 0 使校验失效）"
            "-> line 15 循环 count 次 -> line 16 entries[i] 越界写。\n"
            "4. 缺陷分析：entries 为 32 项栈数组，count 可达 2^32-1；即使 count*8 溢出使 line 14 通过，"
            "循环仍写入 entries[32..]，越过栈帧导致栈溢出。\n"
            "5. 防御检查：line 14 仅校验报文长度，未校验 count <= MAX_ENTRIES。\n"
            "6. 结论：存在 CWE-787 Out-of-bounds Write，风险等级 High。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-787 Out-of-bounds Write",
            "risk_level": "High",
            "source": "line 10/13: pkt 网络报文 + count = *(uint32_t*)pkt",
            "sink": "line 16-17: entries[i].id/entries[i].value 写入固定 32 项数组",
            "explanation": "pkt -> count=超大值 -> line 14 count*8 溢出使长度校验失效 -> line 16 entries[i] 越过 MAX_ENTRIES=32 写入栈",
            "fix_suggestion": "line 14 前增加 if (count > MAX_ENTRIES) return -1; 校验 count 不超过数组容量",
            "fix_code": (
                "// 文件: packet_parse.c\n"
                "#include <stdint.h>\n"
                "#include <string.h>\n"
                "\n"
                "#define MAX_ENTRIES 32\n"
                "\n"
                "typedef struct { uint32_t id; uint32_t value; } Entry;\n"
                "\n"
                "int parse_entries(const uint8_t *pkt, size_t pkt_len) {\n"
                "    Entry entries[MAX_ENTRIES];\n"
                "    if (pkt_len < 4) return -1;\n"
                "    uint32_t count = *(uint32_t *)pkt;\n"
                "    if (count > MAX_ENTRIES) return -1;\n"
                "    if (pkt_len < 4 + (size_t)count * 8) return -1;\n"
                "    for (uint32_t i = 0; i < count; i++) {\n"
                "        entries[i].id    = *(uint32_t *)(pkt + 4 + i*8);\n"
                "        entries[i].value = *(uint32_t *)(pkt + 8 + i*8);\n"
                "    }\n"
                "    return 0;\n"
                "}"
            ),
        },
    },

    # ----- 3. vuln: 自定义 strcpy 循环 off-by-one (C++) -----
    {
        "filename": "vuln_787_copy_str.cpp",
        "language": "cpp",
        "code": r'''// 文件: copy_str.cpp
#include <cstddef>

// 限制长度的自定义字符串拷贝
void copy_str(char *dst, const char *src, size_t cap) {  // line 5: src/cap 污染源
    size_t i = 0;
    // 循环条件使用 <= 导致写入 cap+1 字节（off-by-one）
    while (i <= cap) {  // line 8: off-by-one
        dst[i] = src[i];  // line 9: 越界写
        if (src[i] == '\0') break;
        i++;
    }
}

void log_user(const char *user) {  // line 15: user 污染源
    char buf[64];  // line 16: 64 字节缓冲区
    copy_str(buf, user, sizeof(buf));  // line 17: 当 user>=64 字节时写 buf[64]
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 5 src 和 cap 由调用方传入；line 15 user 来自外部，line 17 传入 sizeof(buf)=64。\n"
            "2. 危险 sink 定位：line 9 dst[i] = src[i]，写入位置由 i 决定。\n"
            "3. 数据流追踪：cap=64 -> line 8 循环 i 从 0 到 64（含）-> line 9 dst[64] 写入 -> 越界。\n"
            "4. 缺陷分析：buf[64] 合法索引为 0..63，但 while (i <= cap) 允许 i=64 时执行 dst[64]=src[64]，"
            "恰好越过缓冲区末尾 1 字节，是经典 off-by-one 越界写。\n"
            "5. 防御检查：无任何额外校验，循环条件本身错误。\n"
            "6. 结论：存在 CWE-787 Out-of-bounds Write，风险等级 Medium（off-by-one 单字节越界）。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-787 Out-of-bounds Write",
            "risk_level": "Medium",
            "source": "line 5/15: src/user 函数参数，cap=sizeof(buf)=64",
            "sink": "line 9: dst[i] 写入，i 可达 cap=64 越过 buf[63]",
            "explanation": "cap=64 -> line 8 while(i<=cap) 允许 i=64 -> line 9 dst[64] 写入 -> 越过 64 字节缓冲区末尾 1 字节",
            "fix_suggestion": "line 8 改为 while (i < cap - 1) 并在循环后 dst[i]='\\0' 显式终止",
            "fix_code": (
                "// 文件: copy_str.cpp\n"
                "#include <cstddef>\n"
                "\n"
                "void copy_str(char *dst, const char *src, size_t cap) {\n"
                "    if (cap == 0) return;\n"
                "    size_t i = 0;\n"
                "    while (i < cap - 1 && src[i] != '\\0') {\n"
                "        dst[i] = src[i];\n"
                "        i++;\n"
                "    }\n"
                "    dst[i] = '\\0';\n"
                "}\n"
                "\n"
                "void log_user(const char *user) {\n"
                "    char buf[64];\n"
                "    copy_str(buf, user, sizeof(buf));\n"
                "}"
            ),
        },
    },

    # ----- 4. vuln: 缓存更新 signed index 越界写 (C) -----
    {
        "filename": "vuln_787_cache_set.c",
        "language": "c",
        "code": r'''// 文件: cache_set.c
#include <stdint.h>
#include <string.h>

#define CACHE_SIZE 256
typedef struct { int key; int value; } CacheItem;
static CacheItem cache[CACHE_SIZE];

// 从网络报文更新缓存
int update_cache(const uint8_t *pkt, size_t len) {  // line 10: pkt 污染源
    if (len < 8) return -1;
    int32_t idx = *(int32_t *)pkt;  // line 12: 用户可控 idx
    int32_t val = *(int32_t *)(pkt + 4);
    // 仅校验上限，且边界条件错误（应为 >=）
    if (idx > CACHE_SIZE) {  // line 15: 不充分校验
        return -1;
    }
    cache[idx].key = idx;  // line 18: 负 idx 越界写
    cache[idx].value = val;  // line 19: 负 idx 越界写
    return 0;
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 10 pkt 来自网络，line 12 idx = *(int32_t *)pkt 完全可控。\n"
            "2. 危险 sink 定位：line 18-19 cache[idx] 写入。\n"
            "3. 数据流追踪：pkt -> line 12 idx=-1 -> line 15 -1 > 256 为假通过 -> line 18 cache[-1] 写入。\n"
            "4. 缺陷分析：idx 为 int32_t 有符号整数，line 15 仅校验 idx > CACHE_SIZE（且边界条件错误，"
            "idx==256 也通过），未校验 idx < 0。负数 idx 导致 cache[idx] 写入数组前方内存，"
            "可破坏其他全局变量或栈帧。\n"
            "5. 防御检查：line 15 校验不完整，缺少下限检查。\n"
            "6. 结论：存在 CWE-787 Out-of-bounds Write，风险等级 High。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-787 Out-of-bounds Write",
            "risk_level": "High",
            "source": "line 10/12: pkt 网络报文 + idx = *(int32_t*)pkt",
            "sink": "line 18-19: cache[idx].key/value 写入，负 idx 越界",
            "explanation": "pkt -> idx=-1 -> line 15 仅校验上限负数绕过 -> line 18 cache[-1] 写入数组前方内存",
            "fix_suggestion": "line 15 改为 if (idx < 0 || idx >= CACHE_SIZE) return -1; 校验完整范围",
            "fix_code": (
                "// 文件: cache_set.c\n"
                "#include <stdint.h>\n"
                "#include <string.h>\n"
                "\n"
                "#define CACHE_SIZE 256\n"
                "typedef struct { int key; int value; } CacheItem;\n"
                "static CacheItem cache[CACHE_SIZE];\n"
                "\n"
                "int update_cache(const uint8_t *pkt, size_t len) {\n"
                "    if (len < 8) return -1;\n"
                "    int32_t idx = *(int32_t *)pkt;\n"
                "    int32_t val = *(int32_t *)(pkt + 4);\n"
                "    if (idx < 0 || idx >= CACHE_SIZE) {\n"
                "        return -1;\n"
                "    }\n"
                "    cache[idx].key = idx;\n"
                "    cache[idx].value = val;\n"
                "    return 0;\n"
                "}"
            ),
        },
    },

    # ----- 5. vuln: 批量表格更新 offset+count 越界 (C++) -----
    {
        "filename": "vuln_787_table_update.cpp",
        "language": "cpp",
        "code": r'''// 文件: table_update.cpp
#include <cstdint>
#include <cstring>

#define MAX_ROWS 64

typedef struct {
    uint32_t id;
    uint32_t score;
} Row;

static Row table[MAX_ROWS];

// 批量更新表格（offset 与 count 来自协议）
int batch_update(uint32_t offset, uint32_t count, const Row *rows) {  // line 15: 污染源
    // 仅校验 count，未校验 offset+count 是否越界
    if (count > MAX_ROWS) return -1;  // line 17: 不充分校验
    for (uint32_t i = 0; i < count; i++) {
        table[offset + i] = rows[i];  // line 19: 越界写
    }
    return 0;
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 15 offset 和 count 均为 uint32_t，来自协议字段，完全可控。\n"
            "2. 危险 sink 定位：line 19 table[offset + i] 写入。\n"
            "3. 数据流追踪：offset=60, count=64 -> line 17 64 > 64 为假通过 -> line 19 table[60+63]=table[123] 越界。\n"
            "4. 缺陷分析：line 17 仅校验 count <= MAX_ROWS，未校验 offset + count <= MAX_ROWS。"
            "当 offset 较大时，offset + i 可超过 MAX_ROWS=64，导致写入数组后方内存。\n"
            "5. 防御检查：缺少 offset 与 offset+count 的边界校验。\n"
            "6. 结论：存在 CWE-787 Out-of-bounds Write，风险等级 High。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-787 Out-of-bounds Write",
            "risk_level": "High",
            "source": "line 15: offset/count 函数参数（协议字段）",
            "sink": "line 19: table[offset + i] 写入固定 64 项数组",
            "explanation": "offset=60, count=64 -> line 17 仅校验 count -> line 19 table[123] 越过 MAX_ROWS=64 写入",
            "fix_suggestion": "line 17 前增加 if (offset > MAX_ROWS || count > MAX_ROWS - offset) return -1; 校验 offset+count 不越界",
            "fix_code": (
                "// 文件: table_update.cpp\n"
                "#include <cstdint>\n"
                "#include <cstring>\n"
                "\n"
                "#define MAX_ROWS 64\n"
                "\n"
                "typedef struct {\n"
                "    uint32_t id;\n"
                "    uint32_t score;\n"
                "} Row;\n"
                "\n"
                "static Row table[MAX_ROWS];\n"
                "\n"
                "int batch_update(uint32_t offset, uint32_t count, const Row *rows) {\n"
                "    if (offset > MAX_ROWS || count > MAX_ROWS - offset) return -1;\n"
                "    for (uint32_t i = 0; i < count; i++) {\n"
                "        table[offset + i] = rows[i];\n"
                "    }\n"
                "    return 0;\n"
                "}"
            ),
        },
    },

    # ----- 6. safe: 图像解码器带边界校验 (C) — hard negative of #1 -----
    {
        "filename": "safe_787_image_decode.c",
        "language": "c",
        "code": r'''// 文件: image_decode_safe.c
#include <stdlib.h>
#include <string.h>

typedef struct { int w, h; unsigned char *px; } Image;

// 解码一行像素到 img->px（带边界校验）
int decode_row(Image *img, int row, const unsigned char *src, int src_len) {  // line 8: 输入
    if (row < 0 || row >= img->h) return -1;  // line 9: 行号校验
    size_t row_bytes = (size_t)img->w * 3;  // line 10: 单行字节数
    if (src_len < 0 || (size_t)src_len > row_bytes) return -1;  // line 11: 长度校验
    unsigned char *dst = img->px + (size_t)row * row_bytes;
    memcpy(dst, src, (size_t)src_len);  // line 13: 安全写
    return 0;
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 8 src 和 src_len 来自调用方，理论上可控。\n"
            "2. 危险 sink 定位：line 13 memcpy(dst, src, src_len)。\n"
            "3. 数据流追踪：src_len -> line 11 校验 -> line 13 memcpy。\n"
            "4. 防御评估：\n"
            "   - line 9 校验 row 在 [0, img->h) 范围内，防止行偏移越界；\n"
            "   - line 10 计算 row_bytes = img->w * 3（使用 size_t 避免溢出）；\n"
            "   - line 11 校验 src_len 不为负且不超过 row_bytes，确保 memcpy 写入不越过单行边界；\n"
            "   - line 13 使用 (size_t)src_len 作为 memcpy 长度，与校验值一致。\n"
            "5. 三重校验（行号、下限、上限）有效阻止越界写，防御有效。\n"
            "6. 结论：防御措施有效，无漏洞。"
        ),
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": "line 9 校验 row 范围 + line 11 校验 src_len 不超过 row_bytes -> line 13 memcpy 写入受限于单行字节数，不会越界",
            "fix_suggestion": "no fix needed",
            "fix_code": "N/A",
        },
    },

    # =====================================================================
    # CWE-125 Out-of-bounds Read (4 条 = 3 vuln + 1 safe)
    # =====================================================================

    # ----- 7. vuln: memcmp 用用户长度越界读 (C) -----
    {
        "filename": "vuln_125_token_check.c",
        "language": "c",
        "code": r'''// 文件: token_check.c
#include <string.h>
#include <stdint.h>

// 校验客户端提供的 token 是否匹配服务端密钥
int check_token(const uint8_t *user_token, size_t user_len) {  // line 6: 污染源
    static const uint8_t secret[16] = "S3cr3tTokenXXXX";  // line 7: 16 字节密钥
    // 未校验 user_len <= sizeof(secret)，直接用 user_len 作为比较长度
    if (memcmp(user_token, secret, user_len) == 0) {  // line 9: 越界读
        return 1;  // 认证通过
    }
    return 0;
}

int handle_auth(const uint8_t *token, size_t len) {  // line 15: 外部入口
    return check_token(token, len);  // line 16: 传入用户可控长度
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 6 user_token 和 user_len 来自 line 15-16 的外部调用，len 完全可控。\n"
            "2. 危险 sink 定位：line 9 memcmp(user_token, secret, user_len)，比较长度由 user_len 决定。\n"
            "3. 数据流追踪：len -> line 16 user_len -> line 9 memcmp 读取 user_len 字节。\n"
            "4. 缺陷分析：secret 仅 16 字节，但 user_len 可远大于 16。memcmp 会从 secret 起始地址读取 user_len 字节，"
            "越过 secret 数组边界读取后续全局内存，泄漏内存内容（类似 Heartbleed）。\n"
            "5. 防御检查：无 user_len <= sizeof(secret) 的校验。\n"
            "6. 结论：存在 CWE-125 Out-of-bounds Read，风险等级 Medium。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-125 Out-of-bounds Read",
            "risk_level": "Medium",
            "source": "line 6/15: user_token/user_len 函数参数",
            "sink": "line 9: memcmp(user_token, secret, user_len) 读取 secret 超过 16 字节",
            "explanation": "user_len=4096 -> line 9 memcmp 从 16 字节 secret 读取 4096 字节 -> 越过 secret 边界泄漏后续内存",
            "fix_suggestion": "line 9 前增加 if (user_len > sizeof(secret)) return 0; 限制比较长度不超过 secret 大小",
            "fix_code": (
                "// 文件: token_check.c\n"
                "#include <string.h>\n"
                "#include <stdint.h>\n"
                "\n"
                "int check_token(const uint8_t *user_token, size_t user_len) {\n"
                "    static const uint8_t secret[16] = \"S3cr3tTokenXXXX\";\n"
                "    if (user_len > sizeof(secret)) return 0;\n"
                "    if (memcmp(user_token, secret, user_len) == 0) {\n"
                "        return 1;\n"
                "    }\n"
                "    return 0;\n"
                "}\n"
                "\n"
                "int handle_auth(const uint8_t *token, size_t len) {\n"
                "    return check_token(token, len);\n"
                "}"
            ),
        },
    },

    # ----- 8. vuln: signed index 越界读 (C) -----
    {
        "filename": "vuln_125_read_entry.c",
        "language": "c",
        "code": r'''// 文件: read_entry.c
#include <stdint.h>
#include <stdlib.h>

#define MAX_RECORDS 128

typedef struct { uint32_t id; uint32_t data; } Record;
static Record records[MAX_RECORDS];

// 读取记录（idx 来自用户输入）
int read_record(int32_t idx, Record *out) {  // line 11: idx 污染源
    // 仅校验上限，未校验下限（负数）
    if (idx > MAX_RECORDS) return -1;  // line 13: 不充分校验
    *out = records[idx];  // line 14: 负 idx 越界读
    return 0;
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 11 idx 为 int32_t，来自用户输入（如 URL 参数或协议字段）。\n"
            "2. 危险 sink 定位：line 14 records[idx] 读取。\n"
            "3. 数据流追踪：idx=-1 -> line 13 -1 > 128 为假通过 -> line 14 records[-1] 读取数组前方内存。\n"
            "4. 缺陷分析：idx 为有符号整数，line 13 仅校验 idx > MAX_RECORDS（且边界条件错误，idx==128 也通过），"
            "未校验 idx < 0。负数 idx 导致读取 records 数组前方的内存，可泄漏敏感数据。\n"
            "5. 防御检查：缺少下限校验。\n"
            "6. 结论：存在 CWE-125 Out-of-bounds Read，风险等级 Medium。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-125 Out-of-bounds Read",
            "risk_level": "Medium",
            "source": "line 11: idx 函数参数（int32_t，来自用户输入）",
            "sink": "line 14: records[idx] 读取，负 idx 越界",
            "explanation": "idx=-1 -> line 13 仅校验上限负数绕过 -> line 14 records[-1] 读取数组前方内存泄漏数据",
            "fix_suggestion": "line 13 改为 if (idx < 0 || idx >= MAX_RECORDS) return -1; 校验完整范围",
            "fix_code": (
                "// 文件: read_entry.c\n"
                "#include <stdint.h>\n"
                "#include <stdlib.h>\n"
                "\n"
                "#define MAX_RECORDS 128\n"
                "\n"
                "typedef struct { uint32_t id; uint32_t data; } Record;\n"
                "static Record records[MAX_RECORDS];\n"
                "\n"
                "int read_record(int32_t idx, Record *out) {\n"
                "    if (idx < 0 || idx >= MAX_RECORDS) return -1;\n"
                "    *out = records[idx];\n"
                "    return 0;\n"
                "}"
            ),
        },
    },

    # ----- 9. vuln: strlen 读取未终止的网络缓冲区 (C) -----
    {
        "filename": "vuln_125_parse_header.c",
        "language": "c",
        "code": r'''// 文件: parse_header.c
#include <string.h>
#include <stdlib.h>

// 从原始网络缓冲区读取 header 字段
char *parse_header(const char *buf, size_t buf_len) {  // line 6: buf 污染源
    // buf 来自网络，可能未以 '\0' 结尾，但代码用 strlen 计算长度
    size_t hlen = strlen(buf);  // line 8: 越界读（无 \0 时读越界）
    if (hlen > 4096) return NULL;  // line 9: 校验太晚
    char *hdr = malloc(hlen + 1);
    if (!hdr) return NULL;
    memcpy(hdr, buf, hlen);  // line 12: 可能读越界
    hdr[hlen] = '\0';
    return hdr;
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 6 buf 来自网络缓冲区，buf_len 标识其合法长度，但 buf 内容不含 '\\0' 终止符。\n"
            "2. 危险 sink 定位：line 8 strlen(buf) 逐字节扫描直到遇到 '\\0'。\n"
            "3. 数据流追踪：buf（无 \\0）-> line 8 strlen 越过 buf_len 继续扫描 -> 读取 buf 后方内存。\n"
            "4. 缺陷分析：strlen 不接受长度参数，依赖 '\\0' 终止。若 buf 未终止，strlen 会越过 buf_len 边界"
            "读取后续内存，直到偶然遇到 '\\0' 或段错误。line 9 的长度校验发生在越界读之后，无法阻止。\n"
            "5. 防御检查：line 9 校验 hlen > 4096，但此时越界读已发生。\n"
            "6. 结论：存在 CWE-125 Out-of-bounds Read，风险等级 High。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-125 Out-of-bounds Read",
            "risk_level": "High",
            "source": "line 6: buf 网络缓冲区（可能未 \\0 终止）",
            "sink": "line 8: strlen(buf) 无长度限制地扫描",
            "explanation": "buf 未终止 -> line 8 strlen 越过 buf_len 扫描 -> 读取 buf 后方内存直到偶然遇到 \\0",
            "fix_suggestion": "line 8 改用 memchr(buf, '\\n', buf_len) 或 memchr(buf, '\\0', buf_len) 限长查找",
            "fix_code": (
                "// 文件: parse_header.c\n"
                "#include <string.h>\n"
                "#include <stdlib.h>\n"
                "\n"
                "char *parse_header(const char *buf, size_t buf_len) {\n"
                "    if (buf_len == 0) return NULL;\n"
                "    const char *end = memchr(buf, '\\n', buf_len);\n"
                "    size_t hlen = end ? (size_t)(end - buf) : buf_len;\n"
                "    if (hlen > 4096) return NULL;\n"
                "    char *hdr = malloc(hlen + 1);\n"
                "    if (!hdr) return NULL;\n"
                "    memcpy(hdr, buf, hlen);\n"
                "    hdr[hlen] = '\\0';\n"
                "    return hdr;\n"
                "}"
            ),
        },
    },

    # ----- 10. safe: 限长查找读取 (C) — hard negative of #9 -----
    {
        "filename": "safe_125_parse_header.c",
        "language": "c",
        "code": r'''// 文件: parse_header_safe.c
#include <string.h>
#include <stdlib.h>

// 从缓冲区读取 header，使用显式长度
char *parse_header(const char *buf, size_t buf_len) {  // line 6: buf 输入
    if (buf_len == 0) return NULL;
    // 用 memchr 限制在 buf_len 内查找行尾
    const char *end = memchr(buf, '\n', buf_len);  // line 9: 限长查找
    size_t hlen = end ? (size_t)(end - buf) : buf_len;
    if (hlen > 256) return NULL;  // line 11: 上限校验
    char *hdr = malloc(hlen + 1);
    if (!hdr) return NULL;
    memcpy(hdr, buf, hlen);  // line 14: 安全读（受 buf_len 限制）
    hdr[hlen] = '\0';
    return hdr;
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 6 buf 和 buf_len 来自网络缓冲区，buf 可能未以 '\\0' 终止。\n"
            "2. 危险 sink 定位：line 14 memcpy(hdr, buf, hlen) 读取 buf。\n"
            "3. 数据流追踪：buf -> line 9 memchr 在 buf_len 范围内查找 -> hlen <= buf_len -> line 14 memcpy。\n"
            "4. 防御评估：\n"
            "   - line 9 memchr(buf, '\\n', buf_len) 仅在 buf_len 范围内扫描，不依赖 '\\0' 终止符；\n"
            "   - hlen 要么是 end-buf（<= buf_len），要么是 buf_len，均不超过缓冲区大小；\n"
            "   - line 11 额外校验 hlen <= 256 防止过大分配；\n"
            "   - line 14 memcpy 读取 hlen 字节，hlen 受 buf_len 约束，不会越界。\n"
            "5. 使用 memchr 替代 strlen 是处理未终止缓冲区的标准做法，防御有效。\n"
            "6. 结论：防御措施有效，无漏洞。"
        ),
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": "line 9 memchr 限长查找 + hlen <= buf_len -> line 14 memcpy 读取受 buf_len 约束，不会越界",
            "fix_suggestion": "no fix needed",
            "fix_code": "N/A",
        },
    },

    # =====================================================================
    # CWE-122 Heap-based Buffer Overflow (4 条 = 3 vuln + 1 safe)
    # =====================================================================

    # ----- 11. vuln: 固定大小 malloc + strcpy 堆溢出 (C) -----
    {
        "filename": "vuln_122_dup_str.c",
        "language": "c",
        "code": r'''// 文件: dup_str.c
#include <stdlib.h>
#include <string.h>

// 类似 strdup 的函数，但分配大小固定
char *dup_str(const char *src) {  // line 6: src 污染源
    char *dst = (char *)malloc(64);  // line 7: 固定 64 字节
    if (!dst) return NULL;
    strcpy(dst, src);  // line 9: 堆溢出
    return dst;
}

void handle_request(const char *user_name) {  // line 13: 外部入口
    char *copy = dup_str(user_name);  // line 14: 触发
    if (copy) {
        log_user(copy);
        free(copy);
    }
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 6 src 来自 line 13 user_name（HTTP 请求参数等），长度无限制。\n"
            "2. 危险 sink 定位：line 9 strcpy(dst, src) 将 src 拷贝到 dst。\n"
            "3. 数据流追踪：user_name -> line 14 dup_str -> line 7 malloc(64) -> line 9 strcpy 写入。\n"
            "4. 缺陷分析：line 7 仅分配 64 字节，但 strcpy 不检查 src 长度，当 src 超过 63 字节时，"
            "strcpy 会越过 64 字节堆块边界写入后续堆内存，破坏堆元数据或相邻对象。\n"
            "5. 防御检查：无任何长度校验，strcpy 是不安全的字符串拷贝函数。\n"
            "6. 结论：存在 CWE-122 Heap-based Buffer Overflow，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-122 Heap-based Buffer Overflow",
            "risk_level": "Critical",
            "source": "line 6/13: src/user_name 函数参数（长度无限制）",
            "sink": "line 9: strcpy(dst, src) 写入 64 字节堆缓冲区",
            "explanation": "user_name > 63 字节 -> line 7 malloc(64) -> line 9 strcpy 越过堆块边界写入后续堆内存",
            "fix_suggestion": "line 7 改为 malloc(strlen(src)+1) 动态分配，或用 strncpy(dst, src, 64) 限制长度",
            "fix_code": (
                "// 文件: dup_str.c\n"
                "#include <stdlib.h>\n"
                "#include <string.h>\n"
                "\n"
                "char *dup_str(const char *src) {\n"
                "    if (!src) return NULL;\n"
                "    size_t len = strlen(src);\n"
                "    if (len > 4096) return NULL;\n"
                "    char *dst = (char *)malloc(len + 1);\n"
                "    if (!dst) return NULL;\n"
                "    memcpy(dst, src, len);\n"
                "    dst[len] = '\\0';\n"
                "    return dst;\n"
                "}\n"
                "\n"
                "void handle_request(const char *user_name) {\n"
                "    char *copy = dup_str(user_name);\n"
                "    if (copy) {\n"
                "        log_user(copy);\n"
                "        free(copy);\n"
                "    }\n"
                "}"
            ),
        },
    },

    # ----- 12. vuln: 缓冲区扩容 off-by-one 堆溢出 (C) -----
    {
        "filename": "vuln_122_buf_append.c",
        "language": "c",
        "code": r'''// 文件: buf_append.c
#include <stdlib.h>
#include <string.h>

typedef struct { char *data; size_t len; size_t cap; } Buffer;

// 追加数据到缓冲区
int buf_append(Buffer *b, const char *src, size_t n) {  // line 8: src/n 污染源
    if (b->len + n + 1 > b->cap) {
        // 新容量计算错误：少分配 1 字节（应为 len+n+1）
        size_t new_cap = b->len + n;  // line 11: off-by-one
        char *p = (char *)malloc(new_cap);  // line 12: 分配不足
        if (!p) return -1;
        memcpy(p, b->data, b->len);
        free(b->data);
        b->data = p;
        b->cap = new_cap;
    }
    memcpy(b->data + b->len, src, n);  // line 19: 堆溢出
    b->data[b->len + n] = '\0';  // line 20: 堆溢出（写 NUL）
    b->len += n;
    return 0;
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 8 src 和 n 来自调用方，n 可控。\n"
            "2. 危险 sink 定位：line 19 memcpy 和 line 20 b->data[b->len+n]='\\0' 写入堆缓冲区。\n"
            "3. 数据流追踪：n -> line 11 new_cap=len+n（少 1 字节）-> line 12 malloc(len+n) -> line 19 写入 n 字节 + line 20 写 1 字节 NUL -> 总写入 len+n+1 字节但仅分配 len+n。\n"
            "4. 缺陷分析：line 11 计算 new_cap = b->len + n，但 line 20 需要额外 1 字节存 NUL 终止符。"
            "当 b->len + n 恰好等于 new_cap 时，line 20 的 NUL 写入越过堆块末尾 1 字节，"
            "可破坏堆元数据（如 glibc chunk size 字段）导致后续 free/malloc 异常。\n"
            "5. 防御检查：扩容逻辑缺少对 NUL 终止符的额外空间计算。\n"
            "6. 结论：存在 CWE-122 Heap-based Buffer Overflow，风险等级 High。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-122 Heap-based Buffer Overflow",
            "risk_level": "High",
            "source": "line 8: src/n 函数参数",
            "sink": "line 19-20: memcpy + NUL 写入越过 new_cap 堆块末尾",
            "explanation": "n -> line 11 new_cap=len+n 少 1 字节 -> line 12 malloc(len+n) -> line 20 NUL 写入堆块末尾之外 1 字节",
            "fix_suggestion": "line 11 改为 size_t new_cap = b->len + n + 1; 为 NUL 终止符预留空间",
            "fix_code": (
                "// 文件: buf_append.c\n"
                "#include <stdlib.h>\n"
                "#include <string.h>\n"
                "\n"
                "typedef struct { char *data; size_t len; size_t cap; } Buffer;\n"
                "\n"
                "int buf_append(Buffer *b, const char *src, size_t n) {\n"
                "    if (b->len + n + 1 > b->cap) {\n"
                "        size_t new_cap = b->len + n + 1;\n"
                "        char *p = (char *)malloc(new_cap);\n"
                "        if (!p) return -1;\n"
                "        memcpy(p, b->data, b->len);\n"
                "        free(b->data);\n"
                "        b->data = p;\n"
                "        b->cap = new_cap;\n"
                "    }\n"
                "    memcpy(b->data + b->len, src, n);\n"
                "    b->data[b->len + n] = '\\0';\n"
                "    b->len += n;\n"
                "    return 0;\n"
                "}"
            ),
        },
    },

    # ----- 13. vuln: 分配未计入前缀长度导致堆溢出 (C) -----
    {
        "filename": "vuln_122_format_msg.c",
        "language": "c",
        "code": r'''// 文件: format_msg.c
#include <stdlib.h>
#include <string.h>

// 格式化消息（前缀 + 用户内容）
char *format_msg(const char *user, size_t user_len) {  // line 6: user 污染源
    const char prefix[] = "USER: ";
    size_t plen = sizeof(prefix) - 1;  // 7
    // 分配时未计入 prefix 长度
    char *out = (char *)malloc(user_len + 1);  // line 10: 分配不足
    if (!out) return NULL;
    memcpy(out, prefix, plen);  // line 12: 堆溢出
    memcpy(out + plen, user, user_len);  // line 13: 堆溢出
    out[plen + user_len] = '\0';  // line 14: 堆溢出
    return out;
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 6 user 和 user_len 来自调用方，长度可控。\n"
            "2. 危险 sink 定位：line 12-14 memcpy 写入 out 堆缓冲区。\n"
            "3. 数据流追踪：user_len -> line 10 malloc(user_len+1) 仅分配 user_len+1 字节 -> line 12 写入 7 字节 prefix + line 13 写入 user_len 字节 + line 14 写入 1 字节 NUL -> 总写入 plen+user_len+1 字节但仅分配 user_len+1。\n"
            "4. 缺陷分析：line 10 分配大小为 user_len+1，但实际需要写入 prefix(7) + user(user_len) + NUL(1) = user_len+8 字节。"
            "prefix 的 7 字节未被计入分配大小，导致 line 12 起就越过堆块边界写入。\n"
            "5. 防御检查：分配大小计算遗漏了 prefix 长度。\n"
            "6. 结论：存在 CWE-122 Heap-based Buffer Overflow，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-122 Heap-based Buffer Overflow",
            "risk_level": "Critical",
            "source": "line 6: user/user_len 函数参数",
            "sink": "line 12-14: memcpy 写入 prefix+user 到 user_len+1 字节堆块",
            "explanation": "user_len -> line 10 malloc(user_len+1) -> line 12 写入 prefix(7) 越过堆块 -> 实际需 user_len+8 字节但仅分配 user_len+1",
            "fix_suggestion": "line 10 改为 malloc(plen + user_len + 1) 计入 prefix 长度和 NUL 终止符",
            "fix_code": (
                "// 文件: format_msg.c\n"
                "#include <stdlib.h>\n"
                "#include <string.h>\n"
                "\n"
                "char *format_msg(const char *user, size_t user_len) {\n"
                "    const char prefix[] = \"USER: \";\n"
                "    size_t plen = sizeof(prefix) - 1;\n"
                "    char *out = (char *)malloc(plen + user_len + 1);\n"
                "    if (!out) return NULL;\n"
                "    memcpy(out, prefix, plen);\n"
                "    memcpy(out + plen, user, user_len);\n"
                "    out[plen + user_len] = '\\0';\n"
                "    return out;\n"
                "}"
            ),
        },
    },

    # ----- 14. safe: 精确分配 + 显式 null 终止 (C) — hard negative of #11 -----
    {
        "filename": "safe_122_dup_str.c",
        "language": "c",
        "code": r'''// 文件: dup_str_safe.c
#include <stdlib.h>
#include <string.h>

// 安全的字符串拷贝：分配精确长度 + 显式 null 终止
char *dup_str(const char *src) {  // line 6: src 输入
    if (!src) return NULL;
    size_t len = strlen(src);
    if (len > 4096) return NULL;  // line 9: 上限校验
    char *dst = (char *)malloc(len + 1);  // line 10: 精确分配 +1
    if (!dst) return NULL;
    memcpy(dst, src, len);  // line 12: 安全写
    dst[len] = '\0';  // line 13: 显式 null 终止
    return dst;
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 6 src 来自调用方，长度未知。\n"
            "2. 危险 sink 定位：line 12 memcpy(dst, src, len) 和 line 13 dst[len]='\\0'。\n"
            "3. 数据流追踪：src -> line 8 strlen(src) 得到 len -> line 9 校验 len <= 4096 -> line 10 malloc(len+1) -> line 12 memcpy 写入 len 字节 -> line 13 写入 1 字节 NUL。\n"
            "4. 防御评估：\n"
            "   - line 9 上限校验 len <= 4096 防止过大分配或 DoS；\n"
            "   - line 10 分配 len+1 字节（+1 给 NUL 终止符），精确匹配写入量；\n"
            "   - line 12 memcpy 写入 len 字节，不超过分配大小；\n"
            "   - line 13 dst[len] 写入 NUL，索引 len 在 [0, len] 范围内，是分配的最后一个字节，不越界。\n"
            "5. 分配大小（len+1）与写入量（len + 1 字节 NUL）完全匹配，使用 memcpy 替代 strcpy 避免了长度依赖，防御有效。\n"
            "6. 结论：防御措施有效，无漏洞。"
        ),
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": "line 10 malloc(len+1) 精确分配 + line 12 memcpy 写入 len 字节 + line 13 NUL 写入第 len+1 字节 -> 写入量 = 分配量，不越界",
            "fix_suggestion": "no fix needed",
            "fix_code": "N/A",
        },
    },

    # =====================================================================
    # CWE-190 Integer Overflow or Wraparound (6 条 = 4 vuln + 2 safe)
    # =====================================================================

    # ----- 15. vuln: 位图分配乘法溢出 (C) -----
    {
        "filename": "vuln_190_bmp_alloc.c",
        "language": "c",
        "code": r'''// 文件: bmp_alloc.c
#include <stdlib.h>
#include <string.h>

// 根据用户提供的尺寸分配位图缓冲区
unsigned char *alloc_bitmap(int width, int height, int bpp) {  // line 6: 污染源
    // width/height/bpp 均为 int，相乘在 int 域内溢出后再转 size_t
    size_t total = (size_t)(width * height * bpp);  // line 8: 整数溢出
    return (unsigned char *)malloc(total);  // line 9: 分配过小
}

int load_image(int w, int h) {  // line 12: 外部入口
    // 攻击者构造 w=65536, h=65536, bpp=4 -> 32-bit 乘法溢出为 0
    unsigned char *p = alloc_bitmap(w, h, 4);  // line 14: 触发
    if (!p) return -1;
    memset(p, 0, (size_t)w * h * 4);  // line 16: 堆溢出
    free(p);
    return 0;
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 6 width/height/bpp 来自 line 12 的 w/h（外部输入），bpp=4 固定。\n"
            "2. 危险 sink 定位：line 8 width*height*bpp 整数乘法，line 9 malloc(total) 按溢出后的小值分配。\n"
            "3. 数据流追踪：w=65536, h=65536 -> line 8 65536*65536*4 在 int 域内：65536*65536=2^32 溢出为 0，0*4=0 -> total=0 -> line 9 malloc(0) -> line 16 memset 写入 65536*65536*4=2^34 字节到 0 字节堆块。\n"
            "4. 缺陷分析：line 8 的乘法在 int 域内执行（width/height/bpp 均为 int），溢出后再 cast 到 size_t 已无法恢复正确值。"
            "malloc(0) 返回有效指针但无可用空间，line 16 的 memset 写入巨量数据导致堆溢出。\n"
            "5. 防御检查：无乘法溢出检查。\n"
            "6. 结论：存在 CWE-190 Integer Overflow or Wraparound，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-190 Integer Overflow or Wraparound",
            "risk_level": "Critical",
            "source": "line 6/12: width/height 函数参数（用户可控图像尺寸）",
            "sink": "line 8: width*height*bpp int 域乘法溢出 -> line 9 malloc(0)",
            "explanation": "w=65536,h=65536 -> line 8 int 乘法溢出为 0 -> line 9 malloc(0) -> line 16 memset 写 2^34 字节堆溢出",
            "fix_suggestion": "line 8 前将 width/height/bpp 转为 size_t 再相乘，并逐步检查 w > SIZE_MAX/h 和 wh > SIZE_MAX/b",
            "fix_code": (
                "// 文件: bmp_alloc.c\n"
                "#include <stdlib.h>\n"
                "#include <string.h>\n"
                "#include <stdint.h>\n"
                "\n"
                "unsigned char *alloc_bitmap(int width, int height, int bpp) {\n"
                "    if (width <= 0 || height <= 0 || bpp <= 0) return NULL;\n"
                "    size_t w = (size_t)width;\n"
                "    size_t h = (size_t)height;\n"
                "    size_t b = (size_t)bpp;\n"
                "    if (w > SIZE_MAX / h) return NULL;\n"
                "    size_t wh = w * h;\n"
                "    if (wh > SIZE_MAX / b) return NULL;\n"
                "    size_t total = wh * b;\n"
                "    if (total > 64 * 1024 * 1024) return NULL;\n"
                "    return (unsigned char *)malloc(total);\n"
                "}\n"
                "\n"
                "int load_image(int w, int h) {\n"
                "    unsigned char *p = alloc_bitmap(w, h, 4);\n"
                "    if (!p) return -1;\n"
                "    memset(p, 0, (size_t)w * h * 4);\n"
                "    free(p);\n"
                "    return 0;\n"
                "}"
            ),
        },
    },

    # ----- 16. vuln: 加法溢出导致分配过小 (C++) -----
    {
        "filename": "vuln_190_pkt_alloc.cpp",
        "language": "cpp",
        "code": r'''// 文件: pkt_alloc.cpp
#include <cstdint>
#include <cstdlib>
#include <cstring>

// 分配头部 + 载荷的合并缓冲区
char *alloc_packet(uint32_t header_len, uint32_t payload_len) {  // line 7: 污染源
    // 加法可能溢出
    uint32_t total = header_len + payload_len;  // line 9: 整数溢出
    char *buf = (char *)malloc(total);  // line 10: 分配过小
    if (!buf) return nullptr;
    return buf;
}

void handle(uint32_t h, uint32_t p) {  // line 15: 外部入口
    char *buf = alloc_packet(h, p);  // line 16: 触发
    if (!buf) return;
    // 随后写入 h+p 字节，触发堆溢出
    memset(buf, 0, (size_t)h + p);  // line 19: 堆溢出
    free(buf);
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 7 header_len 和 payload_len 为 uint32_t，来自 line 15 的 h/p（协议字段）。\n"
            "2. 危险 sink 定位：line 9 header_len + payload_len 加法溢出，line 10 malloc(total) 按溢出后的小值分配。\n"
            "3. 数据流追踪：h=0x80000000, p=0x80000000 -> line 9 0x80000000+0x80000000=0x100000000 溢出为 0（uint32_t）-> line 10 malloc(0) -> line 19 memset 写入 0x100000000 字节到 0 字节堆块。\n"
            "4. 缺陷分析：line 9 的加法在 uint32_t 域内执行，两个大值相加溢出为 0 或小正数。"
            "malloc 分配过小缓冲区，line 19 按实际 h+p 写入导致堆溢出。\n"
            "5. 防御检查：无加法溢出检查。\n"
            "6. 结论：存在 CWE-190 Integer Overflow or Wraparound，风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-190 Integer Overflow or Wraparound",
            "risk_level": "Critical",
            "source": "line 7/15: header_len/payload_len 函数参数（协议字段）",
            "sink": "line 9: header_len+payload_len uint32_t 加法溢出 -> line 10 malloc(0)",
            "explanation": "h=0x80000000,p=0x80000000 -> line 9 加法溢出为 0 -> line 10 malloc(0) -> line 19 memset 写 4GB 堆溢出",
            "fix_suggestion": "line 9 改用 size_t 计算 total = (size_t)header_len + (size_t)payload_len 并校验上限",
            "fix_code": (
                "// 文件: pkt_alloc.cpp\n"
                "#include <cstdint>\n"
                "#include <cstdlib>\n"
                "#include <cstring>\n"
                "\n"
                "char *alloc_packet(uint32_t header_len, uint32_t payload_len) {\n"
                "    size_t total = (size_t)header_len + (size_t)payload_len;\n"
                "    if (total > 65536) return nullptr;\n"
                "    char *buf = (char *)malloc(total);\n"
                "    if (!buf) return nullptr;\n"
                "    return buf;\n"
                "}\n"
                "\n"
                "void handle(uint32_t h, uint32_t p) {\n"
                "    char *buf = alloc_packet(h, p);\n"
                "    if (!buf) return;\n"
                "    memset(buf, 0, (size_t)h + p);\n"
                "    free(buf);\n"
                "}"
            ),
        },
    },

    # ----- 17. vuln: Java 认证限流整数溢出绕过 (Java) -----
    {
        "filename": "vuln_190_AuthCheck.java",
        "language": "java",
        "code": r'''// 文件: AuthCheck.java
public class AuthCheck {
    private static final int MAX_REQUESTS = 1000;

    // 校验请求次数限制（防止暴力破解）
    public static boolean checkLimit(int requestCount, int increment) {  // line 6: 污染源
        // 累加请求次数，可能整数溢出
        int newCount = requestCount + increment;  // line 8: 整数溢出
        // newCount 溢出为负数时绕过上限检查
        if (newCount > MAX_REQUESTS) {  // line 10: 校验失效
            return false;  // 超过限制
        }
        return true;  // line 13: 绕过限制
    }
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 6 requestCount 和 increment 来自请求计数器，increment 可由攻击者控制（如批量请求）。\n"
            "2. 危险 sink 定位：line 8 requestCount + increment 整数加法，line 10 newCount > MAX_REQUESTS 比较校验。\n"
            "3. 数据流追踪：requestCount=Integer.MAX_VALUE, increment=1 -> line 8 Integer.MAX_VALUE+1=Integer.MIN_VALUE（-2147483648）-> line 10 -2147483648 > 1000 为假 -> line 13 return true 绕过限制。\n"
            "4. 缺陷分析：Java int 为有符号 32 位，Integer.MAX_VALUE+1 溢出为 Integer.MIN_VALUE（负数）。"
            "line 10 仅校验上限，负数绕过校验，攻击者可在 requestCount 接近 MAX_VALUE 时通过 increment 触发溢出，"
            "使计数器重置为负数从而无限绕过限流。\n"
            "5. 防御检查：无溢出检测，缺少下限校验。\n"
            "6. 结论：存在 CWE-190 Integer Overflow or Wraparound，风险等级 High。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-190 Integer Overflow or Wraparound",
            "risk_level": "High",
            "source": "line 6: requestCount/increment 函数参数",
            "sink": "line 8: requestCount+increment int 加法溢出 -> line 10 校验失效",
            "explanation": "requestCount=MAX_VALUE,increment=1 -> line 8 溢出为 MIN_VALUE(负数) -> line 10 负数 > 1000 为假 -> line 13 绕过限流",
            "fix_suggestion": "line 8 改用 Math.addExact(requestCount, increment) 检测溢出，并在 catch ArithmeticException 时 return false",
            "fix_code": (
                "// 文件: AuthCheck.java\n"
                "public class AuthCheck {\n"
                "    private static final int MAX_REQUESTS = 1000;\n"
                "\n"
                "    public static boolean checkLimit(int requestCount, int increment) {\n"
                "        if (requestCount < 0 || increment < 0) return false;\n"
                "        try {\n"
                "            int newCount = Math.addExact(requestCount, increment);\n"
                "            if (newCount > MAX_REQUESTS) {\n"
                "                return false;\n"
                "            }\n"
                "            return true;\n"
                "        } catch (ArithmeticException e) {\n"
                "            return false;\n"
                "        }\n"
                "    }\n"
                "}"
            ),
        },
    },

    # ----- 18. vuln: 有符号长度转 size_t 巨量越界读 (C) -----
    {
        "filename": "vuln_190_frag_assemble.c",
        "language": "c",
        "code": r'''// 文件: frag_assemble.c
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// 重组分片：total_len 来自协议头
int assemble(const uint8_t *frag, int total_len) {  // line 7: total_len 污染源
    char *buf = (char *)malloc(4096);
    if (!buf) return -1;
    // 仅校验上限，未校验下限（负数）
    if (total_len > 4096) {  // line 11: 不充分校验
        free(buf);
        return -1;
    }
    // total_len 为 -1 时，转为 size_t 后是 SIZE_MAX
    memcpy(buf, frag, (size_t)total_len);  // line 16: 巨量越界读
    free(buf);
    return 0;
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 7 total_len 为 int（有符号），来自协议头字段，攻击者可构造为负数。\n"
            "2. 危险 sink 定位：line 16 memcpy(buf, frag, (size_t)total_len)，长度参数由 total_len 决定。\n"
            "3. 数据流追踪：total_len=-1 -> line 11 -1 > 4096 为假通过 -> line 16 (size_t)(-1) = SIZE_MAX（0xFFFFFFFFFFFFFFFF）-> memcpy 读取 SIZE_MAX 字节。\n"
            "4. 缺陷分析：line 11 仅校验 total_len > 4096，未校验 total_len < 0。"
            "当 total_len 为负数时，line 16 的 (size_t) 类型转换将负数符号扩展为极大的无符号值（如 -1 变为 SIZE_MAX），"
            "memcpy 试图读取巨量数据导致段错误或信息泄漏。\n"
            "5. 防御检查：缺少下限校验。\n"
            "6. 结论：存在 CWE-190 Integer Overflow or Wraparound（有符号到无符号转换导致值回绕），风险等级 Critical。"
        ),
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-190 Integer Overflow or Wraparound",
            "risk_level": "Critical",
            "source": "line 7: total_len 函数参数（int，来自协议头）",
            "sink": "line 16: (size_t)total_len 将 -1 转为 SIZE_MAX 传入 memcpy",
            "explanation": "total_len=-1 -> line 11 仅校验上限负数绕过 -> line 16 (size_t)(-1)=SIZE_MAX -> memcpy 巨量越界读",
            "fix_suggestion": "line 11 改为 if (total_len < 0 || total_len > 4096) 校验完整范围",
            "fix_code": (
                "// 文件: frag_assemble.c\n"
                "#include <stdint.h>\n"
                "#include <stdlib.h>\n"
                "#include <string.h>\n"
                "\n"
                "int assemble(const uint8_t *frag, int total_len) {\n"
                "    char *buf = (char *)malloc(4096);\n"
                "    if (!buf) return -1;\n"
                "    if (total_len < 0 || total_len > 4096) {\n"
                "        free(buf);\n"
                "        return -1;\n"
                "    }\n"
                "    memcpy(buf, frag, (size_t)total_len);\n"
                "    free(buf);\n"
                "    return 0;\n"
                "}"
            ),
        },
    },

    # ----- 19. safe: 位图分配带溢出检查 (C) — hard negative of #15 -----
    {
        "filename": "safe_190_bmp_alloc.c",
        "language": "c",
        "code": r'''// 文件: bmp_alloc_safe.c
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// 安全分配位图缓冲区（带溢出检查）
unsigned char *alloc_bitmap(int width, int height, int bpp) {  // line 7: 输入
    if (width <= 0 || height <= 0 || bpp <= 0) return NULL;  // line 8: 下限校验
    size_t w = (size_t)width;
    size_t h = (size_t)height;
    size_t b = (size_t)bpp;
    // 逐步乘法 + 溢出检查
    if (w > SIZE_MAX / h) return NULL;  // line 13: 乘法溢出检查
    size_t wh = w * h;
    if (wh > SIZE_MAX / b) return NULL;  // line 15: 二次溢出检查
    size_t total = wh * b;
    if (total > 64 * 1024 * 1024) return NULL;  // line 17: 上限校验
    return (unsigned char *)malloc(total);  // line 18: 安全分配
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 7 width/height/bpp 来自外部输入，理论上可控。\n"
            "2. 危险 sink 定位：line 18 malloc(total)，total 由乘法计算。\n"
            "3. 数据流追踪：width/height/bpp -> line 8 校验正数 -> line 9-11 转 size_t -> line 13 检查 w*h 不溢出 -> line 15 检查 wh*b 不溢出 -> line 17 上限校验 -> line 18 malloc。\n"
            "4. 防御评估：\n"
            "   - line 8 校验 width/height/bpp > 0，防止负数经 size_t 转换变为巨值；\n"
            "   - line 9-11 先转为 size_t（64 位），消除 int 域乘法溢出风险；\n"
            "   - line 13 检查 w > SIZE_MAX/h，确保 w*h 不溢出 size_t；\n"
            "   - line 15 检查 wh > SIZE_MAX/b，确保 wh*b 不溢出 size_t；\n"
            "   - line 17 限制 total <= 64MB，防止过大分配。\n"
            "5. 三层溢出检查（下限、乘法溢出、上限）确保 total 计算正确，防御有效。\n"
            "6. 结论：防御措施有效，无漏洞。"
        ),
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": "line 8 下限校验 + line 9-11 转 size_t + line 13/15 逐步乘法溢出检查 + line 17 上限校验 -> line 18 malloc 分配正确大小",
            "fix_suggestion": "no fix needed",
            "fix_code": "N/A",
        },
    },

    # ----- 20. safe: Java Math.addExact 溢出检测 (Java) — hard negative of #17 -----
    {
        "filename": "safe_190_AuthCheckSafe.java",
        "language": "java",
        "code": r'''// 文件: AuthCheckSafe.java
public class AuthCheckSafe {
    private static final int MAX_REQUESTS = 1000;

    // 校验请求次数限制（防止暴力破解）
    public static boolean checkLimit(int requestCount, int increment) {  // line 6: 输入
        if (requestCount < 0 || increment < 0) return false;  // line 7: 下限校验
        try {
            // 使用 Math.addExact 检测溢出
            int newCount = Math.addExact(requestCount, increment);  // line 10: 溢出检测
            if (newCount > MAX_REQUESTS) {  // line 11: 上限校验
                return false;
            }
            return true;
        } catch (ArithmeticException e) {
            return false;  // line 16: 溢出时拒绝
        }
    }
}''',
        "cot": (
            "分析过程：\n"
            "1. 污染源识别：line 6 requestCount 和 increment 来自请求计数器，理论上可控。\n"
            "2. 危险 sink 定位：line 10 Math.addExact(requestCount, increment) 加法运算。\n"
            "3. 数据流追踪：requestCount/increment -> line 7 校验非负 -> line 10 Math.addExact 加法 + 溢出检测 -> line 11 上限校验。\n"
            "4. 防御评估：\n"
            "   - line 7 校验 requestCount >= 0 且 increment >= 0，防止负数输入；\n"
            "   - line 10 使用 Math.addExact 替代普通 + 运算，当结果溢出 int 范围时抛出 ArithmeticException；\n"
            "   - line 15-16 catch ArithmeticException 并 return false，溢出时拒绝请求；\n"
            "   - line 11 正常情况下校验 newCount > MAX_REQUESTS，防止超过限制。\n"
            "5. Math.addExact 是 Java 8+ 提供的溢出检测算术函数，配合 try-catch 可精确检测整数溢出，防御有效。\n"
            "6. 结论：防御措施有效，无漏洞。"
        ),
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": "line 7 下限校验 + line 10 Math.addExact 溢出检测 + line 16 catch 溢出拒绝 -> 加法溢出被检测并阻断",
            "fix_suggestion": "no fix needed",
            "fix_code": "N/A",
        },
    },
]


# ===========================================================================
# 构建与输出逻辑
# ===========================================================================
def build_user_prompt(filename, language, code):
    return (
        f"代码片段（文件名: {filename}，语言: {language}）：\n"
        f"```{language}\n{code}\n```\n"
        f"请先给出分析过程，然后在最后给出 JSON 结论。"
    )


def build_sample(sample):
    user_prompt = build_user_prompt(
        sample["filename"], sample["language"], sample["code"]
    )
    json_str = json.dumps(sample["verdict"], ensure_ascii=False, indent=2)
    assistant_content = f"{sample['cot']}\n\n```json\n{json_str}\n```"
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": assistant_content},
        ]
    }


def verify_output(filepath):
    """验证输出文件：条数、JSON 合法性、parse_verdict 通过率。"""
    print("\n" + "=" * 60)
    print("验证输出")
    print("=" * 60)

    with open(filepath, encoding="utf-8") as f:
        lines = [l for l in f if l.strip()]

    errors = []
    cwe_counter = Counter()
    lang_counter = Counter()
    vuln_count = 0
    safe_count = 0
    parse_ok = 0
    src_anchored = 0
    sink_anchored = 0
    fix_code_present = 0

    for idx, line in enumerate(lines, 1):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            errors.append(f"行 {idx}: JSON 解析失败 - {e}")
            continue

        messages = obj.get("messages", [])
        if len(messages) != 3:
            errors.append(f"行 {idx}: messages 数量为 {len(messages)}，期望 3")
            continue

        roles = [m["role"] for m in messages]
        if roles != ["system", "user", "assistant"]:
            errors.append(f"行 {idx}: roles 为 {roles}")
            continue

        assistant_content = messages[2]["content"]
        verdict = parse_verdict(assistant_content)
        if not verdict:
            errors.append(f"行 {idx}: parse_verdict 返回空")
            continue

        parse_ok += 1
        has_vuln = verdict.get("has_vulnerability")
        vuln_type = verdict.get("vulnerability_type", "")

        if has_vuln is True:
            vuln_count += 1
            cwe_counter[vuln_type] += 1
            # 检查 source/sink 锚定行号
            if re.search(r"line\s*\d+", str(verdict.get("source", "")), re.I):
                src_anchored += 1
            if re.search(r"line\s*\d+", str(verdict.get("sink", "")), re.I):
                sink_anchored += 1
            # 检查 fix_code 存在且非 N/A
            fix_code = str(verdict.get("fix_code", ""))
            if fix_code and fix_code != "N/A":
                fix_code_present += 1
        elif has_vuln is False:
            safe_count += 1
            cwe_counter["none（安全）"] += 1
        else:
            errors.append(f"行 {idx}: has_vulnerability 为 {has_vuln}，非布尔值")

        # 统计语言
        m = re.search(r"```(\w+)", messages[1]["content"])
        lang_counter[m.group(1) if m else "?"] += 1

    print(f"总条数: {len(lines)}")
    print(f"parse_verdict 成功: {parse_ok}/{len(lines)}")
    print(f"漏洞样本: {vuln_count}")
    print(f"安全样本: {safe_count}")
    print(f"source 含行号: {src_anchored}/{vuln_count}")
    print(f"sink 含行号: {sink_anchored}/{vuln_count}")
    print(f"fix_code 非空: {fix_code_present}/{vuln_count}")
    print(f"\n语言分布: {dict(lang_counter)}")
    print(f"\nCWE 分布:")
    for k, v in cwe_counter.most_common():
        print(f"  {v}  {k}")

    if errors:
        print(f"\n[ERROR] 发现 {len(errors)} 个错误：")
        for e in errors:
            print(f"  {e}")
    else:
        print("\n[OK] 所有验证通过")

    return len(errors) == 0


def main():
    print("=" * 60)
    print("生成 CWE-787/125/122/190 缓冲区溢出与整数溢出训练样本")
    print("=" * 60)

    vuln = sum(1 for s in SAMPLES if s["verdict"]["has_vulnerability"])
    safe = len(SAMPLES) - vuln
    print(f"样本总数: {len(SAMPLES)}（漏洞 {vuln} + 安全 {safe}）")
    print(f"输出文件: {OUTPUT_FILE}")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for sample in SAMPLES:
            obj = build_sample(sample)
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    print(f"\n已写入 {len(SAMPLES)} 条到 {OUTPUT_FILE}")

    ok = verify_output(OUTPUT_FILE)
    if not ok:
        print("\n[FAIL] 验证未通过，请检查上述错误")
        sys.exit(1)
    else:
        print(f"\n[DONE] {len(SAMPLES)} 条样本全部通过验证")


if __name__ == "__main__":
    main()
