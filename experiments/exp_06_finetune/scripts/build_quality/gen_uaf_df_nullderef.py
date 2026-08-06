#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 CWE-416 / CWE-415 / CWE-476 高质量训练样本（hard negative 强化）。

覆盖：
  - CWE-416 Use After Free   10 条（7 漏洞 + 3 安全），C/C++/Rust
  - CWE-415 Double Free       6 条（5 漏洞 + 1 安全），C/C++
  - CWE-476 NULL Pointer Deref 4 条（3 漏洞 + 1 安全），C/C++/Java
  合计 20 条 = 15 正样本 + 5 hard negative。

设计要点：
  - code 字段是展示给模型的原始代码（漏洞样本为有漏洞版本，安全样本为安全版本）。
  - 代码模拟真实场景（网络报文处理、链表、内核 char device、缓存淘汰、事件分发、
    smart pointer 误用、Rust unsafe、realloc、别名释放、malloc 不检等）。
  - hard negative 看起来像漏洞但实际有效防御（free 后置 NULL+检查、shared_ptr 引用
    计数保活、Rust 所有权、free(NULL) 安全空操作、strstr 结果 NULL 检查）。
  - 每条样本 assistant 含详细分析（引用行号 + 数据流 -> 描述）+ ```json 结论。
  - verdict 统一 schema（含 fix_code）；漏洞样本给出完整可运行修复版代码。

用法：
  cd experiments/exp_06_finetune
  python3 scripts/build_quality/gen_uaf_df_nullderef.py
"""
import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(PROJECT_ROOT))
from graduation_project.prompts import BASE_PROMPT  # noqa: E402  与任务要求 SYSTEM 完全一致
from graduation_project.schema import parse_verdict  # noqa: E402

EXP_DIR = Path(__file__).resolve().parents[2]
OUTPUT_FILE = EXP_DIR / "data/quality/hard_samples_uaf_df_nullderef.jsonl"

SYSTEM_PROMPT = BASE_PROMPT  # "你是一名安全研究员..." + 统一 schema（含 fix_code）


def build_user(code, lang, filename):
    return (
        f"代码片段（文件名: {filename}，语言: {lang}）：\n"
        f"```{lang}\n{code}\n```\n"
        f"请先给出分析过程，然后在最后给出 JSON 结论。"
    )


def build_verdict(s):
    return {
        "has_vulnerability": s["is_vuln"],
        "vulnerability_type": s["cwe"],
        "risk_level": s["risk"],
        "source": s["source"],
        "sink": s["sink"],
        "explanation": s["explanation"],
        "fix_suggestion": s["fix_suggestion"],
        "fix_code": s["fix_code"],
    }


# ===========================================================================
# 20 条样本
# ===========================================================================
SAMPLES = [
    # ===================================================================
    # CWE-416 Use After Free（10 条：7 漏洞 + 3 安全）
    # ===================================================================

    # --- UAF-1 漏洞：网络报文解析错误分支缺 return，返回已释放指针 ---
    {
        "lang": "c",
        "filename": "net_handler.c",
        "is_vuln": True,
        "cwe": "CWE-416 Use After Free",
        "risk": "High",
        "code": r"""// net_handler.c
#include <stdlib.h>
#include <string.h>
#define MAX_SIZE 4096

typedef struct {
    char *data;
    int len;
} Packet;

Packet *parse_packet(const char *raw, int size) {  // line 11
    Packet *pkt = malloc(sizeof(Packet));
    if (!pkt) return NULL;
    pkt->data = malloc(size);
    if (!pkt->data) {
        free(pkt);
        return NULL;
    }
    memcpy(pkt->data, raw, size);
    pkt->len = size;
    if (pkt->len > MAX_SIZE) {
        free(pkt->data);                             // line 22
        free(pkt);                                   // line 23: frees pkt
    }
    return pkt;                                      // line 25: UAF - returns freed pkt
}
""",
        "source": "line 11: parse_packet(raw, size) 参数 raw/size 来自网络报文（size 可控，触发 line 21 错误分支）",
        "sink": "line 25: return pkt（pkt 在 line 23 已被 free）",
        "explanation": "line 11 raw/size 可控 -> line 21 len>MAX_SIZE -> line 22 free(pkt->data) -> line 23 free(pkt) -> 错误分支缺 return -> line 25 返回已释放的 pkt -> 调用方解引用 -> Use-After-Free",
        "analysis": """分析过程：
1. 输入识别：line 11 parse_packet(raw, size) 的 raw/size 由上层网络报文解析传入，size 来源于报文长度字段，攻击者可控。
2. 数据流：size -> line 14 malloc(size) -> line 20 pkt->len=size -> line 21 判断 len>MAX_SIZE -> line 22 free(pkt->data) -> line 23 free(pkt) -> 控制流落入 line 25 return pkt。
3. 漏洞成因：line 21-23 的错误处理分支在 free(pkt) 后未 return NULL，控制流继续走到 line 25，返回指向已释放堆块的 pkt 指针。调用方拿到悬垂指针后访问 pkt->data / pkt->len 即触发 Use-After-Free。
4. 防御缺失：错误分支缺少 return；释放后未将 pkt 置 NULL。
5. 结论：存在 CWE-416 Use After Free，风险 High。""",
        "fix_suggestion": "line 23 free(pkt) 后立即 return NULL 并将 pkt 置 NULL；确保错误分支不落入正常返回路径 line 25。",
        "fix_code": r"""// net_handler.c (fixed)
#include <stdlib.h>
#include <string.h>
#define MAX_SIZE 4096

typedef struct {
    char *data;
    int len;
} Packet;

Packet *parse_packet(const char *raw, int size) {
    Packet *pkt = malloc(sizeof(Packet));
    if (!pkt) return NULL;
    pkt->data = malloc(size);
    if (!pkt->data) {
        free(pkt);
        pkt = NULL;
        return NULL;
    }
    memcpy(pkt->data, raw, size);
    pkt->len = size;
    if (pkt->len > MAX_SIZE) {
        free(pkt->data);
        pkt->data = NULL;
        free(pkt);
        pkt = NULL;
        return NULL;                 /* added: prevent fall-through UAF */
    }
    return pkt;
}
""",
    },

    # --- UAF-2 漏洞：链表删除后写已释放节点 ---
    {
        "lang": "c",
        "filename": "list_remove.c",
        "is_vuln": True,
        "cwe": "CWE-416 Use After Free",
        "risk": "High",
        "code": r"""// list_remove.c
#include <stdlib.h>

typedef struct Node {
    int key;
    struct Node *next;
} Node;

void list_remove(Node **head, int key) {
    Node *cur = *head;                          // line 10
    Node *prev = NULL;
    while (cur) {
        if (cur->key == key) {                  // line 13
            if (prev) prev->next = cur->next;
            else *head = cur->next;
            free(cur);                          // line 16: frees node
            cur->next = NULL;                   // line 17: UAF - write freed mem
            cur = NULL;
            break;
        }
        prev = cur;
        cur = cur->next;
    }
}
""",
        "source": "line 9: list_remove(head, key) 参数 key 可控，触发 line 13 命中分支",
        "sink": "line 17: cur->next = NULL（cur 在 line 16 已被 free）",
        "explanation": "line 9 key 可控 -> line 13 命中 -> line 16 free(cur) -> line 17 cur->next = NULL 写已释放内存 -> Use-After-Free",
        "analysis": """分析过程：
1. 输入识别：line 9 list_remove(head, key) 的 key 来自外部调用，可指定任意待删除键。
2. 数据流：key -> line 13 cur->key==key 命中 -> line 16 free(cur) 释放节点 -> line 17 cur->next = NULL 对已释放内存执行写操作。
3. 漏洞成因：line 16 free(cur) 后 cur 成为悬垂指针，line 17 仍通过 cur->next 写入已释放堆块，构成 Use-After-Free（写已释放内存可能被堆分配器复用，导致元数据破坏）。
4. 防御缺失：释放后未将 cur 置 NULL 即继续访问其字段。
5. 结论：存在 CWE-416 Use After Free，风险 High。""",
        "fix_suggestion": "line 16 free(cur) 后将 cur 置 NULL，删除 line 17 对 cur->next 的写入；如需 next 应在 free 前保存。",
        "fix_code": r"""// list_remove.c (fixed)
#include <stdlib.h>

typedef struct Node {
    int key;
    struct Node *next;
} Node;

void list_remove(Node **head, int key) {
    Node *cur = *head;
    Node *prev = NULL;
    while (cur) {
        if (cur->key == key) {
            if (prev) prev->next = cur->next;
            else *head = cur->next;
            free(cur);
            cur = NULL;               /* set NULL after free, no write to freed mem */
            break;
        }
        prev = cur;
        cur = cur->next;
    }
}
""",
    },

    # --- UAF-3 漏洞：unique_ptr::get 取裸指针后 reset 释放再使用 ---
    {
        "lang": "cpp",
        "filename": "cache_lookup.cpp",
        "is_vuln": True,
        "cwe": "CWE-416 Use After Free",
        "risk": "High",
        "code": r"""// cache_lookup.cpp
#include <memory>
#include <cstdio>

struct Resource { int id; char buf[64]; };

void process(std::unique_ptr<Resource> res) {  // line 7
    Resource *raw = res.get();                  // line 8: raw non-owning ptr
    res.reset();                                // line 9: frees Resource
    raw->id = 42;                               // line 10: UAF
    std::printf("%d\n", raw->id);               // line 11: UAF
}
""",
        "source": "line 7: process(std::unique_ptr<Resource> res) 持有独占所有权资源",
        "sink": "line 10: raw->id = 42（raw 在 line 9 res.reset() 后已悬空）",
        "explanation": "line 8 res.get() 取裸指针 raw -> line 9 res.reset() 释放 Resource -> line 10 raw->id=42 解引用已释放内存 -> Use-After-Free",
        "analysis": """分析过程：
1. 输入识别：line 7 process(std::unique_ptr<Resource> res) 接管一块 Resource 的独占所有权。
2. 数据流：line 8 Resource *raw = res.get() 取得非拥有裸指针 -> line 9 res.reset() 释放 Resource（引用计数归零，析构并释放内存）-> line 10 raw->id = 42 -> line 11 printf(raw->id)。
3. 漏洞成因：res.reset() 后 raw 成为悬垂指针，line 10-11 通过 raw 解引用已释放内存，构成 Use-After-Free。unique_ptr 的 get() 返回的裸指针不延长生命周期。
4. 防御缺失：在 reset 后仍持有并使用裸指针；未在释放前完成所有访问。
5. 结论：存在 CWE-416 Use After Free，风险 High。""",
        "fix_suggestion": "在 line 9 res.reset() 之前完成所有对资源的访问（用 res-> 直接操作），释放后不再使用裸指针 raw。",
        "fix_code": r"""// cache_lookup.cpp (fixed)
#include <memory>
#include <cstdio>

struct Resource { int id; char buf[64]; };

void process(std::unique_ptr<Resource> res) {
    res->id = 42;                     /* use owning pointer before release */
    std::printf("%d\n", res->id);
    res.reset();                      /* free after all uses done */
}
""",
    },

    # --- UAF-4 漏洞：Rust unsafe 调用 free 后解引用悬垂裸指针 ---
    {
        "lang": "rust",
        "filename": "unsafe_cache.rs",
        "is_vuln": True,
        "cwe": "CWE-416 Use After Free",
        "risk": "High",
        "code": r"""// unsafe_cache.rs
use std::ffi::c_void;

extern "C" {
    fn libc_free(ptr: *mut c_void);   // line 5
}

pub unsafe fn read_first(buf: *mut u8, _len: usize) -> u8 {  // line 8
    let backup = buf;                  // line 9
    libc_free(buf as *mut c_void);     // line 10: frees memory
    let val = *backup;                 // line 11: UAF - deref freed ptr
    val
}
""",
        "source": "line 8: read_first(buf, _len) 裸指针 buf 由外部 FFI 传入",
        "sink": "line 11: *backup（backup 在 line 10 libc_free 后已悬空）",
        "explanation": "line 9 backup=buf -> line 10 libc_free(buf) 释放内存 -> line 11 *backup 解引用已释放指针 -> Use-After-Free",
        "analysis": """分析过程：
1. 输入识别：line 8 pub unsafe fn read_first(buf: *mut u8, _len: usize) 接收来自 FFI 的裸指针 buf，调用方控制其指向的堆分配。
2. 数据流：line 9 let backup = buf 复制指针值 -> line 10 libc_free(buf as *mut c_void) 释放该堆内存 -> line 11 let val = *backup 解引用。
3. 漏洞成因：line 10 free 后 buf/backup 指向的内存已被释放，line 11 *backup 构成对已释放内存的解引用，即 Use-After-Free。unsafe 绕过 Rust 借用检查，编译器无法拦截。
4. 防御缺失：在 free 后仍解引用同一指针；未在释放前读取值。
5. 结论：存在 CWE-416 Use After Free，风险 High。""",
        "fix_suggestion": "在 line 10 libc_free 之前读取 *buf 的值，释放后不再解引用 backup。",
        "fix_code": r"""// unsafe_cache.rs (fixed)
use std::ffi::c_void;

extern "C" {
    fn libc_free(ptr: *mut c_void);
}

pub unsafe fn read_first(buf: *mut u8, _len: usize) -> u8 {
    let val = *buf;                   /* read before free */
    libc_free(buf as *mut c_void);
    val
}
""",
    },

    # --- UAF-5 漏洞：内核 char device ioctl，free 后未置 NULL 且未检查 ---
    {
        "lang": "c",
        "filename": "chrdev_ioctl.c",
        "is_vuln": True,
        "cwe": "CWE-416 Use After Free",
        "risk": "Critical",
        "code": r"""// chrdev_ioctl.c (Linux char device)
#include <linux/slab.h>
#include <linux/uaccess.h>

static char *dev_buf;                           // line 5

static long device_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
    case IOCTL_FREE:
        kfree(dev_buf);                         // line 10: frees buffer
        break;
    case IOCTL_READ:
        if (copy_to_user((void __user *)arg, dev_buf, 64))  // line 13: UAF
            return -EFAULT;
        break;
    }
    return 0;
}
""",
        "source": "line 7: device_ioctl(f, cmd, arg) cmd 来自用户态 ioctl 调用（IOCTL_FREE/IOCTL_READ 顺序可控）",
        "sink": "line 13: copy_to_user(arg, dev_buf, 64)（dev_buf 在 line 10 已 kfree）",
        "explanation": "line 10 IOCTL_FREE: kfree(dev_buf) 未置 NULL -> 攻击者再发 IOCTL_READ -> line 13 copy_to_user 读取已释放 dev_buf -> Use-After-Free",
        "analysis": """分析过程：
1. 输入识别：line 7 device_ioctl 的 cmd/arg 来自用户态 ioctl 系统调用，攻击者可任意顺序发起 IOCTL_FREE 与 IOCTL_READ。
2. 数据流：IOCTL_FREE -> line 10 kfree(dev_buf) 释放全局缓冲 -> dev_buf 未置 NULL -> 攻击者再发 IOCTL_READ -> line 13 copy_to_user(arg, dev_buf, 64) 读取已释放内存并拷贝到用户态。
3. 漏洞成因：line 10 释放后未将 dev_buf 置 NULL，且 line 13 IOCTL_READ 分支未检查 dev_buf 是否有效，导致先 FREE 后 READ 触发 Use-After-Free，并可泄露内核堆内存。
4. 防御缺失：释放后未置 NULL；使用前未做 NULL 检查。
5. 结论：存在 CWE-416 Use After Free（内核态，可信息泄露），风险 Critical。""",
        "fix_suggestion": "line 10 kfree(dev_buf) 后 dev_buf = NULL；line 13 IOCTL_READ 分支前加 if (!dev_buf) return -EINVAL;。",
        "fix_code": r"""// chrdev_ioctl.c (fixed)
#include <linux/slab.h>
#include <linux/uaccess.h>

static char *dev_buf;

static long device_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
    case IOCTL_FREE:
        kfree(dev_buf);
        dev_buf = NULL;               /* NULL after free */
        break;
    case IOCTL_READ:
        if (!dev_buf)                 /* NULL check before use */
            return -EINVAL;
        if (copy_to_user((void __user *)arg, dev_buf, 64))
            return -EFAULT;
        break;
    }
    return 0;
}
""",
    },

    # --- UAF-6 漏洞：缓存淘汰先 free 再用其字段写日志 ---
    {
        "lang": "c",
        "filename": "cache_evict.c",
        "is_vuln": True,
        "cwe": "CWE-416 Use After Free",
        "risk": "High",
        "code": r"""// cache_evict.c
#include <stdlib.h>
#include <stdio.h>

typedef struct {
    char *key;
    int hits;
} Entry;

static void log_event(const char *k, int h) {
    fprintf(stderr, "[audit] key=%s hits=%d\n", k, h);
}

void evict(Entry *e) {                          // line 14
    printf("evicting %s hits=%d\n", e->key, e->hits);  // line 15
    free(e->key);                               // line 16
    free(e);                                    // line 17
    log_event(e->key, e->hits);                 // line 18: UAF
}
""",
        "source": "line 14: evict(Entry *e) 入口指针 e（淘汰条目）",
        "sink": "line 18: log_event(e->key, e->hits)（e 在 line 17 已 free）",
        "explanation": "line 16 free(e->key) -> line 17 free(e) -> line 18 log_event(e->key, e->hits) 访问已释放 e 的字段 -> Use-After-Free",
        "analysis": """分析过程：
1. 输入识别：line 14 evict(Entry *e) 接收待淘汰的缓存条目指针。
2. 数据流：line 16 free(e->key) 释放键 -> line 17 free(e) 释放条目本身 -> line 18 log_event(e->key, e->hits) 通过已释放的 e 读取 key 指针与 hits 字段。
3. 漏洞成因：line 17 free(e) 后 e 悬空，line 18 仍解引用 e->key 与 e->hits；e->key 本身指向的内存也已在 line 16 释放，构成双重悬垂访问。
4. 防御缺失：在释放条目后仍访问其字段；日志应在释放前完成。
5. 结论：存在 CWE-416 Use After Free，风险 High。""",
        "fix_suggestion": "将 line 18 的 log_event 调用移到 line 16/17 free 之前，或先将 key/hits 复制到局部变量再释放。",
        "fix_code": r"""// cache_evict.c (fixed)
#include <stdlib.h>
#include <stdio.h>

typedef struct {
    char *key;
    int hits;
} Entry;

static void log_event(const char *k, int h) {
    fprintf(stderr, "[audit] key=%s hits=%d\n", k, h);
}

void evict(Entry *e) {
    printf("evicting %s hits=%d\n", e->key, e->hits);
    log_event(e->key, e->hits);       /* log before free */
    free(e->key);
    e->key = NULL;
    free(e);
}
""",
    },

    # --- UAF-7 漏洞：事件分发 delete 后读取已释放对象字段 ---
    {
        "lang": "cpp",
        "filename": "event_dispatch.cpp",
        "is_vuln": True,
        "cwe": "CWE-416 Use After Free",
        "risk": "High",
        "code": r"""// event_dispatch.cpp
#include <vector>
#include <cstdio>

struct Listener {
    void (*cb)();
    const char *name;
};

void dispatch_and_remove(std::vector<Listener*>& v) {  // line 10
    for (auto it = v.begin(); it != v.end(); ) {
        Listener *l = *it;                     // line 12
        l->cb();                               // line 13
        delete l;                              // line 14: frees Listener
        std::printf("removed %s\n", l->name);  // line 15: UAF
        it = v.erase(it);
    }
}
""",
        "source": "line 10: dispatch_and_remove(v) 容器中 Listener 指针",
        "sink": "line 15: printf(l->name)（l 在 line 14 delete 后已悬空）",
        "explanation": "line 14 delete l 释放 Listener -> line 15 printf(l->name) 读取已释放对象字段 -> Use-After-Free",
        "analysis": """分析过程：
1. 输入识别：line 10 dispatch_and_remove 接收 Listener* 容器，逐个回调并删除。
2. 数据流：line 12 l = *it -> line 13 l->cb() 回调 -> line 14 delete l 释放对象 -> line 15 printf(l->name) 通过悬垂指针 l 读取 name 字段。
3. 漏洞成因：line 14 delete 后 l 悬空，line 15 仍解引用 l->name 读取已释放内存，构成 Use-After-Free。
4. 防御缺失：在 delete 后仍访问对象成员；应在释放前完成所有访问。
5. 结论：存在 CWE-416 Use After Free，风险 High。""",
        "fix_suggestion": "将 line 15 的 printf 移到 line 14 delete 之前，确保对 l 的所有访问在释放前完成。",
        "fix_code": r"""// event_dispatch.cpp (fixed)
#include <vector>
#include <cstdio>

struct Listener {
    void (*cb)();
    const char *name;
};

void dispatch_and_remove(std::vector<Listener*>& v) {
    for (auto it = v.begin(); it != v.end(); ) {
        Listener *l = *it;
        l->cb();
        std::printf("removed %s\n", l->name);  /* use before delete */
        delete l;
        l = nullptr;
        it = v.erase(it);
    }
}
""",
    },

    # --- UAF-8 安全（hard negative）：free 后置 NULL + 使用前 NULL 检查 ---
    {
        "lang": "c",
        "filename": "conn_close_safe.c",
        "is_vuln": False,
        "cwe": "none",
        "risk": "None",
        "code": r"""// conn_close_safe.c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

typedef struct {
    char *buf;
    int fd;
} Conn;

void conn_close(Conn *c) {                      // line 11
    if (!c) return;
    if (c->buf) {
        free(c->buf);                          // line 14
        c->buf = NULL;                         // line 15: NULL after free
    }
    close(c->fd);
    free(c);                                   // line 18
    c = NULL;
}

void conn_dump(Conn *c) {                      // line 22
    if (!c) return;                            // line 23: NULL check
    if (c->buf)                                // line 24: NULL check before use
        printf("buf=%s\n", c->buf);            // line 25: safe
}
""",
        "source": "N/A",
        "sink": "N/A",
        "explanation": "line 14 free(c->buf) 后 line 15 c->buf=NULL；conn_dump 在 line 23 检查 !c、line 24 检查 c->buf，line 25 访问前已确认非 NULL，悬垂路径被阻断，无 UAF。",
        "analysis": """分析过程：
1. 输入识别：line 11 conn_close 与 line 22 conn_dump 均接收 Conn 指针。
2. 数据流（释放路径）：line 13 if (c->buf) -> line 14 free(c->buf) -> line 15 c->buf = NULL -> line 18 free(c) -> line 19 c = NULL。
3. 数据流（使用路径）：line 23 if (!c) return -> line 24 if (c->buf) -> line 25 printf(c->buf)。
4. 防御评估：释放后立即将 c->buf 置 NULL（line 15），使用前在 line 24 检查 c->buf 非 NULL。即便 c->buf 曾被 free，悬垂指针已被 NULL 覆盖，line 25 的访问只会在 buf 有效时发生。conn_dump 还在 line 23 对 c 本身做 NULL 检查。
5. 结论：free 后置 NULL + 使用前 NULL 检查，悬垂访问路径被有效阻断，无 Use-After-Free。""",
        "fix_suggestion": "no fix needed",
        "fix_code": "N/A",
    },

    # --- UAF-9 安全（hard negative）：Rust 所有权保证释放后不可访问 ---
    {
        "lang": "rust",
        "filename": "safe_owner.rs",
        "is_vuln": False,
        "cwe": "none",
        "risk": "None",
        "code": r"""// safe_owner.rs
pub struct Buffer { pub data: Vec<u8> }

impl Buffer {
    pub fn consume(self) -> usize {            // line 5
        let len = self.data.len();             // line 6: copy usize out
        drop(self.data);                       // line 7: explicit drop
        len                                    // line 8: safe - len is Copy
    }
}

pub fn process(buf: Buffer) -> usize {         // line 12
    let n = buf.consume();                     // line 13: ownership moved
    // buf moved; accessing buf here is a compile error
    n                                          // line 15
}
""",
        "source": "N/A",
        "sink": "N/A",
        "explanation": "line 7 drop(self.data) 后 self.data 已 move，无法再访问；line 8 返回的 len 是 Copy 类型 usize，在 line 6 已拷贝出值，与 drop 无关，所有权机制阻断 UAF。",
        "analysis": """分析过程：
1. 输入识别：line 12 process(buf: Buffer) 取得 Buffer 所有权，line 13 buf.consume() 将所有权进一步转移。
2. 数据流：line 6 let len = self.data.len() 将 usize 长度拷贝到局部变量 -> line 7 drop(self.data) 显式释放 Vec -> line 8 返回 len -> line 13 n 接收 -> line 15 返回 n。
3. 防御评估：line 7 drop(self.data) 后 self.data 已被 move 出去并释放，编译器禁止后续任何对 self.data 的访问（违反借用检查，编译失败）。line 8 返回的 len 是 Copy 类型 usize，其值在 line 6 已独立拷贝，与 self.data 的生命周期解耦。
4. process 中 buf 在 line 13 move 给 consume 后同样不可再用（line 14 注释说明）。
5. 结论：Rust 所有权与 Copy 语义保证释放后不可访问、返回值独立有效，无 Use-After-Free。""",
        "fix_suggestion": "no fix needed",
        "fix_code": "N/A",
    },

    # --- UAF-10 安全（hard negative）：shared_ptr 拷贝保活，reset 不释放 ---
    {
        "lang": "cpp",
        "filename": "safe_shared.cpp",
        "is_vuln": False,
        "cwe": "none",
        "risk": "None",
        "code": r"""// safe_shared.cpp
#include <memory>
#include <vector>
#include <cstdio>

struct Session { int id; char name[32]; };     // line 6

void process(std::vector<std::shared_ptr<Session>>& v) {  // line 8
    auto keep = v[0];                          // line 9: copy, refcount 2
    v[0].reset();                              // line 10: refcount 1, not freed
    std::printf("id=%d\n", keep->id);          // line 11: safe
    keep.reset();                              // line 12: refcount 0, freed
}
""",
        "source": "N/A",
        "sink": "N/A",
        "explanation": "line 9 auto keep = v[0] 拷贝 shared_ptr，引用计数=2 -> line 10 v[0].reset() 引用计数降为 1，对象未释放 -> line 11 keep->id 访问有效 -> line 12 keep.reset() 才真正释放，无 UAF。",
        "analysis": """分析过程：
1. 输入识别：line 8 process 接收 shared_ptr<Session> 容器。
2. 数据流：line 9 auto keep = v[0] 拷贝一份 shared_ptr（引用计数 2）-> line 10 v[0].reset() 释放该引用（引用计数降为 1，对象仍存活）-> line 11 printf(keep->id) -> line 12 keep.reset()（引用计数 0，对象释放）。
3. 防御评估：line 10 reset 表面上看似释放对象，但由于 line 9 的 keep 持有另一份引用，引用计数未归零，对象不会被析构。line 11 通过 keep 访问 id 时对象依然有效。真正的释放在 line 12 最后一个引用释放时发生。
4. 关键点：shared_ptr 的引用计数语义保证只要还有任一 shared_ptr 持有对象，对象即存活，裸指针悬垂风险被消除。
5. 结论：shared_ptr 拷贝保活，reset 未真正释放，访问有效，无 Use-After-Free。""",
        "fix_suggestion": "no fix needed",
        "fix_code": "N/A",
    },

    # ===================================================================
    # CWE-415 Double Free（6 条：5 漏洞 + 1 安全）
    # ===================================================================

    # --- DF-1 漏洞：错误分支 free 后缺 return，落入第二次 free ---
    {
        "lang": "c",
        "filename": "df_parser.c",
        "is_vuln": True,
        "cwe": "CWE-415 Double Free",
        "risk": "High",
        "code": r"""// df_parser.c
#include <stdlib.h>
#include <stdio.h>

char *load(const char *path) {                 // line 5
    char *buf = malloc(1024);                  // line 6
    if (!buf) return NULL;
    FILE *f = fopen(path, "r");
    if (!f) { free(buf); return NULL; }
    if (fread(buf, 1, 1024, f) < 0) {          // line 10
        free(buf);                             // line 11: first free
        fclose(f);
        /* falls through: missing return */    // line 13
    } else {
        fclose(f);
    }
    free(buf);                                 // line 17: double free
    return NULL;
}
""",
        "source": "line 5: load(path) 内 buf = malloc(1024)，fread 失败触发 line 10 分支",
        "sink": "line 17: free(buf)（buf 已在 line 11 被 free）",
        "explanation": "line 10 fread<0 -> line 11 free(buf) -> 缺 return 落入 -> line 17 free(buf) 再次释放同一块 -> Double Free",
        "analysis": """分析过程：
1. 输入识别：line 5 load(path) 内 line 6 malloc(1024) 分配 buf；path 与读取结果影响控制流。
2. 数据流：line 10 fread 返回 <0 -> line 11 free(buf)（第一次释放）-> line 12 fclose(f) -> line 13 注释（缺 return）-> 控制流落入 line 17 free(buf)（第二次释放）。
3. 漏洞成因：line 11 的错误分支在 free(buf) 后未 return，控制流继续走到 line 17 对同一块内存再次 free，构成 Double Free。
4. 防御缺失：错误分支缺少 return；释放后未将 buf 置 NULL（free(NULL) 本可作空操作兜底）。
5. 结论：存在 CWE-415 Double Free，风险 High。""",
        "fix_suggestion": "line 11 free(buf) 后立即 return NULL 并将 buf 置 NULL，确保错误分支不落入 line 17 的二次释放。",
        "fix_code": r"""// df_parser.c (fixed)
#include <stdlib.h>
#include <stdio.h>

char *load(const char *path) {
    char *buf = malloc(1024);
    if (!buf) return NULL;
    FILE *f = fopen(path, "r");
    if (!f) { free(buf); buf = NULL; return NULL; }
    if (fread(buf, 1, 1024, f) < 0) {
        fclose(f);
        free(buf);                   /* free once */
        buf = NULL;
        return NULL;                 /* return: prevent fall-through double free */
    }
    fclose(f);
    free(buf);
    buf = NULL;
    return NULL;
}
""",
    },

    # --- DF-2 漏洞：校验失败 free 后缺 return，落入二次 free ---
    {
        "lang": "c",
        "filename": "df_ioctl.c",
        "is_vuln": True,
        "cwe": "CWE-415 Double Free",
        "risk": "High",
        "code": r"""// df_ioctl.c
#include <stdlib.h>

static int validate(const char *p);

int process(char *p) {                         // line 6
    if (!p) return -1;
    if (validate(p) < 0) {                     // line 8
        free(p);                               // line 9: first free
        /* missing return; falls through */    // line 10
    }
    free(p);                                   // line 12: double free
    return 0;
}
""",
        "source": "line 6: process(char *p) 参数 p（外部传入堆指针），validate 失败触发 line 8 分支",
        "sink": "line 12: free(p)（p 已在 line 9 被 free）",
        "explanation": "line 8 validate(p)<0 -> line 9 free(p) -> 缺 return -> line 12 free(p) 再次释放 -> Double Free",
        "analysis": """分析过程：
1. 输入识别：line 6 process(char *p) 接收外部堆指针 p，p 的内容由调用方控制；validate 结果决定分支。
2. 数据流：line 8 validate(p) < 0 -> line 9 free(p)（第一次释放）-> line 10 注释（缺 return）-> 控制流落入 line 12 free(p)（第二次释放）。
3. 漏洞成因：line 9 错误分支 free(p) 后未 return，line 12 对同一指针再次 free，构成 Double Free。
4. 防御缺失：错误分支缺 return；释放后未置 NULL。
5. 结论：存在 CWE-415 Double Free，风险 High。""",
        "fix_suggestion": "line 9 free(p) 后立即 return -1 并将 p 置 NULL，避免落入 line 12 的二次释放。",
        "fix_code": r"""// df_ioctl.c (fixed)
#include <stdlib.h>

static int validate(const char *p);

int process(char *p) {
    if (!p) return -1;
    if (validate(p) < 0) {
        free(p);
        p = NULL;
        return -1;                   /* return: prevent double free */
    }
    free(p);
    p = NULL;
    return 0;
}
""",
    },

    # --- DF-3 漏洞：手动 release + 析构函数双重释放同一成员 ---
    {
        "lang": "cpp",
        "filename": "df_owner.cpp",
        "is_vuln": True,
        "cwe": "CWE-415 Double Free",
        "risk": "High",
        "code": r"""// df_owner.cpp
class Owner {
    char *buf;
public:
    Owner() : buf(new char[64]) {}             // line 5
    ~Owner() { delete[] buf; }                 // line 6: destructor frees
    void release() { delete[] buf; }           // line 7: manual free
};

void done(Owner *o) {                          // line 10
    if (!o) return;
    o->release();                              // line 12: first free
    delete o;                                  // line 13: ~Owner frees again
}
""",
        "source": "line 10: done(Owner *o) 调用 o->release() 后 delete o",
        "sink": "line 13: delete o 触发 ~Owner 再次 delete[] buf",
        "explanation": "line 12 o->release() 执行 delete[] buf -> line 13 delete o 触发 ~Owner line 6 再次 delete[] buf -> Double Free",
        "analysis": """分析过程：
1. 输入识别：line 10 done(Owner *o) 接收 Owner 对象指针，其内部 buf 在构造时 new[] 分配。
2. 数据流：line 12 o->release() -> line 7 delete[] buf（第一次释放，未置 nullptr）-> line 13 delete o -> 析构函数 line 6 delete[] buf（第二次释放）。
3. 漏洞成因：release() 释放 buf 后未将 buf 置 nullptr，随后 delete o 触发析构函数再次 delete[] 同一指针，构成 Double Free。手动资源管理与 RAII 析构职责重叠。
4. 防御缺失：release() 释放后未置空；存在两条释放路径未协调。
5. 结论：存在 CWE-415 Double Free，风险 High。""",
        "fix_suggestion": "release() 中 delete[] buf 后置 buf=nullptr（delete[] nullptr 是安全空操作），或移除手动 release 调用，统一由析构函数管理。",
        "fix_code": r"""// df_owner.cpp (fixed)
class Owner {
    char *buf;
public:
    Owner() : buf(new char[64]) {}
    ~Owner() { delete[] buf; buf = nullptr; }
    void release() { delete[] buf; buf = nullptr; }  /* NULL after free */
};

void done(Owner *o) {
    if (!o) return;
    delete o;                        /* single free via destructor */
}
""",
    },

    # --- DF-4 漏洞：realloc 成功后原指针已被释放，再 free 原指针 ---
    {
        "lang": "c",
        "filename": "df_realloc.c",
        "is_vuln": True,
        "cwe": "CWE-415 Double Free",
        "risk": "High",
        "code": r"""// df_realloc.c
#include <stdlib.h>

char *grow(char *ptr, int newsize) {           // line 4
    char *p = realloc(ptr, newsize);           // line 5: success frees ptr
    if (!p) {
        free(ptr);                             // line 7: ok (realloc failed)
        return NULL;
    }
    free(p);                                   // line 10: free new block
    free(ptr);                                 // line 11: double free
    return NULL;
}
""",
        "source": "line 4: grow(ptr, newsize) 参数 ptr 为堆指针，realloc 成功触发 line 10 分支",
        "sink": "line 11: free(ptr)（ptr 在 line 5 realloc 成功时已被释放）",
        "explanation": "line 5 realloc 成功 -> ptr 已被释放（可能已搬迁）-> line 10 free(p) -> line 11 free(ptr) 二次释放原块 -> Double Free",
        "analysis": """分析过程：
1. 输入识别：line 4 grow(ptr, newsize) 接收堆指针 ptr。
2. 数据流：line 5 realloc(ptr, newsize) 成功返回新指针 p；按 C 标准，成功时原 ptr 已被释放（可能就地扩容或搬迁）-> line 10 free(p) 释放新块 -> line 11 free(ptr) 对已被 realloc 释放的原指针再次 free。
3. 漏洞成因：realloc 成功后原 ptr 已失效，line 11 free(ptr) 构成对同一内存的二次释放（Double Free）。若 realloc 搬迁，原块已被释放；若就地扩容，free(ptr) 与 free(p) 指向同一块仍为双重释放。
4. 防御缺失：成功路径错误地保留了原 ptr 并再次释放。
5. 结论：存在 CWE-415 Double Free，风险 High。""",
        "fix_suggestion": "realloc 成功后只使用返回值 p，不得再 free 原 ptr；删除 line 11 的 free(ptr)。",
        "fix_code": r"""// df_realloc.c (fixed)
#include <stdlib.h>

char *grow(char *ptr, int newsize) {
    char *p = realloc(ptr, newsize);
    if (!p) {
        free(ptr);                   /* only free original on failure */
        return NULL;
    }
    /* success: ptr already freed by realloc; only p is valid */
    free(p);
    p = NULL;
    return NULL;
}
""",
    },

    # --- DF-5 漏洞：结构体两个指针字段别名同一块，释放两次 ---
    {
        "lang": "c",
        "filename": "df_alias.c",
        "is_vuln": True,
        "cwe": "CWE-415 Double Free",
        "risk": "High",
        "code": r"""// df_alias.c
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *name;
    char *alias;
} Rec;

Rec *make(const char *n) {                     // line 10
    Rec *r = malloc(sizeof(Rec));              // line 11
    r->name = strdup(n);                       // line 12
    r->alias = r->name;                        // line 13: aliasing
    return r;
}

void free_rec(Rec *r) {                        // line 17
    free(r->name);                             // line 18: first free
    free(r->alias);                            // line 19: double free
    free(r);
}
""",
        "source": "line 10: make(n) 中 r->alias = r->name 别名同一 strdup 块",
        "sink": "line 19: free(r->alias)（与 line 18 free(r->name) 同一块）",
        "explanation": "line 13 r->alias=r->name 别名 -> line 18 free(r->name) -> line 19 free(r->alias) 释放同一块 -> Double Free",
        "analysis": """分析过程：
1. 输入识别：line 10 make(n) 用 strdup 分配 name，并令 alias 别名指向同一块。
2. 数据流：line 12 r->name = strdup(n) 分配 -> line 13 r->alias = r->name（别名，两指针指向同一分配）-> free_rec: line 18 free(r->name)（第一次释放）-> line 19 free(r->alias)（第二次释放同一块）。
3. 漏洞成因：name 与 alias 指向同一堆分配，free_rec 对两者各 free 一次，构成 Double Free。
4. 防御缺失：别名共享所有权但按两个独立指针释放；释放后未置 NULL。
5. 结论：存在 CWE-415 Double Free，风险 High。""",
        "fix_suggestion": "别名场景只释放一次（仅 free(r->name)），释放后将 alias 与 name 均置 NULL；或让 alias 不拥有资源。",
        "fix_code": r"""// df_alias.c (fixed)
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *name;
    char *alias;
} Rec;

Rec *make(const char *n) {
    Rec *r = malloc(sizeof(Rec));
    r->name = strdup(n);
    r->alias = r->name;              /* aliasing: shared ownership */
    return r;
}

void free_rec(Rec *r) {
    free(r->name);                   /* free once */
    r->name = NULL;
    r->alias = NULL;                 /* clear alias, no second free */
    free(r);
}
""",
    },

    # --- DF-6 安全（hard negative）：free 后置 NULL，free(NULL) 安全空操作 ---
    {
        "lang": "c",
        "filename": "safe_df_null.c",
        "is_vuln": False,
        "cwe": "none",
        "risk": "None",
        "code": r"""// safe_df_null.c
#include <stdlib.h>
#include <stdio.h>

char *load(const char *path) {                 // line 5
    char *buf = malloc(1024);                  // line 6
    if (!buf) return NULL;
    FILE *f = fopen(path, "r");
    if (!f) { free(buf); buf = NULL; return NULL; }  // line 9: NULL after free
    if (fread(buf, 1, 1024, f) < 0) {
        free(buf);                             // line 11
        buf = NULL;                            // line 12: NULL after free
    }
    fclose(f);
    free(buf);                                 // line 15: free(NULL) no-op
    return NULL;
}
""",
        "source": "N/A",
        "sink": "N/A",
        "explanation": "line 9 free(buf) 后 buf=NULL；line 11 free(buf) 后 line 12 buf=NULL；line 15 free(buf) 实为 free(NULL)，C 标准定义为安全空操作，不构成 Double Free。",
        "analysis": """分析过程：
1. 输入识别：line 5 load(path) 内 line 6 malloc(1024) 分配 buf。
2. 数据流：path 无效 -> line 9 free(buf); buf = NULL; return NULL。读取失败 -> line 11 free(buf); line 12 buf = NULL。正常/失败汇合 -> line 15 free(buf)。
3. 防御评估：每条 free 路径之后都将 buf 置 NULL（line 9、line 12）。C 标准规定 free(NULL) 是空操作且不产生未定义行为。因此即便控制流到达 line 15，此时 buf 已为 NULL，line 15 等价于 free(NULL)，不会对同一块内存二次释放。
4. 关键点：free 后置 NULL 是防御 Double Free 的标准有效模式，line 15 的"二次 free"因目标为 NULL 而无害。
5. 结论：free 后置 NULL + free(NULL) 空操作语义，Double Free 路径被阻断，无漏洞。""",
        "fix_suggestion": "no fix needed",
        "fix_code": "N/A",
    },

    # ===================================================================
    # CWE-476 NULL Pointer Dereference（4 条：3 漏洞 + 1 安全）
    # ===================================================================

    # --- NULL-1 漏洞：malloc 返回未检查即 strcpy ---
    {
        "lang": "c",
        "filename": "nullderef_alloc.c",
        "is_vuln": True,
        "cwe": "CWE-476 NULL Pointer Dereference",
        "risk": "Medium",
        "code": r"""// nullderef_alloc.c
#include <stdlib.h>
#include <string.h>

char *dup_str(const char *s) {                 // line 5
    size_t n = strlen(s);                      // line 6
    char *buf = malloc(n + 1);                 // line 7: may return NULL
    strcpy(buf, s);                            // line 8: NULL deref
    return buf;
}
""",
        "source": "line 5: dup_str(s) 内 line 7 malloc(n+1) 可能返回 NULL",
        "sink": "line 8: strcpy(buf, s)（buf 可能为 NULL）",
        "explanation": "line 7 malloc 失败返回 NULL -> 未检查 -> line 8 strcpy(NULL, s) 解引用 NULL -> NULL Pointer Dereference",
        "analysis": """分析过程：
1. 输入识别：line 5 dup_str(s) 的 s 来自调用方；line 6 strlen(s) 决定分配大小。
2. 数据流：line 6 n = strlen(s) -> line 7 buf = malloc(n+1)（内存不足时返回 NULL）-> line 8 strcpy(buf, s) 对 NULL 解引用。
3. 漏洞成因：line 7 未检查 malloc 返回值，malloc 失败时 buf 为 NULL，line 8 strcpy 写入 NULL 指针触发 NULL Pointer Dereference（解引用 NULL 导致段错误或内存破坏）。
4. 防御缺失：缺少 if (!buf) return NULL; 的返回值检查。
5. 结论：存在 CWE-476 NULL Pointer Dereference，风险 Medium（取决于内存压力触发条件）。""",
        "fix_suggestion": "line 7 malloc 后增加 if (!buf) return NULL; 检查，通过后再 strcpy。",
        "fix_code": r"""// nullderef_alloc.c (fixed)
#include <stdlib.h>
#include <string.h>

char *dup_str(const char *s) {
    size_t n = strlen(s);
    char *buf = malloc(n + 1);
    if (!buf) return NULL;           /* check malloc result */
    strcpy(buf, s);
    return buf;
}
""",
    },

    # --- NULL-2 漏洞：Java Map.get 可能返回 null 未检查即调用方法 ---
    {
        "lang": "java",
        "filename": "NullDeref.java",
        "is_vuln": True,
        "cwe": "CWE-476 NULL Pointer Dereference",
        "risk": "Medium",
        "code": r"""// NullDeref.java
import java.util.Map;

public class Handler {
    public String process(Map<String, String> req) {   // line 5
        String name = req.get("name");                 // line 6: may return null
        String id = req.get("id");                     // line 7: may return null
        return name.toUpperCase() + ":" + id.length(); // line 8: NPE if null
    }
}
""",
        "source": "line 5: process(Map req) 中 req.get(\"name\")/req.get(\"id\") 可能返回 null",
        "sink": "line 8: name.toUpperCase() / id.length()（name/id 可能为 null）",
        "explanation": "line 6/7 req.get 返回 null（键不存在）-> line 8 name.toUpperCase() 对 null 调方法 -> NullPointerException（NULL 解引用）",
        "analysis": """分析过程：
1. 输入识别：line 5 process(Map<String,String> req) 的 req 内容由 HTTP 请求参数填充，键 name/id 可能缺失。
2. 数据流：line 6 name = req.get("name")（键缺失时返回 null）-> line 7 id = req.get("id")（同上）-> line 8 name.toUpperCase() 与 id.length()。
3. 漏洞成因：Map.get 在键不存在时返回 null，代码未对返回值做 null 检查，line 8 对 null 引用调用实例方法 toUpperCase()/length() 抛出 NullPointerException，即 Java 形式的 NULL 指针解引用（CWE-476）。
4. 防御缺失：缺少 name == null / id == null 判断。
5. 结论：存在 CWE-476 NULL Pointer Dereference，风险 Medium。""",
        "fix_suggestion": "line 8 前增加 if (name == null || id == null) return \"\"; 检查，或用 Optional/默认值处理缺失键。",
        "fix_code": r"""// NullDeref.java (fixed)
import java.util.Map;

public class Handler {
    public String process(Map<String, String> req) {
        String name = req.get("name");
        String id = req.get("id");
        if (name == null || id == null) return "";   /* null check */
        return name.toUpperCase() + ":" + id.length();
    }
}
""",
    },

    # --- NULL-3 漏洞：strstr 返回未检查即做指针运算与解引用 ---
    {
        "lang": "c",
        "filename": "nullderef_parse.c",
        "is_vuln": True,
        "cwe": "CWE-476 NULL Pointer Dereference",
        "risk": "Medium",
        "code": r"""// nullderef_parse.c
#include <string.h>
#include <stdlib.h>

char *get_value(const char *header) {          // line 5
    char *p = strstr(header, ": ");            // line 6: may return NULL
    p += 2;                                    // line 7: NULL arithmetic
    return strdup(p);                          // line 8: NULL deref
}
""",
        "source": "line 5: get_value(header) 中 strstr(header, \": \") 可能返回 NULL",
        "sink": "line 8: strdup(p)（p 来自 NULL+2 解引用）",
        "explanation": "line 6 strstr 未找到返回 NULL -> line 7 p += 2 对 NULL 运算 -> line 8 strdup(p) 解引用 NULL -> NULL Pointer Dereference",
        "analysis": """分析过程：
1. 输入识别：line 5 get_value(header) 的 header 来自外部报文头，内容不可控格式。
2. 数据流：line 6 p = strstr(header, ": ")（未找到子串时返回 NULL）-> line 7 p += 2（对 NULL 做指针算术，未定义行为）-> line 8 strdup(p)（解引用 NULL）。
3. 漏洞成因：strstr 找不到分隔符时返回 NULL，代码未检查即对 p 做加法并传入 strdup（其内部解引用 p），触发 NULL Pointer Dereference。
4. 防御缺失：缺少 if (!p) return NULL; 检查。
5. 结论：存在 CWE-476 NULL Pointer Dereference，风险 Medium。""",
        "fix_suggestion": "line 6 strstr 后增加 if (!p) return NULL; 检查，并校验 header 非 NULL。",
        "fix_code": r"""// nullderef_parse.c (fixed)
#include <string.h>
#include <stdlib.h>

char *get_value(const char *header) {
    if (!header) return NULL;
    char *p = strstr(header, ": ");
    if (!p) return NULL;             /* check strstr result */
    p += 2;
    return strdup(p);
}
""",
    },

    # --- NULL-4 安全（hard negative）：输入与 strstr 返回双重 NULL 检查 ---
    {
        "lang": "c",
        "filename": "safe_nullderef.c",
        "is_vuln": False,
        "cwe": "none",
        "risk": "None",
        "code": r"""// safe_nullderef.c
#include <string.h>
#include <stdlib.h>

char *get_value(const char *header) {          // line 5
    if (!header) return NULL;                  // line 6: input check
    char *p = strstr(header, ": ");            // line 7
    if (!p) return NULL;                       // line 8: NULL check
    p += 2;                                    // line 9: safe
    if (!*p) return NULL;                      // line 10: empty check
    return strdup(p);                          // line 11: safe
}
""",
        "source": "N/A",
        "sink": "N/A",
        "explanation": "line 6 if (!header) return NULL 检查输入；line 8 if (!p) return NULL 检查 strstr 返回；line 9 p+=2 与 line 11 strdup(p) 仅在 p 非 NULL 时执行，NULL 解引用路径被阻断。",
        "analysis": """分析过程：
1. 输入识别：line 5 get_value(header) 接收外部 header 字符串。
2. 数据流：line 6 if (!header) return NULL（输入检查）-> line 7 p = strstr(header, ": ") -> line 8 if (!p) return NULL（返回值检查）-> line 9 p += 2 -> line 10 if (!*p) return NULL（空值检查）-> line 11 strdup(p)。
3. 防御评估：line 6 拦截 NULL 输入；line 8 拦截 strstr 未命中返回的 NULL；line 10 进一步拦截空字符串值。所有对 p 的解引用（line 10 的 *p 与 line 11 strdup 内部解引用）均在 line 8 确认 p 非 NULL 之后发生，NULL 指针解引用路径被完全阻断。
4. 关键点：与漏洞版本（nullderef_parse.c）形似，但多了输入检查与 strstr 返回值检查，防御有效。
5. 结论：双重 NULL 检查覆盖输入与库函数返回值，无 NULL Pointer Dereference。""",
        "fix_suggestion": "no fix needed",
        "fix_code": "N/A",
    },
]


def build_sample(s):
    user = build_user(s["code"], s["lang"], s["filename"])
    verdict = build_verdict(s)
    json_str = json.dumps(verdict, ensure_ascii=False, indent=2)
    assistant = f"{s['analysis']}\n\n```json\n{json_str}\n```"
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ]
    }


def main():
    print("=" * 64)
    print("生成 CWE-416 / CWE-415 / CWE-476 高质量训练样本")
    print("=" * 64)

    vuln = sum(1 for s in SAMPLES if s["is_vuln"])
    safe = len(SAMPLES) - vuln
    print(f"样本总数: {len(SAMPLES)}（漏洞 {vuln} + 安全 {safe}）")

    cwe_count = Counter(s["cwe"] for s in SAMPLES)
    print("CWE 分布:")
    for k, v in cwe_count.most_common():
        print(f"  {v:2d}  {k}")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for s in SAMPLES:
            obj = build_sample(s)
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    print(f"\n已写入: {OUTPUT_FILE}")

    # ---- 验证 ----
    print("\n=== 验证输出 ===")
    with open(OUTPUT_FILE, encoding="utf-8") as f:
        lines = [l for l in f if l.strip()]

    errors = []
    parse_ok = 0
    label_counter = Counter()
    for idx, line in enumerate(lines, 1):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            errors.append(f"行 {idx}: JSON 解析失败 - {e}")
            continue

        msgs = obj.get("messages", [])
        if len(msgs) != 3 or [m["role"] for m in msgs] != ["system", "user", "assistant"]:
            errors.append(f"行 {idx}: messages 角色序列不正确")
            continue

        v = parse_verdict(msgs[2]["content"])
        if not v or "has_vulnerability" not in v:
            errors.append(f"行 {idx}: parse_verdict 未提取到 has_vulnerability")
            continue
        parse_ok += 1

        has_vuln = v.get("has_vulnerability")
        vtype = v.get("vulnerability_type", "")

        if has_vuln is True:
            label_counter[vtype] += 1
            if vtype not in ("CWE-416 Use After Free",
                             "CWE-415 Double Free",
                             "CWE-476 NULL Pointer Dereference"):
                errors.append(f"行 {idx}: 漏洞样本标签异常 '{vtype}'")
            for fld in ("source", "sink", "explanation", "fix_suggestion", "fix_code"):
                if not v.get(fld) or v.get(fld) == "N/A":
                    errors.append(f"行 {idx}: 漏洞样本字段 {fld} 不应为 N/A/空")
        elif has_vuln is False:
            label_counter["none（安全）"] += 1
            if vtype != "none":
                errors.append(f"行 {idx}: 安全样本 vulnerability_type 应为 none，实为 '{vtype}'")
            for fld in ("source", "sink"):
                if v.get(fld) != "N/A":
                    errors.append(f"行 {idx}: 安全样本 {fld} 应为 N/A")
        else:
            errors.append(f"行 {idx}: has_vulnerability 非布尔值: {has_vuln}")

    print(f"总条数: {len(lines)}（期望 20）")
    print(f"parse_verdict 通过: {parse_ok}/20")
    print("标签分布:")
    for k, v in label_counter.most_common():
        print(f"  {v:2d}  {k}")

    if errors:
        print(f"\n[ERROR] 发现 {len(errors)} 个问题:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("\n✓ 所有验证通过：条数=20、parse_verdict 全部通过、CWE 标签正确、安全样本字段合规。")


if __name__ == "__main__":
    main()
