# -*- coding: utf-8 -*-
import re
t = open('live_v2.xml', encoding='utf-8').read()
# 禁止出现的旧口径/红线词
banned = ['157 段', '300 次', '59.1', '250 次', '96.7%', '15.7%', '11.7%', '95%检出',
          '飞轮已', '单一作者', '83.7', '2026 年 6 月', '觉醒', '数据泄露', '降80', '降低 80']
print('== banned ==')
for w in banned:
    n = t.count(w)
    if n:
        print('FOUND', w, n)
        for m in re.finditer(re.escape(w), t):
            print('   ...', t[max(0,m.start()-60):m.end()+60].replace('\n',' '))
print('== alpha0.6 contexts ==')
for m in re.finditer(r'α0\.6|alpha0\.6|α 0\.6', t):
    print('   ...', t[max(0,m.start()-50):m.end()+90].replace('\n',' '))
