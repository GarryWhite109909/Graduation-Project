# -*- coding: utf-8 -*-
import sys
t = open(sys.argv[1], encoding='utf-8').read()
key = sys.argv[2]
i = t.find(key)
print(t[i-80:i+420] if i >= 0 else 'not found')
