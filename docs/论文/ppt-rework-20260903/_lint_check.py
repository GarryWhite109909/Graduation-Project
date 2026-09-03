# -*- coding: utf-8 -*-
import json, subprocess, sys
LINT = r'C:\Users\zane\AppData\Local\Doubao\User Data\Default\.doubao\agent_mode\workspace\.skills\ppt\scripts\xml_lint.py'
for p in sys.argv[1:]:
    r = subprocess.run(['python', LINT, '--input', f'pages/{p}.xml'], capture_output=True, text=True, encoding='utf-8')
    d = json.loads(r.stdout)
    print('=====', p, 'errors=', d['summary']['error_count'])
    for e in d['slides'][0]['errors']:
        desc = []
        for ro in e.get('related_objects', []):
            bb = ro.get('bbox', {})
            desc.append(f"{ro.get('kind')}/{ro.get('type')}@({bb.get('x')},{bb.get('y')},{bb.get('width')},{bb.get('height')})")
        print(' ', e['code'], '|', '; '.join(desc), '|', e.get('measurement'))
