lines = open('src/dashboard/app.py', encoding='utf-8').readlines()
for i, l in enumerate(lines):
    if '# \u2500\u2500 Design tokens' in l:
        print('tokens_start:', i+1)
    if '</style>' in l and i > 50 and i < 400:
        print('css_end:', i+1, l.strip()[:60])
