import re
with open('d:/DEEPTRUST PROJECT 2026/deeptrust/DEEEPTRUST.02/client/dashboard.html', 'r', encoding='utf-8') as f:
    html = f.read()

views = re.findall(r'data-view=\"([^\"]+)\"', html)
sections = re.findall(r'<section[^>]+id=\"([^\"]+)\"', html)
print('Views:', list(set(views)))
print('Sections:', list(set(sections)))
