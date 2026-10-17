import os
import sys

# Root mobile monitor entry point
target_script = os.path.join(os.path.dirname(__file__), 'DEEEPTRUST.02', 'server', 'scripts', 'mobile_monitor.py')
if not os.path.exists(target_script):
    target_script = os.path.join(os.path.dirname(__file__), 'server', 'scripts', 'mobile_monitor.py')

sys.path.insert(0, os.path.dirname(target_script))

with open(target_script, 'r', encoding='utf-8') as f:
    code = f.read()

exec(compile(code, target_script, 'exec'))
