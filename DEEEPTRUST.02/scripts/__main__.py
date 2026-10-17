import os
import sys

target_script = os.path.join(os.path.dirname(__file__), '..', 'server', 'scripts', 'mobile_monitor.py')

with open(target_script, 'r', encoding='utf-8') as f:
    code = f.read()

exec(compile(code, target_script, 'exec'))
