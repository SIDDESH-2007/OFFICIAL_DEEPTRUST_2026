import os
import sys

# Root script pointing to server/scripts/mobile_monitor.py
script_path = os.path.join(os.path.dirname(__file__), 'server', 'scripts', 'mobile_monitor.py')

with open(script_path, 'r', encoding='utf-8') as f:
    code = f.read()

exec(compile(code, script_path, 'exec'))
