import os
import sys
import subprocess
import time
import webbrowser
import json
import socket


def check_port(host, port, timeout=1):
    try:
        s = socket.create_connection((host, port), timeout)
        s.close()
        return True
    except Exception:
        return False


def status(msg):
    print(f'[DeepTrust] {msg}', flush=True)


def load_version():
    try:
        vf = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), 'version.json')
        if os.path.exists(vf):
            with open(vf) as f:
                return json.load(f).get('version', '1.0.0')
    except Exception:
        pass
    return '1.0.0'


def find_project_root():
    """Search for the DeepTrust project root relative to the EXE location."""
    exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    candidates = [
        exe_dir,
        os.path.join(exe_dir, '..'),
        os.path.join(exe_dir, '..', '..'),
        os.path.join(exe_dir, 'DEEEPTRUST.02'),
    ]
    for c in candidates:
        c = os.path.abspath(c)
        if os.path.exists(os.path.join(c, 'server', 'server.js')):
            return c
    return None


def main():
    version = load_version()
    print()
    print('============================================================')
    print('           DEEPTRUST SECURE ACCESS PLATFORM')
    print(f'                   Version {version}')
    print('============================================================')
    print()

    project = find_project_root()
    if not project:
        print('[ERROR] Cannot locate DeepTrust project directory.')
        print('[ERROR] Ensure DeepTrust.exe is placed relative to the project root.')
        print('[ERROR] Expected: server/server.js must be locatable from EXE location.')
        print()
        input('Press Enter to exit...')
        sys.exit(1)

    launcher_js = os.path.join(project, 'server', 'scripts', 'deeptrust_launcher.js')
    if not os.path.exists(launcher_js):
        print(f'[ERROR] Launcher script not found: {launcher_js}')
        print('[ERROR] The DeepTrust project appears to be incomplete.')
        input('Press Enter to exit...')
        sys.exit(1)

    status(f'Project root: {project}')
    status('Starting DeepTrust services via Node.js launcher...')
    print()

    proc = subprocess.Popen(
        ['node', 'server/scripts/deeptrust_launcher.js', 'start'],
        cwd=project,
        shell=True
    )
    proc.wait()


if __name__ == '__main__':
    main()
