# Python Requirements
# installs only the missing packages from requirements.txt when run.py starts

# Imports
from importlib.util import find_spec
from pathlib import Path
import subprocess
import sys


def ensure_python_dependencies(project_root):
    if sys.version_info < (3, 11):
        print('Python 3.11 or newer is required.', file=sys.stderr)
        return False
    missing = [name for name in ('asyncssh', 'httpx') if find_spec(name) is None]
    if not missing:
        return True
    print('Installing missing Python requirements: ' + ', '.join(missing), flush=True)
    command = [sys.executable, '-m', 'pip', 'install', '-r', str(Path(project_root) / 'requirements.txt')]
    try:
        subprocess.run(command, check=True, timeout=600)
        return True
    except (OSError, subprocess.SubprocessError) as exc:
        print(f'Could not install requirements: {exc}. Run python -m pip install -r requirements.txt, then retry.', file=sys.stderr)
        return False
