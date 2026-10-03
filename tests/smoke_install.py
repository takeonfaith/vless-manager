"""Run as root only in a disposable Ubuntu/Debian systemd VM (CI)."""
from pathlib import Path
import subprocess


def cli(*args, ok=True):
    p = subprocess.run(['vless-manager', *args], capture_output=True, text=True, timeout=900)
    if ok and p.returncode:
        raise RuntimeError(p.stderr)
    if not ok and not p.returncode:
        raise AssertionError('Expected operation to fail')
    return p.stdout.strip()


cli('setup', '--host', '127.0.0.1', '--port', '18443')
path = Path('/etc/vless-manager/config.json')
original = path.read_bytes()
cli('setup', '--host', '127.0.0.1', '--port', '18443')
assert path.read_bytes() == original, 'Repeated setup changed keys'
link = cli('add', 'ci-phone')
assert link.startswith('vless://') and 'security=reality' in link
assert link == cli('link', 'ci-phone')
cli('add', 'ci-laptop')
assert cli('list').splitlines() == ['ci-phone', 'ci-laptop']
before_duplicate = path.read_bytes()
cli('add', 'ci-phone', ok=False)
assert path.read_bytes() == before_duplicate
cli('remove', 'ci-phone', '--yes')
assert cli('list') == 'ci-laptop'
cli('remove', 'ci-laptop', '--yes')
assert cli('list') == ''
assert cli('status') == 'active'
assert cli('check') == 'OK'
assert path.stat().st_mode & 0o777 == 0o640
print('Clean install, idempotency, user lifecycle and systemd checks passed.')
