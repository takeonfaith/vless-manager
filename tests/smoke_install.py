"""Run as root only in a disposable Ubuntu/Debian systemd VM (CI)."""
from pathlib import Path
import json
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
pid_command = ['systemctl', 'show', 'vless-manager-xray', '-p', 'MainPID', '--value']
initial_pid = subprocess.check_output(pid_command)
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
assert subprocess.check_output(pid_command) == initial_pid, 'User management restarted Xray'

# Exercise a real 1.0 -> 1.1 migration in this disposable VM as well.
cli('add', 'legacy-user')
legacy = json.loads(path.read_text())
legacy.pop('api')
legacy['outbounds'] = [o for o in legacy['outbounds'] if o['tag'] != 'vless-manager-api-block']
legacy['routing']['rules'] = [r for r in legacy['routing']['rules']
                            if r.get('outboundTag') != 'vless-manager-api-block']
path.write_text(json.dumps(legacy))
subprocess.run(['systemctl', 'restart', 'vless-manager-xray'], check=True)
cli('add', 'must-fail-without-api', ok=False)
cli('enable-api')
upgraded = json.loads(path.read_text())
assert upgraded['inbounds'] == legacy['inbounds'], 'Migration changed keys/users'
migrated_pid = subprocess.check_output(pid_command)
cli('enable-api')
cli('add', 'after-migration')
cli('remove', 'after-migration', '--yes')
assert subprocess.check_output(pid_command) == migrated_pid, 'Migrated management restarted Xray'
print('Clean install, live users, unchanged PID, and legacy migration checks passed.')
