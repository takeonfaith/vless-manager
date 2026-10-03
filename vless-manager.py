#!/usr/bin/env python3
"""Small, dependency-free CLI for VLESS + REALITY on a systemd VPS."""
import argparse
import fcntl
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
import zipfile

STATE = Path('/etc/vless-manager')
META = STATE / 'manager.json'
BACKUPS = Path('/var/lib/vless-manager/backups')
BINARY = Path('/usr/local/lib/vless-manager/xray')
CONFIG = STATE / 'config.json'
SERVICE = 'vless-manager-xray.service'
UNIT = Path('/etc/systemd/system') / SERVICE
XRAY_VERSION = '26.3.27'
FLOW = 'xtls-rprx-vision'


class Error(Exception):
    pass


def run(args, *, timeout=60):
    """Never echo command arguments/output: either can contain private keys."""
    try:
        result = subprocess.run([str(a) for a in args], capture_output=True,
                                text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Error(f'Не удалось выполнить {Path(str(args[0])).name}.') from exc
    if result.returncode:
        raise Error(f'{Path(str(args[0])).name}: код ошибки {result.returncode}.')
    return result.stdout.strip()


def hostname(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        value = value.rstrip('.').lower()
        if len(value) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p)
                                        for p in value.split('.')):
            raise argparse.ArgumentTypeError('Нужен IP или DNS-имя без схемы и порта.')
        return value


def name(value):
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', value):
        raise argparse.ArgumentTypeError('Имя: 1–64 символа A-Z, a-z, 0-9, _ или -.')
    return value


def port(value):
    try:
        number = int(value)
        if 1 <= number <= 65535:
            return number
    except ValueError:
        pass
    raise argparse.ArgumentTypeError('Порт должен быть от 1 до 65535.')


def atomic_write(path, data, *, mode=0o600, uid=0, gid=0):
    path = Path(path)
    if path.is_symlink():
        raise Error(f'Символическая ссылка не поддерживается: {path}')
    fd, tmp = tempfile.mkstemp(prefix='.vless-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), uid, gid)
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def encode(data):
    return (json.dumps(data, ensure_ascii=False, indent=2) + '\n').encode()


def read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise Error(f'Не удалось прочитать JSON: {path}') from exc


def inbound(config, tag=None):
    matches = [i for i in config.get('inbounds', [])
               if i.get('protocol') == 'vless'
               and i.get('streamSettings', {}).get('security') == 'reality'
               and (tag is None or i.get('tag') == tag)]
    if len(matches) != 1:
        raise Error('Нужен ровно один VLESS + REALITY inbound; укажи --tag при adopt.')
    item = matches[0]
    if item['streamSettings'].get('network', 'tcp') not in ('tcp', 'raw'):
        raise Error('Поддерживается только VLESS + REALITY через TCP/RAW.')
    r = item['streamSettings']['realitySettings']
    if not r.get('privateKey') or not r.get('serverNames') or not r.get('shortIds'):
        raise Error('В REALITY отсутствуют privateKey, serverNames или shortIds.')
    if not isinstance(item.get('settings', {}).get('clients'), list):
        raise Error('В inbound отсутствует массив clients.')
    return item


def key_pair(binary, private=None):
    args = [binary, 'x25519']
    if private:
        args += ['-i', private]
    output = run(args)
    values = {}
    for line in output.splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            values[key.strip().lower().replace(' ', '')] = value.strip()
    secret = private or values.get('privatekey')
    public = (values.get('password(publickey)') or values.get('password')
              or values.get('publickey'))
    if not secret or not public or not re.fullmatch(r'[A-Za-z0-9_-]{43}', public):
        raise Error('Не удалось разобрать ключи xray x25519; секретный вывод скрыт.')
    return secret, public


def client_link(item, client, host, public):
    reality = item['streamSettings']['realitySettings']
    query = {'encryption': 'none', 'security': 'reality',
             'sni': reality['serverNames'][0], 'fp': 'chrome', 'pbk': public,
             'sid': reality['shortIds'][0], 'type': 'tcp'}
    if client.get('flow'):
        query['flow'] = client['flow']
    address = f'[{host}]' if ':' in host else host
    return (f'vless://{client["id"]}@{address}:{item["port"]}?'
            + urllib.parse.urlencode(query) + '#'
            + urllib.parse.quote(client.get('email', 'device'), safe=''))


def new_config(private, sni, listen_port):
    return {'log': {'loglevel': 'warning'}, 'inbounds': [{
        'tag': 'vless-reality', 'listen': '0.0.0.0', 'port': listen_port,
        'protocol': 'vless', 'settings': {'clients': [], 'decryption': 'none'},
        'streamSettings': {'network': 'tcp', 'security': 'reality',
                           'realitySettings': {'show': False, 'target': f'{sni}:443',
                                               'xver': 0, 'serverNames': [sni],
                                               'privateKey': private,
                                               'shortIds': [secrets.token_hex(8)]}}}],
        'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}]}


def validate(binary, path):
    run([binary, 'run', '-test', '-config', path])


def healthy(service):
    # systemctl restart may succeed before Xray exits on a runtime error.
    for _ in range(2):
        time.sleep(1)
        run(['systemctl', 'is-active', '--quiet', service])


def apply_config(meta, candidate):
    path = Path(meta['config'])
    if path.is_symlink():
        raise Error('Конфигурация не должна быть символической ссылкой.')
    original = path.read_bytes()
    st = path.stat()
    fd, tmp = tempfile.mkstemp(prefix='.validate-', suffix='.json', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(encode(candidate))
        validate(meta['binary'], tmp)
    finally:
        os.unlink(tmp)
    BACKUPS.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(BACKUPS, 0o700)
    backup = BACKUPS / f'{time.time_ns()}-{secrets.token_hex(4)}.json'
    atomic_write(backup, original)
    attrs = {'mode': st.st_mode & 0o777, 'uid': st.st_uid, 'gid': st.st_gid}
    try:
        atomic_write(path, encode(candidate), **attrs)
        run(['systemctl', 'restart', meta['service']])
        healthy(meta['service'])
    except (Error, OSError, KeyboardInterrupt) as exc:
        atomic_write(path, original, **attrs)
        try:
            run(['systemctl', 'restart', meta['service']])
            healthy(meta['service'])
        except Error:
            raise Error(f'Конфиг восстановлен, но служба не запустилась. Backup: {backup}') from exc
        raise Error('Изменение отменено; прежний конфиг восстановлен, Xray работает.') from exc


def current():
    if not META.exists():
        raise Error('Сначала выполни setup для новой машины или adopt для существующего Xray.')
    meta = read_json(META)
    config = read_json(meta['config'])
    return meta, config, inbound(config, meta.get('tag'))


def unique_client(item, device):
    found = [c for c in item['settings']['clients'] if c.get('email') == device]
    if len(found) != 1:
        raise Error('Устройство не найдено или его имя не уникально.')
    return found[0]


def check_target(sni):
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['h2'])
    try:
        with socket.create_connection((sni, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as tls:
                if tls.selected_alpn_protocol() != 'h2':
                    raise Error('Выбранный SNI не поддерживает HTTP/2. Выбери другой --sni.')
    except (OSError, ValueError) as exc:
        raise Error('SNI недоступен или не поддерживает TLS 1.3 с корректным сертификатом.') from exc


def download_xray(version):
    arch = {'x86_64': '64', 'aarch64': 'arm64-v8a'}.get(platform.machine())
    if not arch:
        raise Error('Поддерживаются только Linux x86_64 и arm64.')
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise Error('Версия Xray должна иметь вид 26.3.27.')
    url = f'https://github.com/XTLS/Xray-core/releases/download/v{version}/Xray-linux-{arch}.zip'
    with tempfile.TemporaryDirectory(prefix='vless-download-') as directory:
        archive = Path(directory) / 'xray.zip'
        digest = Path(directory) / 'xray.dgst'
        for source, dest in [(url, archive), (url + '.dgst', digest)]:
            run(['curl', '--fail', '--silent', '--show-error', '--location',
                 '--proto', '=https', '--tlsv1.2', '--connect-timeout', '15',
                 '--max-time', '180', '--retry', '2', '--output', dest, source], timeout=600)
        sha = hashlib.sha256(archive.read_bytes()).hexdigest()
        if sha not in re.findall(r'\b[0-9a-f]{64}\b', digest.read_text().lower()):
            raise Error('SHA-256 архива Xray не совпал с официальным .dgst.')
        with zipfile.ZipFile(archive) as z:
            data = z.read('xray')
        BINARY.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        # main() uses umask 077; the service user must be able to traverse this directory.
        os.chmod(BINARY.parent, 0o755)
        atomic_write(BINARY, data, mode=0o755)
    run([BINARY, 'version'])


def setup(args):
    if ':' in args.host or ':' in args.sni:
        raise Error('Для setup нужен публичный IPv4/DNS с A-записью и DNS-имя SNI.')
    if META.exists():
        meta, config, _ = current()
        if (meta['host'] != args.host or meta['config'] != str(CONFIG)
                or inbound(config)['port'] != args.port
                or inbound(config)['streamSettings']['realitySettings']['serverNames'][0] != args.sni):
            raise Error('Настройка уже существует с другими параметрами. Перезапись запрещена.')
        validate(meta['binary'], meta['config'])
        healthy(meta['service'])
        print('Уже настроено. Ключи и пользователи сохранены.')
        return
    os_info = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            os_info[key] = value.strip('"')
    supported = {'ubuntu': {'22.04', '24.04', '26.04'}, 'debian': {'12', '13'}}
    if os_info.get('VERSION_ID') not in supported.get(os_info.get('ID'), set()):
        raise Error('Setup поддерживает Ubuntu 22.04/24.04/26.04 и Debian 12/13.')
    if not Path('/run/systemd/system').is_dir():
        raise Error('Нужна машина с работающим systemd.')
    existing = [CONFIG, UNIT, BINARY, Path('/usr/local/etc/xray/config.json'), Path('/etc/xray/config.json')]
    if any(p.exists() for p in existing) or shutil.which('xray'):
        raise Error('Обнаружен Xray или незавершённая установка. Используй adopt; setup ничего не перезаписывает.')
    try:
        with socket.socket() as sock:
            sock.bind(('0.0.0.0', args.port))
    except OSError as exc:
        raise Error(f'Порт {args.port} занят или недоступен.') from exc
    check_target(args.sni)
    print('Устанавливаю зависимости и проверенный архив Xray...', flush=True)
    run(['apt-get', 'update', '-qq'], timeout=600)
    run(['env', 'DEBIAN_FRONTEND=noninteractive', 'apt-get', 'install', '-y', '-qq',
         'ca-certificates', 'curl'], timeout=600)
    try:
        download_xray(args.xray_version)
        try:
            grp.getgrnam('vless-xray')
        except KeyError:
            run(['groupadd', '--system', 'vless-xray'])
        try:
            run(['id', '-u', 'vless-xray'])
        except Error:
            run(['useradd', '--system', '--gid', 'vless-xray', '--no-create-home',
                 '--shell', '/usr/sbin/nologin', 'vless-xray'])
        group = grp.getgrnam('vless-xray').gr_gid
        os.chown(STATE, 0, group)
        os.chmod(STATE, 0o750)
        private, _ = key_pair(BINARY)
        config = new_config(private, args.sni, args.port)
        atomic_write(CONFIG, encode(config), mode=0o640, gid=group)
        validate(BINARY, CONFIG)
        unit = f'''[Unit]
Description=VLESS REALITY managed by vless-manager
After=network-online.target
Wants=network-online.target

[Service]
User=vless-xray
Group=vless-xray
ExecStart={BINARY} run -config {CONFIG}
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
UMask=0077
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
'''
        atomic_write(UNIT, unit.encode(), mode=0o644)
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', '--now', SERVICE])
        healthy(SERVICE)
        meta = {'config': str(CONFIG), 'binary': str(BINARY), 'service': SERVICE,
                'host': args.host, 'tag': 'vless-reality'}
        atomic_write(META, encode(meta))
    except (Error, OSError, KeyboardInterrupt) as exc:
        if UNIT.exists():
            try:
                run(['systemctl', 'disable', '--now', SERVICE])
            except Error:
                raise Error('Установка прервана; не удалось остановить службу. Проверь systemctl status ' + SERVICE) from exc
        for p in (META, CONFIG, UNIT, BINARY):
            p.unlink(missing_ok=True)
        run(['systemctl', 'daemon-reload'])
        raise
    print(f'Готово. Разреши входящий TCP {args.port} в firewall VPS и панели хостинга.')
    print('Firewall автоматически не меняется. Добавь устройство: sudo vless-manager add iphone')


def adopt(args):
    if META.exists():
        raise Error('Менеджер уже настроен; повторный adopt запрещён.')
    path = Path(args.config).absolute()
    if path.is_symlink() or not path.is_file() or any(c.isspace() for c in str(path)):
        raise Error('Нужен обычный config.json без пробелов в пути.')
    binary = str(Path(args.binary).resolve())
    config = read_json(path)
    inbound(config, args.tag)
    service = args.service.removesuffix('.service') + '.service'
    if not re.fullmatch(r'[A-Za-z0-9_@.-]+\.service', service) or service.startswith('-'):
        raise Error('Некорректное имя systemd-службы.')
    command = run(['systemctl', 'show', service, '--property=ExecStart', '--value'])
    if not re.search(r'(?:-config|--config|-c)\s+' + re.escape(str(path)) + r'(?:\s|;|$)', command):
        raise Error('ExecStart службы не использует указанный config. Конфигурации из каталогов не поддерживаются.')
    if '-confdir' in command:
        raise Error('Службы с -confdir не поддерживаются.')
    validate(binary, path)
    healthy(service)
    key_pair(binary, inbound(config, args.tag)['streamSettings']['realitySettings']['privateKey'])
    atomic_write(META, encode({'config': str(path), 'binary': binary, 'service': service,
                              'host': args.host, 'tag': args.tag}))
    print('Существующий Xray подключён. Конфиг и пользователи сохранены; служба не перезапускалась.')
    if path.stat().st_mode & 0o004:
        print('Примечание: существующий config читается всеми локальными пользователями; права сохранены.')


def parser():
    p = argparse.ArgumentParser(description='VLESS + REALITY: установка и управление устройствами.')
    p.add_argument('--version', action='version', version='vless-manager 1.0.0')
    sub = p.add_subparsers(dest='command', required=True)
    s = sub.add_parser('setup', help='Настроить новый VPS (Ubuntu/Debian + systemd)')
    s.add_argument('--host', required=True, type=hostname, help='Публичный IPv4 или DNS сервера')
    s.add_argument('--sni', default='www.bing.com', type=hostname)
    s.add_argument('--port', default=443, type=port)
    s.add_argument('--xray-version', default=XRAY_VERSION)
    a = sub.add_parser('adopt', help='Подключить существующую конфигурацию без её изменения')
    a.add_argument('--host', required=True, type=hostname)
    a.add_argument('--config', default='/usr/local/etc/xray/config.json')
    a.add_argument('--binary', default='/usr/local/bin/xray')
    a.add_argument('--service', default='xray')
    a.add_argument('--tag', help='Тег inbound, если VLESS + REALITY inbound несколько')
    for command, help_text in [('add', 'Добавить устройство и вывести ссылку'),
                               ('remove', 'Отозвать доступ устройства'),
                               ('link', 'Показать ссылку существующего устройства')]:
        cmd = sub.add_parser(command, help=help_text)
        cmd.add_argument('name', type=name)
        if command == 'remove':
            cmd.add_argument('--yes', action='store_true', help='Удалить без вопроса')
    sub.add_parser('list', help='Список имён устройств (без секретов)')
    sub.add_parser('check', help='Проверить конфиг Xray')
    sub.add_parser('status', help='Состояние systemd-службы')
    sub.add_parser('logs', help='Последние 50 строк журнала Xray')
    sub.add_parser('restart', help='Проверить конфиг и перезапустить Xray')
    h = sub.add_parser('set-host', help='Изменить адрес в выдаваемых ссылках')
    h.add_argument('host', type=hostname)
    return p


def dispatch(args):
    if args.command == 'setup':
        return setup(args)
    if args.command == 'adopt':
        return adopt(args)
    meta, config, item = current()
    if args.command == 'list':
        for client in item['settings']['clients']:
            print(client.get('email') or '(без имени: добавь email вручную)')
    elif args.command == 'status':
        print(run(['systemctl', 'is-active', meta['service']]))
    elif args.command == 'logs':
        print(run(['journalctl', '-u', meta['service'], '-n', '50', '--no-pager']))
    elif args.command in ('check', 'restart'):
        validate(meta['binary'], meta['config'])
        if args.command == 'restart':
            run(['systemctl', 'restart', meta['service']])
            healthy(meta['service'])
        print('OK')
    elif args.command == 'set-host':
        meta['host'] = args.host
        atomic_write(META, encode(meta))
        print('Адрес обновлён. Заново импортируй ссылки на устройствах; конфиг Xray не менялся.')
    elif args.command in ('add', 'link'):
        _, public = key_pair(meta['binary'], item['streamSettings']['realitySettings']['privateKey'])
        if args.command == 'add':
            if any(c.get('email') == args.name for c in item['settings']['clients']):
                raise Error('Имя уже существует. Используй link, чтобы получить прежнюю ссылку.')
            client = {'id': str(uuid.uuid4()), 'email': args.name, 'flow': FLOW}
            item['settings']['clients'].append(client)
            link = client_link(item, client, meta['host'], public)
            apply_config(meta, config)
        else:
            client = unique_client(item, args.name)
            link = client_link(item, client, meta['host'], public)
        print(link)
    elif args.command == 'remove':
        client = unique_client(item, args.name)
        if not args.yes:
            if not sys.stdin.isatty():
                raise Error('Для удаления без терминала укажи --yes.')
            if input(f'Отозвать доступ {args.name}? [y/N]: ').lower() not in ('y', 'yes'):
                print('Отменено.')
                return
        item['settings']['clients'].remove(client)
        apply_config(meta, config)
        print(f'Доступ {args.name} отозван.')


def main():
    args = parser().parse_args()
    if os.geteuid() != 0:
        raise Error('Запусти команду через sudo или от root.')
    if platform.system() != 'Linux':
        raise Error('Команды управления поддерживают только Linux.')
    os.umask(0o077)
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    # All reads and mutations share a lock, preventing lost concurrent updates.
    with (STATE / 'manager.lock').open('a') as lock:
        os.chmod(STATE / 'manager.lock', 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        dispatch(args)


if __name__ == '__main__':
    try:
        main()
    except (Error, OSError, ValueError, KeyError) as exc:
        print(f'Ошибка: {exc}', file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print('Отменено.', file=sys.stderr)
        sys.exit(130)
