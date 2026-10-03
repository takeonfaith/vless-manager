"""Opt-in real VLESS handshake; uses only temporary files and loopback ports.

XRAY_TEST_BINARY=/path/to/xray python3 -m unittest discover -s tests -v
Requires outbound HTTPS to www.bing.com for the REALITY target.
"""
import http.server
import http.client
import copy
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('manager', Path(__file__).parents[1] / 'vless-manager.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', str(len(b'vless-manager-integration-ok')))
        self.end_headers()
        self.wfile.write(b'vless-manager-integration-ok')

    def log_message(self, *args):
        pass


@unittest.skipUnless(os.environ.get('XRAY_TEST_BINARY'), 'Set XRAY_TEST_BINARY for real VLESS test')
class RealXrayTest(unittest.TestCase):
    def test_real_vless_and_revoked_user(self):
        binary = os.environ['XRAY_TEST_BINARY']
        private, public = m.key_pair(binary)
        server_port, socks_port = free_port(), free_port()
        identity = str(uuid.uuid4())
        config = m.configure_api(m.new_config(private, 'www.bing.com', server_port), None, free_port())
        item = m.inbound(config)
        item['listen'] = '127.0.0.1'
        item['settings']['clients'] = [{'id': identity, 'email': 'integration', 'flow': m.FLOW}]
        client = {
            'log': {'loglevel': 'error'},
            'inbounds': [{'listen': '127.0.0.1', 'port': socks_port, 'protocol': 'socks',
                          'settings': {'auth': 'noauth'}}],
            'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [
                {'address': '127.0.0.1', 'port': server_port,
                 'users': [{'id': identity, 'encryption': 'none', 'flow': m.FLOW}]}]},
                'streamSettings': {'network': 'tcp', 'security': 'reality',
                                   'realitySettings': {'serverName': 'www.bing.com',
                                                      'fingerprint': 'firefox', 'password': public,
                                                      'shortId': item['streamSettings']['realitySettings']['shortIds'][0]}}}]}
        httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        processes = []

        def stop(process):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

        with tempfile.TemporaryDirectory(prefix='vless-runtime-') as directory:
            def start(data, filename):
                path = Path(directory) / filename
                path.write_bytes(m.encode(data))
                path.chmod(0o600)
                m.validate(binary, path)
                proc = subprocess.Popen([binary, 'run', '-config', str(path)],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                processes.append(proc)
                time.sleep(1)
                self.assertIsNone(proc.poll(), 'Temporary Xray failed to start')
                return proc
            try:
                server = start(config, 'server.json')
                start(client, 'client.json')
                def request():
                    return subprocess.run([
                        'curl', '-fsS', '--max-time', '15', '--noproxy', '',
                        '--proxy', f'socks5h://127.0.0.1:{socks_port}',
                        f'http://127.0.0.1:{httpd.server_port}/'], capture_output=True, timeout=20)
                result = request()
                self.assertEqual(result.returncode, 0, 'VLESS connection failed')
                self.assertEqual(result.stdout, b'vless-manager-integration-ok')
                # Keep a real authenticated TCP stream alive across both RPCs.
                persistent = socket.create_connection(('127.0.0.1', socks_port), timeout=10)
                persistent.sendall(b'\x05\x01\x00')
                self.assertEqual(persistent.recv(2), b'\x05\x00')
                persistent.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1')
                                   + httpd.server_port.to_bytes(2, 'big'))
                reply = persistent.recv(10, socket.MSG_WAITALL)
                self.assertEqual(reply[:2], b'\x05\x00')
                def same_connection():
                    persistent.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n')
                    response = http.client.HTTPResponse(persistent)
                    response.begin()
                    self.assertEqual(response.read(), b'vless-manager-integration-ok')
                    response.close()
                try:
                    same_connection()
                    meta = {'config': str(Path(directory) / 'server.json'), 'binary': binary,
                            'service': 'must-not-be-restarted', 'tag': 'vless-reality'}
                    second = {'id': str(uuid.uuid4()), 'email': 'second', 'flow': m.FLOW}
                    candidate = copy.deepcopy(config)
                    m.inbound(candidate)['settings']['clients'].append(second)
                    with patch.object(m, 'BACKUPS', Path(directory) / 'backups'), patch.object(m.os, 'fchown'):
                        m.apply_user(meta, candidate, 'add', second)
                        same_connection()
                        self.assertIsNone(server.poll(), 'Server stopped on add')
                        self.assertEqual(m.api_users(meta, candidate)['second'], second['id'])
                        second_client = copy.deepcopy(client)
                        second_port = free_port()
                        second_client['inbounds'][0]['port'] = second_port
                        second_client['outbounds'][0]['settings']['vnext'][0]['users'][0]['id'] = second['id']
                        start(second_client, 'second-client.json')
                        def second_request():
                            return subprocess.run(['curl', '-fsS', '--max-time', '8', '--noproxy', '',
                                '--proxy', f'socks5h://127.0.0.1:{second_port}',
                                f'http://127.0.0.1:{httpd.server_port}/'], capture_output=True, timeout=12)
                        self.assertEqual(second_request().returncode, 0, 'New user could not connect')
                        m.apply_user(meta, config, 'remove', second)
                        same_connection()
                        self.assertNotEqual(second_request().returncode, 0, 'Revoked user still connects')
                        self.assertIsNone(server.poll(), 'Server stopped on remove')
                        self.assertEqual(m.read_json(meta['config']), config)
                finally:
                    persistent.close()
            finally:
                for proc in processes:
                    stop(proc)


if __name__ == '__main__':
    unittest.main()
