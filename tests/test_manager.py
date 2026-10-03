import argparse
import contextlib
import copy
import importlib.util
import io
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from urllib.parse import urlsplit, parse_qs

spec = importlib.util.spec_from_file_location('manager', Path(__file__).parents[1] / 'vless-manager.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = m.configure_api(m.new_config('test-private-key', 'www.example.com', 443), None, 10085)
        self.config['inbounds'].insert(0, {'protocol': 'socks', 'port': 1080})
        self.item = self.config['inbounds'][1]
        self.item['settings']['clients'] = [
            {'id': '11111111-1111-4111-8111-111111111111', 'email': 'existing', 'flow': m.FLOW}]
        self.path = self.root / 'config.json'
        self.path.write_bytes(m.encode(self.config))
        self.path.chmod(0o640)
        self.meta = {'config': str(self.path), 'binary': '/test/xray',
                     'service': 'example.service', 'host': '203.0.113.10', 'tag': 'vless-reality'}
        self.meta_path = self.root / 'manager.json'
        self.meta_path.write_bytes(m.encode(self.meta))
        for target, value in [('META', self.meta_path), ('BACKUPS', self.root / 'backups')]:
            p = patch.object(m, target, value)
            p.start()
            self.addCleanup(p.stop)
        # Let filesystem tests run as a regular developer on macOS too.
        p = patch.object(m.os, 'fchown')
        p.start()
        self.addCleanup(p.stop)

    def call(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            m.dispatch(m.parser().parse_args(argv))
        return out.getvalue().strip()

    def test_selects_correct_inbound(self):
        self.assertIs(m.inbound(self.config), self.item)
        self.config['inbounds'].append(copy.deepcopy(self.item))
        self.config['inbounds'][-1]['tag'] = 'second'
        with self.assertRaises(m.Error):
            m.inbound(self.config)
        self.assertIs(m.inbound(self.config, 'second'), self.config['inbounds'][-1])

    def test_add_link_remove_preserves_other_users_and_settings(self):
        live = {'existing': self.item['settings']['clients'][0]['id']}
        def change(meta, config, action, client):
            if action == 'add':
                live[client['email'].lower()] = client['id']
            else:
                live.pop(client['email'].lower())
        with patch.object(m, 'key_pair', return_value=('private', 'p' * 43)), \
             patch.object(m, 'validate'), patch.object(m, 'run', side_effect=AssertionError('No restart allowed')), \
             patch.object(m, 'api_users', side_effect=lambda *a: dict(live)), \
             patch.object(m, 'api_change', side_effect=change):
            link = self.call(['add', 'iphone'])
            parsed = urlsplit(link)
            self.assertEqual(parsed.hostname, self.meta['host'])
            self.assertEqual(parse_qs(parsed.query)['flow'], [m.FLOW])
            self.assertEqual(parse_qs(parsed.query)['fp'], ['firefox'])
            self.assertEqual(parse_qs(parsed.query)['pbk'], ['p' * 43])
            self.assertEqual(self.call(['link', 'iphone']), link)
            changed = m.read_json(self.path)
            self.assertEqual(changed['inbounds'][0], self.config['inbounds'][0])
            self.assertEqual(m.inbound(changed)['settings']['clients'][0], self.item['settings']['clients'][0])
            self.assertEqual(self.call(['list']), 'existing\niphone')
            self.call(['remove', 'iphone', '--yes'])
            self.assertEqual(m.read_json(self.path), self.config)
            self.call(['remove', 'existing', '--yes'])
            self.assertEqual(m.inbound(m.read_json(self.path))['settings']['clients'], [])
            # Adding after deleting the last user must still set Vision.
            self.call(['add', 'new'])
            self.assertEqual(m.inbound(m.read_json(self.path))['settings']['clients'][0]['flow'], m.FLOW)

    def test_duplicate_and_missing_names_do_not_write(self):
        before = self.path.read_bytes()
        with patch.object(m, 'key_pair', return_value=('private', 'p' * 43)):
            for args in [['add', 'existing'], ['add', 'EXISTING'], ['remove', 'missing', '--yes'], ['link', 'missing']]:
                with self.assertRaises(m.Error):
                    self.call(args)
        self.assertEqual(self.path.read_bytes(), before)

    def test_api_failure_restores_file_without_restart(self):
        before = self.path.read_bytes()
        candidate = copy.deepcopy(self.config)
        client = {'email': 'new', 'id': 'test-id', 'flow': m.FLOW}
        m.inbound(candidate)['settings']['clients'].append(client)
        with patch.object(m, 'api_users', return_value={}), patch.object(m, 'validate'), \
             patch.object(m, 'api_change', side_effect=m.Error('API failed')), \
             patch.object(m, 'run', side_effect=AssertionError('No restart allowed')):
            with self.assertRaisesRegex(m.Error, 'без перезапуска'):
                m.apply_user(self.meta, candidate, 'add', client)
        self.assertEqual(self.path.read_bytes(), before)

    def test_timed_out_but_applied_rpc_is_success(self):
        candidate = copy.deepcopy(self.config)
        client = {'email': 'new', 'id': 'test-id', 'flow': m.FLOW}
        m.inbound(candidate)['settings']['clients'].append(client)
        with patch.object(m, 'api_users', side_effect=[{}, {'new': 'test-id'}, {'new': 'test-id'}]), \
             patch.object(m, 'validate'), patch.object(m, 'api_change', side_effect=m.Error('timeout')):
            m.apply_user(self.meta, candidate, 'add', client)
        self.assertEqual(m.read_json(self.path), candidate)

    def test_api_zero_success_is_not_accepted(self):
        with patch.object(m, 'run', return_value='Added 0 user(s) in total.'):
            with self.assertRaisesRegex(m.Error, 'не подтвердил'):
                m.api_change(self.meta, self.config, 'add', {'id': 'test', 'email': 'new'})

    def test_api_unavailable_does_not_modify_disk(self):
        before = self.path.read_bytes()
        with patch.object(m, 'api_users', side_effect=m.Error('unreachable')):
            with self.assertRaises(m.Error):
                m.apply_user(self.meta, self.config, 'add', {'id': 'test', 'email': 'new'})
        self.assertEqual(self.path.read_bytes(), before)

    def test_api_access_guard_is_mandatory(self):
        self.assertEqual(m.api_endpoint(self.config), '127.0.0.1:10085')
        self.config['routing']['rules'] = []
        with self.assertRaises(m.Error):
            m.api_endpoint(self.config)
        with self.assertRaises(m.Error):
            m.configure_api(self.config, None, 10085)

    def test_enable_api_is_idempotent_without_restart(self):
        with patch.object(m, 'api_users', return_value={}), patch.object(m, 'apply_config') as apply:
            self.call(['enable-api'])
        apply.assert_not_called()

    def test_invalid_candidate_never_replaces_config(self):
        before = self.path.read_bytes()
        with patch.object(m, 'validate', side_effect=m.Error('invalid')), patch.object(m, 'run') as run:
            with self.assertRaises(m.Error):
                m.apply_config(self.meta, {})
        self.assertEqual(self.path.read_bytes(), before)
        run.assert_not_called()
        self.assertFalse(list(self.root.glob('.validate-*')))

    def test_failed_restart_rolls_back_exact_bytes_and_mode(self):
        before = self.path.read_bytes()
        with patch.object(m, 'validate'), patch.object(m, 'healthy'), \
             patch.object(m, 'run', side_effect=[m.Error('restart'), '']):
            with self.assertRaisesRegex(m.Error, 'прежний конфиг восстановлен'):
                m.apply_config(self.meta, {})
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o640)
        backup = next((self.root / 'backups').glob('*.json'))
        self.assertEqual(backup.read_bytes(), before)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)

    def test_delayed_crash_rolls_back(self):
        with patch.object(m, 'validate'), patch.object(m, 'run'), \
             patch.object(m, 'healthy', side_effect=[m.Error('crash'), None]):
            with self.assertRaisesRegex(m.Error, 'восстановлен'):
                m.apply_config(self.meta, {})
        self.assertEqual(m.read_json(self.path), self.config)

    def test_failed_rollback_reports_service_failure(self):
        with patch.object(m, 'validate'), patch.object(m, 'run', side_effect=m.Error('restart')):
            with self.assertRaisesRegex(m.Error, 'служба не запустилась'):
                m.apply_config(self.meta, {})
        self.assertEqual(m.read_json(self.path), self.config)

    def test_ipv6_and_url_encoding(self):
        client = {'id': 'id', 'email': 'a b/#', 'flow': m.FLOW}
        self.item['streamSettings']['realitySettings']['shortIds'] = ['']
        link = m.client_link(self.item, client, '2001:db8::1', 'p' * 43)
        parsed = urlsplit(link)
        self.assertEqual(parsed.hostname, '2001:db8::1')
        self.assertEqual(parsed.fragment, 'a%20b%2F%23')
        self.assertIn('sid=', link)

    def test_key_output_variants_and_no_secret_error(self):
        for label in ('Public key', 'PublicKey', 'Password', 'Password (PublicKey)'):
            with patch.object(m, 'run', return_value=f'PrivateKey: secret\n{label}: ' + 'p' * 43):
                self.assertEqual(m.key_pair('xray'), ('secret', 'p' * 43))
        with patch.object(m, 'run', return_value='unexpected private secret value'):
            with self.assertRaises(m.Error) as exc:
                m.key_pair('xray')
            self.assertNotIn('secret value', str(exc.exception))

    def test_validation_of_untrusted_names(self):
        for invalid in ('a b', '../root', 'a;id', '', 'a' * 65):
            with self.assertRaises(argparse.ArgumentTypeError):
                m.name(invalid)
        for invalid in ('https://example.com', 'host:443', '-option', 'host\nname'):
            with self.assertRaises(argparse.ArgumentTypeError):
                m.hostname(invalid)

    def test_adopt_is_read_only_for_existing_server(self):
        self.meta_path.unlink()
        before = self.path.read_bytes()
        with patch.object(m, 'run', return_value=f'argv[]=/test/xray run -config {self.path} ;'), \
             patch.object(m, 'validate'), patch.object(m, 'healthy'), patch.object(m, 'key_pair'):
            self.call(['adopt', '--host', '203.0.113.10', '--config', str(self.path), '--binary', '/test/xray'])
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(m.read_json(self.meta_path)['host'], '203.0.113.10')

    def test_adopt_wrong_service_rejected(self):
        self.meta_path.unlink()
        with patch.object(m, 'run', return_value='xray run -config /wrong/config.json'):
            with self.assertRaises(m.Error):
                self.call(['adopt', '--host', '203.0.113.10', '--config', str(self.path)])
        self.assertFalse(self.meta_path.exists())

    def test_repeated_setup_does_not_rotate_keys(self):
        with patch.object(m, 'CONFIG', self.path), patch.object(m, 'validate'), patch.object(m, 'healthy'):
            before = self.path.read_bytes()
            self.call(['setup', '--host', '203.0.113.10', '--sni', 'www.example.com'])
            self.assertEqual(self.path.read_bytes(), before)
            with self.assertRaises(m.Error):
                self.call(['setup', '--host', '203.0.113.11'])

    def test_symlink_config_refused(self):
        link = self.root / 'link.json'
        link.symlink_to(self.path)
        meta = dict(self.meta, config=str(link))
        with self.assertRaises(m.Error):
            m.apply_config(meta, {})

    def test_set_host_only_updates_metadata(self):
        before = self.path.read_bytes()
        self.call(['set-host', 'vpn.example.com'])
        self.assertEqual(m.read_json(self.meta_path)['host'], 'vpn.example.com')
        self.assertEqual(self.path.read_bytes(), before)

    def test_download_checks_checksum_and_service_can_traverse_binary_directory(self):
        blob = io.BytesIO()
        with zipfile.ZipFile(blob, 'w') as z:
            z.writestr('xray', b'test-binary')
        archive = blob.getvalue()
        digest = hashlib.sha256(archive).hexdigest()

        def downloaded(args, **kwargs):
            if args[0] == 'curl':
                Path(args[-2]).write_bytes(('SHA2-256= ' + digest).encode()
                                          if args[-1].endswith('.dgst') else archive)
            return 'version'

        binary = self.root / 'bin-dir' / 'xray'
        previous = os.umask(0o077)
        try:
            with patch.object(m, 'BINARY', binary), patch.object(m, 'run', side_effect=downloaded), \
                 patch.object(m.platform, 'machine', return_value='x86_64'):
                m.download_xray('26.3.27')
            self.assertEqual(binary.parent.stat().st_mode & 0o777, 0o755)
            self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
            self.assertEqual(binary.read_bytes(), b'test-binary')
            binary.unlink()
            digest = '0' * 64
            with patch.object(m, 'BINARY', binary), patch.object(m, 'run', side_effect=downloaded), \
                 patch.object(m.platform, 'machine', return_value='x86_64'):
                with self.assertRaisesRegex(m.Error, 'SHA-256'):
                    m.download_xray('26.3.27')
            self.assertFalse(binary.exists())
        finally:
            os.umask(previous)


if __name__ == '__main__':
    unittest.main()
