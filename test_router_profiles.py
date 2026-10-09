import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hackscan import Scanner
from reporting import write_report
from router_profiles import effective_profile, json_schema, private_target, run_router_checks


class RouterProfileTests(unittest.TestCase):
    def test_schema_never_retains_values(self):
        summary = json_schema(json.dumps({'ipaddress': '192.168.1.10', 'macaddress': 'aa:bb:cc:dd:ee:ff',
                                          'hostname': 'poste-secret', 'token': 'secret-token'}))
        serialized = json.dumps(summary)
        self.assertEqual(summary['format'], 'JSON objet')
        self.assertIn('ipaddress', summary['keys'])
        for value in ('192.168.1.10', 'aa:bb:cc:dd:ee:ff', 'poste-secret', 'secret-token'):
            self.assertNotIn(value, serialized)

    def test_profiles_are_deterministic_and_router_is_local(self):
        self.assertTrue(private_target('http://192.168.1.254/'))
        self.assertEqual(effective_profile('https://example.invalid', ['WordPress']), 'wordpress')
        self.assertEqual(effective_profile('https://example.invalid', ['Joomla']), 'joomla')
        self.assertEqual(effective_profile('https://mabbox.bytel.fr'), 'router-bouygues')
        self.assertEqual(effective_profile('http://192.168.1.254'), 'web-generic')
        self.assertEqual(effective_profile('http://192.168.1.254', requested='router-generic'), 'router-generic')

    def test_bbox_checks_are_get_only_and_reports_are_redacted(self):
        scanner = Scanner('http://192.168.1.254/', delay=0, timeout=1, max_pages=1, max_requests=16)
        secret_values = ('192.168.1.42', 'aa:bb:cc:dd:ee:ff', 'poste-secret')

        def response(url):
            protected = any(url.endswith(path) for path in ('/wireless', '/hosts', '/firewall', '/device/token'))
            body = json.dumps([{'ipaddress': secret_values[0], 'macaddress': secret_values[1], 'hostname': secret_values[2]}])
            return {'url': url, 'status': 401 if protected else 200,
                    'headers': {'content-type': 'application/json'}, 'body': body}

        with patch.object(scanner, 'get', side_effect=response):
            inventory = run_router_checks(scanner, 'router-bouygues')
        self.assertEqual(len(inventory), 8)
        self.assertEqual(len(scanner.report['findings']), 1)
        serialized = json.dumps(scanner.report, ensure_ascii=False)
        for value in secret_values:
            self.assertNotIn(value, serialized)
        with tempfile.TemporaryDirectory() as folder:
            write_report(scanner.report, Path(folder))
            html = (Path(folder) / 'report.html').read_text(encoding='utf-8')
            self.assertIn('Rapport de pentest routeur', html)
            self.assertIn('API routeur accessibles sans authentification', html)
            for value in secret_values:
                self.assertNotIn(value, html)


if __name__ == '__main__':
    unittest.main()
