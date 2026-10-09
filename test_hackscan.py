import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import subprocess
import threading
import unittest
from urllib.parse import urlsplit, parse_qs
from unittest.mock import patch

from hackscan import Scanner, write_report, detect_cms, canonical_redirect, main, normalize_profile_choice


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ('/joomla', '/drupal', '/unknown'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            body = {'/joomla': '<meta content="Joomla! - CMS" name="generator">',
                    '/drupal': '<script>var drupalSettings = {};</script>',
                    '/unknown': '<p>Bienvenue sur mon site</p>'}[self.path]
            self.wfile.write(body.encode())
            return
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', 'https://outside.invalid/')
            self.end_headers()
            return
        if self.path == '/rate-limit':
            self.send_response(429)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('content-type', 'text/html; charset=utf-8')
        self.end_headers()
        query = parse_qs(urlsplit(self.path).query).get('s', [''])[0]
        if "'" in query:
            body = 'You have an error in your SQL syntax near MySQL'
        elif self.path.endswith('readme.txt'):
            body = '=== Demo ===\nStable tag: 1.2.3\n'
        else:
            body = '<meta name="generator" content="WordPress 6.8"><script src="/wp-content/plugins/demo/app.js?ver=1.2.3"></script><a href="/?s=hello">Search</a>'
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


class ScannerTests(unittest.TestCase):
    def test_interactive_profile_typo_is_normalized(self):
        self.assertEqual(normalize_profile_choice('appronfondi'), 'approfondi')
        self.assertEqual(normalize_profile_choice('standart'), 'standard')
        self.assertEqual(normalize_profile_choice('', 'rapide'), 'rapide')

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = 'http://127.0.0.1:' + str(cls.server.server_port) + '/'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def scanner(self, **kwargs):
        return Scanner(self.url, delay=0, timeout=1, max_pages=1, **kwargs)

    def test_inventory_sql_and_readme(self):
        s = self.scanner()
        pages = s.crawl()
        s.wordpress_checks()
        s.sql_checks(pages)
        plugin = s.report['inventory']['plugins']['demo']
        self.assertEqual(plugin['versions'], ['1.2.3'])
        self.assertEqual(plugin['readme_stable_tag'], '1.2.3')
        self.assertEqual(s.report['inventory']['wordpress'], ['6.8'])
        self.assertEqual(s.report['cms'][0]['name'], 'WordPress')
        self.assertTrue(any('Indice d’erreur SQL' in f['title'] for f in s.report['findings']))
        self.assertEqual(s.report['tools']['sql_probes']['probes'], 4)

    def test_redirect_does_not_contact_other_origin(self):
        s = self.scanner()
        with self.assertRaisesRegex(ValueError, 'hors périmètre'):
            s.get(self.url + 'redirect')
        self.assertEqual(len(s.report['requests']), 1)

    def test_429_stops(self):
        s = self.scanner()
        with self.assertRaisesRegex(RuntimeError, '429'):
            s.get(self.url + 'rate-limit')
        self.assertNotIn(self.url + 'rate-limit', s.cache)

    def test_timestamp_is_not_plugin_version(self):
        s = self.scanner()
        s.inventory({'url': self.url, 'body': '<script src="/wp-content/plugins/demo/app.js?ver=1789004285"></script>'})
        self.assertEqual(s.report['inventory']['plugins']['demo']['versions'], [])
        self.assertEqual(s.report['inventory']['plugins']['demo']['asset_tokens'], ['1789004285'])

    def test_blocked_endpoint_does_not_hide_other_checks(self):
        import requests
        s = self.scanner()
        original = s.get
        def get(url):
            if url.endswith('wp-json/'):
                raise requests.ConnectionError('connection reset')
            return original(url)
        with patch.object(s, 'get', side_effect=get):
            s.wordpress_checks()
        self.assertTrue(any('Endpoint non vérifié' in x for x in s.report['limitations']))
        self.assertTrue(any(x['url'].endswith('xmlrpc.php') for x in s.report['requests']))

    def test_request_budget_and_cache(self):
        s = self.scanner(max_requests=1)
        s.get(self.url)
        s.get(self.url)
        self.assertEqual(len(s.report['requests']), 1)
        with self.assertRaisesRegex(RuntimeError, 'Budget'):
            s.get(self.url + 'another')

    def test_proxy_failure_never_falls_back(self):
        s = self.scanner(proxy='socks5h://127.0.0.1:1')
        import requests
        with self.assertRaises(requests.RequestException):
            s.get(self.url)
        self.assertIsNone(s.report['requests'][0]['status'])
        self.assertIn('aucun repli direct', s.report['requests'][0]['error'])
        self.assertFalse(s.session.trust_env)

    def test_report_escapes_untrusted_html(self):
        s = self.scanner()
        s.finding('Info', '<script>alert(1)</script>', '<img src=x onerror=alert(1)>', 'Correction')
        with tempfile.TemporaryDirectory() as folder:
            write_report(s.report, Path(folder))
            body = (Path(folder) / 'report.html').read_text()
            self.assertNotIn('<script>alert(1)</script>', body)
            self.assertIn('&lt;script&gt;', body)
            self.assertEqual((Path(folder) / 'report.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads((Path(folder) / 'report.json').read_text())['target'], self.url)

    def test_sqlmap_timeout_cannot_claim_completion(self):
        import subprocess
        with tempfile.TemporaryDirectory() as folder, patch('hackscan.shutil.which', return_value='/usr/bin/sqlmap'), patch('hackscan.subprocess.run', side_effect=subprocess.TimeoutExpired(['sqlmap'], 1, output=b'partial test')):
            s = self.scanner()
            s.sqlmap(self.url + '?s=test', Path(folder), 1)
            self.assertIn('incomplet', s.report['tools']['sqlmap']['status'])
            self.assertFalse(any(f['severity'] == 'Haute' for f in s.report['findings']))

    def test_cms_signatures_ignore_mentions_and_external_assets(self):
        samples = [
            ('<a href="mailto:a@example.com">Mail</a><meta content="Joomla!" name="generator">', 'Joomla'),
            ('<script src="/sites/default/files/js/demo.js"></script>', 'Drupal'),
            ('<script>Shopify.shop = "demo";</script>', 'Shopify'),
            ('<meta name="generator" content="PrestaShop">', 'PrestaShop'),
            ('<script type="text/x-magento-init">{}</script>', 'Magento'),
            ('<meta name="generator" content="TYPO3 CMS">', 'TYPO3'),
            ('<meta name="generator" content="Ghost 5">', 'Ghost'),
            ('<p>WordPress Joomla Drupal</p><a href="https://external.invalid/wp-content/a.css">Lien</a>', None),
        ]
        for body, expected in samples:
            with self.subTest(cms=expected):
                found = detect_cms({'url': self.url, 'body': body})
                self.assertEqual([c['name'] for c in found], [expected] if expected else [])

    def test_interactive_launcher_adapts_to_cms(self):
        root = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as folder:
            for slug, expected in [('joomla', 'Joomla'), ('drupal', 'Drupal'), ('unknown', 'non déterminé')]:
                with self.subTest(cms=expected):
                    output = Path(folder) / slug
                    proc = subprocess.run([str(root / 'lancer.sh'), '--profile', 'rapide', '--config', str(Path(folder)/'preferences.json'), '--reports-root', str(Path(folder)/'reports'), '--max-pages', '1', '--delay', '.2', '--output', str(output)],
                                          input=self.url + slug + '\no\n\nn\n', capture_output=True, text=True, timeout=10)
                    self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
                    self.assertIn(expected, proc.stdout)
                    report = json.loads((output / 'report.json').read_text())
                    self.assertEqual(len(report['requests']), {'joomla': 5, 'drupal': 5, 'unknown': 1}[slug])
                    self.assertIn('non applicable', report['tools']['wordpress_checks']['status'])
                    self.assertTrue((output / 'report.html').exists())

    def test_interactive_launcher_selects_bbox_pipeline_and_report(self):
        root = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'bbox'
            proc = subprocess.run(
                [str(root / 'lancer.sh'), '--profile', 'rapide', '--config', str(Path(folder) / 'preferences.json'), '--reports-root', str(Path(folder)/'reports'),
                 '--max-pages', '1', '--delay', '.2', '--output', str(output)],
                input=self.url + 'unknown\no\nbbox\n', capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            report = json.loads((output / 'report.json').read_text())
            self.assertEqual(report['asset_profile']['effective'], 'router-bouygues')
            self.assertEqual(report['asset_profile']['kind'], 'routeur')
            self.assertIn('non applicable', report['tools']['sql_probes']['status'])
            self.assertTrue((output / 'report.html').exists())
            self.assertTrue((output / 'report.pdf').exists())

    def test_canonical_redirect_policy(self):
        self.assertTrue(canonical_redirect('https://defta.eu/', 'https://www.defta.eu/'))
        self.assertTrue(canonical_redirect('http://defta.eu/', 'https://defta.eu/'))
        for target in ('https://attacker.invalid/', 'https://admin.defta.eu/', 'http://www.defta.eu/', 'https://www.defta.eu:8443/'):
            with self.subTest(target=target):
                self.assertFalse(canonical_redirect('https://defta.eu/', target))

    def test_initial_www_redirect_adopts_scope_and_preserves_evidence(self):
        import requests
        s = Scanner('https://defta.eu', delay=0)
        redirect = requests.Response()
        redirect.status_code = 301
        redirect.headers['Location'] = 'https://www.defta.eu/'
        redirect._content = b''
        redirect._content_consumed = True
        page = requests.Response()
        page.status_code = 200
        page.headers['Content-Type'] = 'text/html'
        page._content = b'<p>Canonical</p>'
        page._content_consumed = True
        with patch.object(s.session, 'get', side_effect=[redirect, page]):
            result = s.get(s.url, allow_canonical=True)
        self.assertEqual(result['url'], 'https://www.defta.eu/')
        self.assertTrue(s.in_scope('https://www.defta.eu/about/'))
        self.assertFalse(s.in_scope('https://admin.defta.eu/'))
        self.assertEqual(s.report['requested_target'], 'https://defta.eu/')
        self.assertEqual(len(s.report['redirects']), 1)
        self.assertEqual(len(s.report['requests'][-1]['sha256']), 64)

    def test_interactive_tor_selection_is_used(self):
        import requests
        with tempfile.TemporaryDirectory() as folder, patch('sys.argv', ['hackscan.py', '--interactive', '--profile', 'rapide', '--config', str(Path(folder)/'preferences.json'), '--output', folder]), patch('builtins.input', side_effect=['https://defta.eu', 'o', '', 'o']), patch('hackscan.ensure_tor', side_effect=OSError('proxy refused')) as ensure, patch('hackscan.requests.Session.get') as get:
            self.assertEqual(main(), 1)
            report = json.loads((Path(folder) / 'report.json').read_text())
            self.assertIn('SOCKS', report['proxy'])
            self.assertEqual(get.call_count, 0)
            self.assertTrue(report['analysis_obstacles'])
            ensure.assert_called_once_with(9050, 90)

    def test_report_ciso_preserves_unknowns_and_finding_traceability(self):
        s = self.scanner()
        s.finding('Faible', 'HSTS absent', 'Absent', 'Configurer HSTS')
        s.report['tools']['wpscan'] = {'status': 'échec', 'detail': 'HTTP 403'}
        s.report['status'] = 'incomplet'
        with tempfile.TemporaryDirectory() as folder:
            write_report(s.report, Path(folder))
            r = json.loads((Path(folder) / 'report.json').read_text())
            body = (Path(folder) / 'report.html').read_text()
            self.assertEqual(r['risk_register'][0]['id'], 'F-001')
            self.assertIn('proposed_due_date', r['risk_register'][0])
            self.assertTrue(any(row[1] == 'Non testé' for row in r['coverage']))
            self.assertIn('403', r['analysis_obstacles'][0]['technical'])
            self.assertIn('Tests SQL non réalisés', body)
            self.assertIn('Audit partiel', body)
            self.assertIn('Synthèse décisionnelle', body)
            self.assertIn('Plan de traitement', body)


if __name__ == '__main__':
    unittest.main()
