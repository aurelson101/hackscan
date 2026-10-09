import hashlib
import json
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from argparse import Namespace
from unittest.mock import patch

import requests
from checks import proxy_preflight, header_values, cookie_observations, tls_inventory, VendorReferences, compare_version
from hackscan import Scanner, main, cve_references
from reporting import write_report
from workflow import PROFILES, preferences, save_preferences, compare_reports, fingerprint
from exports import csv_safe
from test_hackscan import Handler
from http.server import ThreadingHTTPServer


class FeaturesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = 'http://127.0.0.1:'+str(cls.server.server_port)+'/'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def report(self):
        s = Scanner(self.url, delay=0, max_pages=1)
        s.report['status'] = 'terminé (couverture limitée)'
        s.finding('Faible', 'HSTS absent', 'preuve', 'Configurer HSTS')
        return s.report

    def test_profiles_and_secret_free_preferences(self):
        self.assertLess(PROFILES['rapide']['budget'], PROFILES['approfondi']['budget'])
        args = Namespace(profile='rapide', tor=False, **PROFILES['rapide'], token='NEVER_SAVE', url='https://secret.invalid')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'settings.json'
            save_preferences(path, args)
            self.assertEqual(preferences(path)['profile'], 'rapide')
            self.assertNotIn('NEVER_SAVE', path.read_text())
            self.assertNotIn('secret.invalid', path.read_text())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_socks_negotiation_and_failure(self):
        class Conn:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def sendall(self, data): self.sent = data
            def recv(self, size): return self.responses.pop(0)
        conn = Conn()
        conn.responses = [b'\x05', b'\x00']
        with patch('checks.socket.create_connection', return_value=conn):
            self.assertEqual(proxy_preflight('socks5h://127.0.0.1:9050')['status'], 'disponible')
        conn.responses = [b'\x05\x02']
        with patch('checks.socket.create_connection', return_value=conn), self.assertRaises(ValueError):
            proxy_preflight('socks5h://127.0.0.1:9050')

    def test_header_values(self):
        self.assertFalse(header_values({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Strict-Transport-Security':'max-age=100'}))
        bad = header_values({'X-Content-Type-Options':'yes','X-Frame-Options':'ALLOWALL','Strict-Transport-Security':'max-age=0','Content-Security-Policy':"script-src 'unsafe-eval'"})
        self.assertEqual(len(bad), 4)

    def test_cookie_flags_without_value(self):
        cookie = requests.cookies.create_cookie('session', 'NEVER_SAVE', secure=True, rest={'HttpOnly':None,'SameSite':'Strict'})
        data = cookie_observations([cookie], self.url)
        self.assertTrue(data[0]['secure'])
        self.assertTrue(data[0]['http_only'])
        self.assertEqual(data[0]['same_site'], 'Strict')
        self.assertNotIn('NEVER_SAVE', json.dumps(data))

    def test_tls_real_handshakes_with_trusted_local_certificate(self):
        with tempfile.TemporaryDirectory() as folder:
            cert, key = Path(folder)/'cert.pem', Path(folder)/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            key.chmod(0o600)
            class TLSHandler(Handler):
                def handle(self):
                    try:
                        super().handle()
                    except (ConnectionResetError, BrokenPipeError):
                        pass  # Le contrôle ferme après la négociation, sans requête HTTP.
            server = ThreadingHTTPServer(('127.0.0.1',0), TLSHandler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert,key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever,daemon=True)
            thread.start()
            original = ssl.create_default_context
            try:
                with patch('checks.ssl.create_default_context', side_effect=lambda: original(cafile=str(cert))):
                    report = tls_inventory('https://localhost:'+str(server.server_port),timeout=2)
                self.assertEqual(report['status'],'terminé')
                self.assertEqual([h['status'] for h in report['handshakes']], ['accepté','accepté'])
                self.assertTrue(all(h['certificate_verified'] for h in report['handshakes']))
                self.assertTrue(all(len(h['certificate_sha256']) == 64 for h in report['handshakes']))
            finally:
                server.shutdown(); server.server_close(); thread.join()

    def test_tls_proxy_does_not_open_direct_connection(self):
        with patch('checks.socks.socksocket', side_effect=OSError('SOCKS unavailable')), patch('checks.socket.create_connection') as direct:
            result = tls_inventory('https://example.com', 'socks5h://127.0.0.1:9050', timeout=1)
        self.assertEqual(result['status'],'incomplet')
        direct.assert_not_called()

    def test_vendor_whitelist_and_unavailable_data_remain_unknown(self):
        session = requests.Session()
        vendor = VendorReferences(session)
        with patch.object(session,'get') as get, self.assertRaises(ValueError):
            vendor.fetch('https://attacker.invalid/secret')
        get.assert_not_called()
        report = self.report()
        report['cms'] = [{'name':'WordPress'}]
        response = requests.Response(); response.status_code=503; response._content=b''; response._content_consumed=True
        with patch.object(session,'get',return_value=response):
            result = vendor.collect(report)
        self.assertEqual(result['status'],'partiel')
        self.assertEqual(result['components'][0]['status'],'inconnu')
        self.assertIn('inconnu', result['components'][0]['cve_status'])

    def test_version_comparison(self):
        self.assertIn('disponible', compare_version('1.2.0','1.3'))
        self.assertIn('égale', compare_version('1.2','1.2.0'))
        self.assertEqual(compare_version('1789004300','1.2'),'non comparable')

    def test_selected_sql_parameter_only(self):
        s = Scanner(self.url,delay=0)
        s.sql_checks([], [self.url+'?s=hello&id=2'], ['id'])
        probes = s.report['tools']['sql_probes']['tested']
        self.assertEqual(len(probes),2)
        self.assertTrue(all(p['parameter']=='id' for p in probes))
        self.assertTrue(all('s=hello' in q['url'] for q in s.report['requests']))

    def test_resume_skips_completed_network_stages(self):
        root = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as folder:
            output, config = Path(folder)/'audit', Path(folder)/'prefs.json'
            base = [str(root/'.venv/bin/python'), str(root/'hackscan.py'), '--authorized', '--profile','rapide','--max-pages','1','--delay','.2','--config',str(config)]
            first = subprocess.run(base+[self.url+'joomla','--output',str(output)],capture_output=True,text=True,timeout=15)
            self.assertEqual(first.returncode,0,first.stderr)
            before = json.loads((output/'report.json').read_text())
            second = subprocess.run(base+['--resume',str(output/'checkpoint.json')],capture_output=True,text=True,timeout=15)
            self.assertEqual(second.returncode,0,second.stderr)
            after = json.loads((output/'report.json').read_text())
            self.assertEqual(len(before['requests']),len(after['requests']))
            self.assertIn('Étape déjà terminée',second.stdout)
            self.assertEqual(len(after['resume_history']),1)

    def test_comparison_does_not_claim_correction_from_partial_audit(self):
        previous=self.report(); current=self.report()
        current['findings']=[]; current['status']='incomplet'
        data=compare_reports(current,previous)
        self.assertEqual(len(data['not_observed']),1)
        self.assertIn('aucune correction',data['conclusion'])
        previous['target']='https://other.invalid'
        with self.assertRaises(ValueError): compare_reports(current,previous)

    def test_editable_plan_exports_pdf_and_manifest(self):
        report=self.report()
        key=fingerprint(report['findings'][0])
        report['treatment_updates']={'schema':1,'entries':[{'key':key,'owner':'Responsable test','proposed_due_date':'2026-11-03','treatment_status':'En cours','decision':'corriger','validator':'RSSI','closure_evidence':'À recontrôler'}]}
        with tempfile.TemporaryDirectory() as folder:
            output=Path(folder); write_report(report,output)
            data=json.loads((output/'report.json').read_text())
            self.assertEqual(data['risk_register'][0]['owner'],'Responsable test')
            self.assertTrue((output/'report.pdf').read_bytes().startswith(b'%PDF'))
            self.assertTrue((output/'executive.html').exists())
            self.assertIn('Responsable test',(output/'risk-register.csv').read_text())
            for line in (output/'manifest.sha256').read_text().splitlines():
                digest,name=line.split('  ',1)
                self.assertEqual(digest,hashlib.sha256((output/name).read_bytes()).hexdigest())

    def test_unvalidated_risk_acceptance_is_rejected(self):
        report=self.report()
        report['treatment_updates']={'schema':1,'entries':[{'key':fingerprint(report['findings'][0]),'decision':'accepter','owner':'SHOULD_NOT_APPLY'}]}
        with tempfile.TemporaryDirectory() as folder:
            write_report(report,Path(folder))
            self.assertNotEqual(report['risk_register'][0]['owner'],'SHOULD_NOT_APPLY')
            self.assertTrue(any('Plan non appliqué' in x for x in report['limitations']))

    def test_csv_and_embedded_json_escape_untrusted_values(self):
        self.assertEqual(csv_safe('=HYPERLINK("x")'),"'=HYPERLINK(\"x\")")
        report=self.report(); report['findings'][0]['title']='</script><img src=x onerror=alert(1)>'
        with tempfile.TemporaryDirectory() as folder:
            write_report(report,Path(folder))
            body=(Path(folder)/'report.html').read_text()
            embedded=re.search(r'<script type="application/json" id="risk-data">(.*?)</script>',body,re.S).group(1)
            self.assertNotIn('<',embedded)
            self.assertEqual(json.loads(embedded)[0]['title'],report['findings'][0]['title'])

    def test_cve_identifiers_are_not_invented(self):
        self.assertEqual(cve_references({'references':{'cve':'2026-12345'}}),['CVE-2026-12345'])
        self.assertEqual(cve_references({'references':{'cve':['invalid','CVE-2026-12345']}}),['CVE-2026-12345'])
        self.assertEqual(cve_references({}),[])

    def test_duplicate_probes_share_one_treatment_key(self):
        report=self.report()
        f=dict(report['findings'][0]); f['url']=self.url+'?s=test%27'
        report['findings'].append(f)
        with tempfile.TemporaryDirectory() as folder:
            write_report(report,Path(folder))
        self.assertEqual(len(report['risk_register']),1)
        self.assertEqual(len(report['risk_register'][0]['source_urls']),2)

    def test_resume_custom_proxy_cannot_fall_back_to_direct(self):
        report=self.report(); report['proxy']='SOCKS5 avec DNS distant'
        report['run_settings']={'profile':'rapide','tor':False,'proxy':'socks5h://127.0.0.1:9999','tls':False,'updates':False}
        with tempfile.TemporaryDirectory() as folder:
            checkpoint=Path(folder)/'checkpoint.json'
            checkpoint.write_text(json.dumps({'schema':1,'report':report,'completed':['crawl','cms']}))
            argv=['hackscan.py','--resume',str(checkpoint),'--authorized','--config',str(Path(folder)/'prefs.json')]
            with patch('sys.argv',argv),patch('hackscan.proxy_preflight',return_value={'status':'disponible'}) as preflight,patch('hackscan.requests.Session.get') as get:
                self.assertEqual(main(),0)
            preflight.assert_called_once_with('socks5h://127.0.0.1:9999')
            get.assert_not_called()

    def test_human_confirmation_requires_evidence(self):
        report=self.report()
        report['treatment_updates']={'schema':1,'entries':[{'key':fingerprint(report['findings'][0]),'qualification':'vulnérabilité confirmée'}]}
        with tempfile.TemporaryDirectory() as folder:
            write_report(report,Path(folder))
        self.assertNotEqual(report['risk_register'][0]['qualification'],'vulnérabilité confirmée')


if __name__ == '__main__':
    unittest.main()
