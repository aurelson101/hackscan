import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_advisor import local_advice
from auth_checks import authenticated_matrix, parse_roles
from evidence_signing import generate_key
from hackscan import Scanner
from nuclei_adapter import run_nuclei
from planner import AdaptivePlanner
from reporting import write_report
from rule_engine import load_rules, paths_for
from threat_intel import enrich_cves


class ProfessionalTests(unittest.TestCase):
    def test_builtin_rules_are_verified_and_profiled(self):
        rules = load_rules()
        self.assertIn('wp-json/', paths_for(rules, 'wordpress'))
        self.assertIn('api/v1/summary', paths_for(rules, 'router-bouygues'))

    def test_external_rules_require_valid_ed25519_signature(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); rule = root / 'custom.yaml'; signature = root / 'custom.yaml.sig'; public = root / 'public.pem'
            rule.write_text('schema: 1\nrules:\n  - {id: custom-health, profile: wordpress, method: GET, path: health, risk: passif, purpose: Health public}\n')
            key = Ed25519PrivateKey.generate()
            public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            signature.write_text(base64.b64encode(key.sign(rule.read_bytes())).decode())
            self.assertIn('health', paths_for(load_rules(root, public), 'wordpress'))
            rule.write_text(rule.read_text() + '# altéré\n')
            with self.assertRaises(Exception):
                load_rules(root, public)

    def test_planner_circuit_breaker_is_explainable(self):
        report = {'requests': [{'status': 429}]}
        planner = AdaptivePlanner(report)
        self.assertIn('429', planner.stop_reason())
        planner.decide('nuclei_safe', False, planner.stop_reason())
        self.assertEqual(report['adaptive_plan'][0]['decision'], 'ignorer')

    def test_threat_intel_only_enriches_supplied_cves(self):
        report = {'findings': [{'title': 'source', 'cves': ['CVE-2025-12345']}]}
        def fake(_session, url, _timeout, _deadline):
            return ({'vulnerabilities': [{'cveID': 'CVE-2025-12345'}]} if 'cisa.gov' in url else
                    {'data': [{'cve': 'CVE-2025-12345', 'epss': '0.42', 'percentile': '0.91'}]})
        with patch('threat_intel._fetch', side_effect=fake):
            result = enrich_cves(report)
        self.assertEqual(result['status'], 'terminé')
        self.assertTrue(report['findings'][0]['threat_intel'][0]['kev'])

    def test_nuclei_never_downloads_or_falls_back_when_missing(self):
        with tempfile.TemporaryDirectory() as folder, patch('nuclei_adapter.shutil.which', return_value=None):
            self.assertEqual(run_nuclei('https://example.invalid', folder)['status'], 'indisponible')

    def test_authenticated_matrix_never_retains_secret(self):
        class Raw:
            def read(self, *_args, **_kwargs): return b'profile'
        class Response:
            status_code = 200; raw = Raw()
            def __enter__(self): return self
            def __exit__(self, *_args): return False
        scanner = Scanner('https://example.invalid', delay=0)
        with patch.dict(os.environ, {'ROLE_TOKEN': 'secret-value'}), patch('auth_checks.requests.Session.get', return_value=Response()):
            roles = parse_roles(['user=ROLE_TOKEN'], [])
            result = authenticated_matrix(scanner, roles, [scanner.url])
        self.assertNotIn('secret-value', json.dumps(result))
        self.assertFalse(result['comparisons'][0]['secret_retained'])

    def test_signed_report_and_machine_readable_exports(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); key_path = root / 'key.pem'; output = root / 'report'
            generate_key(key_path)
            scanner = Scanner('https://example.invalid')
            scanner.report['status'] = 'terminé (couverture limitée)'
            write_report(scanner.report, output, signing_key=key_path)
            self.assertTrue((output / 'manifest.sig').exists())
            self.assertTrue((output / 'findings.sarif.json').exists())
            self.assertTrue((output / 'components.cdx.json').exists())
            self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)

    def test_local_ai_uses_validated_redacted_json(self):
        class Response:
            def raise_for_status(self): pass
            def json(self): return {'response': json.dumps({'summary':'Synthèse','priorities':['Valider'],'questions':['Périmètre ?']})}
        report = {'status':'terminé','findings':[{'title':'HSTS','severity':'Faible','confidence':'observé','remediation':'Configurer'}], 'limitations':[]}
        with patch('ai_advisor.requests.Session.post', return_value=Response()) as post:
            result = local_advice(report, 'local-model')
        self.assertEqual(result['status'], 'proposition à valider')
        self.assertEqual(post.call_args.args[0], 'http://127.0.0.1:11434/api/generate')


if __name__ == '__main__':
    unittest.main()
