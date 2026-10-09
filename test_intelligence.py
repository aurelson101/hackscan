"""Tests de décisions, de preuves et de confidentialité des ajouts v4."""
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest

from intelligence import CATALOGUE, assess, page_snapshot, public_url
from reporting import enrich, write_report


def base_report():
    return {'target':'https://example.invalid/','started_utc':'2026-01-01T00:00:00+00:00',
            'status':'terminé (couverture limitée)','findings':[],'requests':[], 'tools':{},
            'checks':[],'pages':[],'cms':[],'inventory':{},'limitations':[]}


def with_page(body='',headers=None):
    r=base_report()
    r['requests']=[{'url':r['target'],'status':200,'content_type':'text/html',
                    'headers':headers or {},'header_capture_schema':2,'sha256':'a'*64,'duration_ms':100}]
    r['page_observations']=[page_snapshot({'url':r['target'],'body':body})]
    return r


class IntelligenceTests(unittest.TestCase):
    def states(self,r):
        return {c['id']:c for c in assess(r)}

    def test_exactly_100_traceable_improvements_and_60_controls(self):
        self.assertEqual([c['id'] for c in CATALOGUE],[f'A{i:03}' for i in range(1,101)])
        controls=assess(base_report())
        self.assertEqual(len(controls),60)
        self.assertEqual(len({c['id'] for c in controls}),60)
        self.assertTrue(all(c['source'].startswith('https://') for c in controls))

    def test_missing_measurements_are_unknown_not_favorable(self):
        controls=self.states(base_report())
        self.assertTrue(all(c['state']=='inconnu' for c in controls.values()))
        r=with_page()
        self.assertEqual(self.states(r)['C001']['state'],'à revoir')
        self.assertEqual(self.states(r)['C031']['state'],'observé')
        self.assertEqual(self.states(r)['C021']['state'],'inconnu')

    def test_effective_csp_nonce_fallback_duplicate_and_report_only(self):
        headers={'content-security-policy':"default-src 'self'; script-src 'nonce-YWJjZA==' 'unsafe-inline'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"}
        c=self.states(with_page(headers=headers))
        self.assertEqual(c['C004']['state'],'observé')
        self.assertEqual(c['C008']['state'],'observé')
        headers['content-security-policy']="script-src 'unsafe-inline'; script-src 'none'"
        c=self.states(with_page(headers=headers))
        self.assertEqual(c['C004']['state'],'à revoir')
        self.assertEqual(c['C014']['state'],'à revoir')
        self.assertEqual(self.states(with_page(headers={'content-security-policy-report-only':"default-src 'none'"}))['C013']['state'],'à revoir')
        self.assertEqual(self.states(with_page(headers={'content-security-policy':"script-src 'nonce-' 'unsafe-inline'"}))['C004']['state'],'à revoir')

    def test_multi_policy_csp_remains_unknown_for_effective_script_checks(self):
        c=self.states(with_page(headers={'content-security-policy':"script-src *, script-src 'none'"}))
        self.assertEqual(c['C005']['state'],'inconnu')

    def test_referrer_uses_last_recognized_policy(self):
        self.assertEqual(self.states(with_page(headers={'referrer-policy':'unsafe-url, strict-origin,invalid'}))['C019']['state'],'observé')
        self.assertEqual(self.states(with_page(headers={'referrer-policy':'strict-origin,unsafe-url'}))['C019']['state'],'à revoir')

    def test_cookie_prefix_flags_and_values_never_collected(self):
        r=with_page()
        r['cookies']=[{'name':'__Host-session','url':r['target'],'path':'/', 'domain':'.example.invalid',
                       'domain_specified':True,'secure':False,'http_only':False,'same_site':'None','expires':None}]
        c=self.states(r)
        for n in (21,22,24,25,27): self.assertEqual(c[f'C{n:03}']['state'],'à revoir')
        r['cookies'][0].update(secure=True,domain_specified=False,http_only=True,same_site='Lax')
        self.assertEqual(self.states(r)['C025']['state'],'observé')

    def test_passive_snapshot_minimizes_secrets_and_detects_context(self):
        body='''<form action="http://other.invalid/path?token=NEVER_SAVE" method="get"><input type="password" value="NEVER_SAVE" autocomplete="off"></form><script src="https://cdn.invalid/app.js?key=NEVER_SAVE"></script><img src="http://example.invalid/pic"><iframe src="/frame" allow="camera *"></iframe><button onclick="NEVER_SAVE()">X</button><script>const credential="NEVER_SAVE";const socket="ws://example.invalid";</script><base href="https://other.invalid/">'''
        r=with_page(body)
        snapshot=r['page_observations'][0]
        self.assertNotIn('NEVER_SAVE',json.dumps(snapshot))
        c=self.states(r)
        for n in (32,33,34,35,36,37,40,41,42,43,44,45):
            self.assertEqual(c[f'C{n:03}']['state'],'à revoir',str(n))
        self.assertEqual(c['C031']['state'],'observé')

    def test_sri_and_relative_resources_avoid_false_positive(self):
        r=with_page('<script src="https://cdn.invalid/app.js" integrity="sha384-YWJjZA=="></script><script src="/local.js"></script>')
        self.assertEqual(self.states(r)['C037']['state'],'observé')

    def test_no_html_execution_or_network_during_snapshot(self):
        snapshot=page_snapshot({'url':'https://example.invalid/','body':'<script>fetch("https://outside.invalid")</script><img src="javascript:alert(1)">'})
        self.assertEqual(snapshot['resources'][0]['url'],'')
        self.assertEqual(public_url('https://name:secret@example.invalid/p?token=secret#x'),'https://example.invalid/p')

    def test_tls_expiry_and_no_guess_from_failed_handshake(self):
        r=with_page();r['tools']['tls']={'handshakes':[{'status':'non négocié','requested':'TLSv1_3'}]}
        self.assertEqual(self.states(r)['C050']['state'],'inconnu')
        r['tools']['tls']={'handshakes':[{'status':'accepté','protocol':'TLSv1.3','certificate_verified':True,'expires_in_days':6,'subject_alt_names':['*.example.invalid']}]}
        c=self.states(r)
        for n in (46,47,48):self.assertEqual(c[f'C{n:03}']['state'],'à revoir')
        self.assertEqual(c['C049']['state'],'observé')

    def test_cors_impossible_combination_never_claims_exploit(self):
        c=self.states(with_page(headers={'access-control-allow-origin':'*','access-control-allow-credentials':'true'}))['C051']
        self.assertEqual(c['state'],'à revoir')
        self.assertIn('rejetée',c['action'])
        self.assertEqual(c['exploitation'],'non démontrée')

    def test_inconsistent_headers_require_multiple_comparable_pages(self):
        r=with_page(headers={'x-frame-options':'DENY'})
        self.assertEqual(self.states(r)['C059']['state'],'inconnu')
        r['requests'].append({'url':r['target']+'about','status':200,'content_type':'text/html','headers':{}})
        self.assertEqual(self.states(r)['C059']['state'],'à revoir')

    def test_decision_engine_groups_causes_and_links_actual_evidence(self):
        r=with_page()
        r['findings']=[{'title':'En-tête absent : CSP','severity':'Faible','evidence':'Absent','remediation':'Configurer','url':r['target']},
                       {'title':'En-tête absent : nosniff','severity':'Faible','evidence':'Absent','remediation':'Configurer','url':r['target']}]
        enrich(r)
        a=r['intelligence']
        self.assertEqual(len([g for g in a['roadmap'] if g['finding_ids']]),1)
        self.assertEqual(len([g for g in a['roadmap'] if g['theme']=='Navigateur']),1)
        self.assertEqual(r['risk_register'][0]['evidence_ids'],['E001'])
        self.assertIn('Faible',r['risk_register'][0]['triage_reasons'][0])
        self.assertEqual(len(a['internal_evidence']),5)
        self.assertEqual(a['schema'],'hackscan.intelligence/1')

    def test_dates_latency_and_historical_rows(self):
        r=with_page()
        r['requests'][0]['duration_ms']=10
        r['requests'].append({'url':r['target'],'duration_ms':30,'status':200})
        r['requests'].append({'url':r['target'],'duration_ms':900,'historical':True})
        enrich(r)
        self.assertEqual(r['intelligence']['network']['median_ms'],20)
        self.assertEqual(r['intelligence']['network']['p95_ms'],30)
        self.assertGreater(r['intelligence']['evidence_age_days'],30)
        self.assertTrue(any('30 jours' in x for x in r['intelligence']['gaps']))

    def test_closed_declaration_without_proof_is_visible(self):
        r=with_page();r['findings']=[{'title':'HSTS absent','severity':'Faible','url':r['target'],'remediation':'Configurer'}]
        enrich(r)
        r['treatment_updates']={'schema':1,'entries':[{'key':r['risk_register'][0]['key'],'treatment_status':'Clos'}]}
        enrich(r)
        self.assertTrue(r['intelligence']['contradictions'])
        self.assertTrue(r['intelligence']['deadline_alerts']==[])

    def test_exports_are_private_complete_and_safe(self):
        r=with_page('<script src="http://cdn.invalid/app.js"></script>')
        r['metadata']={'organization':'<script>alert(1)</script>'}
        with tempfile.TemporaryDirectory() as folder:
            write_report(r,folder)
            output=Path(folder)
            rows=list(csv.DictReader(io.StringIO((output/'controls.csv').read_text(encoding='utf-8-sig'))))
            self.assertEqual(len(rows),60)
            self.assertEqual(len(json.loads((output/'improvements.json').read_text())),100)
            self.assertEqual(len(json.loads((output/'intelligence.json').read_text())['controls']),60)
            text=(output/'report.html').read_text()
            self.assertIn('control-search',text)
            self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;',text)
            for name in ('controls.csv','intelligence.json','improvements.html','report.pdf'):
                self.assertEqual((output/name).stat().st_mode&0o777,0o600)
            self.assertTrue((output/'report.pdf').read_bytes().startswith(b'%PDF'))


if __name__=='__main__': unittest.main()
