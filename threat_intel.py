"""Enrichissement CVE borné par CISA KEV et FIRST EPSS, sans inférence de CVE."""
import json
import time
from urllib.parse import urlencode, urlsplit

import requests


SOURCES = {
    'www.cisa.gov': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'api.first.org': 'https://api.first.org/data/v1/epss',
}


def _fetch(session, url, timeout, deadline):
    if urlsplit(url).hostname not in SOURCES or time.monotonic() >= deadline:
        raise ValueError('Source de renseignement refusée ou budget atteint')
    with session.get(url, timeout=min(timeout, max(.1, deadline-time.monotonic())), allow_redirects=False, stream=True) as response:
        if response.status_code != 200:
            raise RuntimeError('HTTP ' + str(response.status_code))
        body = response.raw.read(2 * 1024 * 1024 + 1, decode_content=True)
        if len(body) > 2 * 1024 * 1024:
            raise RuntimeError('Réponse trop volumineuse')
        return json.loads(body)


def enrich_cves(report, proxy=None, timeout=10, budget=30):
    cves = sorted({cve for finding in report.get('findings', []) for cve in finding.get('cves', [])})
    if not cves:
        return {'status': 'non applicable : aucune CVE fournie par une source', 'cves': []}
    session = requests.Session(); session.trust_env = False
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    deadline = time.monotonic() + budget
    rows = {cve: {'cve': cve, 'kev': 'inconnu', 'epss': 'inconnu', 'applicability': 'version et conditions à confirmer'} for cve in cves}
    errors = []
    try:
        data = _fetch(session, SOURCES['www.cisa.gov'], timeout, deadline)
        kev = {row.get('cveID') for row in data.get('vulnerabilities', [])}
        for cve in cves:
            rows[cve]['kev'] = cve in kev
    except (requests.RequestException, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        errors.append('CISA KEV : ' + str(exc))
    try:
        url = SOURCES['api.first.org'] + '?' + urlencode({'cve': ','.join(cves[:100])})
        data = _fetch(session, url, timeout, deadline)
        scores = {row.get('cve'): row for row in data.get('data', [])}
        for cve in cves:
            if cve in scores:
                rows[cve]['epss'] = scores[cve].get('epss', 'inconnu')
                rows[cve]['epss_percentile'] = scores[cve].get('percentile', 'inconnu')
    except (requests.RequestException, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        errors.append('FIRST EPSS : ' + str(exc))
    for finding in report.get('findings', []):
        if finding.get('cves'):
            finding['threat_intel'] = [rows[cve] for cve in finding['cves'] if cve in rows]
    return {'status': 'partiel' if errors else 'terminé', 'cves': list(rows.values()), 'errors': errors,
            'qualification': 'KEV/EPSS priorisent ; ils ne prouvent ni présence, ni exploitabilité sur la cible.'}

