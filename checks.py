"""Contrôles bornés : proxy, en-têtes, cookies, TLS et références éditeur."""
import hashlib
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

import requests
import socks


def proxy_preflight(proxy, timeout=3):
    p = urlsplit(proxy)
    with socket.create_connection((p.hostname, p.port), timeout=timeout) as conn:
        conn.sendall(b'\x05\x01\x00')
        answer = b''
        while len(answer) < 2:
            chunk = conn.recv(2-len(answer))
            if not chunk:
                break
            answer += chunk
        if answer != b'\x05\x00':
            raise ValueError('Le proxy ne répond pas en SOCKS5 sans authentification')
    return {'status': 'disponible', 'detail': 'Négociation SOCKS5 acceptée avant toute requête cible. Bootstrap Tor et anonymat non attestés.'}


def header_values(headers):
    h = {k.lower(): v for k, v in headers.items()}
    result = []
    if 'x-content-type-options' in h and h['x-content-type-options'].strip().lower() != 'nosniff':
        result.append(('x-content-type-options', h['x-content-type-options'], 'Utiliser la valeur nosniff.'))
    if 'x-frame-options' in h and h['x-frame-options'].strip().upper() not in ('DENY', 'SAMEORIGIN'):
        result.append(('x-frame-options', h['x-frame-options'], 'Utiliser DENY/SAMEORIGIN ou une CSP frame-ancestors adaptée.'))
    if 'strict-transport-security' in h:
        age = re.search(r'(?:^|;)\s*max-age\s*=\s*(\d+)', h['strict-transport-security'], re.I)
        if not age or int(age.group(1)) == 0:
            result.append(('strict-transport-security', h['strict-transport-security'], 'Définir un max-age positif après validation du périmètre HTTPS.'))
    if 'referrer-policy' in h and h['referrer-policy'].strip().lower() in ('unsafe-url', ''):
        result.append(('referrer-policy', h['referrer-policy'], 'Évaluer une politique strict-origin-when-cross-origin selon les usages.'))
    if 'content-security-policy' in h:
        csp = h['content-security-policy'].lower()
        if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            result.append(('content-security-policy', h['content-security-policy'], 'Analyser les sources script et réduire unsafe-inline/unsafe-eval avec nonces ou hashes ; ne pas casser les parcours métier.'))
    return result


def cookie_observations(cookies, url):
    results = []
    for cookie in cookies:
        rest = {k.lower(): v for k, v in cookie._rest.items()}
        results.append({'url': url, 'name': cookie.name, 'domain': cookie.domain, 'path': cookie.path,
                        'secure': bool(cookie.secure), 'http_only': 'httponly' in rest,
                        'domain_specified': bool(cookie.domain_specified), 'expires': cookie.expires,
                        'same_site': str(rest.get('samesite', 'non déclaré')),
                        'qualification': 'Usage/session sensible non établi ; flags à revoir, aucune valeur conservée.'})
    return results


def tls_inventory(url, proxy=None, timeout=10):
    p = urlsplit(url)
    if p.scheme != 'https':
        return {'status': 'non applicable', 'detail': 'Cible HTTP'}
    report = {'status': 'terminé', 'handshakes': [], 'detail': 'TLS 1.2 et 1.3 seulement, suites négociées ; pas un inventaire exhaustif des suites ou des versions anciennes.'}
    for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        context = ssl.create_default_context()
        context.minimum_version = context.maximum_version = version
        raw = None
        try:
            if proxy:
                address = urlsplit(proxy)
                raw = socks.socksocket()
                raw.set_proxy(socks.SOCKS5, address.hostname, address.port, rdns=True)
                raw.settimeout(timeout)
                raw.connect((p.hostname, p.port or 443))
            else:
                raw = socket.create_connection((p.hostname, p.port or 443), timeout=timeout)
            with context.wrap_socket(raw, server_hostname=p.hostname) as conn:
                cert = conn.getpeercert()
                chain = conn.get_verified_chain() if hasattr(conn, 'get_verified_chain') else None
                report['handshakes'].append({'requested': version.name, 'status': 'accepté',
                    'protocol': conn.version(), 'cipher': list(conn.cipher()), 'certificate_verified': True,
                    'subject': str(cert.get('subject')), 'issuer': str(cert.get('issuer')),
                    'not_before': cert.get('notBefore'), 'not_after': cert.get('notAfter'),
                    'expires_in_days': int((ssl.cert_time_to_seconds(cert['notAfter']) - time.time()) // 86400),
                    'subject_alt_names': [value for name, value in cert.get('subjectAltName', ()) if name == 'DNS'],
                    'certificate_sha256': hashlib.sha256(conn.getpeercert(binary_form=True)).hexdigest(),
                    'verified_chain_length': len(chain) if chain is not None else 'non disponible avec ce client'})
        except (OSError, ValueError) as exc:
            report['handshakes'].append({'requested': version.name, 'status': 'non négocié',
                                         'detail': str(exc), 'conclusion': 'Échec client ou serveur ; ne prouve pas à lui seul que le protocole est désactivé.'})
        finally:
            if raw:
                raw.close()
    if not any(h['status'] == 'accepté' for h in report['handshakes']):
        report['status'] = 'incomplet'
    return report


def version_tuple(value):
    value = str(value).lstrip('v')
    if not re.fullmatch(r'\d+(?:\.\d+){1,4}', value):
        return None
    return tuple(int(part) for part in value.split('.')) + (0,) * (5-len(value.split('.')))


def compare_version(observed, latest):
    a, b = version_tuple(observed), version_tuple(latest)
    if not a or not b:
        return 'non comparable'
    return 'mise à jour disponible selon version déclarée' if a < b else 'version déclarée égale ou supérieure ; installation à confirmer'


class VendorReferences:
    ALLOWED = {'api.wordpress.org', 'updates.drupal.org', 'api.github.com'}

    def __init__(self, session, timeout=10, budget=45):
        self.session, self.timeout = session, timeout
        self.deadline = time.monotonic() + budget
        self.requests = []

    def fetch(self, url):
        p = urlsplit(url)
        if p.scheme != 'https' or p.hostname not in self.ALLOWED or p.username or p.password or p.port not in (None, 443):
            raise ValueError('Référence éditeur hors liste autorisée')
        if len(self.requests) >= 12 or time.monotonic() >= self.deadline:
            raise RuntimeError('Budget références atteint')
        row = {'url': url, 'at_utc': datetime.now(timezone.utc).isoformat(), 'status': 'inconnu'}
        self.requests.append(row)
        try:
            with self.session.get(url, timeout=min(self.timeout, max(.1, self.deadline-time.monotonic())), allow_redirects=False, stream=True) as response:
                if response.status_code != 200:
                    raise RuntimeError('Référence HTTP ' + str(response.status_code))
                chunks, size = [], 0
                for chunk in response.iter_content(16384):
                    size += len(chunk)
                    if size > 2*1024*1024 or time.monotonic() >= self.deadline:
                        raise RuntimeError('Référence trop volumineuse ou budget atteint')
                    chunks.append(chunk)
                row['status'] = 'reçue'
                return b''.join(chunks).decode('utf-8', errors='replace')
        except (requests.RequestException, ValueError, RuntimeError) as exc:
            row['detail'] = str(exc)
            raise

    def collect(self, report):
        import json
        from urllib.parse import urlencode
        results = []
        cms = {c['name'] for c in report.get('cms', [])}
        jobs = []
        if 'WordPress' in cms:
            jobs.append(('WordPress', report['inventory']['wordpress'], 'https://api.wordpress.org/core/version-check/1.7/', 'wp-core'))
            for slug, item in list(report['inventory']['plugins'].items())[:10]:
                jobs.append((slug, item.get('versions', []), 'https://api.wordpress.org/plugins/info/1.2/?' + urlencode({'action': 'plugin_information', 'request[slug]': slug}), 'wp-plugin'))
        if 'Joomla' in cms:
            jobs.append(('Joomla', report.get('cms_versions', {}).get('Joomla', []), 'https://api.github.com/repos/joomla/joomla-cms/releases/latest', 'joomla'))
        if 'Drupal' in cms:
            jobs.append(('Drupal', report.get('cms_versions', {}).get('Drupal', []), 'https://updates.drupal.org/release-history/drupal/current', 'drupal'))
        for name, versions, url, kind in jobs:
            row = {'component': name, 'observed_versions': versions, 'source': url, 'status': 'inconnu',
                   'cve_status': 'inconnu : ce contrôle compare des versions, pas une base de vulnérabilités'}
            try:
                body = self.fetch(url)
                if kind == 'drupal':
                    if '<!DOCTYPE' in body.upper() or '<!ENTITY' in body.upper():
                        raise ValueError('XML avec entités refusé')
                    releases = [el.text for el in ET.fromstring(body).findall('.//release/version') if version_tuple(el.text)]
                    latest = max(releases, key=version_tuple) if releases else None
                else:
                    data = json.loads(body)
                    latest = data.get('version') if kind == 'wp-plugin' else data.get('tag_name', '').lstrip('v') if kind == 'joomla' else next((o.get('version') for o in data.get('offers', []) if o.get('response') == 'upgrade'), None)
                if not version_tuple(latest):
                    raise ValueError('Version stable éditeur non trouvée')
                row['latest'] = latest
                row['status'] = '; '.join(compare_version(v, latest) for v in versions) if versions else 'version publiée connue, version exécutée inconnue'
                row['support'] = 'non évalué ; vérifier la branche et les conditions de migration auprès de l’éditeur'
            except (requests.RequestException, RuntimeError, ValueError, ET.ParseError) as exc:
                row['detail'] = str(exc)
            results.append(row)
        return {'status': 'terminé' if all('detail' not in r for r in results) else 'partiel', 'components': results, 'requests': self.requests}
