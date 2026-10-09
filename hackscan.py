#!/usr/bin/env python3
"""Pentest borné CMS/routeur avec rapports RSSI/CISO automatiques."""
import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from html.parser import HTMLParser
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit, urlunsplit, parse_qsl, urlencode

import requests
from reporting import write_report
from checks import proxy_preflight, header_values, cookie_observations, tls_inventory, VendorReferences
from workflow import PROFILES, preferences, save_preferences, checkpoint, read_json, compare_reports
from intelligence import page_snapshot
from tor_manager import ensure_tor
from router_profiles import TARGET_PROFILES, effective_profile, private_target, run_router_checks
from planner import AdaptivePlanner
from rule_engine import load_rules, paths_for
from threat_intel import enrich_cves
from nuclei_adapter import run_nuclei
from auth_checks import parse_roles, authenticated_matrix
from router_services import inventory_router_services
from evidence_signing import generate_key
from ai_advisor import ai_advice
from report_manager import delete_reports, export_report_list, format_report_list, list_reports, manage_reports, preview_prune, prune_reports

MAX_BODY = 2 * 1024 * 1024
SQL_ERROR = re.compile(r"SQL syntax.*?MySQL|Warning.*?mysqli?[_(:]|PostgreSQL.*?ERROR|pg_query\(.*?failed|ORA-\d{5}|SQLite(?:3)?::|sqlite3?\.OperationalError|Unclosed quotation mark|SQLSTATE\[[A-Z0-9]+\]", re.I | re.S)
SAFE_PARAMS = {'s', 'q', 'search', 'id', 'p', 'page', 'paged', 'cat', 'tag', 'product_id'}


def normalize_profile_choice(value, default='standard'):
    choice = value.strip().lower()
    aliases = {
        '1': 'rapide', 'rapid': 'rapide',
        '2': 'standard', 'standart': 'standard', 'normal': 'standard',
        '3': 'approfondi', 'appronfondi': 'approfondi', 'approfondie': 'approfondi',
        'approfondit': 'approfondi', 'deep': 'approfondi',
    }
    return aliases.get(choice, choice or default)


def cve_references(vulnerability):
    values = vulnerability.get('references', {}).get('cve', [])
    if isinstance(values, str):
        values = [values]
    return sorted({'CVE-' + str(value).removeprefix('CVE-') for value in values
                   if re.fullmatch(r'(?:CVE-)?\d{4}-\d{4,}', str(value))})


def detect_cms(page):
    """Signatures publiques uniquement : une détection reste un indice."""
    class Tags(HTMLParser):
        def __init__(self):
            super().__init__()
            self.generators, self.assets = [], []

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == 'meta' and attrs.get('name', '').lower() == 'generator':
                self.generators.append(attrs.get('content', ''))
            for key in ('src', 'href'):
                value = attrs.get(key)
                if value:
                    try:
                        target = urljoin(page['url'], value)
                        if origin(target) == origin(page['url']):
                            self.assets.append(urlsplit(target).path.lower())
                    except ValueError:
                        continue

    tags = Tags()
    tags.feed(page['body'])
    signals = {}
    for generator in tags.generators:
        for name in ('WordPress', 'Joomla', 'Drupal', 'PrestaShop', 'Magento', 'TYPO3', 'Ghost', 'Shopify', 'Wix', 'Squarespace'):
            if re.search(r'\b' + re.escape(name) + r'\b', generator, re.I):
                signals.setdefault(name, []).append('meta generator : ' + generator[:160])
    for path in tags.assets:
        for name, pattern in [('WordPress', r'/wp-(?:content|includes)/'),
                              ('Joomla', r'/media/(?:system|com_joomla)/'),
                              ('Drupal', r'/core/(?:misc/drupal|modules/)|/sites/(?:default|all)/(?:files|modules|themes)/'),
                              ('TYPO3', r'/typo3conf/|/typo3temp/'),
                              ('Ghost', r'/public/ghost-sdk')]:
            if re.search(pattern, path):
                signals.setdefault(name, []).append('ressource : ' + path[:200])
    for name, pattern in [('Drupal', r'data-drupal-selector\s*=|\bdrupalSettings\s*='),
                          ('Joomla', r'id=["\']joomla-script-options'),
                          ('Shopify', r'\bShopify\.shop\s*='),
                          ('PrestaShop', r'\b(?:var\s+)?prestashop\s*=\s*\{'),
                          ('Magento', r'text/x-magento-init'),
                          ('Wix', r'<meta\b[^>]*name=["\']wix-dynamic-custom-elements'),
                          ('Squarespace', r'\bStatic\.SQUARESPACE_CONTEXT\s*=')]:
        if re.search(pattern, page['body'], re.I):
            signals.setdefault(name, []).append('signature HTML/JavaScript : ' + name)
    return [{'name': name, 'confidence': 'probable', 'evidence': sorted(set(evidence)), 'url': page['url']}
            for name, evidence in sorted(signals.items())]


def origin(url):
    p = urlsplit(url)
    if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password:
        raise ValueError('URL HTTP(S) sans identifiants requise.')
    return p.scheme.lower(), p.hostname.lower(), p.port or (443 if p.scheme == 'https' else 80)


def clean_url(url):
    origin(url)
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path or '/', p.query, ''))


def canonical_redirect(source, target):
    """Alias www initial ou passage HTTP→HTTPS, sans élargir aux sous-domaines."""
    before, after = origin(source), origin(target)
    hosts = {before[1], before[1][4:] if before[1].startswith('www.') else 'www.' + before[1]}
    return (after[1] in hosts and before[2] in (80, 443) and after[2] == 443
            and after[0] == 'https' and (before[0] == 'http' or before[2] == after[2]))


class Scanner:
    def __init__(self, url, *, proxy=None, delay=1, timeout=12, max_requests=50, max_pages=5, budget=300, rules=None):
        self.url = clean_url(url)
        self.scope = origin(self.url)
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers['User-Agent'] = 'Hackscan/5.0 (authorized security audit)'
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.proxy = proxy
        self.delay, self.timeout = delay, timeout
        self.max_requests, self.max_pages = max_requests, max_pages
        self.deadline = time.monotonic() + budget
        self.last = 0
        self.cache = {}
        self.checkpoint_callback = None
        self.rules = rules or load_rules()
        self.report = {'target': self.url, 'started_utc': datetime.now(timezone.utc).isoformat(),
                       'requested_target': self.url, 'redirects': [], 'checks': [], 'pages': [], 'surface': {'forms': [], 'external_domains': []},
                       'configuration': {'max_pages': max_pages, 'max_requests': max_requests, 'delay_seconds': delay,
                                         'timeout_seconds': timeout, 'budget_seconds': budget, 'method': 'GET public, non authentifié'},
                       'proxy': 'SOCKS5 avec DNS distant' if proxy else 'connexion directe',
                       'findings': [], 'cms': [], 'inventory': {'plugins': {}, 'themes': {}, 'wordpress': []},
                       'requests': [], 'tools': {}, 'limitations': [
                           'Audit externe sans accès administrateur : inventaire partiel, versions déclaratives.',
                           'Un indice SQL ne confirme pas une injection ; aucune extraction de données.',
                           'Aucun test authentifié, force brute, formulaire POST ni test de disponibilité.',
                           'Absence de constat ne signifie pas absence de vulnérabilité.',
                           'Les en-têtes observés sur les pages publiques ne décrivent pas tous les parcours.',
                       ]}
        self.report.update({'cookies': [], 'cms_versions': {}, 'sql_candidates': [], 'page_observations': []})

    def in_scope(self, url):
        try:
            return origin(url) == self.scope
        except ValueError:
            return False

    def get(self, url, *, allow_canonical=False):
        url = clean_url(url)
        if not self.in_scope(url):
            raise ValueError('URL hors périmètre')
        if url in self.cache:
            return self.cache[url]
        for _ in range(5):
            current_count = sum(not r.get('historical') for r in self.report['requests'])
            if current_count >= self.max_requests or time.monotonic() >= self.deadline:
                raise RuntimeError('Budget de requêtes ou de temps atteint')
            time.sleep(max(0, self.delay - (time.monotonic() - self.last)))
            self.last = time.monotonic()
            started = time.monotonic()
            row = {'url': url, 'status': None, 'at_utc': datetime.now(timezone.utc).isoformat()}
            self.report['requests'].append(row)
            print(f"  HTTP {current_count+1}/{self.max_requests} · {max(0, int(self.deadline-time.monotonic()))} s restantes · {urlsplit(url).path}", flush=True)
            try:
                with self.session.get(url, timeout=min(self.timeout, max(0.1, self.deadline-time.monotonic())),
                                      allow_redirects=False, stream=True) as r:
                    row['status'] = r.status_code
                    if r.status_code in (301, 302, 303, 307, 308):
                        target = clean_url(urljoin(url, r.headers.get('Location', '')))
                        if not self.in_scope(target):
                            if allow_canonical and canonical_redirect(url, target):
                                self.scope = origin(target)
                                self.url = target
                                self.report['target'] = target
                            else:
                                raise ValueError('Redirection hors périmètre bloquée : ' + target)
                        self.report['redirects'].append({'from': url, 'to': target, 'status': r.status_code,
                                                         'reason': 'normalisation initiale' if allow_canonical else 'même origine'})
                        url = target
                        continue
                    chunks, size = [], 0
                    for chunk in r.iter_content(16384):
                        size += len(chunk)
                        if size > MAX_BODY or time.monotonic() >= self.deadline:
                            raise RuntimeError('Réponse trop volumineuse ou budget dépassé')
                        chunks.append(chunk)
                    body = b''.join(chunks).decode(r.encoding or 'utf-8', errors='replace')
                    result = {'url': url, 'status': r.status_code, 'headers': {k.lower(): v for k, v in r.headers.items()}, 'body': body}
                    for observed in cookie_observations(r.cookies, url):
                        if observed not in self.report['cookies']:
                            self.report['cookies'].append(observed)
                    row.update({'bytes': size, 'header_capture_schema': 2, 'sha256': hashlib.sha256(b''.join(chunks)).hexdigest(),
                                'content_type': r.headers.get('Content-Type', ''),
                                'headers': {k.lower(): v for k, v in r.headers.items() if k.lower() in
                                            {'content-security-policy', 'strict-transport-security', 'x-content-type-options',
                                             'referrer-policy', 'x-frame-options', 'permissions-policy', 'server', 'x-powered-by',
                                             'content-security-policy-report-only', 'access-control-allow-origin',
                                             'access-control-allow-credentials', 'access-control-allow-methods',
                                             'cache-control', 'cross-origin-opener-policy', 'cross-origin-resource-policy'}}})
                    if r.status_code == 429:
                        raise RuntimeError('HTTP 429 : arrêt pour respecter la limitation du serveur')
                    self.cache[row['url']] = result
                    return result
            except (requests.RequestException, ValueError, RuntimeError) as exc:
                detail = str(exc)
                if self.proxy and isinstance(exc, requests.RequestException):
                    detail = ('Échec de connexion à la cible via Tor/SOCKS ; aucun repli direct. '
                              'Tor peut être opérationnel tandis que la cible ou son hébergeur filtre les nœuds de sortie. '
                              'Détail : ' + detail)
                    row['error'] = detail
                    raise requests.ConnectionError(detail) from exc
                row['error'] = detail
                raise
            finally:
                row['duration_ms'] = round((time.monotonic() - started) * 1000)
                if self.checkpoint_callback:
                    self.checkpoint_callback()
        raise RuntimeError('Trop de redirections')

    def finding(self, severity, title, evidence, remediation, url=None, confidence='observé'):
        self.report['findings'].append(dict(severity=severity, title=title, evidence=evidence,
                                           remediation=remediation, url=url or self.url, confidence=confidence))

    def inventory(self, page):
        body = page['body']
        versions = re.findall(r'WordPress\s+(\d+(?:\.\d+)+)', body, re.I)
        self.report['inventory']['wordpress'] = sorted(set(self.report['inventory']['wordpress'] + versions))
        for kind in ('plugins', 'themes'):
            for slug, ver in re.findall(r'/wp-content/' + kind + r'/([a-zA-Z0-9_-]+)/[^\s"\'<>]*?(?:\?ver=([\d.]+))?(?=[\s"\'<>]|$)', html.unescape(body)):
                item = self.report['inventory'][kind].setdefault(slug, {'versions': [], 'evidence': []})
                if ver and re.fullmatch(r'\d+(?:\.\d+){1,4}', ver) and ver not in item['versions']:
                    item['versions'].append(ver)
                elif ver and not re.fullmatch(r'\d+(?:\.\d+){1,4}', ver):
                    tokens = item.setdefault('asset_tokens', [])
                    if ver not in tokens:
                        tokens.append(ver)
                if page['url'] not in item['evidence']:
                    item['evidence'].append(page['url'])

    def headers(self, page):
        h = {k.lower(): v for k, v in page['headers'].items()}
        for name in ('content-security-policy', 'x-content-type-options', 'referrer-policy',
                     'strict-transport-security', 'x-frame-options', 'permissions-policy'):
            applicable = name != 'strict-transport-security' or self.scope[0] == 'https'
            self.report['checks'].append({'category': 'En-têtes HTTP', 'name': name, 'url': page['url'],
                'status': ('présent — valeur à revoir' if name in h else 'absent') if applicable else 'non applicable en HTTP',
                'evidence': h.get(name, 'Non reçu dans cette réponse.')})
        self.report['checks'].append({'category': 'Transport', 'name': 'Validation TLS du client', 'url': page['url'],
            'status': 'effectuée' if self.scope[0] == 'https' else 'non applicable en HTTP',
            'evidence': 'Connexion HTTPS acceptée avec vérification du certificat ; protocoles et suites cryptographiques non inventoriés.' if self.scope[0] == 'https' else 'Connexion HTTP sans TLS.'})
        for name, fix in [('content-security-policy', 'Définir une CSP adaptée aux scripts et ressources du site.'),
                          ('x-content-type-options', 'Configurer X-Content-Type-Options: nosniff.'),
                          ('referrer-policy', 'Configurer Referrer-Policy: strict-origin-when-cross-origin.')]:
            if name not in h:
                self.finding('Faible', 'En-tête absent : ' + name, 'Absent de la réponse HTTP publique.', fix)
        if self.scope[0] == 'https' and 'strict-transport-security' not in h:
            self.finding('Faible', 'HSTS absent', 'En-tête Strict-Transport-Security absent.', 'Activer HSTS après vérification HTTPS des domaines concernés.')
        if 'x-frame-options' not in h and not re.search(r'(?i)(?:^|;)\s*frame-ancestors\s', h.get('content-security-policy', '')):
            self.finding('Faible', 'Protection contre le cadrage absente', 'Ni X-Frame-Options ni frame-ancestors.', "Configurer frame-ancestors dans la CSP selon les usages autorisés.")
        if self.scope[0] == 'http':
            self.finding('Moyenne', 'Transport HTTP', 'URL testée sans TLS.', 'Utiliser HTTPS avec un certificat valide et une redirection HTTP.')
        for name, value, fix in header_values(h):
            self.report['checks'].append({'category': 'Valeurs des en-têtes', 'name': name,
                'url': page['url'], 'status': 'configuration à revoir', 'evidence': value})
            self.finding('Faible', 'En-tête à revoir : ' + name, value, fix, page['url'], 'configuration observée, impact à qualifier')

    def crawl(self):
        first = self.get(self.url, allow_canonical=True)
        self.url = first['url']
        self.report['target'] = self.url
        if first['status'] >= 400:
            raise RuntimeError('Page principale inaccessible : HTTP ' + str(first['status']))
        self.headers(first)
        pages, todo, seen = [], [first['url']], set()
        while todo and len(pages) < self.max_pages:
            url = todo.pop(0)
            if url in seen:
                continue
            seen.add(url)
            page = self.get(url)
            if page['status'] != 200 or 'html' not in page['headers'].get('content-type', '').lower():
                continue
            pages.append(page)
            self.report['pages'].append({'url': page['url'], 'status': page['status']})
            observation = page_snapshot(page)
            saved_observations = self.report.setdefault('page_observations', [])
            saved_observations[:] = [p for p in saved_observations if p['url'] != observation['url']]
            saved_observations.append(observation)
            self.passive_surface(page)
            for cms in detect_cms(page):
                if cms not in self.report['cms']:
                    self.report['cms'].append(cms)
            self.inventory(page)
            for name in ('Joomla', 'Drupal'):
                if name not in {c['name'] for c in self.report['cms']}:
                    continue
                versions = re.findall(r'\b' + name + r'(?:!|\s|[^\w]){0,6}(\d+(?:\.\d+){1,3})', page['body'], re.I)
                self.report['cms_versions'][name] = sorted(set(self.report['cms_versions'].get(name, []) + versions))
            for link in re.findall(r'<a\b[^>]*\bhref=["\']([^"\']+)', page['body'], re.I):
                target = urljoin(page['url'], html.unescape(link)).split('#')[0]
                p = urlsplit(target)
                if self.in_scope(target) and not p.query and not re.search(r'logout|delete|remove|wp-admin|wp-login|cart|checkout', p.path, re.I) and not re.search(r'\.(pdf|zip|png|jpe?g|svg|mp4)$', p.path, re.I):
                    if target not in seen and target not in todo and len(todo) < 30:
                        todo.append(target)
            self.report['sql_candidates'] = self.sql_candidates(pages)
        return pages

    def cms_checks(self, names):
        if 'WordPress' in names:
            self.wordpress_checks()
        else:
            self.report['tools']['wordpress_checks'] = {'status': 'non applicable : aucune signature WordPress'}
        profiles = {'Joomla': 'joomla', 'Drupal': 'drupal'}
        for name in names:
            for path in paths_for(self.rules, profiles[name]) if name in profiles else ():
                try:
                    page = self.get(urljoin(self.url, path))
                except (requests.RequestException, ValueError) as exc:
                    self.report['checks'].append({'category': name, 'name': path, 'url': urljoin(self.url, path), 'status': 'non vérifié', 'evidence': str(exc)})
                    continue
                self.report['checks'].append({'category': name, 'name': path, 'url': page['url'], 'status': 'réponse reçue', 'evidence': 'HTTP ' + str(page['status']) + ' ; présence publique ne signifie pas accès administratif.'})
                if page['status'] == 200:
                    pattern = r'<version>\s*(\d+(?:\.\d+){1,3})\s*</version>' if name == 'Joomla' else r'Drupal\s+(\d+(?:\.\d+){1,3})'
                    versions = re.findall(pattern, page['body'], re.I)
                    if versions:
                        self.report['cms_versions'][name] = sorted(set(self.report['cms_versions'].get(name, []) + versions))
                        self.finding('Info', name + ' : version publiquement déclarée', ', '.join(versions), 'Confirmer la version exécutée, vérifier le support éditeur et réduire les informations inutiles.', page['url'])

    def passive_surface(self, page):
        surface = self.report['surface']
        class Surface(HTMLParser):
            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == 'form' and len(surface['forms']) < 30:
                    action = urljoin(page['url'], attrs.get('action') or page['url'])
                    try:
                        p = urlsplit(action)
                    except ValueError:
                        return
                    entry = {'page': page['url'], 'action': urlunsplit((p.scheme, p.netloc, p.path, '', '')),
                             'method': attrs.get('method', 'GET').upper(), 'tested': False}
                    if entry not in surface['forms']:
                        surface['forms'].append(entry)
                if tag in ('script', 'iframe', 'link', 'img'):
                    resource = attrs.get('src') or attrs.get('href')
                    if resource:
                        try:
                            target = urlsplit(urljoin(page['url'], resource))
                        except ValueError:
                            return
                        if target.scheme in ('http', 'https') and target.hostname and target.hostname != urlsplit(page['url']).hostname:
                            if target.hostname not in surface['external_domains'] and len(surface['external_domains']) < 50:
                                surface['external_domains'].append(target.hostname)
        Surface().feed(page['body'])

    def wordpress_checks(self):
        # Détection publique uniquement, sans récupération d'utilisateurs ni de secrets.
        for path in paths_for(self.rules, 'wordpress'):
            try:
                page = self.get(urljoin(self.url, path))
            except (requests.RequestException, ValueError) as exc:
                self.report['limitations'].append('Endpoint non vérifié : ' + path + ' — ' + str(exc))
                self.report['checks'].append({'category': 'WordPress', 'name': path, 'url': urljoin(self.url, path),
                                              'status': 'non vérifié', 'evidence': str(exc)})
                continue
            self.report['checks'].append({'category': 'WordPress', 'name': path, 'url': page['url'],
                'status': 'réponse reçue', 'evidence': 'HTTP ' + str(page['status']) + ' ; disponibilité GET seulement, sans conclusion sur les droits ni la méthode POST.'})
            if page['status'] == 200 and path == 'readme.html' and re.search(r'WordPress', page['body'], re.I):
                self.finding('Info', 'Readme WordPress accessible', 'HTTP 200 et mention WordPress.', 'Réduire les informations de version exposées ; maintenir le cœur à jour.', page['url'])
            if page['status'] == 200 and path == 'wp-json/' and 'wp/v2' in page['body']:
                self.finding('Info', 'API REST WordPress accessible', 'Namespace wp/v2 présent.', 'Vérifier les droits sur les endpoints sensibles ; la disponibilité publique est normale.', page['url'])
        for slug, item in list(self.report['inventory']['plugins'].items())[:10]:
            try:
                page = self.get(urljoin(self.url, 'wp-content/plugins/' + slug + '/readme.txt'))
            except (requests.RequestException, ValueError) as exc:
                self.report['limitations'].append('Readme non vérifié : ' + slug + ' — ' + str(exc))
                continue
            if page['status'] == 200 and re.search(r'^===.+===$', page['body'], re.M):
                match = re.search(r'^Stable tag:\s*(\S+)', page['body'], re.M | re.I)
                if match:
                    item['readme_stable_tag'] = match.group(1)
                    item['evidence'].append(page['url'])
                    self.report['limitations'].append('Stable tag du plugin ' + slug + ' : version du readme, pas une preuve de la version exécutée.')

    def sql_candidates(self, pages):
        candidates = []
        for page in pages:
            for href in [page['url']] + re.findall(r'<a\b[^>]*\bhref=["\']([^"\']+)', page['body'], re.I):
                url = urljoin(page['url'], html.unescape(href)).split('#')[0]
                p = urlsplit(url)
                pairs = parse_qsl(p.query, keep_blank_values=True)
                if self.in_scope(url) and pairs and all(k in SAFE_PARAMS for k, _ in pairs) and not re.search(r'logout|delete|remove|admin|login|cart|checkout', p.path, re.I):
                    if url not in candidates:
                        candidates.append(url)
        if any(self.report['inventory'].values()) or any('wp-content/' in p['body'] for p in pages):
            candidates.insert(0, urljoin(self.url, '?s=hackscan-audit'))
        return list(dict.fromkeys(candidates))

    def sql_checks(self, pages, selected_urls=None, selected_params=None):
        candidates = selected_urls if selected_urls else self.sql_candidates(pages)
        count = 0
        tested = []
        for url in candidates[:3]:
            p = urlsplit(url)
            pairs = parse_qsl(p.query, keep_blank_values=True)
            base = self.get(url)
            if base['status'] != 200 or SQL_ERROR.search(base['body']):
                self.report['limitations'].append('SQL non concluant : réponse initiale inaccessible ou erreur déjà présente sur ' + url)
                continue
            # Deux marqueurs de syntaxe, sans UNION, délai, écriture, ni extraction.
            indexes = [i for i, (name, _) in enumerate(pairs) if name in (selected_params or [pairs[0][0]])]
            for index in indexes[:3]:
              for mark in ("'", '"'):
                changed = list(pairs)
                changed[index] = (changed[index][0], changed[index][1] + mark)
                probe_url = urlunsplit((p.scheme, p.netloc, p.path, urlencode(changed), ''))
                probe = self.get(probe_url)
                count += 1
                tested.append({'url': url, 'parameter': pairs[index][0], 'status': probe['status'], 'marker': mark})
                match = SQL_ERROR.search(probe['body'])
                if match:
                    self.finding('Moyenne', 'Indice d’erreur SQL sur le paramètre ' + pairs[index][0],
                                 'Erreur absente du témoin, présente après un marqueur de syntaxe : ' + match.group(0)[:240],
                                 'Faire confirmer sur staging ; utiliser des requêtes paramétrées, corriger le composant et masquer les erreurs SQL.',
                                 probe_url, 'indice à confirmer')
        self.report['tools']['sql_probes'] = {'status': 'terminé' if count else 'non testé : aucun paramètre public vérifiable', 'candidates': candidates[:3], 'probes': count, 'tested': tested,
                                              'conclusion': 'Recherche limitée aux erreurs visibles, ne couvre pas les injections aveugles.'}
        if not count:
            self.report['limitations'].append('Aucun paramètre SQL testable trouvé : SQL non testé.')

    def wpscan(self, output, timeout):
        binary = shutil.which('wpscan')
        if not binary:
            self.report['tools']['wpscan'] = {'status': 'indisponible', 'detail': 'Exécuter ./install.sh --wpscan.'}
            return
        path = output / 'wpscan.json'
        cmd = [binary, '--url', self.url, '--scope', self.scope[1], '--ignore-main-redirect',
               '--detection-mode', 'passive', '--plugins-detection', 'passive',
               '--plugins-version-detection', 'passive', '--enumerate', 'ap,at',
               '--throttle', '1000', '--max-threads', '1', '--request-timeout', '12',
               '--connect-timeout', '10', '--no-update', '--format', 'json', '--output', str(path)]
        if self.proxy:
            cmd += ['--proxy', self.proxy]
        token = os.environ.get('WPSCAN_API_TOKEN')
        env = os.environ.copy()
        if token:
            env['WPSCAN_API_TOKEN'] = token  # Variable prise en charge par WPScan ; jamais dans argv.
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
            data = json.loads(path.read_text()) if path.exists() else {}
            detail = (proc.stderr or proc.stdout)[-1500:]
            if token:
                detail = detail.replace(token, '[MASQUÉ]')
            self.report['tools']['wpscan'] = {'status': 'terminé' if proc.returncode == 0 and not data.get('scan_aborted') else 'échec',
                                               'returncode': proc.returncode, 'detail': str(data.get('scan_aborted') or detail).replace(token, '[MASQUÉ]') if token else str(data.get('scan_aborted') or detail),
                                               'api': 'token fourni' if token else 'sans token : base de vulnérabilités non consultée'}
            number = (data.get('version') or {}).get('number')
            if number and number not in self.report['inventory']['wordpress']:
                self.report['inventory']['wordpress'].append(number)
            for finding in data.get('interesting_findings', []):
                self.finding('Info', 'WPScan : ' + str(finding.get('type', 'information publique')),
                             '; '.join(str(x) for x in finding.get('interesting_entries', []))[:1000],
                             'Examiner le résultat dans son contexte avant de décider d’un durcissement.', finding.get('url') or self.url)
            for group in ('plugins', 'themes'):
                for slug, item in data.get(group, {}).items():
                    current = self.report['inventory'][group].setdefault(slug, {'versions': [], 'evidence': []})
                    version = (item.get('version') or {}).get('number')
                    if version and version not in current['versions']:
                        current['versions'].append(version)
                    for vuln in item.get('vulnerabilities', []):
                        self.finding('Moyenne', vuln.get('title', 'Vulnérabilité signalée') + ' — ' + slug,
                                     'Base WPScan ; version corrigée : ' + str(vuln.get('fixed_in', 'inconnue')),
                                     'Confirmer la version installée et l’applicabilité ; mettre à jour en test puis en production.', confidence='correspondance à confirmer')
                        self.report['findings'][-1].update({'component': slug, 'qualification': 'correspondance CVE à confirmer' if cve_references(vuln) else 'correspondance de vulnérabilité à confirmer',
                            'cves': cve_references(vuln),
                            'fixed_in': vuln.get('fixed_in'), 'references': vuln.get('references', {})})
            for vuln in (data.get('version') or {}).get('vulnerabilities', []):
                self.finding('Moyenne', vuln.get('title', 'Vulnérabilité du cœur WordPress'),
                             'Base WPScan ; correction : ' + str(vuln.get('fixed_in', 'inconnue')),
                             'Confirmer la version du cœur et mettre à jour après sauvegarde.', confidence='correspondance à confirmer')
                self.report['findings'][-1].update({'component': 'WordPress', 'qualification': 'correspondance CVE à confirmer' if cve_references(vuln) else 'correspondance de vulnérabilité à confirmer',
                    'cves': cve_references(vuln),
                    'fixed_in': vuln.get('fixed_in'), 'references': vuln.get('references', {})})
            if path.exists():
                path.chmod(0o600)
        except (subprocess.TimeoutExpired, OSError, ValueError) as exc:
            self.report['tools']['wpscan'] = {'status': 'incomplet', 'detail': str(exc)}
        from reporting import obstacle
        data = self.report['tools']['wpscan']
        if data['status'] != 'terminé':
            cause, impact, action = obstacle(data.get('detail', ''))
            data['diagnosis'] = {'cause': cause, 'impact': impact, 'action': action}
        self.report['limitations'].append('WPScan dispose de son propre budget de temps ; sa couverture et ses erreurs sont indiquées séparément.')

    def sqlmap(self, url, output, timeout, parameters=None):
        binary = shutil.which('sqlmap')
        if not binary:
            self.report['tools']['sqlmap'] = {'status': 'indisponible', 'detail': 'Installer sqlmap avec votre gestionnaire système.'}
            return
        cmd = [binary, '-u', url, '--batch', '--level=1', '--risk=1', '--technique=BE',
               '--threads=1', '--delay=1', '--timeout=10', '--retries=0', '--ignore-redirects',
               '--answers=extending=N', '--disable-coloring', '--output-dir=' + str(output / 'sqlmap')]
        if parameters:
            cmd += ['-p', ','.join(parameters)]
        if self.proxy:
            # sqlmap utilise SOCKS5 avec résolution distante par défaut.
            cmd += ['--proxy=' + self.proxy.replace('socks5h://', 'socks5://', 1)]
        else:
            cmd += ['--ignore-proxy']
        status = 'terminé'
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            log = proc.stdout + proc.stderr
            if proc.returncode or '[CRITICAL]' in log or '[ERROR]' in log:
                status = 'échec'
        except subprocess.TimeoutExpired as exc:
            log = (exc.stdout or b'') + (exc.stderr or b'')
            if isinstance(log, bytes):
                log = log.decode('utf-8', errors='replace')
            status = 'incomplet : budget de temps atteint'
        except OSError as exc:
            log, status = str(exc), 'échec'
        (output / 'sqlmap.log').write_text(log, encoding='utf-8')
        positive = 'sqlmap identified the following injection point' in log
        self.report['tools']['sqlmap'] = {'status': status, 'url': url,
            'conclusion': 'Injection signalée par sqlmap : à reproduire sur staging.' if positive else 'Aucune injection confirmée dans les tests réalisés.',
            'log': log[-14000:]}
        if positive:
            self.finding('Haute', 'Injection SQL signalée par sqlmap', log[-5000:],
                         'Reproduire sur staging, corriger les requêtes avec des paramètres liés et vérifier les plugins concernés.',
                         url, 'signalement outil à valider')
        self.report['limitations'].append('sqlmap : URL GET explicite, niveau 1, risque 1, techniques booléenne et erreur ; aucune extraction, écriture ni technique temporelle. Budget distinct du scanner intégré.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url', nargs='?')
    parser.add_argument('--interactive', action='store_true')
    parser.add_argument('--authorized', action='store_true', help='Confirmer votre autorisation sur cette cible')
    parser.add_argument('--profile', choices=PROFILES)
    parser.add_argument('--target-profile', choices=TARGET_PROFILES,
                        help='Technologie : auto, web/CMS ou routeur local')
    parser.add_argument('--config', type=Path, default=Path.home()/'.config/hackscan/preferences.json')
    parser.add_argument('--save-config', action='store_true', help='Enregistrer les préférences techniques, sans URL ni secret')
    parser.add_argument('--resume', type=Path, help='Reprendre un checkpoint.json, sans répéter les étapes terminées')
    parser.add_argument('--compare', type=Path, help='Ancien report.json pour comparaison')
    parser.add_argument('--plan', type=Path, help='Plan de traitement JSON édité et exporté depuis le rapport')
    parser.add_argument('--render-report', type=Path, help='Régénérer les exports d’un JSON existant sans contacter la cible')
    parser.add_argument('--rules-dir', type=Path, help='Règles YAML externes signées')
    parser.add_argument('--rules-public-key', type=Path, help='Clé publique Ed25519 des règles externes')
    parser.add_argument('--signing-key', type=Path, help='Clé privée Ed25519 pour signer le manifeste')
    parser.add_argument('--init-signing-key', type=Path, help='Créer une clé Ed25519 protégée puis quitter')
    parser.add_argument('--organization')
    parser.add_argument('--owner')
    parser.add_argument('--business-owner')
    parser.add_argument('--criticality')
    parser.add_argument('--data-sensitivity')
    parser.add_argument('--sql', action='store_true')
    parser.add_argument('--sql-url', action='append', default=[], help='URL GET précise à sonder (maximum 3)')
    parser.add_argument('--sql-parameters', help='Paramètres de lecture autorisés, séparés par des virgules')
    parser.add_argument('--wpscan', action='store_true')
    parser.add_argument('--nuclei-safe', action='store_true', help='Nuclei signé, HTTP, faible débit, sans fuzz/OAST/code')
    parser.add_argument('--nuclei-timeout', type=int, default=120)
    parser.add_argument('--sqlmap-url')
    parser.add_argument('--auth-token-env', action='append', default=[], metavar='ROLE=ENV')
    parser.add_argument('--auth-cookie-env', action='append', default=[], metavar='ROLE=ENV')
    parser.add_argument('--auth-url', action='append', default=[], help='URL GET de comparaison authentifiée, maximum 5')
    parser.add_argument('--router-services', action='store_true', help='Inventaire TCP local borné sur 7 ports')
    parser.add_argument('--threat-intel', action=argparse.BooleanOptionalAction, default=None, help='Corréler les CVE fournies avec KEV/EPSS')
    parser.add_argument('--ai-local', action='store_true', help='Alias compatible de --ai-provider ollama')
    parser.add_argument('--ai-provider', choices=('none', 'ollama', 'openai', 'mistral'), default='none')
    parser.add_argument('--ai-model', help='Modèle IA ; valeur sûre par défaut selon le fournisseur')
    parser.add_argument('--tor', action='store_true', default=None)
    parser.add_argument('--tor-port', type=int, default=None, help='Port SOCKS Tor local (9050 par défaut)')
    parser.add_argument('--tor-wait', type=int, default=90, help='Attente maximale de validation Tor, 5–300 s')
    parser.add_argument('--direct', action='store_true', help='Connexion directe explicite, ignore la préférence Tor')
    parser.add_argument('--proxy')
    parser.add_argument('--tls', action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument('--updates', action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--reports-root', type=Path, default=Path('reports'))
    parser.add_argument('--keep-reports', type=int, default=10)
    parser.add_argument('--auto-prune', action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument('--list-reports', action='store_true')
    parser.add_argument('--report-target', help='Filtrer la liste par cible')
    parser.add_argument('--report-status', help='Filtrer la liste par statut')
    parser.add_argument('--report-format', choices=('text', 'json', 'csv'), default='text')
    parser.add_argument('--preview-prune', action='store_true', help='Afficher les rapports qui dépassent la rétention sans les supprimer')
    parser.add_argument('--manage-reports', action='store_true')
    parser.add_argument('--delete-report', action='append', default=[], metavar='NOM')
    parser.add_argument('--offer-report-management', action='store_true', help=argparse.SUPPRESS)
    for option, kind in [('max-pages', int), ('max-requests', int), ('delay', float), ('timeout', float), ('budget', int), ('wpscan-timeout', int), ('sqlmap-timeout', int)]:
        parser.add_argument('--'+option, type=kind, default=None)
    args = parser.parse_args()
    explicit_profile = args.profile is not None
    explicit_target_profile = args.target_profile is not None
    explicit_tor = args.tor is True
    explicit_timeout = args.timeout is not None
    explicit_budget = args.budget is not None
    os.umask(0o077)
    if not 1 <= args.keep_reports <= 100:
        parser.error('--keep-reports doit être compris entre 1 et 100')
    try:
        if args.list_reports:
            reports = list_reports(args.reports_root, args.report_target, args.report_status)
            print(export_report_list(reports, args.report_format))
            return 0
        if args.preview_prune:
            candidates = preview_prune(args.reports_root, args.keep_reports)
            print('\n'.join(candidates) if candidates else 'Aucun rapport à supprimer.')
            return 0
        if args.manage_reports:
            removed = manage_reports(args.reports_root)
            print('Rapports supprimés :', ', '.join(removed) if removed else 'aucun')
            return 0
        if args.delete_report:
            removed = delete_reports(args.reports_root, args.delete_report)
            print('Rapports supprimés :', ', '.join(removed))
            return 0
        if args.offer_report_management:
            reports = list_reports(args.reports_root)
            if reports:
                print('\nAnciens rapports disponibles :')
                print(format_report_list(reports))
                try:
                    choice = input('Supprimer certains rapports avant le lancement ? [o/N] : ').strip().lower()
                except EOFError:
                    choice = ''
                except KeyboardInterrupt:
                    print('\nLancement annulé.')
                    return 1
                if choice in ('o', 'oui', 'y', 'yes'):
                    removed = manage_reports(args.reports_root, display=False)
                    print('Rapports supprimés :', ', '.join(removed) if removed else 'aucun')
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if args.ai_local:
        if args.ai_provider != 'none':
            parser.error('--ai-local est incompatible avec --ai-provider')
        args.ai_provider = 'ollama'
    if args.init_signing_key:
        try:
            print('Clé créée :', generate_key(args.init_signing_key).resolve())
            return 0
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
    try:
        saved = preferences(args.config)
        state = read_json(args.resume) if args.resume else None
        if state and (state.get('schema') != 1 or not isinstance(state.get('report'), dict)):
            raise ValueError('Checkpoint incompatible')
        if args.render_report:
            report = read_json(args.render_report)
            output = args.output or args.render_report.parent / ('export-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
            if output.exists() and any(output.iterdir()):
                raise ValueError('Dossier de sortie non vide')
            if args.organization:
                report.setdefault('metadata', {})['organization'] = args.organization
            if args.owner:
                report.setdefault('metadata', {})['owner'] = args.owner
            if args.compare:
                report['comparison'] = compare_reports(report, read_json(args.compare))
            if args.plan:
                report['treatment_updates'] = read_json(args.plan)
            write_report(report, output, signing_key=args.signing_key)
            print('Exports régénérés sans nouvelles mesures :', output.resolve())
            if args.auto_prune and output.parent.resolve() == args.reports_root.resolve():
                removed = prune_reports(args.reports_root, args.keep_reports, {output.name})
                if removed:
                    print('Rétention : rapports supprimés :', ', '.join(removed))
            return 0
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    prior = state['report'] if state else None
    prior_settings = prior.get('run_settings', {}) if prior else {}
    if prior:
        if args.tor_port is None:
            args.tor_port = prior_settings.get('tor_port')
        args.url = args.url or prior.get('requested_target', prior['target'])
        for key in ('profile', 'target_profile', 'tor', 'tls', 'updates'):
            if getattr(args, key) is None:
                setattr(args, key, prior_settings.get(key))
        if not args.sql_url:
            args.sql_url = prior_settings.get('sql_url', [])
        args.sql = args.sql or prior_settings.get('sql', False)
        args.wpscan = args.wpscan or prior_settings.get('wpscan', False)
        args.sqlmap_url = args.sqlmap_url or prior_settings.get('sqlmap_url')
        args.sql_parameters = args.sql_parameters or prior_settings.get('sql_parameters')
        if not args.proxy and not args.direct and not args.tor:
            args.proxy = prior_settings.get('proxy')
            if 'SOCKS' in prior.get('proxy', '') and not args.proxy:
                parser.error('Reprise proxy : préciser --proxy ou choisir explicitement --direct')
    args.profile = args.profile or saved.get('profile', 'standard')
    args.target_profile = args.target_profile or saved.get('target_profile', 'auto')
    if args.profile not in PROFILES:
        parser.error('Profil de configuration invalide')
    if args.rules_public_key and not args.rules_dir:
        parser.error('--rules-public-key exige --rules-dir')
    if not 1 <= args.nuclei_timeout <= 900 or len(args.auth_url) > 5:
        parser.error('Budget Nuclei 1–900 s et maximum 5 URL authentifiées')
    if args.tor is None:
        args.tor = saved.get('tor', False)
    if args.proxy and not explicit_tor:
        args.tor = False
    if not isinstance(args.tor, bool):
        parser.error('Préférence Tor booléenne requise')
    args.tor_port = args.tor_port if args.tor_port is not None else saved.get('tor_port', 9050)
    if not isinstance(args.tor_port, int) or not 1024 <= args.tor_port <= 65535 or not 5 <= args.tor_wait <= 300:
        parser.error('Port Tor 1024–65535 et attente Tor 5–300 s requis')
    if args.direct:
        if args.proxy or explicit_tor:
            parser.error('--direct incompatible avec --tor/--proxy')
        args.tor = False
    if args.interactive:
        try:
            args.url = args.url or input('URL du site à analyser : ').strip()
            if args.url and '://' not in args.url:
                args.url = 'https://' + args.url
            if not args.authorized:
                args.authorized = input('Êtes-vous autorisé à auditer ce site ? [o/N] : ').strip().lower() in ('o', 'oui', 'y', 'yes')
            if not prior and not explicit_target_profile:
                choice = input(
                    'Type de cible : 1 auto, 2 WordPress, 3 Joomla, 4 Bbox, '
                    '5 Livebox, 6 routeur générique [' + args.target_profile + '] : '
                ).strip().lower()
                args.target_profile = {
                    '1': 'auto', '2': 'wordpress', '3': 'joomla',
                    '4': 'router-bouygues', '5': 'router-orange',
                    '6': 'router-generic', 'wp': 'wordpress',
                    'bbox': 'router-bouygues', 'bouygues': 'router-bouygues',
                    'livebox': 'router-orange', 'orange': 'router-orange',
                    'routeur': 'router-generic', 'router': 'router-generic',
                }.get(choice, choice or args.target_profile)
            interactive_target = effective_profile(args.url, requested=args.target_profile) if args.url else 'web-generic'
            if args.authorized and not interactive_target.startswith('router-') and not args.proxy and not args.direct and not explicit_tor:
                choice = input('Utiliser Tor (installation/démarrage et vérification automatiques, port '+str(args.tor_port)+') ? [' + ('O/n' if args.tor else 'o/N') + '] : ').strip().lower()
                if choice:
                    args.tor = choice in ('o', 'oui', 'y', 'yes')
            if not prior and not explicit_profile:
                choice = input('Profil rapide / standard / approfondi [' + args.profile + '] : ').strip().lower()
                normalized = normalize_profile_choice(choice, args.profile)
                if choice and normalized != choice:
                    print('Profil interprété comme : ' + normalized)
                args.profile = normalized
            if not interactive_target.startswith('router-'):
                args.sql = True
        except (EOFError, KeyboardInterrupt):
            print('\nLancement annulé.')
            return 1
    if not args.url or not args.authorized:
        parser.error('URL et autorisation requises')
    if args.profile not in PROFILES:
        parser.error('Profil inconnu')
    if args.target_profile not in TARGET_PROFILES:
        parser.error('Type de cible inconnu')
    preliminary_target_profile = effective_profile(args.url, requested=args.target_profile)
    if preliminary_target_profile.startswith('router-'):
        if not private_target(args.url):
            parser.error('Profil routeur limité aux cibles locales résolues en adresse privée')
        if args.tor or args.proxy:
            parser.error('Profil routeur incompatible avec Tor ou un proxy : utiliser la connexion LAN directe')
        if args.sql or args.sql_url or args.sqlmap_url or args.wpscan:
            parser.error('Profil routeur incompatible avec SQL, sqlmap et WPScan')
        if args.nuclei_safe or args.auth_token_env or args.auth_cookie_env:
            parser.error('Profil routeur incompatible avec Nuclei et les sessions web authentifiées')
    elif args.router_services:
        parser.error('--router-services exige un profil routeur local')
    if args.tor and args.proxy:
        parser.error('Choisir --tor ou --proxy')
    proxy = f'socks5h://127.0.0.1:{args.tor_port}' if args.tor else args.proxy
    if proxy:
        try:
            p = urlsplit(proxy)
            valid = p.scheme == 'socks5h' and p.hostname and p.port and not p.username and not p.password
        except ValueError:
            valid = False
        if not valid:
            parser.error('Proxy socks5h://hôte:port sans identifiants requis')
    for key, default in PROFILES[args.profile].items():
        if getattr(args, key) is None:
            setattr(args, key, saved.get(key, default) if args.profile == saved.get('profile') else default)
    for key in ('tls', 'updates'):
        if getattr(args, key) is None:
            setattr(args, key, args.profile != 'rapide')
    if preliminary_target_profile.startswith('router-'):
        args.max_pages = min(args.max_pages, 1)
        args.max_requests = min(args.max_requests, 16)
        args.delay = max(args.delay, .5)
        args.timeout = min(args.timeout, 10)
        args.budget = min(args.budget, 120)
        args.updates = False
    try:
        valid = (1 <= args.max_pages <= 20 and 1 <= args.max_requests <= 200 and .2 <= args.delay <= 30 and 1 <= args.timeout <= 60 and 1 <= args.budget <= 1800 and 1 <= args.wpscan_timeout <= 900 and 1 <= args.sqlmap_timeout <= 900)
    except TypeError:
        valid = False
    if not valid:
        parser.error('Budgets invalides : pages 1–20, requêtes 1–200, délai 0.2–30, timeout 1–60, budget 1–1800, outils 1–900')
    if args.tor:
        if not explicit_timeout:
            args.timeout = max(args.timeout, 30)
        if not explicit_budget:
            args.budget = max(args.budget, 180)
    if len(args.sql_url) > 3:
        parser.error('Au plus 3 --sql-url')
    selected_params = [v.strip() for v in (args.sql_parameters or '').split(',') if v.strip()]
    if any(v not in SAFE_PARAMS for v in selected_params):
        parser.error('Paramètres SQL hors liste de lecture autorisée')
    try:
        rules = load_rules(args.rules_dir, args.rules_public_key)
        roles = parse_roles(args.auth_token_env, args.auth_cookie_env)
        scanner = Scanner(args.url, proxy=proxy, delay=args.delay, timeout=args.timeout, max_requests=args.max_requests, max_pages=args.max_pages, budget=args.budget, rules=rules)
        if prior:
            if clean_url(args.url) not in (prior.get('requested_target'), prior['target']):
                raise ValueError('Reprise refusée : URL différente du checkpoint')
            if args.profile != prior_settings.get('profile', args.profile):
                raise ValueError('Conserver le profil du checkpoint ; augmenter seulement les budgets si nécessaire')
            if args.target_profile != prior_settings.get('target_profile', args.target_profile):
                raise ValueError('Conserver le profil technologique du checkpoint')
            requested = prior.get('requested_target', prior['target'])
            if origin(prior['target']) != origin(requested) and not canonical_redirect(requested, prior['target']):
                raise ValueError('Checkpoint : cible canonique hors du périmètre initial')
            scanner.report = prior
            scanner.url = prior['target']
            scanner.scope = origin(scanner.url)
            scanner.report.setdefault('resume_history', []).append({'at_utc': datetime.now(timezone.utc).isoformat(), 'previous_status': prior.get('status'), 'previous_finished_utc': prior.pop('finished_utc', None)})
            scanner.report['limitations'] = [x for x in prior.get('limitations', []) if not x.startswith('Arrêt :')]
            for request in scanner.report['requests']:
                request['historical'] = True
            scanner.report.setdefault('cookies', [])
            scanner.report.setdefault('cms_versions', {})
        for url in args.sql_url + ([args.sqlmap_url] if args.sqlmap_url else []):
            pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
            if not scanner.in_scope(url) or not pairs or not all(k in SAFE_PARAMS for k, _ in pairs) or re.search(r'logout|delete|remove|admin|login|cart|checkout', urlsplit(url).path, re.I):
                raise ValueError('URL SQL : même origine et paramètres publics de lecture uniquement')
        if args.save_config:
            save_preferences(args.config, args)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    output = args.output or (args.resume.parent if args.resume else args.reports_root/(scanner.scope[1] + '-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')))
    if output.exists() and any(output.iterdir()) and not args.resume:
        parser.error('Dossier de sortie non vide : choisir un nouveau dossier')
    if args.resume and output.resolve() != args.resume.parent.resolve():
        parser.error('La reprise utilise le dossier du checkpoint')
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    completed = set(state.get('completed', [])) if state else set()
    if state and (args.sql_url != prior_settings.get('sql_url', []) or args.sql_parameters != prior_settings.get('sql_parameters')):
        completed.discard('sql')
        completed.discard('sqlmap')
    if state and args.sqlmap_url != prior_settings.get('sqlmap_url'):
        completed.discard('sqlmap')
    scanner.report['configuration'].update({'profile': args.profile, 'target_profile_requested': args.target_profile,
        'target_profile_effective': preliminary_target_profile, 'max_pages': args.max_pages,
        'max_requests': args.max_requests, 'budget_seconds': args.budget,
        'tls_budget': '2 connexions TLS maximum', 'reference_budget': '12 requêtes / 45 secondes maximum',
        'adaptive_planner': True, 'rule_count': len(rules), 'signed_manifest_requested': bool(args.signing_key)})
    scanner.report['run_settings'] = {key: getattr(args, key) for key in ('profile', 'target_profile', 'tor', 'tor_port', 'proxy', 'tls', 'updates', 'sql', 'wpscan', 'sql_url', 'sqlmap_url', 'sql_parameters')}
    scanner.report['run_settings']['effective_target_profile'] = preliminary_target_profile
    scanner.report['asset_profile'] = {'requested': args.target_profile, 'effective': preliminary_target_profile,
        'kind': 'routeur' if preliminary_target_profile.startswith('router-') else 'web'}
    scanner.report.setdefault('metadata', {}).update({k: v for k, v in [('organization', args.organization), ('owner', args.owner)] if v})
    scanner.report.setdefault('business_context', {}).update({k: v for k, v in [('owner', args.business_owner), ('criticality', args.criticality), ('data_sensitivity', args.data_sensitivity)] if v})
    scanner.report['status'] = 'en cours'
    planner = AdaptivePlanner(scanner.report)
    scanner.checkpoint_callback = lambda: checkpoint(output, scanner.report, completed)
    def stage(name, action, tool=None, reason='Contrôle applicable au profil et demandé par l’opérateur'):
        if name in completed:
            planner.decide(name, False, 'Résultat conservé depuis le checkpoint')
            print('Étape déjà terminée, conservée :', name, flush=True)
            return
        stop = planner.stop_reason()
        if stop and name != 'crawl':
            planner.decide(name, False, stop)
            scanner.report['limitations'].append(stop)
            return
        planner.decide(name, True, reason)
        print('Étape :', name, flush=True)
        action()
        if not tool or scanner.report['tools'].get(tool, {}).get('status', '').startswith(('terminé', 'non applicable')):
            completed.add(name)
        scanner.checkpoint_callback()
    try:
        print('Audit :', scanner.url, '· intensité', args.profile, '· cible', preliminary_target_profile, flush=True)
        print('Transport :', 'proxy SOCKS sans repli direct' if proxy else 'connexion directe', flush=True)
        if proxy:
            if args.tor:
                print('Préparation et validation de Tor avant toute requête cible…', flush=True)
                scanner.report['tools']['tor_route'] = ensure_tor(args.tor_port, args.tor_wait)
                scanner.report['proxy'] = 'Tor vérifié via SOCKS5 avec DNS distant'
                # Le démarrage Tor ne consomme pas le budget réservé à l’audit.
                scanner.deadline = time.monotonic() + args.budget
            print('Vérification SOCKS avant contact de la cible…', flush=True)
            scanner.report['tools']['proxy_preflight'] = proxy_preflight(proxy)
        stage('crawl', scanner.crawl)
        for key in ('sql_url', 'sqlmap_url'):
            urls = args.sql_url if key == 'sql_url' else ([args.sqlmap_url] if args.sqlmap_url else [])
            for index, url in enumerate(urls):
                if not scanner.in_scope(url):
                    p, target = urlsplit(url), urlsplit(scanner.url)
                    if not canonical_redirect(url, scanner.url):
                        raise ValueError('URL SQL hors périmètre après redirection')
                    urls[index] = urlunsplit((target.scheme, target.netloc, p.path, p.query, ''))
            if key == 'sqlmap_url' and urls:
                args.sqlmap_url = urls[0]
        if scanner.report.get('requested_target') != scanner.url:
            print('Adresse canonique :', scanner.url, flush=True)
        names = sorted({c['name'] for c in scanner.report['cms']})
        print('CMS détecté (indices) :', ', '.join(names) or 'non déterminé', flush=True)
        target_profile = effective_profile(scanner.url, names, args.target_profile)
        scanner.report['asset_profile'].update({'effective': target_profile,
            'kind': 'routeur' if target_profile.startswith('router-') else 'web'})
        scanner.report['configuration']['target_profile_effective'] = target_profile
        scanner.report['run_settings']['effective_target_profile'] = target_profile
        if target_profile.startswith('router-'):
            print('Profil routeur local :', target_profile, flush=True)
            stage('router', lambda: run_router_checks(scanner, target_profile, scanner.rules), 'router_profile', 'Règles GET du constructeur sélectionné')
            scanner.report['tools']['wordpress_checks'] = {'status': 'non applicable : profil routeur'}
            if args.router_services:
                stage('router_services', lambda: scanner.report['tools'].update({'router_services': inventory_router_services(scanner.url)}), 'router_services', 'Inventaire TCP local explicitement demandé')
            else:
                planner.decide('router_services', False, 'Option --router-services non demandée')
        else:
            checked_names = list(names)
            forced = {'wordpress': 'WordPress', 'joomla': 'Joomla'}.get(target_profile)
            if forced and forced not in checked_names:
                checked_names.append(forced)
                scanner.report['limitations'].append('Profil ' + target_profile + ' forcé par l’opérateur ; la signature passive du CMS n’a pas été confirmée.')
            stage('cms', lambda: scanner.cms_checks(checked_names))
            names = checked_names
        if not target_profile.startswith('router-') and (args.sql or args.sql_url):
            synthetic_pages = [{'url': scanner.url, 'body': ''.join('<a href="' + html.escape(u, quote=True) + '">point de lecture</a>' for u in scanner.report.get('sql_candidates', []))}]
            stage('sql', lambda: scanner.sql_checks(synthetic_pages, args.sql_url, selected_params))
        else:
            scanner.report['tools']['sql_probes'] = {'status': 'non applicable : profil routeur' if target_profile.startswith('router-') else 'non demandé'}
        if args.tls:
            stage('tls', lambda: scanner.report['tools'].update({'tls': tls_inventory(scanner.url, proxy, min(args.timeout, 10))}), 'tls')
        else:
            scanner.report['tools']['tls'] = {'status': 'non demandé pour ce profil'}
        if args.updates:
            stage('references', lambda: scanner.report['tools'].update({'references': VendorReferences(scanner.session, min(args.timeout, 10)).collect(scanner.report)}), 'references')
        else:
            scanner.report['tools']['references'] = {'status': 'non demandé pour ce profil'}
        if args.interactive and 'WordPress' in names and shutil.which('wpscan'):
            args.wpscan = True
            scanner.report['run_settings']['wpscan'] = True
        if args.wpscan and 'WordPress' in names:
            stage('wpscan', lambda: scanner.wpscan(output, args.wpscan_timeout), 'wpscan')
        elif args.wpscan:
            scanner.report['tools']['wpscan'] = {'status': 'non applicable : aucune signature WordPress'}
        if args.sqlmap_url:
            stage('sqlmap', lambda: scanner.sqlmap(args.sqlmap_url, output, args.sqlmap_timeout, selected_params), 'sqlmap')
        if roles:
            stage('authenticated_matrix', lambda: scanner.report['tools'].update({'authenticated_matrix': authenticated_matrix(scanner, roles, args.auth_url)}), 'authenticated_matrix', 'Rôles fournis par variables d’environnement')
        else:
            planner.decide('authenticated_matrix', False, 'Aucun rôle authentifié fourni')
        if args.nuclei_safe:
            def nuclei_stage():
                data = run_nuclei(scanner.url, output, args.nuclei_timeout)
                scanner.report['tools']['nuclei_safe'] = data
                for item in data.get('findings', []):
                    text = 'Modèle signé ' + str(item.get('template_id')) + ' ; correspondance : ' + str(item.get('matcher'))
                    cves = re.findall(r'CVE-\d{4}-\d{4,}', str(item.get('template_id', '')), re.I)
                    scanner.finding({'critical':'Critique','high':'Haute','medium':'Moyenne','low':'Faible'}.get(str(item.get('severity')).lower(),'Info'),
                                    'Nuclei : ' + str(item.get('name') or item.get('template_id')), text,
                                    'Confirmer manuellement la correspondance et la version avant traitement.', scanner.url,
                                    'signalement de modèle signé à confirmer')
                    scanner.report['findings'][-1]['cves'] = [c.upper() for c in cves]
            stage('nuclei_safe', nuclei_stage, 'nuclei_safe', 'Option Nuclei sûre explicitement demandée')
        else:
            planner.decide('nuclei_safe', False, 'Option --nuclei-safe non demandée')
        use_intel = args.threat_intel if args.threat_intel is not None else args.updates
        if use_intel:
            stage('threat_intel', lambda: scanner.report['tools'].update({'threat_intel': enrich_cves(scanner.report, proxy, min(args.timeout, 10))}), 'threat_intel', 'Corrélation KEV/EPSS des seules CVE fournies par une source')
        else:
            planner.decide('threat_intel', False, 'Corrélation externe non demandée')
        errors = any(r.get('error') and not r.get('historical') for r in scanner.report['requests'])
        incomplete = any(any(word in data.get('status', '').lower() for word in ('échec', 'incomplet', 'indisponible', 'partiel')) for data in scanner.report['tools'].values())
        scanner.report['status'] = 'incomplet' if errors or incomplete else 'terminé (couverture limitée)'
    except (requests.RequestException, OSError, ValueError, RuntimeError, KeyboardInterrupt) as exc:
        scanner.report['status'] = 'incomplet'
        scanner.report['limitations'].append('Arrêt : ' + str(exc))
        if proxy and 'proxy_preflight' not in scanner.report['tools']:
            scanner.report['tools']['proxy_preflight'] = {'status': 'échec', 'detail': str(exc)}
    for name, requested in [('wpscan', args.wpscan), ('sqlmap', args.sqlmap_url), ('sql_probes', args.sql)]:
        if requested and name not in scanner.report['tools']:
            scanner.report['tools'][name] = {'status': 'non exécuté : audit interrompu'}
    try:
        if args.compare:
            scanner.report['comparison'] = compare_reports(scanner.report, read_json(args.compare))
        if args.plan:
            scanner.report['treatment_updates'] = read_json(args.plan)
    except (OSError, ValueError) as exc:
        scanner.report['limitations'].append('Comparaison/plan non appliqué : ' + str(exc))
    scanner.report['finished_utc'] = datetime.now(timezone.utc).isoformat()
    if args.ai_provider != 'none':
        scanner.report['tools']['ai_advisor'] = ai_advice(scanner.report, args.ai_provider, args.ai_model)
    else:
        planner.decide('ai_advisor', False, 'IA facultative non demandée ; aucune donnée transmise')
    scanner.checkpoint_callback()
    try:
        write_report(scanner.report, output, signing_key=args.signing_key)
    except (OSError, ValueError, TypeError) as exc:
        print('Échec de génération/signature du rapport :', exc)
        return 1
    print('Rapport HTML :', (output/'report.html').resolve())
    print('Synthèse direction, PDF, CSV et manifest SHA-256 :', output.resolve())
    if args.auto_prune and output.parent.resolve() == args.reports_root.resolve():
        try:
            removed = prune_reports(args.reports_root, args.keep_reports, {output.name})
            if removed:
                print('Rétention : rapports supprimés :', ', '.join(removed))
        except (OSError, ValueError) as exc:
            print('Rétention non appliquée :', exc)
    if scanner.report['status'] == 'incomplet':
        print('Audit partiel. Reprise : ./lancer.sh --resume', output/'checkpoint.json')
    return 0 if scanner.report['status'] != 'incomplet' else 1

if __name__ == '__main__':
    raise SystemExit(main())
