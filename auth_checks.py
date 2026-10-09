"""Comparaison GET anonyme/authentifiée, secrets fournis uniquement par variables d'environnement."""
import hashlib
import os
import time
from urllib.parse import urlsplit

import requests


def parse_roles(token_specs, cookie_specs):
    roles = {}
    for kind, specs in [('token', token_specs), ('cookie', cookie_specs)]:
        for spec in specs:
            if '=' not in spec:
                raise ValueError('Rôle attendu sous la forme role=VARIABLE_ENV')
            role, variable = spec.split('=', 1)
            if not role or not variable or not role.replace('-', '').replace('_', '').isalnum():
                raise ValueError('Rôle ou variable invalide')
            value = os.environ.get(variable)
            if not value:
                raise ValueError('Variable secrète absente pour le rôle ' + role)
            roles.setdefault(role, {})[kind] = value
    return roles


def authenticated_matrix(scanner, roles, urls):
    targets = list(dict.fromkeys(urls or [scanner.url]))[:5]
    if len(roles) > 3:
        raise ValueError('Trois rôles authentifiés maximum')
    for url in targets:
        if not scanner.in_scope(url) or urlsplit(url).query:
            raise ValueError('URL authentifiée : même origine et sans paramètres requise')
    rows, last = [], 0.0
    for url in targets:
        evidence = next((row for row in reversed(scanner.report.get('requests', [])) if row.get('url') == url and not row.get('historical')), None)
        rows.append({'role': 'anonymous', 'url': url, 'status': evidence.get('status') if evidence else 'inconnu',
                     'sha256': evidence.get('sha256') if evidence else None, 'bytes': evidence.get('bytes') if evidence else None,
                     'secret_retained': False, 'qualification': 'mesure existante' if evidence else 'baseline anonyme non collectée'})
    for role, secret in roles.items():
        session = requests.Session(); session.trust_env = False; session.proxies.update(scanner.session.proxies)
        session.headers['User-Agent'] = scanner.session.headers['User-Agent']
        if secret.get('token'):
            session.headers['Authorization'] = 'Bearer ' + secret['token']
        if secret.get('cookie'):
            session.headers['Cookie'] = secret['cookie']
        for url in targets:
            time.sleep(max(0, scanner.delay - (time.monotonic() - last)))
            last = time.monotonic()
            started = time.monotonic()
            try:
                with session.get(url, timeout=min(scanner.timeout, 10), allow_redirects=False, stream=True) as response:
                    body = response.raw.read(256 * 1024 + 1, decode_content=True)
                    if len(body) > 256 * 1024:
                        raise RuntimeError('Réponse authentifiée trop volumineuse')
                    rows.append({'role': role, 'url': url, 'status': response.status_code,
                                 'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body),
                                 'duration_ms': round((time.monotonic()-started)*1000),
                                 'secret_retained': False})
            except (requests.RequestException, RuntimeError) as exc:
                rows.append({'role': role, 'url': url, 'status': 'inconnu', 'error': str(exc), 'secret_retained': False})
    return {'status': 'terminé' if rows and not any(r.get('error') for r in rows) else 'partiel',
            'roles': ['anonymous', *sorted(roles)], 'comparisons': rows,
            'qualification': 'Différence de statut ou d’empreinte à examiner humainement ; aucun contournement déduit automatiquement.'}

