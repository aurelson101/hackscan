"""Préférences sans secrets, reprise par étape, comparaison et intégrité."""
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

PROFILES = {
    'rapide': dict(max_pages=2, max_requests=25, delay=1, timeout=10, budget=90, wpscan_timeout=45, sqlmap_timeout=60),
    'standard': dict(max_pages=5, max_requests=60, delay=1, timeout=12, budget=300, wpscan_timeout=120, sqlmap_timeout=120),
    'approfondi': dict(max_pages=15, max_requests=150, delay=1.5, timeout=15, budget=600, wpscan_timeout=240, sqlmap_timeout=240),
}
PREFERENCE_KEYS = {'profile', 'target_profile', 'tor', 'tor_port', 'max_pages', 'max_requests', 'delay', 'timeout', 'budget', 'wpscan_timeout', 'sqlmap_timeout'}


def private_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + '.tmp')
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
    temporary.chmod(0o600)
    os.replace(temporary, path)


def read_json(path):
    path = Path(path)
    if path.stat().st_size > 20 * 1024 * 1024:
        raise ValueError('Fichier JSON trop volumineux')
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ValueError('Objet JSON requis')
    return data


def preferences(path):
    data = read_json(path) if Path(path).exists() else {}
    return {k: v for k, v in data.items() if k in PREFERENCE_KEYS}


def save_preferences(path, args):
    private_json(path, {k: getattr(args, k) for k in PREFERENCE_KEYS if hasattr(args, k)})


def checkpoint(output, report, completed):
    private_json(Path(output) / 'checkpoint.json', {'schema': 1, 'report': report, 'completed': sorted(completed)})


def fingerprint(finding):
    p = urlsplit(finding.get('url', ''))
    # Les valeurs de requête et les marqueurs SQL ne doivent pas créer des faux nouveaux constats.
    identity = [finding.get('title'), finding.get('component'), p.hostname, p.path]
    return hashlib.sha256(json.dumps(identity, ensure_ascii=False).encode()).hexdigest()[:20]


def compare_reports(current, previous):
    if urlsplit(current['target']).hostname.removeprefix('www.') != urlsplit(previous['target']).hostname.removeprefix('www.'):
        raise ValueError('Comparaison refusée : cibles différentes')
    before = {fingerprint(f): f for f in previous.get('findings', [])}
    after = {fingerprint(f): f for f in current.get('findings', [])}
    complete = 'incomplet' not in current.get('status', '').lower()
    return {
        'previous_started_utc': previous.get('started_utc'),
        'new': [after[k] for k in after.keys() - before.keys()],
        'persistent': [after[k] for k in after.keys() & before.keys()],
        'not_observed': [before[k] for k in before.keys() - after.keys()],
        'regressions': [after[k] for k in after.keys() & before.keys() if
                        {'Info': 0, 'Faible': 1, 'Moyenne': 2, 'Haute': 3, 'Critique': 4}.get(after[k].get('severity'), 0) >
                        {'Info': 0, 'Faible': 1, 'Moyenne': 2, 'Haute': 3, 'Critique': 4}.get(before[k].get('severity'), 0)],
        'conclusion': 'Un constat non observé doit être recontrôlé avant clôture ; aucune correction automatique déduite.' if complete else
                      'Audit actuel partiel : les constats non observés restent inconnus, aucune correction déduite.',
    }


def manifest(output):
    output = Path(output)
    files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(output.iterdir())
             if p.is_file() and p.name != 'manifest.sha256' and p.suffix in ('.html', '.json', '.csv', '.pdf')}
    path = output / 'manifest.sha256'
    path.write_text(''.join(value + '  ' + name + '\n' for name, value in files.items()), encoding='utf-8')
    path.chmod(0o600)
    return files


def safe_query(url, parameters):
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, parameters, ''))
