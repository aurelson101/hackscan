"""Adaptateur Nuclei explicite : modèles signés, HTTP, faible débit, sans OAST/fuzz/code."""
import json
from pathlib import Path
import shutil
import subprocess
from urllib.parse import urlsplit, urlunsplit


def run_nuclei(target, output, timeout=120):
    binary = shutil.which('nuclei')
    if not binary:
        return {'status': 'indisponible', 'detail': 'Binaire nuclei absent ; aucun repli ni téléchargement automatique.'}
    path = Path(output) / 'nuclei-safe.jsonl'
    cmd = [binary, '-u', target, '-silent', '-jsonl', '-o', str(path), '-duc', '-dut', '-ni',
           '-pt', 'http', '-rl', '2', '-c', '1', '-bs', '1', '-timeout', '8', '-retries', '0',
           '-fhr', '-mr', '3', '-etags', 'fuzz,dos,bruteforce,headless,code', '-no-color']
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        rows = []
        if path.exists():
            for line in path.read_text(encoding='utf-8', errors='replace').splitlines()[:500]:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                info = item.get('info') or {}
                matched = urlsplit(str(item.get('matched-at') or ''))
                matched_at = urlunsplit((matched.scheme, matched.netloc, matched.path, '', '')) if matched.scheme in ('http', 'https') else ''
                rows.append({'template_id': item.get('template-id'), 'name': info.get('name'),
                             'severity': info.get('severity'), 'matched_at': item.get('matched-at'),
                             'matcher': item.get('matcher-name')})
                rows[-1]['matched_at'] = matched_at
            path.write_text('\n'.join(json.dumps(row, ensure_ascii=False) for row in rows) + ('\n' if rows else ''), encoding='utf-8')
            path.chmod(0o600)
        status = 'terminé' if proc.returncode == 0 else 'échec'
        return {'status': status, 'findings': rows, 'count': len(rows),
                'policy': 'modèles signés seulement ; HTTP ; 2 req/s ; concurrence 1 ; OAST, fuzz, code et brute force exclus',
                'detail': (proc.stderr or proc.stdout)[-1200:]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'status': 'incomplet', 'detail': str(exc)}

