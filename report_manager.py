"""Inventaire, suppression explicite et rétention sûre des rapports Hackscan."""
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil

MAX_REPORT_JSON = 20 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024


def _integer(value):
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _clean(value):
    return ''.join(character if character.isprintable() else ' ' for character in str(value)).strip()


def _folder_size(path):
    total = 0
    for base, directories, files in os.walk(path, followlinks=False):
        directories[:] = [name for name in directories if not (Path(base) / name).is_symlink()]
        for name in files:
            candidate = Path(base) / name
            if not candidate.is_symlink():
                try:
                    total += candidate.stat().st_size
                except OSError:
                    pass
    return total


def _integrity(child, report_bytes):
    manifest = child / 'manifest.sha256'
    if manifest.is_symlink() or not manifest.is_file():
        return 'absent'
    try:
        if manifest.stat().st_size > MAX_MANIFEST:
            return 'invalide'
        expected = next((line.split()[0] for line in manifest.read_text(encoding='utf-8').splitlines()
                         if len(line.split()) >= 2 and line.split()[-1] == 'report.json'), None)
        return 'valide' if expected == hashlib.sha256(report_bytes).hexdigest() else 'invalide'
    except (OSError, UnicodeError):
        return 'invalide'


def _age_days(started, mtime):
    try:
        instant = datetime.fromisoformat(str(started).replace('Z', '+00:00'))
        if instant.tzinfo is None:
            instant = instant.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - instant.astimezone(timezone.utc)).days)
    except (TypeError, ValueError):
        return max(0, int((datetime.now(timezone.utc).timestamp() - mtime) // 86400))


def _root(path):
    root = Path(path)
    if root.is_symlink():
        raise ValueError('Le dossier de rapports ne peut pas être un lien symbolique')
    return root.resolve()


def _metadata(child):
    if child.is_symlink() or not child.is_dir():
        return None
    report_file = child / 'report.json'
    if report_file.is_symlink() or not report_file.is_file() or report_file.stat().st_size > MAX_REPORT_JSON:
        return None
    try:
        report_bytes = report_file.read_bytes()
        report = json.loads(report_bytes.decode('utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(report, dict) or not isinstance(report.get('target'), str):
        return None
    summary = report.get('summary') if isinstance(report.get('summary'), dict) else {}
    counts = summary.get('severity_counts') if isinstance(summary.get('severity_counts'), dict) else {}
    findings = report.get('findings') if isinstance(report.get('findings'), list) else []
    severity_order = ('Critique', 'Haute', 'Moyenne', 'Faible', 'Info')
    priorities = {key: _integer(counts.get(key)) for key in severity_order}
    if not any(priorities.values()):
        for finding in findings:
            severity = finding.get('severity') if isinstance(finding, dict) else None
            if severity in priorities:
                priorities[severity] += 1
    top = next((key for key in severity_order if priorities[key]), 'Aucune')
    mtime = report_file.stat().st_mtime
    return {'name': child.name, 'path': child, 'target': _clean(report['target']),
            'started_utc': _clean(report.get('started_utc', '')), 'status': _clean(report.get('status', 'inconnu')),
            'age_days': _age_days(report.get('started_utc'), mtime), 'size_bytes': _folder_size(child),
            'finding_count': _integer(summary.get('finding_count', len(findings))),
            'obstacle_count': _integer(summary.get('obstacle_count', 0)),
            'priorities': priorities, 'top_priority': top, 'integrity': _integrity(child, report_bytes), 'mtime': mtime}


def list_reports(path, target=None, status=None):
    root = _root(path)
    if not root.exists():
        return []
    reports = filter(None, (_metadata(p) for p in root.iterdir()))
    if target:
        reports = (item for item in reports if target.casefold() in item['target'].casefold())
    if status:
        reports = (item for item in reports if status.casefold() in item['status'].casefold())
    return sorted(reports, key=lambda item: (item['started_utc'], item['mtime']), reverse=True)


def _size(value):
    for unit in ('o', 'Kio', 'Mio', 'Gio'):
        if value < 1024 or unit == 'Gio':
            return f'{value:.0f}{unit}' if unit == 'o' else f'{value:.1f}{unit}'
        value /= 1024


def format_report_list(reports):
    lines = []
    for index, report in enumerate(reports, 1):
        p = report['priorities']
        date = report['started_utc'][:10] or 'date inconnue'
        lines.append(f"{index:>2}. {report['name']} | {date} ({report['age_days']} j) | {report['status']} | "
                     f"priorité {report['top_priority']} C/H/M/F/I={p['Critique']}/{p['Haute']}/{p['Moyenne']}/{p['Faible']}/{p['Info']} | "
                     f"constats={report['finding_count']} obstacles={report['obstacle_count']} | "
                     f"{_size(report['size_bytes'])} | intégrité={report['integrity']} | {report['target']}")
    return '\n'.join(lines) if lines else 'Aucun rapport valide.'


def export_report_list(reports, output_format='text'):
    if output_format == 'text':
        return format_report_list(reports)
    fields = ('name', 'started_utc', 'age_days', 'status', 'target', 'top_priority',
              'finding_count', 'obstacle_count', 'size_bytes', 'integrity')
    rows = [{key: report[key] for key in fields} for report in reports]
    if output_format == 'json':
        return json.dumps(rows, ensure_ascii=False, indent=2)
    if output_format == 'csv':
        stream = io.StringIO()
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader(); writer.writerows(rows)
        return stream.getvalue().rstrip()
    raise ValueError('Format d’export inconnu')


def preview_prune(path, keep=10):
    if not 1 <= keep <= 100:
        raise ValueError('La rétention doit être comprise entre 1 et 100')
    return [report['name'] for report in list_reports(path)[keep:]]


def delete_reports(path, names):
    root = _root(path)
    valid = {item['name']: item for item in list_reports(root)}
    removed = []
    for name in names:
        if not isinstance(name, str) or Path(name).name != name or name not in valid:
            raise ValueError('Rapport inconnu ou nom non sûr : ' + str(name))
        target = valid[name]['path']
        if target.parent.resolve() != root or target.is_symlink():
            raise ValueError('Suppression hors périmètre refusée')
        shutil.rmtree(target)
        removed.append(name)
    return removed


def prune_reports(path, keep=10, exclude=()):
    if not 1 <= keep <= 100:
        raise ValueError('La rétention doit être comprise entre 1 et 100')
    excluded = set(exclude)
    return delete_reports(path, [name for name in preview_prune(path, keep) if name not in excluded])


def parse_selection(value, count):
    selected = set()
    for token in (part.strip() for part in value.split(',')):
        if not token:
            continue
        bounds = token.split('-', 1)
        try:
            start, end = int(bounds[0]), int(bounds[-1])
        except ValueError as exc:
            raise ValueError('Sélection invalide') from exc
        if start > end or start < 1 or end > count:
            raise ValueError('Sélection hors liste')
        selected.update(range(start, end + 1))
    return sorted(selected)


def manage_reports(path, input_fn=input, display=True):
    reports = list_reports(path)
    if display:
        print(format_report_list(reports))
    if not reports:
        return []
    indexes = parse_selection(input_fn('Numéros à supprimer (ex. 2,4-6 ; vide = annuler) : ').strip(), len(reports))
    if not indexes:
        return []
    names = [reports[index - 1]['name'] for index in indexes]
    print('Suppression prévue : ' + ', '.join(names))
    if input_fn('Saisir SUPPRIMER pour confirmer : ').strip() != 'SUPPRIMER':
        return []
    return delete_reports(path, names)
