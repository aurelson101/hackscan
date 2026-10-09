"""Planification adaptative explicable et coupe-circuits de l'audit."""
from datetime import datetime, timezone


class AdaptivePlanner:
    def __init__(self, report):
        self.report = report
        self.rows = report.setdefault('adaptive_plan', [])

    def decide(self, stage, enabled, reason, risk='passif'):
        row = {'stage': stage, 'decision': 'exécuter' if enabled else 'ignorer',
               'reason': reason, 'risk': risk, 'at_utc': datetime.now(timezone.utc).isoformat()}
        self.rows.append(row)
        return enabled

    def stop_reason(self):
        current = [r for r in self.report.get('requests', []) if not r.get('historical')]
        if any(r.get('status') == 429 for r in current):
            return 'HTTP 429 observé : coupe-circuit de limitation de débit.'
        recent = current[-3:]
        if len(recent) == 3 and all(r.get('error') for r in recent):
            return 'Trois erreurs réseau consécutives : coupe-circuit.'
        return None

