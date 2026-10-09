"""Présentation RSSI/CISO fondée sur les seules observations du scanner."""
from collections import Counter
from datetime import datetime, timedelta, timezone
import html
import json
from pathlib import Path
from urllib.parse import urlsplit
from workflow import fingerprint, manifest
from exports import export_files, extra_html, filters_html
from intelligence import analyze
from report_v4 import intelligence_html, intelligence_assets
from presentation import styles, executive_body, report_actions, navigation_script
from evidence_signing import sign_manifest


def escape(value):
    return html.escape(str(value), quote=True)


def table(headers, rows):
    head = ''.join('<th scope="col">' + escape(x) + '</th>' for x in headers)
    body = ''.join('<tr>' + ''.join('<td>' + escape(x) + '</td>' for x in row) + '</tr>' for row in rows)
    return '<div class="table"><table><thead><tr>' + head + '</tr></thead><tbody>' + (body or '<tr><td colspan="' + str(len(headers)) + '">Aucune observation enregistrée dans ce périmètre.</td></tr>') + '</tbody></table></div>'


def obstacle(detail, proxy=False):
    text = str(detail)
    lower = text.lower()
    if 'redirection hors périmètre' in lower:
        return ('Redirection vers une origine non autorisée', 'Le scan s’arrête avant de contacter cette origine.',
                'Vérifier l’URL canonique. Les seuls alias initiaux autorisés automatiquement sont le même hôte et son alias www en HTTPS.')
    if '403' in lower or 'waf' in lower:
        return ('Accès refusé / filtrage possible', 'Une réponse 403 ou une heuristique WAF limite les observations ; la présence effective d’un WAF reste à confirmer.',
                'Avec l’hébergeur, prévoir une fenêtre d’audit et une IP source autorisée, ou reproduire sur staging. Ne pas interpréter le blocage comme une preuve de sécurité.')
    if '429' in lower:
        return ('Limitation de débit', 'Le scanner a arrêté les requêtes pour respecter le serveur.', 'Planifier un nouveau passage avec un délai plus élevé et un périmètre réduit.')
    if 'database file is missing' in lower or 'update required' in lower:
        return ('Base locale WPScan manquante', 'L’inventaire spécialisé et la corrélation WPScan n’ont pas été exécutés.', 'Exécuter ./install.sh --wpscan puis relancer l’analyse autorisée.')
    if 'quota' in lower or 'limit exceeded' in lower or 'api token' in lower or 'invalid token' in lower:
        return ('Accès API WPScan / quota', 'La corrélation de vulnérabilités reste inconnue.', 'Vérifier le jeton via WPSCAN_API_TOKEN et le quota, sans enregistrer le secret dans le rapport.')
    if 'certificate' in lower or 'sslerror' in lower:
        return ('Validation TLS en échec', 'La connexion sécurisée n’a pas été acceptée ; aucun verdict sur l’application.', 'Vérifier le certificat, la chaîne et l’horloge sans désactiver la validation TLS.')
    if 'timeout' in lower or 'timed out' in lower or 'expiration' in lower or 'budget' in lower or 'incomplet' in lower:
        return ('Délai ou budget atteint' + (' via proxy SOCKS' if proxy else ''),
                'Les tests restants ne sont pas couverts. Aucun repli direct n’est effectué en mode proxy.',
                'Vérifier le démarrage et le bootstrap Tor, le port SOCKS et la connectivité de sortie.' if proxy else 'Planifier un test ciblé avec un budget adapté ; conserver les résultats partiels.')
    if 'refused' in lower or 'proxy' in lower or 'socks' in lower:
        return ('Proxy ou connexion indisponible', 'La cible peut ne pas avoir été contactée.', 'Vérifier le proxy SOCKS et son port. Si une connexion directe est souhaitée, relancer explicitement sans Tor.')
    if 'reset' in lower or 'connection aborted' in lower:
        return ('Connexion interrompue', 'Cet endpoint n’a pas pu être vérifié ; cause réseau ou filtrage non confirmée.', 'Vérifier les journaux de l’hébergeur, puis recontrôler cet endpoint dans la fenêtre d’audit.')
    return ('Contrôle non abouti', 'La couverture correspondante reste inconnue.', 'Examiner les éléments techniques en annexe et replanifier ce contrôle.')


def finding_context(finding):
    title = finding.get('title', '').lower()
    if 'routeur' in title or 'api réseau' in title:
        return {'impact': 'Divulgation d’informations de topologie locale facilitant la reconnaissance et la préparation d’attaques latérales ; aucun accès administrateur démontré.',
                'condition': 'Accès préalable au LAN/Wi-Fi et réponse reproductible sans session ; confirmer l’isolation des réseaux invité et IoT.',
                'owner': 'Opérateur télécom / administrateur réseau', 'days': 30,
                'closure': 'Routes protégées par authentification ou données minimisées, isolation LAN validée, puis contre-test sans cookie.'}
    if 'sql' in title:
        return {'impact': 'Si confirmé : accès, modification ou perte de données et interruption du service selon les privilèges de la base.',
                'condition': 'Point d’entrée réellement injectable, composant concerné et privilèges de la base à vérifier sur staging.',
                'owner': 'Responsable applicatif / prestataire de développement', 'days': 7,
                'closure': 'Reproduction sur staging documentée, requêtes paramétrées ou composant corrigé, puis test ciblé ne reproduisant plus l’injection.'}
    if 'hsts' in title or 'transport http' in title:
        return {'impact': 'Protection du transport insuffisante dans certains parcours ; risque conditionné par les accès HTTP et la situation de l’utilisateur.',
                'condition': 'Tester le parcours HTTP→HTTPS et l’ensemble des noms concernés avant de généraliser HSTS.',
                'owner': 'Responsable hébergement / reverse proxy', 'days': 30,
                'closure': 'Preuve HTTPS valide, redirection maîtrisée et en-tête HSTS conforme au périmètre décidé.'}
    if 'cadrage' in title or 'frame' in title:
        return {'impact': 'Le cadrage du site pourrait faciliter une tromperie d’interface si un parcours sensible peut être encadré.',
                'condition': 'Reproduction du cadrage sur les pages sensibles et validation des usages d’intégration légitimes.',
                'owner': 'Responsable applicatif / hébergement', 'days': 30,
                'closure': 'Test de cadrage et réponse frame-ancestors ou X-Frame-Options cohérente avec les usages autorisés.'}
    if 'en-tête' in title:
        return {'impact': 'Défense du navigateur réduite. L’absence d’un en-tête ne prouve pas à elle seule une XSS, une fuite de données ou une compromission.',
                'condition': 'Confirmer sur les routes applicatives utiles et analyser la valeur attendue au regard des dépendances du site.',
                'owner': 'Responsable applicatif / hébergement', 'days': 30,
                'closure': 'Réponse HTTP archivée avec la valeur validée ; parcours fonctionnels et ressources tierces vérifiés après changement.'}
    if 'readme' in title or finding.get('severity') == 'Info':
        return {'impact': 'Information publique ou surface exposée pouvant faciliter la reconnaissance ; aucune exploitation démontrée.',
                'condition': 'Évaluer l’information réellement divulguée et son besoin métier ; une API publique peut être normale.',
                'owner': 'Administrateur CMS', 'days': 60,
                'closure': 'Décision documentée de conservation ou réduction de l’exposition, puis recontrôle de l’URL.'}
    return {'impact': 'Impact métier non quantifié : dépend du composant, de la version exécutée et des usages du site.',
            'condition': 'Vérifier la version installée, le correctif et les conditions d’exploitation avant qualification.',
            'owner': 'Responsable applicatif / administrateur CMS', 'days': 7 if finding.get('severity') in ('Haute', 'Critique') else 30,
            'closure': 'Preuve de version corrigée, décision de traitement validée et recontrôle ciblé.'}


def enrich(report):
    generated = datetime.now(timezone.utc).isoformat()
    report.setdefault('finished_utc', generated)
    report['generated_utc'] = generated
    defaults = {'version': '5.0', 'classification': 'Interne — diffusion restreinte',
                                 'owner': 'RSSI / CISO — nom à renseigner', 'organization': urlsplit(report['target']).hostname or 'À renseigner',
                                 'validation': 'Brouillon — validation humaine requise'}
    report['metadata'] = {**defaults, **report.get('metadata', {}), 'version': '5.0'}
    try:
        audit_date = datetime.fromisoformat(report['started_utc']).date()
    except (ValueError, KeyError):
        audit_date = datetime.now(timezone.utc).date()
    register = []
    by_key = {}
    for index, f in enumerate(report.get('findings', []), 1):
        key = fingerprint(f)
        if key in by_key:
            urls = by_key[key]['source_urls']
            if f.get('url') not in urls:
                urls.append(f.get('url'))
            continue
        context = finding_context(f)
        qualification = f.get('qualification') or ('indice à confirmer' if 'sql' in f.get('title', '').lower() or 'indice' in f.get('confidence', '') else 'exposition observée')
        register.append({'id': 'F-' + str(len(register)+1).zfill(3), **f, **context, 'key': key, 'qualification': qualification, 'source_urls': [f.get('url')],
                         'proposed_due_date': (audit_date + timedelta(days=context['days'])).isoformat(),
                         'treatment_status': 'À qualifier / décision RSSI attendue',
                         'decision': 'à décider', 'validator': '', 'closure_evidence': '',
                         'probability': 'Non mesurée ; aucune probabilité chiffrée déduite du scan.',
                         'residual_risk': 'Non évalué ; dépend de la validation et du traitement.'})
        by_key[key] = register[-1]
    report['risk_register'] = register
    plan = report.get('treatment_updates')
    if plan:
        try:
            fields = {'owner', 'proposed_due_date', 'treatment_status', 'decision', 'validator', 'closure_evidence', 'qualification'}
            if plan.get('schema') != 1 or not isinstance(plan.get('entries'), list):
                raise ValueError('schéma de plan invalide')
            updates = {}
            for row in plan['entries']:
                if not isinstance(row, dict) or not isinstance(row.get('key'), str):
                    raise ValueError('entrée de plan invalide')
                selected = {key: value for key, value in row.items() if key in fields}
                if any(not isinstance(value, str) or len(value) > 2000 for value in selected.values()):
                    raise ValueError('champ de plan invalide')
                if selected.get('proposed_due_date'):
                    datetime.strptime(selected['proposed_due_date'], '%Y-%m-%d')
                if selected.get('decision', '').lower().startswith('accepter') and not (selected.get('validator') and selected.get('closure_evidence')):
                    raise ValueError('acceptation proposée : validateur et justification requis')
                if 'confirmé' in selected.get('qualification', '').lower() and not (selected.get('validator') and selected.get('closure_evidence')):
                    raise ValueError('confirmation humaine : validateur et preuve requis')
                updates[row['key']] = selected
            for finding in register:
                finding.update(updates.get(finding['key'], {}))
        except (ValueError, AttributeError) as exc:
            report.setdefault('limitations', []).append('Plan non appliqué : ' + str(exc))
    tools = report.get('tools', {})
    checks = report.get('checks', [])
    cms = sorted({c['name'] for c in report.get('cms', [])})
    report['cms_versions'] = {name: versions for name, versions in report.get('cms_versions', {}).items() if name in cms}
    inv = report.get('inventory', {})
    is_router = report.get('asset_profile', {}).get('kind') == 'routeur'
    coverage = [
        [('Interface HTTP locale' if is_router else 'Pages publiques / CMS'), 'Observé' if report.get('pages') else 'Non enregistré',
         (str(len(report.get('pages', []))) + ' page(s) HTML ; profil : ' + report.get('asset_profile', {}).get('effective', 'routeur') if is_router else
          str(len(report.get('pages', []))) + ' pages HTML ; CMS : ' + (', '.join(cms) or 'non déterminé')),
         'Exploration bornée ; pas un inventaire exhaustif.'],
        ['En-têtes HTTP', 'Observé' if any(c.get('category') == 'En-têtes HTTP' for c in checks) else 'Non enregistré',
         str(sum(c.get('category') == 'En-têtes HTTP' for c in checks)) + ' contrôles enregistrés', 'Observation sur la page principale uniquement.'],
        ['Transport TLS', 'Observation limitée' if any(c.get('category') == 'Transport' for c in checks) else 'Non enregistré',
         'Vérification du certificat par le client HTTP', 'Ce contrôle seul ne décrit pas la configuration cryptographique ; voir le contrôle TLS détaillé si activé.'],
        [('API routeur sans cookie' if is_router else 'Versions CMS et composants'),
         ('Observation limitée' if report.get('router_inventory') else 'Non déterminé') if is_router else ('Inventaire partiel' if any(inv.values()) else 'Non déterminé'),
         (str(len(report.get('router_inventory', []))) + ' routes GET avec schéma expurgé' if is_router else
          str(len(inv.get('plugins', {}))) + ' plugins et ' + str(len(inv.get('themes', {}))) + ' thèmes visibles'),
         ('Aucun POST, secret ni corps complet conservé.' if is_router else 'Versions déclarées et readme ne prouvent pas les versions exécutées.')],
    ]
    tool_rows = [] if is_router else [('wpscan', 'WPScan / vulnérabilités WordPress', 'Base CVE non consultée sans token ; applicabilité des résultats à confirmer.'),
                              ('sql_probes', 'Sondes SQL intégrées', 'Erreurs visibles uniquement ; pas de SQL aveugle ni de formulaire POST.'),
                              ('sqlmap', 'sqlmap', 'URL GET précise ; techniques BE, risque 1, niveau 1 et budget propre.')]
    for key, name, scope in tool_rows:
        data = tools.get(key, {})
        detail = data.get('conclusion') or data.get('api') or data.get('detail') or 'Aucun résultat enregistré.'
        if key == 'sql_probes':
            detail = str(data.get('probes', 0)) + ' sondes ; ' + str(detail)
        coverage.append([name, data.get('status', 'Non demandé / non exécuté'), detail, scope])
    for key, name, scope in [
        ('nuclei_safe', 'Nuclei contrôlé', 'Modèles signés, HTTP, faible débit, sans OAST/fuzz/code.'),
        ('threat_intel', 'Priorisation KEV / EPSS', 'Ne prouve ni présence ni exploitabilité.'),
        ('authenticated_matrix', 'Matrice authentifiée', 'GET uniquement ; secrets exclus ; différences à valider.'),
        ('router_services', 'Services routeur', 'TCP connect borné ; aucune bannière ni exploitation.'),
        ('local_ai', 'Conseiller IA local', 'Propositions expurgées soumises à validation humaine.'),
    ]:
        data = tools.get(key, {})
        coverage.append([name, data.get('status', 'Non demandé'), data.get('detail') or data.get('qualification') or data.get('policy') or 'Aucun résultat enregistré.', scope])
    coverage.extend([
        ['Cookies publics', 'Observation limitée', str(len(report.get('cookies', []))) + ' cookies sans valeurs', 'Attributs Secure/HttpOnly/SameSite ; caractère authentifié non établi.'],
        ['TLS détaillé', tools.get('tls', {}).get('status', 'Non demandé'), str(len(tools.get('tls', {}).get('handshakes', []))) + ' négociations', 'TLS 1.2/1.3, certificat et suites négociées ; versions anciennes et suites exhaustives non testées.'],
        ['Références éditeur', tools.get('references', {}).get('status', 'Non demandé'), str(len(tools.get('references', {}).get('components', []))) + ' composants comparés', 'Versions déclaratives ; support et CVE non déduits d’une simple comparaison.'],
        ['Formulaires', 'Inventaire passif', str(len(report.get('surface', {}).get('forms', []))) + ' formulaires visibles', 'Aucune soumission ni validation active.'],
        ['Authentification / autorisation', tools.get('authenticated_matrix', {}).get('status', 'Non testé'),
         str(len(tools.get('authenticated_matrix', {}).get('comparisons', []))) + ' comparaisons GET expurgées',
         'MFA, mutations, CSRF et logique métier restent hors de ce contrôle.'],
        ['XSS / uploads / SSRF', 'Non testé', 'Aucun verdict issu de cet audit', 'Requiert des scénarios ciblés et un environnement approprié.'],
        ['Sauvegardes / PRA / journaux', 'Non testé', 'Pas d’accès interne', 'Demander preuves de restauration, supervision, patching et procédures d’incident.'],
    ])
    report['coverage'] = coverage
    obstacles = []
    for r in report.get('requests', []):
        if r.get('error') and not r.get('historical'):
            cause, impact, action = obstacle(r['error'], 'SOCKS' in report.get('proxy', ''))
            obstacles.append({'source': r['url'], 'cause': cause, 'impact': impact, 'action': action, 'technical': r['error']})
    for name, data in tools.items():
        status = data.get('status', '')
        if any(x in status.lower() for x in ('échec', 'incomplet', 'indisponible', 'interrompu', 'partiel')):
            cause, impact, action = obstacle(data.get('detail') or status, 'SOCKS' in report.get('proxy', ''))
            obstacles.append({'source': name, 'cause': cause, 'impact': impact, 'action': action, 'technical': data.get('detail') or status})
    report['analysis_obstacles'] = obstacles
    report['summary'] = {'severity_counts': dict(Counter(f.get('severity', 'Info') for f in register)),
                         'finding_count': len(register), 'obstacle_count': len(obstacles),
                         'confirmed_compromise': 'Non évaluée : aucune investigation d’incident réalisée.',
                         'assurance': 'Limitée au périmètre effectivement observé ; aucune certification ni absence de vulnérabilité affirmée.'}
    report.setdefault('document_history', []).append({'version': '5.0', 'generated_utc': generated, 'validation': report['metadata']['validation']})
    return analyze(report)


def render(report):
    r = report
    meta = r['metadata']
    register = r['risk_register']
    counts = r['summary']['severity_counts']
    obstacles = r['analysis_obstacles']
    partial = 'incomplet' in r.get('status', '').lower() or bool(obstacles)
    state = 'Audit partiel — compléter la couverture' if partial else 'Collecte terminée — périmètre limité'
    is_router = r.get('asset_profile', {}).get('kind') == 'routeur'
    positive_sql = [f for f in register if 'sql' in f.get('title', '').lower()]
    sql_tested = r.get('tools', {}).get('sql_probes', {}).get('probes', 0) > 0 or bool(r.get('tools', {}).get('sqlmap', {}).get('log'))
    sql = ('Tests SQL non applicables au profil routeur ; aucune tentative d’exploitation ou de modification.' if is_router else
           'Signalement SQL à qualifier en priorité.' if positive_sql else
           'Aucune injection SQL confirmée dans les tests réalisés ; les parcours non testés restent inconnus.' if sql_tested else
           'Tests SQL non réalisés : aucune conclusion possible sur les injections SQL.')
    result = '''<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Hackscan — Rapport RSSI/CISO</title>
<style>
:root{--ink:#18304b;--muted:#50627a;--line:#d5dfeb;--blue:#154e7b}*{box-sizing:border-box}body{margin:0;font:16px/1.6 system-ui,sans-serif;color:var(--ink);background:#f1f5fa}main{max-width:1240px;margin:auto;padding:32px 24px}header{background:#102c49;color:white;padding:32px;border-radius:16px}header h1{font-size:32px;margin:8px 0}header p{color:#d5e5f4;overflow-wrap:anywhere}.tag{font-size:12px;font-weight:700;letter-spacing:.07em;text-transform:uppercase}nav{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0}a{color:#145a90}nav a{padding:8px 12px;background:white;border:1px solid var(--line);border-radius:8px}h2{font-size:25px;margin:32px 0 14px}h3{margin:0 0 12px;font-size:20px}.panel,.finding{background:white;padding:24px;border:1px solid var(--line);border-radius:12px;margin:16px 0}.banner{border-left:5px solid #d89a1a;background:#fff7e6;padding:18px 24px;margin:20px 0}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}.metric{background:white;border:1px solid var(--line);border-radius:10px;padding:16px}.metric strong{display:block;font-size:30px}.table{overflow:auto;border:1px solid var(--line);border-radius:10px;margin:12px 0}table{border-collapse:collapse;width:100%;background:white;min-width:720px}th,td{text-align:left;vertical-align:top;padding:12px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}th{background:#e8eff7;font-size:14px;overflow-wrap:normal}td{font-size:14px}dt{font-weight:700;color:#294f73;margin-top:14px}dd{margin:4px 0 0;white-space:pre-wrap;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f6fa;padding:14px;font-size:13px}details{margin:12px 0}summary{cursor:pointer;font-weight:600}small,.muted{color:var(--muted)}li{margin:7px 0}.finding{border-left:5px solid #4988b6}.high{border-left-color:#ba3d3d}footer{padding:24px 0;color:var(--muted)}@media(max-width:600px){main{padding:16px 12px}header{padding:22px}header h1{font-size:25px}.panel,.finding{padding:18px}nav a{font-size:14px}.metrics{grid-template-columns:1fr 1fr}}@media print{body{background:white}main{max-width:none;padding:0}nav,details{display:none}header{background:white;color:#18304b;border:1px solid #d5dfeb}header p{color:#18304b}.table{overflow:visible}table{min-width:0}th,td{font-size:10px;padding:6px}.finding,.panel{break-inside:avoid}h2{break-after:avoid}a{color:inherit}}
</style></head><body><main>'''
    report_title = 'Rapport de pentest routeur — RSSI / CISO' if is_router else 'Rapport de sécurité web — RSSI / CISO'
    result += '<header><div class="tag">' + escape(meta['classification']) + ' · ' + escape(meta['validation']) + '</div><h1>' + report_title + '</h1><p>' + escape(meta['organization']) + '<br>Cible évaluée : ' + escape(r['target']) + '</p><p>Version ' + escape(meta['version']) + ' · Responsable : ' + escape(meta['owner']) + '</p></header>'
    result += '<nav aria-label="Sommaire">' + ''.join('<a href="#' + key + '">' + title + '</a>' for key, title in [('synthese', 'Synthèse'), ('perimetre', 'Périmètre'), ('couverture', 'Couverture'), ('constats', 'Constats'), ('inventaire', 'Inventaire'), ('traitement', 'Plan de traitement'), ('annexes', 'Preuves et annexes')]) + '</nav>'
    assurance_text = ('une collecte LAN partielle' if is_router else 'un scan externe partiel')
    result += '<section id="synthese"><h2>1. Synthèse décisionnelle</h2><div class="banner"><strong>' + escape(state) + '</strong><p>' + escape(sql) + '</p><p>Aucune note globale de sécurité n’est attribuée : ' + assurance_text + ' ne permet pas de mesurer le risque résiduel ou de démontrer l’absence de compromission.</p></div><div class="metrics">'
    result += ''.join('<div class="metric"><strong>' + str(counts.get(severity, 0)) + '</strong>' + severity + ' · constats</div>' for severity in ('Critique', 'Haute', 'Moyenne', 'Faible', 'Info'))
    result += '<div class="metric"><strong>' + str(len(obstacles)) + '</strong>Limites / blocages</div></div><div class="panel"><h3>Décisions proposées au RSSI</h3><ul><li>Valider la qualification des constats et affecter un responsable de traitement.</li>'
    if obstacles:
        result += '<li>Prioriser la levée des obstacles ci-dessous pour restaurer la couverture de l’audit.</li>'
    if positive_sql:
        result += '<li>Faire reproduire les signalements SQL sur staging et définir les mesures conservatoires adaptées.</li>'
    result += '<li>' + ('Obtenir de l’opérateur le modèle, le firmware et l’état des correctifs réellement installés.' if is_router else 'Confirmer les versions réellement exécutées et leur état de support à partir de l’inventaire administrateur.') + '</li><li>Demander les preuves internes manquantes : droits, mises à jour, restauration, supervision et réponse à incident.</li></ul><p>Les échéances et responsables ci-dessous sont des propositions, sans affectation effective ni acceptation de risque automatique.</p></div>'
    if obstacles:
        result += '<h3>Obstacles à la décision</h3>' + table(['Source', 'Cause constatée / hypothèse', 'Conséquence', 'Action proposée'], [[o['source'], o['cause'], o['impact'], o['action']] for o in obstacles])
    result += '</section><section id="perimetre"><h2>2. Périmètre et méthode</h2>'
    nature = ('Audit LAN borné de l’interface routeur, non authentifié, GET uniquement et sans modification.' if is_router else
              'Audit externe borné, public et non authentifié. Signatures CMS et versions déclaratives.')
    scope_rows = [['URL demandée', r.get('requested_target', r['target'])], ['URL effectivement évaluée', r['target']], ['Début de collecte UTC', r.get('started_utc', 'non enregistré')], ['Fin de collecte UTC', r.get('finished_utc', 'non enregistrée')], ['Génération du document UTC', r['generated_utc']], ['Transport', r.get('proxy', 'non enregistré')], ['Statut technique', r.get('status', 'non enregistré')], ['Validation', meta['validation']], ['Nature', nature]]
    scope_rows += [[key, value] for key, value in r.get('configuration', {}).items()]
    result += table(['Paramètre', 'Valeur / méthode'], scope_rows)
    result += '<h3>Contexte métier à valider</h3>' + table(['Information', 'Qualification disponible'], [
        ['Actif', 'Passerelle/routeur local correspondant à la cible indiquée' if is_router else 'Site web public correspondant à la cible indiquée'], ['Responsable métier / prestataire', r.get('business_context', {}).get('owner', 'À désigner')],
        ['Données traitées et sensibilité', r.get('business_context', {}).get('data_sensitivity', 'Topologie locale potentiellement exposée' if is_router else 'Non connues depuis ce scan externe')], ['Criticité métier / engagements de disponibilité', r.get('business_context', {}).get('criticality', 'À renseigner par le propriétaire du service')],
        ['RTO / RPO, sauvegardes et restauration', 'Non vérifiés ; preuves internes à demander']])
    if r.get('redirects'):
        result += '<h3>Normalisation et redirections</h3>' + table(['Origine', 'Destination', 'HTTP', 'Règle appliquée'], [[x['from'], x['to'], x['status'], x['reason']] for x in r['redirects']])
    result += '<p>Les budgets des outils externes sont distincts de la limite de requêtes du scanner intégré. Aucun POST, dump de base, écriture applicative, shell, force brute ou test de disponibilité n’est demandé.</p></section>'
    result += '<section id="couverture"><h2>3. Couverture réelle de l’audit</h2>' + table(['Domaine', 'État', 'Observations', 'Limite de conclusion'], r['coverage']) + '<p>« Observé » décrit une mesure reçue ; ce statut ne signifie pas « sécurisé ». « Non testé » et « non déterminé » restent des inconnues.</p></section>'
    result += '<section id="constats"><h2>4. Registre détaillé des constats</h2><p>Priorité technique initiale, distincte d’un risque métier validé. Aucune valeur CVSS, CVE, probabilité ou perte financière n’est inventée.</p>' + filters_html(r)
    if not register:
        result += '<div class="panel">Aucun constat enregistré. Consulter la couverture et les obstacles avant toute conclusion sur le risque.</div>'
    for f in register:
        result += '<article data-key="' + escape(f['key']) + '" class="finding' + (' high' if f['severity'] in ('Haute', 'Critique') else '') + '"><h3>' + escape(f['id'] + ' · ' + f['title']) + '</h3><p><strong>' + escape(f['severity']) + '</strong> · Qualification : ' + escape(f['qualification']) + ' · Confiance : ' + escape(f.get('confidence', 'à qualifier')) + '</p><dl>'
        for label, key in [('Périmètre / URL', 'url'), ('Preuve observée', 'evidence'), ('Impact potentiel', 'impact'), ('Conditions et validation nécessaires', 'condition'), ('Probabilité', 'probability'), ('Remédiation proposée', 'remediation'), ('Responsable proposé', 'owner'), ('Échéance proposée', 'proposed_due_date'), ('Preuve attendue pour clôture', 'closure'), ('État / risque résiduel', 'residual_risk')]:
            result += '<dt>' + label + '</dt><dd>' + escape(f.get(key, 'non renseigné')) + '</dd>'
        result += '<dt>Triage proposé</dt><dd>'+escape(f['triage'])+'</dd><dt>Justification</dt><dd>'+escape(' · '.join(f['triage_reasons']))+'</dd><dt>Qualité et références des preuves</dt><dd>'+escape(f['evidence_level']+' · '+', '.join(f['evidence_ids'])+' · âge '+str(f['evidence_age_days'])+' jour(s)')+'</dd><dt>Prérequis et effort</dt><dd>'+escape(f['dependencies']+' · '+f['effort'])+'</dd>'
        if f.get('cves'):
            result += '<dt>Identifiants CVE fournis par la source</dt><dd>' + escape(', '.join(f['cves'])) + '</dd>'
        if f.get('fixed_in'):
            result += '<dt>Version corrigée selon la source</dt><dd>' + escape(f['fixed_in']) + '</dd>'
        if f.get('validator') or f.get('closure_evidence'):
            result += '<dt>Déclaration humaine — validateur / preuve</dt><dd>' + escape(f.get('validator', '') + ' : ' + f.get('closure_evidence', '')) + '</dd>'
        result += '</dl></article>'
    result += '</section><section id="inventaire"><h2>5. Inventaire et surface observée</h2>'
    if is_router:
        result += '<h3>Profil routeur</h3>' + table(['Profil demandé', 'Profil effectif', 'Nature'], [[
            r.get('asset_profile', {}).get('requested', 'non enregistré'),
            r.get('asset_profile', {}).get('effective', 'non enregistré'), 'Routeur local']])
        result += '<h3>Routes HTTP — valeurs expurgées</h3>' + table(
            ['Route', 'HTTP', 'Format', 'Éléments racine', 'Liste imbriquée max.', 'Champs autorisés', 'Autres noms masqués'],
            [[row.get('path', ''), row.get('http_status', ''), row.get('format', ''), row.get('items', 0), row.get('max_list_items', 0), ', '.join(row.get('keys', [])), row.get('other_key_count', 0)]
             for row in r.get('router_inventory', [])])
        result += '<p>Aucune valeur IP, MAC, nom d’hôte, SSID, jeton ou corps complet n’est conservé. Un HTTP 200 démontre uniquement l’accès GET observé, jamais un rôle administrateur.</p></section>'
    else:
        result += '<h3>CMS : indices de détection</h3>' + table(['CMS', 'Confiance', 'Source', 'Indices'], [[c['name'], c.get('confidence', 'probable'), c.get('url', ''), '; '.join(c.get('evidence', []))] for c in r.get('cms', [])])
        inv = r.get('inventory', {})
        result += '<p>Versions du cœur WordPress observées : ' + escape(', '.join(inv.get('wordpress', [])) or 'non déterminées') + '. Absence de version ≠ version à jour.</p>'
        items = []
        for kind in ('plugins', 'themes'):
            for name, item in inv.get(kind, {}).items():
                items.append([kind, name, ', '.join(item.get('versions', [])) or 'non déterminée', item.get('readme_stable_tag', 'non déterminé'), ', '.join(item.get('asset_tokens', [])) or 'aucun', '; '.join(item.get('evidence', [])), 'État CVE / support non validé ; confirmer version exécutée et avis éditeur.'])
        result += table(['Type', 'Composant', 'Version déclarée', 'Stable tag du readme', 'Marqueurs de cache ignorés', 'Sources', 'Qualification requise'], items)
        result += '<p>Un numéro de ressource ou le stable tag d’un readme n’est pas une preuve de la version exécutée. Une absence de résultat WPScan, de jeton API ou de donnée CVE laisse la qualification inconnue.</p><h3>Formulaires visibles — sans soumission</h3>'
        result += table(['Page', 'Action sans paramètres', 'Méthode déclarée', 'Test actif'], [[f['page'], f['action'], f['method'], 'Non réalisé'] for f in r.get('surface', {}).get('forms', [])])
        result += '<h3>Dépendances externes visibles</h3><p>' + escape(', '.join(r.get('surface', {}).get('external_domains', [])) or 'Aucun domaine enregistré.') + '</p><p>Inventaire passif des ressources : ni preuve de transfert de données personnelles, ni évaluation de conformité.</p></section>'
    result += '<section id="traitement"><h2>6. Plan de traitement et suivi</h2>'
    result += table(['ID', 'Priorité', 'Action', 'Responsable proposé', 'Échéance proposée', 'Statut', 'Preuve de clôture'], [[f['id'], f['severity'], f['remediation'], f['owner'], f['proposed_due_date'], f['treatment_status'], f['closure']] for f in register])
    result += '<div class="panel"><h3>Conditions de validation et d’acceptation</h3><p>Validation technique : version et conditions d’exploitation confirmées. Validation métier : actif, données, exposition et impact documentés. Validation RSSI : traitement ou acceptation explicite, échéance et risque résiduel. Clôture : preuve de changement et recontrôle daté.</p><p>Aucune action de traitement, acceptation ou affectation n’a été exécutée par ce script.</p></div></section>'
    result += '<section id="annexes"><h2>7. Preuves, erreurs et annexes</h2><h3>Mesures de contrôle enregistrées</h3>'
    result += table(['Domaine', 'Contrôle', 'URL', 'État', 'Preuve'], [[c.get('category', ''), c.get('name', ''), c.get('url', ''), c.get('status', ''), c.get('evidence', '')] for c in r.get('checks', [])])
    result += '<h3>Journal HTTP et intégrité des observations</h3>' + table(['Horodatage UTC', 'URL', 'HTTP', 'Durée ms', 'Octets', 'Erreur'], [[q.get('at_utc', 'non enregistré'), q['url'], q.get('status'), q.get('duration_ms', 'non enregistrée'), q.get('bytes', 'non enregistrés'), q.get('error', '')] for q in r.get('requests', [])])
    result += '<details><summary>Empreintes SHA-256 des réponses et en-têtes sélectionnés</summary><pre>' + escape(json.dumps([{'url': q['url'], 'sha256': q.get('sha256', 'non enregistré'), 'headers': q.get('headers', {})} for q in r.get('requests', [])], ensure_ascii=False, indent=2)) + '</pre></details><p>Les empreintes portent sur les octets décompressés reçus ; elles servent à comparer les observations et ne constituent pas une attestation tierce. Les corps complets, valeurs de cookies et secrets ne sont pas archivés.</p>'
    for name, data in r.get('tools', {}).items():
        result += '<details><summary>' + escape(name + ' — ' + data.get('status', 'non enregistré')) + '</summary><pre>' + escape(json.dumps(data, ensure_ascii=False, indent=2)) + '</pre></details>'
    result += '<h3>Hypothèses et limites</h3><ul>' + ''.join('<li>' + escape(x) + '</li>' for x in r.get('limitations', [])) + '</ul><h3>Traçabilité documentaire</h3>'
    result += table(['Version', 'Génération UTC', 'État', 'Historique'], [[meta['version'], r['generated_utc'], meta['validation'], 'Rapport produit depuis report.json ; anciens rapports conservés. Aucun nouveau test déduit d’une régénération.']])
    result += '<h3>Références méthodologiques</h3><p><a href="https://owasp.org/www-project-web-security-testing-guide/">OWASP WSTG</a> · <a href="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html">Prévention SQL</a> · <a href="https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html">En-têtes HTTP</a> · <a href="https://github.com/wpscanteam/wpscan">WPScan</a> · <a href="https://github.com/sqlmapproject/sqlmap/wiki/Usage">sqlmap</a></p><p>Ces références orientent la revue ; le scan ne constitue pas une couverture exhaustive OWASP ni une certification.</p></section><footer>Document de travail RSSI/CISO · Diffusion selon la classification indiquée · Preuves et suivi à conserver dans le registre de sécurité.</footer></main></body></html>'
    result = result.replace('<nav aria-label="Sommaire">', report_actions() + '<nav aria-label="Sommaire">', 1)
    result = result.replace('<section id="synthese">', '<section id="direction-report" hidden>' + executive_body(r) + '</section><section id="synthese">', 1)
    result = result.replace('<footer>', extra_html(r) + '<footer>', 1)
    result = result.replace('</section><section id="perimetre">', '</section>' + intelligence_html(r) + '<section id="perimetre">', 1)
    result = result.replace('<nav aria-label="Sommaire">', '<nav aria-label="Sommaire"><a href="#intelligence">Analyse et décisions</a><a href="#control-matrix">' + str(len(r['intelligence']['controls'])) + ' contrôles</a><a href="improvements.html">100 améliorations</a>', 1)
    result = result.replace('</body>', intelligence_assets() + '</body>', 1)
    result = result.replace('</body>', styles() + navigation_script() + '</body>', 1)
    result = result.replace('</style>', 'input,select,button{font:inherit;padding:8px;border:1px solid #bccbda;border-radius:6px;max-width:100%}.filters{display:flex;gap:12px;flex-wrap:wrap}.filters label{display:grid;gap:4px}.filters p{width:100%}[hidden]{display:none!important}</style>', 1)
    return result


def write_report(report, output, signing_key=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    report = enrich(report)
    for name, content in [('report.json', json.dumps(report, ensure_ascii=False, indent=2)), ('report.html', render(report))]:
        path = output / name
        path.write_text(content, encoding='utf-8')
        path.chmod(0o600)
    export_files(report, output)
    manifest(output)
    if signing_key:
        sign_manifest(output, signing_key)
