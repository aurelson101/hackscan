"""Analyse déterministe, passive et explicable. Aucun verdict d'exploitation."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from html.parser import HTMLParser
import hashlib
import json
import math
import re
from statistics import median
from urllib.parse import urljoin, urlsplit, urlunsplit

SOURCES = {
    'browser': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy',
    'cookie': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie',
    'audit': 'https://owasp.org/projects/web-security-testing-guide',
}
LABELS = [
    'CSP appliquée', 'Source effective des scripts', 'Évaluation dynamique JavaScript',
    'Scripts inline et nonce/hash', 'Sources script universelles', 'Scripts data:',
    'Sources script HTTP', 'Restriction des objets', 'Restriction base-uri',
    'Restriction form-action', 'Restriction frame-ancestors', 'Ancêtres universels',
    'CSP Report-Only', 'Directives CSP répétées', 'Collecte des rapports CSP',
    'Durée HSTS', 'Portée HSTS sous-domaines', 'Déclaration HSTS preload',
    'Politique Referrer effective', 'Permissions sensibles universelles',
    'Cookie Secure', 'Cookie HttpOnly', 'Valeur SameSite', 'SameSite=None et Secure',
    'Préfixe __Host-', 'Préfixe __Secure-', 'Portée Domain', 'Portée Path',
    'Persistance longue des cookies', 'Cookie de session ou persistant',
    'Contenu mixte actif', 'Contenu mixte passif', 'Formulaire vers HTTP',
    'Formulaire vers une autre origine', 'Mot de passe et méthode GET',
    'Autocomplete des mots de passe', 'Intégrité des scripts tiers',
    'Intégrité des feuilles de style tierces', 'Liens nouvel onglet',
    'Sandbox des iframes', 'Permissions des iframes', 'Gestionnaires JS inline',
    'Scripts inline sans nonce', 'Base HTML externe', 'WebSocket non chiffré déclaré',
    'Certificat à renouveler sous 30 jours', 'Certificat à renouveler sous 7 jours',
    'Certificat wildcard', 'Certificat vérifié par le client', 'Protocoles TLS négociés',
    'CORS étoile et credentials', 'CORS null et credentials', 'Méthodes CORS déclarées',
    'Version serveur divulguée', 'Version runtime divulguée', 'Index de répertoire probable',
    'Trace applicative visible', 'Dépendances externes par origine',
    'Cohérence des en-têtes entre pages', 'Versions CMS contradictoires',
]
ANALYSIS_LABELS = [
    'Priorisation explicable', 'Niveau de preuve indépendant de la gravité',
    'Causes regroupées', 'Matrice thèmes et états', 'Décisions contextualisées',
    'Mesures conservatoires proposées', 'Ordre des validations', 'Règles de recontrôle',
    'Effort qualitatif proposé', 'Dépendances de traitement', 'Campagnes 7/30/90 jours',
    'Contrôles internes à demander', 'Ancienneté des preuves', 'Traçabilité preuve-constat',
    'Détection des lacunes de collecte', 'Statistiques réseau robustes',
    'Détection des doublons de traitement', 'Alertes d’échéances',
    'Contradictions entre déclarations et preuves', 'Contrat machine versionné',
]
REPORT_LABELS = [
    'Tableau de bord des contrôles', 'Diagramme de couverture', 'Lecture direction/technique',
    'Cartes de décision', 'Feuille de route par cause', 'Matrice de contrôles complète',
    'Filtre des contrôles par domaine', 'Filtre des contrôles par état',
    'Recherche dans les contrôles', 'Compteur des contrôles visibles',
    'Détails des preuves dépliables', 'Ancres stables de contrôle', 'Liens aux références',
    'Sommaire enrichi', 'Indicateur de modifications non exportées',
    'Raccourci clavier de recherche', 'Registre de contrôles CSV',
    'Export intelligence JSON', 'Catalogue des 100 ajouts', 'Annexe décisionnelle PDF',
]
CATALOGUE = [dict(id=f'A{i:03}', title=title, category=category, implemented=True)
             for start, labels, category in [(1, LABELS, 'contrôle passif'),
                                             (61, ANALYSIS_LABELS, 'analyse'),
                                             (81, REPORT_LABELS, 'rapport')]
             for i, title in enumerate(labels, start)]


def public_url(value):
    """Ne conserver ni credentials ni valeurs de query dans les nouvelles preuves."""
    try:
        p = urlsplit(value)
        if p.scheme not in ('https', 'http', 'ws', 'wss') or not p.hostname:
            return ''
        port = ':' + str(p.port) if p.port else ''
        host = '[' + p.hostname + ']' if ':' in p.hostname else p.hostname
        return urlunsplit((p.scheme, host + port, p.path or '/', '', ''))
    except ValueError:
        return ''


def page_snapshot(page):
    """Résumé HTML sans contenu libre, identifiants, valeurs de champs ou scripts."""
    data = {'url': public_url(page['url']), 'resources': [], 'forms': [], 'links': [],
            'inline_handlers': 0, 'inline_scripts_without_nonce': 0,
            'insecure_websocket_literals': 0, 'directory_index': False, 'stack_trace': False}
    class Parser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.form = None
            self.in_title = False
        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            data['inline_handlers'] += sum(k.lower().startswith('on') for k in a)
            if tag == 'title':
                self.in_title = True
            if tag == 'form' and len(data['forms']) < 30:
                self.form = {'action': public_url(urljoin(page['url'], a.get('action') or page['url'])),
                             'method': a.get('method', 'get').upper(), 'password': False,
                             'password_autocomplete_off': False}
                data['forms'].append(self.form)
            if tag == 'input' and self.form is not None and a.get('type', '').lower() == 'password':
                self.form['password'] = True
                self.form['password_autocomplete_off'] |= a.get('autocomplete', '').lower() == 'off'
            if tag == 'script' and not a.get('src') and not a.get('nonce') and a.get('type', '').lower() not in ('application/json', 'application/ld+json'):
                data['inline_scripts_without_nonce'] += 1
            value = a.get('src') or a.get('href')
            if value and tag in ('script', 'link', 'img', 'iframe', 'audio', 'video', 'source', 'base') and len(data['resources']) < 200:
                data['resources'].append({'tag': tag, 'url': public_url(urljoin(page['url'], value)),
                    'sri': bool(re.search(r'(?:^|\s)sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}(?:\s|$)', a.get('integrity', ''))),
                    'stylesheet': 'stylesheet' in a.get('rel', '').lower().split(),
                    'sandbox': a.get('sandbox'), 'allow': a.get('allow', '')[:300]})
            if tag == 'a' and a.get('target', '').lower() == '_blank' and len(data['links']) < 100:
                data['links'].append({'rel': a.get('rel', '').lower().split()})
        def handle_endtag(self, tag):
            if tag == 'form': self.form = None
            if tag == 'title': self.in_title = False
        def handle_data(self, text):
            if self.in_title and re.search(r'^\s*Index of /', text, re.I):
                data['directory_index'] = True
            if re.search(r'Traceback \(most recent call last\)|Fatal error:.*? on line \d+|Exception in thread', text, re.S):
                data['stack_trace'] = True
            data['insecure_websocket_literals'] += len(re.findall(r'[\"\']ws://', text, re.I))
    Parser().feed(page['body'])
    return data


def csp_directives(value):
    result, duplicates = {}, []
    for part in value.split(';'):
        tokens = part.strip().split()
        if tokens:
            name = tokens[0].lower()
            if name in result: duplicates.append(name)
            else: result[name] = tokens[1:]
    return result, duplicates


def assess_router(report):
    """Contrôles dédiés à une passerelle locale, sans recycler la matrice CMS."""
    controls = []
    inventory = {row.get('path'): row for row in report.get('router_inventory', [])}
    tls = report.get('tools', {}).get('tls', {}).get('handshakes', [])
    accepted = [row for row in tls if row.get('status') == 'accepté']
    html_rows = [row for row in report.get('requests', []) if row.get('status') == 200 and 'html' in row.get('content_type', '').lower()]
    headers = html_rows[0].get('headers', {}) if html_rows else {}

    def emit(number, title, domain, state, evidence, action):
        controls.append({'id': f'C{number:03}', 'improvement_id': f'A{number:03}',
            'title': title, 'domain': domain, 'state': state, 'evidence': str(evidence)[:1600],
            'action': action, 'url': public_url(report['target']), 'source': SOURCES['audit'],
            'method': 'lecture GET locale, non authentifiée et bornée', 'exploitation': 'non démontrée'})

    effective = report.get('asset_profile', {}).get('effective', 'non enregistré')
    emit(1, 'Périmètre routeur local', 'Périmètre', 'observé', 'Profil effectif : ' + effective,
         'Conserver une cible et une autorisation explicites à chaque campagne.')
    config = report.get('configuration', {})
    bounded = config.get('max_pages', 99) <= 1 and config.get('max_requests', 999) <= 16 and config.get('budget_seconds', 9999) <= 120
    emit(2, 'Budgets et méthode non destructive', 'Périmètre', 'observé' if bounded else 'à revoir',
         'GET uniquement ; pages=' + str(config.get('max_pages')) + ', requêtes=' + str(config.get('max_requests')) + ', budget=' + str(config.get('budget_seconds')) + ' s',
         'Maintenir les plafonds et interdire POST, brute force, DoS et changement de configuration.')
    public_paths = ('/api/v1/summary', '/api/v1/hosts/lite', '/api/v1/wan/ip', '/api/v1/wireless/wps')
    exposed = [path for path in public_paths if inventory.get(path, {}).get('http_status') == 200]
    emit(3, 'Authentification des API d’inventaire', 'Contrôle d’accès', 'à revoir' if exposed else 'observé' if any(path in inventory for path in public_paths) else 'inconnu',
         ', '.join(exposed) or 'Aucune route publique confirmée dans les mesures.',
         'Imposer une session ou minimiser strictement les champs accessibles avant authentification.')
    protected_paths = ('/api/v1/wireless', '/api/v1/hosts', '/api/v1/firewall', '/api/v1/device/token')
    protected = [path for path in protected_paths if inventory.get(path, {}).get('http_status') in (401, 403)]
    unexpected = [path for path in protected_paths if inventory.get(path, {}).get('http_status') == 200]
    emit(4, 'Protection des routes administratives ciblées', 'Contrôle d’accès', 'à revoir' if unexpected else 'observé' if len(protected) == len(protected_paths) else 'inconnu',
         ('Protégées : ' + ', '.join(protected)) + (' ; HTTP 200 inattendu : ' + ', '.join(unexpected) if unexpected else ''),
         'Conserver les réponses 401/403 et recontrôler après chaque mise à jour firmware.')
    emit(5, 'Certificat TLS vérifié', 'Transport', 'observé' if any(row.get('certificate_verified') for row in accepted) else 'inconnu',
         str(sum(bool(row.get('certificate_verified')) for row in accepted)) + ' négociation(s) avec certificat vérifié.',
         'Maintenir une chaîne et un nom de certificat valides.')
    for number, protocol in ((6, 'TLSv1.2'), (7, 'TLSv1.3')):
        matches = [row for row in accepted if row.get('protocol') == protocol]
        emit(number, protocol + ' négocié', 'Transport', 'observé' if matches else 'inconnu',
             str(len(matches)) + ' négociation(s).', 'Maintenir TLS 1.2/1.3 ; contrôler séparément les protocoles anciens et les suites exhaustives.')
    hsts = headers.get('strict-transport-security')
    emit(8, 'HSTS sur l’interface HTTPS', 'Transport', 'observé' if hsts else 'à revoir' if html_rows else 'inconnu',
         hsts or 'En-tête absent ou réponse HTML non disponible.', 'Activer HSTS après validation de tous les parcours locaux HTTPS.')
    wanted = ('content-security-policy', 'x-content-type-options', 'referrer-policy', 'x-frame-options')
    missing = [name for name in wanted if name not in headers]
    emit(9, 'En-têtes navigateur de l’interface', 'Navigateur', 'à revoir' if missing and html_rows else 'observé' if html_rows else 'inconnu',
         'Absents : ' + (', '.join(missing) or 'aucun parmi la sélection'), 'Durcir les en-têtes après tests fonctionnels de l’interface locale.')
    emit(10, 'Cookies de session administrateur', 'Authentification', 'inconnu',
         str(len(report.get('cookies', []))) + ' nom(s) de cookie observé(s), sans valeur ; aucune connexion administrateur.',
         'Tester séparément Secure, HttpOnly, SameSite, rotation et invalidation dans une campagne authentifiée.')
    emit(11, 'Version firmware et correctifs fournisseur', 'Patching', 'inconnu',
         'Aucune attestation binaire ou fournisseur dans cette collecte.', 'Obtenir modèle, build, support et état des correctifs auprès de l’opérateur.')
    emit(12, 'Exposition de l’administration depuis Internet', 'Exposition WAN', 'inconnu',
         'Non testée depuis Internet.', 'Vérifier dans la configuration et depuis une source externe autorisée que l’administration WAN est désactivée.')
    emit(13, 'Isolation des réseaux invité et IoT', 'Segmentation', 'inconnu',
         'Non testée depuis un segment invité/IoT.', 'Tester que ces segments ne peuvent pas joindre l’interface d’administration.')
    emit(14, 'WPS et UPnP', 'Services locaux', 'inconnu',
         'L’état WPS peut être lisible ; aucune modification ni attaque WPS/UPnP.', 'Désactiver WPS/UPnP s’ils ne sont pas justifiés et vérifier la configuration localement.')
    emit(15, 'Accès administrateur et élévation de privilèges', 'Authentification', 'non applicable',
         'Exclus du mandat non destructif ; aucun identifiant, brute force ou contournement.', 'Prévoir une campagne authentifiée distincte avec compte de test et rollback.')
    services = report.get('tools', {}).get('router_services', {}).get('services', [])
    emit(16, 'Inventaire borné des ports et services', 'Services locaux', 'observé' if services else 'inconnu',
         (', '.join(str(row['port']) + '/tcp ' + row['state'] for row in services) if services else 'Inventaire TCP non demandé.'),
         'Qualifier les ports ouverts et confirmer leur nécessité depuis les segments autorisés.')
    return controls


def assess(report):
    """Soixante contrôles indépendants : inconnu n'est jamais un résultat favorable."""
    if report.get('asset_profile', {}).get('kind') == 'routeur':
        return assess_router(report)
    controls = []
    headers = [r for r in report.get('requests', []) if r.get('status') == 200 and 'headers' in r
               and 'html' in r.get('content_type', '').lower() and not urlsplit(r['url']).query]
    snapshots = report.get('page_observations', [])
    cookies = report.get('cookies', [])
    tls = report.get('tools', {}).get('tls', {}).get('handshakes', [])
    def emit(number, domain, state, evidence, action, url=None):
        controls.append({'id': f'C{number:03}', 'improvement_id': f'A{number:03}',
            'title': LABELS[number-1], 'domain': domain, 'state': state, 'evidence': str(evidence)[:1600],
            'action': action, 'url': public_url(url or report['target']),
            'source': SOURCES['cookie' if domain == 'Cookies' else 'browser' if domain == 'Navigateur' else 'audit'],
            'method': 'lecture passive des mesures collectées', 'exploitation': 'non démontrée'})
    def condition(number, domain, matches, available, action, detail=None, na=False):
        state = 'non applicable' if na else 'à revoir' if matches else 'observé' if available else 'inconnu'
        if detail is None:
            detail = str(len(matches))+' occurrence(s)' if available else 'Mesure indisponible.'
            if matches and isinstance(matches[0],dict):
                detail += ' — '+json.dumps([{k:v for k,v in m.items() if k in ('url','page','action','method','tag','name','secure','http_only','same_site','path','domain_specified','expires','inline_handlers','inline_scripts_without_nonce','insecure_websocket_literals')} for m in matches[:5]],ensure_ascii=False)
        emit(number, domain, state, detail, action,
             (matches[0].get('page') or matches[0].get('url') or matches[0].get('action')) if matches and isinstance(matches[0], dict) else None)
    h = headers[0].get('headers', {}) if headers else {}
    extended_headers = bool(headers) and headers[0].get('header_capture_schema', 0) >= 2
    directives, duplicates = csp_directives(h.get('content-security-policy', ''))
    # Les politiques multiples nécessitent une interprétation navigateur : pas de verdict favorable synthétique.
    csp_available = bool(directives) and ',' not in h.get('content-security-policy', '')
    scripts = directives.get('script-src-elem', directives.get('script-src', directives.get('default-src', [])))
    has_nonce_hash = any(re.fullmatch(r"'(?:nonce-|sha(?:256|384|512)-)[A-Za-z0-9+/_-]+={0,2}'", t) for t in scripts)
    tests = [
        (1, bool(headers) and not directives, bool(headers), 'Préparer une CSP adaptée, tester en Report-Only puis appliquer.'),
        (2, csp_available and not scripts, csp_available, 'Définir script-src ou une politique par défaut appropriée.'),
        (3, "'unsafe-eval'" in directives.get('script-src', directives.get('default-src', [])), csp_available, 'Remplacer les dépendances à eval après tests fonctionnels.'),
        (4, "'unsafe-inline'" in scripts and not has_nonce_hash, csp_available, 'Étudier nonce/hash ; l’impact dépend de la politique complète.'),
        (5, any(t == '*' or t in ('http:', 'https:') for t in scripts), csp_available, 'Restreindre les origines effectives des scripts.'),
        (6, 'data:' in scripts, csp_available, 'Retirer data: des sources script si les usages le permettent.'),
        (7, any(t.startswith('http://') for t in scripts), csp_available, 'Utiliser des sources HTTPS maîtrisées.'),
        (8, csp_available and directives.get('object-src', directives.get('default-src', [])) != ["'none'"], csp_available, 'Évaluer object-src none.'),
        (9, csp_available and (not directives.get('base-uri') or '*' in directives['base-uri']), csp_available, 'Restreindre base-uri selon le besoin métier.'),
        (10, csp_available and not directives.get('form-action'), csp_available, 'Définir les destinations de formulaires autorisées.'),
        (11, csp_available and not directives.get('frame-ancestors'), csp_available, 'Définir les sites autorisés à encadrer la page.'),
        (12, '*' in directives.get('frame-ancestors', []), csp_available, 'Restreindre les ancêtres autorisés.'),
        (13, 'content-security-policy-report-only' in h and not directives, extended_headers or 'content-security-policy-report-only' in h, 'Une CSP Report-Only observe sans bloquer ; programmer son application.'),
        (14, bool(duplicates), csp_available, 'Éliminer les directives répétées ; la première occurrence est retenue.'),
        (15, csp_available and not any(k in directives for k in ('report-uri', 'report-to')), csp_available, 'Prévoir une collecte de violations proportionnée et protégée.'),
    ]
    for number, bad, available, action in tests:
        policy_evidence = {
            1:'CSP appliquée : '+str(bool(directives)),
            2:'Source des scripts explicitée ou héritée : '+str(bool(scripts)),
            3:'unsafe-eval dans script-src / default-src : '+str(bad),
            4:'unsafe-inline : '+str("'unsafe-inline'" in scripts)+' ; nonce/hash reconnu : '+str(has_nonce_hash),
            5:'Source universelle * / http: / https: : '+str(bad),
            6:'data: autorisé pour les scripts : '+str(bad),
            7:'Source HTTP autorisée pour les scripts : '+str(bad),
            8:'object-src / default-src : '+' '.join(directives.get('object-src',directives.get('default-src',[]))),
            9:'base-uri : '+' '.join(directives.get('base-uri',[])),
            10:'form-action : '+' '.join(directives.get('form-action',[])),
            11:'frame-ancestors : '+' '.join(directives.get('frame-ancestors',[])),
            12:'Ancêtres universels : '+str(bad),
            13:'Report-Only : '+str('content-security-policy-report-only' in h)+' ; CSP appliquée : '+str(bool(directives)),
            14:'Directives répétées : '+', '.join(duplicates),
            15:'Collecte report-uri / report-to déclarée : '+str(not bad),
        }
        condition(number, 'Navigateur', [True] if bad else [], available, action,
                  'Politique à interpréter dans le navigateur.' if ',' in h.get('content-security-policy', '') else policy_evidence[number] if available else None)
    age = re.search(r'(?:^|;)\s*max-age\s*=\s*(\d+)', h.get('strict-transport-security', ''), re.I)
    condition(16, 'Transport', [True] if headers and (not age or int(age[1]) == 0) else [], bool(headers), 'Activer une durée HSTS positive après validation HTTPS.', na=urlsplit(report['target']).scheme!='https')
    for n,token in [(17,'includesubdomains'),(18,'preload')]:
        emit(n,'Transport','observé' if headers else 'inconnu',token+' : '+str(token in h.get('strict-transport-security','').lower()) if headers else 'Pas de réponse HTML.', 'Valider la portée métier ; ne pas activer automatiquement.')
    valid = {'no-referrer','no-referrer-when-downgrade','origin','origin-when-cross-origin','same-origin','strict-origin','strict-origin-when-cross-origin','unsafe-url'}
    referrers = [p.strip().lower() for p in h.get('referrer-policy','').split(',') if p.strip().lower() in valid]
    condition(19,'Navigateur',[True] if headers and (not referrers or referrers[-1] in ('unsafe-url','no-referrer-when-downgrade')) else [],bool(headers),'Choisir la dernière politique reconnue adaptée aux données et parcours.',detail='Politique effective : '+(referrers[-1] if referrers else 'non déclarée/reconnue'))
    condition(20,'Navigateur',re.findall(r'(?:camera|microphone|geolocation)\s*=\s*\(\s*\*',h.get('permissions-policy',''),re.I),bool(headers),'Restreindre les capacités sensibles aux origines utiles.')
    cookie_rules = [
        (21,lambda c:not c['secure'],'Activer Secure si le cookie doit être limité à HTTPS.'),
        (22,lambda c:not c['http_only'],'Vérifier le besoin JavaScript ; HttpOnly pour les cookies de session sensibles.'),
        (23,lambda c:c['same_site'].lower() not in ('strict','lax','none'),'Définir SameSite selon les parcours légitimes.'),
        (24,lambda c:c['same_site'].lower()=='none' and not c['secure'],'SameSite=None nécessite Secure.'),
        (25,lambda c:c['name'].startswith('__Host-') and (not c['secure'] or c['path']!='/' or c.get('domain_specified',True)),'Respecter Secure, Path=/ et absence de Domain pour __Host-.'),
        (26,lambda c:c['name'].startswith('__Secure-') and not c['secure'],'Respecter Secure pour __Secure-.'),
        (27,lambda c:c.get('domain_specified',False),'Évaluer le partage du cookie entre sous-domaines.'),
        (28,lambda c:False,'Documenter les parcours couverts ; Path ne constitue pas une frontière de sécurité.'),
        (29,lambda c:c.get('expires') is not None and c['expires']-datetime.now(timezone.utc).timestamp()>365*86400,'Évaluer la durée de persistance et le besoin métier.'),
        (30,lambda c:False,'Déterminer si le cookie est sensible ; aucune valeur n’est conservée.'),
    ]
    for number,predicate,action in cookie_rules:
        matches = [c for c in cookies if predicate(c)]
        condition(number,'Cookies',matches,bool(cookies),action,detail=(None if number not in (28,30) else json.dumps([{'name':c['name'],'path':c['path'],'persistent':c.get('expires') is not None} for c in cookies],ensure_ascii=False)))
    resources = [dict(r,page=p['url']) for p in snapshots for r in p['resources']]
    forms = [dict(f,page=p['url']) for p in snapshots for f in p['forms']]
    external = lambda r: bool(r['url']) and urlsplit(r['url']).netloc != urlsplit(r['page']).netloc
    surface_rules = [
        (31,[r for r in resources if urlsplit(r['page']).scheme=='https' and r['url'].startswith('http:') and r['tag'] in ('script','iframe','link')],'Corriger les ressources actives déclarées en HTTP ; vérifier blocages navigateur.'),
        (32,[r for r in resources if urlsplit(r['page']).scheme=='https' and r['url'].startswith('http:') and r['tag'] in ('img','audio','video','source')],'Servir les médias en HTTPS et vérifier le comportement du navigateur.'),
        (33,[f for f in forms if f['action'].startswith('http:')],'Utiliser HTTPS pour les actions de formulaire.'),
        (34,[f for f in forms if f['action'] and urlsplit(f['action']).netloc!=urlsplit(f['page']).netloc],'Valider le prestataire et les données transmises avant approbation.'),
        (35,[f for f in forms if f['password'] and f['method']=='GET'],'Employer POST sur HTTPS pour les mots de passe ; aucune soumission réalisée.'),
        (36,[f for f in forms if f['password_autocomplete_off']],'Évaluer current-password/new-password et la compatibilité des gestionnaires.'),
        (37,[r for r in resources if r['tag']=='script' and external(r) and not r['sri']],'Envisager SRI pour les scripts figés et contrôler les dépendances dynamiques.'),
        (38,[r for r in resources if r['tag']=='link' and r['stylesheet'] and external(r) and not r['sri']],'Envisager SRI pour les feuilles de style figées.'),
        (39,[p for p in snapshots if any(not {'noopener','noreferrer'}.intersection(l['rel']) for l in p['links'])],'Les navigateurs modernes appliquent généralement noopener implicitement ; valider le parc réel.'),
        (40,[r for r in resources if r['tag']=='iframe' and r['sandbox'] is None],'Évaluer le besoin sandbox sans casser les intégrations légitimes.'),
        (41,[r for r in resources if r['tag']=='iframe' and re.search(r'(camera|microphone|geolocation)\s+\*',r['allow'])],'Réduire les permissions iframe aux besoins approuvés.'),
        (42,[p for p in snapshots if p['inline_handlers']],'Préparer le remplacement des gestionnaires inline pour une CSP stricte.'),
        (43,[p for p in snapshots if p['inline_scripts_without_nonce']],'Analyser hashes/nonces et politique effective ; absence de nonce ne prouve pas une XSS.'),
        (44,[r for r in resources if r['tag']=='base' and external(r)],'Valider la base externe et définir base-uri.'),
        (45,[p for p in snapshots if p['insecure_websocket_literals']],'Vérifier les chaînes ws:// et les connexions réellement exécutées ; utiliser wss://.'),
    ]
    for number,matches,action in surface_rules:
        condition(number,'Surface HTML',matches,bool(snapshots),action)
    accepted = [t for t in tls if t.get('status')=='accepté']
    for number,days in [(46,30),(47,7)]:
        condition(number,'Transport',[t for t in accepted if t.get('expires_in_days',9999)<=days],bool(accepted),'Prévoir le renouvellement et vérifier la supervision ACME.',detail='Expiration minimum : '+str(min((t.get('expires_in_days',9999) for t in accepted),default='inconnue'))+' jours')
    condition(48,'Transport',[t for t in accepted if any(n.startswith('*.') for n in t.get('subject_alt_names',[]))],bool(accepted),'Documenter la portée des clés et les usages de certificats wildcard.')
    condition(49,'Transport',[t for t in accepted if not t.get('certificate_verified')],bool(accepted),'Conserver la validation de chaîne et nom ; ne pas ignorer les erreurs.')
    emit(50,'Transport','observé' if accepted else 'inconnu',', '.join(sorted({t['protocol'] for t in accepted})) or 'Aucune négociation réussie.','Seuls TLS 1.2/1.3 sont essayés ; absence de preuve concernant les versions anciennes.')
    cors_available = extended_headers or 'access-control-allow-origin' in h
    condition(51,'CORS',[True] if h.get('access-control-allow-origin')=='*' and h.get('access-control-allow-credentials','').lower()=='true' else [],cors_available,'Combinaison rejetée par le navigateur pour les credentials ; corriger la configuration sans prétendre à une fuite.')
    condition(52,'CORS',[True] if h.get('access-control-allow-origin')=='null' and h.get('access-control-allow-credentials','').lower()=='true' else [],cors_available,'Vérifier les origines null autorisées sur les routes sensibles ; exploitation non démontrée.')
    emit(53,'CORS','observé' if extended_headers or 'access-control-allow-methods' in h else 'inconnu',h.get('access-control-allow-methods','Non déclaré / non archivé.'),'Une méthode déclarée n’est pas une preuve qu’elle est autorisée ; aucun OPTIONS/écriture réalisé.')
    for number,name in [(54,'server'),(55,'x-powered-by')]:
        condition(number,'Exposition',[True] if re.search(r'\d+\.\d+',h.get(name,'')) else [],bool(headers),'Réduire les versions divulguées si inutile ; vérifier le patching en interne.',detail=name+' : '+h.get(name,'non déclaré'))
    condition(56,'Exposition',[p for p in snapshots if p['directory_index']],bool(snapshots),'Vérifier un listing réel et supprimer l’exposition inutile ; titre seul = indice.')
    condition(57,'Exposition',[p for p in snapshots if p['stack_trace']],bool(snapshots),'Désactiver les erreurs détaillées en production ; aucun contenu de trace archivé.')
    origins = sorted({urlsplit(r['url']).netloc for r in resources if external(r)})
    emit(58,'Dépendances','observé' if snapshots else 'inconnu',', '.join(origins) or 'Aucune dépendance enregistrée.','Valider chaque fournisseur, les finalités et le suivi de ses changements.')
    security_headers = ('content-security-policy','strict-transport-security','x-content-type-options','referrer-policy','x-frame-options')
    differences = [name for name in security_headers if len({r['headers'].get(name,'') for r in headers})>1]
    condition(59,'Navigateur',differences,len(headers)>1,'Vérifier les différences par route ; politiques distinctes parfois légitimes.',detail=', '.join(differences) or 'Aucune divergence sur les pages comparables.')
    inv = report.get('inventory',{})
    conflicting = ['WordPress'] if len(inv.get('wordpress',[]))>1 else []
    conflicting += [name for name,versions in report.get('cms_versions',{}).items() if len(versions)>1]
    condition(60,'CMS',conflicting,bool(report.get('cms')),'Comparer aux versions réellement exécutées ; pages statiques/caches peuvent déclarer des versions différentes.',detail=', '.join(conflicting) or 'Aucune contradiction déclarative enregistrée.')
    return controls


def theme(finding):
    value = finding.get('title','').lower()
    if 'routeur' in value or 'api réseau' in value: return 'Routeur et exposition'
    if 'sql' in value: return 'Entrées et données'
    if any(x in value for x in ('hsts','tls','transport','certificat')): return 'Transport'
    if any(x in value for x in ('en-tête','cadrage','frame')): return 'Navigateur'
    if 'cookie' in value: return 'Cookies'
    return 'CMS et exposition'


def analyze(report):
    controls = assess(report)
    is_router = report.get('asset_profile', {}).get('kind') == 'routeur'
    register = report.get('risk_register',[])
    groups = defaultdict(list)
    evidence_index = []
    as_of = datetime.fromisoformat(report['generated_utc'])
    try:
        started = datetime.fromisoformat(report.get('started_utc',report['generated_utc']))
    except (TypeError, ValueError):
        started = as_of
    if started.tzinfo is None: started=started.replace(tzinfo=timezone.utc)
    age = max(0,(as_of-started).days)
    for f in register:
        f['theme'] = theme(f)
        if is_router:
            f['owner'] = 'Opérateur télécom / administrateur réseau'
            for field in ('remediation', 'condition', 'closure'):
                value = f.get(field, '')
                f[field] = (value.replace('du site', 'de l’interface locale')
                                  .replace('routes applicatives', 'routes de l’interface')
                                  .replace('parcours fonctionnels', 'parcours de l’interface')
                                  .replace('pages sensibles', 'pages d’administration'))
        qualification = f.get('qualification','').lower()
        f['evidence_level'] = 'déclaration humaine étayée' if 'confirmé' in qualification and f.get('validator') and f.get('closure_evidence') else 'correspondance source à valider' if 'correspondance' in qualification else 'indice' if 'indice' in qualification else 'mesure publique'
        severity = f.get('severity','Info')
        f['triage'] = 'P1 — qualifier sous 7 jours' if severity in ('Haute','Critique') or f['theme']=='Entrées et données' else 'P2 — planifier sous 30 jours' if severity=='Moyenne' else 'P3 — durcir selon fenêtre de changement'
        f['triage_reasons'] = [f'Gravité technique source : {severity}', 'Preuve : '+f['evidence_level'], 'Impact métier : '+report.get('business_context',{}).get('criticality','non renseigné — sans surclassement automatique')]
        if is_router:
            f['effort'] = 'changement firmware/configuration et contre-test — à coordonner avec l’opérateur'
            f['dependencies'] = 'Attestation firmware, sauvegarde de configuration et fenêtre réseau approuvée'
        else:
            f['effort'] = 'à estimer avec le prestataire' if f['theme'] in ('Entrées et données','CMS et exposition') else 'configuration et tests de non-régression — estimation à valider'
            f['dependencies'] = 'Qualification sur staging et inventaire exécuté' if f['theme'] in ('Entrées et données','CMS et exposition') else 'Validation des usages puis fenêtre hébergement'
        f['validation_steps'] = [f.get('condition','Confirmer le périmètre'), 'Documenter le changement approuvé', f.get('closure','Recontrôle ciblé')]
        f['evidence_age_days'] = age
        f['evidence_ids'] = [f'E{i+1:03}' for i,q in enumerate(report.get('requests',[])) if q['url'] in f.get('source_urls',[f.get('url')])]
        groups[f['theme']].append(f)
    for i,q in enumerate(report.get('requests',[])):
        evidence_index.append({'id':f'E{i+1:03}','url':public_url(q['url']),'at_utc':q.get('at_utc'),'sha256':q.get('sha256'), 'status':q.get('status'),'historical':bool(q.get('historical'))})
    tls_records=report.get('tools',{}).get('tls',{}).get('handshakes',[])
    for i,t in enumerate(tls_records):
        evidence_index.append({'id':f'T{i+1:03}','url':public_url(report['target']),
            'at_utc':report.get('finished_utc'), 'sha256':t.get('certificate_sha256'),
            'status':t.get('status'),'historical':bool(report.get('resume_history')),
            'meaning':'Négociation TLS '+str(t.get('requested',''))+' ; horodatage de fin de collecte, pas de la connexion.'})
    for c in controls:
        tls_control=46<=int(c['id'][1:])<=50
        c['evidence_ids']=[q['id'] for q in evidence_index if q['url']==c['url'] and q['id'].startswith('T' if tls_control else 'E')]
    counts = dict(Counter(c['state'] for c in controls))
    matrix = {domain:dict(Counter(c['state'] for c in controls if c['domain']==domain)) for domain in sorted({c['domain'] for c in controls})}
    roadmap = [{'theme':name,'finding_ids':[f['id'] for f in rows], 'control_ids':[c['id'] for c in controls if c['domain']==name and c['state']=='à revoir'],
        'owner':rows[0]['owner'],'action':'; '.join(dict.fromkeys(f['remediation'] for f in rows)),
        'validation':' / '.join(dict.fromkeys(f['dependencies'] for f in rows)), 'effort':rows[0]['effort'],
        'window':'7 jours : qualifier' if any(f['triage'].startswith('P1') for f in rows) else '30 jours : planifier', 'closure':'Recontrôler chaque ID ; une action groupée ne clôture pas automatiquement les constats.'}
        for name,rows in groups.items()]
    # Les indices passifs nouveaux restent des contrôles à qualifier, sans gravité inventée.
    existing_themes = {g['theme'] for g in roadmap}
    for domain in sorted({c['domain'] for c in controls if c['state']=='à revoir'} - existing_themes):
        rows = [c for c in controls if c['domain']==domain and c['state']=='à revoir']
        roadmap.append({'theme':domain,'finding_ids':[],'control_ids':[c['id'] for c in rows],
            'owner':('Administrateur réseau / opérateur — à confirmer' if is_router else 'Responsable applicatif / hébergement — à confirmer'),
            'action':'; '.join(dict.fromkeys(c['action'] for c in rows)),
            'validation':'Qualifier les contrôles passifs avant toute conclusion d’exploitation.',
            'effort':'à estimer après qualification','window':'30 jours : qualifier / planifier',
            'closure':'Recontrôler les contrôles cités et archiver la mesure ; aucune clôture automatique.'})
    decisions = []
    if report.get('analysis_obstacles'):
        decisions.append({'title':'Restaurer la couverture empêchée','reason':str(len(report['analysis_obstacles']))+' obstacle(s) documenté(s)',
                          'action':('Prévoir une fenêtre LAN et coordonner le contre-test avec l’opérateur.' if is_router else 'Prévoir fenêtre/IP autorisée ou staging avec l’hébergeur.'),
                          'owner':('RSSI et administrateur réseau' if is_router else 'RSSI et hébergeur'), 'conservative_measure':'Conserver les constats antérieurs ouverts tant que les contrôles manquent.'})
    for group in roadmap:
        decisions.append({'title':group['theme'],'reason':('Constats '+', '.join(group['finding_ids']) if group['finding_ids'] else 'Contrôles à qualifier '+', '.join(group['control_ids'])), 'action':group['action'],'owner':group['owner'], 'conservative_measure':'Vérifier le suivi des journaux et les mises à jour ; aucune mesure automatique appliquée.'})
    internal = ([
        ('Firmware, modèle et support','Opérateur / administrateur réseau','Version installée, bulletin fournisseur et état des correctifs'),
        ('Administration et comptes','Administrateur réseau','Mot de passe unique, administration WAN désactivée et revue des accès'),
        ('Segmentation LAN','Administrateur réseau','Tests datés depuis LAN principal, invité et IoT'),
        ('Sauvegarde et restauration','Exploitation','Sauvegarde de configuration et procédure de restauration validée'),
        ('Journalisation et incidents','SOC / exploitation','Journaux disponibles, alertes et procédure de remplacement/reprise'),
    ] if is_router else [
        ('Versions exécutées et support','Administrateur CMS','Inventaire administratif, versions et bulletins éditeur'),
        ('Accès et MFA','Responsable IAM','Matrice des rôles, MFA administrateurs et revue des comptes'),
        ('Sauvegarde et restauration','Exploitation','Dernier test de restauration daté, RTO/RPO validés'),
        ('Journalisation et incidents','SOC / exploitation','Rétention, alertes et exercice de réponse'),
        ('Revue applicative authentifiée','Prestataire','Scénarios autorisés IDOR/CSRF/XSS/SQL sur staging'),
    ])
    gaps = []
    if not report.get('page_observations'): gaps.append('Résumés HTML absents : contrôles de surface inconnus ; re-scan nécessaire pour ces contrôles.')
    if not report.get('business_context',{}).get('criticality'): gaps.append('Criticité métier non renseignée.')
    if not report.get('business_context',{}).get('data_sensitivity'): gaps.append('Sensibilité des données non renseignée.')
    if age>30: gaps.append('Mesures âgées de plus de 30 jours : fraîcheur à réévaluer.')
    deadlines=[]
    contradictions=[]
    for f in register:
        due=datetime.strptime(f['proposed_due_date'],'%Y-%m-%d').date()
        if due<as_of.date() and not f['treatment_status'].lower().startswith('clos'):
            deadlines.append({'id':f['id'],'days_overdue':(as_of.date()-due).days,'owner':f['owner']})
        if f['treatment_status'].lower().startswith('clos') and not f.get('closure_evidence'):
            contradictions.append(f['id']+' : statut clos déclaré sans preuve de clôture.')
    latency=sorted(q['duration_ms'] for q in report.get('requests',[]) if isinstance(q.get('duration_ms'),(int,float)) and not q.get('historical'))
    network={'measured_requests':len(latency),'median_ms':median(latency) if latency else None,
             'p95_ms':latency[max(0,math.ceil(.95*len(latency))-1)] if latency else None,
             'http_counts':dict(Counter(str(q.get('status')) for q in report.get('requests',[]) if not q.get('historical'))),
             'meaning':'Durées client incluant réseau/proxy ; ce n’est pas un test de charge.'}
    report['intelligence']={'schema':'hackscan.intelligence/1','engine':'règles déterministes v4 — sans appel IA externe',
        'controls':controls,'control_counts':counts,'domain_matrix':matrix,'roadmap':roadmap,'decisions':decisions,
        'campaigns':[{'window':'7 jours','action':'Qualifier les indices prioritaires et lever les blocages'}, {'window':'30 jours','action':'Déployer les corrections validées et tester les parcours'}, {'window':'90 jours','action':'Compléter les preuves internes et renouveler la revue'}],
        'internal_evidence':[{'domain':a,'owner':b,'proof':c,'state':'non vérifié'} for a,b,c in internal],
        'evidence_age_days':age,'evidence_index':evidence_index,'gaps':gaps,'network':network,
        'deduplication':{'raw_findings':len(report.get('findings',[])),'grouped_findings':len(register),'action_groups':len(roadmap)},
        'deadline_alerts':deadlines,'contradictions':contradictions,'catalogue':CATALOGUE,
        'assurance':'Le diagramme décrit des contrôles évalués, jamais un score de sécurité.'}
    report['intelligence']['id']=hashlib.sha256(json.dumps({'target':report['target'],'started':report.get('started_utc')},sort_keys=True).encode()).hexdigest()[:16]
    return report
