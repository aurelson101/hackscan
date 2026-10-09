"""Profils routeur locaux, bornés et non authentifiés (GET uniquement)."""
import ipaddress
import json
import re
import socket
from urllib.parse import urljoin, urlsplit

import requests
from rule_engine import load_rules, paths_for


TARGET_PROFILES = (
    'auto', 'web-generic', 'wordpress', 'joomla',
    'router-generic', 'router-bouygues', 'router-orange',
)

SENSITIVE_BBOX = {
    'api/v1/summary', 'api/v1/hosts/lite', 'api/v1/wan/ip',
    'api/v1/wireless/wps',
}

SAFE_SCHEMA_KEYS = {
    'alerts', 'authenticated', 'code', 'cpl', 'diags', 'display', 'dnsservers',
    'domain', 'enable', 'errors', 'exception', 'gateway', 'hostname', 'hosts',
    'id', 'internet', 'ipaddress', 'iptv', 'link', 'mac', 'macaddress', 'now',
    'services', 'state', 'subnet', 'timeout', 'usb', 'voip', 'wan', 'wireless', 'wps',
}


def private_target(url):
    """Valide une cible locale ; Bbox peut publier aussi l'IPv6 LAN globale du routeur."""
    host = urlsplit(url).hostname
    if not host:
        return False
    try:
        addresses = {row[4][0].split('%', 1)[0] for row in socket.getaddrinfo(host, None)}
        parsed = [ipaddress.ip_address(value) for value in addresses]
    except (OSError, ValueError):
        return False
    local = [ip.is_private or ip.is_loopback or ip.is_link_local for ip in parsed]
    if host.lower() == 'mabbox.bytel.fr':
        return any(local)
    return bool(parsed) and all(local)


def effective_profile(url, cms_names=(), requested='auto'):
    if requested != 'auto':
        return requested
    names = set(cms_names)
    if 'WordPress' in names:
        return 'wordpress'
    if 'Joomla' in names:
        return 'joomla'
    host = (urlsplit(url).hostname or '').lower()
    if host == 'mabbox.bytel.fr' or host.endswith('.mabbox.bytel.fr'):
        return 'router-bouygues'
    if host == 'livebox' or host.endswith('.livebox') or host.endswith('.livebox.home'):
        return 'router-orange'
    return 'web-generic'


def _keys(value, depth=0):
    found = set()
    if isinstance(value, dict):
        found.update(str(key)[:80] for key in value)
        if depth < 3:
            for child in value.values():
                found.update(_keys(child, depth + 1))
    elif isinstance(value, list) and value and depth < 3:
        found.update(_keys(value[0], depth + 1))
    return found


def _max_list_items(value, depth=0):
    if depth > 3:
        return 0
    if isinstance(value, list):
        children = (_max_list_items(child, depth + 1) for child in value[:3])
        return max([len(value), *children])
    if isinstance(value, dict):
        return max((_max_list_items(child, depth + 1) for child in value.values()), default=0)
    return 0


def json_schema(body):
    """Résumé de structure uniquement ; aucune valeur issue de la cible."""
    try:
        value = json.loads(body)
    except (TypeError, json.JSONDecodeError):
        return {'format': 'non JSON', 'items': 0, 'max_list_items': 0, 'keys': [], 'other_key_count': 0}
    if isinstance(value, list):
        items = len(value)
        root = 'liste'
    elif isinstance(value, dict):
        items = len(value)
        root = 'objet'
    else:
        items = 1
        root = type(value).__name__
    raw_keys = {key.lower() for key in _keys(value) if re.fullmatch(r'[A-Za-z0-9_.:-]{1,80}', key)}
    keys = sorted(raw_keys & SAFE_SCHEMA_KEYS)
    return {'format': 'JSON ' + root, 'items': items, 'max_list_items': _max_list_items(value),
            'keys': keys, 'other_key_count': len(raw_keys - SAFE_SCHEMA_KEYS)}


def run_router_checks(scanner, profile, rules=None):
    if profile not in TARGET_PROFILES or not profile.startswith('router-'):
        raise ValueError('Profil routeur inconnu')
    if not private_target(scanner.url):
        raise ValueError('Profil routeur refusé : la cible résolue doit être locale')

    vendor = {'router-bouygues': 'Bouygues/Bbox', 'router-orange': 'Orange/Livebox',
              'router-generic': 'Routeur local générique'}[profile]
    scanner.report['asset_profile'] = {'requested': profile, 'effective': profile, 'kind': 'routeur'}
    inventory, exposed = [], []
    scanner.report.setdefault('limitations', []).extend([
        'Profil routeur : GET uniquement, sans authentification, POST, brute force, WPS PIN, déni de service ni changement de configuration.',
        'Aucune valeur IP, MAC, nom d’hôte, SSID, jeton ou corps de réponse routeur n’est conservé dans les livrables.',
        'Le profil HTTP routeur ne constitue pas un balayage exhaustif des ports, services, protocoles radio ou interfaces WAN.',
    ])
    scanner.report.setdefault('configuration', {}).update({
        'target_profile': profile,
        'router_vendor': vendor,
        'router_method': 'GET sans cookie sur une liste fixe de routes ; corps expurgés',
    })

    for path in paths_for(rules or load_rules(), profile):
        url = urljoin(scanner.url, '/' + path)
        scanner.session.cookies.clear()
        try:
            page = scanner.get(url)
        except (requests.RequestException, ValueError, RuntimeError) as exc:
            scanner.report['checks'].append({'category': 'Routeur', 'name': '/' + path,
                'url': url, 'status': 'non vérifié', 'evidence': str(exc)})
            if 'budget' in str(exc).lower() or '429' in str(exc):
                break
            continue

        status = page['status']
        schema = json_schema(page['body'])
        entry = {'path': '/' + path, 'http_status': status, **schema}
        inventory.append(entry)
        if status in (401, 403):
            state = 'contrôle d’accès observé'
        elif status == 404:
            state = 'route non observée'
        elif status == 405:
            state = 'méthode GET refusée'
        elif status == 200:
            state = 'accessible sans identifiants fournis'
        else:
            state = 'réponse HTTP reçue'
        evidence = 'HTTP ' + str(status) + ' · ' + schema['format']
        if schema['format'].startswith('JSON'):
            evidence += ' · ' + str(schema['items']) + ' élément(s) racine · liste imbriquée max. ' + str(schema['max_list_items']) + ' · champs autorisés : ' + (', '.join(schema['keys']) or 'aucun') + ' · autres noms masqués : ' + str(schema['other_key_count'])
        scanner.report['checks'].append({'category': 'Routeur', 'name': '/' + path,
            'url': page['url'], 'status': state, 'evidence': evidence})
        if profile == 'router-bouygues' and path in SENSITIVE_BBOX and status == 200 and schema['format'].startswith('JSON'):
            exposed.append(entry)
        if status >= 500:
            scanner.report['limitations'].append('Arrêt du profil routeur après HTTP ' + str(status) + ' sur /' + path + '.')
            break

    scanner.report['router_inventory'] = inventory
    scanner.report['tools']['router_profile'] = {
        'status': 'terminé' if inventory else 'incomplet',
        'profile': profile,
        'vendor': vendor,
        'routes_checked': len(inventory),
        'retained_values': 'schéma, nombre d’éléments et noms de champs uniquement',
    }
    if exposed:
        proof = '; '.join(row['path'] + ' HTTP 200 (' + row['format'] + ', ' + str(row['items']) + ' élément(s) racine, liste imbriquée max. ' + str(row['max_list_items']) + ', champs autorisés : ' + ', '.join(row['keys']) + ', autres noms masqués : ' + str(row['other_key_count']) + ')' for row in exposed)
        scanner.finding('Moyenne', 'API routeur accessibles sans authentification', proof,
            'Imposer une session aux routes d’inventaire et de diagnostic, minimiser les champs avant authentification et isoler les réseaux invité/IoT.',
            confidence='confirmé par réponse GET sans cookie')
    return inventory
