"""Inventaire TCP local borné, sans bannière, identifiant ni exploitation."""
import ipaddress
import socket
import time
from urllib.parse import urlsplit

from router_profiles import private_target


PORTS = (22, 23, 53, 80, 443, 8080, 8443)


def inventory_router_services(url, timeout=.6, budget=8):
    if not private_target(url):
        raise ValueError('Inventaire de services limité aux cibles locales')
    host = urlsplit(url).hostname
    addresses = {row[4][0].split('%', 1)[0] for row in socket.getaddrinfo(host, None)}
    local = [value for value in addresses if (ipaddress.ip_address(value).is_private or ipaddress.ip_address(value).is_loopback or ipaddress.ip_address(value).is_link_local)]
    if not local:
        raise ValueError('Aucune adresse locale figée pour l’inventaire')
    address = sorted(local)[0]
    deadline = time.monotonic() + budget
    rows = []
    for port in PORTS:
        if time.monotonic() >= deadline:
            break
        state = 'fermé ou filtré'
        try:
            with socket.create_connection((address, port), timeout=min(timeout, max(.1, deadline-time.monotonic()))):
                state = 'ouvert'
        except OSError:
            pass
        rows.append({'port': port, 'transport': 'tcp', 'state': state})
    return {'status': 'terminé' if len(rows) == len(PORTS) else 'partiel', 'services': rows,
            'resolved_address_retained': False,
            'policy': 'TCP connect sur 7 ports de gestion usuels ; aucune bannière, authentification ou exploitation.'}

