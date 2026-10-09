"""Installation Tor, instance utilisateur isolée et validation de sortie sans repli."""
import argparse
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time

import requests
from checks import proxy_preflight

CHECK_URL = 'https://check.torproject.org/api/ip'


def check_route(proxy, timeout=15):
    """N'envoyer la requête de vérification que via SOCKS ; ne conserver aucune IP."""
    proxy_preflight(proxy, min(timeout, 3))
    with requests.Session() as session:
        session.trust_env = False
        session.proxies = {'http': proxy, 'https': proxy}
        with session.get(CHECK_URL, timeout=timeout, allow_redirects=False, stream=True) as response:
            if response.status_code != 200:
                raise RuntimeError('Vérification Tor Project : HTTP '+str(response.status_code))
            body = bytearray()
            for chunk in response.iter_content(1024):
                body.extend(chunk)
                if len(body)>8192:
                    raise RuntimeError('Réponse de vérification Tor trop volumineuse')
            import json
            data = json.loads(body)
            if not isinstance(data, dict) or data.get('IsTor') is not True:
                raise RuntimeError('Le service de vérification ne confirme pas une sortie Tor ; scan bloqué.')
    return {'status':'terminé', 'is_tor':True, 'proxy':proxy, 'source':CHECK_URL,
            'detail':'Sortie Tor attestée par Tor Project via le proxy ; aucune IP conservée. Pas de garantie globale d’anonymat.'}


def install_tor():
    if not shutil.which('apt-get'):
        raise RuntimeError('Installation automatique disponible sur Debian/Ubuntu ; installer tor avec le gestionnaire système puis relancer ./tor.sh.')
    prefix=[]
    if os.geteuid()!=0:
        if not shutil.which('sudo'):
            raise RuntimeError('Installation Tor : sudo requis. Relancer ./tor.sh depuis un compte administrateur.')
        prefix=['sudo'] if sys.stdin.isatty() else ['sudo','-n']
    print('Installation du paquet Tor via les dépôts du système (sudo peut demander votre mot de passe).',flush=True)
    subprocess.run(prefix+['apt-get','update'],check=True)
    subprocess.run(prefix+['apt-get','install','-y','--no-install-recommends','tor'],check=True)
    binary=shutil.which('tor')
    if not binary:
        for path in ('/usr/bin/tor','/usr/sbin/tor'):
            if Path(path).is_file() and os.access(path,os.X_OK): return path
        raise RuntimeError('Paquet installé mais exécutable Tor introuvable.')
    return binary


def port_in_use(port):
    try:
        with socket.create_connection(('127.0.0.1',port),timeout=.5): return True
    except OSError:
        return False


def quoted(path):
    value=str(path)
    if '\n' in value or '\r' in value:
        raise ValueError('Chemin de configuration invalide')
    return '"'+value.replace('\\','\\\\').replace('"','\\"')+'"'


def start_local(binary, port, state_dir):
    directory=Path(state_dir)/str(port)
    directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    directory.chmod(0o700)
    data=directory/'data';data.mkdir(exist_ok=True,mode=0o700);data.chmod(0o700)
    config=directory/'torrc'
    content='\n'.join([
        '# Instance client privée Hackscan ; aucune modification de /etc/tor/torrc',
        f'SocksPort 127.0.0.1:{port}', 'SocksPolicy accept 127.0.0.1', 'SocksPolicy reject *',
        'ClientOnly 1', 'ORPort 0', 'ControlPort 0', 'SafeSocks 1', 'AvoidDiskWrites 1',
        'DataDirectory '+quoted(data), 'PidFile '+quoted(directory/'tor.pid'),
        'Log '+quoted('notice file '+str(directory/'notice.log')), 'RunAsDaemon 1', '',
    ])
    if not config.exists():
        config.write_text(content,encoding='utf-8')
    config.chmod(0o600)
    # Lecture/validation avant démarrage, sans arrêter les services déjà présents.
    subprocess.run([binary,'-f',str(config),'--verify-config'],check=True,timeout=15)
    subprocess.run([binary,'-f',str(config)],check=True,timeout=20)
    return directory


def bootstrap_progress(directory):
    if not directory: return ''
    import re
    path=directory/'notice.log'
    try:
        with path.open('rb') as stream:
            stream.seek(max(0,path.stat().st_size-8192))
            matches=re.findall(rb'Bootstrapped (\d+)%',stream.read())
        return 'Bootstrap Tor : '+matches[-1].decode()+' %' if matches else 'Connexion au réseau Tor…'
    except OSError:
        return 'Connexion au réseau Tor…'


def ensure_tor(port=9050, wait=90, *, check_only=False, state_dir=None):
    if not isinstance(port,int) or not 1024<=port<=65535:
        raise ValueError('Port Tor attendu entre 1024 et 65535')
    if not 5<=wait<=300:
        raise ValueError('Attente Tor attendue entre 5 et 300 secondes')
    proxy=f'socks5h://127.0.0.1:{port}'
    state_dir=state_dir or Path.home()/'.local/state/hackscan/tor'
    directory=None
    if port_in_use(port):
        # Un autre programme peut occuper le port : ne jamais le remplacer ni le tuer.
        proxy_preflight(proxy)
        print(f'Proxy SOCKS existant détecté sur 127.0.0.1:{port}.',flush=True)
    elif check_only:
        raise RuntimeError(f'Aucun proxy sur 127.0.0.1:{port}. Exécuter ./tor.sh pour préparer Tor.')
    else:
        try:
            binary=shutil.which('tor') or install_tor()
            # Le paquet Debian peut démarrer son service automatiquement lors de l'installation.
            if port_in_use(port):
                proxy_preflight(proxy)
                print('Proxy démarré par le système détecté ; réutilisation après validation.',flush=True)
            else:
                print('Démarrage d’une instance Tor utilisateur ; configuration locale privée.',flush=True)
                directory=start_local(binary,port,state_dir)
        except subprocess.SubprocessError as exc:
            raise RuntimeError('Installation/démarrage Tor en échec : '+str(exc)+'. Exécuter ./tor.sh dans un terminal pour les éventuels droits sudo.') from exc
    deadline=time.monotonic()+wait
    last_error='connexion non établie'
    while time.monotonic()<deadline:
        try:
            result=check_route(proxy,min(15,max(.1,deadline-time.monotonic())))
            result['instance']='service SOCKS existant' if directory is None else 'instance utilisateur Hackscan'
            print('Sortie réseau Tor confirmée. Proxy : '+proxy,flush=True)
            return result
        except (requests.RequestException,OSError,ValueError,RuntimeError) as exc:
            last_error=str(exc)
            if 'ne confirme pas' in last_error:
                raise RuntimeError(last_error) from exc
            print((bootstrap_progress(directory) or 'Attente d’une sortie Tor fonctionnelle…')+' '+last_error,flush=True)
            remaining=deadline-time.monotonic()
            if remaining>0:time.sleep(min(2,remaining))
    raise RuntimeError('Tor non validé dans le délai : '+last_error+' Aucun trafic cible envoyé. Vérifier le réseau ou relancer ./tor.sh --wait 180.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true',help='Vérifier sans installation ni démarrage')
    parser.add_argument('--port',type=int,default=9050)
    parser.add_argument('--wait',type=int,default=90)
    args=parser.parse_args()
    os.umask(0o077)
    try:
        ensure_tor(args.port,args.wait,check_only=args.check)
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError,KeyboardInterrupt) as exc:
        print('Tor : '+str(exc),file=sys.stderr)
        return 1
    print('Prêt : ./lancer.sh --tor --tor-port '+str(args.port))
    return 0


if __name__=='__main__':raise SystemExit(main())
