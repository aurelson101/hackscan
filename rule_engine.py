"""Règles YAML bornées ; extensions externes obligatoirement signées Ed25519."""
import base64
import hashlib
from pathlib import Path
import re

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


ALLOWED_PROFILES = {'wordpress', 'joomla', 'drupal', 'router-generic', 'router-bouygues', 'router-orange'}


def _validate(rule):
    required = {'id', 'profile', 'method', 'path', 'risk', 'purpose'}
    if not isinstance(rule, dict) or not required <= set(rule):
        raise ValueError('Règle incomplète')
    if rule['profile'] not in ALLOWED_PROFILES or rule['method'] != 'GET' or rule['risk'] not in ('passif', 'faible'):
        raise ValueError('Règle hors politique')
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{2,79}', str(rule['id'])) or len(str(rule['purpose'])) > 200:
        raise ValueError('Identifiant ou objectif de règle invalide')
    if not isinstance(rule['path'], str) or not re.fullmatch(r'[A-Za-z0-9._~!$&()*+,;=:@%/-]{1,240}', rule['path']) or '..' in rule['path']:
        raise ValueError('Chemin de règle invalide')
    return {key: str(rule[key]) for key in required}


def _read_rules(path):
    data = yaml.safe_load(Path(path).read_text(encoding='utf-8'))
    if not isinstance(data, dict) or data.get('schema') != 1 or not isinstance(data.get('rules'), list):
        raise ValueError('Schéma de règles invalide')
    return [_validate(rule) for rule in data['rules']]


def _verify_signature(path, signature_path, public_key_path):
    key = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError('Clé publique Ed25519 requise')
    key.verify(base64.b64decode(Path(signature_path).read_text().strip(), validate=True), Path(path).read_bytes())


def load_rules(external_dir=None, public_key=None):
    root = Path(__file__).resolve().parent / 'rules'
    builtin = root / 'builtin.yaml'
    expected = (root / 'builtin.yaml.sha256').read_text().split()[0]
    actual = hashlib.sha256(builtin.read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError('Intégrité des règles intégrées invalide')
    rules = _read_rules(builtin)
    if external_dir:
        if not public_key:
            raise ValueError('Clé publique requise pour les règles externes')
        for path in sorted(Path(external_dir).glob('*.yaml')):
            if path.is_symlink():
                raise ValueError('Lien symbolique de règle externe refusé')
            _verify_signature(path, path.with_suffix(path.suffix + '.sig'), public_key)
            rules.extend(_read_rules(path))
    identifiers = [r['id'] for r in rules]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError('Identifiant de règle dupliqué')
    return rules


def paths_for(rules, profile):
    return tuple(rule['path'].lstrip('/') for rule in rules if rule['profile'] == profile)


def sign_rule(path, private_key_path):
    key = serialization.load_pem_private_key(Path(private_key_path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError('Clé privée Ed25519 requise')
    signature = Path(path).with_suffix(Path(path).suffix + '.sig')
    signature.write_text(base64.b64encode(key.sign(Path(path).read_bytes())).decode() + '\n', encoding='utf-8')
    signature.chmod(0o600)
    return signature

