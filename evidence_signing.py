"""Signature Ed25519 explicite des livrables et création de clé protégée."""
import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate_key(path):
    path = Path(path)
    if path.exists():
        raise ValueError('Le fichier de clé existe déjà')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    path.chmod(0o600)
    public_path = path.with_suffix(path.suffix + '.pub')
    public_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    public_path.chmod(0o600)
    return path


def sign_manifest(output, key_path):
    output, key_path = Path(output), Path(key_path)
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError('Clé privée Ed25519 requise')
    manifest = (output / 'manifest.sha256').read_bytes()
    signature = key.sign(manifest)
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    key.public_key().verify(signature, manifest)
    files = {'manifest.sig': base64.b64encode(signature).decode(), 'manifest.pub': public.decode(),
             'manifest-signature.json': json.dumps({'algorithm': 'Ed25519', 'signed_file': 'manifest.sha256', 'verified_after_signing': True}, indent=2)}
    for name, content in files.items():
        path = output / name; path.write_text(content, encoding='utf-8'); path.chmod(0o600)
    return {'status': 'signé et vérifié', 'algorithm': 'Ed25519', 'private_key_retained_in_report': False}

