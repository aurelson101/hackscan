#!/usr/bin/env python3
"""Signer une règle YAML externe avec une clé Ed25519 hors du dépôt."""
import argparse
from pathlib import Path

from evidence_signing import generate_key
from rule_engine import sign_rule


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init-key'); init.add_argument('path', type=Path)
    sign = sub.add_parser('sign'); sign.add_argument('rule', type=Path); sign.add_argument('--key', type=Path, required=True)
    args = parser.parse_args()
    try:
        path = generate_key(args.path) if args.command == 'init-key' else sign_rule(args.rule, args.key)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(path.resolve())
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
