#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ! -x .venv/bin/python ]] || ! .venv/bin/python -c 'import requests, socks, reportlab' >/dev/null 2>&1; then
  echo 'Installation locale des dépendances…'
  ./install.sh
fi
exec .venv/bin/python hackscan.py --interactive --offer-report-management "$@"
