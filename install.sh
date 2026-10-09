#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

mode="${1:-}"
case "$mode" in ''|--check|--wpscan|--nuclei|--full) ;; *) echo 'Usage: ./install.sh [--check|--wpscan|--nuclei|--full]' >&2; exit 2;; esac

user_home="$(getent passwd "$(id -un)" | cut -d: -f6)"
user_bin="${XDG_BIN_HOME:-$user_home/.local/bin}"
export PATH="$user_bin:$PATH"

check_installation() {
  for command_name in python3 nmap sqlmap wpscan nuclei; do
    if command -v "$command_name" >/dev/null; then
      printf '%-8s OK  %s\n' "$command_name" "$(command -v "$command_name")"
    else
      printf '%-8s ABSENT\n' "$command_name"
    fi
  done
  [[ -x .venv/bin/python ]] && echo 'venv     OK' || echo 'venv     ABSENT'
  [[ -n "${OPENAI_API_KEY:-}" ]] && echo 'OpenAI   clé configurée' || echo 'OpenAI   clé absente (facultatif)'
  [[ -n "${MISTRAL_API_KEY:-}" ]] && echo 'Mistral  clé configurée' || echo 'Mistral  clé absente (facultatif)'
}

if [[ "$mode" == '--check' ]]; then
  check_installation
  exit 0
fi

if [[ "$mode" == '--full' ]]; then
  [[ -r /etc/os-release ]] || { echo 'Distribution Debian/Ubuntu requise pour --full.' >&2; exit 1; }
  . /etc/os-release
  case "${ID:-}:${ID_LIKE:-}" in ubuntu:*|debian:*|*:debian*) ;; *) echo 'Distribution Debian/Ubuntu requise pour --full.' >&2; exit 1;; esac
  if [[ "${ID:-}" != ubuntu || "${VERSION_ID:-}" != 26.04 ]]; then
    echo "Note : procédure conçue pour Ubuntu 26.04 ; système détecté : ${PRETTY_NAME:-inconnu}."
  fi
  packages=(python3 python3-venv python3-pip ca-certificates git ruby-full ruby-dev build-essential libcurl4-openssl-dev zlib1g-dev sqlmap nmap golang-go tor)
  missing=()
  for package in "${packages[@]}"; do dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed' || missing+=("$package"); done
  if ((${#missing[@]})); then
    sudo -v
    sudo apt-get update
    sudo apt-get install -y --no-install-recommends "${missing[@]}"
  fi
fi

command -v python3 >/dev/null || { echo 'Python 3 est requis.' >&2; exit 1; }
[[ -x .venv/bin/python ]] || python3 -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt

if [[ "$mode" == '--wpscan' || "$mode" == '--full' ]]; then
  command -v gem >/dev/null || { echo 'Ruby et ses outils de compilation sont requis.' >&2; exit 1; }
  if ! command -v wpscan >/dev/null; then
    gem install --user-install wpscan --no-document
    gem_bin="$(ruby -r rubygems -e 'puts Gem.user_dir')/bin"
    export PATH="$gem_bin:$PATH"
    echo "WPScan installé dans $gem_bin"
  fi
  wpscan --update
fi

if [[ "$mode" == '--nuclei' || "$mode" == '--full' ]]; then
  command -v go >/dev/null || { echo 'Go est requis pour installer Nuclei.' >&2; exit 1; }
  mkdir -p -- "$user_bin"
  nuclei_version="${NUCLEI_VERSION:-v3.11.1}"
  GOBIN="$user_bin" go install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@$nuclei_version"
  "$user_bin/nuclei" -update-templates
fi

printf '\nPrêt : .venv/bin/python hackscan.py https://www.defta.eu --authorized --direct\n'
printf 'Diagnostic : ./install.sh --check ; suite complète Ubuntu : ./install.sh --full\n'
printf 'IA facultative : --ai-provider ollama|openai|mistral. Aucun serveur ni base de données n’est activé.\n'
