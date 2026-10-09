# Hackscan

[![Licence: Apache-2.0](https://img.shields.io/badge/Licence-Apache--2.0-blue.svg)](LICENSE)
[![Python 3](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)](https://www.python.org/)
[![Tests](https://github.com/aurelson101/hackscan/actions/workflows/tests.yml/badge.svg)](https://github.com/aurelson101/hackscan/actions/workflows/tests.yml)

> Utilisation exclusivement autorisée, bornée et non destructive. Vous êtes responsable du périmètre et des autorisations applicables.

Audit externe autorisé, avec scanner gratuit autonome, WPScan facultatif et sqlmap facultatif. Rapports HTML autonomes et JSON privés. Aucun mot de passe nécessaire à l'installation locale ; aucun secret inclus dans les fichiers.

## Version 5 : orchestration professionnelle

Le script principal intègre désormais un planificateur adaptatif explicable, des coupe-circuits, des règles YAML bornées, la corrélation facultative CISA KEV/FIRST EPSS, un adaptateur Nuclei sûr, une matrice authentifiée GET, un inventaire TCP local de routeur, les exports SARIF/CycloneDX, la signature Ed25519 et un conseiller IA facultatif. Ces fonctions n'activent jamais automatiquement de brute force, fuzzing, OAST, code distant, changement de configuration ou exploitation.

```bash
# Pipeline adaptatif standard et rapports automatiques
./lancer.sh

# Nuclei : binaire préinstallé, modèles signés, HTTP à 2 req/s
./lancer.sh https://www.defta.eu --authorized --direct --nuclei-safe

# Comparaison authentifiée : secrets uniquement dans l'environnement
export HACKSCAN_USER_TOKEN='valeur-temporaire'
./lancer.sh https://exemple.test --authorized --direct \
  --auth-token-env user=HACKSCAN_USER_TOKEN --auth-url https://exemple.test/compte
unset HACKSCAN_USER_TOKEN

# Routeur local : GET spécifique et sept ports TCP, sans bannière
./lancer.sh https://mabbox.bytel.fr --authorized --direct \
  --target-profile router-bouygues --router-services

# Conseiller RSSI facultatif : local ou API, avec faits expurgés
./lancer.sh https://exemple.test --authorized --direct --ai-local --ai-model metatron-qwen
export OPENAI_API_KEY='...'
./lancer.sh https://exemple.test --authorized --direct --ai-provider openai
unset OPENAI_API_KEY

# Inventaire, sélection interactive et suppression exacte des rapports
.venv/bin/python hackscan.py --list-reports
.venv/bin/python hackscan.py --manage-reports
.venv/bin/python hackscan.py --list-reports --report-target defta --report-status incomplet
.venv/bin/python hackscan.py --list-reports --report-format json
.venv/bin/python hackscan.py --preview-prune --keep-reports 10
```

Pour signer les rapports, créer explicitement une clé protégée hors du projet, puis la fournir au scan. La clé privée n'est jamais copiée dans les livrables.

```bash
.venv/bin/python hackscan.py --init-signing-key ~/.config/hackscan/report-key.pem
./lancer.sh https://exemple.test --authorized --direct \
  --signing-key ~/.config/hackscan/report-key.pem
```

Les règles intégrées sont contrôlées par empreinte. Toute extension externe doit être signée Ed25519 :

```bash
.venv/bin/python rules_tool.py init-key ~/.config/hackscan/rules-key.pem
.venv/bin/python rules_tool.py sign mes-regles/custom.yaml --key ~/.config/hackscan/rules-key.pem
./lancer.sh https://exemple.test --authorized --direct \
  --rules-dir mes-regles --rules-public-key ~/.config/hackscan/rules-key.pem.pub
```

La corrélation KEV/EPSS porte uniquement sur des CVE déjà fournies par WPScan ou un modèle signé ; elle n'invente jamais une correspondance. Nuclei et l'IA restent facultatifs. OpenAI utilise `OPENAI_API_KEY`, Mistral `MISTRAL_API_KEY`, et aucune clé n'est écrite dans le rapport. Les données envoyées sont limitées aux constats expurgés et toute proposition requiert une validation humaine ; aucun repli entre fournisseurs n'est effectué.

## Version 4 : 100 ajouts intégrés

Les 100 ajouts sont consultables, numérotés A001–A100, dans `improvements.html` et `improvements.json` de chaque rapport. Ils comprennent **60 contrôles passifs**, **20 fonctions d'analyse** et **20 fonctions de rapport**, en plus de la version précédente. Ils ne représentent pas 100 tests d'exploitation. Un contrôle implémenté reste **inconnu** si sa mesure manque.

Les contrôles examinent la politique CSP effective, les préfixes/attributs de cookies, le contenu mixte, les formulaires avec mot de passe, les dépendances et SRI, les iframes, les certificats, les déclarations CORS, les traces visibles et les différences entre routes. Ils utilisent les mesures existantes sans ajouter de requête cible. Les formulaires et scripts ne sont jamais exécutés. Les résumés HTML excluent les valeurs de champs, les scripts et les valeurs de query ; les journaux techniques historiques conservent leur format antérieur.

L'analyse est **déterministe et explicable**, sans dépendance à un modèle IA ni envoi du rapport à un service d'IA. Elle regroupe les causes, propose un triage justifié, indique la qualité et l'âge des preuves, relie les constats aux mesures, relève les échéances dépassées et les clôtures déclarées sans preuve. Les propositions de délais, d'effort et d'affectation restent à valider. Un statut « observé » n'est pas un verdict de sécurité ; les indices nouveaux ne reçoivent pas automatiquement une gravité ou une CVE.

Le rapport propose une lecture direction/technique, un diagramme de couverture, des cartes de décision, une feuille de route et une matrice filtrable des 60 contrôles. Le plan édité affiche un rappel tant qu'il n'est pas exporté. La touche `/` ouvre la recherche des constats hors d'un champ de saisie. Les exports supplémentaires sont `controls.csv`, `intelligence.json`, `improvements.html` et `improvements.json`. Le PDF contient les décisions et les 60 contrôles ; les URL, références et mesures détaillées restent dans les annexes HTML/JSON/CSV.

Un ancien rapport peut être régénéré hors ligne : les contrôles dont les données n'étaient pas capturées restent inconnus. Les durées réseau mesurent le client (médiane et P95 par rang le plus proche), jamais la capacité du serveur. Les regroupements d'actions ne clôturent pas les constats. Aucune conformité réglementaire ou absence de vulnérabilité n'est déduite.

Références techniques : [OWASP WSTG](https://owasp.org/projects/web-security-testing-guide), [MDN CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy), [MDN Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie). Les règles sont des aides à la revue et ne couvrent pas ces référentiels intégralement.

## Installation et lancement

Lancement interactif simple :

```bash
./lancer.sh
./lancer.sh --tor             # même lancement via le proxy Tor local
```

Le lanceur demande l'URL, l'autorisation, le type de cible (`auto`, WordPress, Joomla, Bbox, Livebox ou routeur générique), puis **si Tor doit être utilisé comme proxy** pour une cible web (oui/non, port 9050). Il ajoute HTTPS si le protocole est omis, puis détecte WordPress, Joomla, Drupal, PrestaShop, Magento, TYPO3, Ghost, Shopify, Wix ou Squarespace à partir de signatures publiques. Sans signature, il indique « non déterminé ». Les contrôles web et SQL restent génériques ; les contrôles WordPress et WPScan (s'il est installé) s'activent uniquement si WordPress est détecté. Joomla dispose de contrôles GET bornés sur l'administration, l'API et le manifeste public. Les profils routeur désactivent automatiquement Tor, SQL et les outils CMS. Le rapport HTML/PDF RSSI-CISO et ses exports sont produits par la même exécution. Les dépendances Python sont installées localement au premier lancement si nécessaire.

La redirection initiale vers l'alias www du même hôte et le passage HTTP→HTTPS sont pris en charge. Les autres origines, sous-domaines, ports inhabituels et rétrogradations HTTPS→HTTP restent bloqués. L'URL demandée, l'URL évaluée et les redirections sont tracées dans le rapport.

```bash
./install.sh                  # Python + requests/SOCKS dans .venv
./install.sh --wpscan         # ajoute WPScan via RubyGems utilisateur s'il manque
./install.sh --nuclei         # Nuclei épinglé dans ~/.local/bin
./install.sh --full           # Ubuntu 26.04 neuf : outils + Python + WPScan + Nuclei
./install.sh --check          # état des outils et présence des clés, sans les afficher
.venv/bin/python hackscan.py https://www.defta.eu --authorized --sql --wpscan
```

`--full` n'installe ni n'active aucune base de données ou serveur. Par défaut, après la génération réussie d'un rapport dans `reports/`, Hackscan conserve les 10 plus récents et supprime uniquement les anciens dossiers contenant un `report.json` valide. Modifier avec `--keep-reports N`, désactiver avec `--no-auto-prune`, ou cibler un autre emplacement avec `--reports-root`.

Tor est inclus dans l'installation Ubuntu complète et reste vérifiable séparément avec `./tor.sh --check`. Une sortie Tor valide ne garantit pas qu'une cible accepte les nœuds de sortie : dans ce cas Hackscan conserve l'échec comme couverture incomplète et ne bascule jamais silencieusement en accès direct.

`--profile` règle l'intensité (`rapide`, `standard`, `approfondi`). `--target-profile` sélectionne la technologie : `auto`, `web-generic`, `wordpress`, `joomla`, `router-generic`, `router-bouygues` ou `router-orange`.

```bash
# CMS : détection passive et contrôles spécialisés GET
.venv/bin/python hackscan.py https://www.defta.eu --authorized --direct \
  --profile standard --target-profile wordpress --sql --wpscan

# Bbox locale : API GET fixe, sans cookie ni valeur sensible conservée
.venv/bin/python hackscan.py https://mabbox.bytel.fr --authorized --direct \
  --profile standard --target-profile router-bouygues

# Livebox locale : interface et ressources publiques uniquement
.venv/bin/python hackscan.py http://livebox --authorized --direct \
  --profile rapide --target-profile router-orange
```

Les profils routeur exigent une résolution vers une adresse locale et refusent Tor, proxy, SQL, sqlmap et WPScan. Ils plafonnent automatiquement l'exploration à une page, 16 requêtes et 120 secondes. Aucun POST, scan de ports, brute force, test WPS, exploit ou changement de configuration n'est réalisé. Seuls les codes HTTP, le type JSON, le nombre d'éléments et les noms de champs sont conservés ; jamais les IP, MAC, noms d'hôtes, SSID, jetons ou corps de réponse.

Python 3 avec venv est requis. L'installation Ruby de WPScan nécessite Ruby, ses en-têtes et un compilateur. Si sqlmap manque, l'installer via le gestionnaire de paquets de votre système, par exemple `sudo apt install sqlmap` sur Debian/Ubuntu.

Le scanner intégré fonctionne sans abonnement. WPScan découvre les composants sans jeton ; sa base de vulnérabilités nécessite un jeton API avec quota. Fournir le jeton par la variable d'environnement `WPSCAN_API_TOKEN`, jamais dans le code. Licence WPScan : https://github.com/wpscanteam/wpscan — vérifier les conditions pour votre usage.

## Tests SQL

`--sql` cherche des erreurs SQL après deux marqueurs de syntaxe sur au plus trois URL GET publiques. Ce sont des **indices**, et cela ne détecte pas toutes les injections aveugles. Il ne soumet aucun formulaire.

Pour approfondir un point de lecture précis avec sqlmap :

```bash
.venv/bin/python hackscan.py https://www.defta.eu --authorized --sql \
  --sqlmap-url 'https://www.defta.eu/?s=hackscan-audit' --sqlmap-timeout 120
```

sqlmap utilise niveau 1, risque 1, techniques booléennes et erreurs, un seul thread et un délai entre requêtes. Aucun dump, écriture, shell, technique temporelle ou contournement WAF n'est activé. La même origine et une liste limitée de paramètres de lecture sont imposées. Vérifier néanmoins que le GET choisi est sans effet métier. Les outils externes ont leur propre budget de temps ; `--max-requests` ne limite que le scanner intégré. Une interruption ou une erreur est signalée comme couverture incomplète, jamais comme preuve d'absence de faille.

## Tor facultatif

Préparer Tor et vérifier une vraie sortie réseau :

```bash
./tor.sh                          # détecte, installe si nécessaire, démarre et vérifie
./tor.sh --check                   # diagnostic sans installation ni démarrage
./tor.sh --port 9150 --wait 180     # port alternatif / délai de bootstrap
./lancer.sh --tor                  # préparation automatique puis URL interactive
./lancer.sh --tor --tor-port 9150
```

L'installation automatique du paquet est prévue pour Debian/Ubuntu, via les dépôts système. Si nécessaire, `sudo` demande le mot de passe dans votre terminal ; aucun mot de passe n'est enregistré. Lancer `./tor.sh` sans sudo : les privilèges sont demandés uniquement pour installer le paquet. Les autres systèmes reçoivent une instruction d'installation explicite.

Un proxy déjà présent est réutilisé après validation. Sinon, une instance **client utilisateur** est configurée dans `~/.local/state/hackscan/tor/<port>/`, avec données privées, port SOCKS limité à `127.0.0.1`, SafeSocks, aucun relais ni port de contrôle. Les services existants et `/etc/tor/torrc` ne sont pas modifiés. Le fichier local existant est conservé et validé avant démarrage. L'instance locale reste disponible après le scan ; le script est idempotent lorsqu'elle fonctionne.

Le contrôle HTTPS `https://check.torproject.org/api/ip` est envoyé **via le même proxy**, avec DNS distant, sans redirection ni repli direct. `IsTor=true` est exigé avant de contacter la cible ; aucune IP de sortie n'est conservée dans le rapport. La disponibilité SOCKS seule ne suffit pas. `--tor-wait` fixe une attente de 5 à 300 secondes (90 par défaut), distincte du budget d'audit. Une panne de réseau ou du service de vérification bloque le scan via Tor ; elle ne déclenche pas une connexion directe. Les constats du site peuvent encore être limités par son filtrage.

En mode Tor, les valeurs par défaut du délai HTTP et du budget sont portées au minimum à 30 et 180 secondes pour tenir compte de la latence ; des options `--timeout` et `--budget` explicites sont respectées. Le port est conservé pour une reprise. Exemple sans questions lorsque l'URL, l'autorisation et le profil sont déjà fournis :

```bash
./lancer.sh https://www.defta.eu --authorized --tor --profile rapide
```

Contrôles locaux ciblés : `bash -n tor.sh lancer.sh install.sh` et `.venv/bin/python -m unittest -v test_tor`. L'installation d'un paquet manquant est simulée dans les tests ; le démarrage d'une instance, la disponibilité SOCKS et la sortie Tor se vérifient réellement avec `./tor.sh --check`.

```bash
.venv/bin/python hackscan.py https://www.defta.eu --authorized --sql --wpscan --tor
# Ou un proxy SOCKS distant :
.venv/bin/python hackscan.py https://www.defta.eu --authorized --sql --proxy socks5h://127.0.0.1:9150
```

Le scanner utilise SOCKS5 avec DNS distant ; aucun repli direct si le proxy échoue. WPScan utilise socks5h ; sqlmap utilise son proxy SOCKS5 avec résolution distante. `--tor` prépare et vérifie Tor automatiquement, tandis que `--proxy` utilise le proxy personnalisé sans l'installer ni affirmer qu'il s'agit de Tor. Tor ne garantit pas l'anonymat et peut modifier les réponses reçues : comparer les résultats avec un audit direct. Référence de configuration : [manuel Tor](https://manpages.debian.org/testing/tor/tor.1.en.html).

## Couverture et rapports

Inventaire des plugins/thèmes visibles sur cinq pages au maximum, versions déclarées, jusqu'à dix readme de plugins, accès publics WordPress et principaux en-têtes de sécurité. Les requêtes sont espacées, bornées en temps et en volume ; HTTPS est vérifié et les redirections vers une autre origine sont bloquées dans le scanner intégré. Les inventaires passifs sont partiels et les versions de ressources/readme ne prouvent pas la version réellement exécutée.

Le rapport RSSI/CISO comprend une synthèse décisionnelle, le périmètre et les budgets, une matrice de couverture, des fiches de constats avec impact conditionnel et preuve, l'inventaire, les formulaires et dépendances visibles, un plan de traitement avec responsables/échéances proposés et preuves de clôture, puis les annexes techniques. Les blocages sont expliqués avec conséquence et action proposée ; ils ne constituent pas des vulnérabilités. Aucun score de sécurité, CVE, probabilité ni validation métier n'est inventé. Les réponses sont horodatées avec durée, empreinte SHA-256 et en-têtes sélectionnés ; les valeurs des cookies et les corps complets ne sont pas archivés. Les résultats détaillés de WPScan et sqlmap sont conservés si ces outils sont activés. Réutiliser un dossier de sortie non vide est refusé. Les dossiers créés sont privés et les rapports sont lisibles uniquement par leur propriétaire.

```bash
.venv/bin/python -m unittest discover -v
.venv/bin/python hackscan.py --help
```

Les tests locaux couvrent les indices SQL, versions, redirections hors périmètre, erreurs 429, budgets, échec proxy sans repli, échappement HTML et interruption sqlmap. Les résultats d'un audit ne remplacent pas une validation humaine et un contrôle des composants installés.

## Version 3 — les vingt améliorations

| Nº | Fonction livrée | Utilisation / limite |
|---|---|---|
| 1 | Profils rapide, standard, approfondi | Choix interactif ou `--profile` ; budgets bornés. |
| 2 | Précontrôle SOCKS | Avant tout contact cible ; ne garantit ni bootstrap Tor ni anonymat. |
| 3 | Préférences persistantes | `--save-config`, fichier privé ; aucune URL, identité métier ou clé API conservée. |
| 4 | Progression | Étape, requêtes consommées et temps restant du scanner intégré. |
| 5 | Reprise | `--resume checkpoint.json` ; conserve les étapes terminées, nouveau budget d’exécution. |
| 6 | Diagnostic WPScan | Base absente, HTTP 403, quota/API, réseau et timeout distingués. |
| 7 | Contrôles Joomla/Drupal | Endpoints publics et versions déclarées, sans authentification ni écriture. |
| 8 | Références éditeur | WordPress/plugins, Joomla et Drupal ; requêtes HTTPS officielles bornées via le même proxy. |
| 9 | Cookies | Secure, HttpOnly, SameSite ; les valeurs sont exclues. |
| 10 | SQL ciblé | `--sql-url` et `--sql-parameters` ; GET de lecture, trois URL maximum. |
| 11 | Synthèse direction | `executive.html`, séparée du rapport technique. |
| 12 | Contexte métier | Organisation, RSSI, propriétaire métier, criticité et sensibilité personnalisables. |
| 13 | Qualification | Exposition, indice, correspondance CVE et confirmation humaine avec preuve/validateur. |
| 14 | Valeurs d’en-têtes | Vérifie notamment nosniff, cadrage, HSTS et indicateurs CSP faibles. |
| 15 | TLS détaillé | Certificat, dates, empreinte, chaîne vérifiée disponible, TLS 1.2/1.3 et suites négociées. |
| 16 | Comparaison | `--compare report.json` ; nouveaux, persistants, priorités augmentées et non observés. |
| 17 | Plan éditable | Modifier dans le HTML, télécharger le JSON puis réimporter via `--plan`. |
| 18 | Filtres HTML | Recherche par texte/composant/responsable, priorité, qualification et statut. |
| 19 | CSV et PDF | `risk-register.csv` et `report.pdf`, avec polices et pagination A4. |
| 20 | Traçabilité | Historique documentaire/reprise, fichiers privés, `manifest.sha256` de tous les exports. |

```bash
./lancer.sh
./lancer.sh --profile rapide --save-config
./lancer.sh --profile approfondi --direct
./lancer.sh --resume reports/mon-audit/checkpoint.json
```

`--direct` ignore explicitement une préférence Tor. Un proxy personnalisé est conservé dans le checkpoint de reprise sans identifiants ; il ne se transforme jamais implicitement en connexion directe. La disponibilité SOCKS ne suffit pas à attester que le réseau Tor est opérationnel. Si l’analyse s’arrête pendant une étape, cette étape peut recommencer ; les étapes entièrement terminées ne sont pas répétées. Les cookies, sessions et corps HTML ne sont pas conservés pour la reprise. Les anciennes erreurs restent dans le journal avec l’indication d’historique.

Les sondes SQL restent limitées aux paramètres de lecture connus. Aucun formulaire POST n’est soumis. Une comparaison entre audits partiels ne peut pas prouver une correction : les constats disparus sont « non observés », en attente de recontrôle. Une version récente dans le dépôt éditeur ne prouve ni la version exécutée, ni la présence/absence d’une CVE, ni le support de la branche installée. TLS 1.0/1.1 et l’ensemble des suites ne sont pas audités par les deux négociations TLS proposées.

```bash
.venv/bin/python hackscan.py https://www.defta.eu --authorized --profile standard \
  --organization DEFTA --owner 'RSSI du site' \
  --business-owner 'À désigner' --criticality 'À valider' --data-sensitivity 'À qualifier' \
  --sql-url 'https://www.defta.eu/?s=audit' --sql-parameters s \
  --compare reports/defta-ciso-v2/report.json
```

Après édition du plan dans le navigateur, régénérer les livrables sans recontacter le site :

```bash
.venv/bin/python hackscan.py --render-report reports/mon-audit/report.json \
  --plan /chemin/treatment-plan.json --output reports/mon-audit-actualise
```

Les propositions de confirmation et d’acceptation requièrent un validateur et une preuve/justification. La saisie reste une déclaration humaine ; le script ne réalise pas une validation technique automatique et ne corrige pas le site. Le CSV neutralise les cellules susceptibles d’être interprétées comme des formules. Les empreintes détectent les modifications de fichiers mais ne constituent pas une signature numérique ou un horodatage tiers.

```bash
.venv/bin/python -m unittest discover -v
# Vérification réelle des filtres, du plan, des téléchargements et du mobile :
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python browser_validation.py reports/mon-audit --output reports/browser-validation
# Vérification des livrables (depuis le dossier du rapport) :
sha256sum --check manifest.sha256
```

Les fichiers `test_*.py` couvrent les garde-fous automatisables et sont exécutés par la CI GitHub. `browser_validation.py` est volontairement séparé : il exige Firefox/geckodriver et valide visuellement un rapport déjà généré. Dependabot surveille chaque semaine les dépendances Python et les actions GitHub.
