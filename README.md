# Projet 6 - Vulnérabilités : corriger ce qui compte, et le prouver

Mini-projet SOAR - Gestion des vulnérabilités basée sur le risque.
Auteur : Ahlem Baazaoui (+ binôme). Cours SOAR, Dr. Salah Gontara.

## Problème
Un scanner produit des milliers de résultats triés par CVSS. Trier par
CVSS seul fait traiter en premier des failles graves mais inoffensives,
et reléguer des failles moyennes activement exploitées sur des actifs
exposés. Ce projet priorise selon l'exploitation réelle (EPSS, KEV) et
le contexte de l'actif, automatise le cycle des tickets, et ne clôt un
ticket qu'après un nouveau scan.

## Architecture
- Parc vulnérable : 4 conteneurs Docker (voir docker-compose.yml)
- Scan : Trivy (paquets des images) + Nuclei (service exposé)
- Priorisation : API EPSS (FIRST) + catalogue KEV (CISA)
- Tickets : Gitea (issues, dedup, SLA)
- Orchestration : scripts Python (+ workflow n8n)

## Parc (inventaire/assets.yaml)
| Actif | Service | Exposition | Criticité |
|-------|---------|-----------|-----------|
| web-expose | Apache httpd 2.4.49 | internet | 3 |
| web-vuln | Apache httpd 2.4.49 (vulhub) | test | 1 |
| dvwa | DVWA (PHP/MySQL) | internet | 2 |
| cache-interne | Redis 5.0.5 | interne | 2 |

## Formule de priorité
    Menace   = max(EPSS, 1 si KEV sinon 0)
    Impact   = CVSS / 10
    Contexte = poids(exposition) x poids(criticité)
    Score    = (0.7 * Menace + 0.3 * Impact) * Contexte
Niveaux : P1 >= 0.5, P2 >= 0.25, P3 >= 0.1, P4 sinon.
SLA : P1 = 2j, P2 = 7j, P3 = 30j.

## Résultat clé
- 2318 findings, 574 CVE uniques, 7 CVE dans KEV.
- CVE-2023-44487 (KEV, CVSS 7.5) sur web-expose : rang 648/2318 au tri
  CVSS, mais P1 (rang 1) avec notre formule.
- Même CVE sur l'actif de test : P4. Le contexte change tout.

## Pipeline
1. scripts/extract.py  : scans Trivy -> findings.csv (dedup)
2. scripts/enrich.py   : ajoute EPSS + KEV -> enrichment.json
3. scripts/score.py    : applique la formule -> findings_scored.csv + comparaison
4. scripts/tickets.py  : crée les tickets Gitea P1/P2 (dedup, SLA)
5. scripts/verify.py   : re-scan -> clôture ou réouverture des tickets

## Déploiement
    docker compose up -d
    python3 scripts/extract.py
    python3 scripts/enrich.py
    python3 scripts/score.py
    python3 scripts/tickets.py
    python3 scripts/verify.py web-expose httpd:2.4

## Prérequis
Docker, Python 3, jq, python3-yaml. Un token Gitea dans .gitea_token.
