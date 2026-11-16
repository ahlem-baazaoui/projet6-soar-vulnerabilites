# Rapport - Projet 6 : Vulnérabilités, corriger ce qui compte et le prouver

Mini-projet SOAR. Auteur : Ahlem Baazaoui (travail individuel). Encadrant : Dr. Salah Gontara.

## 1. Contexte et problème
Un scanner de vulnérabilités produit des milliers de résultats, triés par
score CVSS. Une équipe ne peut pas tout corriger. Le tri par CVSS seul est
trompeur : il ignore deux informations décisives. D'abord, la faille est-elle
réellement exploitée dans le monde ? Ensuite, l'actif touché est-il exposé et
important ? Résultat : une faille critique sur un serveur de test passe avant
une faille moyenne activement exploitée sur un service exposé. Et personne ne
vérifie que le correctif a tenu.

## 2. Objectifs
- Prioriser selon l'exploitation réelle (EPSS, KEV) et le contexte de l'actif.
- Automatiser le parcours : découverte, ticket, relance, preuve.
- Clore un ticket uniquement après un nouveau scan.

## 3. Architecture et outils
- Parc vulnérable : 4 conteneurs Docker.
- Scan : Trivy (vulnérabilités des paquets de l'image), Nuclei (exploitation
  réelle du service exposé).
- Priorisation : API EPSS (FIRST), catalogue KEV (CISA).
- Tickets : Gitea (issues via API).
- Orchestration : scripts Python et un workflow n8n.
Greenbone et DefectDojo ont été écartés (trop lourds pour 4-8 Go) ; la
déduplication est faite dans le pipeline.

## 4. Parc et inventaire
| Actif | Service | Exposition | Criticité |
|-------|---------|-----------|-----------|
| web-expose | Apache httpd 2.4.49 | internet | 3 |
| web-vuln | Apache httpd 2.4.49 (vulhub) | test | 1 |
| dvwa | DVWA | internet | 2 |
| cache-interne | Redis 5.0.5 | interne | 2 |
L'inventaire (inventaire/assets.yaml) porte l'information que les scanners
n'ont pas : exposition et criticité. C'est le coeur du contexte.

## 5. Scan : vulnérable n'est pas exploitable
Sur web-expose (httpd 2.4.49), Trivy a trouvé 260 vulnérabilités dont 23
CRITICAL et 99 HIGH, toutes dans des paquets Debian. Mais Trivy n'a PAS vu
CVE-2021-41773, la faille phare d'Apache 2.4.49 : dans l'image officielle,
Apache est compilé à la main (/usr/local/apache2), il n'apparait donc pas dans
la liste des paquets Debian que Trivy inspecte. C'est pourquoi un second
scanner est nécessaire : Nuclei teste le service réellement exposé.
Nuclei et une requête curl manuelle ont renvoyé 403 (Forbidden) : la
configuration par défaut (Require all denied, module CGI désactivé) empêche
l'exploitation. La fiche KEV de CVE-2021-41773 confirme exactement cette
condition. Leçon : une version vulnérable n'est pas une faille exploitable ;
seuls la configuration et l'exposition le disent.

## 6. Enrichissement EPSS et KEV
Pour chaque CVE unique du parc, le pipeline interroge l'API EPSS (probabilité
d'exploitation sous 30 jours) et vérifie la présence dans le catalogue KEV
(exploitation confirmée). Sur 574 CVE uniques, seules 7 sont dans KEV. Pour
CVE-2021-41773, EPSS vaut 0.9999 et KEV la marque comme utilisée par des
rançongiciels : les deux signaux concordent vers une menace maximale.

## 7. Formule de priorité
    Menace   = max(EPSS, 1 si KEV sinon 0)
    Impact   = CVSS / 10
    Contexte = poids(exposition) x poids(criticité)
    Score    = (0.7 * Menace + 0.3 * Impact) * Contexte
Poids exposition : internet 1.0, interne 0.6, test 0.2.
Poids criticité : haute 1.0, moyenne 0.7, faible 0.4.
Niveaux : P1 >= 0.5, P2 >= 0.25, P3 >= 0.1, P4 sinon. SLA : P1 2j, P2 7j, P3 30j.

Justification des choix :
- Multiplication par le Contexte (et non addition) : une faille sur un actif
  sans exposition doit tomber à zéro, quel que soit son CVSS. L'addition
  laisserait un gros CVSS dominer même sur un actif inaccessible.
- KEV écrase EPSS (max) : KEV est un fait (exploitation confirmée), EPSS une
  prédiction. Une faille dans KEV reçoit une Menace de 1, quel que soit EPSS.
- Menace pèse plus que l'Impact (0.7 vs 0.3) : l'exploitation réelle prime sur
  la gravité théorique.

## 8. Comparaison : notre classement vs CVSS seul
Sur 2318 findings :
- CVE-2023-44487 (KEV, CVSS 7.5) sur web-expose arrive au rang 648/2318 avec un
  tri CVSS seul, mais devient P1 (rang 1) avec notre formule. Avec un tri CVSS,
  l'équipe traiterait 647 findings avant d'atteindre cette faille activement
  exploitée sur un serveur exposé.
- La même CVE sur l'actif de test (web-vuln) est classée P4 : le contexte fait
  toute la différence.
- CVE-2019-11043 (CVSS 9.8 ET KEV) sur dvwa est haute dans les deux tris : la
  formule ne contredit pas les failles réellement critiques, elle les confirme.
Conclusion : le tri CVSS disperse l'effort ; notre tri remonte les 7 failles
réellement exploitées en tête.

## 9. Cycle des tickets
Les findings P1 et P2 génèrent des tickets Gitea (138 au total). Chaque ticket
porte l'actif, la CVE, le paquet et sa version corrigée, CVSS, EPSS, KEV, le
score, la priorité et l'échéance SLA. Déduplication : la clé (actif, CVE) évite
les doublons, et le script est idempotent (il relit les tickets existants avant
d'en créer). Les exceptions (risque accepté) se gèrent par un label daté dont
l'expiration rouvre le ticket.

## 10. Preuve : clôture après nouveau scan
Après simulation d'un correctif (mise à jour de web-expose de httpd:2.4.49 vers
httpd:2.4), un nouveau scan est lancé. Le script de vérification a clôturé
automatiquement 65 tickets dont la CVE a disparu, avec un commentaire. Si une
CVE est toujours présente, le ticket se rouvre. Un ticket ne se ferme donc
jamais sans preuve par scan.

## 11. Orchestration n8n
Un workflow n8n planifié enchaine : scan, enrichissement, calcul de priorité,
création des tickets, puis vérification. Le workflow s'exécute sur planification
et peut être déclenché à chaque nouvelle entrée KEV.

## 12. Limites et extensions
- Déduplication possible au niveau (actif, CVE) pour une vue plus lisible.
- Extensions : correctif proposé par pull request, blocage temporaire au
  pare-feu (expérience FortiGate), inventaire logiciel SBOM (trivy cyclonedx).

## 13. Conclusion
Le projet montre, chiffres à l'appui, qu'une priorisation basée sur le risque
(EPSS, KEV, contexte) traite les failles réellement dangereuses bien plus vite
qu'un tri par CVSS seul, et que l'automatisation ferme la boucle jusqu'à la
preuve par re-scan.
