import csv, json, urllib.request, datetime

GITEA = "http://127.0.0.1:3000"
REPO  = "ahlem/tickets"
TOKEN = open(".gitea_token").read().strip()
SLA   = {"P1": 2, "P2": 7, "P3": 30, "P4": 90}

def api(method, path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(GITEA + path, data=data, method=method)
    req.add_header("Authorization", "token " + TOKEN)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as r:
        body = r.read()
        return json.loads(body) if body else None

infos = {}
with open("scans/findings.csv") as f:
    for r in csv.DictReader(f):
        infos[(r["actif"], r["cve"], r["paquet"])] = (r["version"], r["fix"])

best = {}
with open("scans/findings_scored.csv") as f:
    for r in csv.DictReader(f):
        if r["priorite"] not in ("P1", "P2"):
            continue
        key = (r["actif"], r["cve"])
        if key not in best or float(r["score"]) > float(best[key]["score"]):
            best[key] = r
print("Findings P1/P2 a traiter :", len(best))

existants = set()
page = 1
while True:
    issues = api("GET", "/api/v1/repos/%s/issues?state=all&type=issues&limit=50&page=%d" % (REPO, page))
    if not issues:
        break
    for it in issues:
        existants.add(it["title"])
    page += 1
print("Issues deja presentes :", len(existants))

cree = 0
for (actif, cve), r in best.items():
    titre = "[%s] %s" % (actif, cve)
    if titre in existants:
        continue
    version, fix = infos.get((actif, cve, r["paquet"]), ("n/a", "n/a"))
    due = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=SLA[r["priorite"]])).strftime("%Y-%m-%dT%H:%M:%SZ")
    corps = (
        "**Actif** : %s (%s, criticite %s)\n\n"
        "**CVE** : %s\n\n"
        "**Paquet** : %s %s -> corrige en %s\n\n"
        "**CVSS** : %s | **EPSS** : %s | **KEV** : %s\n\n"
        "**Score** : %s -> **%s**\n\n"
        "**SLA** : %s jours (echeance %s)\n"
    ) % (actif, r["exposition"], r["criticite"], cve, r["paquet"], version,
         fix or "n/a", r["cvss"], r["epss"], r["kev"], r["score"], r["priorite"],
         SLA[r["priorite"]], due[:10])
    api("POST", "/api/v1/repos/%s/issues" % REPO,
        {"title": titre, "body": corps, "due_date": due})
    cree += 1
print("Tickets crees :", cree)
