import csv, json, yaml

EXPO = {"internet": 1.0, "interne": 0.6, "test": 0.2}
CRIT = {3: 1.0, 2: 0.7, 1: 0.4}
A, B = 0.7, 0.3

with open("inventaire/assets.yaml") as f:
    actifs = {a["nom"]: a for a in yaml.safe_load(f)}
with open("scans/enrichment.json") as f:
    enr = json.load(f)

rows = []
with open("scans/findings.csv") as f:
    for r in csv.DictReader(f):
        a = actifs.get(r["actif"])
        if not a:
            continue
        try:
            cvss = float(r["cvss"])
        except ValueError:
            cvss = 0.0
        e = enr.get(r["cve"], {"epss": 0.0, "kev": False, "ransomware": False})
        menace = max(e["epss"], 1.0 if e["kev"] else 0.0)
        impact = cvss / 10.0
        ctx = EXPO.get(a["exposition"], 0.2) * CRIT.get(a["criticite"], 0.4)
        score = (A * menace + B * impact) * ctx
        rows.append({"actif": r["actif"], "cve": r["cve"], "paquet": r["paquet"],
                     "cvss": cvss, "epss": round(e["epss"], 4), "kev": e["kev"],
                     "exposition": a["exposition"], "criticite": a["criticite"],
                     "score": round(score, 4)})

def prio(s):
    if s >= 0.5: return "P1"
    if s >= 0.25: return "P2"
    if s >= 0.1: return "P3"
    return "P4"
for r in rows:
    r["priorite"] = prio(r["score"])

rows.sort(key=lambda x: x["score"], reverse=True)
with open("scans/findings_scored.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader(); w.writerows(rows)

print("=== TOP 10 par NOTRE score ===")
for r in rows[:10]:
    tag = "KEV" if r["kev"] else "   "
    print(r["priorite"], r["score"], tag, r["cve"], r["actif"], "CVSS", r["cvss"])

parcvss = sorted(rows, key=lambda x: x["cvss"], reverse=True)
print("\n=== TOP 10 par CVSS seul ===")
for r in parcvss[:10]:
    tag = "KEV" if r["kev"] else "   "
    print("CVSS", r["cvss"], tag, r["cve"], r["actif"])

kev_rows = [r for r in rows if r["kev"]]
print("\nFindings KEV :", len(kev_rows))
print("Rang de chaque finding KEV dans le tri CVSS seul :")
for kr in kev_rows:
    rang = parcvss.index(kr) + 1
    print("  ", kr["cve"], kr["actif"], "-> rang CVSS", rang, "/", len(rows), "| notre", kr["priorite"])
