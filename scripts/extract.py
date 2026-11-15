import json, csv, glob, os

# nom du fichier scan  ->  nom de l'actif (depuis l'inventaire)
FICHIER_VERS_ACTIF = {
    "httpd-2.4.49": "web-expose",
    "web-vuln":     "web-vuln",
    "dvwa":         "dvwa",
    "cache-interne":"cache-interne",
}

findings = []
for chemin in glob.glob("scans/*.json"):
    stem = os.path.splitext(os.path.basename(chemin))[0]
    actif = FICHIER_VERS_ACTIF.get(stem, stem)
    with open(chemin) as f:
        data = json.load(f)
    for res in data.get("Results", []):
        for v in res.get("Vulnerabilities", []) or []:
            cvss = (v.get("CVSS", {}).get("nvd", {}) or {}).get("V3Score")
            findings.append({
                "actif": actif,
                "cve": v.get("VulnerabilityID"),
                "paquet": v.get("PkgName"),
                "version": v.get("InstalledVersion"),
                "fix": v.get("FixedVersion", ""),
                "severity": v.get("Severity"),
                "cvss": cvss if cvss is not None else "",
            })

# dedup : meme (actif, cve, paquet) = un seul finding
uniques = { (f["actif"], f["cve"], f["paquet"]): f for f in findings }
findings = list(uniques.values())

with open("scans/findings.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["actif","cve","paquet","version","fix","severity","cvss"])
    w.writeheader()
    w.writerows(findings)

print(f"Total findings uniques : {len(findings)}")
