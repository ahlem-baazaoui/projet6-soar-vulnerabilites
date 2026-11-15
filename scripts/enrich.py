import csv, json, urllib.request, time

cves = set()
with open("scans/findings.csv") as f:
    for row in csv.DictReader(f):
        if row["cve"]:
            cves.add(row["cve"])
cves = sorted(cves)
print("CVE uniques :", len(cves))

kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
with urllib.request.urlopen(kev_url, timeout=60) as r:
    kev_data = json.load(r)
kev = { v["cveID"]: v.get("knownRansomwareCampaignUse","Unknown") for v in kev_data["vulnerabilities"] }
print("Entrees KEV (total CISA) :", len(kev))

epss = {}
for i in range(0, len(cves), 100):
    lot = cves[i:i+100]
    url = "https://api.first.org/data/v1/epss?cve=%s" % ",".join(lot)
    with urllib.request.urlopen(url, timeout=60) as r:
        d = json.load(r)
    for item in d.get("data", []):
        epss[item["cve"]] = float(item["epss"])
    time.sleep(1)
print("CVE avec score EPSS :", len(epss))

enr = {}
for cve in cves:
    enr[cve] = {"epss": epss.get(cve, 0.0), "kev": cve in kev, "ransomware": kev.get(cve, "") == "Known"}
with open("scans/enrichment.json","w") as f:
    json.dump(enr, f, indent=2)

print("CVE de ton parc dans KEV :", sum(1 for e in enr.values() if e["kev"]))
