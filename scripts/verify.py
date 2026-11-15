import sys, os, json, subprocess, urllib.request

GITEA = "http://127.0.0.1:3000"
REPO  = "ahlem/tickets"
TOKEN = open(".gitea_token").read().strip()

def api(method, path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(GITEA + path, data=data, method=method)
    req.add_header("Authorization", "token " + TOKEN)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as r:
        b = r.read()
        return json.loads(b) if b else None

actif = sys.argv[1]
image = sys.argv[2]
print("Nouveau scan de", actif, "(" + image + ") ...")
subprocess.run(["docker", "run", "--rm",
    "-v", "/var/run/docker.sock:/var/run/docker.sock",
    "-v", "trivy-cache:/root/.cache/",
    "-v", os.getcwd() + "/scans:/scans",
    "aquasec/trivy", "image", "--format", "json",
    "-o", "/scans/_verify.json", image], check=True)

present = set()
with open("scans/_verify.json") as f:
    d = json.load(f)
for res in d.get("Results", []):
    for v in res.get("Vulnerabilities", []) or []:
        present.add(v["VulnerabilityID"])
print("CVE encore presentes dans", image, ":", len(present))

page, closed, reopened = 1, 0, 0
while True:
    issues = api("GET", "/api/v1/repos/%s/issues?state=all&type=issues&limit=50&page=%d" % (REPO, page))
    if not issues:
        break
    for it in issues:
        t = it["title"]
        if not t.startswith("[%s] " % actif):
            continue
        cve = t.split()[1]
        num, state = it["number"], it["state"]
        if cve not in present and state == "open":
            api("POST", "/api/v1/repos/%s/issues/%d/comments" % (REPO, num),
                {"body": "Nouveau scan (%s) : CVE absente -> cloture automatique." % image})
            api("PATCH", "/api/v1/repos/%s/issues/%d" % (REPO, num), {"state": "closed"})
            closed += 1
        elif cve in present and state == "closed":
            api("POST", "/api/v1/repos/%s/issues/%d/comments" % (REPO, num),
                {"body": "Nouveau scan (%s) : CVE toujours presente -> reouverture." % image})
            api("PATCH", "/api/v1/repos/%s/issues/%d" % (REPO, num), {"state": "open"})
            reopened += 1
    page += 1
print("Tickets clotures :", closed, "| reouverts :", reopened)
