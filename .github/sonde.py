# Sondage ponctuel (supprimé après usage) : preuves qu'un domaine appartient au même propriétaire qu'un domaine officiel.
import json, subprocess, sys, urllib.request
def get(url, t=60):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "PhishGuard-Outlook/1.0"}), timeout=t) as r: return r.read().decode("utf-8", "replace")
    except Exception as e: return "ERR " + str(e)[:60]
def dig(name):
    return subprocess.run(["dig", "+short", "TXT", name], capture_output=True, text=True).stdout.replace('"', "").strip()
pairs = [p.split(":") for p in sys.argv[1:]]
for c, o in pairs:
    dm = dig("_dmarc." + c).splitlines()[:1]
    dm = dm[0] if dm else ""
    rua = [x.split("@")[-1].strip(" ;!0123456789kmgt") for x in dm.replace(",", ";").split(";") if "rua=" in x or "mailto:" in x and "@" in x]
    auth = {d: dig(c + "._report._dmarc." + d)[:20] for d in set(rua) if d and d != c and not d.endswith("." + c)}
    crt = get("https://crt.sh/?output=json&q=" + c, 90)
    try:
        names = [x["name_value"] for x in json.loads(crt)]
        common = sum(1 for v in names if any(l.lstrip("*.") == o or l.endswith("." + o) for l in v.split("\n")))
        crt = "%d certs, %d avec %s" % (len(names), common, o)
    except Exception: crt = crt[:40]
    rd = get("https://rdap.org/domain/" + c, 30)
    try:
        d = json.loads(rd); reg = "?"
        for e in d.get("entities", []):
            if "registrar" in e.get("roles", []):
                v = e.get("vcardArray", [0, []])[1]
                reg = next((x[3] for x in v if x[0] == "fn"), e.get("handle", "?"))
    except Exception: reg = rd[:40]
    print("::notice::%s -> %s | dmarc: %s | autorisation: %s | crt: %s | registrar: %s" % (c, o, dm[:70], auth, crt, reg))
