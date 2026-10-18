# Sondage ponctuel (supprimé après usage) : serveurs DNS et MX d'un domaine comparés à ceux du domaine officiel.
import subprocess, sys
def dig(name, t):
    return sorted(x.rstrip(".").lower() for x in subprocess.run(["dig", "+short", t, name], capture_output=True, text=True).stdout.split("\n") if x.strip())
def org(h):
    p = h.split("."); return ".".join(p[-2:]) if len(p) >= 2 else h
for pair in sys.argv[1:]:
    c, o = pair.split(":")
    nc, no = dig(c, "NS"), dig(o, "NS")
    mc = [m.split()[-1] for m in dig(c, "MX")]
    same = sorted(set(nc) & set(no))
    nsorgs = sorted(set(org(n) for n in nc))
    print("::notice::%s -> %s | NS %s | communs avec %s : %d | NS chez : %s | MX : %s" % (c, o, " ".join(nc[:4]), o, len(same), ",".join(nsorgs), " ".join(sorted(set(org(m) for m in mc)))))
