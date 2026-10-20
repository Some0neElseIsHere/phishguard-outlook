#!/usr/bin/env python3
"""PhishGuard - résumé du banc d'essai et comparaison avec le passage précédent.

Usage : python tools/bench-summary.py out/bench.csv out/summary.json [précédent.json]

Écrit le résumé (taux d'alerte et de rouge par groupe de corpus, cas fictifs en erreur), l'affiche en Markdown
(dans le résumé de l'exécution GitHub si GITHUB_STEP_SUMMARY est défini) et, si un résumé précédent est fourni,
signale les régressions dans out/regressions.md. Seuls les corpus FIXES servent à détecter une régression : leurs
messages ne changent pas d'un mois à l'autre, une baisse vient donc forcément du moteur. Les corpus qui s'enrichissent
(phishing_pot, spam du mois) sont comparés à titre d'information.
"""
import csv, json, os, sys

GROUPS = [  # (clé, libellé, type, fixe ?)
    ("nazario", "Phishings Nazario 2020-2025", "phish", True),
    ("pot", "Phishings récents (phishing_pot)", "phish", False),
    ("spam", "Spam du mois (untroubled.org)", "phish", False),
    ("cas-phish", "Faux phishings français fictifs", "phish", True),
    ("apache", "Légitimes récents (listes Apache 2025)", "ham", True),
    ("ham2003", "Légitimes 2003 (SpamAssassin)", "ham", True),
    ("cas-legit", "Légitimes français difficiles (fictifs)", "ham", True),
]
DROP_PHISH = 1.0   # points de détection perdus sur un corpus fixe
RISE_HAM = 0.5     # points de fausses alertes gagnés sur un corpus fixe


def group_of(corpus):
    if corpus.startswith("phish-20"): return "nazario"
    if corpus == "phish-pot": return "pot"
    if corpus.startswith("spam-"): return "spam"
    if corpus == "phish-fr-cas": return "cas-phish"
    if corpus.startswith("ham-apache"): return "apache"
    if corpus in ("ham-easy", "ham-easy2", "ham-hard"): return "ham2003"
    if corpus == "ham-cas-difficiles": return "cas-legit"
    return None


PTS = {0: 0, 1: 8, 2: 20, 3: 40, 4: 70}
ERA = {"auth-missing", "link-http"}   # artefacts des messages de 2003 (pas d'authentification, tout en http)


def fair_level(r):
    """Verdict recalculé sans le filtre antispam du serveur d'origine (en-têtes X-Spam, indices filter-*) ni, pour les
    messages de 2003, les indices propres à l'époque : mêmes conditions que la documentation (docs/banc-essai.md)."""
    f = []
    for x in (r.get("findings") or "").split(" "):
        p = x.split(":")
        if len(p) != 3 or p[0].startswith("filter-"): continue
        if r["corpus"] in ("ham-easy", "ham-easy2", "ham-hard") and p[0] in ERA: continue
        f.append((p[0], int(p[1]), p[2]))
    decisive = lambda i: i.startswith("content-combo") or i == "content-iban-change"
    sc = sum(PTS[s] for i, s, c in f if c != "content" or decisive(i))
    ct = sum(PTS[s] for i, s, c in f if c == "content" and not decisive(i))
    score = min(100, sc + min(30, ct))
    if any(s == 4 for _, s, _ in f) or score >= 50: return "dangerous"
    return "suspicious" if score >= 20 else "safe"


def expected_ok(r):
    e, lv = r.get("attendu", ""), r["level"]
    return {"vert": lv == "safe", "orange": lv != "safe", "alerte": lv != "safe", "rouge": lv == "dangerous"}.get(e, True)


def summarize(path):
    stats, ko = {}, []
    for r in csv.DictReader(open(path, encoding="utf-8")):
        if r["mode"] != "inconnus": continue
        g = group_of(r["corpus"])
        if g is None: continue
        s = stats.setdefault(g, {"n": 0, "alert": 0, "red": 0})
        lv = r["level"] if g.startswith("cas-") else fair_level(r)
        s["n"] += 1
        s["alert"] += lv != "safe"
        s["red"] += lv == "dangerous"
        if g.startswith("cas-") and not expected_ok(r): ko.append(f"{r['cas']} (attendu {r['attendu']}, obtenu {r['level']} {r['score']})")
    for s in stats.values():
        s["alert_pct"] = round(100.0 * s["alert"] / s["n"], 2) if s["n"] else 0
        s["red_pct"] = round(100.0 * s["red"] / s["n"], 2) if s["n"] else 0
    return {"groups": stats, "cas_ko": ko}


def main():
    csv_path, out_path = sys.argv[1], sys.argv[2]
    prev = None
    if len(sys.argv) > 3 and os.path.exists(sys.argv[3]):
        try: prev = json.load(open(sys.argv[3], encoding="utf-8"))
        except Exception: prev = None
    cur = summarize(csv_path)
    json.dump(cur, open(out_path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    md = ["## Banc d'essai PhishGuard", "", "| Corpus | Messages | Alerte | Rouge | Mois précédent |", "|---|---|---|---|---|"]
    regress = []
    for key, label, kind, fixed in GROUPS:
        s = cur["groups"].get(key)
        if not s: continue
        p = (prev or {}).get("groups", {}).get(key)
        delta = ""
        if p:
            d = s["alert_pct"] - p["alert_pct"]
            delta = f"{p['alert_pct']:.1f} % ({d:+.1f})"
            if fixed and p["n"] and abs(s["n"] - p["n"]) <= max(5, p["n"] * 0.02):   # même corpus (téléchargement complet)
                if kind == "phish" and d < -DROP_PHISH: regress.append(f"{label} : détection {p['alert_pct']:.1f} % → {s['alert_pct']:.1f} %")
                if kind == "ham" and d > RISE_HAM: regress.append(f"{label} : fausses alertes {p['alert_pct']:.1f} % → {s['alert_pct']:.1f} %")
        md.append(f"| {label}{'' if fixed else ' *'} | {s['n']} | {s['alert_pct']:.1f} % | {s['red_pct']:.1f} % | {delta} |")
    md.append("")
    md.append("\\* corpus qui s'enrichit chaque mois : comparaison indicative.")
    if cur["cas_ko"]:
        md += ["", "**Cas fictifs en erreur :**"] + [f"- {x}" for x in cur["cas_ko"]]
        regress += [f"Cas fictif en erreur : {x}" for x in cur["cas_ko"]]
    text = "\n".join(md) + "\n"
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f: f.write(text)
    reg_path = os.path.join(os.path.dirname(out_path) or ".", "regressions.md")
    if regress:
        with open(reg_path, "w", encoding="utf-8") as f:
            f.write("Le banc d'essai mensuel a détecté une baisse sur un corpus qui n'a pas changé :\n\n")
            f.write("\n".join(f"- {x}" for x in regress) + "\n\n" + text)
        for x in regress: print(f"::warning::Régression : {x}")
    elif os.path.exists(reg_path):
        os.remove(reg_path)


if __name__ == "__main__":
    main()
