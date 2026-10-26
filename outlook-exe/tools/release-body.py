#!/usr/bin/env python3
"""Description courte d'une release GitHub, tirée de docs/release-notes.md.

Liens de téléchargement en tête, nouveautés de cette version seulement, installation, à savoir,
lien vers l'historique complet. Usage : release-body.py <notes.md> <version> <owner/repo> [corps.md]
"""
import re
import sys


def section(text, title):
    m = re.search(r"^### " + re.escape(title) + r"\s*\n(.*?)(?=^### |\Z)", text, re.S | re.M)
    return m.group(1).strip() if m else ""


def entry(news, version):
    """Puce « - **vX.Y.Z** … » et ses lignes de suite, jusqu'à la puce de version suivante."""
    lines, out, inside = news.splitlines(), [], False
    for line in lines:
        if re.match(r"^- \*\*v[0-9]", line):
            if inside:
                break
            inside = line.startswith("- **" + version + "**")
        if inside:
            out.append(line)
    text = "\n".join(out).strip()
    # « - **v1.2.3** : texte » devient « texte » ; une puce suivie d'une liste garde sa liste
    text = re.sub(r"^- \*\*" + re.escape(version) + r"\*\* ?:? ?", "", text).strip()
    text = re.sub(r"^  - ", "- ", text, flags=re.M)          # liste imbriquée remise au premier niveau
    return text[:1].upper() + text[1:]


def build(notes, version, repo):
    base = "https://github.com/%s/releases/download/%s/" % (repo, version)
    history = "https://github.com/%s/blob/main/docs/release-notes.md" % repo
    first = notes.strip().splitlines()[0]
    news = entry(section(notes, "Nouveautés de cette version"), version)
    parts = [
        first,
        "",
        "**⬇ Télécharger : [Installeur (.exe)](%sPhishGuard-Outlook-%s-installeur.exe)** · [Archive (.zip)](%sPhishGuard-Outlook-%s.zip) · [Empreintes SHA-256](%sSHA256SUMS.txt)"
        % (base, version, base, version, base),
        "",
        "### Nouveautés de la %s" % version,
        "",
        news if news else "Voir l'historique.",
        "",
        "[Historique complet des versions](%s)" % history,
        "",
        "### Installation",
        "",
        section(notes, "Installation").replace("vX.Y.Z", version).replace("ci-dessous", "(lien ci-dessus)"),
    ]
    know = section(notes, "À savoir")
    if know:
        parts += ["", "### À savoir", "", know]
    return "\n".join(parts).rstrip() + "\n"


if __name__ == "__main__":
    notes_path, version, repo = sys.argv[1:4]
    with open(notes_path, encoding="utf-8-sig") as f:
        body = build(f.read(), version, repo)
    if len(sys.argv) > 4:
        with open(sys.argv[4], "w", encoding="utf-8", newline="\n") as f:   # écrit en UTF-8 quel que soit le système
            f.write(body)
    else:
        sys.stdout.buffer.write(body.encode("utf-8"))
