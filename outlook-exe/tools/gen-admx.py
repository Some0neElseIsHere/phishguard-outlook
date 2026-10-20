#!/usr/bin/env python3
"""PhishGuard - génère le modèle de stratégies de groupe (policies/PhishGuard.admx et ses traductions .adml).

Les stratégies sont écrites dans HKLM ou HKCU\\Software\\Policies\\PhishGuard (classe « Both » : configuration
ordinateur ou utilisateur), avec les mêmes noms que les clés de config.ini. Le complément les relit à chaque
chargement des réglages ; elles l'emportent sur config.ini et sur les réglages de l'utilisateur, qui ne peut pas
les modifier (seul un administrateur écrit sous « Policies »).

Usage : python3 tools/gen-admx.py   (réécrit policies/)
"""
import os
from xml.sax.saxutils import escape

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "policies")
KEY = r"Software\Policies\PhishGuard"

# (catégorie, nom, type, libellé FR, aide FR, libellé EN, aide EN, options)
CATS = [
    ("Cat_Company", "Entreprise", "Company"),
    ("Cat_Usage", "Affichage et utilisation", "Display and usage"),
    ("Cat_Sources", "Sources et listes", "Sources and lists"),
]

P = [
    ("Cat_Company", "ReportAddress", "text",
     "Adresse de l'équipe sécurité", "Adresse qui reçoit les messages signalés avec le bouton « Signaler à la sécurité » (rapport HTML et message d'origine joint).",
     "Security team address", "Address that receives messages reported with the \"Report to security\" button (HTML report with the original message attached).", None),
    ("Cat_Company", "CompanyDomains", "text",
     "Domaines de l'entreprise", "Domaines de messagerie de l'entreprise, séparés par des virgules (ex. : exemple.fr, exemple.com). Un domaine qui les imite est classé critique, et un message à leur nom non authentifié est une usurpation.",
     "Company domains", "Company email domains, comma-separated (e.g. example.com, example.fr). A domain imitating them is rated critical, and an unauthenticated message using them is spoofing.", None),
    ("Cat_Company", "Company1", "text",
     "Entreprise 1 et ses dirigeants", "Format : Nom | Pays | Identifiant | Dirigeant; Dirigeant. Exemple : Exemple SAS | France | 552100554 | Claire Martin; Hugo Bernard. Le nom de l'entreprise et ceux des dirigeants affichés par un expéditeur externe sont signalés (fraude au président). Si une entreprise est définie par stratégie, la liste des entreprises n'est plus modifiable.",
     "Company 1 and its executives", "Format: Name | Country | Identifier | Executive; Executive. Example: Example Ltd | United Kingdom | 01234567 | Claire Martin; Hugo Bernard. The company name and executive names displayed by an external sender are flagged (CEO fraud). Once a company is set by policy, the company list can no longer be edited.", None),
    ("Cat_Company", "Company2", "text", "Entreprise 2 et ses dirigeants", "Même format que l'entreprise 1 (filiale, autre entité du groupe).",
     "Company 2 and its executives", "Same format as company 1 (subsidiary, other group entity).", None),
    ("Cat_Company", "Company3", "text", "Entreprise 3 et ses dirigeants", "Même format que l'entreprise 1.",
     "Company 3 and its executives", "Same format as company 1.", None),
    ("Cat_Company", "InternalRelays", "text",
     "Équipements internes qui envoient des mails",
     "Adresses IP ou plages CIDR (séparées par des virgules) des copieurs, applications et serveurs qui envoient au nom de l'entreprise sans s'authentifier, telles que les voit votre serveur de messagerie (ex. : 203.0.113.10, 203.0.113.0/28, 10.0.0.0/8). Un message à votre nom venant de là est reconnu comme interne ; venant d'ailleurs, il reste une usurpation critique. N'indiquez jamais l'adresse d'un service partagé (Microsoft 365, Google, plateforme d'envoi) : tous ses clients en profiteraient.",
     "Internal devices that send email",
     "IP addresses or CIDR ranges (comma-separated) of copiers, applications and servers that send on behalf of the company without authenticating, as seen by your mail server (e.g. 203.0.113.10, 203.0.113.0/28, 10.0.0.0/8). A message in your name coming from there is recognized as internal; from anywhere else it remains critical spoofing. Never list the address of a shared service (Microsoft 365, Google, sending platform): all its customers would benefit.", None),
    ("Cat_Company", "TrustedDomains", "text",
     "Domaines de confiance", "Domaines partenaires, séparés par des virgules. Les indices liés à l'expéditeur et au contenu sont abaissés ; un échec d'authentification reste toujours signalé.",
     "Trusted domains", "Partner domains, comma-separated. Sender and content findings are lowered; an authentication failure is always reported.", None),
    ("Cat_Company", "SharedBlocklistPath", "text",
     "Liste de blocage partagée", "Chemin d'un fichier texte (un domaine malveillant par ligne) tenu par l'équipe sécurité, par exemple \\\\serveur\\securite\\phishguard.txt. Rechargé toutes les heures.",
     "Shared blocklist", "Path to a text file (one malicious domain per line) maintained by the security team, e.g. \\\\server\\security\\phishguard.txt. Reloaded every hour.", None),

    ("Cat_Usage", "ForceSimpleMode", "bool",
     "Imposer le mode simple", "Activé : la fenêtre d'analyse affiche uniquement le verdict en clair et « Que dois-je faire ? ». Le bouton « Analyse détaillée » et les réglages avancés (listes, sources de réputation) sont masqués. Recommandé pour les utilisateurs non techniques ; à ne pas appliquer à l'équipe sécurité.",
     "Enforce simple mode", "Enabled: the analysis window shows only the plain-language verdict and \"What should I do?\". The \"Detailed analysis\" button and advanced settings (lists, reputation sources) are hidden. Recommended for non-technical users; do not apply to the security team.", None),
    ("Cat_Usage", "Language", "enum",
     "Langue de l'interface", "Langue de PhishGuard. Automatique : langue de Windows.",
     "Interface language", "PhishGuard language. Automatic: Windows language.",
     [("auto", "Automatique (langue de Windows)", "Automatic (Windows language)"), ("fr", "Français", "French"), ("en", "Anglais", "English")]),
    ("Cat_Usage", "Theme", "enum",
     "Thème des fenêtres", "Couleurs des fenêtres de PhishGuard. Automatique : suit le mode clair ou sombre choisi dans Windows (Paramètres, Personnalisation, Couleurs).",
     "Window theme", "Colors of the PhishGuard windows. Automatic: follows the light or dark mode chosen in Windows (Settings, Personalization, Colors).",
     [("auto", "Automatique (thème de Windows)", "Automatic (Windows theme)"), ("light", "Clair", "Light"), ("dark", "Sombre", "Dark")]),
    ("Cat_Usage", "AlertLevel", "enum",
     "Alertes à l'écran", "Messages pour lesquels une alerte s'affiche en bas à droite de l'écran.",
     "On-screen alerts", "Messages for which an alert is shown at the bottom right of the screen.",
     [("dangerous", "Messages dangereux uniquement", "Dangerous messages only"), ("suspicious", "Messages suspects et dangereux", "Suspicious and dangerous messages"), ("none", "Aucune alerte", "No alert")]),
    ("Cat_Usage", "AutoAnalyze", "bool",
     "Analyse automatique", "Activé : chaque message sélectionné ou ouvert est analysé et son score affiché dans le ruban. Désactivé : analyse sur demande uniquement.",
     "Automatic analysis", "Enabled: every selected or opened message is analyzed and its score shown in the ribbon. Disabled: analysis on demand only.", None),
    ("Cat_Usage", "MoveAfterReport", "bool",
     "Déplacer les messages signalés", "Activé : un message signalé à l'équipe sécurité est déplacé dans Courrier indésirable.",
     "Move reported messages", "Enabled: a message reported to the security team is moved to Junk Email.", None),
    ("Cat_Usage", "KnownCorrespondents", "bool",
     "Correspondants connus", "Activé : PhishGuard apprend sur le poste les adresses auxquelles l'utilisateur a écrit (éléments envoyés, contacts) pour repérer le premier contact et les sosies de ses correspondants.",
     "Known correspondents", "Enabled: PhishGuard learns on the computer the addresses the user has written to (sent items, contacts) to spot first contact and lookalikes of correspondents.", None),
    ("Cat_Usage", "ScoreLog", "bool",
     "Journal des scores", "Activé : chaque analyse est notée dans scores.csv sur le poste (date, verdict, score, domaine et indices ; ni objet ni contenu).",
     "Score log", "Enabled: each analysis is recorded in scores.csv on the computer (date, verdict, score, domain and findings; no subject or content).", None),

    ("Cat_Sources", "AllowApiKeys", "bool",
     "Autoriser les clés d'API", "Désactivé : aucune clé VirusTotal, abuse.ch ou AbuseIPDB n'est utilisée sur le poste et leur saisie est bloquée. Une clé ne peut pas être distribuée par stratégie : toute clé lisible par le poste l'est aussi par l'utilisateur. Les versions gratuites de certains services interdisent l'usage professionnel : vérifiez leurs conditions.",
     "Allow API keys", "Disabled: no VirusTotal, abuse.ch or AbuseIPDB key is used on the computer and entering one is blocked. A key cannot be distributed by policy: any key readable by the computer is readable by the user. The free tiers of some services forbid business use: check their terms.", None),
    ("Cat_Sources", "RedFlagEnabled", "bool",
     "Liste Red Flag Domains", "Nouveaux domaines .fr suspects, téléchargés chaque jour. Licence CC BY-NC-SA 4.0 : vérifiez que votre usage est couvert.",
     "Red Flag Domains list", "New suspicious .fr domains, downloaded daily. CC BY-NC-SA 4.0 license: check that your use is covered.", None),
    ("Cat_Sources", "PublicSectorList", "bool",
     "Liste des domaines du secteur public", "Liste ouverte de la DINUM (environ 100 000 domaines d'organismes publics), téléchargée chaque mois : un message authentifié d'un organisme public n'est pas pris pour un faux.",
     "Public-sector domain list", "Open list from DINUM (about 100,000 French public-body domains), downloaded monthly: an authenticated message from a public body is not mistaken for a fake.", None),
    ("Cat_Sources", "DomainAgeLookup", "bool",
     "Âge des domaines", "Interroge les registres publics (RDAP) pour connaître la date de création des domaines des expéditeurs et des liens. Seul le nom du domaine est envoyé.",
     "Domain age", "Queries public registries (RDAP) for the creation date of sender and link domains. Only the domain name is sent.", None),
    ("Cat_Sources", "BetaDnsChecks", "bool",
     "Vérifications DNS", "Vérifie dans le DNS de l'entreprise le domaine de l'expéditeur (MX, SPF, DMARC, BIMI) et si un domaine qui ressemble à une marque est géré par les serveurs DNS de celle-ci.",
     "DNS checks", "Checks the sender's domain in the company DNS (MX, SPF, DMARC, BIMI) and whether a domain resembling a brand is managed by that brand's DNS servers.", None),
    ("Cat_Sources", "BetaCertAge", "bool",
     "Âge des certificats (crt.sh)", "Envoie le nom des domaines à crt.sh pour connaître la date de leur premier certificat HTTPS.",
     "Certificate age (crt.sh)", "Sends domain names to crt.sh to find the date of their first HTTPS certificate.", None),
    ("Cat_Sources", "BetaOpenPhish", "bool",
     "Liste OpenPhish", "Pages de phishing actives, téléchargées toutes les 12 heures et comparées sur le poste. Flux communautaire réservé à un usage non commercial.",
     "OpenPhish list", "Active phishing pages, downloaded every 12 hours and compared on the computer. Community feed for non-commercial use.", None),
    ("Cat_Sources", "BetaTranco", "bool",
     "Classement Tranco", "Sites les plus visités, téléchargés chaque semaine : réduit les fausses alertes sur les domaines très fréquentés.",
     "Tranco ranking", "Most visited sites, downloaded weekly: reduces false alerts on very popular domains.", None),
]


def admx():
    o = ['<?xml version="1.0" encoding="utf-8"?>',
         '<!-- PhishGuard pour Outlook : modèle de stratégies de groupe (généré par tools/gen-admx.py). -->',
         '<policyDefinitions xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" revision="1.0" schemaVersion="1.0" xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions">',
         '  <policyNamespaces>',
         '    <target prefix="phishguard" namespace="PhishGuard.Policies.PhishGuard" />',
         '  </policyNamespaces>',
         '  <resources minRequiredRevision="1.0" />',
         '  <supportedOn>',
         '    <definitions>',
         '      <definition name="SUPPORTED_PhishGuard" displayName="$(string.SUPPORTED_PhishGuard)" />',
         '    </definitions>',
         '  </supportedOn>',
         '  <categories>',
         '    <category name="Cat_PhishGuard" displayName="$(string.Cat_PhishGuard)" />']
    for cid, _, _ in CATS:
        o.append(f'    <category name="{cid}" displayName="$(string.{cid})">')
        o.append('      <parentCategory ref="Cat_PhishGuard" />')
        o.append('    </category>')
    o.append('  </categories>')
    o.append('  <policies>')
    for cat, name, typ, *_rest, opts in P:
        attrs = f'name="{name}" class="Both" displayName="$(string.{name})" explainText="$(string.{name}_Help)" key="{KEY}"'
        if typ == "bool":
            o.append(f'    <policy {attrs} valueName="{name}">')
            o.append(f'      <parentCategory ref="{cat}" />')
            o.append('      <supportedOn ref="SUPPORTED_PhishGuard" />')
            o.append('      <enabledValue><decimal value="1" /></enabledValue>')
            o.append('      <disabledValue><decimal value="0" /></disabledValue>')
        else:
            o.append(f'    <policy {attrs} presentation="$(presentation.{name})">')
            o.append(f'      <parentCategory ref="{cat}" />')
            o.append('      <supportedOn ref="SUPPORTED_PhishGuard" />')
            o.append('      <elements>')
            if typ == "text":
                o.append(f'        <text id="{name}_Value" valueName="{name}" required="true" maxLength="2048" />')
            else:
                o.append(f'        <enum id="{name}_Value" valueName="{name}" required="true">')
                for val, _fr, _en in opts:
                    o.append(f'          <item displayName="$(string.{name}_{val})"><value><string>{val}</string></value></item>')
                o.append('        </enum>')
            o.append('      </elements>')
        o.append('    </policy>')
    o.append('  </policies>')
    o.append('</policyDefinitions>')
    return "\n".join(o) + "\n"


def adml(lang):
    fr = lang == "fr-FR"
    s = {"SUPPORTED_PhishGuard": "PhishGuard pour Outlook 1.15 et versions ultérieures" if fr else "PhishGuard for Outlook 1.15 and later",
         "Cat_PhishGuard": "PhishGuard pour Outlook" if fr else "PhishGuard for Outlook"}
    for cid, cfr, cen in CATS:
        s[cid] = cfr if fr else cen
    pres = []
    for cat, name, typ, lfr, hfr, len_, hen, opts in P:
        s[name] = lfr if fr else len_
        s[name + "_Help"] = (hfr if fr else hen) + ("\n\n" + ("Valeur de registre : " if fr else "Registry value: ") + KEY + "\\" + name)
        if typ == "text":
            pres.append(f'      <presentation id="{name}"><textBox refId="{name}_Value"><label>{escape(lfr if fr else len_)}</label></textBox></presentation>')
        elif typ == "enum":
            for val, ofr, oen in opts:
                s[f"{name}_{val}"] = ofr if fr else oen
            pres.append(f'      <presentation id="{name}"><dropdownList refId="{name}_Value" noSort="true">{escape(lfr if fr else len_)}</dropdownList></presentation>')
    o = ['<?xml version="1.0" encoding="utf-8"?>',
         '<policyDefinitionResources xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" revision="1.0" schemaVersion="1.0" xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions">',
         f'  <displayName>{"PhishGuard pour Outlook" if fr else "PhishGuard for Outlook"}</displayName>',
         f'  <description>{"Stratégies du complément anti-phishing PhishGuard pour Outlook" if fr else "Policies for the PhishGuard anti-phishing add-in for Outlook"}</description>',
         '  <resources>',
         '    <stringTable>']
    for k, v in s.items():
        o.append(f'      <string id="{k}">{escape(v)}</string>')
    o.append('    </stringTable>')
    o.append('    <presentationTable>')
    o += pres
    o.append('    </presentationTable>')
    o.append('  </resources>')
    o.append('</policyDefinitionResources>')
    return "\n".join(o) + "\n"


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\r\n") as f:
        f.write(text)


if __name__ == "__main__":
    write(os.path.join(ROOT, "PhishGuard.admx"), admx())
    for lang in ("fr-FR", "en-US"):
        write(os.path.join(ROOT, lang, "PhishGuard.adml"), adml(lang))
    print(len(P), "stratégies écrites dans", os.path.normpath(ROOT))
