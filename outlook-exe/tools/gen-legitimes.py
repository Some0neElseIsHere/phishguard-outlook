#!/usr/bin/env python3
"""PhishGuard - génère le corpus de mails LÉGITIMES « difficiles » du banc d'essai (tests/legitimes/*.eml).

Ce sont des mails fictifs, mais construits comme les vrais : domaines d'envoi réels des services concernés,
en-têtes d'authentification tels que Microsoft 365 les ajoute (SPF, DKIM, DMARC, compauth), désinscription
en un clic, liens de suivi des plateformes d'envoi. Ils couvrent les catégories qui ressemblent le plus à du
phishing : factures, colis, codes de vérification, partages de fichiers, signatures électroniques,
administrations, newsletters, fournisseurs.

Chaque message porte un en-tête X-PhishGuard-Attendu : « vert » (aucune alerte acceptable) ou « orange »
(alerte justifiée : demande sensible d'un inconnu, par exemple). Le banc compare le verdict à cette attente.

Usage : python3 tools/gen-legitimes.py   (réécrit tests/legitimes/)
"""
import base64, email.header, email.utils, hashlib, os, random, textwrap

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "legitimes")
TO = "claire.martin@exemple-pme.fr"
random.seed(7)


def auth(mailfrom, dkim, header_from, compauth="pass reason=100", dmarc="pass action=none", spf="pass"):
    return (f"Authentication-Results: spf={spf} (sender IP is 198.51.100.{random.randint(2, 250)}) smtp.mailfrom={mailfrom}; "
            f"dkim=pass (signature was verified) header.d={dkim};dmarc={dmarc} header.from={header_from};compauth={compauth}")


def msg(fid, expect, from_name, from_addr, subject, paras, links=(), mailfrom=None, dkim=None, bulk=True,
        reply_to=None, attachments=(), extra_headers=(), dmarc="pass action=none", compauth="pass reason=100", known=False,
        raw_auth=None, to=TO, plain_extra=""):
    dom = from_addr.split("@")[1]
    org = ".".join(dom.split(".")[-2:]) if not dom.endswith(".gouv.fr") else dom
    mailfrom = mailfrom or ("bounce." + org)
    dkim = dkim or org
    date = email.utils.format_datetime(email.utils.localtime().replace(year=2026, month=random.randint(1, 9), day=random.randint(1, 28),
                                                                       hour=random.randint(7, 20), minute=random.randint(0, 59), second=0, microsecond=0))
    mid = f"<{hashlib.md5(fid.encode()).hexdigest()}@{mailfrom}>"
    h = (list(raw_auth) if raw_auth else [auth(mailfrom, dkim, org, compauth=compauth, dmarc=dmarc)]) + [
         f"Received: from mail.{mailfrom} (198.51.100.{random.randint(2, 250)}) by PR3P192MB0001.EURP192.PROD.OUTLOOK.COM",
         f"From: {from_name} <{from_addr}>", f"To: {to}", f"Subject: {email.header.Header(subject, 'utf-8').encode()}",
         f"Date: {date}", f"Message-ID: {mid}", "MIME-Version: 1.0", f"X-PhishGuard-Attendu: {expect}",
         f"X-PhishGuard-Cas: {fid}"]
    if known: h.append("X-PhishGuard-Connu: oui")   # expéditeur déjà dans les correspondants (collègue, client, fournisseur)
    if reply_to: h.append(f"Reply-To: {reply_to}")
    if bulk:
        h += [f"List-Unsubscribe: <https://unsubscribe.{org}/u?id={hashlib.md5(fid.encode()).hexdigest()[:12]}>, <mailto:unsubscribe@{mailfrom}>",
              "List-Unsubscribe-Post: List-Unsubscribe=One-Click"]
    h += list(extra_headers)
    html = "<html><body style=\"font-family:Arial\">" + "".join(f"<p>{p}</p>" for p in paras)
    for href, text in links:
        html += f"<p><a href=\"{href}\">{text}</a></p>"
    html += "</body></html>"
    text = "\n\n".join(textwrap.fill(p.replace("<b>", "").replace("</b>", ""), 76) for p in paras)
    for href, text_l in links:
        text += f"\n\n{text_l} : {href}"
    if plain_extra: text += "\n\n" + plain_extra
    b = "=_pg_" + hashlib.md5(fid.encode()).hexdigest()[:10]
    body = [f"Content-Type: multipart/mixed; boundary=\"{b}\"", "", f"--{b}",
            "Content-Type: multipart/alternative; boundary=\"alt" + b + "\"", "",
            "--alt" + b, "Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: base64", "",
            base64.encodebytes(text.encode()).decode().strip(), "--alt" + b,
            "Content-Type: text/html; charset=utf-8", "Content-Transfer-Encoding: base64", "",
            base64.encodebytes(html.encode()).decode().strip(), "--alt" + b + "--"]
    for name, ctype, data in attachments:
        body += [f"--{b}", f"Content-Type: {ctype}; name=\"{name}\"", f"Content-Disposition: attachment; filename=\"{name}\"",
                 "Content-Transfer-Encoding: base64", "", base64.encodebytes(data).decode().strip()]
    body.append(f"--{b}--")
    with open(os.path.join(OUT, fid + ".eml"), "w", encoding="utf-8", newline="\r\n") as f:
        f.write("\n".join(h + body) + "\n")


PDF = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[]/Count 0>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"


def main():
    os.makedirs(OUT, exist_ok=True)
    for f in os.listdir(OUT):
        if f.endswith(".eml"): os.remove(os.path.join(OUT, f))

    # ---- Factures et abonnements ----
    msg("facture-orange", "vert", "Orange", "facture@orange.fr", "Votre facture Orange est disponible",
        ["Bonjour Claire Martin,", "Votre facture de septembre d'un montant de 42,99 € est disponible dans votre Espace Client.",
         "Le prélèvement sera effectué le 12 octobre sur votre compte bancaire."],
        [("https://r.orange.fr/r/Eespace_client?xtor=EREC-123", "Consulter ma facture")], mailfrom="mail.orange.fr")
    msg("facture-edf", "vert", "EDF", "noreply@edf.fr", "Votre facture d'électricité",
        ["Bonjour,", "Votre nouvelle facture est disponible. Montant : 87,40 €. Date limite de paiement : 25/10/2026.",
         "Pour la consulter, connectez-vous à votre espace client."],
        [("https://particulier.edf.fr/fr/accueil/espace-client.html", "Mon espace client")], mailfrom="email.edf.fr")
    msg("facture-free", "vert", "Free Mobile", "noreply@free-mobile.fr", "Votre facture Free Mobile",
        ["Bonjour,", "Votre facture du mois est disponible dans votre espace abonné. Montant : 19,99 €."],
        [("https://mobile.free.fr/account/", "Accéder à mon espace abonné")])
    msg("facture-totalenergies", "vert", "TotalEnergies", "service-client@totalenergies.fr", "Votre échéancier et votre facture",
        ["Bonjour Claire,", "Votre facture annuelle de régularisation est disponible.", "Vous avez un remboursement de 34,12 € qui sera versé sous 15 jours."],
        [("https://www.totalenergies.fr/clients/connexion", "Voir ma facture")])
    msg("renouvellement-ovh", "vert", "OVHcloud", "support@ovh.com", "Renouvellement de votre nom de domaine exemple-pme.fr",
        ["Bonjour,", "Votre nom de domaine exemple-pme.fr expire dans 30 jours. Le renouvellement automatique est activé.",
         "Aucune action n'est requise de votre part."],
        [("https://www.ovh.com/manager/#/billing/autorenew", "Gérer mes renouvellements")], bulk=False)
    msg("abonnement-microsoft", "vert", "Microsoft", "microsoft-noreply@microsoft.com", "Votre abonnement Microsoft 365 Business Standard",
        ["Bonjour,", "Votre abonnement sera renouvelé le 01/11/2026. Le montant de 126,00 € HT sera prélevé sur votre moyen de paiement enregistré."],
        [("https://admin.microsoft.com/Adminportal/Home#/subscriptions", "Gérer votre abonnement")], mailfrom="email.microsoft.com", bulk=False)
    msg("relance-fournisseur", "vert", "Comptabilité Bureautique Pro", "compta@bureautique-pro.fr", "Relance : facture F2026-0912 échue",
        ["Bonjour,", "Sauf erreur de notre part, la facture F2026-0912 du 12/09/2026 d'un montant de 1 284,00 € TTC reste impayée.",
         "Merci de procéder au règlement par virement sur notre compte habituel. Cordialement, Service comptabilité."],
        attachments=[("F2026-0912.pdf", "application/pdf", PDF)], bulk=False, known=True)

    # ---- Colis et livraisons ----
    msg("colis-laposte", "vert", "La Poste - Colissimo", "noreply@notif-colissimo-laposte.info", "Votre colis arrive aujourd'hui",
        ["Bonjour,", "Votre colis n° 6A12345678901 sera livré aujourd'hui entre 9h et 13h.", "Absent ? Choisissez une autre date de livraison."],
        [("https://www.laposte.fr/outils/suivre-vos-envois?code=6A12345678901", "Suivre mon colis")], mailfrom="notif-colissimo-laposte.info")
    msg("colis-chronopost", "vert", "Chronopost", "chronopost@network1.pickup.fr", "Votre colis Chronopost est en cours de livraison",
        ["Bonjour,", "Votre colis XY123456789FR est en cours de livraison.", "Vous pouvez modifier votre livraison jusqu'à 7h ce matin."],
        [("https://www.chronopost.fr/tracking-no-cms/suivi-page?listeNumerosLT=XY123456789FR", "Suivre ou modifier ma livraison")], mailfrom="pickup.fr")
    msg("colis-amazon", "vert", "Amazon.fr", "expedition-confirmation@amazon.fr", "Expédié : votre commande n° 402-1234567-1234567",
        ["Bonjour Claire,", "Votre colis a été expédié et arrivera jeudi.", "Total de la commande : 34,90 €"],
        [("https://www.amazon.fr/gp/css/order-details?orderID=402-1234567-1234567", "Afficher ou gérer la commande")], mailfrom="amazonses.com", dkim="amazon.fr")
    msg("colis-ups", "vert", "UPS", "mcinfo@ups.com", "Mise à jour UPS : livraison prévue demain",
        ["Bonjour,", "Votre colis 1Z999AA10123456784 sera livré demain.", "Expéditeur : Bureautique Pro"],
        [("https://www.ups.com/track?loc=fr_FR&tracknum=1Z999AA10123456784", "Suivre l'envoi")])
    msg("colis-dhl", "vert", "DHL Express", "noreply@dhl.com", "Votre envoi DHL : frais de douane à régler",
        ["Bonjour,", "Votre envoi 1234567890 en provenance du Royaume-Uni est soumis à des droits et taxes de 23,50 €.",
         "Vous pouvez les régler en ligne sur le site DHL pour éviter tout retard."],
        [("https://mydhl.express.dhl/fr/fr/tracking.html#/results?id=1234567890", "Payer les droits et taxes")])

    # ---- Sécurité de compte (codes, connexions) ----
    msg("code-microsoft", "vert", "Équipe des comptes Microsoft", "account-security-noreply@accountprotection.microsoft.com", "Code de sécurité du compte Microsoft",
        ["Veuillez utiliser le code de sécurité suivant pour le compte Microsoft cl*****@exemple-pme.fr.", "Code de sécurité : <b>482913</b>",
         "Si vous ne reconnaissez pas ce compte, vous pouvez cliquer ici pour supprimer votre adresse e-mail de ce compte."],
        [("https://account.live.com/dp?ft=abc123", "cliquer ici")], mailfrom="accountprotection.microsoft.com", bulk=False)
    msg("connexion-google", "vert", "Google", "no-reply@accounts.google.com", "Alerte de sécurité",
        ["Nouvelle connexion sur Windows.", "Nous avons détecté une nouvelle connexion à votre compte Google. Si c'était vous, aucune action n'est requise.",
         "Sinon, nous vous aiderons à sécuriser votre compte."],
        [("https://accounts.google.com/AccountChooser?Email=claire.martin@exemple-pme.fr&continue=https://myaccount.google.com/alert", "Vérifier l'activité")],
        mailfrom="accounts.google.com", dkim="accounts.google.com", bulk=False)
    msg("mdp-linkedin", "vert", "LinkedIn", "security-noreply@linkedin.com", "Claire, voici le lien pour réinitialiser votre mot de passe",
        ["Bonjour Claire,", "Nous avons reçu une demande de réinitialisation du mot de passe de votre compte LinkedIn.",
         "Ce lien expirera dans 24 heures. Si vous n'êtes pas à l'origine de cette demande, ignorez ce message."],
        [("https://www.linkedin.com/e/v2?e=abc&a=checkpoint-password-reset", "Réinitialiser mon mot de passe")], bulk=False)
    msg("code-doctolib", "vert", "Doctolib", "no-reply@doctolib.fr", "Votre code de vérification Doctolib",
        ["Bonjour,", "Voici votre code de vérification : 731 004. Il est valable 10 minutes.", "Ne le communiquez à personne."], bulk=False)
    msg("connexion-banque", "vert", "BNP Paribas", "alerte@bnpparibas.com", "Connexion à votre espace client",
        ["Bonjour,", "Une connexion à votre espace client a eu lieu le 03/10/2026 à 09:14 depuis un nouvel appareil.",
         "Si vous n'êtes pas à l'origine de cette connexion, contactez-nous au numéro figurant au dos de votre carte."], bulk=False)
    msg("mdp-expire-interne-it", "vert", "Support informatique Exemple PME", "support@exemple-pme.fr",
        "Votre mot de passe expire dans 7 jours",
        ["Bonjour Claire,", "Votre mot de passe Windows expire dans 7 jours.", "Pour le changer : Ctrl + Alt + Suppr puis « Modifier un mot de passe ». Ne cliquez sur aucun lien."],
        bulk=False, extra_headers=["X-MS-Exchange-Organization-AuthAs: Internal"])

    # ---- Partages de fichiers, signature électronique, réunions ----
    msg("partage-onedrive", "vert", "Paul Durand (via OneDrive)", "no-reply@sharepointonline.com", "Paul Durand a partagé « Budget 2027.xlsx » avec vous",
        ["Paul Durand a partagé un fichier avec vous.", "Voici le budget mis à jour avant la réunion de jeudi."],
        [("https://exemplepme-my.sharepoint.com/:x:/g/personal/paul_durand_exemple-pme_fr/EaBcD123?e=xyz", "Ouvrir")],
        mailfrom="sharepointonline.com", bulk=False)
    msg("partage-gdrive", "vert", "Julie Bernard (via Google Drive)", "drive-shares-dm-noreply@google.com", "Document partagé avec vous : « Planning salon 2027 »",
        ["Julie Bernard a partagé le document suivant :", "Planning salon 2027"],
        [("https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz/edit?usp=sharing_eip", "Ouvrir")], mailfrom="google.com", bulk=False,
        reply_to="julie.bernard@client-alpha.fr", known=True)
    msg("docusign", "vert", "Cabinet Lefèvre via DocuSign", "dse_NA4@docusign.net", "Veuillez signer : Contrat de maintenance 2027",
        ["Cabinet Lefèvre vous a envoyé un document à consulter et à signer.", "Merci de signer le contrat avant le 30 octobre."],
        [("https://na4.docusign.net/Signing/EmailStart.aspx?a=1b2c3d&etti=24&acct=abc", "CONSULTER LE DOCUMENT")], mailfrom="docusign.net",
        bulk=False, reply_to="contact@cabinet-lefevre.fr")
    msg("yousign", "vert", "Yousign", "noreply@yousign.app", "Signature demandée : Avenant au bail commercial",
        ["Bonjour Claire Martin,", "Vous êtes invité(e) à signer le document « Avenant au bail commercial » envoyé par SCI Horizon."],
        [("https://yousign.app/signatures/8f1c2d/sign?k=abc", "Signer le document")], bulk=False)
    msg("teams-invitation", "vert", "Paul Durand", "paul.durand@client-alpha.fr", "Réunion de lancement du projet",
        ["Bonjour,", "Je vous propose une réunion de lancement jeudi à 10h.", "Réunion Microsoft Teams. Rejoindre sur votre ordinateur ou application mobile."],
        [("https://teams.microsoft.com/l/meetup-join/19%3ameeting_abc%40thread.v2/0?context=%7b%22Tid%22%3a%22x%22%7d", "Cliquez ici pour rejoindre la réunion")],
        mailfrom="client-alpha.fr", bulk=False, known=True)
    msg("zoom", "vert", "Zoom", "no-reply@zoom.us", "Rappel : votre réunion commence dans 1 heure",
        ["Bonjour Claire,", "Votre réunion « Point mensuel » commence dans 1 heure."],
        [("https://us02web.zoom.us/j/81234567890?pwd=abcDEF", "Rejoindre la réunion")])
    msg("wetransfer", "vert", "WeTransfer", "noreply@wetransfer.com", "Studio Graphik vous a envoyé des fichiers via WeTransfer",
        ["3 fichiers, 48 Mo au total. Expire dans 7 jours.", "Message : « Voici les maquettes de la plaquette, bonne réception. »"],
        [("https://we.tl/t-AbCdEf1234", "Télécharger vos fichiers")], bulk=False)

    # ---- Administrations ----
    msg("impots", "vert", "impots.gouv.fr", "ne-pas-repondre@dgfip.finances.gouv.fr", "Votre avis d'impôt est disponible",
        ["Madame,", "Votre avis d'impôt sur le revenu 2026 est disponible dans votre espace particulier sur impots.gouv.fr.",
         "Pour des raisons de sécurité, ce message ne contient aucun lien. Connectez-vous directement au site."],
        mailfrom="dgfip.finances.gouv.fr", dkim="dgfip.finances.gouv.fr", bulk=False)
    msg("ameli", "vert", "l'Assurance Maladie", "ne_pas_repondre@assurance-maladie.fr", "Un nouveau message dans votre compte ameli",
        ["Bonjour Claire,", "Un nouveau document est disponible dans votre compte ameli : votre relevé de remboursements.",
         "Connectez-vous à votre compte ameli pour le consulter."],
        [("https://assure.ameli.fr/", "Accéder à mon compte")])
    msg("urssaf", "vert", "Urssaf", "ne-pas-repondre@urssaf.fr", "Votre échéance de cotisations du 15/10/2026",
        ["Bonjour,", "Votre prochaine échéance de cotisations est fixée au 15/10/2026. Montant estimé : 1 920,00 €.",
         "Le paiement par prélèvement sera effectué automatiquement."],
        [("https://www.urssaf.fr/accueil/espace-employeur.html", "Mon espace")])
    msg("antai-legit", "vert", "ANTAI", "ne-pas-repondre@antai.gouv.fr", "Avis de contravention disponible",
        ["Madame, Monsieur,", "Un avis de contravention concernant le véhicule AB-123-CD est disponible sur votre espace.",
         "Vous pouvez le consulter et le payer sur le site officiel antai.gouv.fr."],
        [("https://www.antai.gouv.fr/", "antai.gouv.fr")], mailfrom="antai.gouv.fr", dkim="antai.gouv.fr", bulk=False)

    # ---- Newsletters et promotions ----
    msg("promo-fnac", "vert", "Fnac", "fnac@newsletter.fnac.com", "⏰ Dernier jour : -30 % sur une sélection de PC portables",
        ["Offre valable uniquement aujourd'hui jusqu'à minuit !", "Profitez-en vite : stocks limités.", "Livraison gratuite dès 25 €."],
        [("https://e.newsletter.fnac.com/c/abc123?url=https%3A%2F%2Fwww.fnac.com%2Fpc-portables", "J'en profite"),
         ("https://e.newsletter.fnac.com/c/def456", "Voir toutes les offres"), ("https://www.fnac.com", "www.fnac.com")], mailfrom="newsletter.fnac.com")
    msg("promo-sncf", "vert", "SNCF Connect", "newsletter@info.sncf-connect.com", "Vos billets à petit prix pour les vacances",
        ["Bonjour Claire,", "Réservez dès maintenant vos billets pour la Toussaint.", "Offre soumise à conditions, dans la limite des places disponibles."],
        [("https://click.info.sncf-connect.com/?qs=abcdef0123456789", "Je réserve")], mailfrom="info.sncf-connect.com")
    msg("newsletter-mailchimp-asso", "vert", "Club des entrepreneurs du Var", "contact@club-entrepreneurs83.fr", "La lettre du Club - octobre",
        ["Chers membres,", "Retrouvez notre programme du mois : petit-déjeuner réseau le 12, atelier cybersécurité le 20.",
         "Pensez à renouveler votre adhésion avant le 31 décembre."],
        [("https://club-entrepreneurs83.us12.list-manage.com/track/click?u=abc&id=def&e=123", "Voir le programme"),
         ("https://club-entrepreneurs83.us12.list-manage.com/track/click?u=abc&id=ghi&e=123", "Renouveler mon adhésion")],
        mailfrom="mail123.suw11.mcsv.net", dkim="mcsv.net")
    msg("newsletter-brevo", "vert", "Bureautique Pro", "newsletter@bureautique-pro.fr", "Nouveautés : imprimantes et contrats de maintenance",
        ["Bonjour,", "Découvrez notre nouvelle gamme d'imprimantes multifonctions.", "Offre spéciale clients : -15 % sur les contrats de maintenance jusqu'au 31 octobre."],
        [("https://r.sendibm1.com/mk/cl/f/abcDEF123", "Découvrir la gamme")], mailfrom="sendibm1.com", dkim="bureautique-pro.fr")
    msg("webinar-hubspot", "vert", "CyberSécurité Mag", "events@cybersecurite-mag.fr", "Webinar : comment repérer un email de phishing",
        ["Inscrivez-vous à notre webinar gratuit du 22 octobre.", "Au programme : faux mots de passe, fausses factures, fraude au président."],
        [("https://hs-1234567.s.hubspotemail.net/e3t/Ctc/abc", "Je m'inscris")], mailfrom="hubspotemail.net", dkim="cybersecurite-mag.fr")

    # ---- Notifications d'outils ----
    msg("github", "vert", "GitHub", "noreply@github.com", "[GitHub] A third-party OAuth application has been added to your account",
        ["Hey claire-martin!", "A third-party OAuth application (Netlify) with read:user scope was recently authorized to access your account.",
         "If you did not grant this access, please review your authorized applications."],
        [("https://github.com/settings/applications", "https://github.com/settings/applications")], bulk=False)
    msg("calendly", "vert", "Calendly", "notifications@calendly.com", "Nouvel événement : Jean Petit - Rendez-vous découverte",
        ["Bonjour Claire,", "Un nouvel événement a été planifié.", "Invité : Jean Petit (jean.petit@gmail.com). Jeudi 16 octobre, 14h00."],
        [("https://calendly.com/app/scheduled_events/user/me", "Voir l'événement")], bulk=False)
    msg("absence", "vert", "Paul Durand", "paul.durand@client-alpha.fr", "Réponse automatique : Devis maintenance",
        ["Bonjour,", "Je suis absent du bureau jusqu'au 20 octobre avec un accès limité à mes emails.", "Pour toute urgence, contactez mon collègue au 04 94 00 00 00."],
        mailfrom="client-alpha.fr", bulk=False, extra_headers=["Auto-Submitted: auto-replied", "In-Reply-To: <devis-123@exemple-pme.fr>", "References: <devis-123@exemple-pme.fr>"], known=True)
    msg("ndr-outlook", "vert", "Microsoft Outlook", "MicrosoftExchange329e71ec88ae4615bbc36ab6ce41109e@exemple-pme.fr", "Non remis : Devis maintenance",
        ["Votre message n'a pas pu être remis à jean.dupont@client-alpha.fr car l'adresse est introuvable.",
         "Vérifiez l'adresse du destinataire et renvoyez le message."],
        bulk=False, extra_headers=["X-MS-Exchange-Organization-AuthAs: Internal", "Auto-Submitted: auto-replied"])

    # ---- Premier contact professionnel ----
    msg("prospect-devis", "vert", "Jean Petit", "jean.petit@gmail.com", "Demande de devis",
        ["Bonjour,", "Je souhaiterais obtenir un devis pour l'entretien de nos locaux (200 m²) à Toulon.", "Pouvez-vous me rappeler au 06 12 34 56 78 ? Merci, Jean Petit"],
        mailfrom="gmail.com", dkim="gmail.com", bulk=False)
    msg("candidature", "vert", "Sophie Leroy", "sophie.leroy@outlook.fr", "Candidature spontanée - assistante de direction",
        ["Madame, Monsieur,", "Je vous adresse ma candidature pour un poste d'assistante de direction.", "Vous trouverez mon CV en pièce jointe."],
        attachments=[("CV_Sophie_Leroy.pdf", "application/pdf", PDF)], mailfrom="outlook.fr", dkim="outlook.fr", bulk=False)
    msg("fournisseur-nouveau-rib", "orange", "Comptabilité Bureautique Pro", "compta@bureautique-pro.fr", "Changement de coordonnées bancaires",
        ["Bonjour,", "Suite au changement de notre banque, merci de noter nos nouvelles coordonnées bancaires pour vos prochains virements :",
         "IBAN : FR76 3000 6000 0112 3456 7890 189 - BIC : AGRIFRPP", "Cordialement, Service comptabilité."], bulk=False, known=True)

    # ---- Codes de connexion envoyés par des services qui ne sont pas des « marques » connues ----
    # Avertissement habituel : « si ce n'est pas vous, changez immédiatement votre mot de passe ».
    # Boîte Orange relevée dans Outlook : Orange n'écrit que DKIM dans Authentication-Results, le reste dans ARC.
    orange_auth = ["Authentication-Results: opmta1mti36nd1;\n\tarc=none;\n\tdkim=pass header.d=mail.accounts.riotgames.com header.b=tIbvD503",
                   "ARC-Authentication-Results: i=1; opmta1mti36nd1; spf=pass (opmta1mti36nd1: domain of bounces@sg.mail.accounts.riotgames.com designates 149.72.148.222 as permited sender) smtp.mailfrom=bounces@sg.mail.accounts.riotgames.com;\n\tarc=none;\n\tdkim=pass header.d=mail.accounts.riotgames.com header.b=tIbvD503;\n\tdmarc=pass header.from=mail.accounts.riotgames.com",
                   "X-me-spamlevel: not-spam"]
    long = "u001.1qaABrx8Fusbo9A5Atzd56QQHhkOvKB-2BhG44gsGb4e2QCSrhWoVgMVlVZsNX464KdpYUhefn6DrvFMLyMTzTxQ-3D-3DnSse"
    msg("code-riot-orange", "vert", "Riot Games", "noreply@mail.accounts.riotgames.com", "Login Code: 360928",
        ["Sign-in Code", "Here's your sign-in code:", "<b>360928</b>", "This code will expire soon.",
         "Visit Account Management to unenroll any authentication factors you no longer need.",
         "If this request did not come from you, change your account password immediately to prevent further unauthorized access. Read Protecting Your Account for tips on password strength."],
        [("https://links.riotgames.com/ls/click?upn=" + long, "Account Management"), ("https://links.riotgames.com/ls/click?upn=" + long[::-1], "Protecting Your Account")],
        bulk=False, raw_auth=orange_auth, to="claire.martin@orange.fr",
        plain_extra="<https://cdn.mcauto-images-production.sendgrid.net/6c2047a1/e457af93/8x8.png>")   # pixel recopié par Outlook dans le texte
    msg("code-steam", "vert", "Steam", "noreply@steampowered.com", "Your Steam account: Access from new computer",
        ["Dear claire_m,", "Here is the login code you need to sign in to your account: <b>58213</b>",
         "If you are not attempting to log in, please change your Steam password immediately and consider changing your email password as well."],
        [("https://help.steampowered.com/en/wizard/HelpWithLoginInfo", "Steam Support")], bulk=False)
    msg("code-vinted", "vert", "Vinted", "no-reply@vinted.fr", "Votre code de vérification Vinted",
        ["Bonjour claire_m,", "Voici votre code de vérification : <b>482 913</b>. Il expire dans 10 minutes.",
         "Si vous n'êtes pas à l'origine de cette demande, modifiez immédiatement votre mot de passe et ne communiquez ce code à personne."],
        [("https://www.vinted.fr/help", "Centre d'aide")], bulk=False)
    msg("code-leboncoin", "vert", "leboncoin", "noreply@leboncoin.fr", "Code de connexion leboncoin",
        ["Bonjour,", "Pour vous connecter, saisissez le code suivant : <b>7391</b>",
         "Vous n'avez pas demandé ce code ? Quelqu'un essaie peut-être d'accéder à votre compte : changez votre mot de passe sans délai."], bulk=False)


# ---- Passerelles de messagerie des entreprises françaises ----
# Le format d'Authentication-Results dépend de la passerelle qui reçoit le message : Microsoft 365 (par défaut ci-dessus),
# FortiMail (SPF et DKIM sans DMARC, signature notée header.i), Google Workspace, ou un filtre français (Mailinblack, Vade…).
def gw_fortimail(mailfrom, dkim_domains):
    lines = [f"Authentication-Results: fml01.exemple-pme.fr;\n\tspf=pass (exemple-pme.fr: domain of bounce-{random.randint(1000, 9999)}@{mailfrom} designates 198.51.100.{random.randint(2, 250)} as permitted sender) smtp.mailfrom=bounce-{random.randint(1000, 9999)}@{mailfrom};"]
    lines[0] += "".join(f"\n\tdkim=pass header.i=@{d}" for d in dkim_domains) + ";"
    return lines + ["X-FEAS-DKIM: Valid", "X-FE-Policy-ID: 0:1:2:exemple-pme.fr", "X-MS-Exchange-Organization-AuthAs: Anonymous",
                    "X-MS-Exchange-Organization-AuthSource: SRV-EXCH02.exemple-pme.local"]


def gw_google(mailfrom, dkim, org, policy="QUARANTINE"):
    return [f"Authentication-Results: mx.google.com;\n       dkim=pass header.i=@{dkim} header.s=s1 header.b=Ab12Cd34;\n       spf=pass (google.com: domain of bounce@{mailfrom} designates 198.51.100.{random.randint(2, 250)} as permitted sender) smtp.mailfrom=bounce@{mailfrom};\n       dmarc=pass (p={policy} sp={policy} dis=NONE) header.from={org}"]


def gw_filtre_fr(mailfrom, dkim, org):
    return [f"Authentication-Results: mx.exemple-pme.fr; spf=pass smtp.mailfrom={mailfrom}; dkim=pass header.d={dkim}; dmarc=pass header.from={org}",
            "X-Mailinblack-Status: clean", "X-VR-SPAMSTATE: OK"]


def entreprise():
    """Mails courants dans une PME française : paie, RH, banque pro, comptabilité, administrations, fournisseurs, outils."""
    # ---- Paie, RH, avantages salariés ----
    msg("payfit-bulletin", "vert", "PayFit", "noreply@payfit.com", "Votre bulletin de paie d'octobre est disponible",
        ["Bonjour Claire,", "Votre bulletin de paie du mois d'octobre 2026 est disponible dans votre espace PayFit.",
         "Pour des raisons de confidentialité, il n'est pas joint à ce message."],
        [("https://app.payfit.com/payslips", "Voir mon bulletin")], bulk=False, raw_auth=gw_fortimail("mail.payfit.com", ["payfit.com"]))
    msg("lucca-conges", "vert", "Lucca", "notifications@ilucca.net", "Demande d'absence de Paul Durand à valider",
        ["Bonjour Claire,", "Paul Durand a posé une demande de congés payés du 22/12/2026 au 02/01/2027 (8 jours).",
         "Merci de la valider ou de la refuser."],
        [("https://exemple-pme.ilucca.net/timmi/absences/approvals", "Valider ou refuser")], bulk=False)
    msg("swile-recharge", "vert", "Swile", "hello@swile.co", "Votre carte Swile a été rechargée",
        ["Bonjour Claire,", "Votre employeur a crédité 168,00 € de titres-restaurant sur votre carte Swile.", "Bon appétit !"],
        [("https://team.swile.co/wallets", "Voir mon solde")])
    msg("alan-remboursement", "vert", "Alan", "no-reply@alan.com", "Votre remboursement de 45,00 € est en route",
        ["Bonjour Claire,", "Nous avons traité votre consultation du 02/10/2026. 45,00 € seront versés sur votre compte bancaire sous 48 h."],
        [("https://alan.com/app/dashboard", "Voir le détail")], bulk=False, raw_auth=gw_google("mail.alan.com", "alan.com", "alan.com"))
    msg("medecine-travail", "vert", "Service de santé au travail", "convocations@sante-travail-var.fr", "Convocation à votre visite d'information et de prévention",
        ["Madame,", "Vous êtes convoquée le 12/11/2026 à 9 h 30 au centre de Toulon pour votre visite d'information et de prévention.",
         "Merci de vous munir de votre carte Vitale. En cas d'empêchement, prévenez votre employeur."],
        attachments=[("Convocation_VIP.pdf", "application/pdf", PDF)], bulk=False)

    # ---- Banque professionnelle et comptabilité ----
    msg("qonto-virement-recu", "vert", "Qonto", "no-reply@qonto.com", "Virement reçu : 12 400,00 € de CLIENT ALPHA SAS",
        ["Bonjour Claire,", "Vous avez reçu un virement de 12 400,00 € de CLIENT ALPHA SAS.", "Référence : FACTURE F2026-0877."],
        [("https://app.qonto.com/transactions", "Voir la transaction")], bulk=False, raw_auth=gw_fortimail("mail.qonto.com", ["qonto.com"]))
    msg("qonto-justificatif", "vert", "Qonto", "no-reply@qonto.com", "3 justificatifs manquants",
        ["Bonjour Claire,", "3 transactions de septembre n'ont pas encore de justificatif.",
         "Ajoutez-les depuis l'application pour faciliter la clôture avec votre expert-comptable."],
        [("https://app.qonto.com/transactions?attachments=missing", "Ajouter les justificatifs")])
    msg("pennylane-facture", "vert", "Pennylane", "no-reply@pennylane.com", "Nouvelle facture fournisseur à valider",
        ["Bonjour,", "Une nouvelle facture de BUREAUTIQUE PRO (1 284,00 € TTC, échéance 30/10/2026) a été reçue.",
         "Validez-la pour la mettre en paiement."],
        [("https://app.pennylane.com/companies/123456/supplier_invoices", "Valider la facture")], bulk=False)
    msg("expert-comptable", "vert", "Cabinet Ferrand Expertise", "m.ferrand@ferrand-expertise.fr", "Pièces manquantes pour la clôture",
        ["Bonjour Claire,", "Pour finaliser la clôture au 31/12, il nous manque les relevés bancaires de novembre et la facture d'achat du véhicule.",
         "Merci de les déposer sur votre espace client dès que possible. Bien cordialement, Marc Ferrand"],
        [("https://ferrand-expertise.inqom.com/espace-client", "Espace client")], bulk=False, known=True)
    msg("facture-nouveau-fournisseur", "vert", "Transports Martin", "facturation@transports-martin.fr", "Facture FA-2026-1043",
        ["Madame, Monsieur,", "Veuillez trouver ci-joint notre facture FA-2026-1043 relative au transport du 08/10/2026.",
         "Règlement à 30 jours fin de mois. Nous restons à votre disposition. Service facturation"],
        attachments=[("FA-2026-1043.pdf", "application/pdf", PDF)], bulk=False, raw_auth=gw_fortimail("transports-martin.fr", ["transports-martin.fr"]))
    msg("bon-de-commande", "vert", "Achats Groupe Horizon", "no-reply-achats@groupe-horizon.fr", "Bon de commande 4500123456",
        ["Bonjour,", "Veuillez trouver ci-joint notre bon de commande n° 4500123456.", "Merci de rappeler ce numéro sur votre facture. Ce message est envoyé automatiquement."],
        attachments=[("BC_4500123456.pdf", "application/pdf", PDF)], bulk=False)
    msg("relance-client", "vert", "Client Alpha", "comptabilite@client-alpha.fr", "RE: Facture F2026-0877",
        ["Bonjour,", "Le virement a été émis ce matin, vous devriez le recevoir sous 48 h.", "Cordialement, Service comptabilité"],
        bulk=False, known=True, extra_headers=["In-Reply-To: <f2026-0877@exemple-pme.fr>", "References: <f2026-0877@exemple-pme.fr>"])

    # ---- Administrations et organismes ----
    msg("chorus-pro", "vert", "Chorus Pro", "ne-pas-repondre@aife.economie.gouv.fr", "Votre facture a été mise à disposition du destinataire",
        ["Bonjour,", "La facture n° F2026-0877 déposée le 08/10/2026 a été mise à disposition de la structure destinataire.",
         "Vous pouvez suivre son traitement depuis votre espace Chorus Pro."],
        [("https://portail.chorus-pro.gouv.fr/aife_csm", "Accéder à Chorus Pro")], mailfrom="aife.economie.gouv.fr", dkim="aife.economie.gouv.fr", bulk=False)
    msg("net-entreprises-dsn", "vert", "net-entreprises.fr", "ne-pas-repondre@net-entreprises.fr", "DSN mensuelle : bilan de traitement",
        ["Bonjour,", "Votre déclaration sociale nominative du mois de septembre 2026 a été traitée. Aucune anomalie bloquante.",
         "Le bilan est disponible dans votre tableau de bord."],
        [("https://www.net-entreprises.fr/", "net-entreprises.fr")], bulk=False)
    msg("urssaf-vigilance", "vert", "Urssaf", "ne-pas-repondre@urssaf.fr", "Votre attestation de vigilance est disponible",
        ["Bonjour,", "Votre attestation de vigilance est disponible dans votre espace en ligne.",
         "Elle peut être demandée par vos donneurs d'ordre pour tout contrat de 5 000 € HT ou plus."],
        [("https://www.urssaf.fr/accueil/espace-employeur.html", "Mon espace")], bulk=False)
    msg("impots-pro", "vert", "impots.gouv.fr", "ne-pas-repondre@dgfip.finances.gouv.fr", "Vous avez reçu un message dans votre messagerie sécurisée",
        ["Madame, Monsieur,", "Un nouveau message est disponible dans la messagerie sécurisée de votre espace professionnel.",
         "Pour le consulter, connectez-vous à impots.gouv.fr. Ce courriel ne contient aucun lien, par sécurité."],
        mailfrom="dgfip.finances.gouv.fr", dkim="dgfip.finances.gouv.fr", bulk=False, raw_auth=gw_fortimail("dgfip.finances.gouv.fr", ["dgfip.finances.gouv.fr"]))
    msg("infogreffe-kbis", "vert", "Infogreffe", "commande@infogreffe.fr", "Votre extrait Kbis",
        ["Bonjour,", "Veuillez trouver ci-joint l'extrait Kbis de la société EXEMPLE PME commandé le 14/10/2026.",
         "Il est également disponible dans votre espace pendant 3 mois."],
        attachments=[("Kbis_EXEMPLE_PME.pdf", "application/pdf", PDF)], bulk=False)
    msg("cybermalveillance-alerte", "vert", "Cybermalveillance.gouv.fr", "newsletter@cybermalveillance.gouv.fr", "Alerte : faux mails de factures Chorus Pro",
        ["Bonjour,", "Une campagne de faux courriels imitant Chorus Pro est en cours. Les messages invitent à cliquer pour régler une facture en retard ou à saisir vos identifiants.",
         "Ne cliquez pas, ne communiquez jamais votre mot de passe et signalez le message sur signal-spam.fr."],
        [("https://www.cybermalveillance.gouv.fr/tous-nos-contenus/actualites/alerte-chorus-pro", "Lire l'alerte")], mailfrom="cybermalveillance.gouv.fr", dkim="cybermalveillance.gouv.fr")

    # ---- Informatique et outils ----
    msg("ovh-prelevement-echoue", "vert", "OVHcloud", "noreply@ovh.com", "Échec du prélèvement de votre commande",
        ["Bonjour,", "Le prélèvement de 23,99 € pour la facture FR12345678 n'a pas pu être effectué.",
         "Pour éviter la suspension de vos services, réglez cette facture depuis votre espace client OVHcloud."],
        [("https://www.ovh.com/manager/#/billing/history", "Régler ma facture")], mailfrom="ovh.net", dkim="ovh.com", bulk=False)
    msg("gandi-expiration", "vert", "Gandi", "noreply@gandi.net", "exemple-pme.com expire dans 7 jours",
        ["Bonjour,", "Le domaine exemple-pme.com expire le 26/10/2026. Le renouvellement automatique n'est pas activé.",
         "Renouvelez-le depuis votre interface pour ne pas perdre votre site et vos emails."],
        [("https://admin.gandi.net/domain/exemple-pme.com/renew", "Renouveler")], bulk=False)
    msg("quota-boite-interne", "vert", "Microsoft Exchange", "MicrosoftExchange329e71ec88ae4615bbc36ab6ce41109e@exemple-pme.fr", "Votre boîte aux lettres est presque pleine",
        ["Votre boîte aux lettres a atteint 90 % de sa taille maximale.", "Supprimez ou archivez des éléments pour continuer à recevoir des messages."],
        bulk=False, extra_headers=["X-MS-Exchange-Organization-AuthAs: Internal", "Auto-Submitted: auto-generated"])
    msg("sensibilisation-interne", "vert", "Service informatique", "informatique@exemple-pme.fr", "Attention : campagne de phishing en cours",
        ["Bonjour à tous,", "Plusieurs collaborateurs ont reçu un faux mail « Votre mot de passe expire aujourd'hui » qui demande de saisir vos identifiants.",
         "Ne cliquez pas sur le lien, supprimez le message et signalez-le avec le bouton « Signaler ». Le service informatique ne vous demandera jamais votre mot de passe."],
        bulk=False, extra_headers=["X-MS-Exchange-Organization-AuthAs: Internal"])
    msg("teams-message-manque", "vert", "Microsoft Teams", "noreply@email.teams.microsoft.com", "Vous avez manqué des messages de Paul Durand",
        ["Paul Durand vous a envoyé un message : « Tu peux me renvoyer le devis signé ? »"],
        [("https://teams.microsoft.com/l/message/19:abc@thread.v2/123", "Répondre dans Teams")], mailfrom="email.teams.microsoft.com", dkim="microsoft.com")
    msg("sharepoint-client", "vert", "Julie Bernard", "no-reply@sharepointonline.com", "Julie Bernard a partagé « Bon de commande signé.pdf » avec vous",
        ["Julie Bernard (Client Alpha) a partagé un fichier avec vous.", "Voici le bon de commande signé, bonne réception."],
        [("https://clientalpha.sharepoint.com/:b:/s/achats/EaBcD456?e=abc", "Ouvrir")], mailfrom="sharepointonline.com", bulk=False)
    msg("adobe-sign", "vert", "Groupe Horizon via Adobe Acrobat Sign", "adobesign@adobesign.com", "Contrat cadre 2027 – signature requise",
        ["Groupe Horizon vous demande de signer « Contrat cadre 2027 ».", "Cliquez ci-dessous pour consulter et signer le document."],
        [("https://secure.eu1.adobesign.com/public/apiesign?pid=CBFCIBAA3AAABLblqZhA", "Consulter et signer")], bulk=False,
        reply_to="achats@groupe-horizon.fr")
    msg("editeur-marketo-fortimail", "vert", "Logiciel Pro Partner Program", "engage@partner.logiciel-pro.com", "Invitation : session partenaires du 5 novembre",
        ["Bonjour,", "Nous avons le plaisir de vous inviter à notre session partenaires en ligne.", "Au programme : nouveautés produit et feuille de route 2027."],
        [("https://click.logiciel-pro.com/u/NDI3LVRCQy00NzQAAAGk8pOfjkPoAk", "Je m'inscris")], bulk=True,
        raw_auth=gw_fortimail("mail01.go.logiciel-pro.com", ["mktdns.com", "partner.logiciel-pro.com"]), mailfrom="mail01.go.logiciel-pro.com")

    # ---- Déplacements ----
    msg("sncf-ebillet", "vert", "SNCF Connect", "ne-pas-repondre@sncf-connect.com", "Votre e-billet Paris → Toulon du 12/11",
        ["Bonjour Claire,", "Voici votre e-billet pour le TGV INOUI 6171 du 12/11/2026, départ 08:07.", "Présentez-le à bord sur votre téléphone ou imprimé."],
        attachments=[("e-billet.pdf", "application/pdf", PDF)], bulk=False)
    msg("ulys-facture", "vert", "Ulys by VINCI Autoroutes", "ne-pas-repondre@ulys.vinci-autoroutes.com", "Votre facture de télépéage est disponible",
        ["Bonjour,", "Votre facture d'octobre (48,30 € TTC) est disponible dans votre espace client.", "Elle sera prélevée le 10 du mois prochain."],
        [("https://www.ulys.vinci-autoroutes.com/espace-client/factures", "Voir ma facture")])
    msg("uber-recu", "vert", "Uber Receipts", "noreply@uber.com", "Votre course de jeudi matin avec Uber",
        ["Merci d'avoir choisi Uber, Claire.", "Total : 32,40 €. Payé avec le profil professionnel Exemple PME."],
        [("https://riders.uber.com/trips/abc123", "Voir le reçu")], bulk=False, raw_auth=gw_google("uber.com", "uber.com", "uber.com", "REJECT"))

    # ---- Commerciaux et veille ----
    msg("linkedin-message", "vert", "LinkedIn", "messages-noreply@linkedin.com", "Jean Petit vous a envoyé un message",
        ["Jean Petit, Responsable achats chez Groupe Horizon :", "« Bonjour Claire, suite au salon, pouvons-nous échanger sur votre offre de maintenance ? »"],
        [("https://www.linkedin.com/comm/messaging/thread/2-abc", "Répondre")], bulk=True)
    msg("newsletter-lesechos", "vert", "Les Echos", "newsletters@lesechos.fr", "La Matinale : les PME face aux cyberattaques",
        ["Bonjour,", "Rançongiciels, faux virements, usurpation d'identité : les PME restent la cible numéro un.",
         "Également ce matin : le crédit d'impôt recherche, les taux d'emprunt, la conjoncture."],
        [("https://link.lesechos.fr/c/abc123", "Lire l'article"), ("https://link.lesechos.fr/c/def456", "Toutes les actualités"),
         ("https://link.lesechos.fr/c/ghi789", "Gérer mes newsletters")], mailfrom="mail.lesechos.fr", raw_auth=gw_filtre_fr("mail.lesechos.fr", "lesechos.fr", "lesechos.fr"))
    msg("salon-badge", "vert", "Euromaritime", "badge@euromaritime.fr", "Votre badge visiteur Euromaritime 2027",
        ["Bonjour Claire Martin,", "Votre inscription est confirmée. Votre badge est joint à ce message : imprimez-le ou présentez-le sur votre téléphone."],
        attachments=[("Badge_Euromaritime_2027.pdf", "application/pdf", PDF)], bulk=False)


if __name__ == "__main__":
    main()
    entreprise()
    print(len([f for f in os.listdir(OUT) if f.endswith(".eml")]), "messages dans", os.path.normpath(OUT))
