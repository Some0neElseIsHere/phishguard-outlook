#!/usr/bin/env python3
"""PhishGuard - génère le corpus de FAUX phishings français du banc d'essai (tests/phishings-fr/*.eml).

Messages entièrement fictifs, inspirés des campagnes décrites publiquement par Cybermalveillance.gouv.fr, l'ANSSI
et le CERT-FR : faux Ameli, CPF, ANTAI, Crit'Air, colis, impots.gouv, Chorus Pro, Urssaf, Microsoft 365, banques,
fraude au président, faux changement de RIB, pièces jointes piégées, conversations détournées. Aucune donnée réelle :
domaines d'arnaque inventés, destinataire fictif (claire.martin@exemple-pme.fr).

Ils sont construits comme les vrais : la plupart viennent d'un domaine sosie correctement authentifié (c'est le cas
le plus courant aujourd'hui et le plus difficile hors ligne), d'autres d'une boîte piratée, d'une messagerie gratuite
ou d'une adresse usurpée. Chaque message porte X-PhishGuard-Attendu : « rouge » (doit être classé dangereux) ou
« alerte » (orange ou rouge). Le banc compare le verdict à cette attente.

Usage : python3 tools/gen-phishings.py   (réécrit tests/phishings-fr/)
"""
import importlib.util, io, os, random, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("legit", os.path.join(HERE, "gen-legitimes.py"))
legit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legit)
legit.OUT = os.path.join(HERE, "..", "tests", "phishings-fr")
random.seed(11)
msg, PDF = legit.msg, legit.PDF


def ph(fid, expect, *args, **kw):
    kw.setdefault("bulk", False)
    msg(fid, expect, *args, **kw)


def spoof(mailfrom, header_from):
    """Adresse usurpée : SPF et DMARC en échec (le domaine affiché n'a pas autorisé ce serveur)."""
    return [f"Authentication-Results: spf=fail (sender IP is 203.0.113.{random.randint(2, 250)}) smtp.mailfrom={mailfrom}; "
            f"dkim=none (message not signed) header.d=none;dmarc=fail action=quarantine header.from={header_from};compauth=fail reason=000"]


def zip_with(name, data=b"MZ\x90\x00"):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr(name, data)
    return b.getvalue()


PDF_URI = (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
           b"3 0 obj<</Type/Page/Parent 2 0 R/Annots[4 0 R]>>endobj\n"
           b"4 0 obj<</Type/Annot/Subtype/Link/A<</S/URI/URI(https://docs-partage-securise.com/f/8841?u=claire)>>>>endobj\n"
           b"trailer<</Root 1 0 R>>\n%%EOF\n")

HTML_LOGIN = ("<html><body><h2>Microsoft 365</h2><p>Connectez-vous pour afficher le document.</p>"
              "<form action='https://collect-portail.example/p' method='post'><input name='login' value='claire.martin@exemple-pme.fr'>"
              "<input type='password' name='pwd'><button>Se connecter</button></form></body></html>").encode()


def main():
    os.makedirs(legit.OUT, exist_ok=True)
    for f in os.listdir(legit.OUT):
        if f.endswith(".eml"): os.remove(os.path.join(legit.OUT, f))

    # ---- Administrations et organismes imités (domaines sosies authentifiés) ----
    ph("ameli-carte-vitale", "rouge", "Assurance Maladie", "contact@ameli-renouvellement.fr", "Votre carte Vitale expire : renouvelez-la avant le 31/10",
       ["Cher(e) assuré(e),", "Votre carte Vitale arrive à expiration. Pour continuer à être remboursé, vous devez la renouveler avant le 31/10/2026.",
        "Des frais d'envoi de 4,99 € vous seront demandés. Sans action de votre part, vos remboursements seront suspendus."],
       [("https://ameli-renouvellement.fr/vitale/commande", "Renouveler ma carte Vitale")])
    ph("cpf-droits", "rouge", "Mon Compte Formation", "info@moncompte-formation-cpf.com", "Vos droits CPF expirent : 1 450 € à utiliser",
       ["Bonjour,", "Il vous reste 1 450 € sur votre Compte Personnel de Formation. Ces droits seront perdus le 31 décembre.",
        "Connectez-vous avec votre numéro de sécurité sociale pour les conserver. Offre limitée."],
       [("https://moncompte-formation-cpf.com/connexion", "Conserver mes droits")])
    ph("antai-amende", "rouge", "ANTAI - Service des amendes", "noreply@antai-paiement.com", "Avis de contravention impayé : majoration sous 48 h",
       ["Madame, Monsieur,", "Sauf erreur de notre part, l'avis de contravention n° 4521-8841 reste impayé.",
        "Réglez immédiatement 35,00 € pour éviter la majoration à 75,00 €. Paiement par carte bancaire."],
       [("https://antai-paiement.com/payer?ref=4521-8841", "Payer mon amende")])
    ph("critair-vignette", "rouge", "Crit'Air", "service@certificat-critair.info", "Votre vignette Crit'Air n'est plus valide",
       ["Bonjour,", "Votre certificat qualité de l'air n'est plus valide. Circuler sans vignette est passible d'une amende de 68 €.",
        "Commandez votre nouvelle vignette (3,77 €) dès aujourd'hui."],
       [("https://certificat-critair.info/commande", "Commander ma vignette")])
    ph("impots-remboursement", "rouge", "impots.gouv.fr", "remboursement@impots-gouv-fr.com", "Remboursement de 245,80 € en attente",
       ["Madame, Monsieur,", "Après le dernier calcul de votre impôt, vous êtes éligible à un remboursement de 245,80 €.",
        "Pour le recevoir, confirmez vos coordonnées bancaires sous 72 heures, faute de quoi la somme sera perdue."],
       [("https://impots-gouv-fr.com/remboursement", "Recevoir mon remboursement")])
    ph("urssaf-majoration", "rouge", "Urssaf", "contact@urssaf-recouvrement.fr", "Dernier rappel avant majoration",
       ["Bonjour,", "Votre échéance de cotisations du 15/10 n'a pas été réglée. Une majoration de 10 % sera appliquée sous 24 h.",
        "Régularisez votre situation en ligne immédiatement."],
       [("https://urssaf-recouvrement.fr/espace/regler", "Régulariser")])
    ph("chorus-pro-facture", "rouge", "Chorus Pro", "facturation@chorus-pro-portail.fr", "Facture en retard FR-2026-8841 : régularisez sous 24 h",
       ["Bonjour,", "La facture FR-2026-8841 d'un montant de 3 480,00 € TTC est en retard de paiement.",
        "Connectez-vous à votre espace Chorus Pro pour consulter la facture et procéder au règlement avant suspension de votre compte."],
       [("https://chorus-pro-portail.fr/login", "Accéder à mon espace")])
    ph("france-travail-dossier", "alerte", "France Travail", "dossier@francetravail-actualisation.fr", "Mise à jour obligatoire de votre dossier",
       ["Bonjour,", "Suite à une mise à jour de nos services, vous devez vérifier vos informations personnelles et votre RIB.",
        "Sans mise à jour sous 5 jours, vos versements seront interrompus."],
       [("https://francetravail-actualisation.fr/maj", "Mettre à jour mon dossier")])

    # ---- Colis ----
    ph("laposte-frais", "rouge", "La Poste", "suivi@laposte-livraison.net", "Colis en attente : frais de réexpédition",
       ["Bonjour,", "Votre colis n° LP8841FR n'a pas pu être livré : l'adresse est incomplète.",
        "Réglez les frais de réexpédition de 1,99 € pour programmer une nouvelle livraison. Le colis sera retourné à l'expéditeur sous 48 h."],
       [("https://laposte-livraison.net/suivi/LP8841FR", "Programmer la livraison")])
    ph("chronopost-boite-piratee", "alerte", "Chronopost", "contact@boulangerie-dupont.fr", "Livraison en attente : action requise",
       ["Votre colis est en attente au dépôt.", "Confirmez votre adresse et réglez 2,99 € de frais de douane pour le recevoir."],
       [("https://bit.ly/3ChrOno8", "Suivre mon colis")])
    ph("dhl-raccourci", "alerte", "DHL Express", "service@transit-logistique.net", "Votre envoi est bloqué en douane",
       ["Bonjour,", "Votre envoi 1234567890 est retenu en douane. Des frais de 3,20 € doivent être réglés aujourd'hui."],
       [("https://tinyurl.com/dhl-douane-8841", "Régler les frais")])

    # ---- Comptes et messagerie ----
    ph("m365-mdp-expire", "rouge", "Microsoft 365", "no-reply@micros0ft-securite.com", "Votre mot de passe expire aujourd'hui pour claire.martin@exemple-pme.fr",
       ["Votre mot de passe Microsoft 365 expire aujourd'hui.", "Pour conserver le même mot de passe, confirmez-le immédiatement. Sinon, l'accès à votre messagerie sera bloqué."],
       [("https://micros0ft-securite.com/office/keep-password", "Conserver mon mot de passe")])
    ph("boite-pleine-sosie-entreprise", "rouge", "Administrateur de messagerie", "admin@exemple-pme-mail.fr", "Votre boîte aux lettres est pleine : 14 messages bloqués",
       ["Bonjour Claire,", "Votre boîte aux lettres a dépassé son quota. 14 messages entrants sont bloqués.",
        "Validez votre compte pour augmenter votre espace et libérer vos messages."],
       [("https://exemple-pme-mail.fr/owa/quota", "Libérer mes messages")])
    ph("sharepoint-faux", "rouge", "Paul Durand (via SharePoint)", "partage@sharepoint-docs.net", "Paul Durand a partagé « Facture impayée.pdf » avec vous",
       ["Paul Durand a partagé un fichier avec vous.", "Facture impayée.pdf", "Connectez-vous avec votre compte professionnel pour l'ouvrir."],
       [("https://sharepoint-docs.net/s/facture-impayee", "Ouvrir")])
    ph("docusign-faux", "rouge", "DocuSign", "dse@docusign-esign.net", "Veuillez signer : avenant salarial 2027",
       ["La direction des ressources humaines vous a envoyé un document à signer : avenant salarial 2027.", "Merci de signer avant ce soir."],
       [("https://docusign-esign.net/Signing/start?id=8841", "CONSULTER LE DOCUMENT")])
    ph("orange-messagerie", "rouge", "Orange", "service.client@orange-messagerie.fr", "Votre messagerie sera désactivée sous 24 h",
       ["Cher client,", "Votre compte de messagerie n'a pas été vérifié. Il sera désactivé sous 24 heures.", "Vérifiez votre compte maintenant pour conserver vos emails."],
       [("https://orange-messagerie.fr/verification", "Vérifier mon compte")])
    ph("teams-vocal-html", "rouge", "Messagerie vocale Teams", "voicemail@teams-audio.net", "Vous avez reçu un message vocal (0:42)",
       ["Vous avez un nouveau message vocal de +33 4 94 00 00 00.", "Écoutez-le en ouvrant la pièce jointe."],
       attachments=[("Message_vocal_0042.htm", "text/html", HTML_LOGIN)])
    ph("linkedin-faux", "alerte", "LinkedIn", "messages@linkedin-notification.net", "Vous avez 3 nouveaux messages",
       ["Bonjour Claire,", "Des recruteurs ont consulté votre profil et vous ont envoyé 3 messages.", "Connectez-vous pour les lire."],
       [("https://linkedin-notification.net/login", "Voir mes messages")])
    ph("support-gmail", "rouge", "Assistance Microsoft", "microsoft.support.france@gmail.com", "Activité suspecte détectée sur votre compte",
       ["Bonjour,", "Une connexion suspecte a été détectée sur votre compte Microsoft.", "Vérifiez votre identité immédiatement en saisissant vos identifiants, sinon votre compte sera suspendu."],
       [("https://forms.gle/a1B2c3D4e5", "Vérifier mon identité")], mailfrom="gmail.com", dkim="gmail.com")

    # ---- Banques et paiement ----
    ph("banque-operation", "rouge", "Crédit Agricole", "securite@credit-agricole-alerte.com", "Opération inhabituelle : validez votre identité",
       ["Cher client,", "Une opération de 1 249,00 € a été détectée sur votre compte.", "Si vous n'êtes pas à l'origine de ce paiement, annulez-le immédiatement en vous connectant."],
       [("https://credit-agricole-alerte.com/annulation", "Annuler l'opération")])
    ph("leboncoin-paiement", "rouge", "leboncoin", "paiement@leboncoin-securise.fr", "Votre acheteur a payé : recevez l'argent",
       ["Bonjour,", "L'acheteur de votre annonce a réglé 180,00 €. Vous avez reçu un paiement sécurisé.",
        "Pour recevoir l'argent, saisissez votre numéro de carte bancaire sur la page de réception des fonds."],
       [("https://leboncoin-securise.fr/reception", "Recevoir l'argent")])
    ph("paypal-usurpe", "rouge", "PayPal", "service@paypal.fr", "Votre compte est limité",
       ["Bonjour,", "Nous avons limité votre compte suite à une activité inhabituelle.", "Confirmez vos informations pour lever la limitation."],
       [("https://paypal-resolution-centre.com/fr", "Confirmer mes informations")], raw_auth=spoof("mailer.resolution-centre.com", "paypal.fr"))
    ph("conseiller-rappel", "alerte", "Service sécurité bancaire", "alerte@securite-banque-service.fr", "Fraude détectée : votre conseiller va vous rappeler",
       ["Bonjour,", "Une tentative de fraude a été détectée sur votre compte. Votre conseiller va vous appeler dans l'heure.",
        "Pour sécuriser vos fonds, il vous demandera de valider une opération avec votre code reçu par SMS. Ne raccrochez pas."])

    # ---- Fraude au virement ----
    ph("president-virement", "rouge", "Jean Martin", "jean.martin.direction@gmail.com", "Demande confidentielle",
       ["Bonjour Claire,", "Je suis en réunion et ne peux pas être joint. J'ai besoin que vous effectuiez un virement urgent de 48 500 € pour une acquisition confidentielle.",
        "Ne parlez de ceci à personne, même en interne, avant l'annonce officielle. Je vous envoie les coordonnées bancaires."], mailfrom="gmail.com", dkim="gmail.com")
    ph("rib-fournisseur-sosie", "alerte", "Comptabilité Bureautique Pro", "compta@bureautique-pro-fr.com", "Changement de coordonnées bancaires - urgent",
       ["Bonjour,", "Notre banque a changé. Merci de mettre à jour nos coordonnées dès aujourd'hui pour le règlement de la facture F2026-0912 :",
        "IBAN : FR76 1027 8060 3100 0205 2840 172 - BIC : CMCIFR2A", "Merci de traiter ce changement en priorité. Service comptabilité."])
    ph("conversation-detournee", "alerte", "Paul Durand", "paul.durand@client-alpha-group.com", "RE: Devis maintenance 2027",
       ["Bonjour Claire,", "Suite à notre échange, voici la facture mise à jour avec nos nouvelles coordonnées.",
        "Le document est disponible sur notre espace de partage, merci de le consulter rapidement."],
       [("https://onedrive-partage.net/f/devis-2027", "Voir le document")],
       extra_headers=["In-Reply-To: <devis-123@exemple-pme.fr>", "References: <devis-123@exemple-pme.fr>"])
    ph("usurpation-interne", "rouge", "Service comptabilité", "compta@exemple-pme.fr", "Virement fournisseur à valider aujourd'hui",
       ["Bonjour,", "Merci de valider le virement de 12 900 € au fournisseur ci-dessous avant 16 h, la direction l'a approuvé.", "Cordialement"],
       raw_auth=spoof("compta-validation.com", "exemple-pme.fr"))

    # ---- Pièces jointes piégées ----
    ph("facture-html-login", "rouge", "Service facturation", "facturation@gestion-factures-pro.com", "Facture n° 2026-8841",
       ["Bonjour,", "Veuillez trouver ci-joint votre facture. Ouvrez le fichier pour la consulter."],
       attachments=[("Facture_2026-8841.html", "text/html", HTML_LOGIN)])
    ph("commande-zip-exe", "rouge", "Service commandes", "commandes@achats-fournitures-pro.fr", "Bon de commande n° 8841",
       ["Bonjour,", "Vous trouverez ci-joint notre bon de commande. Merci de confirmer la disponibilité."],
       attachments=[("Commande_8841.zip", "application/zip", zip_with("Commande_8841.pdf.exe"))])
    ph("livraison-img", "alerte", "Transporteur", "livraison@express-transport-fr.com", "Bon de livraison à signer",
       ["Bonjour,", "Le bon de livraison est joint. Merci de l'ouvrir et de le signer."],
       attachments=[("Bon_de_livraison.img", "application/octet-stream", b"\x00" * 2048)])
    ph("pdf-lien-partage", "alerte", "Cabinet Ferrand Expertise", "contact@ferrand-expertise-comptable.com", "Documents de clôture à consulter",
       ["Bonjour,", "Les documents de clôture sont dans le PDF joint. Cliquez sur le lien du document pour y accéder."],
       attachments=[("Documents_cloture.pdf", "application/pdf", PDF_URI)])


if __name__ == "__main__":
    main()
    print(len([f for f in os.listdir(legit.OUT) if f.endswith(".eml")]), "messages dans", os.path.normpath(legit.OUT))
