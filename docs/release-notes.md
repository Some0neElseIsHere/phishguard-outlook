**PhishGuard pour Outlook** : analyse anti-phishing locale, dans le ruban d'Outlook classique.

### Installation

1. Téléchargez **`PhishGuard-Outlook-vX.Y.Z-installeur.exe`** ci-dessous.
2. Fermez Outlook, lancez l'exe, cliquez sur **Installer**, rouvrez Outlook.
3. Réglages depuis Outlook : cliquez sur le score PhishGuard, puis **Paramètres**.

Aucun droit administrateur requis. Installation silencieuse : `PhishGuard-Outlook-vX.Y.Z-installeur.exe /quiet`.
Si l'exe est bloqué par l'antivirus ou AppLocker : prenez le zip et lancez `installer.cmd`.
Une version déjà installée est simplement mise à jour (vos réglages sont conservés).

### Nouveautés de cette version

- **v1.5.1** : pour un expéditeur vérifié, la fenêtre rappelle que le contenu a bien été analysé (texte, liens, pièces jointes) et la preuve « déjà écrit » indique l'adresse.

- **Expéditeur vérifié** : pastille verte avec une coche dans le ruban quand le message est authentifié pour le domaine affiché **et** vient d'un contact déjà connu, sans aucun indice. Les preuves sont listées dans la fenêtre (« Preuves de légitimité ») et ne compensent jamais un indice grave.
- **Alignement DKIM/SPF** : une signature du domaine de l'expéditeur compte comme preuve ; une signature d'un prestataire (outil d'emailing) est simplement signalée.
- **Codes de raison Microsoft (compauth)** : 001 devient « authentification insuffisante » (moyen), 002 « envoi interdit », 010/6xx « usurpation de votre propre domaine » (critique), 1xx/130 comptent comme preuve.
- **Réponse à vos messages** : une vraie réponse à un message que vous avez envoyé est reconnue ; une « réponse » venant d'une autre organisation que celle à qui vous aviez écrit est signalée comme **détournement de fil** (élevé).
- **Envois en nombre conformes** (désabonnement en un clic + DMARC) : le ton commercial n'est plus compté comme un indice faible.
- **Bêta, DNS** : politique DMARC (p=reject/quarantine = domaine protégé, p=none signalé) et **BIMI** (logo de marque avec certificat VMC/CMC).

### Points forts

- Score de risque permanent dans le ruban et alerte pour les messages dangereux.
- Fenêtre d'enquête façon PhishTool : en-têtes, parcours et IP d'origine, URL, pièces jointes avec empreintes, observables et liens VirusTotal/AbuseIPDB.
- Domaines sosies (marques, votre entreprise, vos correspondants), premier contact, âge du domaine.
- SPF/DKIM/DMARC (y compris via ARC), filtres antispam, Red Flag Domains.
- Liens réécrits par les passerelles de sécurité (Proofpoint, Safe Links, Barracuda, Sophos…) décodés et analysés.
- Inspection du contenu des pièces jointes : ZIP, macros, PDF, HTML.
- IBAN et demandes de changement de RIB, fraude au président.
- Interface en français ou en anglais.

### À savoir

- Outlook classique pour Windows uniquement.
- Fichiers non signés : Windows peut afficher « Windows a protégé votre ordinateur » → *Informations complémentaires* → *Exécuter quand même*.
- Liste Red Flag Domains sous licence CC BY-NC-SA 4.0 : vérifiez que votre usage est couvert, ou désactivez-la.

`SHA256SUMS.txt` contient les empreintes des fichiers de cette release.
