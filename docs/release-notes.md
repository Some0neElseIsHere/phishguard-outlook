**PhishGuard pour Outlook** : analyse anti-phishing locale, dans le ruban d'Outlook classique.

### Installation

1. Téléchargez **`PhishGuard-Outlook-vX.Y.Z-installeur.exe`** ci-dessous.
2. Fermez Outlook, lancez l'exe, cliquez sur **Installer**, rouvrez Outlook.
3. Réglages depuis Outlook : cliquez sur le score PhishGuard, puis **Paramètres**.

Aucun droit administrateur requis. Installation silencieuse : `PhishGuard-Outlook-vX.Y.Z-installeur.exe /quiet`.
Si l'exe est bloqué par l'antivirus ou AppLocker : prenez le zip et lancez `installer.cmd`.
Une version déjà installée est simplement mise à jour (vos réglages sont conservés).

### Nouveautés de cette version

- **Analyser mon domaine** (Paramètres → Entreprise) : à partir de votre domaine, PhishGuard fait le bilan de la sécurité email (SPF, DKIM, DMARC, BIMI, MTA-STS, services autorisés à envoyer en votre nom, avec quoi corriger), lit le SIREN dans les mentions légales du site pour retrouver les dirigeants, liste les **sosies déjà enregistrés** (environ 170 variantes vérifiées dans le DNS), les certificats récents contenant votre marque et les domaines liés à vos certificats. Un clic les ajoute à la liste de blocage ou aux domaines de l'entreprise.
- **Surveillance hebdomadaire des sosies** : les sosies de vos domaines apparus depuis la dernière vérification sont bloqués automatiquement (indice Élevé). Ceux qui existaient déjà ne sont jamais bloqués sans votre accord : il peut s'agir d'homonymes légitimes.
- Recherche des dirigeants par nom ou SIREN, onglet Bêta renommé Réputation (v1.6).

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
