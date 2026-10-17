**PhishGuard pour Outlook** : analyse anti-phishing locale, dans le ruban d'Outlook classique.

### Installation

1. Téléchargez **`PhishGuard-Outlook-vX.Y.Z-installeur.exe`** ci-dessous.
2. Fermez Outlook, lancez l'exe, cliquez sur **Installer**, rouvrez Outlook.
3. Réglages depuis Outlook : cliquez sur le score PhishGuard, puis **Paramètres**.

Aucun droit administrateur requis. Installation silencieuse : `PhishGuard-Outlook-vX.Y.Z-installeur.exe /quiet`.
Si l'exe est bloqué par l'antivirus ou AppLocker : prenez le zip et lancez `installer.cmd`.
Une version déjà installée est simplement mise à jour (vos réglages sont conservés).

### Nouveautés de cette version

- **Clés d'API conservées** : elles sont désormais rangées dans le Gestionnaire d'identification de Windows (chiffrées pour votre compte, jamais en clair sur le disque) et ne sont plus à retaper après une mise à jour. Les clés déjà saisies y sont déplacées automatiquement.
- Bandeau et zone d'alerte retirés (le score reste dans le ruban, l'alerte en bas à droite reste disponible).
- Résumé compact, authentification lisible (SPF ✓, DKIM ✓, DMARC ✓), explications au survol.

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
