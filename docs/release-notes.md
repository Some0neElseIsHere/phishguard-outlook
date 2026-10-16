Première version publique de **PhishGuard pour Outlook** : analyse anti-phishing locale, dans le ruban d'Outlook classique.

### Installation

1. Téléchargez `PhishGuard-Outlook-vX.Y.Z.zip` ci-dessous et décompressez-le.
2. (Facultatif) Réglez `config.ini` : domaines de l'entreprise, adresse de signalement…
3. Fermez Outlook, lancez `installer.cmd`, rouvrez Outlook.

Aucun droit administrateur requis. Désinstallation : Paramètres Windows → Applications.

### Points forts

- Score de risque permanent dans le ruban et alerte pour les messages dangereux.
- Fenêtre d'enquête façon PhishTool : en-têtes, parcours et IP d'origine, URL, pièces jointes avec empreintes, observables et liens VirusTotal/AbuseIPDB.
- Domaines sosies (marques, votre entreprise, vos correspondants), premier contact, âge du domaine.
- SPF/DKIM/DMARC (y compris via ARC), filtres antispam, Red Flag Domains.
- Inspection du contenu des pièces jointes : ZIP, macros, PDF, HTML.
- IBAN et demandes de changement de RIB, fraude au président.
- Signaler en un clic, « Ce n'est pas du phishing », explications pédagogiques désactivables, paramètres depuis Outlook.

### À savoir

- Outlook classique pour Windows uniquement.
- Fichiers non signés : votre antivirus ou AppLocker peut les bloquer ; faites-les autoriser ou signez la DLL.
- Liste Red Flag Domains sous licence CC BY-NC-SA 4.0 : vérifiez que votre usage est couvert, ou désactivez-la.

`SHA256SUMS.txt` contient les empreintes des fichiers de cette release.
