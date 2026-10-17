**PhishGuard pour Outlook** : analyse anti-phishing locale, dans le ruban d'Outlook classique.

### Installation

1. Téléchargez **`PhishGuard-Outlook-vX.Y.Z-installeur.exe`** ci-dessous.
2. Fermez Outlook, lancez l'exe, cliquez sur **Installer**, rouvrez Outlook.
3. Réglages depuis Outlook : cliquez sur le score PhishGuard, puis **Paramètres**.

Aucun droit administrateur requis. Installation silencieuse : `PhishGuard-Outlook-vX.Y.Z-installeur.exe /quiet`.
Si l'exe est bloqué par l'antivirus ou AppLocker : prenez le zip et lancez `installer.cmd`.
Une version déjà installée est simplement mise à jour (vos réglages sont conservés).

### Nouveautés de cette version

- **v1.8.3** : liens piégés qui imitent un fichier : texte en forme de chemin (`C:\…`) ou de document (`facture.pdf`) qui ouvre autre chose, liens vers un fichier local ou un partage réseau (`file:`, `\\serveur\…`), protocoles qui lancent une fonction de Windows (`search-ms:`, `ms-msdt:`…). Paramètres : les textes d'aide sur deux lignes ne chevauchent plus le champ suivant.

- **v1.8.2** : rapport de signalement : les contrôles SPF / DKIM / DMARC ne sont plus collés dans Outlook. Onglet Pièces jointes : « Item not found » de VirusTotal expliqué, et résultat VirusTotal affiché directement si une clé est configurée. Les serveurs qui écrivent un en-tête Authentication-Results par contrôle sont maintenant lus en entier (SPF et DMARC n'apparaissent plus « absents » à tort).

- **v1.8.1** : documentation revue (README, notice du zip), `config.ini` sans valeurs d'exemple : sans domaine configuré, celui de votre adresse Outlook est utilisé ; la surveillance des sosies tient un point de départ par domaine (un second domaine n'est plus bloqué en masse au premier passage).

- **Signalement à la sécurité refait** : le rapport envoyé est maintenant un email HTML lisible : verdict en bandeau, « En bref », chaque point de doute avec sa gravité, son explication et ses preuves, authentification et origine (SPF/DKIM/DMARC, IP, parcours), liens et texte affiché, pièces jointes avec empreintes, observables à copier, preuves de légitimité, et une copie du texte du message d'origine. Toutes les adresses sont désarmées (hxxps://exemple[.]com) : rien n'est cliquable.
- Le **message d'origine reste joint** (.msg avec tous ses en-têtes) pour l'analyse.
- **Double confirmation** avant l'envoi, puis envoi direct (si Outlook refuse l'envoi automatique, le message s'ouvre pour être envoyé à la main). Le message n'est déplacé dans Courrier indésirable qu'une fois le signalement parti.
- v1.7 : Analyser mon domaine et surveillance hebdomadaire des sosies.

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
