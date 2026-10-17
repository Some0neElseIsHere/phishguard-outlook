**PhishGuard pour Outlook** : analyse anti-phishing locale, dans le ruban d'Outlook classique.

### Installation

1. Téléchargez **`PhishGuard-Outlook-vX.Y.Z-installeur.exe`** ci-dessous.
2. Fermez Outlook, lancez l'exe, cliquez sur **Installer**, rouvrez Outlook.
3. Réglages depuis Outlook : cliquez sur le score PhishGuard, puis **Paramètres**.

Aucun droit administrateur requis. Installation silencieuse : `PhishGuard-Outlook-vX.Y.Z-installeur.exe /quiet`.
Si l'exe est bloqué par l'antivirus ou AppLocker : prenez le zip et lancez `installer.cmd`.
Une version déjà installée est simplement mise à jour (vos réglages sont conservés).

### Nouveautés de cette version

- **v1.9.3** : liens de vérification ESET et France Verif retirés (VirusTotal, Cisco Talos, AbuseIPDB, listes noires et WHOIS restent).

- **v1.9.2** : liens de vérification : France Verif ajouté à côté d'ESET ; mode simple : pour un expéditeur vérifié, ce qui le confirme est affiché ; rapport de signalement : IP d'origine sans doublon.

- **v1.9.1** : mode simple : chaque point dangereux ou suspect est détaillé (explication, preuves), les simples informations restent en gris sans détail ; bouton « Supprimer le message » retiré.

- **Mode simple pour les débutants** (par défaut) : la fenêtre d'analyse dit en clair « Ce message est dangereux / suspect / Aucun danger détecté », détaille chaque point dangereux ou suspect sans jargon technique (explication et preuves), laisse les simples informations en gris, et donne **« Que dois-je faire ? »** étape par étape (adapté au cas : paiement, mot de passe, pièce jointe…), avec des conseils pour reconnaître un phishing.
- **Mode expert** : la fenêtre d'enquête complète d'avant, en un clic sur **Analyse détaillée** ; le choix est mémorisé. En mode simple, les paramètres n'affichent que l'essentiel (les onglets Listes, Réputation et l'analyse de domaine apparaissent en mode expert).
- **Assistant au démarrage d'Outlook** : à la première installation, il explique la pastille (vert, orange, rouge) et demande la langue, l'entreprise, l'adresse de l'équipe sécurité et le mode d'affichage. Après une mise à jour, il ne pose **que les questions ajoutées** (ici : le mode d'affichage) ; les réponses déjà renseignées ne sont jamais redemandées.
- **QR codes dans les images** (« quishing ») : les QR codes des images du message sont lus sur le poste ; leur présence est signalée et l'adresse qu'ils contiennent est analysée comme un lien (sosies, listes de blocage, réputation…).
- Depuis la v1.8 : signalement HTML détaillé, analyse de votre domaine, liens piégés imitant un fichier, liens de vérification sans compte.

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
