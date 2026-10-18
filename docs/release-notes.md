**PhishGuard pour Outlook** : analyse anti-phishing locale, dans le ruban d'Outlook classique.

### Installation

1. Téléchargez **`PhishGuard-Outlook-vX.Y.Z-installeur.exe`** ci-dessous.
2. Fermez Outlook, lancez l'exe, cliquez sur **Installer**, rouvrez Outlook.
3. Réglages depuis Outlook : cliquez sur le score PhishGuard, puis **Paramètres**.

Aucun droit administrateur requis. Installation silencieuse : `PhishGuard-Outlook-vX.Y.Z-installeur.exe /quiet`.
Si l'exe est bloqué par l'antivirus ou AppLocker : prenez le zip et lancez `installer.cmd`.
Une version déjà installée est simplement mise à jour (vos réglages sont conservés).

### Nouveautés de cette version

- **v1.12.2** : correctif de la v1.12.1 : les adresses d'images (logos, pixels) qu'Outlook recopie dans la version texte des messages empêchaient de reconnaître un vrai mail de code de connexion.

- **v1.12.1** : les vrais mails de **code de connexion ou de vérification** (Riot Games, Steam, Vinted, leboncoin…, en anglais comme en français) ne sont plus classés dangereux à cause de leur avertissement « si ce n'est pas vous, changez immédiatement votre mot de passe ». Conditions : message authentifié, aucun indice d'usurpation, ni pièce jointe ni formulaire, et tous les liens chez l'expéditeur ; un seul lien vers un autre site et l'alerte revient.

- **v1.12.0** : moins de fausses alertes sur les vrais mails, mesuré sur 41 mails légitimes « difficiles » (factures, colis, codes de vérification, partages, DocuSign, impots.gouv…) et 4 459 mails de listes de diffusion récentes ([banc d'essai](https://github.com/Some0neElseIsHere/phishguard-outlook/blob/main/docs/banc-essai.md)) : 17 fausses alertes sur 40 → **0**, détection des phishings inchangée (80 %).
  - Un mail authentifié sur le domaine officiel d'une marque (Microsoft, LinkedIn, EDF, La Poste…) n'est plus pénalisé pour parler de mot de passe ou de paiement ; il peut obtenir « Expéditeur vérifié ».
  - DocuSign, Google Drive, OneDrive : l'adresse de réponse de la personne qui partage n'est plus suspecte… mais un partage dont le titre imite une alerte de compte est désormais signalé.
  - Domaines officiels ajoutés (Colissimo, Chronopost, DGFiP, ameli, SharePoint, Yousign, Doctolib) ; « facture@orange.fr » reconnu.

- **v1.11.0** : barème vérifié sur de vrais emails publics (1 800 phishings, 4 700 messages légitimes, voir [docs/banc-essai.md](https://github.com/Some0neElseIsHere/phishguard-outlook/blob/main/docs/banc-essai.md)). Détection : 73 % → **80 %** des phishings ; fausses alertes sur les messages légitimes récents : 46 % → **1 %**.
  - Les listes de diffusion ne déclenchent plus « Reply-To » ni « premier contact ».
  - Nouveaux indices : fausses alertes de messagerie (messages bloqués, boîte pleine, mot de passe qui expire) et votre adresse email dans l'objet.
  - Les combinaisons décisives (identifiants + urgence, paiement + discrétion…) ne sont plus plafonnées : davantage de phishings classés rouges.

- **v1.10.1** : entreprises absentes des annuaires (filiale étrangère, Monaco…) : « Ajouter sans recherche » et « Modifier… » permettent de saisir le pays, l'identifiant et les dirigeants à la main ; Wikidata propose aussi les fiches peu renseignées.

- **Plusieurs entreprises** (Paramètres → Entreprise) : groupe, filiales, y compris à l'étranger. **Ajouter une entreprise…** cherche dans l'Annuaire des Entreprises (France) ou dans Wikidata (autres pays) et récupère ses dirigeants ; pour Wikidata, le site officiel est ajouté aux domaines. Le nom de chaque entreprise est repéré dans le nom affiché des expéditeurs externes.
- **Dirigeants** : la liste est maintenant remplie automatiquement à partir des entreprises et n'est plus modifiable à la main. Les noms saisis dans les versions précédentes sont repris dans la première entreprise.
- **Red Flag Domains** passe dans l'onglet Réputation, avec les autres sources externes.
- Depuis la v1.9 : mode simple et mode expert, assistant de démarrage, QR codes dans les images.

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
