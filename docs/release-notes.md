**PhishGuard pour Outlook** : analyse anti-phishing locale, dans le ruban d'Outlook classique.

### Installation

1. Téléchargez **`PhishGuard-Outlook-vX.Y.Z-installeur.exe`** ci-dessous.
2. Fermez Outlook, lancez l'exe, cliquez sur **Installer**, rouvrez Outlook.
3. Réglages depuis Outlook : cliquez sur le score PhishGuard, puis **Paramètres**.

Aucun droit administrateur requis. Installation silencieuse : `PhishGuard-Outlook-vX.Y.Z-installeur.exe /quiet`.
Si l'exe est bloqué par l'antivirus ou AppLocker : prenez le zip et lancez `installer.cmd`.
Une version déjà installée est simplement mise à jour (vos réglages sont conservés).

### Nouveautés de cette version

- **v1.18.0** : **analyse approfondie**, un bouton de la fenêtre d'analyse pour les messages douteux. Elle ne montre que ce que les autres onglets ne voient pas, et recalcule le verdict :
  - **pièces jointes, sur le poste** : code des macros (lancement automatique, téléchargement ou exécution d'un programme), modèles et objets distants des documents Office, accès à un partage réseau (vol du mot de passe Windows), champs DDE, liens et code cachés dans les parties compressées des PDF, actions à l'ouverture, archives imbriquées, bombes de décompression, pages HTML qui fabriquent un fichier, QR codes de toutes les images ;
  - **votre boîte, sur le poste** : premier message de cette adresse, même nom déjà vu avec une autre adresse (usurpation d'un collègue ou d'un fournisseur), conversation citée introuvable ;
  - **en ligne, sans contenu** : âge et premier certificat de tous les domaines du message, réputation de chaque serveur traversé (AbuseIPDB) et de toutes les pièces jointes (VirusTotal, MalwareBazaar) ;
  - **avec votre accord, case par case** : suivre les liens jusqu'à leur destination réelle (page qui demande un mot de passe, téléchargement direct) et consulter VirusTotal avec l'adresse complète des liens. Deux stratégies permettent au service informatique de l'interdire (`AllowLinkFollowing`, `AllowUrlLookup`).
  - Un récapitulatif indique ce qui a été vérifié, ce qui ne l'a pas été, et tout ce qui est sorti du poste.

- **v1.17.3** : sources de réputation. crt.sh, souvent surchargé, et les autres services sont retentés automatiquement après quelques secondes en cas d'erreur passagère. L'onglet Réputation de l'analyse détaillée distingue maintenant un service momentanément indisponible (nouvel essai dans 10 minutes) d'une clé d'API refusée, au lieu d'afficher « Service injoignable ou clé refusée » pour tout, y compris pour crt.sh qui n'utilise aucune clé.

- **v1.17.2** : paramètres réorganisés. Nouvel onglet **Affichage** : langue, fenêtre d'analyse (simple ou expert), thème, alerte à l'écran, explications pédagogiques et couleur des messages suspects. L'onglet **Analyse** ne garde que ce qui règle l'analyse elle-même.

- **v1.17.1** : niveaux de protection SPF, DKIM et DMARC (avec les vérifications DNS activées). Un expéditeur inconnu dont le SPF se termine par « +all » (n'importe quel serveur peut envoyer en son nom) est signalé. Une politique DMARC appliquée à une partie des messages seulement (pct inférieur à 100) n'est plus comptée comme preuve de protection. « Analyser mon domaine » indique la taille de vos clés DKIM et signale une clé de 1024 bits ou moins, ainsi qu'une clé révoquée.

- **v1.17.0** :
  - **Nouvelles arnaques détectées** : l'annonce d'un appel d'un faux conseiller bancaire (« validez l'opération avec le code reçu par SMS »), la demande de numéro de carte ou de cryptogramme, et le lien caché dans un PDF joint. Nouvelles marques : leboncoin, Vinted.
  - **31 faux phishings français fictifs** ajoutés au banc d'essai : tous signalés, 27 en rouge. Les mails légitimes difficiles restent tous verts (78 sur 78).
  - **Sécurité** : un message contenant un caractère Unicode invalide pouvait faire échouer l'analyse et rester sans verdict ni alerte. Corrigé ; une analyse qui échoue classe désormais le message « suspect ». Pour un expéditeur inconnu, les vérifications DNS n'interrogent plus que le domaine principal, ce qui empêche un sous-domaine unique par destinataire de servir d'accusé de lecture.
  - **Qualité** : banc d'essai complet chaque mois avec ticket automatique en cas de baisse ; tests de robustesse sur des milliers de messages malformés ; signature Authenticode du complément possible lors de la construction (certificat à fournir).

- **v1.16.5** : sécurité. Un message piégé pouvait **figer Outlook** plusieurs minutes dès sa sélection : un HTML de quelques centaines de Ko construit pour faire travailler la lecture des liens en temps quadratique (200 Ko : environ 15 s ; 1 Mo : plusieurs minutes). La lecture des liens et des formulaires est maintenant linéaire (2 Mo piégés : 0,1 s), les autres motifs appliqués au contenu du message sont bornés, et une image qui annonce plus de 40 millions de pixels n'est plus décodée pour y chercher un QR code. Aucun effet sur la détection (banc d'essai identique).

- **v1.16.4** : thème sombre. Le bandeau du bas de la fenêtre d'analyse (boutons et ligne d'état) pouvait rester blanc quand le thème de Windows changeait pendant qu'Outlook était ouvert. Le thème est maintenant revérifié à chaque affichage de la fenêtre.

- **v1.16.3** : travail sur les mails d'entreprise français. 32 nouveaux cas réalistes (paie, banque pro, comptabilité, Chorus Pro, Urssaf, Infogreffe, OVHcloud, Teams, SNCF…), reçus par Microsoft 365, FortiMail, Google Workspace ou un filtre français : tous corrects. Un avis de virement reçu ou de remboursement versé n'est plus pris pour une « demande sensible ». Nouvelles marques reconnues : Mon Compte Formation (CPF), VINCI Autoroutes, Qonto, OVHcloud, SNCF, Chorus Pro, Urssaf, Crit'Air. Sur 421 vrais phishings en français : 99,8 % signalés, 84 % en rouge.

- **v1.16.2** : messages internes. Au lieu de « SPF absent, DKIM absent, DMARC absent », la fenêtre d'analyse et le rapport de signalement expliquent pourquoi : le message n'est pas passé par Internet, et c'est le serveur Exchange (ou un équipement interne déclaré) qui garantit l'expéditeur.

- **v1.16.1** : passerelles de messagerie qui ne donnent pas de résultat DMARC (FortiMail, par exemple). La signature DKIM est maintenant reconnue quand la passerelle n'indique que `header.i`. Si la signature DKIM ou le SPF est valide et appartient au domaine affiché, DMARC s'affiche « pass », avec la mention « déduit par PhishGuard », au lieu de « absent ». La politique DMARC publiée par le domaine est formulée plus clairement, pour ne plus être confondue avec le résultat du contrôle.

- **v1.16.0** : **thème sombre**. Les fenêtres de PhishGuard (analyse, paramètres, assistant, alerte) suivent le mode clair ou sombre de Windows, y compris quand il change pendant qu'Outlook est ouvert. Le thème peut aussi être choisi dans Paramètres → Analyse → Thème, ou imposé par stratégie (`Theme`). Le rapport envoyé à l'équipe sécurité reste en clair.

- **v1.15.1** : testé sur 12 271 phishings récents supplémentaires (phishing_pot, 2023-2026) : 78 % détectés, comme sur le premier corpus. **Analyse jusqu'à 7 fois plus rapide** sur les messages chargés en liens, et un lien au nom de serveur invalide ne peut plus faire échouer l'analyse.

- **v1.15.0** : **déploiement en entreprise** ([guide](https://github.com/Some0neElseIsHere/phishguard-outlook/blob/main/docs/deploiement-entreprise.md)).
  - **Stratégies de groupe (GPO) et Intune** : modèle `policies\PhishGuard.admx` en français et en anglais dans le zip. Les réglages imposés (adresse de signalement, entreprises, domaines, sources…) sont grisés et l'utilisateur ne peut pas les modifier.
  - **Mode simple imposé** pour les groupes choisis : plus de bouton « Analyse détaillée » ni de réglages avancés.
  - **Clés d'API interdites** sur les postes, au choix (une clé lisible par le poste l'est aussi par l'utilisateur).
  - **Copieurs et applications internes** : déclarez leurs IP (Paramètres → Entreprise en mode expert, ou par stratégie) ; leurs mails au nom de l'entreprise ne sont plus pris pour une usurpation, un mail à votre nom venant d'ailleurs reste critique.
  - L'option `AllowUserSettings`, contournable, est retirée : `config.ini` fournit les valeurs de départ.

- **v1.14.0** : nouvel onglet **À propos** dans les paramètres : version, liens vers le projet, nouveautés et signalement d'un problème, ce qui sort du poste, sources et licences, bouton « Copier les informations pour le support » (sans donnée personnelle). Quand la configuration est imposée par l'entreprise, le bouton Paramètres devient « À propos » et l'indique. Fenêtre d'analyse allégée : les onglets Observables et Corps sont retirés, les liens de vérification des domaines passent dans En-têtes et URL.

- **v1.13.0** : moins de fausses alertes sur les organismes publics et les autres domaines des marques.
  - **Organismes publics** : les domaines `.gouv.fr` et les quelque 100 000 domaines de la liste ouverte du secteur public (DINUM : ministères, collectivités, hôpitaux, écoles…) ne sont plus pris pour des sosies. Liste téléchargée chaque mois (Paramètres → Réputation, activée par défaut). Pour les petites structures, souvent piratées, le contenu des messages reste analysé normalement.
  - **Autres domaines d'une marque** (autre extension, ancien nom) : avec la vérification DNS activée, un domaine qui ressemble à une marque ou à votre entreprise est reconnu comme le sien s'il est géré par ses propres serveurs DNS, ou si le domaine officiel autorise ses rapports DMARC. Un escroc ne peut produire ni l'un ni l'autre.
  - Adresses automatiques avec tiret bas (`no_reply`, `do_not_reply`, `ne_pas_repondre`) reconnues.

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
- Fenêtre d'enquête détaillée : en-têtes, parcours et IP d'origine, URL, pièces jointes avec empreintes, observables et liens VirusTotal/AbuseIPDB.
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
