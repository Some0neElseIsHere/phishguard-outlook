**PhishGuard pour Outlook** : analyse anti-phishing locale, dans le ruban d'Outlook classique.

### Installation

1. Téléchargez **`PhishGuard-Outlook-vX.Y.Z-installeur.exe`** ci-dessous.
2. Fermez Outlook, lancez l'exe, cliquez sur **Installer**, rouvrez Outlook.
3. Réglages depuis Outlook : cliquez sur le score PhishGuard, puis **Paramètres**.

Aucun droit administrateur requis. Installation silencieuse : `PhishGuard-Outlook-vX.Y.Z-installeur.exe /quiet`.
Si l'exe est bloqué par l'antivirus ou AppLocker : prenez le zip et lancez `installer.cmd`.
Une version déjà installée est simplement mise à jour (vos réglages sont conservés).

### Nouveautés de cette version

- **v1.21.7** : retour du lien permanent vers la dernière version (`…/releases/latest/download/PhishGuard-Outlook-installeur.exe`, en tête du README) : chaque version publie aussi une copie de l'installeur sans numéro dans son nom.

- **v1.21.6** : page des versions plus lisible : chaque version n'affiche plus que ses propres nouveautés, avec les liens de téléchargement en tête. Le lien « Télécharger » du README mène toujours à la dernière version.

- **v1.21.5** : le fichier de configuration de l'entreprise ne contient plus que ce qui décrit l'entreprise : entreprises et dirigeants, domaines, adresse de l'équipe sécurité, réseau interne. Les sources de réputation, listes et autres réglages restent propres à chaque poste (et ne sont plus lus à l'import).

- **v1.21.4** : molette de la souris dans les paramètres, l'assistant et l'analyse du domaine : la page défile d'un trait, sans s'arrêter sur chaque zone de saisie ou liste traversée. Pour faire défiler une zone longue, cliquez d'abord dedans. Une liste déroulante n'est plus modifiée par erreur en passant dessus.

- **v1.21.3** : désinstallation : la fenêtre se ferme toute seule après quelques secondes (plus de « Appuyez sur une touche »).

- **v1.21.2** : correction de la v1.21.1 : « Plus tard » sur les pages de l'entreprise fermait encore l'assistant au lieu de passer à la page Réputation.

- **v1.21.1** : assistant, en entreprise : « Plus tard » sur les pages Configuration, Entreprise ou Réseau interne passe directement à la page Réputation (au lieu de fermer l'assistant). Ces informations se complètent ensuite dans Paramètres → Entreprise.

- **v1.21.0** :
  - **Paramètres complets en mode simple** : les onglets Listes et Réputation, et l'analyse de votre domaine, ne sont plus réservés au mode expert. Le mode ne change plus que la fenêtre d'analyse. Seule la stratégie « mode simple imposé » les masque encore ;
  - **usage personnel** : l'onglet Entreprise est masqué. Le choix se change dans Paramètres → Analyse → Utilisation, et l'onglet revient aussitôt ;
  - **assistant, en entreprise** : une page propose d'**importer le fichier de configuration de l'entreprise**. Sans fichier, tout est obligatoire : entreprise (annuaire), domaines, équipe sécurité, serveurs de messagerie, équipements (ou « aucun »), réseaux des postes ;
  - **Paramètres → Entreprise → Exporter… / Importer…** : le fichier de configuration à donner aux autres postes, sans clé d'API ni réglage personnel ;
  - **assistant, réputation** : toutes les sources sont cochées par défaut.

- **v1.20.2** : thème sombre : la ligne sélectionnée d'une liste (entreprises, résultats de l'annuaire, sosies…) s'affiche en blanc sur bleu, au lieu de gris foncé sur gris, illisible.

- **v1.20.1** : corrections de l'assistant de démarrage et de la désinstallation :
  - **l'usage (entreprise ou personnel) est toujours demandé** tant qu'il n'est pas connu, y compris après une mise à jour. Le choix proposé par défaut est « entreprise », sauf pour une adresse personnelle (Gmail, Orange…). En choisissant « entreprise », ce qui manque (entreprise, équipe sécurité, réseau interne) est proposé dans la foulée ;
  - **l'entreprise se cherche dans l'Annuaire des Entreprises** (France) ou Wikidata, comme dans les paramètres : nom, SIREN et dirigeants ;
  - **le réseau interne reste visible dans les paramètres en mode simple** pour une utilisation en entreprise ;
  - **la désinstallation garde vos réglages** (`config.user.ini`, domaines bloqués) dans `%LOCALAPPDATA%\PhishGuard-reglages` : une réinstallation les retrouve. Avant, ils étaient effacés avec le programme.

- **v1.20.0** : nouvel **assistant de démarrage**, page par page :
  - **Bienvenue** : la pastille, la langue, l'affichage simple ou expert ;
  - **Utilisation** : en entreprise ou à titre personnel. En usage personnel, pas de questions sur l'entreprise ni d'équipe sécurité : le bouton **Signaler** déplace simplement le message dans le courrier indésirable ;
  - **Votre entreprise** (si entreprise) : nom, domaines, adresse de l'équipe sécurité ;
  - **Réseau interne** (si entreprise) : serveurs de messagerie, équipements et leurs expéditeurs autorisés, réseaux des postes, avec des exemples ;
  - **Réputation** : chaque source expliquée (ce qu'elle apporte, ce qui est envoyé et à qui), à cocher ou non.
  
  Après la mise à jour, l'assistant ne propose que ce qui n'est pas encore réglé (par exemple le réseau interne et la réputation). Les questions imposées par l'administrateur (GPO, `config.ini`) ne sont jamais posées.

- **v1.19.19** : mode simple : les indices faibles, qui comptent dans la note, sont maintenant détaillés dans une rubrique « À noter », avec leur explication et la preuve (par exemple l'adresse réelle d'un lien). Seules les simples informations, sans effet sur la note, restent en gris.

- **v1.19.18** : « Analyser mon domaine » depuis le réseau de l'entreprise : quand le domaine interne (Active Directory) porte le même nom que le domaine public, le DNS interne cachait les enregistrements publics, et l'analyse annonçait à tort « aucun MX, pas de SPF, pas de DMARC ». PhishGuard le détecte et lit alors ces enregistrements sur un DNS public (1.1.1.1 ou 8.8.8.8), en l'indiquant dans le rapport. Si aucun DNS public n'est joignable, un avertissement invite à confirmer les résultats depuis un réseau extérieur.

- **v1.19.17** : « Analyser mon domaine » → Sosies du domaine :
  - **plus de lettres qui se ressemblent** : m ↔ nn, ni, ri, in ; n ↔ ri, ii ; u ↔ v ; w ↔ uu ; g ↔ q ; o, e ↔ c… (par exemple `exemple.fr` → `exernple.fr`, `exenple.fr`) ;
  - **« Ajouter les domaines cochés à l'entreprise »** n'est plus grisé : il suit les cases cochées. Pour un domaine que rien ne relie au vôtre, une confirmation est demandée, car un domaine de l'entreprise est considéré comme sûr.

- **v1.19.16** : « Analyser mon domaine » :
  - **DKIM plus juste** : seul un vrai enregistrement DKIM compte (un DNS « joker » qui répond pour n'importe quel nom est détecté), chaque sélecteur trouvé indique le service qui l'utilise habituellement, et une clé publiée seulement pour une plateforme d'envoi (Brevo, Mailchimp, Mailjet, SendGrid) est signalée « À améliorer » : vos propres emails ne sont probablement pas signés ;
  - **recherche en cours visible** : barre animée et pointeur d'attente pendant l'analyse ;
  - **Sosies du domaine** : boutons « Tout cocher » et « Tout décocher » ; en mode sombre, plus de titres de groupe en bleu illisibles (la colonne Type indique déjà le genre de domaine).

- **v1.19.15** : « Analyser mon domaine » :
  - **DKIM introuvable** : signalé « À améliorer » (au lieu d'une simple information), avec ses conséquences, et deux fois plus de sélecteurs essayés ;
  - **Sosies du domaine** (onglet renommé) : 350 à 500 variantes au lieu d'environ 170 ; nouvelles techniques : touches voisines (AZERTY et QWERTY), voyelles changées, lettres cyrilliques identiques à l'œil (`xn--…`), préfixes (my, mon, www…), 25 extensions et 25 mots de plus ;
  - **onglet Entreprise retiré**, ainsi que la lecture des mentions légales du site : l'identité de l'entreprise se gère dans Paramètres → Entreprise.

- **v1.19.14** : paramètres → Entreprise : le cadre « Dirigeants », qui répétait la colonne Dirigeants de la liste des entreprises, est retiré. La détection de la fraude au président est inchangée.

- **v1.19.13** : plus de vérification quotidienne automatique des nouvelles versions. Un bouton **Rechercher une nouvelle version** dans Paramètres → À propos interroge GitHub d'un clic et propose le téléchargement si une version plus récente existe. La stratégie `CheckUpdates = false` masque le bouton.

- **v1.19.12** : paramètres → Entreprise : les aides des champs « Serveurs de messagerie internes » et « Réseaux des postes de travail » indiquent ce qu'on peut saisir, avec des exemples (adresse IP, nom complet, plage).

- **v1.19.11** : chaque fichier publié est accompagné d'une **attestation de provenance** signée par GitHub, qui prouve qu'il a été construit par le workflow du dépôt à partir du code publié (vérification : `gh attestation verify <fichier> --repo Some0neElseIsHere/phishguard-outlook`). Nouvelle politique de sécurité (`SECURITY.md`) et analyse automatique du code par CodeQL.

- **v1.19.10** : bilan complet de l'application.
  - **Sécurité** : pour un message reçu sur un compte IMAP/POP (Gmail, Orange…) ou lu dans un fichier .pst, les en-têtes « Exchange » qui marquent un message comme interne sont ignorés : un expéditeur pouvait les ajouter lui-même pour faire passer un faux message pour interne et adoucir son analyse.
  - **Nouvel indice** : un message au nom de votre entreprise, arrivé d'Internet sans aucun résultat d'authentification, est signalé (élevé).
  - **Lien « Récupérer l'âge des domaines »** : il passe désormais par un canal direct entre la page et le complément, et non plus par une navigation que le composant web d'Outlook ne transmet pas sur certains postes. Un contrôle automatique vérifie à chaque construction que le clic arrive bien.
  - **Banc d'essai** : 83,8 % des phishings signalés (58 % en rouge), fausses alertes inchangées (Apache 3,0 %, SpamAssassin 10,6 %), 78 cas légitimes difficiles corrects, 5 000 messages malformés sans plantage.

- **v1.19.9** : paramètres lisibles quel que soit le réglage d'affichage de Windows : la hauteur des textes d'aide est mesurée sur les contrôles eux-mêmes, avec une marge, au lieu d'être estimée. Les titres « Réseaux des postes de travail (VLAN) » (Entreprise) et « Avec une clé gratuite » (Réputation) ne sont plus recouverts. Le bouton « Âge des domaines » ajouté en v1.19.8 est retiré : la recherche se lance depuis l'onglet Réputation.

- **v1.19.8** : bouton **Âge des domaines** en bas de la fenêtre d'analyse détaillée. Il lance la recherche et ouvre l'onglet Réputation, même quand le composant web d'Outlook ne transmet pas le clic sur le lien de la page (cas constaté sur certains postes).

- **v1.19.7** : âge des domaines plus fiable. PhishGuard interroge maintenant directement le registre de chaque extension (annuaire officiel de l'IANA, téléchargé une fois par mois) ; rdap.org, protégé par Cloudflare et limité à 10 requêtes par 10 secondes, ne sert plus qu'en secours. En cas d'échec, l'onglet Réputation affiche « recherche impossible » avec la raison (au lieu de « date non publiée »), l'erreur n'est plus mémorisée 7 jours et figure dans les informations pour le support.

- **v1.19.6** : les preuves de légitimité d'un message d'équipement indiquent son adresse IP et les adresses d'expéditeur autorisées (« Équipement interne déclaré (10.0.50.12), autorisé à écrire au nom de : alertes@entreprise.fr »), ou « sans restriction d'expéditeur ».

- **v1.19.5** : correction. Un serveur de messagerie déclaré aussi comme équipement (pour ses propres rapports, limité à ses adresses) jugeait à tort tous les messages qui ne faisaient que le traverser : ils étaient signalés comme « équipement piraté ». L'équipement est maintenant celui d'où le message est parti (ou le client vu par Microsoft 365) ; un serveur traversé n'est retenu que s'il n'est limité à aucune adresse.

- **v1.19.4** : l'analyse détaillée montre quelle déclaration a reconnu un équipement (adresse IP, expéditeur, adresses autorisées, ou « toutes » quand aucune n'est déclarée). Les paramètres refusent une ligne d'équipement dont la suite n'est pas une adresse d'expéditeur (par exemple `10.0.50.12 serveur.entreprise.local`), qui laissait l'équipement écrire au nom de n'importe qui.

- **v1.19.3** : l'origine réseau est contrôlée **quel que soit l'expéditeur affiché**, et plus seulement pour les adresses de l'entreprise. Une machine interne non déclarée qui passe par un relais Exchange au nom d'une adresse externe (fausse alerte Microsoft) ou d'un nom de machine (`supervision@serveur`) est critique. Un équipement déclaré peut être limité à ce type d'adresse (`10.0.50.30 supervision@serveur`). Pour un message venu d'Internet, la recherche de l'origine s'arrête au premier serveur public : les adresses privées du réseau de l'expéditeur ne sont pas prises pour les vôtres. Banc d'essai : aucune fausse alerte.

- **v1.19.2** : correction. Un message déposé sur un connecteur de relais Exchange qui fait confiance à l'adresse IP de la machine (`AuthAs: Internal`, `AuthMechanism: 10`, sans identifiants) était pris pour un message interne authentifié, et la machine d'origine n'était pas contrôlée. Il est maintenant traité comme non authentifié : venant d'une machine non déclarée, il est **critique** (au lieu d'élevé), avec son adresse IP ; venant d'un équipement déclaré, l'adresse d'expéditeur est vérifiée.

- **v1.19.1** : **équipements limités à leurs propres adresses**. Dans « Équipements qui envoient des mails », chaque ligne peut indiquer, après l'adresse IP, les seules adresses d'expéditeur autorisées (`10.0.50.12 alertes@entreprise.fr`). Un message venant de cet équipement au nom d'une autre adresse, un collègue ou la direction par exemple, est classé **critique** : équipement piraté ou détourné. Les entrées sans adresse gardent l'ancien comportement.

- **v1.19.0** : **phishing fabriqué en interne**. Nouvelle section **Réseau interne** dans Paramètres → Entreprise (mode expert) : serveurs de messagerie, équipements qui envoient des alertes, réseaux des postes de travail (adresses IP, plages ou noms). Un message au nom de l'entreprise déposé directement au serveur depuis un poste, sans authentification, est classé **critique** avec l'adresse du poste ; venu d'une machine interne non déclarée, il est signalé aussi. Également par stratégie (`MailServers`, `WorkstationNets`). Détails dans le guide de déploiement (`docs/deploiement-entreprise.md`, section 3).

- **v1.18.8** :
  - **fausses factures à rappeler** (« callback phishing ») : un faux débit (renouvellement Norton ou McAfee, achat PayPal…) et un numéro de téléphone pour l'annuler, souvent sans aucun lien. Au téléphone, l'escroc fait installer un logiciel de prise en main à distance ou dicter des codes bancaires. Nouvel indice, élevé quand l'expéditeur n'est pas authentifié, utilise une messagerie gratuite ou cite une marque qui n'est pas la sienne. Banc d'essai : 24 des 481 phishings de 2025 en contiennent, sans nouvelle fausse alerte ;
  - **avertissement de nouvelle version** : une fois par jour, PhishGuard demande à GitHub le numéro de la dernière version publiée. Si elle est plus récente, l'onglet **À propos** l'indique avec un lien de téléchargement, et la barre d'état de l'analyse détaillée le rappelle. Rien n'est envoyé ni installé. Désactivable dans À propos, ou par stratégie (`CheckUpdates`).

- **v1.18.7** : nouveaux indices, issus d'un spam de casino :
  - **domaine d'expéditeur impossible** (tiret au début ou à la fin, caractère interdit) : il n'existe dans aucun registre, l'adresse est fabriquée ;
  - **nom de domaine tiré au hasard** (suite de lettres et de chiffres sans voyelles) ;
  - **aucune authentification** (ni SPF ni DKIM), plus grave pour un envoi en nombre, que Gmail, Yahoo et Microsoft exigent authentifié depuis 2024 ; les listes de diffusion ne sont pas concernées ;
  - **publicité pour un casino en ligne** : interdit en France (seuls paris sportifs, hippiques et poker agréés par l'ANJ).
  Banc d'essai : 83,6 % des phishings alertés (58 % en rouge), faux positifs inchangés (Apache 3,0 %, SpamAssassin 10,6 %, 78/78 cas légitimes difficiles).

- **v1.18.6** : correction de la v1.18.5 : le fichier `config.ini` installé réactivait la recherche automatique de l'âge des domaines. Elle se fait maintenant vraiment d'un clic par défaut. Décocher l'option arrête aussi les recherches déjà en attente. L'option est déplacée dans Paramètres → **Réputation**, avec les autres sources en ligne. Les âges trouvés restent enregistrés sur le poste : un domaine déjà vérifié n'est plus jamais redemandé (une date restée inconnue est retentée au bout de 7 jours).

- **v1.18.5** : l'âge des domaines n'est plus recherché automatiquement : vous le lancez quand vous le décidez, avec **Récupérer l'âge des domaines** dans l'onglet Réputation. Les autres résultats n'attendent plus ces recherches. Pour revenir à la recherche automatique : Paramètres → Réputation → « Rechercher automatiquement l'âge des domaines ». Le service informatique peut toujours l'imposer (stratégie ou `config.ini`, `DomainAgeLookup`).

- **v1.18.4** : **l'analyse approfondie est retirée** (onglet, bouton et stratégies `AllowLinkFollowing` / `AllowUrlLookup`) : elle apportait peu pour le temps qu'elle prenait. À la place, l'onglet **Réputation** affiche l'**âge de chaque domaine** du message (expéditeur, adresse de réponse, liens) et un lien **Récupérer l'âge des domaines** pour ceux qui ne sont pas encore connus. Le clic fonctionne même si la recherche automatique est désactivée ; un domaine récent est alors pris en compte dans le verdict. L'onglet affiché reste le même quand la page se met à jour.

- **v1.18.3** : analyse approfondie, historique de votre boîte. La recherche des messages déjà reçus de l'expéditeur portait seulement sur la boîte de réception du compte principal : un expéditeur habituel dont les messages sont classés dans un sous-dossier, archivés ou supprimés était annoncé comme « premier message ». Elle porte maintenant sur tous les dossiers de la boîte qui contient le message (sauf le courrier indésirable), indique où un message a été trouvé et précise ce qui n'a pas été consulté (autres comptes, archives .pst). Même correction pour le nom d'expéditeur et la conversation citée.

- **v1.18.2** : l'analyse approfondie ne se lance plus d'elle-même : un bouton **Lancer l'analyse approfondie** dans l'onglet Approfondie la démarre, pour le message affiché uniquement. Ouvrir l'analyse détaillée redevient instantané. La recherche dans votre boîte (messages déjà reçus de l'expéditeur) ne parcourt plus les messages un par un, ce qui la rend beaucoup plus rapide dans une grosse boîte.

- **v1.18.1** : l'analyse approfondie devient un onglet **Approfondie**, toujours présent en mode expert. Elle se lance d'elle-même à l'ouverture de l'analyse détaillée (une fois par message, avec les sources activées dans les paramètres) et l'onglet se met à jour à la fin, sans changer l'onglet affiché ni voler le focus. Suivre les liens et consulter VirusTotal avec l'adresse complète restent soumis à votre accord, par un lien dans l'onglet. Plus d'analyse approfondie en mode simple.

- **v1.18.0** : **analyse approfondie** pour les messages douteux. Elle ne montre que ce que les autres onglets ne voient pas, et recalcule le verdict :
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
