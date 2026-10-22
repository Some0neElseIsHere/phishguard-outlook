# Déployer PhishGuard en entreprise

Ce guide s'adresse au service informatique. PhishGuard s'installe dans le profil de chaque utilisateur, sans droits
administrateur. Les réglages communs sont imposés par **stratégie de groupe (GPO)** ou par **Intune** : l'utilisateur
ne peut pas les modifier.

## 1. Installer sur les postes

- Installation silencieuse : `PhishGuard-Outlook-vX.Y.Z-installeur.exe /quiet` (script d'ouverture de session,
  outil de déploiement). L'installeur attend la fermeture d'Outlook, au plus 10 minutes.
- Une version déjà installée est mise à jour, et les réglages de l'utilisateur sont conservés.
- Si l'antivirus, AppLocker ou la stratégie « compléments signés uniquement » bloque le complément, signez
  `PhishGuard.dll` avec le certificat de signature de code de l'entreprise, ou autorisez le dossier
  `%LOCALAPPDATA%\PhishGuard`. Pour construire une version signée : définissez `PG_SIGN_PFX` (chemin du certificat
  `.pfx`) et `PG_SIGN_PASSWORD` avant de lancer `construire.bat` ; le complément et l'installeur sont signés et
  horodatés (signtool du Windows SDK requis). Sur GitHub, les secrets `SIGN_PFX_BASE64` et `SIGN_PASSWORD` font la
  même chose lors de la publication.

## 2. Imposer les réglages par stratégie

Le zip de chaque release contient le modèle de stratégies dans le dossier `policies\` :
`PhishGuard.admx`, `fr-FR\PhishGuard.adml` et `en-US\PhishGuard.adml`.

**Avec les GPO (Active Directory)**

1. Copiez `PhishGuard.admx` dans le magasin central `\\<domaine>\SYSVOL\<domaine>\Policies\PolicyDefinitions\`, et
   les fichiers `.adml` dans les sous-dossiers `fr-FR` et `en-US` correspondants.
2. Dans la console de gestion des stratégies de groupe, les réglages apparaissent sous
   **Modèles d'administration → PhishGuard pour Outlook**, côté *Configuration ordinateur* comme côté
   *Configuration utilisateur*.
3. Pour viser un groupe précis (par exemple imposer le mode simple au service comptable), liez la GPO à l'unité
   d'organisation voulue ou utilisez le filtrage de sécurité. Les réglages côté *Configuration utilisateur* suivent
   l'utilisateur sur tous les postes.

**Avec Intune**

Importez `PhishGuard.admx` et `fr-FR\PhishGuard.adml` dans *Appareils → Profils de configuration → Importer des
fichiers ADMX*, puis créez un profil « Modèles importés » et affectez-le aux groupes voulus.

**Ce qui se passe sur le poste**

- Les valeurs sont écrites dans `HKLM` ou `HKCU\Software\Policies\PhishGuard`. Seul un administrateur peut écrire
  sous `Policies`.
- PhishGuard les relit à chaque chargement de ses réglages. Elles l'emportent sur `config.ini` et sur les réglages
  de l'utilisateur. Si une même valeur est définie pour l'ordinateur et pour l'utilisateur, celle de l'ordinateur
  l'emporte.
- Dans les paramètres, les réglages imposés sont grisés, sous un bandeau « imposés par votre service
  informatique ». L'assistant de démarrage ne pose plus les questions déjà réglées.
- Le bouton « Copier les informations pour le support » (onglet À propos) liste les réglages imposés sur le poste.

**Stratégies disponibles**

| Catégorie | Stratégie | Valeur de registre |
|---|---|---|
| Entreprise | Adresse de l'équipe sécurité | `ReportAddress` |
| | Domaines de l'entreprise | `CompanyDomains` |
| | Entreprises 1 à 3 et leurs dirigeants (`Nom \| Pays \| Identifiant \| Dirigeant; Dirigeant`) | `Company1` à `Company3` |
| | Équipements internes qui envoient des mails | `InternalRelays` |
| | Serveurs de messagerie internes | `MailServers` |
| | Réseaux des postes de travail | `WorkstationNets` |
| | Domaines de confiance | `TrustedDomains` |
| | Liste de blocage partagée | `SharedBlocklistPath` |
| Affichage et utilisation | Imposer le mode simple | `ForceSimpleMode` |
| | Langue, thème des fenêtres, alertes à l'écran | `Language`, `Theme`, `AlertLevel` |
| | Analyse automatique, déplacer les messages signalés, correspondants connus, journal des scores | `AutoAnalyze`, `MoveAfterReport`, `KnownCorrespondents`, `ScoreLog` |
| Sources et listes | Autoriser les clés d'API | `AllowApiKeys` |
| | Red Flag Domains, secteur public, âge des domaines, DNS, crt.sh, OpenPhish, Tranco | `RedFlagEnabled`, `PublicSectorList`, `DomainAgeLookup`, `BetaDnsChecks`, `BetaCertAge`, `BetaOpenPhish`, `BetaTranco` |

## 3. Repérer les messages « internes » fabriqués depuis un poste

Quelqu'un sur le réseau peut déposer un message directement à votre serveur de messagerie (SMTP, port 25), au nom de
la direction ou du service informatique, sans s'authentifier. Pour le repérer, déclarez dans Paramètres → Entreprise
(mode expert) ou par stratégie :

- **Serveurs de messagerie internes** (`MailServers`) : Exchange, passerelle de filtrage, relais SMTP ;
- **Équipements qui envoient des mails** (`InternalRelays`, ci-dessous) : supervision, pare-feu, copieurs, applications ;
- **Réseaux des postes de travail** (`WorkstationNets`) : les plages des VLAN des postes, par exemple `10.20.30.0/24`.

Adresses IP, plages CIDR ou noms (traduits par votre DNS). PhishGuard regarde la machine d'où le message est parti
(le plus ancien en-tête `Received` écrit par vos serveurs) :

| Message au nom de l'entreprise parti de… | Résultat |
|---|---|
| un serveur ou un équipement déclaré | normal |
| un poste, sans authentification | **critique**, avec l'adresse du poste |
| un poste, accepté comme authentifié par Exchange (SMTP authentifié, relais « Externally Secured ») | moyen : vérifier auprès de l'expéditeur |
| une autre machine interne non déclarée | élevé |
| une machine interne, rien n'étant déclaré, sans authentification | moyen |

Un équipement placé dans le réseau des postes (copieur) doit être déclaré par son adresse exacte : une plage large
d'équipements ne masque pas le réseau des postes. Pour tester, envoyez un message en SMTP depuis votre poste
(`Send-MailMessage` en PowerShell, par exemple) au nom d'une adresse de l'entreprise.

Limite : la détection suppose que le message passe par un serveur interne qui note l'adresse du poste. Un message
envoyé directement à Microsoft 365 ou Google depuis Internet n'en porte pas trace : ce sont alors SPF, DKIM et DMARC
qui le trahissent.

## 4. Déclarer les copieurs et applications qui envoient des mails

Les copieurs (numérisation vers mail), ERP et outils de supervision envoient souvent au nom de l'entreprise sans
s'authentifier (SPF, DKIM). PhishGuard les prend alors pour une usurpation de votre domaine, classée critique.

Indiquez leurs adresses IP dans **Équipements internes qui envoient des mails** (`InternalRelays`) : adresses ou
plages CIDR séparées par des virgules, par exemple `203.0.113.10, 10.0.0.0/24`.

- **Microsoft 365** : indiquez l'IP publique avec laquelle l'équipement (ou votre relais) se connecte à Exchange
  Online. PhishGuard la lit dans le rapport anti-spam écrit par Microsoft (`CIP`), que l'expéditeur ne peut pas
  falsifier.
- **Exchange sur site** : indiquez l'IP interne de l'équipement. PhishGuard ne lit que les sauts écrits par vos
  propres serveurs : tout ce qui se trouve sous le premier saut venu d'Internet est ignoré.
- **N'indiquez jamais** l'adresse d'un service partagé (Microsoft 365, Google, plateforme d'envoi) : tous ses clients
  pourraient alors envoyer « en votre nom » sans alerte.

Un message à votre nom venant d'un équipement déclaré est traité comme interne. Un message à votre nom, non
authentifié et venant d'ailleurs, reste une usurpation critique.

Les messages internes authentifiés par Exchange ou Microsoft 365 (envoyés depuis une boîte de l'entreprise) sont déjà
reconnus sans rien déclarer.

## 5. Clés d'API (VirusTotal, abuse.ch, AbuseIPDB)

- **Toute clé utilisable par le poste peut être lue par l'utilisateur**, même chiffrée. PhishGuard ne permet donc pas
  de distribuer une clé par stratégie ou par `config.ini`.
- Les quotas gratuits sont faibles et partagés par tous les postes qui utilisent la même clé. Les conditions de
  **l'API publique de VirusTotal en interdisent l'usage commercial** ; vérifiez celles des autres services.
- Recommandation : désactivez **Autoriser les clés d'API** pour les utilisateurs. Réservez les clés à l'équipe
  sécurité, chacun avec la sienne, saisie dans les paramètres et rangée dans le Gestionnaire d'identification de
  Windows.
- Les fonctions sans clé (listes, DNS, âge des domaines) restent disponibles pour tous.

## 6. Limites

- Un utilisateur peut désactiver le complément dans Outlook, sauf si une stratégie Office l'en empêche
  (*Liste des compléments gérés*).
- Un utilisateur administrateur de son poste peut contourner toute stratégie.
- Le **nouvel Outlook** et Outlook sur le web n'acceptent pas les compléments COM. Microsoft prévoit de rendre le
  nouvel Outlook par défaut en entreprise à partir de mars 2027, avec possibilité de revenir à la version classique.
