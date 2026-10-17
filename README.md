# PhishGuard pour Outlook

**Analyse anti-phishing des emails, directement dans Outlook.** Dès qu'un message est sélectionné,
PhishGuard affiche un score de risque dans le ruban, alerte en cas de danger, et ouvre sur demande
une fenêtre d'enquête complète, à la manière de [PhishTool](https://www.phishtool.com/).

- **Analyse locale** : le contenu des messages ne quitte jamais le poste. Aucune clé d'API nécessaire ; les sources de réputation externes sont optionnelles et ne reçoivent que des domaines, des empreintes ou une IP.
- **Sans droits administrateur** : installation dans le profil de l'utilisateur.
- **Pensé pour l'entreprise** : Exchange interne ou Microsoft 365, proxy et inspection HTTPS, déploiement silencieux, configuration centralisée.

> *English summary — PhishGuard is a free phishing analyzer for classic Outlook on Windows
> (COM add-in, .NET Framework 4). Message content is analyzed locally and never leaves the PC; external
> reputation sources are optional. It scores every email in the ribbon, detects lookalike domains, spoofing,
> thread hijacking, malicious links and attachments, offers a PhishTool-like investigation view and sends
> detailed HTML reports to your security team. The interface is available in French and English.*

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Configuration](#configuration)
- [Déploiement en entreprise](#déploiement-en-entreprise)
- [Confidentialité](#confidentialité)
- [Construire depuis les sources](#construire-depuis-les-sources)
- [Dépannage](#dépannage)
- [Limites connues](#limites-connues)
- [Licence et crédits](#licence-et-crédits)

---

## Fonctionnalités

### Dans Outlook

| | |
|---|---|
| **Score permanent** | Un seul bouton dans le ruban : il affiche le verdict et le score (pastille verte, orange ou rouge) du message sélectionné ou ouvert, sans clic. |
| **Alerte** | Une notification discrète en bas à droite de l'écran pour les messages dangereux (ou suspects, au choix). |
| **Fenêtre d'enquête** | Jauge de risque, indices classés par gravité, parcours des serveurs en frise ; onglets Résumé, En-têtes, Parcours, URL, Pièces jointes, Observables, Source, Corps, Réputation. Les boutons Signaler, Ce n'est pas du phishing, Copier le rapport et Paramètres sont en bas de cette fenêtre. |
| **Signaler** | Après une double confirmation, envoie à l'équipe sécurité un rapport HTML (verdict, points de doute détaillés, authentification et origine, liens désarmés, pièces jointes et empreintes, observables à copier, copie du texte du message) avec le message d'origine joint (.msg avec tous ses en-têtes), puis le déplace dans Courrier indésirable. |
| **Ce n'est pas du phishing** | Ajoute l'expéditeur ou son domaine aux expéditeurs de confiance (une usurpation reste toujours signalée). |
| **Explications pédagogiques** | Sous chaque indice, « pourquoi c'est dangereux » et quoi faire. Désactivables pour les utilisateurs expérimentés. |
| **Paramètres** | Tous les réglages depuis Outlook, sans éditer de fichier (onglets Entreprise, Analyse, Listes, Réputation). Onglet Entreprise : **Rechercher…** retrouve les dirigeants dans l'[Annuaire des Entreprises](https://annuaire-entreprises.data.gouv.fr/) (API publique de l'État, sans clé), et le domaine de votre adresse Outlook est proposé comme domaine de l'entreprise. |
| **Réputation** | Sources externes optionnelles : OpenPhish, Tranco, DNS (MX, SPF, politique DMARC, BIMI avec certificat VMC/CMC), crt.sh (sans clé) ; VirusTotal, abuse.ch, AbuseIPDB (clé gratuite). Résultats regroupés dans l'onglet Réputation de la fenêtre. Les clés sont rangées dans le Gestionnaire d'identification de Windows. |
| **Analyser mon domaine** | Depuis Paramètres → Entreprise : bilan de la sécurité email de votre domaine (MX, SPF, DKIM, DMARC, BIMI, MTA-STS, services autorisés à envoyer en votre nom), SIREN lu dans les mentions légales du site puis dirigeants, **sosies déjà enregistrés** (≈170 variantes vérifiées dans le DNS), certificats récents contenant votre marque et domaines liés (crt.sh). Les sosies cochés rejoignent la liste de blocage. |
| **Surveillance des sosies** | Chaque semaine, les variantes de vos domaines sont revérifiées : un sosie apparu depuis la dernière fois est bloqué automatiquement (et un nouveau certificat contenant votre marque, si crt.sh est activé). |
| **Expéditeur vérifié** | Pastille verte avec une coche quand le message est authentifié pour le domaine affiché (DMARC, DKIM aligné ou compauth Microsoft) **et** vient de quelqu'un avec qui vous êtes déjà en relation (correspondant connu, réponse à l'un de vos messages, expéditeur de confiance), sans aucun indice. Les preuves sont listées dans la fenêtre ; elles ne compensent jamais un indice Élevé ou Critique. |
| **Français / anglais** | Langue de l'interface au choix, ou automatique selon Windows. |

### Contrôles effectués

| Domaine | Contrôles |
|---|---|
| **Authentification** | SPF, DKIM, DMARC, compauth (Microsoft, avec ses codes de raison : 001 insuffisant, 002 interdit, 010/6xx usurpation interne, 1xx/130 réussite), y compris via `ARC-Authentication-Results` écrit par votre propre serveur. **Alignement** DKIM et SPF avec le domaine affiché. Usurpation de votre propre domaine. Envoi en nombre conforme (désabonnement en un clic + DMARC). |
| **Fil de discussion** | Réponse réelle à l'un de vos messages envoyés (Message-ID), et **détournement de fil** : une « réponse » qui vient d'une autre organisation que celle à qui vous aviez écrit. |
| **Expéditeur** | Domaines sosies de grandes marques, de **votre entreprise** et de **vos correspondants** (typosquatting, homoglyphes, caractères Unicode, marque + mots ajoutés, marque en sous-domaine). **Premier contact**. **Âge du domaine** (RDAP). Nom affiché trompeur, Reply-To détourné, usurpation d'un dirigeant (fraude au président), tenant `onmicrosoft.com`. |
| **Liens** | Sosies, texte du lien ≠ destination, **texte qui imite un fichier** (`C:\…`, `facture.pdf` qui télécharge un `.exe` ou un `.lnk`), **liens vers un fichier local ou un partage réseau** (`file:`, `\\serveur\…`), protocoles qui lancent Windows (`search-ms:`, `ms-msdt:`…) ou un document Office distant, liens réécrits par les passerelles (Proofpoint, Safe Links, Barracuda, Sophos, Trend Micro, Symantec, FortiMail) et redirections déballés, adresse IP, `@` dans l'URL, raccourcisseurs, hébergeurs gratuits détournés, extensions à risque, domaines récents, listes de blocage. Les liens contenus dans les PDF et pièces jointes HTML sont aussi analysés. |
| **Pièces jointes** | Extension, double extension, caractère d'inversion Unicode, **type réel** (programme renommé en `.pdf`…), empreintes MD5/SHA1/SHA256, et **contenu** : programme caché dans un ZIP, archive chiffrée, macros (y compris cachées dans un `.docx`), JavaScript dans un PDF, fausse page de connexion HTML, objet RTF. |
| **Contenu** | Urgence, demande d'identifiants, demande financière, **IBAN** et changement de RIB, demande de discrétion, QR code, faux « RE: », formulaire dans le message. |
| **Filtres de messagerie** | Objet marqué « SPAM »/« PHISHING », SCL d'Exchange, SpamAssassin, Orange, FortiMail (au mieux). |
| **Listes de blocage** | [Red Flag Domains](https://red.flag.domains/) (nouveaux domaines .fr suspects, mise à jour quotidienne), liste de l'équipe sécurité (`custom.txt`), liste de l'utilisateur (onglet Listes), liste partagée sur le réseau, sosies détectés par la surveillance. |
| **Réputation** (optionnel) | OpenPhish, Tranco, DNS de l'expéditeur (existence, MX, SPF, politique DMARC, BIMI), âge du premier certificat (crt.sh), VirusTotal (empreintes des pièces jointes), URLhaus et ThreatFox (abuse.ch), AbuseIPDB (IP d'origine). |

### Fenêtre d'enquête

- **En-têtes** : champs principaux décodés, détail de l'authentification (domaines, sélecteur DKIM), en-têtes des filtres antispam.
- **Parcours** : chaque serveur traversé, IP, protocole, horodatage et délai entre les sauts ; **IP d'origine**.
- **Observables** : adresses, domaines, IP et empreintes, avec liens de vérification sans compte à créer : VirusTotal, Google Safe Browsing, Cisco Talos, AbuseIPDB, listes noires (MXToolbox) et WHOIS (ouverts dans le navigateur, seul l'élément vérifié est transmis).
- **Réputation** : état de chaque source externe et résultats obtenus.
- **Rapport complet** copiable, avec URL « désarmées » (`hxxps://exemple[.]com`).

---

## Installation

**Prérequis** : Windows 10/11, **Outlook classique** (Microsoft 365, 2019, 2021…), .NET Framework 4.6 ou plus (présent par défaut).

1. Téléchargez **`PhishGuard-Outlook-vX.Y.Z-installeur.exe`** dans [Releases](../../releases).
2. **Fermez Outlook**, lancez l'exe et cliquez sur **Installer** (aucun droit administrateur demandé).
3. Ouvrez Outlook : le score PhishGuard apparaît dans l'onglet Accueil. Les réglages (domaines de l'entreprise,
   adresse de signalement, langue…) se font depuis Outlook : cliquez sur le score, puis **Paramètres**.

L'exe n'est pas signé : Windows peut afficher « Windows a protégé votre ordinateur » → *Informations
complémentaires* → *Exécuter quand même*. Si votre antivirus ou AppLocker bloque l'exe, prenez le zip
`PhishGuard-Outlook-vX.Y.Z.zip`, décompressez-le et lancez `installer.cmd` (même installation, en script).
Pour imposer des valeurs par défaut à toute l'entreprise, modifiez `config.ini` dans le zip avant de l'installer.

**Désinstaller** : Paramètres Windows → Applications → *PhishGuard pour Outlook*, ou `%LOCALAPPDATA%\PhishGuard\desinstaller.cmd`.

---

## Utilisation

1. **Sélectionnez un email** : le bouton PhishGuard affiche par exemple « Dangereux (85) ». Survolez-le pour voir les principaux indices.
2. **Cliquez dessus** pour ouvrir la fenêtre d'enquête.
3. En bas de la fenêtre : **Signaler à la sécurité** envoie le message et un rapport détaillé à l'équipe sécurité (après double confirmation), **Ce n'est pas du phishing** corrige un faux positif, **Paramètres** ouvre les réglages.

Niveaux : **Risque faible** (0–19), **Suspect** (20–49), **Dangereux** (50 et plus, ou au moins un indice critique).
**Expéditeur vérifié** remplace « Risque faible » quand l'expéditeur est authentifié, déjà en relation avec vous et qu'aucun indice n'a été relevé.

---

## Configuration

Depuis Outlook : cliquez sur le score PhishGuard, puis sur **Paramètres** en bas de la fenêtre d'analyse
(sans email sélectionné, un clic sur le bouton propose aussi d'ouvrir les paramètres). Les réglages sont enregistrés pour chaque
utilisateur dans `%LOCALAPPDATA%\PhishGuard\config.user.ini` et survivent aux réinstallations.

Le fichier `config.ini` fourni avec l'installeur définit les valeurs par défaut :

| Clé | Rôle | Défaut |
|---|---|---|
| `CompanyName`, `CompanyDomains` | Votre entreprise ; ses sosies sont classés critiques | — (domaines : celui de l'adresse Outlook de l'utilisateur, hors messageries gratuites) |
| `VipNames` | Dirigeants et personnes sensibles (fraude au président) | — |
| `ReportAddress` | Adresse de l'équipe sécurité pour **Signaler** | — |
| `Language` | `auto` (langue de Windows), `fr` ou `en` | `auto` |
| `TrustedDomains`, `TrustedSenders` | Domaines et adresses de confiance | — |
| `AutoAnalyze` | Score automatique du message sélectionné | `true` |
| `AlertLevel` | `dangerous`, `suspicious` ou `none` | `dangerous` |
| `AutoHashMaxMB` | Taille max. des pièces jointes analysées automatiquement | `5` |
| `ShowExplanations` | Explications pédagogiques | `true` |
| `KnownCorrespondents` | Premier contact et sosies de correspondants | `true` |
| `DomainAgeLookup` | Âge des domaines (RDAP) | `true` |
| `TagCategory` | Catégorie de couleur dans la boîte de réception | `false` |
| `MoveAfterReport` | Déplacer en Courrier indésirable après signalement | `true` |
| `ScoreLog` | Journal des scores (`scores.csv`) | `true` |
| `SharedBlocklistPath` | Liste de blocage partagée (ex. `\\serveur\securite\phishguard.txt`) | — |
| `RedFlagEnabled`, `RedFlagUrl`, `RedFlagMaxAgeHours` | Liste Red Flag Domains, son adresse, âge maximal avant mise à jour | `true`, liste officielle, `24` |
| `WatchDomains` | Surveillance hebdomadaire des sosies de `CompanyDomains` | `true` |
| `BetaOpenPhish`, `BetaTranco`, `BetaDnsChecks`, `BetaCertAge` | Sources de réputation sans clé (onglet Réputation) | `false` |
| `VirusTotalKey`, `AbuseChKey`, `AbuseIpdbKey` | Clés par défaut pour tous ; un utilisateur peut saisir les siennes, rangées dans le Gestionnaire d'identification de Windows et prioritaires | — |
| `AllowUserSettings` | Bouton Paramètres de la fenêtre d'analyse ; `false` impose `config.ini` à tous | `true` |

Une clé d'API écrite dans `config.ini` y est lisible en clair : préférez la saisie par chaque utilisateur.

---

## Déploiement en entreprise

- **Installation silencieuse** (script de connexion, GPO, outil de déploiement) : `PhishGuard-Outlook-vX.Y.Z-installeur.exe /quiet` ou `installer.cmd /quiet`.
- **Configuration imposée** : adaptez `config.ini` avant de distribuer le dossier, avec `AllowUserSettings = false`.
- **Liste de blocage commune** : un fichier texte sur un partage réseau (`SharedBlocklistPath`), rechargé toutes les heures.
- **Signature** : signer `PhishGuard.dll` avec le certificat de signature de code de l'entreprise évite les blocages par l'antivirus, AppLocker ou la stratégie « compléments signés uniquement ».
- **Postes verrouillés** : rien n'est compilé sur le poste ; si l'exe est bloqué, le zip de la release s'installe avec `installer.cmd`.

---

## Confidentialité

| Donnée | Où elle va |
|---|---|
| Contenu, objet, pièces jointes des messages | **Nulle part** : analyse sur le poste |
| Noms de domaine (âge du domaine) | `rdap.org` puis le registre du domaine (désactivable) |
| Liste Red Flag Domains | Téléchargée depuis `dl.red.flag.domains` (aucune donnée envoyée) |
| Nom de l'entreprise (bouton « Rechercher » des paramètres) | `recherche-entreprises.api.gouv.fr`, uniquement au clic |
| Vos domaines et leurs variantes (analyse et surveillance des sosies) | Serveur DNS de votre entreprise ; `crt.sh` pour les certificats ; votre propre site pour les mentions légales |
| Sources de réputation (si activées) | OpenPhish et Tranco : listes téléchargées, comparaison sur le poste. DNS : serveur DNS de l'entreprise. crt.sh, abuse.ch : noms de domaine. VirusTotal, abuse.ch : empreintes SHA-256 des pièces jointes (jamais le fichier). AbuseIPDB : IP d'origine |
| Signalement | Le message et le rapport sont envoyés à l'adresse de l'équipe sécurité configurée, et à elle seule |
| Liens de vérification (VirusTotal…) | Uniquement si vous cliquez, et seulement l'élément vérifié |

Fichiers créés dans `%LOCALAPPDATA%\PhishGuard` : réglages (`config.user.ini`, `custom.user.txt`), correspondants (`correspondants.txt`),
identifiants techniques de vos messages envoyés et domaines de leurs destinataires (`fils.txt`, sans objet ni contenu),
sosies surveillés (`surveillance.txt`), âge des domaines déjà vérifiés, listes Red Flag Domains, OpenPhish et Tranco,
journal des scores (`scores.csv`, sans objet ni contenu), journal technique (`phishguard.log`).
Les clés d'API ne sont pas dans ce dossier : elles sont dans le Gestionnaire d'identification de Windows (« PhishGuard:… »).

---

## Construire depuis les sources

Aucune installation nécessaire : le compilateur C# fourni avec Windows (.NET Framework 4) suffit.

```bat
cd outlook-exe
construire.bat
```

Le script compile et lance les tests du moteur, compile `PhishGuard.dll`, prépare `build\package\`
(installation) et crée l'installeur `build\PhishGuard-Outlook.exe` (fichiers intégrés à l'exe).

L'intégration continue ([`.github/workflows/build.yml`](.github/workflows/build.yml)) fait la même chose
sur un serveur Windows de GitHub à chaque modification, et publie une release (installeur, zip, empreintes SHA-256)
pour chaque tag `v*` ou lancement manuel avec un numéro de version. Les erreurs de compilation et les tests
en échec apparaissent dans les annotations du job.

### Structure du dépôt

```
outlook-exe/                  Complément Outlook (COM, C# 5, .NET Framework 4)
  src/Engine/                 Moteur d'analyse (sans dépendance à Outlook, testable)
  src/AddIn/                  Ruban, lecture des messages, fenêtres, tâches de fond
  tests/Tests.cs              Tests du moteur (lancés à chaque construction)
  installer/                  Installeur .exe (Setup.cs) et scripts installer.cmd / desinstaller.cmd
  tools/gen-lists.mjs         Génère src/Engine/Lists.cs depuis src/engine/lists.js
  config.ini, custom.txt      Configuration par défaut et liste de blocage de l'équipe sécurité
  LISEZMOI.md                 Notice incluse dans le zip de la release
docs/                         Notes de version, documentation du complément web
src/, test/, tools/,          Version « complément web » (Office.js), voir docs/complement-web.md
manifest.xml, server.js
.github/workflows/            Construction, tests et releases
```

---

## Dépannage

| Symptôme | Solution |
|---|---|
| Le groupe PhishGuard n'apparaît pas | Outlook → Fichier → Options → Compléments → *Gérer : Compléments COM* → **Atteindre** : cocher PhishGuard ; vérifier aussi *Éléments désactivés*. |
| PhishGuard est décoché à chaque démarrage | Une stratégie de groupe limite les compléments ou exige qu'ils soient signés. |
| « Windows a protégé votre ordinateur » | Exe non signé : *Informations complémentaires* → *Exécuter quand même*, ou installation par le zip. |
| « Liste Red Flag Domains non chargée » | Le proxy bloque `dl.red.flag.domains` ; l'analyse fonctionne sans la liste. |
| Une source de l'onglet Réputation reste « injoignable » | Le proxy bloque le service, ou la clé est refusée ; l'analyse locale continue. |
| Le signalement s'ouvre au lieu de partir | Outlook a refusé l'envoi automatique (stratégie, mode hors connexion) : cliquez sur Envoyer. |
| « Windows refuse de lancer le compilateur » (`construire.bat`) | Compilateur bloqué sur ce poste : utilisez la release déjà compilée. |

Journal technique : `%LOCALAPPDATA%\PhishGuard\phishguard.log`.

---

## Limites connues

- Fonctionne avec **Outlook classique pour Windows** uniquement (pas le nouvel Outlook ni Outlook sur le web : voir la version « complément web » dans `docs/`).
- Les liens contenus dans des flux PDF compressés ne sont pas extraits.
- Mimecast et Cisco réécrivent les liens sous une forme chiffrée : leur vraie destination ne peut pas être lue.
- La recherche de certificats contenant votre marque (crt.sh) est lente et peut expirer ; le reste de l'analyse du domaine n'en dépend pas.
- La détection FortiMail repose sur des noms d'en-têtes génériques ; les contributions avec des exemples réels sont bienvenues.
- Aucun outil ne détecte 100 % des attaques : PhishGuard aide à décider, il ne remplace pas la vigilance.

---

## Licence et crédits

Code publié sous licence **GNU GPL v3** (voir [LICENSE](LICENSE)) : vous pouvez l'utiliser, le modifier et le redistribuer, à condition que les versions modifiées restent sous la même licence et que leur code source soit fourni.

- Liste [Red Flag Domains](https://red.flag.domains/) : données sous licence **CC BY-NC-SA 4.0** (usage non commercial). Elle est téléchargée par chaque poste et n'est pas redistribuée ici. Pour un usage en entreprise, vérifiez que votre cas est couvert (hello@red.flag.domains) ou désactivez-la (`RedFlagEnabled = false`).
- Âge des domaines : service public [rdap.org](https://rdap.org/) et registres RDAP.
- Dirigeants : [Annuaire des Entreprises](https://annuaire-entreprises.data.gouv.fr/) (données INSEE et RNE).
- Sources de réputation optionnelles : [OpenPhish](https://openphish.com/) (flux communautaire, usage non commercial), [Tranco](https://tranco-list.eu/), [crt.sh](https://crt.sh/), [VirusTotal](https://www.virustotal.com/), [abuse.ch](https://abuse.ch/), [AbuseIPDB](https://www.abuseipdb.com/), chacune selon ses propres conditions d'utilisation.
- Inspiré par [PhishTool](https://www.phishtool.com/).
