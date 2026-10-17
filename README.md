# PhishGuard pour Outlook

**Analyse anti-phishing des emails, directement dans Outlook.** Dès qu'un message est sélectionné,
PhishGuard affiche un score de risque dans le ruban, alerte en cas de danger, et ouvre sur demande
une fenêtre d'enquête complète, à la manière de [PhishTool](https://www.phishtool.com/).

- **100 % local** : le contenu des messages ne quitte jamais le poste. Aucune clé d'API.
- **Sans droits administrateur** : installation dans le profil de l'utilisateur.
- **Pensé pour l'entreprise** : Exchange interne ou Microsoft 365, proxy et inspection HTTPS, déploiement par script, configuration centralisée.

> *English summary — PhishGuard is a free, local-only phishing analyzer for classic Outlook on Windows
> (COM add-in, .NET Framework 4, no API key). It scores every email in the ribbon, detects lookalike
> domains, spoofing, malicious links and attachments, and offers a PhishTool-like investigation view.
> The user interface is in French.*

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
| **Zone d'alerte** | Pour les messages dangereux uniquement : une zone rouge dans l'en-tête du message (sous l'expéditeur) avec le score, les principaux indices et les boutons Détails et Signaler. |
| **Alerte** | Une notification discrète en bas à droite de l'écran pour les messages dangereux (ou suspects, au choix). |
| **Fenêtre d'enquête** | Jauge de risque, indices classés par gravité, parcours des serveurs en frise ; onglets Résumé, En-têtes, Parcours, URL, Pièces jointes, Observables, Source, Corps. Les boutons Signaler et Paramètres sont en bas de cette fenêtre. |
| **Signaler** | Envoie le message (en pièce jointe) et le rapport complet à l'équipe sécurité, puis le déplace dans Courrier indésirable. |
| **Ce n'est pas du phishing** | Ajoute l'expéditeur ou son domaine aux expéditeurs de confiance (une usurpation reste toujours signalée). |
| **Explications pédagogiques** | Sous chaque indice, « pourquoi c'est dangereux » et quoi faire. Désactivables pour les utilisateurs expérimentés. |
| **Paramètres** | Tous les réglages depuis Outlook, sans éditer de fichier. |
| **Bêta** | Sources externes optionnelles : OpenPhish, Tranco, DNS, crt.sh (sans clé) ; VirusTotal, abuse.ch, AbuseIPDB (clé gratuite). Résultats regroupés dans l'onglet Bêta de la fenêtre. |
| **Français / anglais** | Langue de l'interface au choix, ou automatique selon Windows. |

### Contrôles effectués

| Domaine | Contrôles |
|---|---|
| **Authentification** | SPF, DKIM, DMARC, compauth (Microsoft), y compris via `ARC-Authentication-Results` écrit par votre propre serveur. Usurpation de votre propre domaine. |
| **Expéditeur** | Domaines sosies de grandes marques, de **votre entreprise** et de **vos correspondants** (typosquatting, homoglyphes, caractères Unicode, marque + mots ajoutés, marque en sous-domaine). **Premier contact**. **Âge du domaine** (RDAP). Nom affiché trompeur, Reply-To détourné, usurpation d'un dirigeant (fraude au président), tenant `onmicrosoft.com`. |
| **Liens** | Sosies, texte du lien ≠ destination, Safe Links et redirections déballés, adresse IP, `@` dans l'URL, raccourcisseurs, hébergeurs gratuits détournés, extensions à risque, domaines récents, listes de blocage. Les liens contenus dans les PDF et pièces jointes HTML sont aussi analysés. |
| **Pièces jointes** | Extension, double extension, caractère d'inversion Unicode, **type réel** (programme renommé en `.pdf`…), empreintes MD5/SHA1/SHA256, et **contenu** : programme caché dans un ZIP, archive chiffrée, macros (y compris cachées dans un `.docx`), JavaScript dans un PDF, fausse page de connexion HTML, objet RTF. |
| **Contenu** | Urgence, demande d'identifiants, demande financière, **IBAN** et changement de RIB, demande de discrétion, QR code, faux « RE: », formulaire dans le message. |
| **Filtres de messagerie** | Objet marqué « SPAM »/« PHISHING », SCL d'Exchange, SpamAssassin, Orange, FortiMail (au mieux). |
| **Listes de blocage** | [Red Flag Domains](https://red.flag.domains/) (nouveaux domaines .fr suspects, mise à jour quotidienne), liste interne de l'utilisateur, liste partagée sur le réseau. |

### Fenêtre d'enquête

- **En-têtes** : champs principaux décodés, détail de l'authentification (domaines, sélecteur DKIM), en-têtes des filtres antispam.
- **Parcours** : chaque serveur traversé, IP, protocole, horodatage et délai entre les sauts ; **IP d'origine**.
- **Observables** : adresses, domaines, IP et empreintes, avec liens de vérification vers VirusTotal, AbuseIPDB, urlscan, WHOIS et MXToolbox (ouverts dans le navigateur, seul l'élément vérifié est transmis).
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
3. En bas de la fenêtre : **Signaler à la sécurité** envoie le message à l'équipe sécurité, **Ce n'est pas du phishing** corrige un faux positif, **Paramètres** ouvre les réglages.

Niveaux : **Risque faible** (0–19), **Suspect** (20–49), **Dangereux** (50 et plus, ou au moins un indice critique).

---

## Configuration

Depuis Outlook : cliquez sur le score PhishGuard, puis sur **Paramètres** en bas de la fenêtre d'analyse
(sans email sélectionné, un clic sur le bouton propose aussi d'ouvrir les paramètres). Les réglages sont enregistrés pour chaque
utilisateur dans `%LOCALAPPDATA%\PhishGuard\config.user.ini` et survivent aux réinstallations.

Le fichier `config.ini` fourni avec l'installeur définit les valeurs par défaut :

| Clé | Rôle | Défaut |
|---|---|---|
| `CompanyName`, `CompanyDomains` | Votre entreprise ; ses sosies sont classés critiques | — |
| `VipNames` | Dirigeants et personnes sensibles (fraude au président) | — |
| `ReportAddress` | Adresse de l'équipe sécurité pour **Signaler** | — |
| `ShowBanner` | Zone d'alerte dans l'en-tête des messages dangereux | `true` |
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
| `RedFlagEnabled` | Liste Red Flag Domains | `true` |
| `AllowUserSettings` | Bouton Paramètres de la fenêtre d'analyse ; `false` impose `config.ini` à tous | `true` |

---

## Zone d'alerte dans l'en-tête (zone.ofs)

Outlook n'affiche une zone dans l'en-tête des messages qu'à partir d'une mise en page créée avec son concepteur
de formulaires. À faire une seule fois :

1. Fichier → Options → Personnaliser le ruban → cocher **Développeur**.
2. Onglet Développeur → **Créer un formulaire** → **Message** → Ouvrir.
3. Onglet Développeur → **Zone de formulaire** → **Nouvelle zone de formulaire** (laisser vide ; réduire sa hauteur à environ 2 cm).
4. **Zone de formulaire** → **Enregistrer la zone de formulaire sous…** → `zone.ofs` dans `%LOCALAPPDATA%\PhishGuard`.
5. Fermer le formulaire sans l'enregistrer, puis redémarrer Outlook.

Sans ce fichier, PhishGuard affiche un bandeau en haut de la fenêtre pour les messages dangereux.

## Déploiement en entreprise

- **Installation silencieuse** (script de connexion, GPO, outil de déploiement) : `PhishGuard-Outlook-vX.Y.Z-installeur.exe /quiet` ou `installer.cmd /quiet`.
- **Configuration imposée** : adaptez `config.ini` avant de distribuer le dossier, avec `AllowUserSettings = false`.
- **Liste de blocage commune** : un fichier texte sur un partage réseau (`SharedBlocklistPath`), rechargé toutes les heures.
- **Signature** : signer `PhishGuard.dll` avec le certificat de signature de code de l'entreprise évite les blocages par l'antivirus, AppLocker ou la stratégie « compléments signés uniquement ».
- **Postes verrouillés** : si le compilateur C# est bloqué, utilisez la DLL de la release (déjà compilée) au lieu de construire sur le poste.

---

## Confidentialité

| Donnée | Où elle va |
|---|---|
| Contenu, objet, pièces jointes des messages | **Nulle part** : analyse sur le poste |
| Noms de domaine (âge du domaine) | `rdap.org` puis le registre du domaine (désactivable) |
| Liste Red Flag Domains | Téléchargée depuis `dl.red.flag.domains` (aucune donnée envoyée) |
| Liens de vérification (VirusTotal…) | Uniquement si vous cliquez, et seulement l'élément vérifié |

Fichiers créés dans `%LOCALAPPDATA%\PhishGuard` : réglages, correspondants (`correspondants.txt`),
âge des domaines déjà vérifiés, liste Red Flag Domains, journal des scores (sans objet ni contenu), journal technique.

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
sur un serveur Windows de GitHub à chaque modification, et publie une release pour chaque tag `v*`.

### Structure du dépôt

```
outlook-exe/                  Complément Outlook (COM, C# 5, .NET Framework 4)
  src/Engine/                 Moteur d'analyse (sans dépendance à Outlook, testable)
  src/AddIn/                  Ruban, lecture des messages, fenêtres, tâches de fond
  tests/Tests.cs              Tests du moteur (lancés à chaque construction)
  installer/                  Installation par utilisateur (copy + reg, sans droits admin)
  config.ini, custom.txt      Configuration par défaut et liste de blocage interne
src/, manifest.xml, server.js Version « complément web » (Office.js), voir docs/complement-web.md
.github/workflows/            Construction, tests et releases
```

---

## Dépannage

| Symptôme | Solution |
|---|---|
| Le groupe PhishGuard n'apparaît pas | Outlook → Fichier → Options → Compléments → *Gérer : Compléments COM* → **Atteindre** : cocher PhishGuard ; vérifier aussi *Éléments désactivés*. |
| PhishGuard est décoché à chaque démarrage | Une stratégie de groupe limite les compléments ou exige qu'ils soient signés. |
| « Windows refuse de lancer le compilateur » | Compilateur bloqué sur ce poste : utilisez la release déjà compilée. |
| « Liste Red Flag Domains non chargée » | Le proxy bloque `dl.red.flag.domains` ; l'analyse fonctionne sans la liste. |

Journal technique : `%LOCALAPPDATA%\PhishGuard\phishguard.log`.

---

## Limites connues

- Fonctionne avec **Outlook classique pour Windows** uniquement (pas le nouvel Outlook ni Outlook sur le web : voir la version « complément web » dans `docs/`).
- Les liens contenus dans des flux PDF compressés ne sont pas extraits.
- La détection FortiMail repose sur des noms d'en-têtes génériques ; les contributions avec des exemples réels sont bienvenues.
- Aucun outil ne détecte 100 % des attaques : PhishGuard aide à décider, il ne remplace pas la vigilance.

---

## Licence et crédits

Code publié sous licence **GNU GPL v3** (voir [LICENSE](LICENSE)) : vous pouvez l'utiliser, le modifier et le redistribuer, à condition que les versions modifiées restent sous la même licence et que leur code source soit fourni.

- Liste [Red Flag Domains](https://red.flag.domains/) : données sous licence **CC BY-NC-SA 4.0** (usage non commercial). Elle est téléchargée par chaque poste et n'est pas redistribuée ici. Pour un usage en entreprise, vérifiez que votre cas est couvert (hello@red.flag.domains) ou désactivez-la (`RedFlagEnabled = false`).
- Âge des domaines : service public [rdap.org](https://rdap.org/) et registres RDAP.
- Inspiré par [PhishTool](https://www.phishtool.com/).
