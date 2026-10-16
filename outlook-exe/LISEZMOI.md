# PhishGuard pour Outlook — version installable (.exe)

Complément « COM » pour **Outlook classique sous Windows** (comme le plugin FortiMail).
Il ajoute dans le ruban un bouton qui affiche le score du message, et une entrée
« Analyser avec PhishGuard » dans le menu clic droit d'un email. Le signalement et les
paramètres sont dans la fenêtre d'analyse (clic sur le score). Interface en français ou en anglais.

- Aucun droit administrateur : installation dans le profil de l'utilisateur.
- Aucun serveur, aucun certificat, aucune fenêtre à laisser ouverte.
- Fonctionne avec Exchange interne : les en-têtes SPF/DKIM/DMARC sont lus directement dans le message.
- Liste **Red Flag Domains** téléchargée une fois par jour au démarrage d'Outlook (proxy et certificats Windows).

## 1. Configurer

Ouvrez `config.ini` avec le Bloc-notes :

| Clé | Rôle |
|---|---|
| `CompanyName` | Nom de l'entreprise |
| `CompanyDomains` | Vos domaines (protégés contre les sosies, niveau critique) |
| `VipNames` | Dirigeants et personnes sensibles (fraude au président) |
| `TrustedDomains` | Partenaires de confiance |
| `ReportAddress` | Adresse de l'équipe sécurité (bouton **Signaler** de la fenêtre d'analyse) |
| `Language` | `auto` (langue de Windows), `fr` ou `en` |
| `RedFlagEnabled` | `true` / `false` pour la liste Red Flag Domains |

La liste interne de domaines malveillants est dans `custom.txt` (un domaine par ligne).

## 2. Construire l'installeur (une fois)

Double-cliquez sur **`construire.bat`**. Il utilise le compilateur C# fourni avec Windows
(.NET Framework 4), donc rien à installer :

1. compile et lance les tests du moteur d'analyse ;
2. compile `PhishGuard.dll` ;
3. fabrique **`build\PhishGuard-Outlook.exe`** avec IExpress (outil intégré à Windows).

Si une étape échoue, la fenêtre affiche l'erreur : copiez-la pour correction.

## 3. Installer

Fermez Outlook, puis double-cliquez sur **`build\PhishGuard-Outlook.exe`**.
Windows peut afficher « Windows a protégé votre ordinateur » (fichier non signé) :
**Informations complémentaires → Exécuter quand même**.

Si l'exe ne peut pas être créé ou lancé, la même installation est possible avec
`build\package\installer.cmd`.

Déploiement silencieux (script de connexion, GPO) : `installer.cmd /quiet`.

## 4. Utiliser

Dès qu'un email est sélectionné ou ouvert, le bouton PhishGuard du ruban (onglet Accueil, ou ruban
du message ouvert) affiche **le score et le verdict**, avec une pastille verte, orange ou rouge.
Le survol du bouton montre les principaux indices ; un clic ouvre la fenêtre d'enquête détaillée
(en-têtes, parcours, URL, pièces jointes, observables...).

Pour un message dangereux, une alerte apparaît en bas à droite de l'écran (cliquez dessus pour le détail).

**Paramètres** (en bas de la fenêtre d'analyse) : langue, domaines de l'entreprise, dirigeants, adresse de signalement,
analyse automatique, niveau d'alerte, domaines de confiance, domaines à bloquer, liste Red Flag Domains.
Les réglages sont propres à chaque utilisateur (`%LOCALAPPDATA%\PhishGuard\config.user.ini` et
`custom.user.txt`) et survivent aux réinstallations. Pour imposer la configuration de `config.ini`
à tous, mettez `AllowUserSettings = false` : le bouton disparaît.

**Signaler à la sécurité** (en bas de la fenêtre d'analyse) prépare un email vers l'équipe sécurité avec le message suspect en pièce
jointe et le rapport complet, puis déplace le message dans Courrier indésirable (désactivable).
Si l'adresse de l'équipe sécurité n'est pas encore configurée, PhishGuard propose de l'indiquer.

**Ce n'est pas du phishing** (fenêtre d'enquête) ajoute l'expéditeur ou son domaine aux expéditeurs de
confiance. Un échec d'authentification (usurpation) reste toujours signalé.

### Contrôles

| Contrôle | Détail |
|---|---|
| Authentification | SPF, DKIM, DMARC, compauth ; lecture d'ARC-Authentication-Results écrit par votre propre serveur |
| Filtres de messagerie | Objet marqué « SPAM »/« PHISHING », en-têtes Exchange (SCL), SpamAssassin, Orange, FortiMail (meilleur effort) |
| Expéditeur | Domaines sosies (marques, votre entreprise, **vos correspondants**), **premier contact**, **âge du domaine**, nom affiché trompeur, Reply-To, dirigeants |
| Liens | Sosies, listes de blocage, texte trompeur, redirections, raccourcisseurs, hébergeurs détournés, âge des domaines, liens contenus dans les PDF et pièces jointes HTML |
| Pièces jointes | Extension, type réel, empreintes, **contenu** : programmes dans un ZIP, archive chiffrée, macros (même cachées dans un .docx), JavaScript dans un PDF, fausse page de connexion HTML, objet RTF |
| Contenu | Urgence, identifiants, demande financière, **IBAN** (et changement de RIB), discrétion, QR code, faux « RE: » |

### Fichiers créés sur le poste (`%LOCALAPPDATA%\PhishGuard`)

| Fichier | Contenu |
|---|---|
| `config.user.ini`, `custom.user.txt` | Réglages et domaines bloqués par l'utilisateur |
| `correspondants.txt` | Adresses de vos correspondants (éléments envoyés + contacts), recalculées chaque jour |
| `domaines-age.txt` | Dates de création des domaines déjà vérifiés |
| `redflagdomains.txt` | Liste Red Flag Domains |
| `scores.csv` | Journal des scores (si activé) |
| `phishguard.log` | Journal technique |

## Désinstaller

Paramètres Windows → Applications → **PhishGuard pour Outlook** → Désinstaller,
ou `%LOCALAPPDATA%\PhishGuard\desinstaller.cmd`.

## Dépannage

| Symptôme | Cause probable |
|---|---|
| Les boutons n'apparaissent pas | Outlook → Fichier → Options → Compléments → en bas « Gérer : Compléments COM » → **Atteindre** : cocher PhishGuard. S'il est dans « Éléments désactivés », le réactiver. |
| PhishGuard est décoché à chaque démarrage | Une stratégie de groupe n'autorise que certains compléments, ou exige des compléments signés : voir le service informatique. |
| L'exe est bloqué ou supprimé | Antivirus / EDR / AppLocker : utiliser `build\package\installer.cmd`, ou faire autoriser l'exe par le service informatique (fichier non signé). |
| `construire.bat` : « Windows refuse de lancer le compilateur » | Le compilateur C# est bloqué sur ce poste : lancer la construction sur un poste où il est autorisé, puis copier le dossier `build`. |
| « Liste Red Flag Domains non chargée » | Le proxy bloque `dl.red.flag.domains` ; l'analyse fonctionne sans la liste. |

Journal d'erreurs : `%LOCALAPPDATA%\PhishGuard\phishguard.log`.

## Structure

```
config.ini, custom.txt       Configuration (intégrée à l'installeur)
construire.bat               Compilation + tests + création de l'exe
src\Engine\                  Moteur d'analyse (portage C# du moteur JavaScript)
  Lists.cs                   Généré depuis ..\src\engine\lists.js (tools\gen-lists.mjs)
src\AddIn\                   Complément Outlook : ruban, lecture du message, fenêtre, signalement
tests\Tests.cs               Tests lancés à chaque construction
installer\                   Installation / désinstallation par utilisateur (copy + reg, sans PowerShell)
tools\make-installer.ps1     Création de l'exe avec IExpress
```
