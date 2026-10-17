# PhishGuard pour Outlook — notice d'installation

Complément « COM » pour **Outlook classique sous Windows**. Il affiche dans le ruban le score de risque
du message sélectionné ou ouvert, alerte en cas de danger, et ouvre sur demande une fenêtre d'enquête
détaillée. Il ajoute aussi « Analyser avec PhishGuard » au menu clic droit d'un email.
Interface en français ou en anglais.

- Aucun droit administrateur : installation dans le profil de l'utilisateur (`%LOCALAPPDATA%\PhishGuard`).
- Aucun serveur, aucun certificat, aucune fenêtre à laisser ouverte.
- Le contenu des messages est analysé sur le poste et n'en sort jamais.

Documentation complète : <https://github.com/Some0neElseIsHere/phishguard-outlook>

## 1. Configurer (facultatif)

Les réglages se font **depuis Outlook** après l'installation. Pour imposer des valeurs à toute
l'entreprise, ouvrez `config.ini` avec le Bloc-notes **avant** d'installer :

| Clé | Rôle |
|---|---|
| `CompanyName`, `CompanyDomains` | Votre entreprise et ses domaines (leurs sosies sont classés critiques) |
| `Company1`, `Company2`… | Entreprises surveillées et leurs dirigeants (fraude au président) : `Nom \| Pays \| Identifiant \| Dirigeant; Dirigeant` |
| `TrustedDomains`, `TrustedSenders` | Partenaires et adresses de confiance |
| `ReportAddress` | Adresse de l'équipe sécurité (bouton **Signaler à la sécurité**) |
| `Language` | `auto` (langue de Windows), `fr` ou `en` |
| `RedFlagEnabled` | `true` / `false` pour la liste Red Flag Domains |
| `WatchDomains` | Surveillance hebdomadaire des sosies de vos domaines |
| `AllowUserSettings` | `false` : configuration imposée, le bouton Paramètres disparaît |

Les autres clés sont décrites dans `config.ini`. La liste de domaines malveillants de l'équipe sécurité
est dans `custom.txt` (un domaine par ligne).

## 2. Installer

1. Fermez Outlook.
2. Double-cliquez sur **`installer.cmd`**.
3. Rouvrez Outlook : le score PhishGuard apparaît dans l'onglet Accueil.

Déploiement silencieux (script de connexion, GPO) : `installer.cmd /quiet`.
Une version déjà installée est mise à jour ; les réglages de l'utilisateur sont conservés.

## 3. Utiliser

- **Mode simple** (par défaut) : un clic sur la pastille indique en clair si le message est dangereux, pourquoi, et **quoi faire**. Le bouton **Analyse détaillée** passe au mode expert (analyse technique complète et réglages avancés). Au démarrage d'Outlook, un assistant explique les couleurs et demande l'essentiel (après une mise à jour, seulement les nouveautés).
- **Le bouton du ruban** affiche le verdict et le score (pastille verte, orange ou rouge), ou
  « Expéditeur vérifié » avec une coche. Le survol montre les principaux indices ; un clic ouvre la fenêtre d'enquête.
- **Alerte** en bas à droite de l'écran pour les messages dangereux (cliquez dessus pour le détail).
- **Signaler à la sécurité** (en bas de la fenêtre d'enquête) : après une double confirmation, envoie à
  l'équipe sécurité un rapport HTML détaillé avec le message d'origine joint, puis déplace le message
  dans Courrier indésirable (désactivable). Si l'adresse n'est pas configurée, PhishGuard propose de l'indiquer.
- **Ce n'est pas du phishing** : ajoute l'expéditeur ou son domaine aux expéditeurs de confiance.
  Un échec d'authentification (usurpation) reste toujours signalé.
- **Paramètres** (en bas de la fenêtre d'enquête) :
  - *Entreprise* : une ou plusieurs entreprises (recherche dans l'Annuaire des Entreprises ou Wikidata) et leurs dirigeants, domaines,
    adresse de l'équipe sécurité, **Analyser mon domaine…** (sécurité email, sosies enregistrés) ;
  - *Analyse* : langue, analyse automatique, alertes, explications, correspondants, âge des domaines ;
  - *Listes* : domaines et expéditeurs de confiance, domaines à bloquer, liste partagée ;
  - *Réputation* : sources externes optionnelles (Red Flag Domains, OpenPhish, Tranco, DNS, crt.sh, VirusTotal, abuse.ch, AbuseIPDB).
    Les clés d'API sont rangées dans le Gestionnaire d'identification de Windows.

## Fichiers créés sur le poste (`%LOCALAPPDATA%\PhishGuard`)

| Fichier | Contenu |
|---|---|
| `config.user.ini`, `custom.user.txt` | Réglages et domaines bloqués par l'utilisateur |
| `correspondants.txt` | Adresses de vos correspondants (éléments envoyés et contacts), recalculées chaque jour |
| `fils.txt` | Identifiants de vos messages envoyés et domaines de leurs destinataires (détection des réponses et des détournements de fil) |
| `surveillance.txt` | Sosies de vos domaines déjà vus, et ceux bloqués par la surveillance |
| `domaines-age.txt` | Dates de création des domaines déjà vérifiés |
| `redflagdomains.txt`, `openphish.txt`, `tranco.txt` | Listes téléchargées |
| `scores.csv` | Journal des scores (si activé ; ni objet ni contenu) |
| `phishguard.log` | Journal technique |

## Désinstaller

Paramètres Windows → Applications → **PhishGuard pour Outlook** → Désinstaller,
ou `%LOCALAPPDATA%\PhishGuard\desinstaller.cmd`.

## Dépannage

| Symptôme | Cause probable |
|---|---|
| Le bouton n'apparaît pas | Outlook → Fichier → Options → Compléments → en bas « Gérer : Compléments COM » → **Atteindre** : cocher PhishGuard. S'il est dans « Éléments désactivés », le réactiver. |
| PhishGuard est décoché à chaque démarrage | Une stratégie de groupe n'autorise que certains compléments, ou exige des compléments signés : voir le service informatique. |
| `installer.cmd` est bloqué | Antivirus / EDR / AppLocker : faire autoriser le dossier par le service informatique. |
| « Liste Red Flag Domains non chargée » | Le proxy bloque `dl.red.flag.domains` ; l'analyse fonctionne sans la liste. |
| Le signalement s'ouvre au lieu de partir | Outlook a refusé l'envoi automatique : cliquez sur Envoyer. |

Journal d'erreurs : `%LOCALAPPDATA%\PhishGuard\phishguard.log`.
