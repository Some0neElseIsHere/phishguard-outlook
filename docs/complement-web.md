# PhishGuard — complément Outlook anti-phishing

Un bouton **Analyser** dans Outlook ouvre un panneau qui donne un verdict (sûr / suspect / dangereux),
un score sur 100 et la liste des indices trouvés. Tout est calculé **localement** dans le panneau :
aucune clé d'API, aucun envoi du contenu des emails vers un service externe.

## Ce qui est analysé

| Catégorie | Contrôles |
|---|---|
| **Authentification** | SPF, DKIM, DMARC et `compauth` (Exchange Online) ; usurpation de votre propre domaine ; message interne authentifié |
| **Expéditeur** | Domaine sosie (voir ci-dessous) ; nom affiché qui cite une marque (« Microsoft 365 Support » depuis un autre domaine) ; nom affiché contenant une autre adresse ; nom d'un dirigeant depuis une adresse externe (fraude au président) ; `Reply-To` vers un autre domaine ou une messagerie gratuite ; tenant `*.onmicrosoft.com` |
| **Liens** | Domaines sosies ; texte du lien ≠ vraie destination ; liens Safe Links et redirections « déballés » ; adresse IP ; `@` dans l'URL ; caractères non latins ; raccourcisseurs ; hébergements gratuits souvent détournés ; extensions à risque ; http ; ports inhabituels ; téléchargement direct de fichiers dangereux |
| **Pièces jointes** | Exécutables, double extension (`facture.pdf.exe`), caractère d'inversion Unicode, HTML/SVG, macros Office, ISO/IMG/VHD, OneNote, archives |
| **Contenu** (FR + EN) | Urgence, demande d'identifiants, demande financière (RIB, virement, carte cadeau), discrétion, prétextes classiques, QR code ; combinaisons (identifiants + urgence, paiement + confidentialité) ; formulaire ou champ mot de passe dans le message ; faux « RE: » |

### Détection des domaines sosies (sans API)

Le moteur compare chaque domaine (expéditeur, Reply-To, liens) à **vos domaines** et à ~45 marques
souvent usurpées (Microsoft, Google, PayPal, DocuSign, La Poste, ameli, impots.gouv, banques françaises…) :

| Technique | Exemple |
|---|---|
| Faute de frappe (distance d'édition) | `niicrosoft.com`, `arnazon.fr`, `linkedln.com` |
| Homoglyphes ASCII | `rnicrosoft.com` (rn → m), `micros0ft.com`, `paypa1.com` |
| Homoglyphes Unicode (punycode) | `pаypal.com` avec un « а » cyrillique (`xn--pypal-4ve.com`) |
| Marque + mots ajoutés | `microsoft-login-secure.com`, `secure-paypal.xyz`, `microsoft-login.web.app` |
| Marque dans un sous-domaine | `login.microsoft.com.verify-acct.xyz` |
| Même nom, autre extension | `mon-entreprise.com` au lieu de `mon-entreprise.fr` |

Un domaine qui imite **votre** domaine est toujours classé **critique**.

## Démarrage (poste de développement Windows)

Prérequis : Node.js 18+ et Outlook pour Windows (Microsoft 365).

```bash
npm run certs      # crée et approuve un certificat HTTPS local (une seule fois)
npm start          # sert le panneau sur https://localhost:3000
npm test           # tests du moteur d'analyse
npm run validate   # vérifie le manifeste avec l'outil officiel de Microsoft
```

Installer le complément pour vous (sideloading) :
1. Ouvrez https://aka.ms/olksideload dans votre navigateur (ou, dans Outlook : **Fichier → Gérer les compléments**).
2. **Mes compléments → Ajouter un complément personnalisé → Ajouter à partir du fichier** → choisissez `manifest.xml`.
3. Ouvrez un email : le bouton **Analyser** apparaît dans le ruban. L'icône d'épingle garde le panneau ouvert et il se met à jour à chaque message.

## Configuration

Modifiez `src/config.js` : nom et domaines de l'entreprise, noms des dirigeants (fraude au président),
domaines partenaires de confiance, adresse de l'équipe sécurité pour le bouton **Signaler**.
Les listes de marques, raccourcisseurs, extensions suspectes, etc. sont dans `src/engine/lists.js`.

Chaque utilisateur peut aussi « faire confiance » à un domaine depuis le panneau (stocké dans sa boîte aux lettres).

## Listes de domaines malveillants

Le panneau compare l'expéditeur, l'adresse de réponse et tous les liens (sous-domaines compris) à des listes
de domaines malveillants connus :

| Source | Contenu | Niveau |
|---|---|---|
| [Red Flag Domains](https://red.flag.domains/) | Nouveaux domaines .fr (et .re, .paris, .bzh…) suspects, vérifiés manuellement, publiés chaque jour | Élevé |
| `blocklists/custom.txt` | Liste interne de votre équipe sécurité, un domaine par ligne | Critique |

```bash
npm run update-lists   # télécharge les listes et produit src/data/blocklist.json
```

Le panneau lit `src/data/blocklist.json` sur le serveur du complément (même adresse, donc aucun problème de
navigateur). Si le fichier est absent ou si le téléchargement échoue, l'analyse continue sans les listes,
et la dernière liste valide est conservée.

**À planifier chaque jour sur le serveur qui héberge le complément**, par exemple sous Windows :

```powershell
schtasks /Create /TN "PhishGuard - listes" /SC DAILY /ST 07:30 `
  /TR "cmd /c cd /d C:\phishguard && node tools\update-blocklists.mjs >> logs\update-lists.log 2>&1"
```

⚠️ **Licence** : les données Red Flag Domains sont publiées sous licence CC BY-NC-SA 4.0 (usage non commercial,
à des fins de sécurité). Avant un déploiement en entreprise, vérifiez que votre usage est couvert ou demandez
l'autorisation à hello@red.flag.domains. Pour désactiver la source, retirez-la du tableau `SOURCES`
dans `tools/update-blocklists.mjs` ; vous pouvez y ajouter d'autres listes au même format (un domaine par ligne).

Le même fichier peut aussi alimenter votre proxy, votre DNS filtrant ou votre pare-feu : vous bloquez ainsi les
clics depuis n'importe quelle application, pas seulement depuis Outlook.

## Déploiement en entreprise

1. Hébergez le dossier `src/` sur un serveur web HTTPS interne ou public (IIS, Azure Static Web Apps, etc.).
   Ce sont des fichiers statiques, sans serveur applicatif.
2. Générez le manifeste de production : `npm run manifest:prod -- https://phishguard.mon-entreprise.fr`
3. Centre d'administration Microsoft 365 → **Paramètres → Applications intégrées → Charger des applications personnalisées**
   → envoyez `manifest.prod.xml` et choisissez les utilisateurs ou groupes.
   Le déploiement peut prendre jusqu'à 24 h.

Compatibilité : Outlook classique pour Windows (Microsoft 365, moteur WebView2), nouvel Outlook et Outlook sur le web.
La lecture des en-têtes (SPF/DKIM/DMARC) nécessite l'ensemble d'API Mailbox 1.8 ; sur une version plus ancienne,
ces contrôles sont simplement ignorés.

## Structure

```
manifest.xml              Manifeste du complément (développement : https://localhost:3000)
server.js                 Serveur HTTPS de développement (aucune dépendance)
src/config.js             Configuration de l'entreprise
src/engine/               Moteur d'analyse (JavaScript pur, testable sans Outlook)
  index.js                Score, verdict, rapport
  domains.js              Domaine enregistrable, punycode, homoglyphes, sosies
  auth.js sender.js links.js attachments.js content.js
  lists.js                Marques, raccourcisseurs, extensions, messageries gratuites
src/taskpane/             Panneau Outlook (HTML/CSS/JS)
src/assets/               Icônes
src/engine/blocklist.js   Recherche dans les listes de domaines malveillants
src/data/blocklist.json   Listes téléchargées (généré par npm run update-lists)
blocklists/custom.txt     Liste interne de l’équipe sécurité
tools/update-blocklists.mjs  Mise à jour quotidienne des listes
test/engine.test.js       Tests (node --test)
tools/build-manifest.mjs  Génère le manifeste de production
```

## Sécurité du complément

- Le contenu des emails n'est jamais injecté en HTML dans le panneau (uniquement `textContent`).
- Le corps est analysé avec `DOMParser`, qui n'exécute ni scripts ni images.
- Les URL du rapport sont « désarmées » (`hxxps://exemple[.]com`).
- Permission minimale : `ReadItem` (lecture du message ouvert uniquement).

## Pistes d'évolution

- **Âge du domaine** : un domaine créé il y a moins de 30 jours est un signal très fort. Le protocole RDAP
  (successeur de WHOIS) est gratuit et sans clé, mais il faut l'appeler depuis un petit backend (CORS).
- **Réputation des URL** via un backend : URLhaus / ThreatFox (abuse.ch, clé gratuite),
  Google Safe Browsing (clé gratuite), OpenPhish (flux gratuit réservé à l'usage non commercial : licence payante en entreprise).
- **Surveillance proactive de vos sosies** : `dnstwist` (open source) génère les variantes de votre domaine et
  indique celles qui sont enregistrées ; à lancer régulièrement pour alimenter une liste de blocage.
- **Tableau de bord** des signalements pour l'équipe sécurité.
