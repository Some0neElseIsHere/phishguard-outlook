# Sécurité / Security

## Signaler une faille

PhishGuard est un outil de sécurité : une faille peut exposer ses utilisateurs. **Ne la signalez pas dans une issue
publique.** Utilisez le signalement privé de GitHub : onglet **Security** du dépôt, puis **Report a vulnerability**.

Indiquez si possible :

- la version de PhishGuard (Paramètres → À propos) et celle d'Outlook ;
- ce qui se passe et ce qui devrait se passer ;
- un message d'exemple **sans données personnelles** (adresses, noms et contenu remplacés), ou la manière de le
  reproduire.

Vous recevrez une réponse dès que possible. La correction est publiée dans une nouvelle version, et la faille décrite
dans les notes de version une fois la correction disponible.

## Ce qui compte comme une faille

- un message qui échappe à l'analyse ou la fait planter ou figer Outlook ;
- un message capable de se faire passer pour authentifié, interne ou « vérifié » alors qu'il ne l'est pas ;
- une donnée du message ou de l'utilisateur envoyée hors du poste sans que les paramètres le prévoient ;
- l'exécution de code ou l'ouverture d'un lien depuis la fenêtre d'analyse ;
- une clé d'API lisible en clair.

Un phishing simplement non détecté n'est pas une faille : signalez-le dans une issue normale, toujours sans données
personnelles.

## Versions maintenues

Seule la dernière version publiée reçoit des corrections. PhishGuard prévient lui-même quand une nouvelle version est
disponible (Paramètres → À propos).

---

## Reporting a vulnerability

PhishGuard is a security tool: please **do not open a public issue** for a vulnerability. Use GitHub private
reporting instead: **Security** tab, then **Report a vulnerability**. Include the PhishGuard and Outlook versions, the
expected and actual behaviour, and a sample message **with personal data removed**. Only the latest release receives
fixes.
