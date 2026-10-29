# Banc d'essai du moteur sur des corpus publics

Les poids et les seuils du score de PhishGuard sont vérifiés sur de **vrais emails publics** :
de vrais phishings, pour mesurer la détection, et de vrais messages légitimes, pour mesurer les fausses alertes.
Le banc se relance à tout moment depuis l'onglet **Actions** du dépôt (workflow « Banc d'essai »).

## Corpus

| Corpus | Contenu | Messages |
|---|---|---|
| [Corpus de phishing de Jose Nazario](https://monkey.org/~jose/phishing/) | vrais phishings reçus de 2020 à 2025 (identifiants, fausses factures, colis, messagerie…) | 1 807 |
| [phishing_pot](https://github.com/rf-peixoto/phishing_pot) | vrais phishings et arnaques capturés par des pièges à spam, 2023 à 2026, en plusieurs langues (adresses des victimes remplacées par `phishing@pot`) | 12 271 |
| [SPAM Archive](https://untroubled.org/spam) (Bruce Guenter) | spam reçu de juin à octobre 2026, échantillon régulier | 3 000 |
| Listes de diffusion Apache (10 listes, juin à septembre 2025) | messages légitimes récents avec en-têtes d'authentification modernes : développeurs, utilisateurs (souvent depuis Gmail ou Outlook.com), annonces | 4 459 |
| Cas difficiles (`outlook-exe/tests/legitimes`) | mails légitimes français qui ressemblent à du phishing : factures, colis, codes de vérification, réinitialisation de mot de passe, partages OneDrive et Google Drive, DocuSign, Yousign, impots.gouv, ameli, newsletters, fournisseurs ; et la vie courante d'une PME : paie (PayFit, Lucca, Swile, Alan), banque pro (Qonto), comptabilité (Pennylane, expert-comptable, factures et bons de commande), Chorus Pro, net-entreprises, Urssaf, Infogreffe, OVHcloud, Gandi, Teams, SharePoint, Adobe Sign, SNCF, télépéage | 77 |
| [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) (easy_ham, easy_ham_2, hard_ham) | messages légitimes de 2002 et 2003, dont des newsletters commerciales (hard_ham) | 4 150 |

Les cas difficiles sont fictifs (aucun corpus public ne contient ce genre de mails avec leurs en-têtes), mais construits
comme les vrais : domaines d'envoi réels des services, authentification telle que Microsoft 365 l'ajoute, désinscription
en un clic, liens de suivi des plateformes d'envoi. Chacun indique le verdict attendu (vert, ou orange quand l'alerte est
justifiée, comme un changement de RIB). Ils sont générés par `outlook-exe/tools/gen-legitimes.py` : pour ajouter un cas
(une fausse alerte rencontrée au travail, par exemple), il suffit d'y ajouter quelques lignes.

Les corpus publics sont téléchargés par le serveur de test et ne sont jamais copiés dans ce dépôt.
Seul un tableau des indices détectés (identifiant, gravité, catégorie) est produit, ce qui permet de recalculer
d'autres barèmes sans relancer le moteur.

## Conditions

- **Hors ligne** : ni âge des domaines, ni Red Flag Domains, ni OpenPhish, ni DNS. Les domaines de ces vieux
  phishings ont disparu depuis ; sur un vrai poste, ces sources détectent en plus une partie des messages manqués ici.
- **Expéditeurs inconnus** : le carnet de correspondants est chargé mais ne contient aucun des expéditeurs
  (cas le plus défavorable pour les messages légitimes).
- Le domaine `monkey.org` (destinataire des phishings) joue le rôle du domaine de l'entreprise.
- Pour une comparaison équitable, le verdict du filtre antispam du serveur de Nazario (en-têtes `X-Spam`) est retiré,
  ainsi que deux indices propres aux messages de 2003 (aucune authentification SPF/DKIM, liens tous en `http`).

## Résultats

« Alerte » = verdict orange (Suspect) ou rouge (Dangereux).

| | Phishings détectés (alerte) | dont rouges | Fausses alertes, légitimes récents | Fausses alertes, légitimes 2003 |
|---|---|---|---|---|
| v1.10.1 | 73,5 % | 31,0 % | 45,9 % | 23,9 % |
| v1.11.0 | 80,1 % | 43,9 % | 1,2 % (aucun rouge) | 10,5 % (0,9 % rouges) |
| v1.12.0 | 79,8 % | 45,1 % | 3,0 % (0,2 % rouges) sur 4 459 messages | 10,5 % (0,9 % rouges) |
| v1.19.10 | 83,8 % (Nazario 81,4 %, phishing_pot 84,2 %) | 58,1 % | 3,0 % (0,2 % rouges) | 10,6 % (0,9 % rouges) |
| v1.22.0 | 83,9 % (Nazario 81,6 %, phishing_pot 84,2 %) | 58,2 % | 3,1 % (0,2 % rouges) | 10,6 % (0,9 % rouges) |
| v1.23.0 | 84,4 % (Nazario 81,9 %, phishing_pot 84,8 % sur 12 864 messages) | 59,3 % | 3,1 % (0,2 % rouges) | 10,6 % (0,9 % rouges) |
| **v1.24.0** | **86,2 %** (Nazario 83,2 %, phishing_pot 86,6 %) | **60,8 %** | **3,1 %** (0,2 % rouges) | **10,7 %** (0,9 % rouges) |

Les fausses alertes « récentes » de la v1.11.0 portaient sur 567 messages de trois listes ; celles de la v1.12.0 sur
4 459 messages de dix listes, plus variés (questions d'utilisateurs, annonces). Avant les corrections ci-dessous, la
v1.11.0 était à 5,1 % sur ce corpus élargi.

**Cas difficiles** : 17 fausses alertes sur 40 en v1.11.0, **aucune** en v1.12.0 (le changement de RIB reste orange,
comme attendu). 11 de ces mails obtiennent « Expéditeur vérifié ».

**Nouveaux corpus (v1.15.1)** : sur les **12 271 phishings récents de phishing_pot**, PhishGuard en signale **78,2 %**,
dont **47,7 % en rouge**, soit les mêmes taux que sur le corpus de Nazario, sans aucun réglage spécifique : le barème
n'est pas sur-ajusté à un corpus. 46 % de ces messages datent de 2026. Les messages manqués sont surtout des
arnaques commerciales (faux bons d'achat, loteries, faux produits) envoyées depuis des domaines authentifiés, sans
demande d'identifiants. Sur le **spam 2026**, 88 % des messages sont signalés, mais seulement 11 % en rouge : c'est
voulu, un spam publicitaire n'est pas un phishing.

Détection par année (v1.11.0) : 2020 90 %, 2021 85 %, 2022 76 %, 2023 86 %, 2024 78 %, 2025 74 %.

## Ce que le banc a corrigé

1. **Listes de diffusion** : leur `Reply-To` pointe vers la liste, ce qui déclenchait « Les réponses partiront vers
   une autre adresse » sur 45 % des messages légitimes récents. Une réponse vers l'adresse de publication de la liste
   (`List-Post`) n'est plus un indice, et un message adressé à la liste n'est plus un « premier contact ».
   Un faux en-tête de liste ne suffit pas : l'adresse de la liste doit figurer parmi les destinataires.
2. **Fausses alertes de messagerie** (« messages bloqués », « boîte pleine », « mot de passe qui expire ») :
   nouveau prétexte détecté (22 % des phishings, 0 % des légitimes) et combinaison avec l'urgence ou une demande
   d'identifiants classée Élevée.
3. **Votre adresse dans l'objet** (« Incoming messages failed for vous@entreprise.fr ») ou en guise de salutation :
   19 % des phishings, aucun message légitime.
4. **Combinaisons décisives hors plafond** : les mots-clés du contenu restent plafonnés à 30 points (un message
   commercial en contient beaucoup), mais les combinaisons (identifiants + urgence, paiement + urgence ou discrétion,
   fausse alerte de messagerie, changement de RIB) comptent en entier. Les phishings classés rouges passent de
   37 % à 44 %, sans fausse alerte rouge supplémentaire.

## Ce que les cas difficiles ont corrigé (v1.12.0)

5. **Mails authentifiés sur le domaine officiel d'une marque** (code Microsoft, réinitialisation LinkedIn, facture EDF,
   alerte Google) : leur texte parle forcément de mot de passe ou de paiement, c'est leur métier. Quand le domaine
   appartient à la marque et que l'authentification est alignée, les indices de contenu sont abaissés et l'expéditeur
   peut être « vérifié ». Les messageries gratuites (outlook.fr, gmail.com…) et les plateformes n'en profitent jamais.
6. **Domaines officiels manquants** : `notif-colissimo-laposte.info`, `pickup.fr` (Chronopost),
   `dgfip.finances.gouv.fr`, `assurance-maladie.fr`, `sharepointonline.com`, Yousign, Doctolib.
7. **Opérateurs qui sont aussi des messageries** (Orange, Free) : `facture@orange.fr` authentifié n'est plus un faux
   « Orange », mais une boîte orange.fr quelconque nommée « Orange » reste signalée.
8. **Plateformes de partage et de signature** (DocuSign, Google Drive, OneDrive, Yousign…) : l'adresse de réponse est
   celle de la personne qui envoie le document, c'est normal (indice abaissé). En contrepartie, **un partage dont le titre
   imite une alerte de compte** (« We Have Limited Your Login ID… ») devient un indice Élevé : c'est une technique
   courante du corpus de phishing (22 messages en 2023-2024), absente des mails légitimes.
9. **Messages internes** : un « Microsoft Outlook » interne (rapport de non-remise d'Exchange) n'est plus un faux Microsoft.
10. **Listes techniques** : les liens d'exemple vers `localhost` ou le réseau local, les adresses réécrites en
    `@….invalid` par les listes et les questions de « mot de passe » posées sur une liste publique ne sont plus des indices.

## Codes de connexion (v1.12.1)

11. **Vrais mails de code** (signalé au travail : un code Riot Games à 70/100, reçu sur une boîte Orange) : leur
    avertissement « si ce n'est pas vous, changez immédiatement votre mot de passe » déclenchait « identifiants + urgence ».
    Un message qui **donne** un code, authentifié, sans indice d'usurpation, sans pièce jointe ni formulaire, et dont
    **tous les liens restent sur le domaine de l'expéditeur**, n'est plus pénalisé pour son texte. Le même texte avec un
    lien vers un autre site reste en alerte. Cas ajoutés : Riot Games (en-têtes Orange), Steam, Vinted, leboncoin.
    Aucun effet sur la détection des phishings du corpus.

## Barèmes testés et écartés

- **Relever le seuil de « Suspect »** (de 20 à 25 ou 30 points) : moins de fausses alertes sur les newsletters de 2003,
  mais 9 à 15 points de détection perdus. Écarté.
- **Regrouper les indices par catégorie** (le plus grave compte, les autres pour un quart) : résultats équivalents
  au barème actuel, en plus compliqué. Écarté.
- **Règle « tromperie sur l'identité + demande d'action = rouge »** : +2 points de rouges, mais deux fois plus de
  fausses alertes rouges. Écarté.

## Robustesse et rapidité (v1.15.1)

Les 12 271 messages de phishing_pot ont aussi servi de test de robustesse : un lien dont le nom de serveur est invalide
faisait échouer la lecture de l'adresse, et pouvait faire échouer l'analyse. Le nom de serveur est désormais lu sans
exception partout, et un test passe en revue une série de liens piégés. Les expressions régulières construites à
chaque message (mots-clés, noms de marques) ont été remplacées par une recherche directe ou mises en cache : le
message le plus lent passe de 4,6 s à 0,6 s, et l'ensemble du banc (plus de 25 000 messages) de plus de 30 minutes à 9.
Le banc impose un délai maximal de 3 secondes à chaque expression régulière : aucun message n'a déclenché ce délai.

## Mails d'entreprise français (v1.16.3)

Aucun corpus public ne contient de vrais mails d'entreprise français avec leurs en-têtes (ils sont personnels) ; les
listes de diffusion francophones encore actives sont rares, et la plupart n'exportent pas leurs archives. Deux sources
ont donc servi :

- **Les 421 phishings en français de phishing_pot** (faux Chronopost, CPF, rachat de crédit, mutuelle, VINCI
  Autoroutes, faux bons d'achat…) : **99,8 % signalés, 84 % en rouge** (83 % avant). Les mots-clés français font
  leur travail.
- **32 nouveaux cas difficiles** construits sur le modèle des vrais mails d'une PME, reçus par **différentes passerelles** :
  Microsoft 365, **FortiMail** (SPF et DKIM sans résultat DMARC, signature notée `header.i`), Google Workspace et un
  filtre français. Deux fausses alertes trouvées et corrigées : un **avis de virement reçu** (Qonto) et un
  **remboursement de mutuelle** (Alan) étaient pris pour une « demande sensible dès le premier message ». Un avis
  d'argent reçu n'est plus une demande, sauf s'il réclame quelque chose (coordonnées bancaires, formulaire, frais…) :
  le faux remboursement qui demande votre RIB reste signalé.
- **Marques françaises ajoutées** : Mon Compte Formation (CPF), VINCI Autoroutes, Qonto, OVHcloud, SNCF, Chorus Pro,
  Urssaf, Crit'Air. Leurs vrais mails obtiennent « Expéditeur vérifié » ; un faux à leur nom envoyé d'un autre domaine
  est signalé.

Résultat : **77 cas difficiles sur 77 corrects**, 27 avec « Expéditeur vérifié » ; détection des phishings 78,6 %
(78,4 % avant), fausses alertes inchangées sur les listes Apache (3,0 %).

## Faux phishings français et contrôle mensuel (v1.17.0)

- **31 faux phishings français fictifs** (`outlook-exe/tests/phishings-fr`, générés par `outlook-exe/tools/gen-phishings.py`),
  inspirés des campagnes décrites publiquement par Cybermalveillance.gouv.fr, l'ANSSI et le CERT-FR : faux Ameli, CPF,
  ANTAI, Crit'Air, impots.gouv, Urssaf, Chorus Pro, France Travail, colis, Microsoft 365, Orange, banques, leboncoin,
  fraude au président, faux changement de RIB, conversation détournée, usurpation de votre propre domaine, pièces jointes
  piégées (page de connexion HTML, programme déguisé dans un zip, image disque, PDF avec lien). La plupart viennent d'un
  domaine sosie **correctement authentifié**, le cas le plus difficile hors ligne. Chacun indique le verdict attendu
  (rouge, ou au moins orange). **31 sur 31 signalés, 27 en rouge.** Trois techniques passaient inaperçues et sont
  maintenant détectées : l'**annonce d'un appel d'un faux conseiller** (« validez l'opération avec le code reçu par
  SMS »), la **demande de numéro de carte ou de cryptogramme** (faux acheteur, faux remboursement) et le **lien caché
  dans le PDF joint** (« cliquez sur le lien du document »). Un mail de prévention de la banque qui décrit l'arnaque
  (« votre conseiller ne vous demandera jamais… ») n'est pas signalé.
- **Contrôle mensuel automatique** : le banc complet tourne le 1er de chaque mois, avec les phishings et le spam les plus
  récents. Un résumé compare chaque corpus au mois précédent ; une baisse sur un corpus qui n'a pas changé (donc due au
  moteur) ouvre automatiquement un ticket sur le dépôt.
- **Tests de robustesse** : à chaque construction, 400 messages malformés générés au hasard (en-têtes cassés, encodages
  invalides, HTML piégé, pièces jointes corrompues) traversent toute l'analyse ; le banc mensuel en lance 5 000 avec une
  graine différente chaque mois. Aucune exception, aucun message de plus de 2 secondes. Ces tests ont trouvé un défaut :
  un texte contenant un caractère Unicode invalide faisait échouer l'analyse, et le message restait **sans verdict ni
  alerte**. Ce texte est maintenant accepté, et une analyse qui échoue malgré tout classe le message « suspect » avec la
  raison, au lieu de ne rien afficher.

## Ce qui reste manqué

Les 20 % de phishings non détectés hors ligne sont presque tous des messages courts, envoyés d'un domaine inconnu
correctement authentifié, avec un seul lien vers un site piraté. Seuls l'âge du domaine et les listes de sites
malveillants (Red Flag Domains, OpenPhish), actifs sur un vrai poste, peuvent les repérer : d'où l'intérêt de les laisser activés.

## Limites

- Le corpus de phishing est surtout en anglais ; les mots-clés de PhishGuard sont d'abord français.
- Les vrais messages légitimes récents viennent de listes techniques ; newsletters, factures et notifications ne sont
  couvertes que par les cas difficiles, fictifs.
- Un poste réel connaît une bonne partie de ses expéditeurs, ce qui réduit encore les fausses alertes.
