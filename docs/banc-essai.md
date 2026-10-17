# Banc d'essai du moteur sur des corpus publics

Les poids et les seuils du score de PhishGuard sont vérifiés sur de **vrais emails publics** :
de vrais phishings, pour mesurer la détection, et de vrais messages légitimes, pour mesurer les fausses alertes.
Le banc se relance à tout moment depuis l'onglet **Actions** du dépôt (workflow « Banc d'essai »).

## Corpus

| Corpus | Contenu | Messages |
|---|---|---|
| [Corpus de phishing de Jose Nazario](https://monkey.org/~jose/phishing/) | vrais phishings reçus de 2020 à 2025 (identifiants, fausses factures, colis, messagerie…) | 1 807 |
| Listes de diffusion Apache (septembre 2025) | messages légitimes récents, avec en-têtes d'authentification modernes | 567 |
| [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) (easy_ham, easy_ham_2, hard_ham) | messages légitimes de 2002 et 2003, dont des newsletters commerciales (hard_ham) | 4 150 |

Les corpus sont téléchargés par le serveur de test et ne sont jamais copiés dans ce dépôt.
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
| **v1.11.0** | **80,1 %** | **43,9 %** | **1,2 %** (aucun rouge) | **10,5 %** (0,9 % rouges) |

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

## Barèmes testés et écartés

- **Relever le seuil de « Suspect »** (de 20 à 25 ou 30 points) : moins de fausses alertes sur les newsletters de 2003,
  mais 9 à 15 points de détection perdus. Écarté.
- **Regrouper les indices par catégorie** (le plus grave compte, les autres pour un quart) : résultats équivalents
  au barème actuel, en plus compliqué. Écarté.
- **Règle « tromperie sur l'identité + demande d'action = rouge »** : +2 points de rouges, mais deux fois plus de
  fausses alertes rouges. Écarté.

## Ce qui reste manqué

Les 20 % de phishings non détectés hors ligne sont presque tous des messages courts, envoyés d'un domaine inconnu
correctement authentifié, avec un seul lien vers un site piraté. Seuls l'âge du domaine et les listes de sites
malveillants (Red Flag Domains, OpenPhish), actifs sur un vrai poste, peuvent les repérer : d'où l'intérêt de les laisser activés.

## Limites

- Le corpus de phishing est surtout en anglais ; les mots-clés de PhishGuard sont d'abord français.
- Les messages légitimes récents viennent de listes techniques : pas de newsletters ni de factures récentes, pour
  lesquelles aucun corpus public avec en-têtes complets n'est disponible.
- Un poste réel connaît une bonne partie de ses expéditeurs, ce qui réduit encore les fausses alertes.
