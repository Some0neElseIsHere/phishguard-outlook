// PhishGuard - explications pédagogiques : pour chaque indice, « pourquoi c'est dangereux » et « que faire ».
// Affichées sous chaque indice (désactivables dans Paramètres pour les utilisateurs expérimentés).

using System.Collections.Generic;

namespace PhishGuard
{
    public static class Lessons
    {
        // Clé exacte, ou préfixe se terminant par "-" (ex. "sender-lookalike-")
        static readonly Dictionary<string, string> Texts = new Dictionary<string, string>
        {
            { "auth-dmarc", "DMARC vérifie que le domaine affiché dans « De » a réellement autorisé cet envoi. En cas d’échec, n’importe qui a pu écrire ce nom : c’est le cœur de l’usurpation d’identité. Ne vous fiez pas au nom affiché." },
            { "sender-thread-hijack", "Un fraudeur qui a piraté la boîte d’un de vos contacts, ou qui a intercepté un échange, peut répondre à une vraie conversation depuis un domaine proche. Vérifiez toujours un changement de coordonnées bancaires par téléphone, avec un numéro que vous connaissez déjà." },
            { "auth-compauth-intra", "Votre propre domaine est protégé par DMARC : un message qui s’en réclame sans passer par vos serveurs est presque toujours une usurpation." },
            { "auth-compauth", "Microsoft combine plusieurs contrôles (SPF, DKIM, DMARC, réputation). Un échec signifie que l’expéditeur affiché n’est probablement pas le vrai." },
            { "auth-spf", "SPF liste les serveurs autorisés à envoyer pour un domaine. Ce message vient d’un serveur qui n’est pas sur la liste." },
            { "auth-spf-soft", "Le domaine n’autorise pas clairement ce serveur. Seul, ce n’est pas grave ; combiné à d’autres indices, c’est un signal d’usurpation." },
            { "auth-dkim", "DKIM est une signature numérique. Une signature invalide veut dire que le message a été modifié ou que la signature est fausse." },
            { "auth-company-unauth", "Un vrai message interne passe par vos serveurs. Celui-ci prétend venir de votre entreprise mais arrive de l’extérieur sans authentification : c’est une usurpation." },
            { "sender-lookalike-", "Les pirates achètent des domaines presque identiques aux vrais (une lettre changée, « rn » à la place de « m », un « l » à la place d’un « i »…). Lisez l’adresse lettre par lettre, ne vous fiez pas au nom affiché." },
            { "links-lookalike-", "Le lien mène vers un site dont le nom imite un site connu. La page imitera sans doute aussi la vraie pour voler vos identifiants. Passez par le site officiel en tapant vous-même l’adresse." },
            { "sender-correspondent-lookalike", "Fraude au fournisseur : le pirate imite le domaine d’un partenaire avec qui vous échangez déjà, puis demande un paiement ou un changement de RIB. Appelez votre contact au numéro habituel." },
            { "sender-first-contact", "Vous n’avez jamais écrit à cet expéditeur. Ce n’est pas suspect en soi, mais un inconnu mérite plus de prudence, surtout s’il demande une action." },
            { "sender-new-domain", "Les domaines de phishing sont utilisés juste après leur création, avant d’être repérés et bloqués. Un domaine de quelques jours qui vous écrit est un signal fort." },
            { "link-new-domain", "Le lien mène vers un domaine créé il y a quelques jours : les sites de phishing ont souvent une durée de vie très courte." },
            { "sender-brand-name", "N’importe qui peut écrire « Microsoft » ou « La Poste » dans son nom d’expéditeur. Seule l’adresse après le @ compte." },
            { "sender-vip", "Fraude au président : le pirate se fait passer pour un dirigeant, souvent depuis une adresse personnelle, et demande un virement urgent et confidentiel. Vérifiez toujours de vive voix." },
            { "sender-replyto", "Vos réponses partiraient vers une autre adresse que celle affichée : technique pour poursuivre l’échange avec le pirate tout en paraissant légitime." },
            { "sender-name-address", "Le nom affiché contient une fausse adresse pour vous tromper ; l’adresse réelle est différente." },
            { "sender-onmicrosoft", "Les adresses en « .onmicrosoft.com » se créent gratuitement en quelques minutes. Une vraie entreprise utilise son propre domaine." },
            { "sender-blocklist-", "Ce domaine est déjà connu comme malveillant. Ne répondez pas et ne cliquez sur rien." },
            { "links-blocklist-", "Ce lien mène vers un domaine déjà connu comme malveillant." },
            { "sender-trusted-spoof", "Vous faites confiance à cet expéditeur, mais le message ne vient pas de ses serveurs : quelqu’un usurpe son identité." },
            { "link-text-mismatch", "Le texte du lien affiche une adresse rassurante, mais le clic mène ailleurs. Survolez toujours un lien pour voir sa vraie destination." },
            { "link-ip", "Un vrai service utilise un nom de domaine ; un lien vers une simple adresse IP sert souvent à contourner les filtres." },
            { "link-shortener", "Un lien raccourci cache sa destination réelle : impossible de savoir où il mène avant de cliquer." },
            { "link-hosting", "Ces hébergeurs sont légitimes, mais n’importe qui peut y créer gratuitement une fausse page de connexion à l’apparence officielle." },
            { "link-userinfo", "Dans une adresse web, tout ce qui précède « @ » est ignoré : « microsoft.com@site-pirate.xyz » mène en réalité vers site-pirate.xyz." },
            { "link-rewritten", "Proofpoint (urldefense.com), Safe Links, Mimecast... remplacent chaque lien par le leur pour le vérifier au moment du clic. C’est normal et non suspect : seule la vraie destination compte." },
            { "link-redirect", "Le lien passe par un site intermédiaire qui vous redirige ailleurs, pour échapper aux filtres." },
            { "link-download", "Le lien télécharge directement un fichier à risque (programme, archive, document à macros)." },
            { "link-tld", "Ces extensions de domaine sont très bon marché et massivement utilisées pour des campagnes de phishing." },
            { "att-double", "« facture.pdf.exe » : Windows masque souvent la dernière extension, le fichier semble être un PDF mais c’est un programme." },
            { "att-rtlo", "Un caractère invisible inverse l’affichage de la fin du nom pour faire passer un programme pour un document." },
            { "att-exec", "Un programme reçu par email peut prendre le contrôle de votre poste. Aucun partenaire sérieux n’envoie de programme par email." },
            { "att-magic-", "Le contenu réel du fichier ne correspond pas à son extension : il se fait passer pour autre chose." },
            { "att-html", "Une pièce jointe HTML s’ouvre dans le navigateur, souvent sur une fausse page de connexion qui envoie votre mot de passe au pirate." },
            { "att-macro", "Les macros sont des programmes cachés dans un document Office. N’activez jamais le contenu d’un document reçu par email." },
            { "att-content-", "PhishGuard a regardé à l’intérieur du fichier (sans l’ouvrir) et y a trouvé un élément dangereux." },
            { "att-archive", "Une archive peut cacher un programme. Si elle est protégée par mot de passe, l’antivirus ne peut pas en vérifier le contenu." },
            { "att-image", "Les images disque (ISO, IMG) servent à contourner les protections de Windows pour livrer un logiciel malveillant." },
            { "content-combo-cred", "Le classique du phishing : vous faire peur (compte bloqué, boîte pleine…) pour que vous saisissiez vos identifiants sans réfléchir. Allez sur le site officiel par vos propres moyens." },
            { "content-combo-bec", "Urgence + confidentialité + argent = schéma typique de fraude au virement. Aucune procédure légitime ne vous interdit de vérifier par téléphone." },
            { "content-iban-change", "Fraude au changement de RIB : le pirate se fait passer pour un fournisseur et donne « ses nouvelles coordonnées ». Validez toujours par téléphone avec un numéro déjà connu, jamais celui du message." },
            { "content-iban-foreign", "Un IBAN étranger inattendu est un signal classique de fraude au virement." },
            { "content-freemail-request", "Une banque, une administration ou un fournisseur n’utilise pas une adresse Gmail ou Outlook.com pour demander un paiement ou des identifiants." },
            { "content-first-contact-request", "Un inconnu qui demande d’emblée un paiement, des identifiants ou une action urgente : c’est le scénario type du phishing." },
            { "content-form-password", "Aucun service sérieux ne vous demande votre mot de passe dans le corps d’un email." },
            { "content-qrcode", "Le « quishing » : un QR code vous emmène vers un faux site sur votre téléphone, hors de la protection de votre entreprise." },
            { "content-fake-reply", "Un faux « RE: » donne l’impression d’une conversation existante pour gagner votre confiance." },
            { "links-intel-", "Ce résultat vient d’un service de réputation externe (activé dans l’onglet Réputation des paramètres) : d’autres analystes ou robots ont déjà repéré ce lien ou ce domaine comme dangereux." },
            { "sender-intel-", "Ce résultat vient d’une vérification externe (DNS, réputation) activée dans l’onglet Réputation des paramètres. Un expéditeur légitime a un domaine réel, configuré pour l’email et sans mauvaise réputation." },
            { "att-intel-", "L’empreinte du fichier (pas le fichier lui-même) a été comparée aux bases de logiciels malveillants connus : ce fichier y figure déjà." },
            { "filter-", "Le filtre antispam de votre entreprise ou de votre fournisseur a déjà jugé ce message douteux. Ne l’ignorez pas." },
        };

        /// <summary>Explication pour un indice (null si aucune).</summary>
        public static string For(string id)
        {
            if (string.IsNullOrEmpty(id)) return null;
            string t;
            if (Texts.TryGetValue(id, out t)) return L.T(t);
            string best = null; int bestLen = 0;
            foreach (var kv in Texts)
                if (kv.Key.EndsWith("-") && id.StartsWith(kv.Key) && kv.Key.Length > bestLen) { best = kv.Value; bestLen = kv.Key.Length; }
            return best == null ? null : L.T(best);
        }
    }
}
