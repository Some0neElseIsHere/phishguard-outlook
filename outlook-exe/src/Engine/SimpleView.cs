// PhishGuard - mode simple de la fenêtre d'analyse (par défaut) : pour les utilisateurs non spécialistes.
// Le verdict en clair, les raisons principales en langage courant et « Que dois-je faire ? ».
// Même règles de sécurité que le mode expert : tout texte du message est encodé, aucune ressource externe.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;

namespace PhishGuard
{
    public static class SimpleView
    {
        static string H(string s) { return WebUtility.HtmlEncode(s ?? ""); }

        const string Css =
            "*{box-sizing:border-box}" +
            "body{font:14px/1.55 'Segoe UI',Arial,sans-serif;color:#17202b;background:#f3f5f8;margin:0}" +
            ".page{max-width:760px;margin:0 auto;padding:20px 18px 24px}" +
            ".hero{background:#fff;border:1px solid #e3e7ed;border-radius:14px;padding:20px 22px;overflow:hidden;border-top-width:6px}" +
            ".hero.dangerous{border-top-color:#c4262e;background:#fff8f8}.hero.suspicious{border-top-color:#c26a00;background:#fffaf3}.hero.safe{border-top-color:#13804a;background:#f6fbf8}" +
            ".ico{float:left;width:56px;height:56px;border-radius:50%;color:#fff;font-size:30px;font-weight:700;text-align:center;line-height:56px;margin-right:16px}" +
            ".dangerous .ico{background:#c4262e}.suspicious .ico{background:#c26a00}.safe .ico{background:#13804a}" +
            ".hv{overflow:hidden}h1{font-size:23px;margin:2px 0 2px;line-height:1.25}" +
            ".dangerous h1{color:#b01f27}.suspicious h1{color:#9a5200}.safe h1{color:#106b3d}" +
            ".sub{color:#2b3542;margin:0}.from{margin-top:10px;color:#5f6b7a;font-size:12.5px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}" +
            "h2{font-size:16px;margin:22px 0 8px}" +
            ".card{background:#fff;border:1px solid #e3e7ed;border-radius:12px;padding:6px 18px}" +
            ".why{padding:10px 0;border-top:1px solid #eef1f5}.why:first-child{border-top:0}" +
            ".dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:8px;vertical-align:1px}" +
            ".Critical{background:#a1141c}.High{background:#d13438}.Medium{background:#d47b00}.Low{background:#8a95a3}" +
            ".wt{font-weight:600}.wd{color:#4a5563;font-size:13px;margin:2px 0 0 18px}" +
            ".more{color:#5f6b7a;font-size:12.5px;padding:8px 0 10px;border-top:1px solid #eef1f5}" +
            ".todo{background:#fff;border:1px solid #e3e7ed;border-radius:12px;padding:8px 18px;counter-reset:n}" +
            ".step{padding:9px 0 9px 38px;position:relative;border-top:1px solid #eef1f5}.step:first-child{border-top:0}" +
            ".step:before{counter-increment:n;content:counter(n);position:absolute;left:0;top:8px;width:26px;height:26px;border-radius:50%;background:#0f6cbd;color:#fff;font-weight:700;text-align:center;line-height:26px;font-size:13px}" +
            ".step.key{font-weight:600}" +
            ".help{margin-top:22px;font-size:13px}.help a{color:#0f6cbd;text-decoration:none;font-weight:600}" +
            "#tips{display:none;margin-top:8px}.tip{padding:6px 0 6px 22px;position:relative;color:#2b3542}" +
            ".tip:before{content:'\\2022';position:absolute;left:6px;color:#0f6cbd;font-weight:700}" +
            ".foot{color:#8a95a3;font-size:12px;margin-top:18px}";

        const string Script =
            "function tips(){var t=document.getElementById('tips');t.style.display=(t.style.display=='block')?'none':'block';return false;}";

        /// <summary>Titre sans jargon technique (SPF, DKIM, DMARC…) pour le mode simple.</summary>
        public static string PlainTitle(Finding f)
        {
            switch (f.Id)
            {
                case "auth-dmarc": return L.T("L’expéditeur n’est pas celui qu’il prétend être : son adresse est usurpée");
                case "auth-compauth": case "auth-compauth-intra": return L.T("Microsoft n’a pas pu confirmer l’identité de l’expéditeur");
                case "auth-spf": case "auth-spf-soft": return L.T("Le message vient d’un serveur que l’expéditeur n’a pas autorisé");
                case "auth-dkim": return L.T("La signature du message est invalide : il a pu être falsifié");
                case "auth-missing": return L.T("L’identité de l’expéditeur ne peut pas être vérifiée");
            }
            return f.Title;
        }

        /// <summary>Que faire, selon le verdict et la nature des indices.</summary>
        public static List<KeyValuePair<string, bool>> Actions(AnalysisResult r)
        {
            var steps = new List<KeyValuePair<string, bool>>();   // texte, étape clé (en gras)
            var ids = new HashSet<string>(r.Findings.Where(f => f.Severity >= Severity.Low).Select(f => f.Id));
            bool money = ids.Any(i => i.StartsWith("content-iban") || i == "sender-thread-hijack" || i == "sender-vip" || i == "content-financial" || i == "content-combo-bec" || i == "content-first-contact-request");
            bool creds = ids.Any(i => i == "content-credentials" || i == "content-combo-cred" || i == "content-form" || i == "content-form-password");
            bool atts = r.Attachments.Count > 0;

            if (r.Level == "dangerous")
            {
                steps.Add(new KeyValuePair<string, bool>(L.T("Ne cliquez sur aucun lien et n’ouvrez aucune pièce jointe."), true));
                if (money) steps.Add(new KeyValuePair<string, bool>(L.T("Ne faites aucun paiement et ne modifiez aucune coordonnée bancaire demandés dans ce message."), true));
                steps.Add(new KeyValuePair<string, bool>(L.T("Ne répondez pas et ne transférez pas ce message à vos collègues."), false));
                steps.Add(new KeyValuePair<string, bool>(L.T("Cliquez sur « Signaler à la sécurité » : l’équipe sécurité est prévenue et le message quitte votre boîte de réception."), false));
                steps.Add(new KeyValuePair<string, bool>(L.T("Si vous avez déjà cliqué, ouvert une pièce jointe ou saisi un mot de passe : prévenez tout de suite le service informatique."), false));
            }
            else if (r.Level == "suspicious")
            {
                steps.Add(new KeyValuePair<string, bool>(L.T("Ne cliquez pas tout de suite et ne saisissez aucun mot de passe."), true));
                if (atts) steps.Add(new KeyValuePair<string, bool>(L.T("N’ouvrez pas les pièces jointes avant d’avoir vérifié."), false));
                steps.Add(new KeyValuePair<string, bool>(L.T("Vérifiez auprès de l’expéditeur par un autre moyen : appelez-le avec un numéro que vous connaissez déjà, pas celui du message."), true));
                if (money) steps.Add(new KeyValuePair<string, bool>(L.T("Un changement de coordonnées bancaires ou un paiement urgent se confirme toujours par téléphone avant d’agir."), false));
                steps.Add(new KeyValuePair<string, bool>(L.T("En cas de doute, cliquez sur « Signaler à la sécurité »."), false));
            }
            else
            {
                steps.Add(new KeyValuePair<string, bool>(L.T("Vous pouvez traiter ce message normalement."), false));
                steps.Add(new KeyValuePair<string, bool>(L.T("Restez attentif à toute demande inhabituelle : paiement urgent, mot de passe, changement de coordonnées bancaires."), false));
            }
            if (creds && r.Level != "safe")
                steps.Insert(1, new KeyValuePair<string, bool>(L.T("Ne saisissez jamais votre mot de passe depuis un lien reçu par email : passez par l’adresse habituelle du site."), false));
            return steps;
        }

        public static string Build(AnalysisResult r, EmailData e, bool showExplanations)
        {
            var sb = new StringBuilder();
            sb.Append("<!DOCTYPE html><html><head><meta charset='utf-8'><meta http-equiv='X-UA-Compatible' content='IE=edge'>");
            sb.Append("<style>" + Css + "</style><script>" + Script + "</script></head><body><div class='page'>");

            // ---- Verdict ----
            string title, sub, icon;
            if (r.Level == "dangerous") { title = L.T("Ce message est dangereux"); sub = L.T("Il présente des signes clairs de tentative d’arnaque."); icon = "&#10007;"; }
            else if (r.Level == "suspicious") { title = L.T("Ce message est suspect"); sub = L.T("Certains éléments sont inhabituels : vérifiez avant d’agir."); icon = "!"; }
            else if (r.Verified) { title = L.T("Expéditeur vérifié"); sub = L.T("Son identité est confirmée et vous avez déjà échangé avec lui."); icon = "&#10003;"; }
            else { title = L.T("Aucun danger détecté"); sub = L.T("PhishGuard n’a rien trouvé d’inquiétant dans ce message."); icon = "&#10003;"; }
            sb.Append("<div class='hero " + H(r.Level) + "'><div class='ico'>" + icon + "</div><div class='hv'><h1>" + H(title) + "</h1><p class='sub'>" + H(sub) + "</p>");
            sb.Append("<div class='from'>" + H(L.T("De : ")) + "<b>" + H(string.IsNullOrEmpty(e.FromName) ? e.FromAddress : e.FromName) + "</b> &lt;" + H(e.FromAddress) + "&gt; &middot; "
                + H(string.IsNullOrEmpty(e.Subject) ? L.T("(sans objet)") : e.Subject) + "</div>");
            sb.Append("</div></div>");

            // ---- Pourquoi ----
            var doubts = r.Findings.Where(f => f.Severity >= Severity.Low).OrderByDescending(f => (int)f.Severity).ToList();
            if (doubts.Count > 0)
            {
                sb.Append("<h2>" + H(L.T("Pourquoi ?")) + "</h2><div class='card'>");
                foreach (var f in doubts.Take(4))
                {
                    sb.Append("<div class='why'><span class='dot " + f.Severity + "'></span><span class='wt'>" + H(PlainTitle(f)) + "</span>");
                    // Les explications d'authentification sont techniques : le titre simplifié suffit
                    string lesson = showExplanations && f.Category != "auth" ? Lessons.For(f.Id) : "";
                    if (!string.IsNullOrEmpty(lesson)) sb.Append("<div class='wd'>" + H(lesson) + "</div>");
                    sb.Append("</div>");
                }
                if (doubts.Count > 4)
                    sb.Append("<div class='more'>" + H(L.F("… et {0} autre(s) élément(s), visibles dans l’analyse détaillée.", doubts.Count - 4)) + "</div>");
                sb.Append("</div>");
            }

            // ---- Que dois-je faire ----
            sb.Append("<h2>" + H(L.T("Que dois-je faire ?")) + "</h2><div class='todo'>");
            foreach (var s in Actions(r))
                sb.Append("<div class='step" + (s.Value ? " key" : "") + "'>" + H(s.Key) + "</div>");
            sb.Append("</div>");

            // ---- Conseils ----
            sb.Append("<div class='help'><a href='#' onclick='return tips()'>" + H(L.T("Comment reconnaître un phishing ?")) + "</a><div id='tips'>");
            foreach (var t in new[] {
                L.T("Regardez l’adresse de l’expéditeur, pas seulement son nom : « Microsoft » peut écrire depuis n’importe quelle adresse."),
                L.T("Survolez un lien sans cliquer : sa vraie adresse s’affiche en bas de l’écran."),
                L.T("Méfiez-vous de l’urgence (« dernier rappel », « compte suspendu ») : elle sert à vous empêcher de réfléchir."),
                L.T("Aucun service sérieux ne vous demande par email votre mot de passe ou un code reçu par SMS."),
                L.T("Un changement de RIB ou un paiement inhabituel se vérifie toujours par téléphone, avec un numéro connu."),
                L.T("Une pièce jointe inattendue (facture, colis, document partagé) peut contenir un programme : ne l’ouvrez pas sans vérifier.") })
                sb.Append("<div class='tip'>" + H(t) + "</div>");
            sb.Append("</div></div>");
            sb.Append("<div class='foot'>" + H(L.T("Pour le détail technique (en-têtes, liens, pièces jointes), cliquez sur « Analyse détaillée » en bas de la fenêtre.")) + "</div>");
            sb.Append("</div></body></html>");
            return sb.ToString();
        }
    }
}
