// PhishGuard - SPF, DMARC et DKIM publiés par chaque domaine du message (onglet Réputation de l'analyse détaillée).
// Lu dans le DNS du poste, en arrière-plan et seulement à la demande (ouverture de l'onglet) ; gardé en mémoire pour
// la session. Seuls des noms de domaine sont demandés au DNS, comme pour une navigation ordinaire.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace PhishGuard
{
    /// <summary>Un contrôle (SPF, DMARC ou DKIM) : état (ok, mid, bad, na), résumé lisible, enregistrement publié.</summary>
    public class MailAuthCheck
    {
        public string State = "na";
        public string Summary = "";
        public string Record = "";
        public MailAuthCheck(string state, string summary, string record) { State = state; Summary = summary ?? ""; Record = record ?? ""; }
    }

    public class MailAuthInfo
    {
        public MailAuthCheck Spf, Dmarc, Dkim;
        public string Error = "";
    }

    public static class DomainMail
    {
        public static volatile int Version;
        /// <summary>Domaines de l'entreprise : lus si besoin sur un DNS public (DNS interne « split-horizon »).</summary>
        public static HashSet<string> CompanyDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        static readonly object Sync = new object();
        static readonly Dictionary<string, MailAuthInfo> cache = new Dictionary<string, MailAuthInfo>(StringComparer.OrdinalIgnoreCase);
        static readonly HashSet<string> pending = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Sélecteurs DKIM les plus courants, essayés quand le message ne dit pas lequel est utilisé
        static readonly string[] CommonSelectors = { "selector1", "selector2", "google", "default", "dkim", "k1", "s1", "s2", "mail", "key1", "everlytickey1", "mailjet", "brevo1", "zoho" };

        public static MailAuthInfo Get(string domain)
        {
            lock (Sync) { MailAuthInfo i; return cache.TryGetValue(domain ?? "", out i) ? i : null; }
        }

        /// <summary>Pour les tests et les captures d'écran.</summary>
        public static void SetForTests(string domain, MailAuthInfo info)
        {
            lock (Sync) { cache[domain] = info; pending.Remove(domain); }
            Version++;
        }

        public static bool IsPending(string domain)
        {
            lock (Sync) return pending.Contains(domain ?? "");
        }

        /// <summary>
        /// Lance la lecture en arrière-plan des domaines pas encore connus. selectors : sélecteurs DKIM vus dans le message
        /// pour un domaine.
        /// Renvoie le nombre de domaines à lire.
        /// </summary>
        public static int Fetch(IEnumerable<string> domains, Func<string, List<KeyValuePair<string, string>>> selectors)
        {
            var todo = new List<string>();
            lock (Sync)
                foreach (var d in domains ?? Enumerable.Empty<string>())
                    if (!string.IsNullOrEmpty(d) && !cache.ContainsKey(d) && pending.Add(d)) todo.Add(d);
            if (todo.Count == 0) return 0;
            new Thread(() =>
            {
                Parallel.ForEach(todo, new ParallelOptions { MaxDegreeOfParallelism = 3 }, d =>
                {
                    MailAuthInfo info;
                    try
                    {
                        string server = CompanyDomains.Contains(d) ? DomainAudit.PublicResolver(d) : "";
                        info = Lookup(d, selectors != null ? selectors(d) : null, server);
                    }
                    catch (Exception ex) { info = new MailAuthInfo { Error = ex.Message }; }
                    lock (Sync) { cache[d] = info; pending.Remove(d); }
                    Version++;
                });
            }) { IsBackground = true, Name = "PhishGuard SPF DMARC DKIM" }.Start();
            return todo.Count;
        }

        /// <summary>Lecture DNS d'un domaine (bloquante). signatures : (sélecteur, domaine signataire d=) vus dans le message.</summary>
        public static MailAuthInfo Lookup(string domain, List<KeyValuePair<string, string>> signatures, string server)
        {
            var txt = new List<string>(); var dmarc = new List<string>();
            int rc = Intel.Query(domain, Intel.TypeTxt, txt, server);
            if (rc == Intel.NameError) return new MailAuthInfo { Error = L.T("le domaine n’existe pas dans le DNS") };
            Intel.Query("_dmarc." + domain, Intel.TypeTxt, dmarc, server);
            var info = new MailAuthInfo { Spf = EvalSpf(txt), Dmarc = EvalDmarc(dmarc) };

            // DKIM : d'abord les sélecteurs annoncés par les signatures du message, sinon les plus courants
            var fromMessage = (signatures ?? new List<KeyValuePair<string, string>>())
                .Where(s => Regex.IsMatch(s.Key, @"^[A-Za-z0-9._-]{1,63}$") && Regex.IsMatch(s.Value, @"^[A-Za-z0-9.-]{1,253}$")).Distinct().ToList();
            var probe = new List<string>();
            Intel.Query("pg" + Guid.NewGuid().ToString("N").Substring(0, 10) + "._domainkey." + domain, Intel.TypeTxt, probe, server);
            var wildcard = new HashSet<string>(probe);   // DNS « joker » : une réponse identique au témoin ne compte pas
            var found = new List<KeyValuePair<string, string>>();
            var sync = new object();
            var tried = fromMessage.Count > 0 ? fromMessage : CommonSelectors.Select(s => new KeyValuePair<string, string>(s, domain)).ToList();
            Parallel.ForEach(tried, new ParallelOptions { MaxDegreeOfParallelism = 6 }, s =>
            {
                var v = new List<string>();
                Intel.Query(s.Key + "._domainkey." + s.Value, Intel.TypeTxt, v, server);
                string rec = v.FirstOrDefault(x => DomainAudit.IsDkimRecord(x) && !wildcard.Contains(x));
                string name = s.Value.Equals(domain, StringComparison.OrdinalIgnoreCase) ? s.Key : s.Key + " (" + s.Value + ")";
                if (rec != null) lock (sync) found.Add(new KeyValuePair<string, string>(name, rec));
            });
            info.Dkim = EvalDkim(found, fromMessage.Count > 0);
            return info;
        }

        /// <summary>SPF : un seul enregistrement « v=spf1 », dont la fin (« -all », « ~all »…) dit quoi faire des autres serveurs.</summary>
        public static MailAuthCheck EvalSpf(List<string> txt)
        {
            var spf = (txt ?? new List<string>()).Where(t => Regex.IsMatch(t ?? "", @"^\s*v=spf1(\s|$)", RegexOptions.IgnoreCase)).ToList();
            if (spf.Count == 0) return new MailAuthCheck("bad", L.T("absent : n’importe quel serveur peut envoyer au nom du domaine"), "");
            if (spf.Count > 1) return new MailAuthCheck("bad", L.T("plusieurs enregistrements : invalide"), string.Join(" | ", spf.ToArray()));
            string r = spf[0].Trim();
            var all = Regex.Match(r, @"(^|\s)([+?~-]?)all(\s|$)", RegexOptions.IgnoreCase);
            bool redirect = Regex.IsMatch(r, @"(^|\s)redirect=", RegexOptions.IgnoreCase);
            if (!all.Success) return redirect ? new MailAuthCheck("ok", L.T("renvoie vers la règle d’un autre domaine"), r)
                                              : new MailAuthCheck("mid", L.T("sans règle finale (« all ») : les autres serveurs sont tolérés"), r);
            switch (all.Groups[2].Value)
            {
                case "-": return new MailAuthCheck("ok", L.T("strict (-all) : les autres serveurs sont refusés"), r);
                case "~": return new MailAuthCheck("mid", L.T("souple (~all) : les autres serveurs sont seulement signalés"), r);
                case "?": return new MailAuthCheck("bad", L.T("neutre (?all) : ne protège pas"), r);
                default: return new MailAuthCheck("bad", L.T("ouvert (+all) : tout serveur est autorisé"), r);
            }
        }

        /// <summary>DMARC : la politique p= dit quoi faire d'un message qui échoue (rien, indésirable, rejet).</summary>
        public static MailAuthCheck EvalDmarc(List<string> txt)
        {
            var rec = (txt ?? new List<string>()).Where(t => Regex.IsMatch(t ?? "", @"^\s*v=DMARC1\s*(;|$)", RegexOptions.IgnoreCase)).ToList();
            if (rec.Count == 0) return new MailAuthCheck("bad", L.T("absent : aucune consigne contre l’usurpation du domaine"), "");
            if (rec.Count > 1) return new MailAuthCheck("bad", L.T("plusieurs enregistrements : invalide"), string.Join(" | ", rec.ToArray()));
            string r = rec[0].Trim();
            string p = Tag(r, "p").ToLowerInvariant();
            int pct = 100;
            int.TryParse(Tag(r, "pct"), out pct);
            if (Tag(r, "pct").Length == 0) pct = 100;
            string part = pct < 100 ? " " + L.F("(sur {0} % des messages seulement)", pct) : "";
            if (p == "reject") return new MailAuthCheck(pct < 100 ? "mid" : "ok", L.T("rejet (p=reject) : les messages usurpés sont refusés") + part, r);
            if (p == "quarantine") return new MailAuthCheck(pct < 100 ? "mid" : "ok", L.T("quarantaine (p=quarantine) : les messages usurpés vont en indésirables") + part, r);
            if (p == "none") return new MailAuthCheck("mid", L.T("surveillance seule (p=none) : les messages usurpés sont livrés"), r);
            return new MailAuthCheck("bad", L.T("politique absente ou invalide"), r);
        }

        /// <summary>DKIM : clé publique trouvée pour un sélecteur (et sa taille), révoquée, ou introuvable.</summary>
        public static MailAuthCheck EvalDkim(List<KeyValuePair<string, string>> found, bool fromMessage)
        {
            if (found == null || found.Count == 0)
                return fromMessage ? new MailAuthCheck("bad", L.T("introuvable : pas de clé pour le sélecteur de la signature"), "")
                                   : new MailAuthCheck("na", L.T("inconnu : aucun sélecteur courant ne répond (il peut exister sous un autre nom)"), "");
            var parts = new List<string>();
            string worst = "ok";
            foreach (var f in found.OrderBy(x => x.Key))
            {
                int bits = Intel.DkimKeyBits(f.Value);
                bool revoked = Regex.IsMatch(f.Value, @"(^|;)\s*p=\s*(;|$)");
                bool ed = Regex.IsMatch(f.Value, @"(^|;)\s*k=\s*ed25519", RegexOptions.IgnoreCase);
                string who = DomainAudit.SelectorProvider(f.Key.Split(' ')[0]);
                string state = revoked ? "bad" : ed || bits >= 2048 ? "ok" : bits >= 1024 ? "mid" : bits > 0 ? "bad" : "ok";
                if (state == "bad" || (state == "mid" && worst == "ok")) worst = state;
                parts.Add(f.Key + (who != null ? " (" + who + ")" : "") + " : "
                    + (revoked ? L.T("clé révoquée") : ed ? "Ed25519" : bits > 0 ? L.F("{0} bits", bits) : L.T("clé publiée")));
            }
            return new MailAuthCheck(worst, string.Join(" · ", parts.ToArray()), found.Count == 1 ? found[0].Value : "");
        }

        static string Tag(string record, string name)
        {
            var m = Regex.Match(record ?? "", @"(^|;)\s*" + Regex.Escape(name) + @"\s*=\s*([^;]*)", RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[2].Value.Trim() : "";
        }

        /// <summary>Sélecteurs DKIM des signatures du message, par domaine signataire (d=) ramené à son domaine enregistrable.</summary>
        public static Dictionary<string, List<KeyValuePair<string, string>>> SignatureSelectors(string rawHeaders)
        {
            var res = new Dictionary<string, List<KeyValuePair<string, string>>>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in Analyzer.ParseHeaders(rawHeaders ?? ""))
            {
                if (kv.Key != "dkim-signature") continue;
                var d = Regex.Match(kv.Value, @"(^|;)\s*d\s*=\s*([^;\s]+)", RegexOptions.IgnoreCase);
                var s = Regex.Match(kv.Value, @"(^|;)\s*s\s*=\s*([^;\s]+)", RegexOptions.IgnoreCase);
                if (!d.Success || !s.Success) continue;
                string signer = d.Groups[2].Value.Trim().TrimEnd('.').ToLowerInvariant();
                string reg = Domains.RegistrableDomain(signer);
                if (string.IsNullOrEmpty(reg)) continue;
                List<KeyValuePair<string, string>> list;
                if (!res.TryGetValue(reg, out list)) res[reg] = list = new List<KeyValuePair<string, string>>();
                var pair = new KeyValuePair<string, string>(s.Groups[2].Value.Trim(), signer);   // interrogé sous le domaine exact de la signature
                if (!list.Contains(pair)) list.Add(pair);
            }
            return res;
        }
    }
}
