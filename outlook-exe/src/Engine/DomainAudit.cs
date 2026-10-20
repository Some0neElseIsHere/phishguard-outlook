// PhishGuard - analyse de votre propre domaine (Paramètres → Entreprise → « Analyser mon domaine ») :
// 1. sécurité de la messagerie : MX, SPF, DKIM, DMARC, BIMI, MTA-STS (DNS de Windows) ;
// 2. identité : mentions légales du site → SIREN → Annuaire des Entreprises (dirigeants) ;
// 3. domaines liés trouvés sur vos certificats HTTPS (crt.sh) ;
// 4. certificats récents contenant votre marque sur d'autres domaines (crt.sh) ;
// 5. sosies déjà enregistrés (variantes de votre domaine vérifiées dans le DNS).
// La surveillance hebdomadaire refait le point 5 (et le 4 si crt.sh est activé) et bloque les sosies apparus depuis.
// Rien d'autre que des noms de domaine ne sort du poste.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace PhishGuard
{
    public class AuditItem
    {
        public string Status;    // ok, warn, bad, info
        public string Title;
        public string Detail = "";
        public AuditItem(string status, string title, string detail) { Status = status; Title = title; Detail = detail ?? ""; }
    }

    public class FoundDomain
    {
        public string Domain = "";
        public string Kind = "";        // lookalike, cert, related
        public string Technique = "";   // pour les sosies : extension, faute de frappe, caractère trompeur, mot ajouté...
        public bool HasMx;
        public bool LikelyOwned;        // même serveur de messagerie que votre domaine
        public int Count;               // domaines liés : nombre de certificats communs
        public DateTime? Seen;          // certificats : date du certificat
    }

    public class DomainReport
    {
        public string Domain = "";
        public List<AuditItem> Email = new List<AuditItem>();
        public List<string> Senders = new List<string>();
        public string Siren = "";
        public string LegalUrl = "";
        public CompanyInfo Company;
        public List<FoundDomain> Lookalikes = new List<FoundDomain>();
        public int VariantsChecked;
        public List<FoundDomain> BrandCerts = new List<FoundDomain>();
        public List<FoundDomain> Related = new List<FoundDomain>();
        public List<string> Errors = new List<string>();
    }

    public static class DomainAudit
    {
        // =================================================================
        // Variantes (sosies possibles)
        // =================================================================

        static readonly string[] Tlds = { "com", "fr", "net", "org", "eu", "info", "biz", "co", "io", "online", "site", "shop", "store", "app", "pro", "group", "cloud", "tech" };
        static readonly string[] Words = { "fr", "france", "group", "groupe", "sas", "pay", "paiement", "facture", "factures", "invoice", "rh", "support",
            "secure", "securite", "login", "connexion", "compte", "mail", "info", "service", "services", "client", "clients", "online", "portail" };
        static readonly string[][] Glyphs = { new[] { "o", "0" }, new[] { "l", "1" }, new[] { "i", "1" }, new[] { "i", "l" }, new[] { "l", "i" }, new[] { "m", "rn" },
            new[] { "rn", "m" }, new[] { "w", "vv" }, new[] { "vv", "w" }, new[] { "d", "cl" }, new[] { "cl", "d" }, new[] { "e", "3" }, new[] { "a", "4" }, new[] { "s", "5" } };

        /// <summary>Variantes plausibles d'un domaine, avec la technique utilisée. Le domaine lui-même est exclu.
        /// Les remplacements « touche voisine du clavier » sont volontairement absents : ils tombent trop souvent sur de vraies entreprises.</summary>
        public static List<KeyValuePair<string, string>> Variants(string domain)
        {
            var list = new List<KeyValuePair<string, string>>();
            var p = Domains.ParseHost(domain);
            if (p == null || p.IsIp || p.Suffix.Length == 0 || p.Label.Length < 3) return list;
            string label = p.Label, suffix = p.Suffix, self = p.Registrable;
            var seen = new HashSet<string> { self };
            Action<string, string, string> add = (lab, suf, tech) =>
            {
                if (lab.Length < 2 || lab.StartsWith("-") || lab.EndsWith("-") || lab.Contains("--")) return;
                string d = lab + "." + suf;
                if (seen.Add(d)) list.Add(new KeyValuePair<string, string>(d, tech));
            };
            string tTld = L.T("autre extension"), tTypo = L.T("faute de frappe"), tGlyph = L.T("caractère trompeur"), tHyphen = L.T("tiret ajouté"), tWord = L.T("mot ajouté");

            foreach (var t in Tlds) if (t != suffix) add(label, t, tTld);
            if (suffix != "com" && suffix != "fr") add(label, "com.fr", tTld);
            for (int i = 0; i < label.Length && label.Length >= 4; i++) add(label.Remove(i, 1), suffix, tTypo);                    // omission
            for (int i = 0; i < label.Length; i++) if (char.IsLetter(label[i])) add(label.Insert(i, label[i].ToString()), suffix, tTypo);   // lettre doublée
            for (int i = 0; i + 1 < label.Length; i++)                                                                              // inversion
                if (label[i] != label[i + 1]) add(label.Substring(0, i) + label[i + 1] + label[i] + label.Substring(i + 2), suffix, tTypo);
            foreach (var g in Glyphs)
                for (int i = label.IndexOf(g[0], StringComparison.Ordinal); i >= 0; i = label.IndexOf(g[0], i + 1, StringComparison.Ordinal))
                    add(label.Substring(0, i) + g[1] + label.Substring(i + g[0].Length), suffix, tGlyph);
            for (int i = 2; i <= label.Length - 2; i++) add(label.Insert(i, "-"), suffix, tHyphen);
            var sufs = suffix == "com" ? new[] { "com", "fr" } : new[] { suffix, "com" };
            foreach (var w in Words)
                foreach (var s in sufs)
                {
                    add(label + "-" + w, s, tWord);
                    add(w + "-" + label, s, tWord);
                    if (s == suffix) add(label + w, s, tWord);
                }
            foreach (var s in new[] { "com", "fr" }) add(label + "-" + suffix.Replace(".", "-"), s, tWord);   // lorema-com.fr
            return list;
        }

        /// <summary>Vérifie dans le DNS quelles variantes sont enregistrées (en parallèle).</summary>
        public static List<FoundDomain> ScanLookalikes(string domain, Action<int, int> progress)
        {
            var variants = Variants(domain);
            var ownMx = new List<string>();
            Intel.Query(Domains.RegistrableDomain(domain), Intel.TypeMx, ownMx);
            var ownMxSet = new HashSet<string>(ownMx.Select(x => x.ToLowerInvariant().TrimEnd('.')));
            string ownLabel = Domains.ParseHost(domain).Label;
            var found = new List<FoundDomain>();
            var sync = new object();
            int done = 0;
            Parallel.ForEach(variants, new ParallelOptions { MaxDegreeOfParallelism = 8 }, v =>
            {
                try
                {
                    var ns = new List<string>();
                    int rc = Intel.Query(v.Key, Intel.TypeNs, ns);
                    if (rc == 0 && ns.Count > 0)
                    {
                        var mx = new List<string>();
                        Intel.Query(v.Key, Intel.TypeMx, mx);
                        var mxSet = mx.Select(x => x.ToLowerInvariant().TrimEnd('.')).ToList();
                        bool owned = mxSet.Any(ownMxSet.Contains)
                            || ns.Any(n => Domains.ParseHost(n) != null && Domains.ParseHost(n).Label == ownLabel);
                        var f = new FoundDomain { Domain = v.Key, Kind = "lookalike", Technique = v.Value, HasMx = mx.Count > 0, LikelyOwned = owned };
                        lock (sync) found.Add(f);
                    }
                }
                catch (Exception) { }
                int n2;
                lock (sync) n2 = ++done;
                if (progress != null && n2 % 10 == 0) progress(n2, variants.Count);
            });
            return found.OrderBy(f => f.LikelyOwned ? 1 : 0).ThenBy(f => f.HasMx ? 0 : 1).ThenBy(f => f.Domain).ToList();
        }

        // =================================================================
        // Sécurité de la messagerie
        // =================================================================

        static readonly string[][] Providers = {
            new[] { "protection.outlook.com", "Microsoft 365" }, new[] { "outlook.com", "Microsoft 365" }, new[] { "_spf.google.com", "Google Workspace" },
            new[] { "google.com", "Google Workspace" }, new[] { "googlemail.com", "Google Workspace" }, new[] { "sendgrid.net", "SendGrid" },
            new[] { "mailgun.org", "Mailgun" }, new[] { "mcsv.net", "Mailchimp" }, new[] { "mandrillapp.com", "Mailchimp Transactional" },
            new[] { "sendinblue.com", "Brevo" }, new[] { "brevo.com", "Brevo" }, new[] { "amazonses.com", "Amazon SES" }, new[] { "salesforce.com", "Salesforce" },
            new[] { "mktomail.com", "Marketo" }, new[] { "hubspotemail.net", "HubSpot" }, new[] { "hubspot", "HubSpot" }, new[] { "zendesk.com", "Zendesk" },
            new[] { "mailjet.com", "Mailjet" }, new[] { "mlsend.com", "MailerLite" }, new[] { "freshdesk.com", "Freshdesk" }, new[] { "docusign", "DocuSign" },
            new[] { "sparkpostmail.com", "SparkPost" }, new[] { "mtasv.net", "Postmark" }, new[] { "pphosted.com", "Proofpoint" }, new[] { "mimecast", "Mimecast" },
            new[] { "messagelabs.com", "Broadcom (MessageLabs)" }, new[] { "barracudanetworks.com", "Barracuda" }, new[] { "ovh", "OVHcloud" },
            new[] { "ionos", "IONOS" }, new[] { "1and1", "IONOS" }, new[] { "gandi.net", "Gandi" }, new[] { "o2switch", "o2switch" }, new[] { "zoho", "Zoho" },
            new[] { "infomaniak", "Infomaniak" }, new[] { "sophos", "Sophos" }, new[] { "vadesecure", "Vade" }, new[] { "altospam", "Altospam" }
        };

        static string ProviderOf(string host)
        {
            string h = (host ?? "").ToLowerInvariant();
            foreach (var p in Providers) if (h.Contains(p[0])) return p[1];
            return null;
        }

        static Dictionary<string, string> Tags(string record)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var part in (record ?? "").Split(';'))
            {
                int i = part.IndexOf('=');
                if (i <= 0) continue;
                string k = part.Substring(0, i).Trim();
                if (!map.ContainsKey(k)) map[k] = part.Substring(i + 1).Trim();
            }
            return map;
        }

        /// <summary>Bilan à partir des enregistrements DNS déjà lus (testable sans réseau).</summary>
        public static List<AuditItem> AuditRecords(string domain, List<string> mx, List<string> txt, List<string> dmarcTxt, List<string> bimiTxt,
            List<string> mtaStsTxt, List<string> tlsRptTxt, List<string> dkimSelectors, List<string> senders)
        {
            var items = new List<AuditItem>();
            var spf = txt.Where(t => t.TrimStart().StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)).ToList();
            var dmarc = dmarcTxt.Where(t => t.TrimStart().StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase)).ToList();

            // ---- DMARC ----
            string policy = "", sp = "", pct = "100", rua = "";
            if (dmarc.Count == 1)
            {
                var t = Tags(dmarc[0]);
                t.TryGetValue("p", out policy); policy = (policy ?? "").ToLowerInvariant();
                t.TryGetValue("sp", out sp); sp = (sp ?? "").ToLowerInvariant();
                string v; if (t.TryGetValue("pct", out v) && v.Length > 0) pct = v;
                t.TryGetValue("rua", out rua); rua = rua ?? "";
            }
            bool strict = (policy == "reject" || policy == "quarantine") && pct == "100";

            // ---- Verdict ----
            if (dmarc.Count == 0)
                items.Add(new AuditItem("bad", L.T("Votre domaine est facile à usurper"), L.T("Sans DMARC, n’importe qui peut envoyer un email « de » votre domaine, et la plupart des messageries le livreront.")));
            else if (!strict)
                items.Add(new AuditItem("warn", L.T("Votre domaine est en partie protégé"), L.T("DMARC est publié mais ne demande pas encore de bloquer les usurpations.")));
            else
                items.Add(new AuditItem("ok", L.T("Votre domaine est difficile à usurper"), L.T("DMARC demande aux messageries de rejeter ou d’isoler les messages qui se font passer pour vous.")));

            // ---- MX ----
            if (mx.Count == 0)
                items.Add(new AuditItem("bad", L.T("Aucun serveur de messagerie (MX)"), L.T("Le domaine ne peut pas recevoir d’emails.")));
            else
            {
                var prov = mx.Select(ProviderOf).Where(x => x != null).Distinct().ToList();
                items.Add(new AuditItem("info", L.T("Messagerie : ") + (prov.Count > 0 ? string.Join(", ", prov.ToArray()) : mx[0]), string.Join(", ", mx.Take(4).ToArray())));
            }

            // ---- SPF ----
            if (spf.Count == 0)
                items.Add(new AuditItem("bad", L.T("Pas d’enregistrement SPF"), L.T("Rien n’indique quels serveurs ont le droit d’envoyer vos emails. Publiez un enregistrement TXT « v=spf1 … -all ».")));
            else if (spf.Count > 1)
                items.Add(new AuditItem("bad", L.T("Plusieurs enregistrements SPF"), L.T("Un domaine ne doit en avoir qu’un : avec plusieurs, SPF est invalide partout. Fusionnez-les.")));
            else
            {
                string rec = spf[0].ToLowerInvariant();
                var terms = rec.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                int lookups = terms.Count(x => Regex.IsMatch(x, @"^[+?~-]?(include:|a\b|a:|a/|mx\b|mx:|mx/|ptr|exists:|redirect=)"));
                string all = terms.FirstOrDefault(x => Regex.IsMatch(x, @"^[+?~-]?all$")) ?? "";
                if (all == "-all") items.Add(new AuditItem("ok", L.T("SPF strict (-all)"), spf[0]));
                else if (all == "~all") items.Add(new AuditItem("ok", L.T("SPF en échec doux (~all)"), L.T("Normal avec un DMARC strict, qui fait le tri.") + " " + spf[0]));
                else if (all == "?all") items.Add(new AuditItem("warn", L.T("SPF neutre (?all)"), L.T("Les serveurs non autorisés ne sont pas signalés. Préférez ~all ou -all.") + " " + spf[0]));
                else if (all == "+all" || all == "all") items.Add(new AuditItem("bad", L.T("SPF autorise le monde entier (+all)"), L.T("N’importe quel serveur est déclaré légitime. Remplacez par -all.") + " " + spf[0]));
                else if (!rec.Contains("redirect=")) items.Add(new AuditItem("warn", L.T("SPF sans règle finale (all)"), spf[0]));
                else items.Add(new AuditItem("ok", L.T("SPF publié (redirection)"), spf[0]));
                if (lookups > 10)
                    items.Add(new AuditItem("bad", L.F("SPF trop long : au moins {0} recherches DNS (limite 10)", lookups), L.T("Au-delà de 10, SPF est en erreur et vos emails peuvent être rejetés.")));
                else if (lookups >= 8)
                    items.Add(new AuditItem("warn", L.F("SPF proche de la limite : au moins {0} recherches DNS sur 10", lookups), L.T("Chaque « include » peut en contenir d’autres : vérifiez avant d’ajouter un service.")));
                foreach (var t in terms.Where(x => x.Contains("include:") || x.Contains("redirect=")))
                {
                    string p = ProviderOf(t);
                    if (p != null && !senders.Contains(p)) senders.Add(p);
                }
            }
            foreach (var m in mx) { string p = ProviderOf(m); if (p != null && !senders.Contains(p) && (p == "Microsoft 365" || p == "Google Workspace")) senders.Insert(0, p); }
            if (senders.Count > 0)
                items.Add(new AuditItem("info", L.T("Services autorisés à envoyer en votre nom : ") + string.Join(", ", senders.ToArray()),
                    L.T("Déclarés dans SPF. Retirez ceux que vous n’utilisez plus : chacun peut envoyer des emails « de » votre domaine.")));

            // ---- DKIM ----
            if (dkimSelectors.Count > 0)
                items.Add(new AuditItem("ok", L.T("Signature DKIM publiée"), L.T("Sélecteurs trouvés : ") + string.Join(", ", dkimSelectors.ToArray())));
            else
                items.Add(new AuditItem("info", L.T("Aucun sélecteur DKIM courant trouvé"), L.T("Il peut exister sous un autre nom : vérifiez dans l’en-tête « DKIM-Signature » (s=) d’un de vos emails.")));

            // ---- DMARC (détail) ----
            if (dmarc.Count > 1)
                items.Add(new AuditItem("bad", L.T("Plusieurs enregistrements DMARC"), L.T("Avec plusieurs enregistrements, DMARC est ignoré. Gardez-en un seul.")));
            else if (dmarc.Count == 0)
                items.Add(new AuditItem("bad", L.T("Pas de DMARC"), L.F("Publiez un TXT sur _dmarc.{0} : « v=DMARC1; p=none; rua=mailto:… », lisez les rapports, puis passez à p=quarantine et p=reject.", domain)));
            else
            {
                if (policy == "reject") items.Add(new AuditItem("ok", L.T("DMARC p=reject : les usurpations sont rejetées"), dmarc[0]));
                else if (policy == "quarantine") items.Add(new AuditItem("ok", L.T("DMARC p=quarantine : les usurpations vont en courrier indésirable"), dmarc[0]));
                else items.Add(new AuditItem("warn", L.T("DMARC en surveillance seulement (p=none)"), L.T("Les usurpations sont signalées mais livrées. Une fois vos services légitimes alignés, passez à p=quarantine puis p=reject.") + " " + dmarc[0]));
                if (pct != "100" && policy != "none")
                    items.Add(new AuditItem("warn", L.F("DMARC appliqué à {0} % des messages seulement", pct), L.T("Le reste des usurpations passe. Montez pct à 100.")));
                if (sp == "none" && policy != "none")
                    items.Add(new AuditItem("warn", L.T("Sous-domaines non protégés (sp=none)"), L.F("Un usurpateur peut envoyer depuis n’importe quel sous-domaine (paiement.{0}…). Retirez sp=none ou mettez sp=reject.", domain)));
                if (rua.Length > 0) items.Add(new AuditItem("ok", L.T("Rapports DMARC reçus"), rua));
                else items.Add(new AuditItem("warn", L.T("Pas de rapports DMARC (rua)"), L.T("Sans rapports, vous ne voyez ni vos services mal configurés ni ceux qui usurpent votre domaine.")));
            }

            // ---- BIMI, MTA-STS ----
            string bimi = Intel.ParseBimi(bimiTxt.FirstOrDefault(t => t.TrimStart().StartsWith("v=BIMI1", StringComparison.OrdinalIgnoreCase)) ?? "");
            if (bimi == "vmc") items.Add(new AuditItem("ok", L.T("BIMI avec certificat : votre logo s’affiche dans les messageries"), ""));
            else if (bimi == "logo") items.Add(new AuditItem("info", L.T("BIMI sans certificat"), L.T("Gmail et Apple n’affichent le logo qu’avec un certificat VMC ou CMC.")));
            else items.Add(new AuditItem("info", L.T("Pas de BIMI (facultatif)"), L.T("Affiche votre logo à côté de vos emails ; nécessite DMARC en quarantine ou reject.")));
            bool sts = mtaStsTxt.Any(t => t.TrimStart().StartsWith("v=STSv1", StringComparison.OrdinalIgnoreCase));
            bool rpt = tlsRptTxt.Any(t => t.TrimStart().StartsWith("v=TLSRPTv1", StringComparison.OrdinalIgnoreCase));
            items.Add(sts ? new AuditItem("ok", L.T("MTA-STS : chiffrement imposé pour les emails reçus"), rpt ? L.T("Rapports TLS activés.") : "")
                          : new AuditItem("info", L.T("Pas de MTA-STS (facultatif)"), L.T("Impose le chiffrement des emails qui vous sont envoyés.")));
            return items;
        }

        static readonly string[] DkimSelectors = { "selector1", "selector2", "google", "default", "dkim", "mail", "k1", "k2", "s1", "s2", "smtp", "mx", "key1", "sig1", "everlytickey1", "mailjet", "mandrill" };

        public static List<AuditItem> AuditEmail(string domain, List<string> senders)
        {
            var mx = new List<string>(); var txt = new List<string>(); var dmarc = new List<string>(); var bimi = new List<string>();
            var sts = new List<string>(); var rpt = new List<string>();
            int rc = Intel.Query(domain, Intel.TypeMx, mx);
            if (rc == Intel.NameError) return new List<AuditItem> { new AuditItem("bad", L.T("Ce domaine n’existe pas dans le DNS"), domain) };
            Intel.Query(domain, Intel.TypeTxt, txt);
            Intel.Query("_dmarc." + domain, Intel.TypeTxt, dmarc);
            Intel.Query("default._bimi." + domain, Intel.TypeTxt, bimi);
            Intel.Query("_mta-sts." + domain, Intel.TypeTxt, sts);
            Intel.Query("_smtp._tls." + domain, Intel.TypeTxt, rpt);
            var found = new List<string>();
            var sync = new object();
            Parallel.ForEach(DkimSelectors, new ParallelOptions { MaxDegreeOfParallelism = 6 }, s =>
            {
                var v = new List<string>();
                Intel.Query(s + "._domainkey." + domain, Intel.TypeTxt, v);
                if (v.Any(x => x.Contains("p=") || x.Contains("k=rsa"))) lock (sync) found.Add(s);
            });
            return AuditRecords(domain, mx, txt, dmarc, bimi, sts, rpt, DkimSelectors.Where(found.Contains).ToList(), senders);
        }

        // =================================================================
        // Mentions légales → SIREN
        // =================================================================

        /// <summary>Clé de Luhn du SIREN (La Poste, 356 000 000, fait exception).</summary>
        public static bool IsValidSiren(string siren)
        {
            if (siren == null || !Regex.IsMatch(siren, @"^\d{9}$")) return false;
            if (siren == "356000000") return true;
            int sum = 0;
            for (int i = 0; i < 9; i++)
            {
                int d = siren[8 - i] - '0';
                if (i % 2 == 1) { d *= 2; if (d > 9) d -= 9; }
                sum += d;
            }
            return sum % 10 == 0;
        }

        static readonly Regex SirenRe = new Regex(
            @"(SIREN|SIRET|R\.?\s?C\.?\s?S\.?|TVA|VAT)[^0-9]{0,60}?((?:FR\s?[0-9A-Z]{2}\s?)?\d{3}[\s .]?\d{3}[\s .]?\d{3}(?:[\s .]?\d{5})?)",
            RegexOptions.IgnoreCase);

        /// <summary>SIREN trouvé dans une page (mentions légales, pied de page), ou "".</summary>
        public static string FindSiren(string html)
        {
            string text = WebUtility.HtmlDecode(Regex.Replace(html ?? "", @"<script[\s\S]{0,200000}?</script>|<style[\s\S]{0,200000}?</style>|<[^>]{1,4000}>", " ", RegexOptions.IgnoreCase));
            foreach (Match m in SirenRe.Matches(text))
            {
                string raw = m.Groups[2].Value;
                bool vat = Regex.IsMatch(raw, @"^FR", RegexOptions.IgnoreCase);
                string digits = Regex.Replace(vat ? raw.Substring(2) : raw, @"\D", "");
                string siren = vat && digits.Length == 11 ? digits.Substring(2) : digits.Length == 14 ? digits.Substring(0, 9) : digits.Length == 9 ? digits : "";
                if (IsValidSiren(siren)) return siren;
            }
            return "";
        }

        /// <summary>Liens vers les mentions légales (ou pages équivalentes) trouvés dans une page.</summary>
        public static List<string> LegalLinks(string html, string baseUrl)
        {
            var list = new List<string>();
            Uri b;
            if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out b)) return list;
            foreach (Match m in Regex.Matches(html ?? "", @"<a\b[^>]{0,2000}?href\s*=\s*[""']([^""'#]{1,2000})[""'][^>]{0,2000}>([\s\S]{0,200}?)</a>", RegexOptions.IgnoreCase))
            {
                string href = WebUtility.HtmlDecode(m.Groups[1].Value.Trim());
                string text = Regex.Replace(m.Groups[2].Value, "<[^>]+>", " ");
                string probe = (href + " " + text).ToLowerInvariant();
                if (!Regex.IsMatch(probe, @"mention|l[ée]gal|legal|imprint|impressum|cgu|cgv|conditions|a-propos|about")) continue;
                Uri u;
                if (!Uri.TryCreate(b, href, out u) || (u.Scheme != "https" && u.Scheme != "http")) continue;
                if (Domains.RegistrableDomain(u.Host) != Domains.RegistrableDomain(b.Host)) continue;
                string s = u.GetLeftPart(UriPartial.Query);
                // les mentions légales d'abord
                if (Regex.IsMatch(probe, @"mention|l[ée]gal|legal|imprint|impressum")) { if (!list.Contains(s)) list.Insert(0, s); }
                else if (!list.Contains(s)) list.Add(s);
            }
            return list;
        }

        static string GetPage(string url)
        {
            return Intel.Http("GET", url, null, null, null, 1500000, "text/html,application/xhtml+xml", 15000);
        }

        /// <summary>Cherche le SIREN sur le site du domaine. Renvoie le SIREN (ou "") et l'adresse de la page.</summary>
        public static string SirenFromWebsite(string domain, out string pageUrl)
        {
            pageUrl = "";
            var tried = new HashSet<string>();
            foreach (var home in new[] { "https://www." + domain + "/", "https://" + domain + "/" })
            {
                string html;
                try { html = GetPage(home); } catch (Exception) { continue; }
                string s = FindSiren(html);
                if (s.Length > 0) { pageUrl = home; return s; }
                var pages = LegalLinks(html, home).Take(4).ToList();
                foreach (var path in new[] { "mentions-legales", "mentions-legales/", "mentions-legales.html", "fr/mentions-legales", "legal" })
                    pages.Add(home + path);
                foreach (var page in pages)
                {
                    if (!tried.Add(page)) continue;
                    try
                    {
                        s = FindSiren(GetPage(page));
                        if (s.Length > 0) { pageUrl = page; return s; }
                    }
                    catch (Exception) { }
                }
                return "";   // le site répond : inutile d'essayer l'autre adresse
            }
            return "";
        }

        // =================================================================
        // Certificats (crt.sh)
        // =================================================================

        class CrtEntry { public List<string> Names = new List<string>(); public DateTime? NotBefore; }

        static List<CrtEntry> ParseCrt(string json)
        {
            var list = new List<CrtEntry>();
            var arr = new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.DeserializeObject(json ?? "") as object[];
            if (arr == null) return list;
            foreach (var o in arr)
            {
                var d = o as Dictionary<string, object>;
                if (d == null) continue;
                var e = new CrtEntry();
                object v;
                if (d.TryGetValue("name_value", out v) && v != null)
                    foreach (var n in v.ToString().Split('\n'))
                    {
                        string h = n.Trim().ToLowerInvariant().TrimStart('*', '.');
                        if (h.Length > 0 && !h.Contains("@") && !e.Names.Contains(h)) e.Names.Add(h);
                    }
                DateTime nb;
                if (d.TryGetValue("not_before", out v) && v != null && DateTime.TryParse(v.ToString(), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out nb))
                    e.NotBefore = nb;
                list.Add(e);
            }
            return list;
        }

        /// <summary>Autres domaines présents sur les certificats de votre domaine (certificats partagés par plus de 5 domaines ignorés).</summary>
        public static List<FoundDomain> ParseRelated(string crtJson, IEnumerable<string> companyOrgs)
        {
            var own = new HashSet<string>(companyOrgs.Select(Domains.RegistrableDomain));
            var counts = new Dictionary<string, int>();
            foreach (var e in ParseCrt(crtJson))
            {
                var orgs = e.Names.Select(Domains.RegistrableDomain).Where(x => x.Length > 0 && x.Contains(".")).Distinct().ToList();
                if (orgs.Count > 5 || !orgs.Any(own.Contains)) continue;
                foreach (var o in orgs.Where(x => !own.Contains(x)))
                {
                    int c; counts.TryGetValue(o, out c); counts[o] = c + 1;
                }
            }
            return counts.OrderByDescending(kv => kv.Value).Take(30)
                .Select(kv => new FoundDomain { Domain = kv.Key, Kind = "related", Count = kv.Value }).ToList();
        }

        /// <summary>La marque apparaît comme un mot dans l'un des labels (lorema-paiement.com, lorema.secure-login.net), pas au milieu d'un autre mot.</summary>
        public static bool BrandInHost(string host, string brand)
        {
            if (string.IsNullOrEmpty(brand) || brand.Length < 4) return false;
            foreach (var label in (host ?? "").ToLowerInvariant().Split('.'))
            {
                if (label == brand || label.StartsWith(brand) || label.EndsWith("-" + brand) || label.Contains("-" + brand + "-")) return true;
            }
            return false;
        }

        /// <summary>Certificats récents dont un nom contient la marque, sur un domaine qui n'est pas le vôtre.</summary>
        public static List<FoundDomain> ParseBrandCerts(string crtJson, string brand, IEnumerable<string> companyOrgs, DateTime since)
        {
            var own = new HashSet<string>(companyOrgs.Select(Domains.RegistrableDomain));
            var map = new Dictionary<string, FoundDomain>();
            foreach (var e in ParseCrt(crtJson))
            {
                if (!e.NotBefore.HasValue || e.NotBefore.Value < since) continue;
                foreach (var h in e.Names)
                {
                    string org = Domains.RegistrableDomain(h);
                    if (org.Length == 0 || own.Contains(org) || !BrandInHost(h, brand)) continue;
                    FoundDomain f;
                    if (!map.TryGetValue(org, out f)) map[org] = new FoundDomain { Domain = org, Kind = "cert", Technique = h, Seen = e.NotBefore };
                    else if (e.NotBefore > f.Seen) f.Seen = e.NotBefore;
                }
            }
            return map.Values.OrderByDescending(f => f.Seen).Take(50).ToList();
        }

        static string Crt(string query, int timeoutMs)
        {
            return Intel.Http("GET", "https://crt.sh/?output=json&exclude=expired&q=" + Uri.EscapeDataString(query), null, null, null, 30000000, null, timeoutMs);
        }

        public static List<FoundDomain> BrandCertsOnline(string brand, IEnumerable<string> companyOrgs, DateTime since)
        {
            return ParseBrandCerts(Crt("%" + brand + "%", 120000), brand, companyOrgs, since);
        }

        // =================================================================
        // Analyse complète (bouton « Analyser mon domaine »)
        // =================================================================

        public static DomainReport Run(string domain, IEnumerable<string> companyDomains, Action<string> progress)
        {
            string d = Domains.RegistrableDomain((domain ?? "").Trim().ToLowerInvariant().TrimStart('@'));
            var r = new DomainReport { Domain = d };
            var orgs = new List<string> { d };
            foreach (var c in companyDomains ?? new string[0]) { string o = Domains.RegistrableDomain(c); if (o.Length > 0 && !orgs.Contains(o)) orgs.Add(o); }
            Action<string> step = s => { if (progress != null) progress(s); };

            step(L.T("Sécurité de la messagerie (DNS)…"));
            try { r.Email = AuditEmail(d, r.Senders); } catch (Exception ex) { r.Errors.Add("DNS : " + ex.Message); }

            step(L.T("Mentions légales du site…"));
            try
            {
                string page;
                r.Siren = SirenFromWebsite(d, out page);
                r.LegalUrl = page;
                if (r.Siren.Length > 0)
                {
                    step(L.T("Annuaire des Entreprises…"));
                    r.Company = CompanyLookup.Search(r.Siren).FirstOrDefault(c => c.Siren == r.Siren);
                }
            }
            catch (Exception ex) { r.Errors.Add(L.T("Site web : ") + ex.Message); }

            step(L.T("Domaines liés (certificats, crt.sh)…"));
            try { r.Related = ParseRelated(Crt(d, 60000), orgs); } catch (Exception ex) { r.Errors.Add("crt.sh : " + ex.Message); }

            string brand = Domains.ParseHost(d).Label;
            if (brand.Length >= 5)
            {
                step(L.F("Certificats récents contenant « {0} » (crt.sh, peut prendre une minute)…", brand));
                try { r.BrandCerts = BrandCertsOnline(brand, orgs, DateTime.UtcNow.AddDays(-90)); }
                catch (Exception ex) { r.Errors.Add(L.T("crt.sh (marque) : ") + ex.Message); }
            }

            int total = Variants(d).Count;
            r.VariantsChecked = total;
            step(L.F("Sosies enregistrés : vérification de {0} variantes…", total));
            try { r.Lookalikes = ScanLookalikes(d, (n, t) => step(L.F("Sosies enregistrés : {0}/{1}…", n, t))); }
            catch (Exception ex) { r.Errors.Add(L.T("Sosies : ") + ex.Message); }
            var lookSet = new HashSet<string>(r.Lookalikes.Select(x => x.Domain));
            r.BrandCerts = r.BrandCerts.Where(x => !lookSet.Contains(x.Domain)).ToList();
            return r;
        }

        /// <summary>Rapport texte (bouton « Copier le rapport »).</summary>
        public static string FormatReport(DomainReport r)
        {
            var sb = new StringBuilder();
            sb.AppendLine(L.F("=== PhishGuard - analyse du domaine {0} ({1}) ===", r.Domain, DateTime.Now.ToString("dd/MM/yyyy HH:mm")));
            sb.AppendLine();
            sb.AppendLine(L.T("--- Sécurité de la messagerie ---"));
            foreach (var i in r.Email) sb.AppendLine("[" + Mark(i.Status) + "] " + i.Title + (i.Detail.Length > 0 ? " - " + i.Detail : ""));
            sb.AppendLine();
            sb.AppendLine(L.T("--- Entreprise ---"));
            if (r.Company != null) sb.AppendLine(r.Company.Name + " (SIREN " + r.Company.Siren + ", " + r.Company.City + ") : " + string.Join(", ", r.Company.Roles.ToArray()));
            else if (r.Siren.Length > 0) sb.AppendLine("SIREN " + r.Siren);
            else sb.AppendLine(L.T("SIREN introuvable sur le site."));
            sb.AppendLine();
            sb.AppendLine(L.F("--- Sosies enregistrés ({0} sur {1} variantes) ---", r.Lookalikes.Count, r.VariantsChecked));
            foreach (var f in r.Lookalikes) sb.AppendLine("- " + f.Domain + " (" + f.Technique + (f.HasMx ? ", MX" : "") + (f.LikelyOwned ? ", " + L.T("probablement à vous") : "") + ")");
            if (r.BrandCerts.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine(L.T("--- Certificats récents contenant votre marque ---"));
                foreach (var f in r.BrandCerts) sb.AppendLine("- " + f.Technique + (f.Seen.HasValue ? " (" + f.Seen.Value.ToString("dd/MM/yyyy") + ")" : ""));
            }
            if (r.Related.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine(L.T("--- Domaines présents sur vos certificats ---"));
                foreach (var f in r.Related) sb.AppendLine("- " + f.Domain);
            }
            foreach (var e in r.Errors) sb.AppendLine("! " + e);
            return sb.ToString();
        }

        static string Mark(string status)
        {
            return status == "ok" ? "OK" : status == "warn" ? L.T("À AMÉLIORER") : status == "bad" ? L.T("PROBLÈME") : "INFO";
        }

        // =================================================================
        // Surveillance hebdomadaire
        // =================================================================

        public class WatchEntry { public string Domain; public string Status; public DateTime Date; public string Detail = ""; }
        // Status : baseline (déjà là lors du premier point, non bloqué), owned (à vous), new / cert (apparu depuis : bloqué), ignored

        public static string WatchPath { get { return Path.Combine(Blocklists.DataDir, "surveillance.txt"); } }
        public static DateTime LastWatch = DateTime.MinValue;
        public static int LastNew;
        public static string LastWatchError = "";

        public static Dictionary<string, WatchEntry> LoadWatch()
        {
            var map = new Dictionary<string, WatchEntry>();
            try
            {
                if (!File.Exists(WatchPath)) return map;
                foreach (var line in File.ReadAllLines(WatchPath, Encoding.UTF8))
                {
                    if (line.StartsWith("#")) continue;
                    var p = line.Split('\t');
                    if (p.Length < 3) continue;
                    DateTime dt;
                    DateTime.TryParseExact(p[2], "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out dt);
                    map[p[0]] = new WatchEntry { Domain = p[0], Status = p[1], Date = dt, Detail = p.Length > 3 ? p[3] : "" };
                }
            }
            catch (Exception) { }
            return map;
        }

        public static void SaveWatch(Dictionary<string, WatchEntry> map)
        {
            var lines = new List<string> { "# PhishGuard - surveillance de vos domaines : domaine, état (baseline, owned, new, cert, ignored), date, détail" };
            lines.AddRange(map.Values.OrderBy(x => x.Domain).Select(x => x.Domain + "\t" + x.Status + "\t" + x.Date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + "\t" + (x.Detail ?? "").Replace("\t", " ")));
            Directory.CreateDirectory(Blocklists.DataDir);
            File.WriteAllLines(WatchPath, lines.ToArray(), new UTF8Encoding(false));
        }

        /// <summary>Enregistre le résultat d'une analyse manuelle comme point de départ de la surveillance.</summary>
        public static void RecordBaseline(string domain, IEnumerable<FoundDomain> lookalikes)
        {
            var map = LoadWatch();
            string org = Domains.RegistrableDomain(domain);
            if (org.Length > 0 && !map.ContainsKey("*:" + org)) map["*:" + org] = new WatchEntry { Domain = "*:" + org, Status = "check", Date = DateTime.Today };
            foreach (var f in lookalikes)
                if (!map.ContainsKey(f.Domain))
                    map[f.Domain] = new WatchEntry { Domain = f.Domain, Status = f.LikelyOwned ? "owned" : "baseline", Date = DateTime.Today, Detail = f.Technique };
            SaveWatch(map);
        }

        /// <summary>Vrai si la dernière vérification date de plus de 7 jours.</summary>
        public static bool WatchDue()
        {
            var map = LoadWatch();
            WatchEntry last;
            return !map.TryGetValue("*", out last) || last.Date < DateTime.Today.AddDays(-7);
        }

        /// <summary>
        /// Point hebdomadaire : les sosies (et, si demandé, les certificats contenant la marque) apparus depuis la dernière
        /// vérification sont bloqués (liste « surveillance »). Le premier passage sert de référence et ne bloque rien.
        /// isKnown : domaines à ne jamais bloquer (correspondants, partenaires, sites très fréquentés).
        /// </summary>
        public static List<string> WeeklyCheck(IEnumerable<string> companyDomains, bool brandCerts, Func<string, bool> isKnown)
        {
            var orgs = companyDomains.Select(Domains.RegistrableDomain).Where(x => x.Length > 0).Distinct().Take(3).ToList();
            var map = LoadWatch();
            var added = new List<string>();
            foreach (var org in orgs)
            {
                // Premier passage pour ce domaine (sosies) ou pour la recherche de certificats : simple point de référence
                bool first = !map.ContainsKey("*:" + org);
                bool firstCrt = !map.ContainsKey("*crt:" + org);
                map["*:" + org] = new WatchEntry { Domain = "*:" + org, Status = "check", Date = DateTime.Today };
                foreach (var f in ScanLookalikes(org, null))
                {
                    if (map.ContainsKey(f.Domain) || orgs.Contains(f.Domain)) continue;
                    string status = f.LikelyOwned ? "owned" : first || isKnown(f.Domain) ? "baseline" : "new";
                    map[f.Domain] = new WatchEntry { Domain = f.Domain, Status = status, Date = DateTime.Today, Detail = L.F("sosie de {0} ({1})", org, f.Technique) };
                    if (status == "new") added.Add(f.Domain);
                }
                string brand = Domains.ParseHost(org).Label;
                if (brandCerts && brand.Length >= 5)
                {
                    try
                    {
                        foreach (var f in BrandCertsOnline(brand, orgs, DateTime.UtcNow.AddDays(-10)))
                        {
                            if (map.ContainsKey(f.Domain) || isKnown(f.Domain)) continue;
                            map[f.Domain] = new WatchEntry { Domain = f.Domain, Status = firstCrt ? "baseline" : "cert", Date = DateTime.Today, Detail = L.F("certificat {0}", f.Technique) };
                            if (!firstCrt) added.Add(f.Domain);
                        }
                        map["*crt:" + org] = new WatchEntry { Domain = "*crt:" + org, Status = "check", Date = DateTime.Today };
                    }
                    catch (Exception ex) { LastWatchError = "crt.sh : " + ex.Message; }
                }
            }
            map["*"] = new WatchEntry { Domain = "*", Status = "check", Date = DateTime.Today, Detail = added.Count.ToString(CultureInfo.InvariantCulture) };
            SaveWatch(map);
            LastWatch = DateTime.Now;
            LastNew = added.Count;
            return added;
        }

        /// <summary>Domaines bloqués par la surveillance (sosies et certificats apparus depuis la référence).</summary>
        public static HashSet<string> WatchedBlocked()
        {
            return new HashSet<string>(LoadWatch().Values.Where(x => x.Status == "new" || x.Status == "cert").Select(x => x.Domain));
        }
    }
}
