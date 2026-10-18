// PhishGuard - noms de domaine : domaine enregistrable, punycode, homoglyphes,
// distance d'édition et détection des domaines qui imitent un domaine légitime.
// Portage fidèle de src/engine/domains.js (C# 5).

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace PhishGuard
{
    public class HostParts
    {
        public string Host;
        public string Registrable;
        public string Label;
        public string Suffix;
        public string Subdomain;
        public bool IsIp;
    }

    public class DomainTarget
    {
        public string Label;
        public string Brand;
        public string Domain;
        public bool IsCompany;
        public bool Generic;
        public bool Keyword;
    }

    public class DomainContext
    {
        public HashSet<string> Legit = new HashSet<string>();
        public List<DomainTarget> Targets = new List<DomainTarget>();
        public HashSet<string> CompanyDomains = new HashSet<string>();
    }

    public class Lookalike
    {
        public string Technique;
        public string TechniqueText;
        public string Brand;
        public string Target;
        public bool IsCompany;
        public Severity Severity;
        public string Host;
        public string UnicodeHost;
    }

    public static class Domains
    {
        /// <summary>Nom du serveur d'une adresse, en minuscules, sans lever d'exception : une adresse piégée peut être
        /// acceptée par Uri.TryCreate puis faire échouer la lecture de Host (nom de serveur invalide).</summary>
        public static string HostOf(Uri u)
        {
            if (u == null) return "";
            string h = null;
            try { h = u.IdnHost; }
            catch (Exception) { try { h = u.Host; } catch (Exception) { h = ""; } }
            return (h ?? "").ToLowerInvariant().Trim('[', ']');
        }

        static readonly Regex Ipv4 = new Regex(@"^\d{1,3}(\.\d{1,3}){3}$");

        public static bool IsIpHost(string host)
        {
            string h = (host ?? "").Trim('[', ']');
            return Ipv4.IsMatch(h) || h.Contains(":") || Regex.IsMatch(h, @"^\d+$") || Regex.IsMatch(h, @"^0x[0-9a-f]+$", RegexOptions.IgnoreCase);
        }

        /// <summary>login.microsoft.com.evil.co.uk → registrable "evil.co.uk", label "evil", sous-domaine "login.microsoft.com".</summary>
        public static HostParts ParseHost(string host)
        {
            string h = (host ?? "").Trim().ToLowerInvariant().TrimEnd('.');
            if (h.Length == 0) return null;
            if (IsIpHost(h)) return new HostParts { Host = h, Registrable = h, Label = h, Suffix = "", Subdomain = "", IsIp = true };
            var labels = new List<string>();
            foreach (var l in h.Split('.')) if (l.Length > 0) labels.Add(l);
            if (labels.Count == 0) return null;
            if (labels.Count == 1) return new HostParts { Host = h, Registrable = h, Label = h, Suffix = "", Subdomain = "", IsIp = false };

            int suffixLen = 1;
            for (int n = Math.Min(4, labels.Count - 1); n >= 2; n--)
            {
                if (Lists.MultiLabelSuffixes.Contains(string.Join(".", labels.GetRange(labels.Count - n, n)))) { suffixLen = n; break; }
            }
            if (labels.Count <= suffixLen) suffixLen = labels.Count - 1;
            int regCount = suffixLen + 1;
            var reg = labels.GetRange(labels.Count - regCount, regCount);
            return new HostParts
            {
                Host = h,
                Registrable = string.Join(".", reg),
                Label = reg[0],
                Suffix = string.Join(".", labels.GetRange(labels.Count - suffixLen, suffixLen)),
                Subdomain = string.Join(".", labels.GetRange(0, labels.Count - regCount)),
                IsIp = false
            };
        }

        public static string RegistrableDomain(string host)
        {
            var p = ParseHost(host);
            return p == null ? "" : p.Registrable;
        }

        public static string DomainOfAddress(string address)
        {
            string a = (address ?? "").Trim().ToLowerInvariant();
            int at = a.LastIndexOf('@');
            return at >= 0 ? a.Substring(at + 1).TrimEnd('>', ' ') : "";
        }

        /// <summary>Convertit les labels "xn--" en Unicode.</summary>
        public static string ToUnicode(string host)
        {
            if (string.IsNullOrEmpty(host) || host.IndexOf("xn--", StringComparison.OrdinalIgnoreCase) < 0) return host ?? "";
            var idn = new IdnMapping();
            var parts = host.Split('.');
            for (int i = 0; i < parts.Length; i++)
            {
                if (!parts[i].StartsWith("xn--", StringComparison.OrdinalIgnoreCase)) continue;
                try { parts[i] = idn.GetUnicode(parts[i]); } catch (Exception) { }
            }
            return string.Join(".", parts);
        }

        public static string ToAscii(string host)
        {
            if (string.IsNullOrEmpty(host) || !HasNonAscii(host)) return host ?? "";
            try { return new IdnMapping().GetAscii(host); } catch (Exception) { return host; }
        }

        public static bool HasNonAscii(string s)
        {
            foreach (char c in s ?? "") if (c > 127) return true;
            return false;
        }

        // ---------------------------------------------------------------
        // "Squelette" visuel
        // ---------------------------------------------------------------

        static readonly Dictionary<char, char> Confusables = BuildConfusables();

        static Dictionary<char, char> BuildConfusables()
        {
            var d = new Dictionary<char, char>();
            // Cyrillique
            string from = "авеёкмнорстухѕіїјԁӏɡһԛԝүոսօ";
            string to   = "abeekmhopctyxsiijdlghqwynuo";
            for (int i = 0; i < from.Length; i++) d[from[i]] = to[i];
            // Grec
            from = "αβεικνορτυχωγ";
            to   = "abeikvoptuxwy";
            for (int i = 0; i < from.Length; i++) d[from[i]] = to[i];
            // Divers
            from = "ıłƚɩⅼℓｍⅿß";
            to   = "illillmmb";
            for (int i = 0; i < from.Length; i++) d[from[i]] = to[i];
            // Chiffres et symboles
            from = "013457 89!|".Replace(" ", "");
            to   = "oleastbgll";
            for (int i = 0; i < from.Length; i++) d[from[i]] = to[i];
            return d;
        }

        public static string RemoveDiacritics(string s)
        {
            string n = (s ?? "").Normalize(NormalizationForm.FormD);
            var sb = new StringBuilder(n.Length);
            foreach (char c in n)
                if (CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark) sb.Append(c);
            return sb.ToString().Normalize(NormalizationForm.FormC);
        }

        public static string Skeleton(string s)
        {
            var sb = new StringBuilder();
            foreach (char c in (s ?? "").ToLowerInvariant())
            {
                char m;
                sb.Append(Confusables.TryGetValue(c, out m) ? m : c);
            }
            string o = RemoveDiacritics(sb.ToString());
            o = o.Replace("-", "").Replace("_", "").Replace(".", "");
            return o.Replace("rn", "m").Replace("vv", "w").Replace("cl", "d").Replace("i", "l");
        }

        /// <summary>Distance de Damerau-Levenshtein (substitution, insertion, suppression, inversion).</summary>
        public static int EditDistance(string a, string b)
        {
            a = a ?? ""; b = b ?? "";
            int m = a.Length, n = b.Length;
            if (Math.Abs(m - n) > 3) return Math.Abs(m - n);
            var d = new int[m + 1, n + 1];
            for (int i = 0; i <= m; i++) d[i, 0] = i;
            for (int j = 0; j <= n; j++) d[0, j] = j;
            for (int i = 1; i <= m; i++)
            {
                for (int j = 1; j <= n; j++)
                {
                    int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                    d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
                    if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1])
                        d[i, j] = Math.Min(d[i, j], d[i - 2, j - 2] + 1);
                }
            }
            return d[m, n];
        }

        // ---------------------------------------------------------------
        // Contexte : marques + domaines de l'entreprise + domaines de confiance
        // ---------------------------------------------------------------

        public static DomainContext BuildContext(PhishGuardConfig config)
        {
            var ctx = new DomainContext();
            var seen = new HashSet<string>();
            Action<string, string, string, bool, bool, bool> add = (label, brand, domain, isCompany, generic, keyword) =>
            {
                string key = label + "|" + brand;
                if (string.IsNullOrEmpty(label) || seen.Contains(key)) return;
                seen.Add(key);
                ctx.Targets.Add(new DomainTarget { Label = label, Brand = brand, Domain = domain, IsCompany = isCompany, Generic = generic, Keyword = keyword });
            };

            foreach (var d in config.CompanyDomains)
            {
                var p = ParseHost(d);
                if (p == null) continue;
                ctx.Legit.Add(p.Registrable);
                ctx.CompanyDomains.Add(p.Registrable);
                add(p.Label, string.IsNullOrEmpty(config.CompanyName) ? p.Registrable : config.CompanyName, p.Registrable, true, false, false);
            }
            foreach (var b in Lists.Brands)
            {
                foreach (var d in b.Domains)
                {
                    var p = ParseHost(d);
                    ctx.Legit.Add(p.Registrable);
                    add(p.Label, b.Name, p.Registrable, false, b.Generic, false);
                }
                foreach (var k in b.Keywords) add(k, b.Name, b.Domains[0], false, b.Generic, true);
            }
            foreach (var d in config.TrustedDomains)
            {
                var p = ParseHost(d);
                if (p != null) ctx.Legit.Add(p.Registrable);
            }
            return ctx;
        }

        static readonly HashSet<string> GenericLabels = new HashSet<string>(new[] {
            "office", "live", "windows", "azure", "bing", "skype", "force", "apple", "orange",
            "free", "zoom", "meta", "me", "mac", "g", "fb", "we", "aka", "cloud", "msn", "okta", "engie" });

        static readonly HashSet<string> AffixWords = new HashSet<string>(new[] {
            "login", "logon", "signin", "sign", "in", "secure", "security", "securite", "support", "help",
            "helpdesk", "verify", "verification", "verif", "account", "accounts", "acct", "update", "service", "services",
            "online", "auth", "sso", "mail", "email", "web", "webmail", "portal", "portail", "id", "alert", "alerte", "billing",
            "pay", "payment", "paiement", "cloud", "team", "teams", "check", "confirm", "client", "clients", "customer", "connect",
            "connexion", "access", "acces", "center", "centre", "app", "apps", "doc", "docs", "document", "share", "file", "files",
            "drive", "info", "infos", "notice", "notification", "france", "fr", "official", "officiel", "recover", "recovery",
            "reset", "unlock", "member", "user", "my", "mon", "ma", "espace", "compte", "assistance", "aide", "remboursement",
            "refund", "livraison", "delivery", "colis", "parcel", "tracking", "suivi", "store", "shop", "prime", "office", "admin",
            "it", "hr", "rh", "net", "live", "the", "and", "of", "en", "ligne", "particulier", "pro", "banque", "bank",
            "gouv", "gov", "impot", "impots", "amende", "dossier", "session", "safe", "safety", "protect", "protection", "sync",
            "storage", "quota", "box", "invoice", "facture", "paye", "rib", "iban", "card", "carte", "wallet", "cash", "gift" });

        static bool IsAffixChain(string s)
        {
            if (string.IsNullOrEmpty(s)) return true;
            var ok = new bool[s.Length + 1];
            ok[0] = true;
            for (int i = 1; i <= s.Length; i++)
                for (int j = Math.Max(0, i - 14); j < i && !ok[i]; j++)
                    if (ok[j] && AffixWords.Contains(s.Substring(j, i - j))) ok[i] = true;
            return ok[s.Length];
        }

        static bool ContainsToken(string label, string kw)
        {
            string k = kw.Replace("-", "");
            if (Regex.IsMatch(label, "(^|[-0-9])" + kw.Replace("-", "-?") + "($|[-0-9])")) return true;
            if (k.Length < 5) return false;
            string l = label.Replace("-", "");
            int idx = l.IndexOf(k, StringComparison.Ordinal);
            if (idx < 0) return false;
            string rest = l.Substring(0, idx) + "-" + l.Substring(idx + k.Length);
            foreach (var part in Regex.Split(rest, "[-0-9]+"))
                if (!IsAffixChain(part)) return false;
            return true;
        }

        static string TechniqueText(string t)
        {
            switch (t)
            {
                case "tld": return L.T("même nom avec une autre extension");
                case "homoglyph": return L.T("caractères visuellement identiques (homoglyphes)");
                case "unicode": return L.T("caractères étrangers (Unicode) imitant des lettres latines");
                case "typo": return L.T("faute de frappe volontaire (typosquatting)");
                case "combo": return L.T("nom de marque combiné à d’autres mots");
                case "subdomain": return L.T("nom de marque placé dans un sous-domaine");
            }
            return t;
        }

        /// <summary>
        /// Le domaine "host" imite-t-il le domaine d'un correspondant connu ("knownRegistrable") ?
        /// Renvoie la technique (homoglyph, unicode, typo, tld) ou null.
        /// </summary>
        public static string LookalikeOfKnown(string host, string knownRegistrable)
        {
            var p = ParseHost(host);
            var k = ParseHost(knownRegistrable);
            if (p == null || k == null || p.IsIp || k.IsIp) return null;
            if (p.Registrable == k.Registrable) return null;
            string label = p.Label.StartsWith("xn--") ? ToUnicode(p.Registrable).Split('.')[0] : p.Label;
            string kl = k.Label;
            if (kl.Length < 4) return null;
            bool unicode = HasNonAscii(label);
            if (label == kl) return kl.Length >= 5 ? "tld" : null;          // fournisseur.com au lieu de fournisseur.fr
            if (Skeleton(label) == Skeleton(kl)) return unicode ? "unicode" : "homoglyph";
            if (kl.Length >= 5 && !label.StartsWith(kl) && !label.EndsWith(kl))
            {
                int max = kl.Length >= 8 ? 2 : 1;
                if (EditDistance(label, kl) <= max) return "typo";
            }
            return null;
        }

        public static string TechniqueLabel(string t) { return TechniqueText(t); }

        /// <summary>Cherche si un nom d'hôte imite un domaine protégé. Renvoie null sinon.</summary>
        public static Lookalike DetectLookalike(string host, DomainContext ctx)
        {
            var p = ParseHost(host);
            if (p == null || p.IsIp) return null;
            if (ctx.Legit.Contains(p.Registrable)) return null;

            string uniLabel = ToUnicode(p.Registrable).Split('.')[0];
            string label = p.Label.StartsWith("xn--") ? uniLabel : p.Label;
            bool isUnicode = HasNonAscii(uniLabel);
            string skelLabel = Skeleton(label);

            bool extendsOtherTarget = false;
            foreach (var t in ctx.Targets)
                if (t.Label.Length >= 5 && label != t.Label && (label.StartsWith(t.Label) || label.EndsWith(t.Label))) { extendsOtherTarget = true; break; }

            Lookalike best = null;
            Action<string, DomainTarget, Severity> consider = (technique, t, severity) =>
            {
                Severity sev = t.IsCompany ? (severity == Severity.Medium ? Severity.High : Severity.Critical) : severity;
                if (best == null || sev > best.Severity)
                {
                    best = new Lookalike { Technique = technique, TechniqueText = TechniqueText(technique), Brand = t.Brand, Target = t.Domain, IsCompany = t.IsCompany, Severity = sev, Host = p.Host, UnicodeHost = ToUnicode(p.Host) };
                }
            };

            foreach (var t in ctx.Targets)
            {
                string tl = t.Label;
                if (GenericLabels.Contains(tl) && !t.IsCompany)
                {
                    if (label != tl && skelLabel == Skeleton(tl)) consider(isUnicode ? "unicode" : "homoglyph", t, Severity.High);
                    continue;
                }
                if (label == tl)
                {
                    if (!t.Keyword) consider("tld", t, Severity.Medium);
                    continue;
                }
                if (skelLabel == Skeleton(tl))
                {
                    consider(isUnicode ? "unicode" : "homoglyph", t, Severity.High);
                    continue;
                }
                bool isExtension = label.StartsWith(tl) || label.EndsWith(tl) || extendsOtherTarget;
                if (tl.Length >= 5 && !t.Keyword && !isExtension)
                {
                    int dist = EditDistance(label, tl);
                    int max = tl.Length >= 8 ? 2 : 1;
                    if (dist <= max || (tl.Length >= 6 && EditDistance(skelLabel, Skeleton(tl)) <= 1))
                    {
                        consider("typo", t, tl.Length >= 7 ? Severity.High : Severity.Medium);
                        continue;
                    }
                }
                if (!t.Generic && tl.Length >= 3 && ContainsToken(label, tl))
                    consider("combo", t, Severity.Medium);
            }

            if (!string.IsNullOrEmpty(p.Subdomain))
            {
                string sub = p.Subdomain;
                var subParts = new HashSet<string>(sub.Split('.', '-'));
                foreach (var t in ctx.Targets)
                {
                    if (t.Generic || t.Label.Length < 4) continue;
                    string full = t.Domain;
                    if (sub == full || sub.EndsWith("." + full) || sub.Contains(full + ".") || sub.EndsWith(full))
                        consider("subdomain", t, Severity.High);
                    else if (!GenericLabels.Contains(t.Label) && subParts.Contains(t.Label))
                        consider("subdomain", t, Severity.Medium);
                }
            }

            if (best == null && isUnicode)
            {
                best = new Lookalike { Technique = "unicode", TechniqueText = L.T("nom de domaine contenant des caractères non latins"), Brand = null, Target = null, IsCompany = false, Severity = Severity.Medium, Host = p.Host, UnicodeHost = ToUnicode(p.Host) };
            }
            return best;
        }
    }
}
