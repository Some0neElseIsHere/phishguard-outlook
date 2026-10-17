// PhishGuard - données d'enquête (comme PhishTool) : en-têtes, parcours du message,
// IP d'origine, détail SPF/DKIM/DMARC, type réel et empreintes des pièces jointes,
// liens de vérification vers des services publics (VirusTotal, AbuseIPDB...).

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace PhishGuard
{
    public class ReceivedHop
    {
        public int Number;              // 1 = premier serveur (le plus ancien)
        public string FromHost = "";
        public string FromDetail = "";  // nom inverse / HELO entre parenthèses
        public string FromIp = "";
        public string ByHost = "";
        public string With = "";
        public string RawDate = "";
        public DateTimeOffset? Date;
        public TimeSpan? Delay;         // délai depuis le saut précédent
        public string Raw = "";
    }

    public class AuthDetails
    {
        public string Spf, SpfMailFrom, SpfIp;
        public string Dkim, DkimDomain, DkimSelector;
        public string Dmarc, DmarcAction, DmarcFrom;
        public string CompAuth, CompAuthReason;
        public string Source;           // en-tête d'où viennent les résultats
    }

    public class HeaderDetails
    {
        public List<KeyValuePair<string, string>> Fields = new List<KeyValuePair<string, string>>();
        public List<ReceivedHop> Hops = new List<ReceivedHop>();
        public string OriginIp = "";
        public string OriginHost = "";
        public string OriginSource = "";
        public string Country = "";     // CTRY du rapport anti-spam Microsoft, si présent
        public string Scl = "";         // Spam Confidence Level (Exchange)
        public string Bcl = "";         // Bulk Complaint Level
        public TimeSpan? TotalTransit;
        public AuthDetails Auth = new AuthDetails();
        public List<KeyValuePair<string, string>> All = new List<KeyValuePair<string, string>>();
        public List<KeyValuePair<string, string>> FilterHeaders = new List<KeyValuePair<string, string>>(); // passerelles antispam
    }

    public static class Forensics
    {
        // -----------------------------------------------------------------
        // En-têtes
        // -----------------------------------------------------------------

        static readonly string[][] DisplayFields =
        {
            new[] { "from", "De" }, new[] { "sender", "Expéditeur technique" }, new[] { "reply-to", "Répondre à" },
            new[] { "return-path", "Return-Path" }, new[] { "to", "À" }, new[] { "cc", "Cc" },
            new[] { "date", "Date" }, new[] { "subject", "Objet" }, new[] { "message-id", "Message-ID" },
            new[] { "in-reply-to", "En réponse à" }, new[] { "x-mailer", "Logiciel d’envoi (X-Mailer)" },
            new[] { "user-agent", "Logiciel d’envoi (User-Agent)" }, new[] { "x-originating-ip", "X-Originating-IP" },
            new[] { "list-unsubscribe", "Désabonnement" }, new[] { "content-type", "Content-Type" }
        };

        static string First(List<KeyValuePair<string, string>> h, string name)
        {
            foreach (var kv in h) if (kv.Key == name) return kv.Value;
            return null;
        }

        static string Pick(string pattern, string s)
        {
            var m = Regex.Match(s ?? "", pattern, RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value : null;
        }

        public static HeaderDetails ParseHeaders(string raw)
        {
            var d = new HeaderDetails();
            var h = Analyzer.ParseHeaders(raw);
            d.All = h;
            if (h.Count == 0) return d;

            foreach (var f in DisplayFields)
            {
                foreach (var kv in h)
                    if (kv.Key == f[0]) d.Fields.Add(new KeyValuePair<string, string>(L.T(f[1]), DecodeMimeWords(kv.Value)));
            }

            // Parcours : les en-têtes Received sont du plus récent au plus ancien → on inverse
            var received = h.Where(kv => kv.Key == "received").Select(kv => kv.Value).ToList();
            received.Reverse();
            int n = 0;
            ReceivedHop prev = null;
            foreach (var r in received)
            {
                var hop = ParseReceived(r);
                hop.Number = ++n;
                if (prev != null && prev.Date.HasValue && hop.Date.HasValue) hop.Delay = hop.Date.Value - prev.Date.Value;
                d.Hops.Add(hop);
                prev = hop;
            }
            var dated = d.Hops.Where(x => x.Date.HasValue).ToList();
            if (dated.Count >= 2) d.TotalTransit = dated[dated.Count - 1].Date.Value - dated[0].Date.Value;

            // IP d'origine : X-Originating-IP (webmails), sinon la première IP publique du parcours
            string xoip = First(h, "x-originating-ip");
            string ip = xoip != null ? Pick(@"([0-9a-f:.]{3,})", xoip.Trim('[', ']', ' ')) : null;
            if (!string.IsNullOrEmpty(ip) && IsPublicIp(ip)) { d.OriginIp = ip; d.OriginSource = "X-Originating-IP"; }
            else
            {
                foreach (var hop in d.Hops)
                {
                    if (hop.FromIp.Length > 0 && IsPublicIp(hop.FromIp))
                    {
                        d.OriginIp = hop.FromIp;
                        d.OriginHost = hop.FromDetail.Length > 0 ? hop.FromDetail : hop.FromHost;
                        d.OriginSource = L.T("saut n°") + hop.Number + L.T(" du parcours");
                        break;
                    }
                }
            }

            // Rapports anti-spam Microsoft (présents si le message est passé par Exchange Online Protection)
            string fore = First(h, "x-forefront-antispam-report") ?? "";
            d.Country = Pick(@"\bCTRY:([A-Z]{2})", fore) ?? "";
            if (d.OriginIp.Length == 0)
            {
                string cip = Pick(@"\bCIP:([0-9a-f:.]+)", fore);
                if (!string.IsNullOrEmpty(cip)) { d.OriginIp = cip; d.OriginSource = L.T("rapport anti-spam Microsoft (CIP)"); }
            }
            d.Scl = First(h, "x-ms-exchange-organization-scl") ?? Pick(@"\bSCL:(-?\d)", fore) ?? "";
            d.Bcl = Pick(@"\bBCL:(\d)", First(h, "x-microsoft-antispam") ?? "") ?? "";

            // En-têtes ajoutés par les filtres de messagerie (Exchange, FortiMail, Orange, SpamAssassin...)
            foreach (var kv in h)
            {
                if (!FilterHeaderRe.IsMatch(kv.Key)) continue;
                string v = kv.Value.Length > 300 ? kv.Value.Substring(0, 300) + "…" : kv.Value;
                d.FilterHeaders.Add(new KeyValuePair<string, string>(kv.Key, v));
            }

            // Authentification : Authentication-Results (+ ARC du même serveur), sinon toute valeur contenant spf=/dkim=/dmarc=
            var a = d.Auth;
            string arSource;
            string ar = AuthResultsText(h, out arSource);
            if (ar.Length == 0) ar = null;
            a.Source = arSource;
            if (ar == null)
            {
                foreach (var kv in h)
                    if (Regex.IsMatch(kv.Value, @"\b(spf|dkim|dmarc)=\w", RegexOptions.IgnoreCase)) { ar = kv.Value; a.Source = kv.Key; break; }
            }
            ar = ar ?? "";
            a.Spf = Pick(@"\bspf=([a-z]+)", ar);
            a.SpfMailFrom = Pick(@"smtp\.mailfrom=([^\s;]+)", ar);
            a.SpfIp = Pick(@"sender IP is ([0-9a-f:.]+)", ar) ?? Pick(@"client-ip=([0-9a-f:.]+)", First(h, "received-spf") ?? "");
            a.Dkim = Pick(@"\bdkim=([a-z]+)", ar);
            a.DkimDomain = Pick(@"header\.d=([^\s;]+)", ar);
            a.DkimSelector = Pick(@"header\.s=([^\s;]+)", ar);
            string dkimSig = First(h, "dkim-signature") ?? "";
            if (string.IsNullOrEmpty(a.DkimDomain)) a.DkimDomain = Pick(@"\bd=([^\s;]+)", dkimSig);
            if (string.IsNullOrEmpty(a.DkimSelector)) a.DkimSelector = Pick(@"\bs=([^\s;]+)", dkimSig);
            a.Dmarc = Pick(@"\bdmarc=([a-z]+)", ar);
            a.DmarcAction = Pick(@"\baction=([a-z]+)", ar);
            a.DmarcFrom = Pick(@"header\.from=([^\s;]+)", ar);
            a.CompAuth = Pick(@"\bcompauth=([a-z]+)", ar);
            a.CompAuthReason = Pick(@"\breason=(\d+)", ar);
            if (a.Spf == null)
            {
                string rspf = First(h, "received-spf");
                if (rspf != null) { a.Spf = Pick(@"^\s*([a-z]+)", rspf); if (a.Source.Length == 0) a.Source = "Received-SPF"; }
            }
            return d;
        }

        static readonly Regex FromRe = new Regex(@"^\s*from\s+(\S+)(?:\s+\(([^)]*)\))?", RegexOptions.IgnoreCase);
        static readonly Regex IpRe = new Regex(@"\[(?:IPv6:)?([0-9a-fA-F:.]{3,})\]");
        static readonly Regex Ipv4Re = new Regex(@"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b");
        static readonly Regex ByRe = new Regex(@"\bby\s+(\S+)", RegexOptions.IgnoreCase);
        static readonly Regex WithRe = new Regex(@"\bwith\s+(\S+)", RegexOptions.IgnoreCase);

        public static ReceivedHop ParseReceived(string value)
        {
            var hop = new ReceivedHop { Raw = value ?? "" };
            string v = hop.Raw;
            int semi = v.LastIndexOf(';');
            string main = semi >= 0 ? v.Substring(0, semi) : v;
            if (semi >= 0) { hop.RawDate = v.Substring(semi + 1).Trim(); hop.Date = ParseDate(hop.RawDate); }

            int byIdx = Regex.Match(main, @"\bby\s", RegexOptions.IgnoreCase).Index;
            string fromPart = byIdx > 0 ? main.Substring(0, byIdx) : main;
            var fm = FromRe.Match(fromPart);
            if (fm.Success) { hop.FromHost = fm.Groups[1].Value; hop.FromDetail = fm.Groups[2].Success ? fm.Groups[2].Value.Trim() : ""; }
            var im = IpRe.Match(fromPart);
            if (im.Success) hop.FromIp = im.Groups[1].Value;
            else { var m4 = Ipv4Re.Match(fromPart); if (m4.Success) hop.FromIp = m4.Groups[1].Value; }
            // Le nom entre parenthèses contient souvent "nom.inverse [IP]" : on ne garde que le nom
            hop.FromDetail = Regex.Replace(hop.FromDetail, @"\s*\[[^\]]*\]", "").Trim();
            var bm = ByRe.Match(main);
            if (bm.Success) hop.ByHost = bm.Groups[1].Value;
            var wm = WithRe.Match(main);
            if (wm.Success) hop.With = wm.Groups[1].Value;
            return hop;
        }

        public static DateTimeOffset? ParseDate(string s)
        {
            if (string.IsNullOrEmpty(s)) return null;
            string t = Regex.Replace(s, @"\([^)]*\)", "").Trim();
            t = Regex.Replace(t, @"\s+", " ");
            t = Regex.Replace(t, @"([+-]\d{2})(\d{2})$", "$1:$2");
            t = Regex.Replace(t, @"\s(GMT|UT|UTC|Z)$", " +00:00");
            string[] formats = {
                "ddd, d MMM yyyy H:mm:ss zzz", "ddd, d MMM yyyy H:mm:ss.fffffff zzz", "d MMM yyyy H:mm:ss zzz",
                "ddd, d MMM yyyy H:mm zzz", "ddd, dd MMM yyyy HH:mm:ss zzz" };
            DateTimeOffset dto;
            if (DateTimeOffset.TryParseExact(t, formats, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out dto)) return dto;
            if (DateTimeOffset.TryParse(t, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out dto)) return dto;
            return null;
        }

        public static bool IsPublicIp(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return false;
            System.Net.IPAddress addr;
            if (!System.Net.IPAddress.TryParse(ip, out addr)) return false;
            var b = addr.GetAddressBytes();
            if (b.Length == 4)
            {
                if (b[0] == 10 || b[0] == 127 || b[0] == 0) return false;
                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
                if (b[0] == 192 && b[1] == 168) return false;
                if (b[0] == 169 && b[1] == 254) return false;
                if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;
                return true;
            }
            if (System.Net.IPAddress.IsLoopback(addr) || addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal) return false;
            if ((b[0] & 0xFE) == 0xFC) return false; // fc00::/7
            return true;
        }

        public static string FormatDelay(TimeSpan? t)
        {
            if (!t.HasValue) return "";
            var v = t.Value;
            string sign = v < TimeSpan.Zero ? "-" : "";
            v = v.Duration();
            if (v.TotalSeconds < 60) return sign + (int)v.TotalSeconds + " s";
            if (v.TotalMinutes < 60) return sign + (int)v.TotalMinutes + " min " + v.Seconds + " s";
            if (v.TotalHours < 48) return sign + (int)v.TotalHours + " h " + v.Minutes + " min";
            return sign + (int)v.TotalDays + L.T(" j ") + v.Hours + " h";
        }

        // -----------------------------------------------------------------
        // Pièces jointes : type réel (signature binaire) et empreintes
        // -----------------------------------------------------------------

        public static string DetectMagic(byte[] d)
        {
            if (d == null || d.Length < 4) return "";
            if (d[0] == 0x4D && d[1] == 0x5A) return "exe";
            if (d[0] == 0x50 && d[1] == 0x4B && (d[2] == 3 || d[2] == 5 || d[2] == 7)) return "zip";
            if (d[0] == 0x25 && d[1] == 0x50 && d[2] == 0x44 && d[3] == 0x46) return "pdf";
            if (d[0] == 0xD0 && d[1] == 0xCF && d[2] == 0x11 && d[3] == 0xE0) return "ole";
            if (d[0] == 0x52 && d[1] == 0x61 && d[2] == 0x72 && d[3] == 0x21) return "rar";
            if (d[0] == 0x37 && d[1] == 0x7A && d[2] == 0xBC && d[3] == 0xAF) return "7z";
            if (d[0] == 0x1F && d[1] == 0x8B) return "gzip";
            if (d[0] == 0x89 && d[1] == 0x50 && d[2] == 0x4E && d[3] == 0x47) return "png";
            if (d[0] == 0xFF && d[1] == 0xD8 && d[2] == 0xFF) return "jpeg";
            if (d[0] == 0x47 && d[1] == 0x49 && d[2] == 0x46) return "gif";
            if (d[0] == 0x7B && d[1] == 0x5C && d[2] == 0x72 && d[3] == 0x74) return "rtf";
            if (d[0] == 0x4C && d[1] == 0x00 && d[2] == 0x00 && d[3] == 0x00) return "lnk";
            if (d.Length > 0x8005 && d[0x8001] == 0x43 && d[0x8002] == 0x44 && d[0x8003] == 0x30 && d[0x8004] == 0x30 && d[0x8005] == 0x31) return "iso";
            string head = Encoding.ASCII.GetString(d, 0, Math.Min(d.Length, 512)).ToLowerInvariant().TrimStart('\uFEFF', ' ', '\r', '\n', '\t');
            if (head.StartsWith("<!doctype html") || head.StartsWith("<html") || head.Contains("<script") || head.Contains("<form")) return "html";
            if (head.StartsWith("<svg") || (head.StartsWith("<?xml") && head.Contains("<svg"))) return "svg";
            return "";
        }

        static readonly Dictionary<string, string[]> ExpectedMagic = new Dictionary<string, string[]>
        {
            { "pdf", new[] { "pdf" } },
            { "docx", new[] { "zip" } }, { "xlsx", new[] { "zip" } }, { "pptx", new[] { "zip" } },
            { "docm", new[] { "zip" } }, { "xlsm", new[] { "zip" } }, { "pptm", new[] { "zip" } },
            { "zip", new[] { "zip" } }, { "odt", new[] { "zip" } }, { "ods", new[] { "zip" } },
            { "doc", new[] { "ole", "rtf" } }, { "xls", new[] { "ole" } }, { "ppt", new[] { "ole" } }, { "msg", new[] { "ole" } },
            { "png", new[] { "png" } }, { "jpg", new[] { "jpeg" } }, { "jpeg", new[] { "jpeg" } }, { "gif", new[] { "gif" } },
            { "rar", new[] { "rar" } }, { "7z", new[] { "7z" } }, { "rtf", new[] { "rtf" } },
            { "txt", new[] { "" } }, { "csv", new[] { "" } }
        };

        public static string MagicLabel(string magic)
        {
            switch (magic)
            {
                case "exe": return L.T("programme Windows (exe/dll)");
                case "zip": return L.T("archive ZIP / document Office");
                case "pdf": return "PDF";
                case "ole": return L.T("document Office ancien format / message Outlook");
                case "html": return L.T("page web HTML");
                case "svg": return L.T("image SVG");
                case "iso": return L.T("image disque ISO");
                case "lnk": return L.T("raccourci Windows");
                case "rtf": return L.T("document RTF");
                case "": return "";
            }
            return magic.ToUpperInvariant();
        }

        /// <summary>Indice si le contenu réel ne correspond pas à l'extension (null sinon).</summary>
        public static Finding MagicMismatch(AttachmentInfo a)
        {
            if (string.IsNullOrEmpty(a.Magic)) return null;
            string ext = "";
            int i = (a.Name ?? "").LastIndexOf('.');
            if (i >= 0) ext = a.Name.Substring(i + 1).ToLowerInvariant();

            if (a.Magic == "exe" && !Lists.ExtExecutable.Contains(ext))
                return new Finding("att-magic-exe", "attachments", Severity.Critical, L.T("Programme déguisé : le fichier est en réalité un exécutable"),
                    L.T("Le nom se termine par « .") + ext + L.T(" » mais le contenu est un programme Windows."), new[] { a.Name });
            if ((a.Magic == "html" || a.Magic == "svg") && !Lists.ExtHtml.Contains(ext) && ext != "xml" && ext != "txt")
                return new Finding("att-magic-html", "attachments", Severity.High, L.T("Page web déguisée en autre type de fichier"),
                    L.T("Le contenu est du HTML : il s’ouvrira dans le navigateur, souvent sur une fausse page de connexion."), new[] { a.Name });
            if (a.Magic == "lnk" && ext != "lnk")
                return new Finding("att-magic-lnk", "attachments", Severity.Critical, L.T("Raccourci Windows déguisé"), "", new[] { a.Name });
            string[] expected;
            if (ExpectedMagic.TryGetValue(ext, out expected) && !expected.Contains(a.Magic))
                return new Finding("att-magic-mismatch", "attachments", Severity.Medium, L.T("Le contenu ne correspond pas à l’extension"),
                    L.T("Extension « .") + ext + L.T(" », contenu réel : ") + MagicLabel(a.Magic) + ".", new[] { a.Name });
            return null;
        }

        public static void ComputeHashes(AttachmentInfo a, byte[] data)
        {
            if (data == null) return;
            a.Size = data.LongLength;
            a.Magic = DetectMagic(data);
            using (var md5 = MD5.Create()) a.Md5 = Hex(md5.ComputeHash(data));
            using (var sha1 = SHA1.Create()) a.Sha1 = Hex(sha1.ComputeHash(data));
            using (var sha256 = SHA256.Create()) a.Sha256 = Hex(sha256.ComputeHash(data));
            InspectContent(a, data);
        }

        static string Hex(byte[] b)
        {
            var sb = new StringBuilder(b.Length * 2);
            foreach (var x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }

        // -----------------------------------------------------------------
        // Authentication-Results complété par ARC-Authentication-Results
        // -----------------------------------------------------------------

        static string AuthServId(string value, bool arc)
        {
            var parts = (value ?? "").Split(';');
            int idx = arc ? 1 : 0;   // ARC : "i=1; serveur; ..." / classique : "serveur; ..."
            if (parts.Length <= idx) return "";
            return parts[idx].Trim().Split(' ', '\t')[0].ToLowerInvariant();
        }

        /// <summary>
        /// Texte d'authentification à analyser : le premier Authentication-Results (ajouté par votre serveur),
        /// complété par les ARC-Authentication-Results écrits par CE MÊME serveur (certains serveurs n'y mettent que SPF/DMARC).
        /// Les résultats ARC d'un autre serveur ne sont pas pris en compte (ils pourraient être falsifiés).
        /// </summary>
        public static string AuthResultsText(List<KeyValuePair<string, string>> h, out string source)
        {
            source = "";
            string ar = null;
            foreach (var kv in h) if (kv.Key == "authentication-results") { ar = kv.Value; break; }
            if (ar == null) return "";
            source = "Authentication-Results";
            string id = AuthServId(ar, false);
            var sb = new StringBuilder(ar);
            // Certains serveurs écrivent un en-tête par contrôle (SPF, puis DKIM, puis DMARC) : on regroupe ceux
            // du même serveur (même identifiant). Ceux d'autres serveurs, plus bas, ont pu être ajoutés par l'expéditeur.
            // (RFC 8601 §5 : un serveur supprime à la réception les en-têtes qui portent déjà son identifiant.)
            bool firstSeen = false;
            foreach (var kv in h)
            {
                if (kv.Key != "authentication-results") continue;
                if (!firstSeen) { firstSeen = true; continue; }
                if (id.Length > 0 && AuthServId(kv.Value, false) == id) { sb.Append("; ").Append(kv.Value); source = "Authentication-Results (" + id + ")"; }
            }
            foreach (var kv in h)
            {
                if (kv.Key != "arc-authentication-results") continue;
                if (id.Length > 0 && AuthServId(kv.Value, true) == id)
                {
                    sb.Append("; ").Append(kv.Value);
                    source = "Authentication-Results + ARC (" + id + ")";
                }
            }
            return sb.ToString();
        }

        static readonly Regex FilterHeaderRe = new Regex(@"spam|^x-me-|^x-feas|^x-fe-|forti|^x-forefront|^x-microsoft-antispam$|^x-ms-exchange-organization-scl|^x-mimecast|^x-proofpoint|^x-barracuda|^x-vade|^x-ironport|^x-sophos|^x-tm-|^x-virus|^x-amavis|^x-rspamd", RegexOptions.IgnoreCase);

        // -----------------------------------------------------------------
        // Décodage des mots encodés (RFC 2047) : =?UTF-8?Q?=C3=89valuez?=
        // -----------------------------------------------------------------

        static readonly Regex EncodedWordRe = new Regex(@"=\?([^?\s]+)\?([BbQq])\?([^?\s]*)\?=");

        public static string DecodeMimeWords(string s)
        {
            if (string.IsNullOrEmpty(s) || s.IndexOf("=?", StringComparison.Ordinal) < 0) return s ?? "";
            // les espaces entre deux mots encodés ne comptent pas
            string t = Regex.Replace(s, @"(\?=)\s+(=\?)", "$1$2");
            return EncodedWordRe.Replace(t, m =>
            {
                try
                {
                    Encoding enc;
                    try { enc = Encoding.GetEncoding(m.Groups[1].Value.Split('*')[0]); } catch (Exception) { enc = Encoding.UTF8; }
                    string data = m.Groups[3].Value;
                    byte[] bytes;
                    if (m.Groups[2].Value.ToUpperInvariant() == "B") bytes = Convert.FromBase64String(data);
                    else
                    {
                        var list = new List<byte>();
                        for (int i = 0; i < data.Length; i++)
                        {
                            char c = data[i];
                            if (c == '_') list.Add(0x20);
                            else if (c == '=' && i + 2 < data.Length && Uri.IsHexDigit(data[i + 1]) && Uri.IsHexDigit(data[i + 2]))
                            {
                                list.Add(Convert.ToByte(data.Substring(i + 1, 2), 16));
                                i += 2;
                            }
                            else list.Add((byte)c);
                        }
                        bytes = list.ToArray();
                    }
                    return enc.GetString(bytes);
                }
                catch (Exception) { return m.Value; }
            });
        }

        // -----------------------------------------------------------------
        // Inspection du contenu des pièces jointes (jamais exécuté, jamais ouvert)
        // -----------------------------------------------------------------

        static Finding F(string id, Severity sev, string title, string detail, params string[] evidence)
        {
            return new Finding(id, "attachments", sev, title, detail, evidence);
        }

        public static void InspectContent(AttachmentInfo a, byte[] d)
        {
            if (d == null || d.Length == 0) return;
            string ext = "";
            int dot = (a.Name ?? "").LastIndexOf('.');
            if (dot >= 0) ext = a.Name.Substring(dot + 1).ToLowerInvariant();
            try
            {
                if (a.Magic == "zip") InspectZip(a, d, ext);
                else if (a.Magic == "pdf") InspectPdf(a, d);
                else if (a.Magic == "ole")
                {
                    if (ContainsAscii(d, "_VBA_PROJECT") || ContainsUnicode(d, "_VBA_PROJECT") || ContainsAscii(d, "VBA_PROJECT"))
                        a.ContentFindings.Add(F("att-content-macro", Severity.High, L.T("Document contenant des macros"), L.T("Le fichier contient du code VBA : n’activez jamais les macros d’un document reçu."), a.Name));
                }
                else if (a.Magic == "rtf")
                {
                    string head = Latin1(d, 2 * 1024 * 1024);
                    if (head.Contains("\\objdata") || head.Contains("\\objupdate"))
                        a.ContentFindings.Add(F("att-content-rtf", Severity.Medium, L.T("Document RTF contenant un objet incorporé"), L.T("Technique utilisée pour exploiter des failles de Word."), a.Name));
                }
                if (a.Magic == "html" || a.Magic == "svg" || Lists.ExtHtml.Contains(ext)) InspectHtml(a, d);
            }
            catch (Exception) { }
        }

        static string Latin1(byte[] d, int max)
        {
            return Encoding.GetEncoding(28591).GetString(d, 0, Math.Min(d.Length, max));
        }

        static bool ContainsAscii(byte[] d, string s)
        {
            return Latin1(d, 20 * 1024 * 1024).IndexOf(s, StringComparison.Ordinal) >= 0;
        }

        static bool ContainsUnicode(byte[] d, string s)
        {
            string u = Encoding.Unicode.GetString(d, 0, Math.Min(d.Length, 20 * 1024 * 1024) & ~1);
            return u.IndexOf(s, StringComparison.Ordinal) >= 0;
        }

        /// <summary>Lit le répertoire central d'une archive ZIP (noms et chiffrement), sans rien extraire.</summary>
        public static List<KeyValuePair<string, bool>> ZipEntries(byte[] d)
        {
            var list = new List<KeyValuePair<string, bool>>();
            Encoding cp437;
            try { cp437 = Encoding.GetEncoding(437); } catch (Exception) { cp437 = Encoding.ASCII; }
            for (int i = 0; i + 46 <= d.Length && list.Count < 2000; i++)
            {
                if (d[i] != 0x50 || d[i + 1] != 0x4B || d[i + 2] != 0x01 || d[i + 3] != 0x02) continue;
                int flags = d[i + 8] | (d[i + 9] << 8);
                int nlen = d[i + 28] | (d[i + 29] << 8);
                int elen = d[i + 30] | (d[i + 31] << 8);
                int clen = d[i + 32] | (d[i + 33] << 8);
                if (i + 46 + nlen > d.Length) break;
                string name = ((flags & 0x800) != 0 ? Encoding.UTF8 : cp437).GetString(d, i + 46, nlen);
                list.Add(new KeyValuePair<string, bool>(name, (flags & 1) != 0));
                i += 46 + nlen + elen + clen - 1;
            }
            return list;
        }

        static readonly HashSet<string> OfficeZipExt = new HashSet<string>(new[] { "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotx", "xltx", "potx", "ppsx", "odt", "ods", "odp" });

        static void InspectZip(AttachmentInfo a, byte[] d, string ext)
        {
            var entries = ZipEntries(d);
            if (OfficeZipExt.Contains(ext))
            {
                bool vba = entries.Any(e => e.Key.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase));
                if (vba && !Lists.ExtMacro.Contains(ext))
                    a.ContentFindings.Add(F("att-content-hidden-macro", Severity.High, L.T("Macros cachées dans un document Office"),
                        L.T("Le document contient du code VBA alors que son extension ne l’annonce pas."), a.Name));
                if (entries.Any(e => e.Key.IndexOf("oleObject", StringComparison.OrdinalIgnoreCase) >= 0 && e.Key.EndsWith(".bin", StringComparison.OrdinalIgnoreCase)))
                    a.ContentFindings.Add(F("att-content-ole", Severity.Medium, L.T("Document Office contenant un objet incorporé"), L.T("Un objet incorporé peut cacher un programme ou un script."), a.Name));
                return;
            }
            foreach (var e in entries.Take(50)) a.ArchiveEntries.Add(e.Key + (e.Value ? L.T("  (chiffré)") : ""));
            var dangerous = new List<string>();
            var doubleExt = new List<string>();
            foreach (var e in entries)
            {
                string n = e.Key.ToLowerInvariant();
                if (n.EndsWith("/")) continue;
                int i = n.LastIndexOf('.');
                string x = i >= 0 ? n.Substring(i + 1) : "";
                var parts = n.Split('/').Last().Split('.');
                string prev = parts.Length > 2 ? parts[parts.Length - 2] : "";
                bool danger = Lists.ExtExecutable.Contains(x) || Lists.ExtDiskImage.Contains(x) || Lists.ExtHtml.Contains(x) || Lists.ExtMacro.Contains(x) || Lists.ExtOneNote.Contains(x);
                if (danger && Lists.ExtDocument.Contains(prev)) doubleExt.Add(e.Key);
                else if (danger) dangerous.Add(e.Key);
            }
            if (doubleExt.Count > 0)
                a.ContentFindings.Add(F("att-content-zip-double", Severity.Critical, L.T("Archive contenant un programme déguisé en document"), "", doubleExt.Take(5).ToArray()));
            if (dangerous.Count > 0)
                a.ContentFindings.Add(F("att-content-zip-danger", Severity.High, L.T("Archive contenant un fichier dangereux"), L.T("Script, programme, raccourci ou page web cachés dans l’archive."), dangerous.Take(5).ToArray()));
            if (entries.Any(e => e.Value))
                a.ContentFindings.Add(F("att-content-zip-encrypted", Severity.Medium, L.T("Archive protégée par mot de passe"), L.T("L’antivirus ne peut pas analyser son contenu : technique classique pour faire passer un logiciel malveillant."), a.Name));
        }

        static readonly Regex PdfUriRe = new Regex(@"/URI\s*\(((?:\\.|[^\\)]){4,500})\)");

        static void InspectPdf(AttachmentInfo a, byte[] d)
        {
            string s = Latin1(d, 10 * 1024 * 1024);
            if (Regex.IsMatch(s, @"/(JavaScript|JS)\b"))
                a.ContentFindings.Add(F("att-content-pdf-js", Severity.High, L.T("PDF contenant du JavaScript"), L.T("Un PDF ordinaire n’a pas besoin de code ; celui-ci peut exploiter le lecteur PDF."), a.Name));
            if (s.Contains("/Launch"))
                a.ContentFindings.Add(F("att-content-pdf-launch", Severity.High, L.T("PDF capable de lancer un programme"), "", a.Name));
            if (s.Contains("/EmbeddedFile"))
                a.ContentFindings.Add(F("att-content-pdf-file", Severity.Medium, L.T("PDF contenant un fichier caché"), L.T("Un fichier est incorporé à l’intérieur du PDF."), a.Name));
            foreach (Match m in PdfUriRe.Matches(s))
            {
                string u = Regex.Replace(m.Groups[1].Value, @"\\(.)", "$1").Trim();
                if (Regex.IsMatch(u, "^(https?://|www\\.)", RegexOptions.IgnoreCase) && !a.EmbeddedUrls.Contains(u)) a.EmbeddedUrls.Add(u);
                if (a.EmbeddedUrls.Count >= 30) break;
            }
        }

        static void InspectHtml(AttachmentInfo a, byte[] d)
        {
            string s = Encoding.UTF8.GetString(d, 0, Math.Min(d.Length, 5 * 1024 * 1024));
            bool pwd = Regex.IsMatch(s, @"<input\b[^>]*\btype\s*=\s*[""']?password", RegexOptions.IgnoreCase);
            bool form = Regex.IsMatch(s, @"<form\b", RegexOptions.IgnoreCase);
            if (pwd)
                a.ContentFindings.Add(F("att-content-html-password", Severity.Critical, L.T("Fausse page de connexion en pièce jointe"), L.T("Le fichier contient un champ « mot de passe » : il sert à voler vos identifiants."), a.Name));
            else if (form)
                a.ContentFindings.Add(F("att-content-html-form", Severity.High, L.T("Formulaire en pièce jointe"), L.T("Les informations saisies sont envoyées à un site extérieur."), a.Name));
            if (Regex.IsMatch(s, @"(atob\(|unescape\(|eval\(|document\.write\()", RegexOptions.IgnoreCase))
                a.ContentFindings.Add(F("att-content-html-obfuscated", Severity.Medium, L.T("Pièce jointe HTML contenant du code masqué"), "", a.Name));
            foreach (Match m in Regex.Matches(s, @"\b(?:href|action|src)\s*=\s*[""'](https?://[^""'\s>]{4,500})", RegexOptions.IgnoreCase))
            {
                string u = m.Groups[1].Value;
                if (!a.EmbeddedUrls.Contains(u)) a.EmbeddedUrls.Add(u);
                if (a.EmbeddedUrls.Count >= 30) break;
            }
        }

        // -----------------------------------------------------------------
        // Liens de vérification (ouverts dans le navigateur à la demande)
        // -----------------------------------------------------------------

        public static readonly string[] LookupHosts = { "www.virustotal.com", "www.abuseipdb.com", "talosintelligence.com", "transparencyreport.google.com", "who.is", "mxtoolbox.com" };

        static KeyValuePair<string, string> SafeBrowsing(string target)
        {
            return new KeyValuePair<string, string>("Google Safe Browsing", "https://transparencyreport.google.com/safe-browsing/search?url=" + Enc(target));
        }

        static KeyValuePair<string, string> Talos(string target)
        {
            return new KeyValuePair<string, string>("Talos", "https://talosintelligence.com/reputation_center/lookup?search=" + Enc(target));
        }

        // Liens de vérification, sans compte à créer. Le meilleur pour chaque type d'élément est en premier.
        public static List<KeyValuePair<string, string>> LookupsForDomain(string d)
        {
            return new List<KeyValuePair<string, string>> {
                new KeyValuePair<string, string>("VirusTotal", "https://www.virustotal.com/gui/domain/" + Enc(d)),
                SafeBrowsing(d),
                Talos(d),
                new KeyValuePair<string, string>("WHOIS", "https://who.is/whois/" + Enc(d)) };
        }

        public static List<KeyValuePair<string, string>> LookupsForIp(string ip)
        {
            // IP d'origine d'un email : AbuseIPDB (signalements d'abus) et Talos (réputation email de Cisco) sont plus parlants que VirusTotal
            return new List<KeyValuePair<string, string>> {
                new KeyValuePair<string, string>("AbuseIPDB", "https://www.abuseipdb.com/check/" + Enc(ip)),
                Talos(ip),
                new KeyValuePair<string, string>(L.T("Listes noires"), "https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a" + Enc(ip)),
                new KeyValuePair<string, string>("VirusTotal", "https://www.virustotal.com/gui/ip-address/" + Enc(ip)) };
        }

        public static List<KeyValuePair<string, string>> LookupsForUrl(string url)
        {
            return new List<KeyValuePair<string, string>> {
                new KeyValuePair<string, string>("VirusTotal", "https://www.virustotal.com/gui/search/" + Enc(Enc(url))),
                SafeBrowsing(url) };
        }

        public static List<KeyValuePair<string, string>> LookupsForHash(string sha256)
        {
            return new List<KeyValuePair<string, string>> {
                new KeyValuePair<string, string>("VirusTotal", "https://www.virustotal.com/gui/file/" + Enc(sha256)) };
        }
    }
}
