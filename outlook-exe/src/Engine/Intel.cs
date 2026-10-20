// PhishGuard - sources externes « bêta » (désactivées par défaut, réglables dans l'onglet Bêta des paramètres).
//
// Sans clé :  vérifications DNS (MX, SPF, DMARC) avec le DNS de Windows ; âge du premier certificat HTTPS (crt.sh).
// Avec clé gratuite : VirusTotal (empreintes des pièces jointes), abuse.ch URLhaus + ThreatFox,
//                     AbuseIPDB (IP d'origine).
//
// Fonctionnement : l'analyse ne bloque jamais. Elle lit le cache ; ce qui manque est demandé en arrière-plan
// (un seul fil, avec un délai minimal par service), puis Changed passe à true et le complément relance l'analyse.
// Seuls des domaines, des adresses de liens, des empreintes de fichiers et des IP sont envoyés, jamais un email.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace PhishGuard
{
    public class IntelResult
    {
        public bool Ok;              // réponse obtenue (false = erreur réseau ou service indisponible)
        public bool Found;           // l'élément est connu du service (listé, signalé, enregistré...)
        public int Malicious;        // VirusTotal : moteurs « malveillant » ; AbuseIPDB : score de confiance
        public int Suspicious;
        public int Total;
        public string Label = "";    // famille de malware, type de menace, pays...
        public DateTime? Date;       // crt.sh : premier certificat
        public bool Exists = true;   // DNS : le domaine existe
        public bool HasMx, HasSpf, HasDmarc;
        public string DmarcPolicy = "";   // DNS : none, quarantine, reject (politique appliquée au domaine)
        public string Bimi = "";          // DNS : "vmc" (logo avec certificat VMC/CMC), "logo" (logo sans certificat), "" (aucun)
        public string SpfAll = "";        // DNS : fin du SPF : "-" (strict), "~" (échec doux), "?" (neutre), "+" (tout le monde), "" (absent)
        public int DmarcPct = 100;        // DNS : part des messages à laquelle la politique DMARC s'applique
        public DateTime When = DateTime.UtcNow;
    }

    public class IntelSettings
    {
        public bool DnsChecks, CertAge;
        public string VirusTotalKey = "", AbuseChKey = "", AbuseIpdbKey = "";

        public bool Any
        {
            get
            {
                return DnsChecks || CertAge || VirusTotalKey.Length > 0 || AbuseChKey.Length > 0 || AbuseIpdbKey.Length > 0;
            }
        }
    }

    public static class Intel
    {
        static readonly object Sync = new object();
        static readonly Dictionary<string, IntelResult> cache = new Dictionary<string, IntelResult>();
        static readonly LinkedList<string> queue = new LinkedList<string>();
        static readonly HashSet<string> pending = new HashSet<string>();
        static readonly Dictionary<string, DateTime> lastCall = new Dictionary<string, DateTime>();
        static bool worker;

        public static IntelSettings Settings = new IntelSettings();
        public static volatile bool Changed;
        public static string LastError = "";

        // -----------------------------------------------------------------
        // Cache
        // -----------------------------------------------------------------

        /// <summary>Résultat en cache (null si inconnu ; dans ce cas, appeler Request).</summary>
        public static IntelResult Get(string key)
        {
            lock (Sync)
            {
                IntelResult r;
                if (!cache.TryGetValue(key, out r)) return null;
                // erreurs retentées après 10 minutes, résultats gardés 24 h
                if (!r.Ok && r.When < DateTime.UtcNow.AddMinutes(-10)) return null;
                if (r.When < DateTime.UtcNow.AddHours(-24)) return null;
                return r;
            }
        }

        /// <summary>Lit le cache ; si l'élément est inconnu, le demande en arrière-plan.</summary>
        public static IntelResult GetOrRequest(string key)
        {
            var r = Get(key);
            if (r == null) Request(key);
            return r;
        }

        public static void Request(string key)
        {
            lock (Sync)
            {
                if (pending.Contains(key) || queue.Count > 200) return;
                pending.Add(key);
                queue.AddLast(key);
                if (worker) return;
                worker = true;
            }
            var t = new Thread(Work) { IsBackground = true, Name = "PhishGuard Intel" };
            t.Start();
        }

        public static void SetForTests(string key, IntelResult r)
        {
            lock (Sync) { r.When = DateTime.UtcNow; cache[key] = r; }
        }

        public static void ClearForTests()
        {
            lock (Sync) { cache.Clear(); queue.Clear(); pending.Clear(); }
        }

        static void Work()
        {
            while (true)
            {
                string key;
                lock (Sync)
                {
                    if (queue.Count == 0) { worker = false; return; }
                    key = queue.First.Value;
                    queue.RemoveFirst();
                }
                IntelResult result;
                try { result = Fetch(key); LastError = ""; }
                catch (Exception ex)
                {
                    LastError = Service(key) + " : " + ex.Message;
                    result = new IntelResult { Ok = false };
                }
                lock (Sync)
                {
                    result.When = DateTime.UtcNow;
                    cache[key] = result;
                    pending.Remove(key);
                }
                Changed = true;
            }
        }

        static string Service(string key)
        {
            int i = key.IndexOf(':');
            return i > 0 ? key.Substring(0, i) : key;
        }

        /// <summary>Respecte un délai minimal entre deux appels au même service (VirusTotal gratuit : 4 par minute).</summary>
        static void Throttle(string service, int ms)
        {
            DateTime last;
            lock (Sync) { if (!lastCall.TryGetValue(service, out last)) last = DateTime.MinValue; }
            var wait = last.AddMilliseconds(ms) - DateTime.UtcNow;
            if (wait > TimeSpan.Zero) Thread.Sleep(wait);
            lock (Sync) lastCall[service] = DateTime.UtcNow;
        }

        static IntelResult Fetch(string key)
        {
            string service = Service(key);
            string v = key.Substring(service.Length + 1);
            var s = Settings;
            switch (service)
            {
                case "dns": return Dns(v);
                case "own": return Owner(v);
                case "crt": Throttle("crt", 2000); return ParseCrt(Http("GET", "https://crt.sh/?output=json&q=" + Uri.EscapeDataString(v), null, null, null, 4000000));
                case "vtf": Throttle("vt", 15500); return ParseVirusTotal(VtGet("files/" + v));
                case "uhh": Throttle("abusech", 1000); return ParseUrlhaus(Http("POST", "https://urlhaus-api.abuse.ch/v1/host/", "host=" + Uri.EscapeDataString(v), "application/x-www-form-urlencoded", AbuseChHeaders(), 1000000));
                case "uhp": Throttle("abusech", 1000); return ParseUrlhaus(Http("POST", "https://urlhaus-api.abuse.ch/v1/payload/", "sha256_hash=" + v, "application/x-www-form-urlencoded", AbuseChHeaders(), 1000000));
                case "tfi": Throttle("abusech", 1000); return ParseThreatFox(Http("POST", "https://threatfox-api.abuse.ch/api/v1/", "{\"query\":\"search_ioc\",\"search_term\":\"" + JsonEscape(v) + "\"}", "application/json", AbuseChHeaders(), 1000000));
                case "tfh": Throttle("abusech", 1000); return ParseThreatFox(Http("POST", "https://threatfox-api.abuse.ch/api/v1/", "{\"query\":\"search_hash\",\"hash\":\"" + JsonEscape(v) + "\"}", "application/json", AbuseChHeaders(), 1000000));
                case "ip":
                    Throttle("abuseipdb", 1000);
                    return ParseAbuseIpdb(Http("GET", "https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress=" + Uri.EscapeDataString(v), null, null,
                        new Dictionary<string, string> { { "Key", s.AbuseIpdbKey } }, 200000));
            }
            return new IntelResult { Ok = false };
        }

        static Dictionary<string, string> AbuseChHeaders()
        {
            return new Dictionary<string, string> { { "Auth-Key", Settings.AbuseChKey } };
        }

        static string VtGet(string path)
        {
            try
            {
                return Http("GET", "https://www.virustotal.com/api/v3/" + path, null, null,
                    new Dictionary<string, string> { { "x-apikey", Settings.VirusTotalKey } }, 2000000);
            }
            catch (WebException ex)
            {
                var r = ex.Response as HttpWebResponse;
                if (r != null && (int)r.StatusCode == 404) return "{\"notfound\":true}";
                throw;
            }
        }

        // -----------------------------------------------------------------
        // HTTP (proxy et certificats de Windows, comme le reste du complément)
        // -----------------------------------------------------------------

        internal static string Http(string method, string url, string body, string contentType, Dictionary<string, string> headers, int maxChars)
        {
            return Http(method, url, body, contentType, headers, maxChars, null, 20000);
        }

        internal static string Http(string method, string url, string body, string contentType, Dictionary<string, string> headers, int maxChars, string accept, int timeoutMs)
        {
            ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; // TLS 1.2
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = method;
            req.Proxy = WebRequest.GetSystemWebProxy();
            req.Proxy.Credentials = CredentialCache.DefaultCredentials;
            req.UserAgent = "PhishGuard-Outlook/1.0";
            req.Accept = accept ?? "application/json";
            req.Timeout = timeoutMs;
            req.ReadWriteTimeout = timeoutMs;
            req.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            if (headers != null) foreach (var h in headers) req.Headers[h.Key] = h.Value;
            if (body != null)
            {
                byte[] data = Encoding.UTF8.GetBytes(body);
                req.ContentType = contentType;
                req.ContentLength = data.Length;
                using (var s = req.GetRequestStream()) s.Write(data, 0, data.Length);
            }
            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var reader = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
            {
                var buf = new char[8192];
                var sb = new StringBuilder();
                int n;
                while ((n = reader.Read(buf, 0, buf.Length)) > 0)
                {
                    sb.Append(buf, 0, n);
                    if (sb.Length > maxChars) break;
                }
                return sb.ToString();
            }
        }

        static string JsonEscape(string s)
        {
            var sb = new StringBuilder();
            foreach (char c in s ?? "")
            {
                if (c == '"' || c == '\\') sb.Append('\\').Append(c);
                else if (c < 32) sb.Append("\\u").Append(((int)c).ToString("x4"));
                else sb.Append(c);
            }
            return sb.ToString();
        }

        // -----------------------------------------------------------------
        // Lecture des réponses (fonctions pures, testées)
        // -----------------------------------------------------------------

        static int IntField(string json, string name)
        {
            var m = Regex.Match(json ?? "", "\"" + Regex.Escape(name) + "\"\\s*:\\s*\"?(\\d+)");
            int v;
            return m.Success && int.TryParse(m.Groups[1].Value, out v) ? v : 0;
        }

        static string StrField(string json, string name)
        {
            var m = Regex.Match(json ?? "", "\"" + Regex.Escape(name) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
            return m.Success ? Regex.Unescape(m.Groups[1].Value) : "";
        }

        public static IntelResult ParseVirusTotal(string json)
        {
            if (json != null && json.Contains("\"notfound\"")) return new IntelResult { Ok = true, Found = false };
            var m = Regex.Match(json ?? "", "\"last_analysis_stats\"\\s*:\\s*\\{([^}]*)\\}");
            if (!m.Success) return new IntelResult { Ok = true, Found = false };
            string st = "{" + m.Groups[1].Value + "}";
            int mal = IntField(st, "malicious"), sus = IntField(st, "suspicious");
            int total = mal + sus + IntField(st, "harmless") + IntField(st, "undetected");
            return new IntelResult { Ok = true, Found = true, Malicious = mal, Suspicious = sus, Total = total };
        }

        public static IntelResult ParseCrt(string json)
        {
            DateTime? first = null;
            foreach (Match m in Regex.Matches(json ?? "", "\"not_before\"\\s*:\\s*\"([^\"]+)\""))
            {
                DateTime d;
                if (DateTime.TryParse(m.Groups[1].Value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out d))
                    if (!first.HasValue || d < first.Value) first = d;
            }
            return new IntelResult { Ok = true, Found = first.HasValue, Date = first };
        }

        public static IntelResult ParseUrlhaus(string json)
        {
            string status = StrField(json, "query_status");
            if (status != "ok") return new IntelResult { Ok = status == "no_results" || status.Length > 0, Found = false };
            int count = IntField(json, "url_count");
            string sig = StrField(json, "signature");
            return new IntelResult { Ok = true, Found = true, Total = count, Label = sig };
        }

        public static IntelResult ParseThreatFox(string json)
        {
            string status = StrField(json, "query_status");
            if (status != "ok") return new IntelResult { Ok = status.Length > 0, Found = false };
            return new IntelResult { Ok = true, Found = true, Label = StrField(json, "malware_printable") };
        }

        public static IntelResult ParseAbuseIpdb(string json)
        {
            if ((json ?? "").IndexOf("abuseConfidenceScore", StringComparison.Ordinal) < 0) return new IntelResult { Ok = false };
            int score = IntField(json, "abuseConfidenceScore");
            return new IntelResult { Ok = true, Found = score > 0, Malicious = score, Total = IntField(json, "totalReports"), Label = StrField(json, "countryCode") };
        }

        // -----------------------------------------------------------------
        // DNS (serveur DNS de Windows, sans service externe)
        // -----------------------------------------------------------------

        [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_W", CharSet = CharSet.Unicode, ExactSpelling = true)]
        static extern int DnsQuery(string name, ushort type, uint options, IntPtr extra, out IntPtr results, IntPtr reserved);

        [DllImport("dnsapi.dll")]
        static extern void DnsRecordListFree(IntPtr list, int freeType);

        internal const ushort TypeNs = 2, TypeMx = 15, TypeTxt = 16;
        internal const int NameError = 9003, NoRecords = 9501;

        /// <summary>Renvoie le code DNS et la liste des MX ou des textes TXT.</summary>
        internal static int Query(string name, ushort type, List<string> values)
        {
            IntPtr list;
            int rc = DnsQuery(name, type, 0, IntPtr.Zero, out list, IntPtr.Zero);
            if (rc != 0 || list == IntPtr.Zero) return rc;
            try
            {
                int ptr = IntPtr.Size;
                int dataOffset = 2 * ptr + 16;   // pNext, pName, wType, wDataLength, Flags, dwTtl, dwReserved
                for (IntPtr rec = list; rec != IntPtr.Zero; rec = Marshal.ReadIntPtr(rec))
                {
                    ushort t = (ushort)Marshal.ReadInt16(rec, 2 * ptr);
                    if (t != type) continue;
                    IntPtr data = IntPtr.Add(rec, dataOffset);
                    if (type != TypeTxt)
                    {
                        // MX (pNameExchange) et NS (pNameHost) : le nom est le premier champ
                        string host = Marshal.PtrToStringUni(Marshal.ReadIntPtr(data));
                        if (!string.IsNullOrEmpty(host)) values.Add(host);
                    }
                    else
                    {
                        int count = Marshal.ReadInt32(data);
                        var sb = new StringBuilder();
                        for (int i = 0; i < count && i < 64; i++)
                            sb.Append(Marshal.PtrToStringUni(Marshal.ReadIntPtr(data, ptr + i * ptr)));
                        values.Add(sb.ToString());
                    }
                }
            }
            finally { DnsRecordListFree(list, 1); }
            return 0;
        }

        /// <summary>Clé "dns:domaine|domaine-organisation".</summary>
        static IntelResult Dns(string v)
        {
            var parts = v.Split('|');
            string domain = parts[0], org = parts.Length > 1 ? parts[1] : parts[0];
            var mx = new List<string>();
            int rc = Query(domain, TypeMx, mx);
            if (rc == NameError) return new IntelResult { Ok = true, Exists = false };
            if (rc != 0 && rc != NoRecords) throw new Exception("DNS " + rc);
            var txt = new List<string>();
            Query(domain, TypeTxt, txt);
            var dmarc = new List<string>();
            Query("_dmarc." + domain, TypeTxt, dmarc);
            bool dmarcFromOrg = false;
            if (!dmarc.Any(IsDmarc) && org != domain) { dmarc.Clear(); Query("_dmarc." + org, TypeTxt, dmarc); dmarcFromOrg = true; }
            string dmarcRecord = dmarc.FirstOrDefault(IsDmarc) ?? "";
            var bimi = new List<string>();
            Query("default._bimi." + domain, TypeTxt, bimi);
            if (!bimi.Any(IsBimi) && org != domain) { bimi.Clear(); Query("default._bimi." + org, TypeTxt, bimi); }
            return new IntelResult
            {
                Ok = true,
                Exists = true,
                HasMx = mx.Count > 0,
                HasSpf = txt.Any(t => t.TrimStart().StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)),
                HasDmarc = dmarcRecord.Length > 0,
                DmarcPolicy = ParseDmarcPolicy(dmarcRecord, dmarcFromOrg),
                DmarcPct = ParseDmarcPct(dmarcRecord),
                SpfAll = SpfAllQualifier(txt.FirstOrDefault(t => t.TrimStart().StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)) ?? ""),
                Bimi = ParseBimi(bimi.FirstOrDefault(IsBimi) ?? "")
            };
        }

        /// <summary>Clé de la vérification « même propriétaire » : domaine à vérifier et domaines officiels de la marque.</summary>
        public static string OwnerKey(string candidate, IEnumerable<string> officials)
        {
            return "own:" + (candidate ?? "").ToLowerInvariant() + "|" + string.Join(",", officials.Select(o => o.ToLowerInvariant()).Distinct().OrderBy(o => o, StringComparer.Ordinal).ToArray());
        }

        /// <summary>« Même propriétaire » : le domaine est géré par des serveurs DNS situés sous un domaine officiel
        /// (ns1.marque.com…), ou son DMARC envoie ses rapports à un domaine officiel qui l'autorise explicitement
        /// (enregistrement « domaine._report._dmarc.officiel », RFC 7489 §7.1). Un tiers ne peut produire ni l'un ni l'autre.</summary>
        static IntelResult Owner(string v)
        {
            var parts = v.Split('|');
            if (parts.Length < 2) return new IntelResult { Ok = false };
            string cand = parts[0];
            var officials = new HashSet<string>(parts[1].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries));
            var ns = new List<string>();
            int rc = Query(cand, TypeNs, ns);
            if (rc == NameError) return new IntelResult { Ok = true, Found = false, Exists = false };
            if (rc != 0 && rc != NoRecords) throw new Exception("DNS " + rc);
            var dmarc = new List<string>();
            Query("_dmarc." + cand, TypeTxt, dmarc);
            return OwnerProof(cand, ns, dmarc.FirstOrDefault(IsDmarc) ?? "", officials, d =>
            {
                var auth = new List<string>();
                Query(cand + "._report._dmarc." + d, TypeTxt, auth);
                return auth.Any(IsDmarc);
            });
        }

        /// <summary>Décision de la vérification « même propriétaire » (fonction pure, testée).</summary>
        public static IntelResult OwnerProof(string cand, IEnumerable<string> nameServers, string dmarcRecord, ICollection<string> officials, Func<string, bool> reportAuthorized)
        {
            foreach (var h in nameServers)
            {
                string host = (h ?? "").TrimEnd('.').ToLowerInvariant();
                if (officials.Contains(Domains.RegistrableDomain(host))) return new IntelResult { Ok = true, Found = true, Label = L.T("serveur DNS ") + host };
            }
            foreach (Match m in Regex.Matches(dmarcRecord ?? "", @"mailto:[^@,;\s]+@([A-Za-z0-9.-]+)", RegexOptions.IgnoreCase))
            {
                string d = m.Groups[1].Value.TrimEnd('.').ToLowerInvariant();
                if (officials.Contains(Domains.RegistrableDomain(d)) && reportAuthorized(d))
                    return new IntelResult { Ok = true, Found = true, Label = L.T("rapports DMARC autorisés par ") + d };
            }
            return new IntelResult { Ok = true, Found = false };
        }

        static bool IsDmarc(string t) { return t.TrimStart().StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase); }
        static bool IsBimi(string t) { return t.TrimStart().StartsWith("v=BIMI1", StringComparison.OrdinalIgnoreCase); }

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

        /// <summary>Politique DMARC d'un enregistrement (« none », « quarantine », « reject » ou "").
        /// forSubdomain : l'enregistrement est celui du domaine parent, la politique « sp= » s'applique si elle existe.</summary>
        /// <summary>Part des messages couverte par la politique DMARC (pct=, 100 par défaut).</summary>
        public static int ParseDmarcPct(string record)
        {
            string v; int n;
            if (Tags(record).TryGetValue("pct", out v) && int.TryParse(v.Trim(), out n)) return Math.Max(0, Math.Min(100, n));
            return 100;
        }

        /// <summary>Qualificatif du mécanisme « all » d'un SPF : "-", "~", "?", "+" ("all" seul vaut "+"), ou "" s'il n'y en a pas.</summary>
        public static string SpfAllQualifier(string record)
        {
            if (string.IsNullOrEmpty(record)) return "";
            string q = "";
            foreach (var tok in record.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string t = tok.Trim().ToLowerInvariant();
                if (t == "all") q = "+";
                else if (t.Length == 4 && t.EndsWith("all") && "+-~?".IndexOf(t[0]) >= 0) q = t.Substring(0, 1);
            }
            return q;
        }

        /// <summary>
        /// Taille de la clé d'un enregistrement DKIM (« v=DKIM1; k=rsa; p=MIIB… ») en bits : 256 pour ed25519,
        /// 0 si la clé est révoquée (p= vide), -1 si elle est illisible. Lit la plus grande valeur entière de la
        /// structure ASN.1 (le module RSA), que la clé soit publiée au format SubjectPublicKeyInfo ou PKCS#1.
        /// </summary>
        public static int DkimKeyBits(string record)
        {
            var t = Tags(record);
            string k, p;
            if (t.TryGetValue("k", out k) && k.Trim().Equals("ed25519", StringComparison.OrdinalIgnoreCase)) return 256;
            if (!t.TryGetValue("p", out p)) return -1;
            p = System.Text.RegularExpressions.Regex.Replace(p, @"\s+", "");
            if (p.Length == 0) return 0;
            byte[] der;
            try { der = Convert.FromBase64String(p); } catch (FormatException) { return -1; }
            int best = 0;
            LargestInteger(der, 0, der.Length, 0, ref best);
            return best > 0 ? best : -1;
        }

        static void LargestInteger(byte[] d, int start, int end, int depth, ref int best)
        {
            int i = start;
            while (i + 2 <= end && depth < 6)
            {
                byte tag = d[i++];
                int len = d[i++];
                if ((len & 0x80) != 0)
                {
                    int n = len & 0x7F; if (n == 0 || n > 3 || i + n > end) return;
                    len = 0; for (int j = 0; j < n; j++) len = (len << 8) | d[i++];
                }
                if (len < 0 || i + len > end) return;
                if (tag == 0x02)          // INTEGER : nombre de bits significatifs
                {
                    int s = i; while (s < i + len && d[s] == 0) s++;
                    if (s < i + len) { int bits = (i + len - s) * 8; byte top = d[s]; while ((top & 0x80) == 0) { bits--; top <<= 1; } if (bits > best) best = bits; }
                }
                else if (tag == 0x30) LargestInteger(d, i, i + len, depth + 1, ref best);          // SEQUENCE
                else if (tag == 0x03 && len > 1) LargestInteger(d, i + 1, i + len, depth + 1, ref best);   // BIT STRING (octet de bourrage)
                i += len;
            }
        }

        public static string ParseDmarcPolicy(string record, bool forSubdomain)
        {
            var t = Tags(record);
            string p;
            if (forSubdomain && t.TryGetValue("sp", out p) && p.Length > 0) return p.ToLowerInvariant();
            return t.TryGetValue("p", out p) ? p.ToLowerInvariant() : "";
        }

        /// <summary>BIMI : "vmc" si un certificat de marque (a=) est publié, "logo" si seul un logo (l=) l'est, sinon "".</summary>
        public static string ParseBimi(string record)
        {
            var t = Tags(record);
            string a, l;
            if (t.TryGetValue("a", out a) && a.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return "vmc";
            if (t.TryGetValue("l", out l) && l.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return "logo";
            return "";
        }
    }
}
