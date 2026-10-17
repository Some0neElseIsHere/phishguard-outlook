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
            ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; // TLS 1.2
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = method;
            req.Proxy = WebRequest.GetSystemWebProxy();
            req.Proxy.Credentials = CredentialCache.DefaultCredentials;
            req.UserAgent = "PhishGuard-Outlook/1.0";
            req.Accept = "application/json";
            req.Timeout = 20000;
            req.ReadWriteTimeout = 20000;
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

        const ushort TypeMx = 15, TypeTxt = 16;
        const int NameError = 9003, NoRecords = 9501;

        /// <summary>Renvoie le code DNS et la liste des MX ou des textes TXT.</summary>
        static int Query(string name, ushort type, List<string> values)
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
                    if (type == TypeMx)
                    {
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
            if (dmarc.Count == 0 && org != domain) Query("_dmarc." + org, TypeTxt, dmarc);
            return new IntelResult
            {
                Ok = true,
                Exists = true,
                HasMx = mx.Count > 0,
                HasSpf = txt.Any(t => t.TrimStart().StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)),
                HasDmarc = dmarc.Any(t => t.TrimStart().StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase))
            };
        }
    }
}
