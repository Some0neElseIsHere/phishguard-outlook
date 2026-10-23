// PhishGuard - âge des domaines via RDAP (successeur de WHOIS, gratuit et sans clé).
// Un domaine créé il y a quelques jours est un signal fort de phishing.
// Les recherches se font en arrière-plan ; le résultat est mis en cache sur le poste.
// Seul le nom de domaine est envoyé (au service rdap.org puis au registre du domaine), jamais l'email.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

namespace PhishGuard
{
    public static class DomainAge
    {
        static readonly object Sync = new object();
        static readonly Dictionary<string, DateTime?> known = new Dictionary<string, DateTime?>();
        static readonly Dictionary<string, DateTime> checkedOn = new Dictionary<string, DateTime>();
        static readonly Queue<string> queue = new Queue<string>();
        static readonly HashSet<string> pending = new HashSet<string>();
        static readonly HashSet<string> forced = new HashSet<string>();   // demandés d'un clic : faits même si la recherche automatique est coupée
        static bool worker;
        static bool loaded;

        /// <summary>Passe à true quand une nouvelle date est connue (le complément relance alors l'analyse affichée).</summary>
        public static volatile bool Changed;
        /// <summary>Augmente à chaque date reçue : la fenêtre d'analyse se redessine même si le verdict ne change pas.</summary>
        public static volatile int Version;
        public static bool Enabled = true;
        public static string LastError = "";
        static readonly Dictionary<string, string> errors = new Dictionary<string, string>();   // dernière erreur par domaine (mémoire seulement)

        /// <summary>Erreur de la dernière recherche de ce domaine (service injoignable, refus…), ou "".</summary>
        public static string ErrorFor(string domain)
        {
            string e;
            lock (Sync) return errors.TryGetValue((domain ?? "").ToLowerInvariant(), out e) ? e : "";
        }

        static string CachePath { get { return Path.Combine(Blocklists.DataDir, "domaines-age.txt"); } }

        static void EnsureLoaded()
        {
            if (loaded) return;
            loaded = true;
            try
            {
                if (!File.Exists(CachePath)) return;
                foreach (var line in File.ReadAllLines(CachePath, Encoding.UTF8))
                {
                    var p = line.Split(';');
                    if (p.Length < 3) continue;
                    DateTime created, chk;
                    DateTime? c = null;
                    if (DateTime.TryParse(p[1], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out created)) c = created;
                    if (!DateTime.TryParse(p[2], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out chk)) chk = DateTime.MinValue;
                    known[p[0]] = c;
                    checkedOn[p[0]] = chk;
                }
            }
            catch (Exception) { }
        }

        /// <summary>true si la recherche a déjà été faite ; created vaut null si la date est inconnue.</summary>
        public static bool TryGetCreated(string domain, out DateTime? created)
        {
            created = null;
            string d = (domain ?? "").ToLowerInvariant();
            lock (Sync)
            {
                EnsureLoaded();
                if (!known.ContainsKey(d)) return false;
                created = known[d];
                // une date inconnue est retentée après 7 jours
                DateTime chk;
                if (!created.HasValue && checkedOn.TryGetValue(d, out chk) && chk < DateTime.UtcNow.AddDays(-7)) return false;
                return true;
            }
        }

        public static void Request(string domain)
        {
            if (!Enabled) return;
            Request(domain, false);
        }

        /// <summary>Recherche demandée d'un clic (onglet Réputation) : faite même si l'option automatique est désactivée,
        /// et retentée si la date était restée inconnue.</summary>
        public static void Fetch(string domain)
        {
            Request(domain, true);
        }

        public static bool IsPending(string domain)
        {
            lock (Sync) return pending.Contains((domain ?? "").ToLowerInvariant());
        }

        /// <summary>Domaines enregistrés du message, avec leur rôle : expéditeur, réponse, liens (8 au plus).</summary>
        public static List<KeyValuePair<string, string>> DomainsOf(EmailData e)
        {
            var res = new List<KeyValuePair<string, string>>();
            var seen = new HashSet<string>();
            Action<string, string> add = (host, role) =>
            {
                string h = (host ?? "").Trim().ToLowerInvariant();
                if (h.Length < 4 || !h.Contains(".") || Domains.IsIpHost(h)) return;
                string reg = Domains.RegistrableDomain(h);
                if (string.IsNullOrEmpty(reg) || !seen.Add(reg)) return;
                res.Add(new KeyValuePair<string, string>(reg, role));
            };
            if (e == null) return res;
            add(Domains.DomainOfAddress(e.FromAddress), L.T("Expéditeur"));
            foreach (var rt in e.ReplyTo) add(Domains.DomainOfAddress(rt), L.T("Adresse de réponse"));
            int links = 0;
            foreach (var l in e.Links)
            {
                if (links >= 8) break;
                Uri u;
                if (!Uri.TryCreate(l.Href ?? "", UriKind.Absolute, out u) || (u.Scheme != "http" && u.Scheme != "https")) continue;
                int before = res.Count;
                add(Domains.HostOf(u), L.T("Lien"));
                if (res.Count > before) links++;
            }
            return res;
        }

        static void Request(string domain, bool force)
        {
            string d = (domain ?? "").ToLowerInvariant();
            if (d.Length < 4 || !d.Contains(".") || Domains.IsIpHost(d)) return;
            lock (Sync)
            {
                EnsureLoaded();
                if (pending.Contains(d)) return;
                DateTime? c;
                if (known.TryGetValue(d, out c) && (c.HasValue || (!force && checkedOn.ContainsKey(d) && checkedOn[d] > DateTime.UtcNow.AddDays(-7)))) return;
                pending.Add(d);
                if (force) forced.Add(d);
                queue.Enqueue(d);
                if (worker) return;
                worker = true;
            }
            var t = new Thread(Work) { IsBackground = true, Name = "PhishGuard RDAP" };
            t.Start();
        }

        static void Work()
        {
            while (true)
            {
                string d;
                lock (Sync)
                {
                    while (true)
                    {
                        if (queue.Count == 0) { worker = false; return; }
                        d = queue.Dequeue();
                        // Recherche automatique désactivée entre-temps : les demandes en attente sont abandonnées
                        if (Enabled || forced.Contains(d)) break;
                        pending.Remove(d);
                    }
                    forced.Remove(d);
                }
                DateTime? created = null;
                string error = "";
                try { created = Lookup(d); LastError = ""; }
                catch (Exception ex) { error = ex.Message; LastError = d + " : " + ex.Message; }
                lock (Sync)
                {
                    known[d] = created;
                    checkedOn[d] = DateTime.UtcNow;
                    pending.Remove(d);
                    if (error.Length > 0) errors[d] = error; else errors.Remove(d);
                }
                // Une erreur (réseau, refus) n'est pas mémorisée sur le disque : elle sera retentée à la prochaine session ou d'un clic
                if (error.Length == 0) try
                {
                    Directory.CreateDirectory(Blocklists.DataDir);
                    File.AppendAllText(CachePath, d + ";" + (created.HasValue ? created.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : "?")
                        + ";" + DateTime.UtcNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + Environment.NewLine, Encoding.UTF8);
                }
                catch (Exception) { }
                Version++;
                Changed = true;
                Thread.Sleep(1500); // politesse envers le service
            }
        }

        static readonly Regex RegistrationEvent = new Regex(@"\{[^{}]*""eventAction""\s*:\s*""registration""[^{}]*\}", RegexOptions.IgnoreCase);
        static readonly Regex EventDate = new Regex(@"""eventDate""\s*:\s*""([^""]+)""", RegexOptions.IgnoreCase);

        public static DateTime? ParseRdap(string json)
        {
            var m = RegistrationEvent.Match(json ?? "");
            if (!m.Success) return null;
            var dm = EventDate.Match(m.Value);
            DateTime dt;
            if (dm.Success && DateTime.TryParse(dm.Groups[1].Value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out dt)) return dt;
            return null;
        }

        // ---- Annuaire officiel des serveurs RDAP (IANA) : chaque registre est interrogé directement ----
        // rdap.org, simple aiguillage, sert de secours : il est derrière Cloudflare (10 requêtes / 10 s, blocages possibles).
        static Dictionary<string, string> bootstrap;
        static DateTime bootstrapTried = DateTime.MinValue;
        static string BootstrapPath { get { return Path.Combine(Blocklists.DataDir, "rdap-dns.json"); } }

        /// <summary>Lit l'annuaire IANA (dns.json) : extension → adresse du serveur RDAP du registre.</summary>
        public static Dictionary<string, string> ParseBootstrap(string json)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var root = new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.DeserializeObject(json ?? "") as Dictionary<string, object>;
            object services;
            if (root == null || !root.TryGetValue("services", out services) || !(services is object[])) return map;
            foreach (var s in (object[])services)
            {
                var pair = s as object[];
                if (pair == null || pair.Length < 2) continue;
                var tlds = pair[0] as object[]; var urls = pair[1] as object[];
                if (tlds == null || urls == null) continue;
                string url = null;
                foreach (var u in urls) { string su = u as string; if (su != null && su.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) { url = su; break; } }
                if (url == null) continue;
                foreach (var t in tlds) { string st = t as string; if (!string.IsNullOrEmpty(st) && !map.ContainsKey(st)) map[st] = url; }
            }
            return map;
        }

        static string RegistryUrl(string domain)
        {
            int dot = domain.LastIndexOf('.');
            if (dot < 0) return null;
            string tld = domain.Substring(dot + 1);
            // Appelé seulement par le fil de recherche : le téléchargement se fait hors du verrou (l'interface n'attend jamais)
            var map = bootstrap;
            if (map == null)
            {
                try
                {
                    if (File.Exists(BootstrapPath) && File.GetLastWriteTimeUtc(BootstrapPath) > DateTime.UtcNow.AddDays(-30))
                        map = ParseBootstrap(File.ReadAllText(BootstrapPath, Encoding.UTF8));
                }
                catch (Exception) { }
            }
            if ((map == null || map.Count == 0) && bootstrapTried < DateTime.UtcNow.AddHours(-1))
            {
                bootstrapTried = DateTime.UtcNow;
                try
                {
                    string json = Get("https://data.iana.org/rdap/dns.json", "application/json");
                    var fresh = ParseBootstrap(json);
                    if (fresh.Count > 0)
                    {
                        map = fresh;
                        try { Directory.CreateDirectory(Blocklists.DataDir); File.WriteAllText(BootstrapPath, json, Encoding.UTF8); } catch (Exception) { }
                    }
                }
                catch (Exception) { }
            }
            if (map != null && map.Count > 0) bootstrap = map;
            string url;
            return map != null && map.TryGetValue(tld, out url) ? url : null;
        }

        static string Get(string url, string accept)
        {
            ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; // TLS 1.2
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Proxy = WebRequest.GetSystemWebProxy();
            req.Proxy.Credentials = CredentialCache.DefaultCredentials;
            req.Accept = accept;
            req.UserAgent = "PhishGuard-Outlook/1.0";
            req.Timeout = 15000;
            req.ReadWriteTimeout = 15000;
            req.AllowAutoRedirect = true;
            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var reader = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                return reader.ReadToEnd();
        }

        /// <summary>Registre du domaine d'abord (annuaire IANA), rdap.org en secours.</summary>
        static DateTime? Lookup(string domain)
        {
            string registry = RegistryUrl(domain);
            if (registry != null)
            {
                try { return LookupAt(registry.TrimEnd('/') + "/domain/" + Uri.EscapeDataString(domain)); }
                catch (WebException ex)
                {
                    var r = ex.Response as HttpWebResponse;
                    if (r != null && (int)r.StatusCode == 404) return null;   // domaine inconnu du registre
                    // registre injoignable : essai par rdap.org
                }
            }
            return LookupAt("https://rdap.org/domain/" + Uri.EscapeDataString(domain));
        }

        static DateTime? LookupAt(string url)
        {
            ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; // TLS 1.2
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Proxy = WebRequest.GetSystemWebProxy();
            req.Proxy.Credentials = CredentialCache.DefaultCredentials;
            req.Accept = "application/rdap+json, application/json";
            req.UserAgent = "PhishGuard-Outlook/1.0";
            req.Timeout = 15000;
            req.ReadWriteTimeout = 15000;
            req.AllowAutoRedirect = true;
            try
            {
                using (var resp = (HttpWebResponse)req.GetResponse())
                using (var reader = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                    return ParseRdap(reader.ReadToEnd());
            }
            catch (WebException ex)
            {
                var r = ex.Response as HttpWebResponse;
                if (r != null && (int)r.StatusCode == 404) return null; // domaine inconnu du registre
                throw;
            }
        }

        /// <summary>Pour les tests.</summary>
        public static void SetForTests(string domain, DateTime? created)
        {
            lock (Sync) { loaded = true; known[domain.ToLowerInvariant()] = created; checkedOn[domain.ToLowerInvariant()] = DateTime.UtcNow; }
        }

        public static void ClearForTests()
        {
            lock (Sync) { loaded = true; known.Clear(); checkedOn.Clear(); }
        }
    }
}
