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

namespace PhishGuard
{
    public static class DomainAge
    {
        static readonly object Sync = new object();
        static readonly Dictionary<string, DateTime?> known = new Dictionary<string, DateTime?>();
        static readonly Dictionary<string, DateTime> checkedOn = new Dictionary<string, DateTime>();
        static readonly Queue<string> queue = new Queue<string>();
        static readonly HashSet<string> pending = new HashSet<string>();
        static bool worker;
        static bool loaded;

        /// <summary>Passe à true quand une nouvelle date est connue (le complément relance alors l'analyse affichée).</summary>
        public static volatile bool Changed;
        public static bool Enabled = true;
        public static string LastError = "";

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

        /// <summary>Date de création, en attendant la réponse si besoin (analyse approfondie, hors du fil d'Outlook).</summary>
        public static DateTime? LookupNow(string domain, out bool ok)
        {
            ok = true;
            DateTime? created;
            if (TryGetCreated(domain, out created)) return created;
            string d = (domain ?? "").ToLowerInvariant();
            try { created = Lookup(d); LastError = ""; }
            catch (Exception ex) { LastError = ex.Message; ok = false; return null; }
            lock (Sync) { EnsureLoaded(); known[d] = created; checkedOn[d] = DateTime.UtcNow; }
            try
            {
                Directory.CreateDirectory(Blocklists.DataDir);
                File.AppendAllText(CachePath, d + ";" + (created.HasValue ? created.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : "?")
                    + ";" + DateTime.UtcNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + Environment.NewLine, Encoding.UTF8);
            }
            catch (Exception) { }
            Changed = true;
            return created;
        }

        public static void Request(string domain)
        {
            if (!Enabled) return;
            string d = (domain ?? "").ToLowerInvariant();
            if (d.Length < 4 || !d.Contains(".") || Domains.IsIpHost(d)) return;
            lock (Sync)
            {
                EnsureLoaded();
                if (pending.Contains(d)) return;
                DateTime? c;
                if (known.TryGetValue(d, out c) && (c.HasValue || (checkedOn.ContainsKey(d) && checkedOn[d] > DateTime.UtcNow.AddDays(-7)))) return;
                pending.Add(d);
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
                    if (queue.Count == 0) { worker = false; return; }
                    d = queue.Dequeue();
                }
                DateTime? created = null;
                try { created = Lookup(d); LastError = ""; }
                catch (Exception ex) { LastError = ex.Message; }
                lock (Sync)
                {
                    known[d] = created;
                    checkedOn[d] = DateTime.UtcNow;
                    pending.Remove(d);
                }
                try
                {
                    Directory.CreateDirectory(Blocklists.DataDir);
                    File.AppendAllText(CachePath, d + ";" + (created.HasValue ? created.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : "?")
                        + ";" + DateTime.UtcNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + Environment.NewLine, Encoding.UTF8);
                }
                catch (Exception) { }
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

        static DateTime? Lookup(string domain)
        {
            ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; // TLS 1.2
            var req = (HttpWebRequest)WebRequest.Create("https://rdap.org/domain/" + Uri.EscapeDataString(domain));
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
