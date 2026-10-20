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
        static readonly HashSet<string> forced = new HashSet<string>();   // demandés d'un clic : faits même si la recherche automatique est coupée
        static bool worker;
        static bool loaded;

        /// <summary>Passe à true quand une nouvelle date est connue (le complément relance alors l'analyse affichée).</summary>
        public static volatile bool Changed;
        /// <summary>Augmente à chaque date reçue : la fenêtre d'analyse se redessine même si le verdict ne change pas.</summary>
        public static volatile int Version;
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
