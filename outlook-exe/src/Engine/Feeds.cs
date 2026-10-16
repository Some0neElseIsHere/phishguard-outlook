// PhishGuard - listes publiques téléchargées (bêta, sans clé) :
// - OpenPhish (flux communautaire) : adresses de pages de phishing actives, mis à jour toutes les 12 h ;
// - Tranco : classement des sites les plus visités (100 000 premiers), mis à jour chaque semaine,
//   pour reconnaître les domaines très fréquentés et limiter les faux positifs.
// Les fichiers sont gardés dans %LOCALAPPDATA%\PhishGuard ; seul le téléchargement passe par le réseau.

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Text;
using System.Threading;

namespace PhishGuard
{
    public static class Feeds
    {
        static readonly object Sync = new object();
        static HashSet<string> phishUrls = new HashSet<string>();
        static HashSet<string> phishHosts = new HashSet<string>();
        static Dictionary<string, int> tranco = new Dictionary<string, int>();
        static DateTime openPhishUpdated = DateTime.MinValue, trancoUpdated = DateTime.MinValue;
        static bool downloadingOpenPhish, downloadingTranco;

        public static bool OpenPhishEnabled, TrancoEnabled;
        public static string LastError = "";
        public static volatile bool Changed;

        public const string OpenPhishUrl = "https://openphish.com/feed.txt";
        public const string TrancoUrl = "https://tranco-list.eu/top-1m.csv.zip";
        const int TrancoKeep = 100000;

        static string OpenPhishPath { get { return Path.Combine(Blocklists.DataDir, "openphish.txt"); } }
        static string TrancoPath { get { return Path.Combine(Blocklists.DataDir, "tranco.txt"); } }

        public static int OpenPhishCount { get { lock (Sync) return phishUrls.Count; } }
        public static int TrancoCount { get { lock (Sync) return tranco.Count; } }
        public static DateTime OpenPhishUpdated { get { lock (Sync) return openPhishUpdated; } }
        public static DateTime TrancoUpdated { get { lock (Sync) return trancoUpdated; } }

        /// <summary>Charge les fichiers déjà téléchargés et met à jour ceux qui sont trop anciens.</summary>
        public static void Init(bool openPhish, bool trancoOn)
        {
            OpenPhishEnabled = openPhish;
            TrancoEnabled = trancoOn;
            if (!openPhish) lock (Sync) { phishUrls = new HashSet<string>(); phishHosts = new HashSet<string>(); }
            if (!trancoOn) lock (Sync) tranco = new Dictionary<string, int>();

            if (openPhish)
            {
                try { if (File.Exists(OpenPhishPath) && OpenPhishCount == 0) LoadOpenPhish(File.ReadAllText(OpenPhishPath, Encoding.UTF8), File.GetLastWriteTime(OpenPhishPath)); }
                catch (Exception ex) { LastError = ex.Message; }
                if (OpenPhishUpdated < DateTime.Now.AddHours(-12)) StartDownload(true);
            }
            if (trancoOn)
            {
                try { if (File.Exists(TrancoPath) && TrancoCount == 0) LoadTranco(File.ReadAllLines(TrancoPath, Encoding.UTF8), File.GetLastWriteTime(TrancoPath)); }
                catch (Exception ex) { LastError = ex.Message; }
                if (TrancoUpdated < DateTime.Now.AddDays(-7)) StartDownload(false);
            }
        }

        // -----------------------------------------------------------------
        // Consultation
        // -----------------------------------------------------------------

        /// <summary>Forme normalisée d'une adresse pour la comparaison (sans « / » final, schéma et hôte en minuscules).</summary>
        public static string NormalizeUrl(string url)
        {
            Uri u;
            if (!Uri.TryCreate((url ?? "").Trim(), UriKind.Absolute, out u)) return (url ?? "").Trim().TrimEnd('/');
            string s = u.Scheme.ToLowerInvariant() + "://" + u.Host.ToLowerInvariant() + (u.IsDefaultPort ? "" : ":" + u.Port) + u.PathAndQuery;
            return s.TrimEnd('/');
        }

        /// <summary>"url" si l'adresse exacte est listée, "host" si le serveur héberge des pages listées, sinon null.</summary>
        public static string OpenPhishMatch(string url)
        {
            if (!OpenPhishEnabled) return null;
            string n = NormalizeUrl(url);
            Uri u;
            string host = Uri.TryCreate(url, UriKind.Absolute, out u) ? u.Host.ToLowerInvariant() : "";
            lock (Sync)
            {
                if (phishUrls.Count == 0) return null;
                if (phishUrls.Contains(n)) return "url";
                foreach (var p in phishUrls) if (n.StartsWith(p + "/") || n.StartsWith(p + "?")) return "url";
                if (host.Length > 0 && phishHosts.Contains(host)) return "host";
            }
            return null;
        }

        /// <summary>Rang Tranco du domaine (1 = le plus visité), 0 s'il n'est pas dans les 100 000 premiers.</summary>
        public static int TrancoRank(string registrable)
        {
            if (!TrancoEnabled || string.IsNullOrEmpty(registrable)) return 0;
            int r;
            lock (Sync) return tranco.TryGetValue(registrable.ToLowerInvariant(), out r) ? r : 0;
        }

        // -----------------------------------------------------------------
        // Chargement
        // -----------------------------------------------------------------

        public static void LoadOpenPhish(string text, DateTime updated)
        {
            var urls = new HashSet<string>();
            var hosts = new HashSet<string>();
            foreach (var raw in (text ?? "").Split('\n'))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;
                Uri u;
                if (!Uri.TryCreate(line, UriKind.Absolute, out u)) continue;
                urls.Add(NormalizeUrl(line));
                string h = u.Host.ToLowerInvariant();
                // Un hébergeur partagé (sites.google.com, github.io...) n'est pas suspect en soi : seule l'adresse exacte compte
                if (!Domains.IsIpHost(h) && !IsSharedHost(h)) hosts.Add(h);
            }
            lock (Sync) { phishUrls = urls; phishHosts = hosts; openPhishUpdated = updated; }
        }

        static bool IsSharedHost(string host)
        {
            foreach (var d in Lists.AbusedHosting) if (host == d || host.EndsWith("." + d)) return true;
            foreach (var d in Lists.Shorteners) if (host == d || host.EndsWith("." + d)) return true;
            return false;
        }

        /// <summary>Lignes « rang,domaine ».</summary>
        public static void LoadTranco(IEnumerable<string> lines, DateTime updated)
        {
            var map = new Dictionary<string, int>();
            foreach (var raw in lines)
            {
                int i = raw.IndexOf(',');
                if (i <= 0) continue;
                int rank;
                if (!int.TryParse(raw.Substring(0, i), out rank)) continue;
                string d = raw.Substring(i + 1).Trim().ToLowerInvariant();
                if (d.Length > 0 && !map.ContainsKey(d)) map[d] = rank;
                if (map.Count >= TrancoKeep) break;
            }
            lock (Sync) { tranco = map; trancoUpdated = updated; }
        }

        public static void StartDownload(bool openPhish)
        {
            lock (Sync)
            {
                if (openPhish ? downloadingOpenPhish : downloadingTranco) return;
                if (openPhish) downloadingOpenPhish = true; else downloadingTranco = true;
            }
            var t = new Thread(() =>
            {
                try
                {
                    Directory.CreateDirectory(Blocklists.DataDir);
                    if (openPhish) DownloadOpenPhish(); else DownloadTranco();
                    Changed = true;
                }
                catch (Exception ex) { LastError = (openPhish ? "OpenPhish : " : "Tranco : ") + ex.Message; }
                finally { lock (Sync) { if (openPhish) downloadingOpenPhish = false; else downloadingTranco = false; } }
            });
            t.IsBackground = true;
            t.Start();
        }

        static HttpWebRequest Request(string url)
        {
            ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; // TLS 1.2
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Proxy = WebRequest.GetSystemWebProxy();
            req.Proxy.Credentials = CredentialCache.DefaultCredentials;
            req.UserAgent = "PhishGuard-Outlook/1.0";
            req.Timeout = 120000;
            req.ReadWriteTimeout = 120000;
            return req;
        }

        static void DownloadOpenPhish()
        {
            string text;
            using (var resp = (HttpWebResponse)Request(OpenPhishUrl).GetResponse())
            using (var reader = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                text = reader.ReadToEnd();
            if (text.IndexOf("http", StringComparison.OrdinalIgnoreCase) < 0) throw new Exception(L.T("réponse inattendue"));
            File.WriteAllText(OpenPhishPath, text, Encoding.UTF8);
            LoadOpenPhish(text, DateTime.Now);
        }

        static void DownloadTranco()
        {
            var lines = new List<string>();
            using (var resp = (HttpWebResponse)Request(TrancoUrl).GetResponse())
            using (var mem = new MemoryStream())
            {
                resp.GetResponseStream().CopyTo(mem);
                mem.Position = 0;
                using (var zip = new ZipArchive(mem, ZipArchiveMode.Read))
                {
                    if (zip.Entries.Count == 0) throw new Exception(L.T("archive vide"));
                    using (var reader = new StreamReader(zip.Entries[0].Open(), Encoding.UTF8))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null && lines.Count < TrancoKeep) lines.Add(line);
                    }
                }
            }
            if (lines.Count < 1000) throw new Exception(L.F("liste anormalement courte ({0})", lines.Count));
            File.WriteAllLines(TrancoPath, lines, Encoding.UTF8);
            LoadTranco(lines, DateTime.Now);
        }
    }
}
