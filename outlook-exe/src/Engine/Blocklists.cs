// PhishGuard - listes de domaines malveillants (Red Flag Domains + liste interne).
// La liste Red Flag Domains est téléchargée au démarrage d'Outlook si elle a plus de 24 h,
// avec le proxy et les certificats de Windows (compatible avec l'inspection HTTPS des entreprises).

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace PhishGuard
{
    public class BlocklistHit
    {
        public string Domain;
        public string SourceId;
        public string SourceName;
        public Severity Severity;
        public DateTime Updated;
    }

    public static class Blocklists
    {
        static readonly object Sync = new object();
        static HashSet<string> redFlag = new HashSet<string>();
        static DateTime redFlagUpdated = DateTime.MinValue;
        static HashSet<string> custom = new HashSet<string>();
        static bool downloading;

        public static string LastError = "";

        public static string DataDir
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhishGuard"); }
        }

        static string RedFlagCache { get { return Path.Combine(DataDir, "redflagdomains.txt"); } }

        public static int RedFlagCount { get { lock (Sync) return redFlag.Count; } }
        public static DateTime RedFlagUpdated { get { lock (Sync) return redFlagUpdated; } }
        public static int CustomCount { get { lock (Sync) return custom.Count; } }

        static readonly Regex DomainRe = new Regex(@"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(xn--[a-z0-9-]{2,59}|[a-z]{2,63})$");

        /// <summary>Un domaine par ligne ; ignore commentaires et en-têtes ; accepte le format hosts et AdGuard.</summary>
        public static HashSet<string> ParseList(string text)
        {
            var set = new HashSet<string>();
            foreach (var raw in (text ?? "").Split('\n'))
            {
                string line = Regex.Replace(raw, "[#!;].*$", "").Trim().ToLowerInvariant();
                if (line.Length == 0) continue;
                var parts = Regex.Split(line, @"\s+");
                string d = parts.Length > 1 && Regex.IsMatch(parts[0], @"^(0\.0\.0\.0|127\.0\.0\.1|::1?)$") ? parts[1] : parts[0];
                d = Regex.Replace(d, @"^\|\||\^$", "");
                if (d.StartsWith("*.")) d = d.Substring(2);
                d = d.TrimEnd('.');
                if (DomainRe.IsMatch(d)) set.Add(d);
            }
            return set;
        }

        static string installDirCache;

        /// <summary>Liste partagée sur le réseau (ex. \\serveur\partage\phishguard.txt), gérée par l'équipe sécurité.</summary>
        public static string SharedPath = "";

        /// <summary>Liste interne de l'utilisateur (modifiable depuis Outlook).</summary>
        public static string UserCustomPath { get { return Path.Combine(DataDir, "custom.user.txt"); } }

        /// <summary>Recharge la liste interne : celle de l'administrateur (custom.txt) + celle de l'utilisateur.</summary>
        public static void ReloadCustom()
        {
            var c = new HashSet<string>();
            foreach (var f in new[] { Path.Combine(installDirCache ?? DataDir, "custom.txt"), UserCustomPath, SharedPath })
            {
                if (string.IsNullOrEmpty(f)) continue;
                try { if (File.Exists(f)) c.UnionWith(ParseList(File.ReadAllText(f, Encoding.UTF8))); } catch (Exception) { }
            }
            lock (Sync) custom = c;
        }

        public static void ClearRedFlag()
        {
            lock (Sync) { redFlag = new HashSet<string>(); redFlagUpdated = DateTime.MinValue; }
        }

        public static bool IsDownloading { get { lock (Sync) return downloading; } }

        /// <summary>Charge les listes locales puis, si besoin, lance le téléchargement en arrière-plan.</summary>
        public static void Init(PhishGuardConfig cfg, string installDir)
        {
            try { Directory.CreateDirectory(DataDir); } catch (Exception) { }

            installDirCache = installDir;
            ReloadCustom();

            if (!cfg.RedFlagEnabled) return;
            try
            {
                if (File.Exists(RedFlagCache))
                {
                    var set = ParseList(File.ReadAllText(RedFlagCache, Encoding.UTF8));
                    lock (Sync) { redFlag = set; redFlagUpdated = File.GetLastWriteTime(RedFlagCache); }
                }
            }
            catch (Exception ex) { LastError = ex.Message; }

            if (RedFlagUpdated < DateTime.Now.AddHours(-cfg.RedFlagMaxAgeHours))
                StartDownload(cfg.RedFlagUrl);
        }

        public static void StartDownload(string url)
        {
            lock (Sync) { if (downloading) return; downloading = true; }
            var t = new Thread(() =>
            {
                try { Download(url); LastError = ""; }
                catch (Exception ex) { LastError = ex.Message; }
                finally { lock (Sync) downloading = false; }
            });
            t.IsBackground = true;
            t.Start();
        }

        static void Download(string url)
        {
            ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; // TLS 1.2
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Proxy = WebRequest.GetSystemWebProxy();
            req.Proxy.Credentials = CredentialCache.DefaultCredentials;
            req.UserAgent = "PhishGuard-Outlook/1.0";
            req.Timeout = 60000;
            req.ReadWriteTimeout = 60000;
            string text;
            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var reader = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                text = reader.ReadToEnd();

            var set = ParseList(text);
            if (set.Count < 10) throw new Exception(L.F("liste anormalement courte ({0})", set.Count));
            string tmp = RedFlagCache + ".tmp";
            File.WriteAllText(tmp, text, Encoding.UTF8);
            if (File.Exists(RedFlagCache)) File.Delete(RedFlagCache);
            File.Move(tmp, RedFlagCache);
            lock (Sync) { redFlag = set; redFlagUpdated = DateTime.Now; }
        }

        /// <summary>Pour les tests : remplace les listes en mémoire.</summary>
        public static void SetForTests(IEnumerable<string> redFlagDomains, IEnumerable<string> customDomains)
        {
            lock (Sync)
            {
                redFlag = new HashSet<string>(redFlagDomains ?? new string[0]);
                custom = new HashSet<string>(customDomains ?? new string[0]);
                redFlagUpdated = DateTime.Now;
            }
        }

        /// <summary>Cherche le nom d'hôte puis chaque domaine parent : a.b.evil.fr → b.evil.fr → evil.fr.</summary>
        public static BlocklistHit Lookup(string host)
        {
            var p = Domains.ParseHost(host);
            if (p == null) return null;
            HashSet<string> rf, cu;
            DateTime upd;
            lock (Sync) { rf = redFlag; cu = custom; upd = redFlagUpdated; }

            var labels = p.Host.Split('.');
            int minLabels = p.Registrable.Split('.').Length;
            for (int i = 0; labels.Length - i >= minLabels; i++)
            {
                string cand = string.Join(".", labels, i, labels.Length - i);
                if (cu.Contains(cand))
                    return new BlocklistHit { Domain = cand, SourceId = "custom", SourceName = "Liste interne de l’équipe sécurité", Severity = Severity.Critical, Updated = DateTime.Now };
                if (rf.Contains(cand))
                    return new BlocklistHit { Domain = cand, SourceId = "redflagdomains", SourceName = "Red Flag Domains", Severity = Severity.High, Updated = upd };
            }
            return null;
        }
    }
}
