// PhishGuard - avertissement de nouvelle version.
// Une fois par jour au plus, en arrière-plan : demande à GitHub le numéro de la dernière version publiée.
// Rien n'est envoyé (ni version installée, ni identifiant) : une simple lecture de la page publique des versions.
// Rien n'est téléchargé ni installé : l'utilisateur est seulement prévenu.

using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace PhishGuard
{
    public static class Updates
    {
        public static volatile string LatestTag = "";
        public static volatile string LatestUrl = "";
        public static string LastError = "";
        public static DateTime CheckedOn = DateTime.MinValue;
        static bool loaded;
        static int running;

        static string CachePath { get { return Path.Combine(Blocklists.DataDir, "derniere-version.txt"); } }

        static void EnsureLoaded()
        {
            if (loaded) return;
            loaded = true;
            try
            {
                if (!File.Exists(CachePath)) return;
                var p = File.ReadAllText(CachePath, Encoding.UTF8).Trim().Split(';');
                if (p.Length < 3) return;
                LatestTag = p[0]; LatestUrl = p[1];
                DateTime d;
                if (DateTime.TryParse(p[2], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out d)) CheckedOn = d;
            }
            catch (Exception) { }
        }

        /// <summary>« v1.18.7 » → 1.18.7 ; null si ce n'est pas un numéro de version.</summary>
        public static Version Parse(string tag)
        {
            var m = Regex.Match(tag ?? "", @"^\s*v?(\d+)\.(\d+)(?:\.(\d+))?\s*$", RegexOptions.IgnoreCase);
            if (!m.Success) return null;
            return new Version(int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value), m.Groups[3].Success ? int.Parse(m.Groups[3].Value) : 0);
        }

        /// <summary>true si la dernière version connue est plus récente que la version installée (jamais pour une version de développement).</summary>
        public static bool IsNewer(string latest, string installed)
        {
            var a = Parse(latest); var b = Parse(installed);
            return a != null && b != null && a > b;
        }

        public static bool UpdateAvailable(string installed)
        {
            EnsureLoaded();
            return IsNewer(LatestTag, installed);
        }

        /// <summary>Vérification demandée d'un clic : bloquante (à appeler hors du fil de l'interface). Renvoie "" ou l'erreur.</summary>
        public static string CheckNow(string repository)
        {
            EnsureLoaded();
            try { Check(repository); LastError = ""; }
            catch (Exception ex) { LastError = ex.Message; }
            CheckedOn = DateTime.UtcNow;
            Save();
            return LastError;
        }

        /// <summary>Vérification en arrière-plan si la dernière date de plus de 24 h (ou si force).</summary>
        public static void CheckAsync(string repository, bool force)
        {
            EnsureLoaded();
            if (!force && CheckedOn > DateTime.UtcNow.AddHours(-24)) return;
            if (Interlocked.CompareExchange(ref running, 1, 0) != 0) return;
            new Thread(() =>
            {
                try { Check(repository); LastError = ""; }
                catch (Exception ex) { LastError = ex.Message; }
                finally { CheckedOn = DateTime.UtcNow; Save(); running = 0; }
            }) { IsBackground = true, Name = "PhishGuard mise à jour" }.Start();
        }

        static readonly Regex TagRe = new Regex("\"tag_name\"\\s*:\\s*\"([^\"]{1,40})\"");
        static readonly Regex UrlRe = new Regex("\"html_url\"\\s*:\\s*\"(https://github\\.com/[^\"]{1,200}/releases/tag/[^\"]{1,40})\"");

        /// <summary>Lecture de la réponse de l'API GitHub (dernière version publiée).</summary>
        public static bool ParseRelease(string json, out string tag, out string url)
        {
            tag = ""; url = "";
            var t = TagRe.Match(json ?? "");
            if (!t.Success || Parse(t.Groups[1].Value) == null) return false;
            tag = t.Groups[1].Value;
            var u = UrlRe.Match(json);
            url = u.Success ? u.Groups[1].Value : "";
            return true;
        }

        static void Check(string repository)
        {
            // https://github.com/proprietaire/depot → https://api.github.com/repos/proprietaire/depot/releases/latest
            var m = Regex.Match(repository ?? "", @"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/?$");
            if (!m.Success) return;
            ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; // TLS 1.2
            var req = (HttpWebRequest)WebRequest.Create("https://api.github.com/repos/" + m.Groups[1].Value + "/" + m.Groups[2].Value + "/releases/latest");
            req.Proxy = WebRequest.GetSystemWebProxy();
            req.Proxy.Credentials = CredentialCache.DefaultCredentials;
            req.Accept = "application/vnd.github+json";
            req.UserAgent = "PhishGuard-Outlook";
            req.Timeout = 15000;
            req.ReadWriteTimeout = 15000;
            string json;
            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var reader = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
            {
                var buf = new char[200000];
                int n = reader.ReadBlock(buf, 0, buf.Length);   // la description de la version peut être longue : le début suffit
                json = new string(buf, 0, n);
            }
            string tag, url;
            if (!ParseRelease(json, out tag, out url)) throw new Exception(L.T("réponse de GitHub illisible"));
            LatestTag = tag;
            LatestUrl = url.Length > 0 ? url : repository.TrimEnd('/') + "/releases/latest";
        }

        static void Save()
        {
            try
            {
                Directory.CreateDirectory(Blocklists.DataDir);
                File.WriteAllText(CachePath, LatestTag + ";" + LatestUrl + ";" + CheckedOn.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture), Encoding.UTF8);
            }
            catch (Exception) { }
        }
    }
}
