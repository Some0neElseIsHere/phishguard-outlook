// PhishGuard - décodage des liens réécrits par les passerelles de sécurité
// (Proofpoint URL Defense, Safe Links, Barracuda, Sophos, Trend Micro, FortiMail...).
// Ces services remplacent chaque lien par le leur pour le contrôler au clic :
// il faut retrouver la vraie destination avant de l'analyser.

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace PhishGuard
{
    public static class Rewriters
    {
        public class Result
        {
            /// <summary>Nom du service (ex. « Proofpoint »).</summary>
            public string Service;
            /// <summary>Vraie destination, ou null si le service ne la laisse pas lire.</summary>
            public string Target;
        }

        const string RunValues = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        static bool HostIs(string host, string domain)
        {
            return host == domain || host.EndsWith("." + domain);
        }

        /// <summary>
        /// Renvoie null si le lien n'est pas réécrit par un service de sécurité connu.
        /// </summary>
        public static Result Decode(Uri url, string host, Func<Uri, string, string> queryParam)
        {
            string raw = url.OriginalString;
            string path = url.AbsolutePath;

            // Proofpoint URL Defense
            if (HostIs(host, "urldefense.com") || HostIs(host, "urldefense.proofpoint.com") || HostIs(host, "urldefense.us"))
            {
                string target = null;
                if (raw.IndexOf("/v3/__", StringComparison.Ordinal) >= 0) target = ProofpointV3(raw);
                else if (path.StartsWith("/v2/", StringComparison.Ordinal)) target = ProofpointV2(RawQueryParam(url, "u"));
                else if (path.StartsWith("/v1/", StringComparison.Ordinal)) target = queryParam(url, "u");
                return new Result { Service = "Proofpoint", Target = target };
            }

            // Microsoft Defender Safe Links
            if (host.EndsWith("safelinks.protection.outlook.com"))
                return new Result { Service = "Safe Links", Target = queryParam(url, "url") };

            // Barracuda Link Protection
            if (HostIs(host, "linkprotect.cudasvc.com"))
                return new Result { Service = "Barracuda", Target = queryParam(url, "a") };

            // Sophos Time-of-Click (paramètre u en base64)
            if (host.EndsWith("protection.sophos.com"))
            {
                string u = queryParam(url, "u");
                string target = null;
                if (u != null)
                {
                    if (Regex.IsMatch(u, "^https?://", RegexOptions.IgnoreCase)) target = u;
                    else
                    {
                        byte[] b = FromBase64(u);
                        if (b != null) target = Encoding.UTF8.GetString(b);
                    }
                }
                return new Result { Service = "Sophos", Target = target };
            }

            // Trend Micro Time-of-Click
            if (HostIs(host, "trendmicro.com") && path.IndexOf("/clicktime/", StringComparison.OrdinalIgnoreCase) >= 0)
                return new Result { Service = "Trend Micro", Target = queryParam(url, "url") };

            // Symantec / Broadcom Click-time
            if (HostIs(host, "clicktime.symantec.com"))
                return new Result { Service = "Symantec", Target = queryParam(url, "u") };

            // FortiMail (réécriture faite par votre propre FortiMail, nom d'hôte variable)
            if (path.IndexOf("/fmlurlsvc", StringComparison.OrdinalIgnoreCase) >= 0)
                return new Result { Service = "FortiMail", Target = queryParam(url, "url") };

            // Services qui ne laissent pas lire la destination
            if (Regex.IsMatch(host, @"^protect(-[a-z0-9]+)?\.mimecast\.com$") || HostIs(host, "mimecastprotect.com"))
                return new Result { Service = "Mimecast", Target = null };
            if (HostIs(host, "secure-web.cisco.com"))
                return new Result { Service = "Cisco", Target = null };

            return null;
        }

        /// <summary>Valeur brute (non décodée) d'un paramètre de la requête.</summary>
        static string RawQueryParam(Uri u, string name)
        {
            string q = u.Query;
            if (q.StartsWith("?")) q = q.Substring(1);
            foreach (var pair in q.Split('&'))
            {
                int i = pair.IndexOf('=');
                string k = i >= 0 ? pair.Substring(0, i) : pair;
                if (string.Equals(k, name, StringComparison.OrdinalIgnoreCase)) return i >= 0 ? pair.Substring(i + 1) : "";
            }
            return null;
        }

        /// <summary>v2 : u=https-3A__www.exemple.fr_chemin (« - » remplace « % », « _ » remplace « / »).</summary>
        public static string ProofpointV2(string u)
        {
            if (string.IsNullOrEmpty(u)) return null;
            try { return Uri.UnescapeDataString(u.Replace('-', '%').Replace('_', '/')); }
            catch (Exception) { return null; }
        }

        /// <summary>
        /// v3 : https://urldefense.com/v3/__https://www.exemple.fr/chemin__;JSU!!jeton$
        /// Les caractères retirés sont remplacés par « * » (ou « **X » pour une suite) et listés
        /// en base64 après « __; ».
        /// </summary>
        public static string ProofpointV3(string raw)
        {
            var m = Regex.Match(raw, @"/v3/__(.+?)__;([^!]*)!");
            if (!m.Success) return null;
            string enc = m.Groups[1].Value;
            var chars = new List<string>();
            if (m.Groups[2].Value.Length > 0)
            {
                byte[] b = FromBase64(m.Groups[2].Value);
                if (b == null) return null;
                string s = Encoding.UTF8.GetString(b);
                for (int i = 0; i < s.Length; i++)
                {
                    if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length) { chars.Add(s.Substring(i, 2)); i++; }
                    else chars.Add(s[i].ToString());
                }
            }
            var sb = new StringBuilder();
            int next = 0;
            for (int i = 0; i < enc.Length; i++)
            {
                if (enc[i] != '*') { sb.Append(enc[i]); continue; }
                int count = 1;
                if (i + 2 < enc.Length && enc[i + 1] == '*')
                {
                    int r = RunValues.IndexOf(enc[i + 2]);
                    if (r < 0) return null;
                    count = r + 2;
                    i += 2;
                }
                for (int k = 0; k < count; k++)
                {
                    if (next >= chars.Count) return null;
                    sb.Append(chars[next++]);
                }
            }
            return sb.ToString();
        }

        static byte[] FromBase64(string s)
        {
            string t = s.Trim().Replace('-', '+').Replace('_', '/');
            while (t.Length % 4 != 0) t += "=";
            try { return Convert.FromBase64String(t); }
            catch (FormatException) { return null; }
        }
    }
}
