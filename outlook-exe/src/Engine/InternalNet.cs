// PhishGuard - réseau interne déclaré : serveurs de messagerie, équipements qui envoient des alertes, réseaux des postes.
// Sert à repérer un message « interne » fabriqué depuis un poste du réseau (envoi SMTP direct, sans passer
// par l'authentification de la messagerie). Les noms (FQDN) sont traduits en adresses IP par le DNS de l'entreprise,
// en arrière-plan ; seules les adresses IP vues dans les en-têtes Received sont comparées (un nom annoncé se falsifie).

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;

namespace PhishGuard
{
    public static class InternalNet
    {
        static readonly object Sync = new object();
        static readonly Dictionary<string, string[]> resolved = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

        static readonly char[] Blanks = { ' ', '\t' };

        /// <summary>Partie réseau d'une entrée « 10.0.50.12 alertes@entreprise.fr » : l'adresse, la plage ou le nom.</summary>
        public static string NetPart(string entry)
        {
            var parts = (entry ?? "").Trim().Split(Blanks, StringSplitOptions.RemoveEmptyEntries);
            return parts.Length == 0 ? "" : parts[0].TrimEnd('.');
        }

        /// <summary>Adresses d'expéditeur autorisées pour un équipement (après l'adresse IP, séparées par des espaces).</summary>
        public static List<string> SendersOf(string entry)
        {
            return (entry ?? "").Trim().Split(Blanks, StringSplitOptions.RemoveEmptyEntries).Skip(1)
                .Select(x => x.Trim('<', '>', '"').ToLowerInvariant()).Where(x => x.Contains("@")).Distinct().ToList();
        }

        /// <summary>Entrée qui est une adresse IP ou une plage CIDR (sinon : un nom à résoudre).</summary>
        public static bool IsAddress(string entry)
        {
            string e = NetPart(entry);
            int slash = e.IndexOf('/');
            if (slash > 0) e = e.Substring(0, slash);
            IPAddress a;
            return IPAddress.TryParse(e.Trim('[', ']'), out a);
        }

        /// <summary>Traduit en arrière-plan les noms de la liste (DNS de l'entreprise, une fois par session).</summary>
        public static void ResolveAsync(IEnumerable<string> entries)
        {
            var names = (entries ?? Enumerable.Empty<string>()).Select(x => NetPart(x)).Where(x => x.Length > 0 && !IsAddress(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            lock (Sync) names = names.Where(n => !resolved.ContainsKey(n)).ToList();
            if (names.Count == 0) return;
            new Thread(() =>
            {
                foreach (var n in names)
                {
                    string[] ips;
                    try { ips = Dns.GetHostAddresses(n).Select(a => a.ToString()).ToArray(); }
                    catch (Exception) { ips = new string[0]; }
                    lock (Sync) resolved[n] = ips;
                }
            }) { IsBackground = true, Name = "PhishGuard réseau interne" }.Start();
        }

        /// <summary>Adresses et plages de la liste, noms remplacés par leurs adresses IP (si déjà résolus).</summary>
        public static List<string> Expand(IEnumerable<string> entries)
        {
            var res = new List<string>();
            foreach (var raw in entries ?? Enumerable.Empty<string>())
            {
                string e = NetPart(raw);
                if (e.Length == 0) continue;
                if (IsAddress(e)) { res.Add(e); continue; }
                string[] ips;
                lock (Sync) if (resolved.TryGetValue(e, out ips)) res.AddRange(ips);
            }
            return res;
        }

        public static bool Matches(string ip, IEnumerable<string> entries)
        {
            return !string.IsNullOrEmpty(ip) && Forensics.IpInList(ip, Expand(entries));
        }

        /// <summary>L'IP est déclarée une par une (adresse ou nom), et non par une plage.</summary>
        public static bool MatchesExact(string ip, IEnumerable<string> entries)
        {
            var single = (entries ?? Enumerable.Empty<string>()).Where(x => { string s = NetPart(x); return !s.Contains("/") || s.EndsWith("/32") || s.EndsWith("/128"); });
            return Matches(ip, single);
        }

        /// <summary>
        /// L'expéditeur a-t-il le droit d'écrire depuis cet équipement ? Les entrées les plus précises (adresse seule) priment
        /// sur les plages. Une entrée sans adresse d'expéditeur accepte tout expéditeur de l'entreprise (ancien format).
        /// </summary>
        public static bool SenderAllowed(string ip, string from, IEnumerable<string> relays, out List<string> allowed)
        {
            allowed = new List<string>();
            var matching = (relays ?? Enumerable.Empty<string>()).Where(r => Matches(ip, new[] { r })).ToList();
            if (matching.Count == 0) return false;
            var exact = matching.Where(r => MatchesExact(ip, new[] { r })).ToList();
            if (exact.Count > 0) matching = exact;
            if (matching.Any(r => SendersOf(r).Count == 0)) return true;
            allowed = matching.SelectMany(r => SendersOf(r)).Distinct().ToList();
            return allowed.Contains((from ?? "").Trim().ToLowerInvariant());
        }

        /// <summary>
        /// Machine d'où le message est parti, vue par vos serveurs : on descend les en-têtes Received (du plus récent au plus
        /// ancien) tant que les adresses sont internes. Dès qu'une adresse publique apparaît, le message vient d'Internet :
        /// c'est elle qui est renvoyée (les adresses privées du réseau de l'expéditeur, plus bas, ne sont pas les vôtres).
        /// </summary>
        public static ReceivedHop Origin(List<KeyValuePair<string, string>> headers)
        {
            ReceivedHop origin = null;
            if (headers == null) return null;
            foreach (var kv in headers)
            {
                if (kv.Key != "received") continue;
                var hop = Forensics.ParseReceived(kv.Value);
                IPAddress a;
                // une boucle locale (::1, 127.0.0.1) ne dit rien de l'origine
                if (string.IsNullOrEmpty(hop.FromIp) || !IPAddress.TryParse(hop.FromIp.Trim('[', ']'), out a) || IPAddress.IsLoopback(a)) continue;
                origin = hop;
                if (Forensics.IsPublicIp(hop.FromIp)) break;
            }
            return origin;
        }

        /// <summary>Pour les tests.</summary>
        public static void SetForTests(string name, params string[] ips)
        {
            lock (Sync) resolved[name] = ips;
        }
    }
}
