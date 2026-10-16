// PhishGuard - vos correspondants habituels (adresses auxquelles vous avez déjà écrit, contacts).
// Sert à repérer le « premier contact » et les domaines qui imitent ceux de vos fournisseurs/clients.
// La liste est construite par le complément à partir des Éléments envoyés et des Contacts (sur le poste uniquement).

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace PhishGuard
{
    public static class Correspondents
    {
        static readonly object Sync = new object();
        static HashSet<string> addresses = new HashSet<string>();
        static HashSet<string> domains = new HashSet<string>();
        static List<string> lookalikeTargets = new List<string>();

        public static bool Loaded { get; private set; }
        public static DateTime Updated { get; private set; }

        public static string CachePath { get { return Path.Combine(Blocklists.DataDir, "correspondants.txt"); } }

        public static int Count { get { lock (Sync) return addresses.Count; } }

        /// <summary>Remplace la liste. Les domaines de messageries gratuites et des grandes marques ne servent pas de modèles de sosies.</summary>
        public static void Set(IEnumerable<string> list, bool save)
        {
            var a = new HashSet<string>();
            foreach (var x in list)
            {
                string v = (x ?? "").Trim().ToLowerInvariant();
                if (v.Contains("@") && v.IndexOf(' ') < 0) a.Add(v);
            }
            var d = new HashSet<string>(a.Select(x => Domains.RegistrableDomain(Domains.DomainOfAddress(x))).Where(x => x.Length > 0));
            var targets = d.Where(x => !Lists.FreemailDomains.Contains(x) && Domains.ParseHost(x) != null && Domains.ParseHost(x).Label.Length >= 4).ToList();
            lock (Sync)
            {
                addresses = a; domains = d; lookalikeTargets = targets;
                Loaded = true; Updated = DateTime.Now;
            }
            if (save)
            {
                try
                {
                    Directory.CreateDirectory(Blocklists.DataDir);
                    File.WriteAllLines(CachePath, a.OrderBy(x => x).ToArray(), new UTF8Encoding(false));
                }
                catch (Exception) { }
            }
        }

        /// <summary>Charge la liste enregistrée lors de la dernière analyse des Éléments envoyés.</summary>
        public static bool LoadCache(out DateTime fileDate)
        {
            fileDate = DateTime.MinValue;
            try
            {
                if (!File.Exists(CachePath)) return false;
                fileDate = File.GetLastWriteTime(CachePath);
                Set(File.ReadAllLines(CachePath, Encoding.UTF8), false);
                Updated = fileDate;
                return true;
            }
            catch (Exception) { return false; }
        }

        public static bool IsKnownAddress(string address)
        {
            lock (Sync) return addresses.Contains((address ?? "").ToLowerInvariant());
        }

        public static bool IsKnownDomain(string registrable)
        {
            lock (Sync) return domains.Contains((registrable ?? "").ToLowerInvariant());
        }

        public static List<string> LookalikeTargets()
        {
            lock (Sync) return lookalikeTargets;
        }

        /// <summary>Pour les tests.</summary>
        public static void Reset()
        {
            lock (Sync) { addresses = new HashSet<string>(); domains = new HashSet<string>(); lookalikeTargets = new List<string>(); Loaded = false; }
        }
    }
}
