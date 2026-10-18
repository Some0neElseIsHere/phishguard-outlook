// PhishGuard - configuration lue dans config.ini (format "clé = valeur", listes séparées par des virgules).

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PhishGuard
{
    public class PhishGuardConfig
    {
        public string CompanyName = "";          // première entreprise (compatibilité) ; la liste complète est Companies
        public List<CompanyEntry> Companies = new List<CompanyEntry>();
        public List<string> CompanyDomains = new List<string>();
        public List<string> VipNames = new List<string>();
        public List<string> TrustedDomains = new List<string>();
        public string ReportAddress = "";
        public bool RedFlagEnabled = true;
        public string RedFlagUrl = "https://dl.red.flag.domains/red.flag.domains.txt";
        public int RedFlagMaxAgeHours = 24;
        public bool AutoAnalyze = true;          // analyse automatique du message sélectionné ou ouvert
        public string AlertLevel = "dangerous";  // dangerous, suspicious ou none
        public int AutoHashMaxMB = 5;            // empreintes des pièces jointes en analyse automatique
        public bool AllowUserSettings = true;    // bouton « Paramètres » dans Outlook (lu seulement dans config.ini)
        public bool ShowExplanations = true;     // explications pédagogiques sous chaque indice
        public bool KnownCorrespondents = true;  // premier contact et sosies de vos correspondants
        public bool DomainAgeLookup = true;      // âge des domaines (RDAP, sans clé)
        public bool TagCategory = false;         // catégorie de couleur sur les messages suspects/dangereux
        public bool MoveAfterReport = true;      // déplacer en Courrier indésirable après signalement
        public bool ScoreLog = true;             // journal des scores (scores.csv)
        public string SharedBlocklistPath = "";  // liste de blocage partagée (ex. \\serveur\partage\phishguard.txt)
        public List<string> TrustedSenders = new List<string>();
        public string Language = "auto";         // auto (langue de Windows), fr ou en
        public List<string> SetupDone = new List<string>();   // étapes de l'assistant de démarrage déjà vues
        public bool SetupKeyPresent;                         // SetupDone trouvé dans config.user.ini
        public bool ExpertMode = false;          // fenêtre d'analyse : false = mode simple (débutants), true = analyse détaillée
        public bool WatchDomains = true;         // surveillance hebdomadaire des nouveaux sosies de vos domaines (DNS)

        // Bêta : sources externes (désactivées par défaut)
        public bool PublicSectorList = true;     // liste des domaines du secteur public (DINUM), téléchargée chaque mois
        public bool BetaOpenPhish = false;       // flux OpenPhish (sans clé)
        public bool BetaTranco = false;          // classement Tranco des sites les plus visités (sans clé)
        public bool BetaDnsChecks = false;       // MX / SPF / DMARC du domaine expéditeur (DNS de Windows)
        public bool BetaCertAge = false;         // âge du premier certificat HTTPS (crt.sh, sans clé)
        public string VirusTotalKey = "";        // clés gratuites : rangées dans le Gestionnaire d'identification de Windows
        public string AbuseChKey = "";
        public string AbuseIpdbKey = "";

        // Clés d'API : nom dans le coffre de Windows et nom de la clé dans les fichiers .ini
        static readonly string[][] ApiKeys = { new[] { "VirusTotal", "VirusTotalKey" }, new[] { "AbuseCh", "AbuseChKey" }, new[] { "AbuseIpdb", "AbuseIpdbKey" } };
        readonly Dictionary<string, string> adminKeys = new Dictionary<string, string>();   // clés imposées par config.ini
        readonly HashSet<string> legacyUserKeys = new HashSet<string>();                    // clés trouvées dans config.user.ini (anciennes versions)

        string GetKey(string name)
        {
            switch (name)
            {
                case "VirusTotal": return VirusTotalKey ?? "";
                case "AbuseCh": return AbuseChKey ?? "";
                default: return AbuseIpdbKey ?? "";
            }
        }

        void SetKey(string name, string value)
        {
            switch (name)
            {
                case "VirusTotal": VirusTotalKey = value; break;
                case "AbuseCh": AbuseChKey = value; break;
                default: AbuseIpdbKey = value; break;
            }
        }

        static void ReadKey(PhishGuardConfig c, string name, string val, bool isAdminFile)
        {
            string k = Unprotect(val);
            if (isAdminFile) { c.adminKeys[name] = k; c.SetKey(name, k); }
            else if (k.Length > 0) { c.SetKey(name, k); c.legacyUserKeys.Add(name); }
        }

        public static PhishGuardConfig Load(string path)
        {
            var c = new PhishGuardConfig();
            Apply(c, path, true);
            c.NormalizeCompanies();
            return c;
        }

        /// <summary>
        /// Entreprises : les anciennes versions n'avaient qu'un nom (CompanyName) et une liste de dirigeants saisie
        /// à la main (VipNames) ; elles deviennent la première entreprise. Les dirigeants surveillés sont ensuite
        /// ceux de toutes les entreprises.
        /// </summary>
        public void NormalizeCompanies()
        {
            if (Companies.Count == 0 && (!string.IsNullOrEmpty(CompanyName) || VipNames.Count > 0))
                Companies.Add(new CompanyEntry { Name = CompanyName ?? "", Directors = new List<string>(VipNames) });
            if (Companies.Count == 0) return;
            CompanyName = Companies.Select(x => x.Name).FirstOrDefault(n => !string.IsNullOrEmpty(n)) ?? "";
            var vips = new List<string>();
            foreach (var d in Companies.SelectMany(x => x.Directors))
                if (d.Trim().Length > 0 && !vips.Any(v => string.Equals(v, d.Trim(), StringComparison.OrdinalIgnoreCase))) vips.Add(d.Trim());
            VipNames = vips;
        }

        /// <summary>Noms de toutes les entreprises (repérés dans le nom affiché des expéditeurs externes).</summary>
        public List<string> CompanyNames()
        {
            var names = Companies.Select(x => x.Name).Where(n => !string.IsNullOrEmpty(n)).ToList();
            if (names.Count == 0 && !string.IsNullOrEmpty(CompanyName)) names.Add(CompanyName);
            return names.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        /// <summary>config.ini (installé par l'administrateur) puis, si autorisé, les réglages de l'utilisateur.</summary>
        public static PhishGuardConfig LoadMerged(string installPath, string userPath)
        {
            var c = Load(installPath);
            if (c.AllowUserSettings)
            {
                var adminCompanies = c.Companies;
                c.Companies = new List<CompanyEntry>();
                var userKeys = Apply(c, userPath, false);
                // Fichier utilisateur sans entreprise : on garde celles de config.ini ; ancien format (CompanyName,
                // VipNames) : il devient la première entreprise
                if (!userKeys.Contains("company#") && !userKeys.Contains("companyname") && !userKeys.Contains("vipnames")) c.Companies = adminCompanies;
                c.NormalizeCompanies();
                // Clés de l'utilisateur : coffre de Windows (prioritaire). Les clés des anciennes versions,
                // trouvées dans config.user.ini, y sont déplacées ; elles disparaîtront du fichier au prochain enregistrement.
                foreach (var k in ApiKeys)
                {
                    string stored = Secrets.Get(k[0]);
                    if (stored.Length > 0) c.SetKey(k[0], stored);
                    else if (c.legacyUserKeys.Contains(k[0])) Secrets.Set(k[0], c.GetKey(k[0]));
                }
            }
            return c;
        }

        /// <summary>Lit un fichier de réglages ; renvoie les clés rencontrées.</summary>
        static HashSet<string> Apply(PhishGuardConfig c, string path, bool isAdminFile)
        {
            var seen = new HashSet<string>();
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return seen;
            bool companiesReplaced = false;   // les entreprises d'un fichier remplacent celles du précédent
            foreach (var raw in File.ReadAllLines(path, Encoding.UTF8))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#") || line.StartsWith(";") || line.StartsWith("[")) continue;
                int eq = line.IndexOf('=');
                if (eq <= 0) continue;
                string key = line.Substring(0, eq).Trim().ToLowerInvariant();
                string val = line.Substring(eq + 1).Trim();
                seen.Add(System.Text.RegularExpressions.Regex.IsMatch(key, @"^company\d+$") ? "company#" : key);
                if (System.Text.RegularExpressions.Regex.IsMatch(key, @"^company\d+$"))
                {
                    if (!companiesReplaced) { c.Companies = new List<CompanyEntry>(); companiesReplaced = true; }
                    var ce = CompanyEntry.Parse(val);
                    if (ce != null) c.Companies.Add(ce);
                    continue;
                }
                switch (key)
                {
                    case "companyname": c.CompanyName = val; break;
                    case "companydomains": c.CompanyDomains = SplitList(val, true); break;
                    case "vipnames": c.VipNames = SplitList(val, false); break;
                    case "trusteddomains": c.TrustedDomains = SplitList(val, true); break;
                    case "reportaddress": c.ReportAddress = val; break;
                    case "redflagenabled": c.RedFlagEnabled = !(val == "0" || val.Equals("false", StringComparison.OrdinalIgnoreCase) || val.Equals("non", StringComparison.OrdinalIgnoreCase)); break;
                    case "redflagurl": if (val.Length > 0) c.RedFlagUrl = val; break;
                    case "autoanalyze": c.AutoAnalyze = !IsFalse(val); break;
                    case "alertlevel": c.AlertLevel = val.ToLowerInvariant(); break;
                    case "autohashmaxmb": int mb; if (int.TryParse(val, out mb) && mb >= 0) c.AutoHashMaxMB = mb; break;
                    case "redflagmaxagehours": int h; if (int.TryParse(val, out h) && h > 0) c.RedFlagMaxAgeHours = h; break;
                    case "showexplanations": c.ShowExplanations = !IsFalse(val); break;
                    case "knowncorrespondents": c.KnownCorrespondents = !IsFalse(val); break;
                    case "domainagelookup": c.DomainAgeLookup = !IsFalse(val); break;
                    case "tagcategory": c.TagCategory = !IsFalse(val); break;
                    case "moveafterreport": c.MoveAfterReport = !IsFalse(val); break;
                    case "scorelog": c.ScoreLog = !IsFalse(val); break;
                    case "sharedblocklistpath": c.SharedBlocklistPath = val; break;
                    case "trustedsenders": c.TrustedSenders = SplitList(val, true); break;
                    case "language": c.Language = val.Trim().ToLowerInvariant(); break;
                    case "watchdomains": c.WatchDomains = !IsFalse(val); break;
                    case "expertmode": c.ExpertMode = IsTrue(val); break;
                    case "setupdone": if (!isAdminFile) { c.SetupDone = SplitList(val, true); c.SetupKeyPresent = true; } break;
                    case "publicsectorlist": c.PublicSectorList = !IsFalse(val); break;
                    case "betaopenphish": c.BetaOpenPhish = IsTrue(val); break;
                    case "betatranco": c.BetaTranco = IsTrue(val); break;
                    case "betadnschecks": c.BetaDnsChecks = IsTrue(val); break;
                    case "betacertage": c.BetaCertAge = IsTrue(val); break;
                    case "virustotalkey": ReadKey(c, "VirusTotal", val, isAdminFile); break;
                    case "abusechkey": ReadKey(c, "AbuseCh", val, isAdminFile); break;
                    case "abuseipdbkey": ReadKey(c, "AbuseIpdb", val, isAdminFile); break;
                    case "allowusersettings": if (isAdminFile) c.AllowUserSettings = !IsFalse(val); break;
                }
            }
            return seen;
        }

        /// <summary>
        /// Étapes de l'assistant de démarrage à proposer : celles jamais vues. Pour une installation antérieure à l'assistant,
        /// l'accueil et la langue sont considérés comme vus ; une étape dont la réponse est déjà renseignée (par l'utilisateur
        /// ou par config.ini) n'est pas reposée.
        /// </summary>
        public List<string> PendingSetup(IEnumerable<string> steps, bool userFileExists)
        {
            var done = new HashSet<string>(SetupDone);
            if (!SetupKeyPresent && userFileExists) { done.Add("intro"); done.Add("language"); }
            if (CompanyDomains.Count > 0) done.Add("company");
            if (!string.IsNullOrEmpty(ReportAddress)) done.Add("report");
            return steps.Where(s => !done.Contains(s)).ToList();
        }

        /// <summary>Enregistre les réglages modifiables par l'utilisateur.</summary>
        public void SaveUser(string path)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# PhishGuard - réglages de l'utilisateur (modifiés depuis Outlook, bouton Paramètres).");
            sb.AppendLine("# Ils complètent et remplacent ceux de config.ini.");
            NormalizeCompanies();
            sb.AppendLine("CompanyName = " + Clean(CompanyName));
            for (int i = 0; i < Companies.Count; i++) sb.AppendLine("Company" + (i + 1) + " = " + Companies[i].Serialize());
            sb.AppendLine("CompanyDomains = " + string.Join(", ", CompanyDomains.Select(x => Clean(x)).ToArray()));
            sb.AppendLine("VipNames = " + string.Join(", ", VipNames.Select(x => Clean(x)).ToArray()));
            sb.AppendLine("TrustedDomains = " + string.Join(", ", TrustedDomains.Select(x => Clean(x)).ToArray()));
            sb.AppendLine("ReportAddress = " + Clean(ReportAddress));
            sb.AppendLine("AutoAnalyze = " + (AutoAnalyze ? "true" : "false"));
            sb.AppendLine("AlertLevel = " + Clean(AlertLevel));
            sb.AppendLine("AutoHashMaxMB = " + AutoHashMaxMB);
            sb.AppendLine("RedFlagEnabled = " + (RedFlagEnabled ? "true" : "false"));
            sb.AppendLine("ShowExplanations = " + (ShowExplanations ? "true" : "false"));
            sb.AppendLine("KnownCorrespondents = " + (KnownCorrespondents ? "true" : "false"));
            sb.AppendLine("DomainAgeLookup = " + (DomainAgeLookup ? "true" : "false"));
            sb.AppendLine("TagCategory = " + (TagCategory ? "true" : "false"));
            sb.AppendLine("MoveAfterReport = " + (MoveAfterReport ? "true" : "false"));
            sb.AppendLine("ScoreLog = " + (ScoreLog ? "true" : "false"));
            sb.AppendLine("SharedBlocklistPath = " + (SharedBlocklistPath ?? "").Replace("\r", "").Replace("\n", "").Trim());
            sb.AppendLine("TrustedSenders = " + string.Join(", ", TrustedSenders.Select(x => Clean(x)).ToArray()));
            sb.AppendLine("Language = " + Clean(Language));
            sb.AppendLine("WatchDomains = " + (WatchDomains ? "true" : "false"));
            sb.AppendLine("ExpertMode = " + (ExpertMode ? "true" : "false"));
            sb.AppendLine("SetupDone = " + string.Join(", ", SetupDone.Select(x => Clean(x)).ToArray()));
            sb.AppendLine("# Réputation : sources externes");
            sb.AppendLine("PublicSectorList = " + (PublicSectorList ? "true" : "false"));
            sb.AppendLine("BetaOpenPhish = " + (BetaOpenPhish ? "true" : "false"));
            sb.AppendLine("BetaTranco = " + (BetaTranco ? "true" : "false"));
            sb.AppendLine("BetaDnsChecks = " + (BetaDnsChecks ? "true" : "false"));
            sb.AppendLine("BetaCertAge = " + (BetaCertAge ? "true" : "false"));
            // Clés d'API : dans le Gestionnaire d'identification de Windows (jamais en clair, conservées entre deux
            // installations). Repli sur ce fichier, chiffré pour ce compte Windows, seulement si le coffre est indisponible.
            foreach (var k in ApiKeys)
            {
                string admin;
                adminKeys.TryGetValue(k[0], out admin);
                string value = GetKey(k[0]).Trim();
                string userValue = value == (admin ?? "") ? "" : value;   // la clé de config.ini n'est pas recopiée
                if (!Secrets.Set(k[0], userValue) && userValue.Length > 0)
                    sb.AppendLine(k[1] + " = " + Protect(userValue));
            }
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
        }

        static string Clean(string s)
        {
            return (s ?? "").Replace("\r", " ").Replace("\n", " ").Replace(",", " ").Trim();
        }

        static bool IsTrue(string val)
        {
            return val == "1" || val.Equals("true", StringComparison.OrdinalIgnoreCase) || val.Equals("oui", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Chiffre une clé pour l'utilisateur Windows courant (préfixe « dpapi: »).</summary>
        public static string Protect(string key)
        {
            string k = (key ?? "").Trim();
            if (k.Length == 0) return "";
            try { return "dpapi:" + Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(k), null, DataProtectionScope.CurrentUser)); }
            catch (Exception) { return ""; }
        }

        /// <summary>Clé en clair (config.ini de l'administrateur) ou chiffrée (« dpapi: »).</summary>
        public static string Unprotect(string val)
        {
            string v = (val ?? "").Trim();
            if (!v.StartsWith("dpapi:", StringComparison.OrdinalIgnoreCase)) return v;
            try { return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(v.Substring(6)), null, DataProtectionScope.CurrentUser)); }
            catch (Exception) { return ""; }
        }

        static bool IsFalse(string val)
        {
            return val == "0" || val.Equals("false", StringComparison.OrdinalIgnoreCase) || val.Equals("non", StringComparison.OrdinalIgnoreCase);
        }

        static List<string> SplitList(string val, bool lower)
        {
            var list = new List<string>();
            foreach (var part in val.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string p = part.Trim();
                if (lower) p = p.ToLowerInvariant();
                if (p.Length > 0) list.Add(p);
            }
            return list;
        }
    }

    /// <summary>Entreprise surveillée : « Nom | Pays | Identifiant (SIREN ou Wikidata) | Dirigeant; Dirigeant ».</summary>
    public class CompanyEntry
    {
        public string Name = "";
        public string Country = "";
        public string Id = "";
        public List<string> Directors = new List<string>();

        static string C(string s) { return (s ?? "").Replace("|", " ").Replace(";", " ").Replace("\r", " ").Replace("\n", " ").Trim(); }

        public string Serialize()
        {
            return C(Name) + " | " + C(Country) + " | " + C(Id) + " | " + string.Join("; ", Directors.Select(C).Where(d => d.Length > 0).ToArray());
        }

        public static CompanyEntry Parse(string value)
        {
            var p = (value ?? "").Split('|');
            var e = new CompanyEntry { Name = p[0].Trim() };
            if (p.Length > 1) e.Country = p[1].Trim();
            if (p.Length > 2) e.Id = p[2].Trim();
            if (p.Length > 3) e.Directors = p[3].Split(';').Select(d => d.Trim()).Where(d => d.Length > 0).ToList();
            return e.Name.Length > 0 || e.Directors.Count > 0 ? e : null;
        }
    }
}
