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
        public string CompanyName = "";
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

        // Bêta : sources externes (désactivées par défaut)
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
            return c;
        }

        /// <summary>config.ini (installé par l'administrateur) puis, si autorisé, les réglages de l'utilisateur.</summary>
        public static PhishGuardConfig LoadMerged(string installPath, string userPath)
        {
            var c = Load(installPath);
            if (c.AllowUserSettings)
            {
                Apply(c, userPath, false);
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

        static void Apply(PhishGuardConfig c, string path, bool isAdminFile)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return;
            foreach (var raw in File.ReadAllLines(path, Encoding.UTF8))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#") || line.StartsWith(";") || line.StartsWith("[")) continue;
                int eq = line.IndexOf('=');
                if (eq <= 0) continue;
                string key = line.Substring(0, eq).Trim().ToLowerInvariant();
                string val = line.Substring(eq + 1).Trim();
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
        }

        /// <summary>Enregistre les réglages modifiables par l'utilisateur.</summary>
        public void SaveUser(string path)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# PhishGuard - réglages de l'utilisateur (modifiés depuis Outlook, bouton Paramètres).");
            sb.AppendLine("# Ils complètent et remplacent ceux de config.ini.");
            sb.AppendLine("CompanyName = " + Clean(CompanyName));
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
            sb.AppendLine("# Réputation : sources externes");
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
}
