// PhishGuard - configuration lue dans config.ini (format "clé = valeur", listes séparées par des virgules).

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
            if (c.AllowUserSettings) Apply(c, userPath, false);
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
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
        }

        static string Clean(string s)
        {
            return (s ?? "").Replace("\r", " ").Replace("\n", " ").Replace(",", " ").Trim();
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
