// PhishGuard - tâches de fond du complément (toutes exécutées sur le fil d'Outlook, par petites étapes) :
// - liste de vos correspondants (Éléments envoyés + Contacts) pour le « premier contact » et les sosies ;
// - rafraîchissement quand l'âge d'un domaine vient d'être connu ;
// - catégorie de couleur sur les messages suspects/dangereux de la boîte de réception (option) ;
// - journal des scores ; recharge périodique des listes (liste partagée réseau, Red Flag Domains).

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace PhishGuard.AddIn
{
    public partial class Connect
    {
        const int OlFolderSentMail = 5, OlFolderInbox = 6, OlFolderContacts = 10, OlFolderJunk = 23;
        const string PR_SMTP_ADDRESS = "http://schemas.microsoft.com/mapi/proptag/0x39FE001F";
        const string CatDanger = "PhishGuard : Dangereux", CatSuspect = "PhishGuard : Suspect";

        int tickCount;

        // Analyse des correspondants
        int corrPhase;                 // 0 = à démarrer, 1 = éléments envoyés, 2 = contacts, 3 = terminé
        object corrItems;
        int corrIndex, corrCount;
        HashSet<string> corrFound = new HashSet<string>();
        Dictionary<string, HashSet<string>> corrThreads = new Dictionary<string, HashSet<string>>();
        const string PR_INTERNET_MESSAGE_ID = "http://schemas.microsoft.com/mapi/proptag/0x1035001F";
        DateTime corrNextRun = DateTime.MinValue;

        readonly HashSet<string> taggedKeys = new HashSet<string>();
        readonly HashSet<string> loggedKeys = new HashSet<string>();

        /// <summary>Réglages qui agissent sur les modules partagés (langue, listes, âge des domaines).</summary>
        /// <summary>Met à jour la fenêtre d'enquête ouverte quand des résultats externes arrivent.</summary>
        void RefreshDetailsIfOpen()
        {
            if (form == null || form.IsDisposed || !form.Visible || lastMail == null) return;
            try
            {
                var c = AnalyzeCached(lastMail, true);
                form.RefreshResult(c.Result, c.Data, ListStatus(), config.ShowExplanations, config.AllowUserSettings);
            }
            catch (Exception ex) { Log("Mise à jour de la fenêtre : " + ex.Message); }
        }

        void ApplyRuntimeSettings()
        {
            L.SetLanguage(config.Language);
            DomainAge.Enabled = config.DomainAgeLookup;
            Intel.Settings = new IntelSettings
            {
                DnsChecks = config.BetaDnsChecks,
                CertAge = config.BetaCertAge,
                VirusTotalKey = config.VirusTotalKey ?? "",
                AbuseChKey = config.AbuseChKey ?? "",
                AbuseIpdbKey = config.AbuseIpdbKey ?? ""
            };
            Feeds.Init(config.BetaOpenPhish, config.BetaTranco);
            Blocklists.SharedPath = config.SharedBlocklistPath ?? "";
        }

        void BackgroundTick()
        {
            tickCount++;
            try
            {
                if (DomainAge.Changed || Intel.Changed || Feeds.Changed)
                {
                    DomainAge.Changed = false;
                    Intel.Changed = false;
                    Feeds.Changed = false;
                    cache.Clear();
                    cacheOrder.Clear();
                    lastSelectionKey = "\u0001";       // réanalyse du message affiché
                    if (!config.AutoAnalyze) InvalidateRibbons();
                    RefreshDetailsIfOpen();
                }
                if (config.KnownCorrespondents) CorrespondentsStep();
                if (config.TagCategory && tickCount % 30 == 5) InboxStep();
                if (tickCount % 5000 == 0)                // environ toutes les heures
                {
                    Blocklists.Init(config, InstallDir); // recharge la liste partagée et met à jour Red Flag Domains si besoin
                    Feeds.Init(config.BetaOpenPhish, config.BetaTranco);
                }
            }
            catch (Exception ex) { Log("Tâche de fond : " + ex.Message); }
        }

        // -----------------------------------------------------------------
        // Correspondants
        // -----------------------------------------------------------------

        void CorrespondentsStep()
        {
            dynamic app = application;
            if (app == null) return;

            if (corrPhase == 0)
            {
                DateTime fileDate;
                if (Correspondents.LoadCache(out fileDate))
                {
                    Log("Correspondants : " + Correspondents.Count + " adresses (cache du " + fileDate.ToString("dd/MM/yyyy") + ")");
                    if (fileDate > DateTime.Now.AddDays(-1) && File.Exists(Correspondents.ThreadsPath)) { corrPhase = 3; corrNextRun = fileDate.AddDays(1); return; }
                }
                StartCorrespondentPhase(1);
                return;
            }
            if (corrPhase == 3)
            {
                if (DateTime.Now > corrNextRun) StartCorrespondentPhase(1);
                return;
            }

            dynamic items = corrItems;
            int end = Math.Min(corrCount, corrIndex + 25);
            for (; corrIndex <= end; corrIndex++)
            {
                try
                {
                    dynamic it = items.Item(corrIndex);
                    if (corrPhase == 1) CollectRecipients(it);
                    else CollectContact(it);
                }
                catch (Exception) { }
            }
            if (corrIndex > corrCount)
            {
                if (corrPhase == 1) StartCorrespondentPhase(2);
                else
                {
                    Correspondents.Set(corrFound, true);
                    Correspondents.SetThreads(corrThreads, true);
                    corrThreads = new Dictionary<string, HashSet<string>>();
                    Log("Correspondants : " + Correspondents.Count + " adresses trouvées dans les éléments envoyés et les contacts");
                    corrFound = new HashSet<string>();
                    corrItems = null;
                    corrPhase = 3;
                    corrNextRun = DateTime.Now.AddDays(1);
                    cache.Clear(); cacheOrder.Clear();
                    lastSelectionKey = "\u0001";
                }
            }
        }

        void StartCorrespondentPhase(int phase)
        {
            corrPhase = phase;
            corrIndex = 1;
            corrCount = 0;
            corrItems = null;
            try
            {
                dynamic app = application;
                dynamic folder = app.Session.GetDefaultFolder(phase == 1 ? OlFolderSentMail : OlFolderContacts);
                dynamic items = folder.Items;
                if (phase == 1) items.Sort("[SentOn]", true);
                corrItems = items;
                corrCount = Math.Min((int)items.Count, phase == 1 ? 1500 : 3000);
            }
            catch (Exception ex) { Log("Correspondants (dossier " + phase + ") : " + ex.Message); corrCount = 0; }
        }

        void CollectRecipients(object itemObj)
        {
            dynamic it = itemObj;
            if ((int)it.Class != MailReader.OlMail) return;
            dynamic recips = it.Recipients;
            int n = recips.Count;
            var orgs = new HashSet<string>();
            for (int i = 1; i <= n && i <= 50; i++)
            {
                try
                {
                    dynamic r = recips.Item(i);
                    string addr = Str(() => r.Address);
                    if (!addr.Contains("@")) addr = Str(() => r.PropertyAccessor.GetProperty(PR_SMTP_ADDRESS));
                    if (addr.Contains("@"))
                    {
                        corrFound.Add(addr.ToLowerInvariant());
                        string org = PhishGuard.Domains.RegistrableDomain(PhishGuard.Domains.DomainOfAddress(addr));
                        if (org.Length > 0) orgs.Add(org);
                    }
                }
                catch (Exception) { }
            }
            // Message-ID du message envoyé : permet de reconnaître les vraies réponses (et les détournements de fil)
            string msgId = Str(() => it.PropertyAccessor.GetProperty(PR_INTERNET_MESSAGE_ID));
            if (msgId.Length > 0 && orgs.Count > 0) corrThreads[Correspondents.NormalizeMessageId(msgId)] = orgs;
        }

        void CollectContact(object itemObj)
        {
            dynamic c = itemObj;
            if ((int)c.Class != 40) return; // olContact
            foreach (var n in new[] { 1, 2, 3 })
            {
                string addr = "", type = "";
                if (n == 1) { addr = Str(() => c.Email1Address); type = Str(() => c.Email1AddressType); }
                if (n == 2) { addr = Str(() => c.Email2Address); type = Str(() => c.Email2AddressType); }
                if (n == 3) { addr = Str(() => c.Email3Address); type = Str(() => c.Email3AddressType); }
                if (addr.Contains("@") && (type.Length == 0 || type.Equals("SMTP", StringComparison.OrdinalIgnoreCase))) corrFound.Add(addr.ToLowerInvariant());
            }
        }

        // -----------------------------------------------------------------
        // Catégories de couleur dans la boîte de réception (option)
        // -----------------------------------------------------------------

        void InboxStep()
        {
            dynamic app = application;
            dynamic items = app.Session.GetDefaultFolder(OlFolderInbox).Items;
            items.Sort("[ReceivedTime]", true);
            int n = Math.Min((int)items.Count, 25);
            int analysed = 0;
            for (int i = 1; i <= n && analysed < 3; i++)
            {
                object mail;
                try { mail = items.Item(i); } catch (Exception) { continue; }
                if (!IsMail(mail) || !AutoAllowed(mail)) continue;
                string key = KeyOf(mail);
                if (taggedKeys.Contains(key)) continue;
                taggedKeys.Add(key);
                analysed++;
                var c = AnalyzeCached(mail, false);
                if (c != null) AfterAnalysis(mail, key, c.Result);
            }
        }

        void EnsureCategory(string name, int color)
        {
            dynamic app = application;
            dynamic cats = app.Session.Categories;
            object existing = null;
            try { existing = cats.Item(name); } catch (Exception) { }
            if (existing == null) cats.Add(name, color);
        }

        void ApplyCategory(object mailObj, AnalysisResult r)
        {
            if (!config.TagCategory) return;
            dynamic mail = mailObj;
            string wanted = r.Level == "dangerous" ? CatDanger : r.Level == "suspicious" ? CatSuspect : null;
            string current = Str(() => mail.Categories);
            var parts = current.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim())
                .Where(x => x.Length > 0 && x != CatDanger && x != CatSuspect).ToList();
            if (wanted != null)
            {
                EnsureCategory(wanted, wanted == CatDanger ? 1 : 2); // rouge / orange
                parts.Add(wanted);
            }
            string next = string.Join(", ", parts.ToArray());
            if (next == current) return;
            mail.Categories = next;
            mail.Save();
        }

        // -----------------------------------------------------------------
        // Après chaque analyse : journal et catégorie
        // -----------------------------------------------------------------

        void AfterAnalysis(object mail, string key, AnalysisResult r)
        {
            try { ApplyCategory(mail, r); } catch (Exception ex) { Log("Catégorie : " + ex.Message); }
            if (!config.ScoreLog || !loggedKeys.Add(key)) return;
            try
            {
                string path = Path.Combine(Blocklists.DataDir, "scores.csv");
                bool header = !File.Exists(path);
                var sb = new StringBuilder();
                if (header) sb.AppendLine("date;niveau;score;domaine_expediteur;premier_contact;indices");
                sb.AppendLine(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + ";" + r.Level + ";" + r.Score + ";"
                    + (r.SenderDomain ?? "").Replace(";", "") + ";" + (r.FirstContact ? "oui" : "non") + ";"
                    + string.Join(" ", r.Findings.Where(f => f.Severity != Severity.Info).Select(f => f.Id).ToArray()));
                File.AppendAllText(path, sb.ToString(), new UTF8Encoding(header));
            }
            catch (Exception ex) { Log("Journal des scores : " + ex.Message); }
        }

        // -----------------------------------------------------------------
        // « Ce n'est pas du phishing »
        // -----------------------------------------------------------------

        void MarkNotPhishing(AnalysisResult r)
        {
            if (!config.AllowUserSettings)
            {
                MessageBox.Show(L.T("Les réglages sont gérés par votre service informatique : demandez-lui d’ajouter cet expéditeur aux expéditeurs de confiance."),
                    "PhishGuard", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            string addr = (r.SenderAddress ?? "").ToLowerInvariant();
            string domain = PhishGuard.Domains.RegistrableDomain(PhishGuard.Domains.DomainOfAddress(addr));
            if (addr.Length == 0) return;
            var cfg = PhishGuardConfig.LoadMerged(Path.Combine(InstallDir, "config.ini"), UserConfigPath);

            bool freemail = Lists.FreemailDomains.Contains(PhishGuard.Domains.DomainOfAddress(addr));
            DialogResult choice = DialogResult.No;
            if (!freemail && domain.Length > 0)
            {
                choice = MessageBox.Show(L.F("Faire confiance à tout le domaine « {0} » ?", domain) + "\n\n"
                    + L.F("Oui : tous les expéditeurs de {0}", domain) + "\n" + L.F("Non : seulement {0}", addr),
                    L.T("PhishGuard - Ce n’est pas du phishing"), MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
                if (choice == DialogResult.Cancel) return;
            }
            if (choice == DialogResult.Yes) { if (!cfg.TrustedDomains.Contains(domain)) cfg.TrustedDomains.Add(domain); }
            else { if (!cfg.TrustedSenders.Contains(addr)) cfg.TrustedSenders.Add(addr); }
            cfg.SaveUser(UserConfigPath);
            config = PhishGuardConfig.LoadMerged(Path.Combine(InstallDir, "config.ini"), UserConfigPath);
            cache.Clear(); cacheOrder.Clear();
            lastSelectionKey = "\u0001";
            Log("Ajouté aux expéditeurs de confiance : " + (choice == DialogResult.Yes ? domain : addr));
            if (lastMail != null && form != null && !form.IsDisposed && form.Visible)
            {
                try { OpenDetails(lastMail); } catch (Exception) { }
            }
            InvalidateRibbons();
        }

        /// <summary>Après un signalement : le message est déplacé dans « Courrier indésirable ».</summary>
        void MoveToJunk(object mailObj)
        {
            if (!config.MoveAfterReport || mailObj == null) return;
            try
            {
                dynamic app = application;
                dynamic junk = app.Session.GetDefaultFolder(OlFolderJunk);
                string key = KeyOf(mailObj);
                ((dynamic)mailObj).Move(junk);
                cache.Remove(key);
                if (lastMail == mailObj) lastMail = null;
                Log("Message signalé déplacé dans Courrier indésirable");
            }
            catch (Exception ex) { Log("Déplacement : " + ex.Message); }
        }
    }
}
