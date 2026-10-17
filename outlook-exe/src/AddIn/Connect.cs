// PhishGuard - point d'entrée du complément COM Outlook.
// - Le bouton du ruban affiche en permanence le score du message sélectionné ou ouvert.
// - Une alerte apparaît en bas à droite pour les messages dangereux (réglable dans config.ini).
// - Un clic sur le score ouvre la fenêtre d'enquête détaillée, qui donne aussi accès
//   au signalement et aux paramètres (le ruban ne garde que le bouton du score).

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace PhishGuard.AddIn
{
    [ComVisible(true)]
    [Guid("6C3F2A1E-8B5D-4E7A-9F21-3D4B8C6E2A71")]
    [ProgId("PhishGuard.Connect")]
    [ClassInterface(ClassInterfaceType.AutoDispatch)]
    public partial class Connect : IDTExtensibility2, IRibbonExtensibility
    {
        object application;
        PhishGuardConfig config = new PhishGuardConfig();
        ResultForm form;
        AlertForm alert;
        Bitmap iconApp;
        object lastMail;

        readonly List<object> ribbons = new List<object>();
        Timer selectionTimer;
        string lastSelectionKey = "";
        bool busy;

        class Cached { public EmailData Data; public AnalysisResult Result; public bool Full; }
        readonly Dictionary<string, Cached> cache = new Dictionary<string, Cached>();
        readonly Queue<string> cacheOrder = new Queue<string>();
        readonly HashSet<string> alerted = new HashSet<string>();

        /// <summary>Réglages de l'utilisateur (bouton Paramètres).</summary>
        public static string UserConfigPath { get { return Path.Combine(Blocklists.DataDir, "config.user.ini"); } }

        static string InstallDir
        {
            get { return Path.GetDirectoryName(new Uri(Assembly.GetExecutingAssembly().CodeBase).LocalPath); }
        }

        // -----------------------------------------------------------------
        // IDTExtensibility2
        // -----------------------------------------------------------------

        public void OnConnection(object Application, ext_ConnectMode ConnectMode, object AddInInst, ref Array custom)
        {
            application = Application;
            try
            {
                AppDomain.CurrentDomain.UnhandledException += (s, e) => Log("Exception non gérée : " + e.ExceptionObject);
                Log("Chargement (mode " + ConnectMode + ", .NET " + Environment.Version + ", " + (IntPtr.Size * 8) + " bits)");
                config = PhishGuardConfig.LoadMerged(Path.Combine(InstallDir, "config.ini"), UserConfigPath);
                ApplyRuntimeSettings();
                Blocklists.Init(config, InstallDir);
                Log("Configuration chargée, listes : " + Blocklists.RedFlagCount + " domaines en cache, analyse auto : " + config.AutoAnalyze);
                // Chargé après le démarrage d'Outlook (activé à la main) : OnStartupComplete ne sera pas appelé
                if (ConnectMode == ext_ConnectMode.ext_cm_AfterStartup) { sessionReady = true; CompleteConfig(); StartWatching(); }
            }
            catch (Exception ex) { Log("Démarrage : " + ex); }
        }

        public void OnStartupComplete(ref Array custom)
        {
            sessionReady = true;
            CompleteConfig();
            StartWatching();
        }

        public void OnDisconnection(ext_DisconnectMode RemoveMode, ref Array custom)
        {
            try { if (selectionTimer != null) { selectionTimer.Stop(); selectionTimer.Dispose(); selectionTimer = null; } } catch (Exception) { }
            try { if (alert != null && !alert.IsDisposed) alert.Close(); } catch (Exception) { }
            try { if (form != null) { form.Dispose(); form = null; } } catch (Exception) { }
            ribbons.Clear();
            cache.Clear();
            application = null;
        }

        public void OnAddInsUpdate(ref Array custom) { }
        public void OnBeginShutdown(ref Array custom)
        {
            try { if (selectionTimer != null) selectionTimer.Stop(); } catch (Exception) { }
        }

        // -----------------------------------------------------------------
        // Surveillance du message sélectionné
        // -----------------------------------------------------------------

        void StartWatching()
        {
            if (selectionTimer != null) return;
            try
            {
                selectionTimer = new Timer { Interval = 700 };
                selectionTimer.Tick += (s, e) =>
                {
                    if (config.AutoAnalyze) CheckSelection();
                    if (!busy) BackgroundTick();
                };
                selectionTimer.Start();
                Log("Surveillance démarrée (analyse automatique : " + config.AutoAnalyze + ")");
            }
            catch (Exception ex) { Log("Minuterie : " + ex.Message); }
        }

        void StopWatching()
        {
            if (selectionTimer == null) return;
            try { selectionTimer.Stop(); selectionTimer.Dispose(); } catch (Exception) { }
            selectionTimer = null;
        }

        void CheckSelection()
        {
            if (busy || application == null) return;
            busy = true;
            try
            {
                object mail = null;
                string key = "";
                try
                {
                    dynamic app = application;
                    dynamic explorer = app.ActiveExplorer();
                    if (explorer != null)
                    {
                        dynamic sel = explorer.Selection;
                        if (sel.Count > 0)
                        {
                            object item = sel.Item(1);
                            if (IsMail(item)) { mail = item; key = KeyOf(item); }
                        }
                    }
                }
                catch (Exception) { /* vue sans sélection (calendrier, réponse en ligne...) */ }

                if (key == lastSelectionKey) return;
                lastSelectionKey = key;

                AnalysisResult result = null;
                if (mail != null && AutoAllowed(mail))
                {
                    var c = AnalyzeCached(mail, false);
                    if (c != null) result = c.Result;
                }
                InvalidateRibbons();
                if (result != null)
                {
                    AfterAnalysis(mail, key, result);
                    MaybeAlert(mail, key, result);
                }
            }
            catch (Exception ex) { Log("Sélection : " + ex.Message); }
            finally { busy = false; }
        }

        static bool IsMail(object item)
        {
            try { return (int)((dynamic)item).Class == MailReader.OlMail; } catch (Exception) { return false; }
        }

        static string KeyOf(object mail)
        {
            string id = Str(() => ((dynamic)mail).EntryID);
            if (id.Length > 0) return id;
            return "tmp:" + Str(() => ((dynamic)mail).Subject) + "|" + Str(() => ((dynamic)mail).ReceivedTime);
        }

        /// <summary>Pas d'analyse automatique des messages chiffrés ou signés S/MIME (pour ne pas déclencher de demande de déchiffrement).</summary>
        static bool AutoAllowed(object mail)
        {
            string cls = Str(() => ((dynamic)mail).MessageClass);
            return !cls.StartsWith("IPM.Note.SMIME", StringComparison.OrdinalIgnoreCase);
        }

        Cached AnalyzeCached(object mail, bool full)
        {
            string key = KeyOf(mail);
            Cached c;
            if (cache.TryGetValue(key, out c) && (c.Full || !full)) return c;

            long maxHash = full ? MailReader.FullHashSize : (long)config.AutoHashMaxMB * 1024 * 1024;
            var data = MailReader.Read(mail, maxHash);
            var result = Analyzer.Analyze(data, config);
            c = new Cached { Data = data, Result = result, Full = full };
            if (!cache.ContainsKey(key)) cacheOrder.Enqueue(key);
            cache[key] = c;
            while (cacheOrder.Count > 300) cache.Remove(cacheOrder.Dequeue());
            return c;
        }

        void InvalidateRibbons()
        {
            foreach (var r in ribbons.ToArray())
            {
                try { ((dynamic)r).InvalidateControl("PhishGuardScore"); }
                catch (Exception) { ribbons.Remove(r); }
            }
        }

        void MaybeAlert(object mail, string key, AnalysisResult r)
        {
            string lvl = (config.AlertLevel ?? "dangerous").ToLowerInvariant();
            bool show = (r.Level == "dangerous" && lvl != "none") || (r.Level == "suspicious" && lvl == "suspicious");
            if (!show || alerted.Contains(key)) return;
            alerted.Add(key);
            try
            {
                if (alert != null && !alert.IsDisposed) alert.Close();
                string subject = Str(() => ((dynamic)mail).Subject);
                alert = new AlertForm(r, subject);
                object target = mail;
                alert.DetailsRequested += (s, e) => { try { OpenDetails(target); } catch (Exception ex) { Log("Alerte : " + ex.Message); } };
                alert.Show();
            }
            catch (Exception ex) { Log("Alerte : " + ex.Message); }
        }

        // -----------------------------------------------------------------
        // Ruban
        // -----------------------------------------------------------------

        const string Ns = "http://schemas.microsoft.com/office/2009/07/customui";

        static string Group()
        {
            // Un seul bouton : le score. Signaler et Paramètres sont dans la fenêtre d'enquête.
            return "<group id='PhishGuardGroup' label='PhishGuard'>"
                 + "<button id='PhishGuardScore' size='large' getLabel='GetScoreLabel' getImage='GetScoreImage' onAction='OnAnalyze' "
                 + "getScreentip='GetScoreTip' getSupertip='GetScoreSupertip'/>"
                 + "</group>";
        }

        public string GetCustomUI(string RibbonID)
        {
            Log("Ruban demandé : " + RibbonID);
            if (RibbonID == "Microsoft.Outlook.Explorer")
            {
                return "<customUI xmlns='" + Ns + "' onLoad='OnRibbonLoad'><ribbon><tabs><tab idMso='TabMail'>" + Group() + "</tab></tabs></ribbon>"
                     + "<contextMenus><contextMenu idMso='ContextMenuMailItem'>"
                     + "<button id='PhishGuardContextAnalyze' getLabel='GetContextLabel' getImage='GetImage' onAction='OnAnalyze'/>"
                     + "</contextMenu></contextMenus></customUI>";
            }
            if (RibbonID == "Microsoft.Outlook.Mail.Read")
            {
                return "<customUI xmlns='" + Ns + "' onLoad='OnRibbonLoad'><ribbon><tabs><tab idMso='TabReadMessage'>" + Group() + "</tab></tabs></ribbon></customUI>";
            }
            return null;
        }

        public void OnRibbonLoad(object ribbon)
        {
            if (ribbon != null) ribbons.Add(ribbon);
        }

        /// <summary>Résultat pour le message du contexte (sélection ou fenêtre ouverte), depuis le cache si possible.</summary>
        AnalysisResult ResultFor(object control)
        {
            try
            {
                object mail = GetMail(control);
                if (mail == null) return null;
                Cached c;
                if (cache.TryGetValue(KeyOf(mail), out c)) return c.Result;
                if (!config.AutoAnalyze || !AutoAllowed(mail)) return null;
                c = AnalyzeCached(mail, false);
                return c == null ? null : c.Result;
            }
            catch (Exception ex) { Log("Score : " + ex.Message); return null; }
        }

        static string ShortLevel(AnalysisResult r)
        {
            if (r.Level == "dangerous") return L.T("Dangereux");
            if (r.Level == "suspicious") return L.T("Suspect");
            return L.T("Risque faible");
        }

        public string GetContextLabel(object control)
        {
            return L.T("Analyser avec PhishGuard");
        }

        public string GetScoreLabel(object control)
        {
            var r = ResultFor(control);
            if (r != null && r.Verified) return L.T("Expéditeur vérifié");
            return r == null ? L.T("Analyser") : ShortLevel(r) + " (" + r.Score + ")";
        }

        public string GetScoreTip(object control)
        {
            var r = ResultFor(control);
            return r == null ? L.T("Analyser ce message") : "PhishGuard : " + (r.Verified ? L.T("Expéditeur vérifié") : r.LevelLabel) + ", score " + r.Score + "/100";
        }

        public string GetScoreSupertip(object control)
        {
            var r = ResultFor(control);
            if (r == null) return L.T("Recherche les indices de phishing : expéditeur, domaines sosies, liens, pièces jointes, contenu.");
            if (r.Verified)
                return string.Join("\n", r.Trust.Take(3).Select(t => "✓ " + t).ToArray()) + "\n\n" + L.T("Cliquez pour voir le détail, signaler le message ou modifier les paramètres.");
            var top = r.Findings.Where(f => f.Severity != Severity.Info).Take(3).Select(f => "• " + f.Title).ToArray();
            return (top.Length > 0 ? string.Join("\n", top) : L.T("Aucun indice suspect.")) + "\n\n" + L.T("Cliquez pour voir le détail, signaler le message ou modifier les paramètres.");
        }

        public object GetScoreImage(object control)
        {
            try
            {
                var r = ResultFor(control);
                if (r == null) return GetImage(control);
                return PictureConverter.ToPicture(ScoreBadge(r));
            }
            catch (Exception ex) { Log("Pastille : " + ex.Message); return null; }
        }

        /// <summary>Pastille 32x32 : fond coloré selon le niveau, score en blanc.</summary>
        internal static Bitmap ScoreBadge(AnalysisResult r)
        {
            Color c = r.Level == "dangerous" ? Color.FromArgb(196, 22, 34) : r.Level == "suspicious" ? Color.FromArgb(214, 120, 0) : Color.FromArgb(16, 124, 65);
            var bmp = new Bitmap(32, 32);
            using (var g = Graphics.FromImage(bmp))
            using (var brush = new SolidBrush(c))
            using (var font = new Font("Segoe UI", r.Score >= 100 ? 9.5f : 12f, FontStyle.Bold))
            using (var fmt = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center })
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
                g.FillRectangle(brush, 0, 0, 32, 32);
                if (r.Verified)
                {
                    // coche blanche : expéditeur vérifié
                    using (var pen = new Pen(Color.White, 4f) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
                        g.DrawLines(pen, new[] { new PointF(8, 17), new PointF(14, 23), new PointF(25, 10) });
                }
                else
                    g.DrawString(r.Score.ToString(), font, Brushes.White, new RectangleF(0, 1, 32, 32), fmt);
            }
            return bmp;
        }

        public object GetImage(object control)
        {
            try
            {
                Bitmap bmp = iconApp ?? (iconApp = LoadBitmap("icon-32.png"));
                return bmp == null ? null : PictureConverter.ToPicture(bmp);
            }
            catch (Exception ex) { Log("Icône : " + ex.Message); return null; }
        }

        /// <summary>Domaine de l'adresse SMTP de la boîte Outlook principale ("" si inconnu).</summary>
        string MailboxDomain()
        {
            try
            {
                dynamic outlook = application;
                dynamic entry = outlook.Session.CurrentUser.AddressEntry;
                string smtp = "";
                try { dynamic ex = entry.GetExchangeUser(); if (ex != null) smtp = Convert.ToString(ex.PrimarySmtpAddress); } catch (Exception) { }
                if (string.IsNullOrEmpty(smtp) || !smtp.Contains("@")) smtp = Convert.ToString(entry.Address);
                return PhishGuard.Domains.RegistrableDomain(PhishGuard.Domains.DomainOfAddress(smtp));
            }
            catch (Exception) { return ""; }
        }

        /// <summary>Ouvre les paramètres (depuis la fenêtre d'enquête). Renvoie true si l'utilisateur a enregistré.</summary>
        bool OpenSettings(IWin32Window owner)
        {
            if (!config.AllowUserSettings) return false;
            try
            {
                Icon icon = null;
                try { var b = LoadBitmap("settings-32.png"); if (b != null) icon = Icon.FromHandle(b.GetHicon()); } catch (Exception) { }
                bool redFlagBefore = config.RedFlagEnabled;
                using (var f = new SettingsForm(PhishGuardConfig.LoadMerged(Path.Combine(InstallDir, "config.ini"), UserConfigPath), icon, MailboxDomain()))
                {
                    if ((owner == null ? f.ShowDialog() : f.ShowDialog(owner)) != DialogResult.OK) return false;
                }
                config = PhishGuardConfig.LoadMerged(Path.Combine(InstallDir, "config.ini"), UserConfigPath);
                ApplyRuntimeSettings();
                Blocklists.ReloadCustom();
                if (!config.RedFlagEnabled) Blocklists.ClearRedFlag();
                else if (!redFlagBefore || Blocklists.RedFlagCount == 0) Blocklists.Init(config, InstallDir);
                cache.Clear();
                cacheOrder.Clear();
                lastSelectionKey = "\u0001"; // force la réanalyse du message affiché
                StartWatching();
                if (!config.KnownCorrespondents) corrPhase = 0;
                foreach (var r in ribbons.ToArray())
                {
                    try { ((dynamic)r).Invalidate(); } catch (Exception) { ribbons.Remove(r); }
                }
                Log("Paramètres enregistrés (analyse auto : " + config.AutoAnalyze + ", alerte : " + config.AlertLevel + ", langue : " + config.Language + ")");
                return true;
            }
            catch (Exception ex)
            {
                Log("Paramètres : " + ex);
                MessageBox.Show(L.T("Impossible d’ouvrir les paramètres :") + "\n" + ex.Message, "PhishGuard", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
        }

        static Bitmap LoadBitmap(string name)
        {
            var asm = Assembly.GetExecutingAssembly();
            using (var s = asm.GetManifestResourceStream("PhishGuard." + name))
            {
                if (s == null) return null;
                return new Bitmap(s);
            }
        }

        // -----------------------------------------------------------------
        // Actions
        // -----------------------------------------------------------------

        public void OnAnalyze(object control)
        {
            Log("Clic sur Analyser");
            try
            {
                object mail = GetMail(control);
                if (mail == null)
                {
                    if (config.AllowUserSettings)
                    {
                        var ask = MessageBox.Show(L.T("Sélectionnez ou ouvrez un email pour l’analyser.") + "\n\n" + L.T("Ouvrir les paramètres de PhishGuard ?"),
                            "PhishGuard", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
                        if (ask == DialogResult.Yes) OpenSettings(null);
                    }
                    else MessageBox.Show(L.T("Sélectionnez ou ouvrez un email pour l’analyser."), "PhishGuard", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                OpenDetails(mail);
            }
            catch (Exception ex)
            {
                Log("Analyse : " + ex);
                MessageBox.Show(L.T("L’analyse n’a pas pu aboutir :") + "\n" + ex.Message, "PhishGuard", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        /// <summary>Analyse complète (empreintes de toutes les pièces jointes) et fenêtre d'enquête.</summary>
        void OpenDetails(object mail)
        {
            var c = AnalyzeCached(mail, true);
            Log("Analyse détaillée : " + c.Result.Level + " (" + c.Result.Score + "), " + c.Data.Links.Count + " liens, " + c.Data.Attachments.Count + " pièces jointes");
            lastMail = mail;
            RunSetupIfNeeded();
            if (form == null || form.IsDisposed)
            {
                Icon icon = null;
                try { var b = LoadBitmap("icon-32.png"); if (b != null) icon = Icon.FromHandle(b.GetHicon()); } catch (Exception) { }
                form = new ResultForm(icon);
                form.NotPhishingRequested += (s, e) =>
                {
                    try { if (form.CurrentResult != null) MarkNotPhishing(form.CurrentResult); }
                    catch (Exception ex) { Log("Confiance : " + ex); }
                };
                form.ReportRequested += (s, e) =>
                {
                    try
                    {
                        if (lastMail == null) return;
                        var cc = AnalyzeCached(lastMail, true);
                        Report(lastMail, cc.Data, cc.Result);
                    }
                    catch (Exception ex) { form.SetStatus(L.T("Signalement impossible : ") + ex.Message); }
                };
                form.ModeChanged += (s, e) =>
                {
                    try
                    {
                        config.ExpertMode = form.Expert;
                        if (!config.AllowUserSettings) return;   // configuration imposée : le choix vaut pour la session
                        var cfg = PhishGuardConfig.LoadMerged(Path.Combine(InstallDir, "config.ini"), UserConfigPath);
                        cfg.ExpertMode = form.Expert;
                        cfg.SaveUser(UserConfigPath);
                    }
                    catch (Exception ex) { Log("Mode d'affichage : " + ex.Message); }
                };
                form.SettingsRequested += (s, e) =>
                {
                    try
                    {
                        if (!OpenSettings(form)) return;
                        // Réanalyse avec les nouveaux réglages (langue, domaines, explications...)
                        if (lastMail != null) OpenDetails(lastMail);
                    }
                    catch (Exception ex) { Log("Paramètres depuis la fenêtre : " + ex); }
                };
            }
            form.Expert = config.ExpertMode;
            form.ShowResult(c.Result, c.Data, ListStatus(), config.ShowExplanations, config.AllowUserSettings);
            InvalidateRibbons();
        }

        bool setupChecked;

        /// <summary>Assistant de démarrage : tout au premier lancement, puis seulement les étapes ajoutées par une mise à jour.</summary>
        void RunSetupIfNeeded()
        {
            if (setupChecked || !config.AllowUserSettings) return;
            setupChecked = true;
            try
            {
                var cfg = PhishGuardConfig.LoadMerged(Path.Combine(InstallDir, "config.ini"), UserConfigPath);
                var pending = cfg.PendingSetup(FirstRunForm.Steps, File.Exists(UserConfigPath));
                if (pending.Count == 0)
                {
                    if (cfg.SetupDone.Count < FirstRunForm.Steps.Length) { cfg.SetupDone = FirstRunForm.Steps.ToList(); cfg.SaveUser(UserConfigPath); }
                    return;
                }
                Icon icon = null;
                try { var b = LoadBitmap("icon-32.png"); if (b != null) icon = Icon.FromHandle(b.GetHicon()); } catch (Exception) { }
                using (var f = new FirstRunForm(cfg, MailboxDomain(), icon, pending)) f.ShowDialog();
                Log("Assistant de démarrage : " + string.Join(", ", pending.ToArray()));
                cfg.SetupDone = FirstRunForm.Steps.ToList();   // vu, même avec « Plus tard » : l'assistant ne revient pas
                cfg.SaveUser(UserConfigPath);
                config = PhishGuardConfig.LoadMerged(Path.Combine(InstallDir, "config.ini"), UserConfigPath);
                ApplyRuntimeSettings();
                cache.Clear(); cacheOrder.Clear();
            }
            catch (Exception ex) { Log("Premier lancement : " + ex.Message); }
        }

        void Report(object mail, EmailData data, AnalysisResult result)
        {
            if (string.IsNullOrEmpty(config.ReportAddress))
            {
                if (config.AllowUserSettings)
                {
                    var ask = MessageBox.Show(L.T("Aucune adresse de l’équipe sécurité n’est configurée.") + "\n\n" + L.T("Voulez-vous l’indiquer maintenant ?"),
                        "PhishGuard", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                    if (ask == DialogResult.Yes) OpenSettings(form != null && !form.IsDisposed && form.Visible ? form : null);
                }
                else MessageBox.Show(L.T("Aucune adresse de signalement n’est configurée : contactez votre service informatique."), "PhishGuard", MessageBoxButtons.OK, MessageBoxIcon.Information);
                if (string.IsNullOrEmpty(config.ReportAddress)) return;
            }
            IWin32Window owner = form != null && !form.IsDisposed && form.Visible ? form : null;

            // Double confirmation : un signalement part vers une autre personne et déplace le message
            string after = config.MoveAfterReport ? L.T("puis déplacé dans « Courrier indésirable »") : L.T("puis laissé à sa place");
            string first = L.T("Signaler ce message à l’équipe sécurité ?") + "\n\n"
                + L.T("De : ") + data.FromName + " <" + data.FromAddress + ">\n"
                + L.T("Objet : ") + data.Subject + "\n"
                + L.T("Verdict PhishGuard : ") + result.LevelLabel + " (" + result.Score + "/100)\n\n"
                + L.F("Il sera transféré à {0} avec le rapport d’analyse, {1}.", config.ReportAddress, after);
            if (MessageBox.Show(owner, first, L.T("PhishGuard - Signaler (1/2)"), MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            string second = L.F("Confirmez-vous l’envoi du signalement à {0} ?", config.ReportAddress)
                + (result.Level == "safe" ? "\n\n" + L.T("PhishGuard n’a relevé aucun indice important sur ce message.") : "");
            if (MessageBox.Show(owner, second, L.T("PhishGuard - Signaler (2/2)"), MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;

            dynamic app = application;
            string reporter = "";
            try { reporter = Convert.ToString(app.Session.CurrentUser.Name); } catch (Exception) { }
            dynamic msg = app.CreateItem(0); // olMailItem
            msg.To = config.ReportAddress;
            string subject = L.T("[Signalement phishing] ") + "[" + result.LevelLabel + " " + result.Score + "] " + data.Subject;
            msg.Subject = subject.Length > 250 ? subject.Substring(0, 250) : subject;
            msg.BodyFormat = 2; // olFormatHTML
            msg.HTMLBody = ReportHtml.Build(result, data, reporter);
            try { msg.Attachments.Add(mail, 5); } // olEmbeddeditem : le message d'origine joint, avec tous ses en-têtes
            catch (Exception ex) { Log("Pièce jointe du signalement : " + ex.Message); }
            try
            {
                msg.Send();
                Log("Signalement envoyé à " + config.ReportAddress);
            }
            catch (Exception ex)
            {
                // Envoi refusé (stratégie, compte hors ligne...) : on laisse l'utilisateur envoyer lui-même
                Log("Envoi du signalement : " + ex.Message);
                msg.Display(false);
                if (form != null && !form.IsDisposed) form.SetStatus(L.T("Le signalement est ouvert : cliquez sur « Envoyer » dans Outlook."));
                return;
            }
            MoveToJunk(mail);
            if (form != null && !form.IsDisposed) form.SetStatus(L.F("Signalement envoyé à {0}. Merci !", config.ReportAddress));
        }

        /// <summary>Message sélectionné (explorateur, menu contextuel) ou ouvert (inspecteur).</summary>
        object GetMail(object control)
        {
            object candidate = null;
            dynamic ctx = null;
            try { ctx = ((dynamic)control).Context; } catch (Exception) { }

            if (ctx != null)
            {
                try { candidate = ctx.CurrentItem; } catch (Exception) { }             // Inspecteur
                if (candidate == null)
                {
                    try { dynamic sel = ctx.Selection; if (sel.Count > 0) candidate = sel.Item(1); } catch (Exception) { } // Explorateur
                }
                if (candidate == null)
                {
                    try { if (ctx.Count > 0) candidate = ctx.Item(1); } catch (Exception) { }  // Menu contextuel (Selection)
                }
            }
            if (candidate == null)
            {
                try
                {
                    dynamic app = application;
                    dynamic sel = app.ActiveExplorer().Selection;
                    if (sel.Count > 0) candidate = sel.Item(1);
                }
                catch (Exception) { }
            }
            if (candidate == null) return null;
            return IsMail(candidate) ? candidate : null;
        }

        static string ListStatus()
        {
            int n = Blocklists.RedFlagCount;
            string s = n > 0
                ? L.F("Listes : Red Flag Domains, {0} domaines (mise à jour le {1})", n.ToString("N0"), Blocklists.RedFlagUpdated.ToString("dd/MM/yyyy"))
                : L.T("Liste Red Flag Domains non chargée") + (string.IsNullOrEmpty(Blocklists.LastError) ? "" : " : " + Blocklists.LastError);
            int c = Blocklists.CustomCount;
            if (c > 0) s += L.F(" ; liste interne : {0} domaines", c);
            return s;
        }

        static string Str(Func<object> getter)
        {
            try { object v = getter(); return v == null ? "" : v.ToString(); } catch (Exception) { return ""; }
        }

        static void Log(string text)
        {
            try
            {
                Directory.CreateDirectory(Blocklists.DataDir);
                File.AppendAllText(Path.Combine(Blocklists.DataDir, "phishguard.log"), DateTime.Now.ToString("s") + " " + text + Environment.NewLine);
            }
            catch (Exception) { }
        }
    }
}
