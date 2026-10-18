// PhishGuard - fenêtre de réglages, ouverte depuis le bouton « Paramètres » de la fenêtre d'analyse.
// Les réglages sont enregistrés pour l'utilisateur dans %LOCALAPPDATA%\PhishGuard\config.user.ini
// (et la liste interne dans custom.user.txt) : une réinstallation ne les efface pas.

using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace PhishGuard.AddIn
{
    internal class SettingsForm : Form
    {
        readonly PhishGuardConfig cfg;
        readonly TextBox txtDomains, txtReport, txtVips, txtTrusted, txtCustom, txtTrustedSenders, txtShared;
        readonly CheckBox chkAuto, chkRedFlag, chkExplain, chkCorr, chkAge, chkTag, chkMove, chkLog;
        readonly CheckBox chkOpenPhish, chkTranco, chkDns, chkCert, chkPublic;
        readonly TextBox txtVt, txtAbuseCh, txtAbuseIpdb;
        readonly Label lblBeta;
        readonly ComboBox cboAlert, cboLang, cboMode;
        readonly NumericUpDown numHash;
        readonly Label lblLists;

        static readonly string[] AlertValues = { "dangerous", "suspicious", "none" };
        static readonly string[] LangValues = { "auto", "fr", "en" };

        readonly string mailboxDomain;
        readonly ListView lvCompanies;
        readonly List<CompanyEntry> companies;
        CheckBox chkWatch;

        public SettingsForm(PhishGuardConfig current, Icon icon) : this(current, icon, "") { }

        /// <param name="mailboxDomain">domaine de l'adresse de la boîte Outlook (proposé comme domaine de l'entreprise)</param>
        public SettingsForm(PhishGuardConfig current, Icon icon, string mailboxDomain)
        {
            cfg = current;
            this.mailboxDomain = (mailboxDomain ?? "").Trim().ToLowerInvariant();
            Text = L.T("PhishGuard - Paramètres");
            var alertLabels = new[] { L.T("Messages dangereux uniquement"), L.T("Messages suspects et dangereux"), L.T("Aucune alerte") };
            var langLabels = new[] { L.T("Automatique (langue de Windows)"), "Français", "English" };
            Size = new Size(580, 760);
            MinimumSize = new Size(480, 520);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Segoe UI", 9f);
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = true;
            if (icon != null) Icon = icon;

            var tabs = new TabControl { Dock = DockStyle.Fill, Padding = new Point(12, 4) };

            // ---------------- Entreprise ----------------
            var pGeneral = Page(L.T("Entreprise"));
            var y = 12;
            companies = cfg.Companies.Select(c => new CompanyEntry { Name = c.Name, Country = c.Country, Id = c.Id, Directors = new List<string>(c.Directors) }).ToList();
            pGeneral.Controls.Add(new Label { Text = L.T("Entreprises"), Location = new Point(12, y), AutoSize = true, Font = new Font(Font, FontStyle.Bold) });
            y += 22;
            lvCompanies = new ListView { Location = new Point(12, y), Size = new Size(500, 96), View = View.Details, FullRowSelect = true, HideSelection = false,
                HeaderStyle = ColumnHeaderStyle.Nonclickable, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            lvCompanies.Columns.Add(L.T("Entreprise"), 160);
            lvCompanies.Columns.Add(L.T("Pays"), 70);
            lvCompanies.Columns.Add(L.T("Identifiant"), 80);
            lvCompanies.Columns.Add(L.T("Dirigeants"), 180);
            pGeneral.Controls.Add(lvCompanies);
            y += 100;
            var btnAddCompany = new Button { Text = L.T("Ajouter une entreprise…"), Location = new Point(12, y), AutoSize = true };
            btnAddCompany.Click += (s, e) => AddCompanyDialog();
            var btnRemoveCompany = new Button { Text = L.T("Retirer"), Location = new Point(190, y), AutoSize = true };
            btnRemoveCompany.Click += (s, e) =>
            {
                if (lvCompanies.SelectedIndices.Count == 0) return;
                companies.RemoveAt(lvCompanies.SelectedIndices[0]);
                RefreshCompanies();
            };
            var btnEditCompany = new Button { Text = L.T("Modifier…"), Location = new Point(270, y), AutoSize = true };
            btnEditCompany.Click += (s, e) => EditCompany();
            lvCompanies.DoubleClick += (s, e) => EditCompany();
            pGeneral.Controls.Add(btnAddCompany);
            pGeneral.Controls.Add(btnRemoveCompany);
            pGeneral.Controls.Add(btnEditCompany);
            y += 32;
            AddHint(pGeneral, ref y, L.T("Le nom de chaque entreprise est repéré dans le nom affiché des expéditeurs externes. Recherche dans l’Annuaire des Entreprises (France) ou Wikidata (autres pays) ; « Modifier… » complète les dirigeants à la main."));
            y += 10;
            int yDomains = y;
            txtDomains = AddText(pGeneral, ref y, L.T("Domaines de l’entreprise (un par ligne)"), string.Join(Environment.NewLine, cfg.CompanyDomains.ToArray()), true, 70,
                L.T("Un domaine qui les imite (mon-entreprlse.fr, mon-entreprise-fr.com...) est classé critique."));
            if (this.mailboxDomain.Length > 0 && !Lists.FreemailDomains.Contains(this.mailboxDomain))
            {
                var addDom = new LinkLabel { Text = L.F("Ajouter {0} (votre adresse)", this.mailboxDomain), Location = new Point(300, yDomains), AutoSize = true, Anchor = AnchorStyles.Top | AnchorStyles.Right };
                addDom.LinkClicked += (s, e) => AddLines(txtDomains, new[] { this.mailboxDomain });
                pGeneral.Controls.Add(addDom);
            }
            chkWatch = new CheckBox { Text = L.T("Surveiller chaque semaine les nouveaux sosies"), Checked = cfg.WatchDomains, Location = new Point(200, y - 2), AutoSize = true };
            if (cfg.ExpertMode)
            {
                var btnAudit = new Button { Text = L.T("Analyser mon domaine…"), Location = new Point(12, y - 6), AutoSize = true };
                btnAudit.Click += (s, e) => OpenAudit();
                pGeneral.Controls.Add(btnAudit);
                pGeneral.Controls.Add(chkWatch);
                y += 26;
                AddHint(pGeneral, ref y, WatchStatus());
                y += 14;
            }
            txtVips = AddText(pGeneral, ref y, L.T("Dirigeants"), "", true, 60,
                L.T("Rempli à partir des entreprises ci-dessus. Un email externe affichant l’un de ces noms est signalé (fraude au président)."));
            txtVips.ReadOnly = true;
            txtVips.BackColor = SystemColors.Control;
            RefreshCompanies();
            txtReport = AddText(pGeneral, ref y, L.T("Adresse de l’équipe sécurité (bouton « Signaler »)"), cfg.ReportAddress, false, 0,
                L.T("Le bouton « Signaler » de la fenêtre d’analyse lui transfère le message avec le rapport."));
            tabs.TabPages.Add(pGeneral);

            // ---------------- Analyse ----------------
            var pAnalyse = Page(L.T("Analyse"));
            y = 12;
            pAnalyse.Controls.Add(new Label { Text = L.T("Langue de PhishGuard") + " / Language", Location = new Point(12, y), AutoSize = true, Font = new Font(Font, FontStyle.Bold) });
            y += 22;
            cboLang = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Location = new Point(12, y), Width = 300 };
            cboLang.Items.AddRange(langLabels);
            int li = Array.IndexOf(LangValues, (cfg.Language ?? "auto").ToLowerInvariant());
            cboLang.SelectedIndex = li < 0 ? 0 : li;
            pAnalyse.Controls.Add(cboLang);
            y += 36;
            pAnalyse.Controls.Add(new Label { Text = L.T("Affichage"), Location = new Point(12, y), AutoSize = true, Font = new Font(Font, FontStyle.Bold) });
            y += 22;
            cboMode = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Location = new Point(12, y), Width = 300 };
            cboMode.Items.AddRange(new object[] { L.T("Simple : le verdict et quoi faire (recommandé)"), L.T("Expert : analyse technique détaillée") });
            cboMode.SelectedIndex = cfg.ExpertMode ? 1 : 0;
            pAnalyse.Controls.Add(cboMode);
            y += 28;
            AddHint(pAnalyse, ref y, L.T("En mode expert, les onglets Listes et Réputation et l’analyse de votre domaine apparaissent ici (rouvrez les paramètres après avoir changé)."));
            y += 12;
            chkAuto = new CheckBox { Text = L.T("Analyser automatiquement le message sélectionné ou ouvert"), Checked = cfg.AutoAnalyze, Location = new Point(12, y), AutoSize = true };
            pAnalyse.Controls.Add(chkAuto);
            y += 26;
            AddHint(pAnalyse, ref y, L.T("Le score s’affiche alors en permanence dans le ruban."));
            y += 8;
            pAnalyse.Controls.Add(new Label { Text = L.T("Alerte en bas à droite de l’écran"), Location = new Point(12, y), AutoSize = true, Font = new Font(Font, FontStyle.Bold) });
            y += 22;
            cboAlert = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Location = new Point(12, y), Width = 300 };
            cboAlert.Items.AddRange(alertLabels);
            int idx = Array.IndexOf(AlertValues, (cfg.AlertLevel ?? "dangerous").ToLowerInvariant());
            cboAlert.SelectedIndex = idx < 0 ? 0 : idx;
            pAnalyse.Controls.Add(cboAlert);
            y += 36;
            pAnalyse.Controls.Add(new Label { Text = L.T("Empreintes des pièces jointes en analyse automatique, jusqu’à (Mo)"), Location = new Point(12, y), AutoSize = true, Font = new Font(Font, FontStyle.Bold) });
            y += 22;
            numHash = new NumericUpDown { Minimum = 0, Maximum = 40, Value = Math.Max(0, Math.Min(40, cfg.AutoHashMaxMB)), Location = new Point(12, y), Width = 80 };
            pAnalyse.Controls.Add(numHash);
            y += 30;
            AddHint(pAnalyse, ref y, L.T("Au-delà, les empreintes sont calculées à l’ouverture du détail. 0 = jamais en automatique."));
            y += 8;
            chkExplain = AddCheck(pAnalyse, ref y, L.T("Afficher les explications pédagogiques sous chaque indice"), cfg.ShowExplanations,
                L.T("À décocher pour les utilisateurs à l’aise avec la sécurité : seuls les indices bruts sont affichés."));
            chkCorr = AddCheck(pAnalyse, ref y, L.T("Repérer les premiers contacts et les sosies de mes correspondants"), cfg.KnownCorrespondents,
                L.F("Utilise les adresses de vos éléments envoyés et de vos contacts ({0} connues), sans rien envoyer à l’extérieur.", Correspondents.Count));
            chkAge = AddCheck(pAnalyse, ref y, L.T("Vérifier l’âge des domaines (RDAP)"), cfg.DomainAgeLookup,
                L.T("Envoie uniquement le nom du domaine à rdap.org et au registre concerné, jamais le contenu des messages."));
            chkTag = AddCheck(pAnalyse, ref y, L.T("Marquer les messages suspects d’une couleur dans l’en-tête et la liste (catégorie Outlook)"), cfg.TagCategory,
                L.T("Ajoute une catégorie au message : bande de couleur dans son en-tête et dans la liste des messages."));
            chkMove = AddCheck(pAnalyse, ref y, L.T("Déplacer le message dans « Courrier indésirable » après l’avoir signalé"), cfg.MoveAfterReport, null);
            chkLog = AddCheck(pAnalyse, ref y, L.T("Tenir un journal des scores (scores.csv) pour ajuster les réglages"), cfg.ScoreLog,
                L.T("Date, verdict, score, domaine de l’expéditeur et indices ; ni l’objet ni le contenu des messages."));
            tabs.TabPages.Add(pAnalyse);

            // ---------------- Listes ----------------
            var pLists = Page(L.T("Listes"));
            y = 12;
            txtTrusted = AddText(pLists, ref y, L.T("Domaines de confiance (un par ligne)"), string.Join(Environment.NewLine, cfg.TrustedDomains.ToArray()), true, 60,
                L.T("Partenaires jamais signalés comme domaines sosies."));
            txtTrustedSenders = AddText(pLists, ref y, L.T("Expéditeurs de confiance (une adresse par ligne)"), string.Join(Environment.NewLine, cfg.TrustedSenders.ToArray()), true, 60,
                L.T("Ajoutés aussi par le bouton « Ce n’est pas du phishing ». Un échec d’authentification reste toujours signalé."));
            string userCustom = "";
            try { if (File.Exists(Blocklists.UserCustomPath)) userCustom = File.ReadAllText(Blocklists.UserCustomPath, Encoding.UTF8); } catch (Exception) { }
            txtCustom = AddText(pLists, ref y, L.T("Domaines malveillants à bloquer (un par ligne)"), userCustom, true, 90,
                L.T("Tout message ou lien vers ces domaines (et leurs sous-domaines) est classé critique."));
            txtShared = AddText(pLists, ref y, L.T("Liste de blocage partagée (chemin réseau, facultatif)"), cfg.SharedBlocklistPath, false, 0,
                L.T("Ex. : \\\\serveur\\securite\\phishguard.txt — gérée par l’équipe sécurité, un domaine par ligne."));
            if (cfg.ExpertMode) tabs.TabPages.Add(pLists);

            // ---------------- Réputation ----------------
            var pBeta = Page(L.T("Réputation"));
            y = 12;
            AddHint(pBeta, ref y, L.T("Sources de réputation externes. Elles n’envoient jamais le contenu des messages : seulement des noms de domaine, des adresses de liens, des empreintes de fichiers ou une adresse IP."));
            y += 18;
            pBeta.Controls.Add(new Label { Text = L.T("Sans clé"), Location = new Point(12, y), AutoSize = true, Font = new Font(Font, FontStyle.Bold) });
            y += 24;
            chkRedFlag = new CheckBox { Text = L.T("Utiliser la liste Red Flag Domains (nouveaux domaines .fr suspects)"), Checked = cfg.RedFlagEnabled, Location = new Point(12, y), AutoSize = true };
            pBeta.Controls.Add(chkRedFlag);
            y += 26;
            lblLists = new Label { Location = new Point(30, y), Size = new Size(370, 34), ForeColor = SystemColors.GrayText };
            pBeta.Controls.Add(lblLists);
            var btnUpdate = new Button { Text = L.T("Mettre à jour"), Location = new Point(410, y - 2), AutoSize = true, Anchor = AnchorStyles.Top | AnchorStyles.Right };
            btnUpdate.Click += (s, e) => { Blocklists.StartDownload(cfg.RedFlagUrl); lblLists.Text = L.T("Téléchargement en cours…"); };
            pBeta.Controls.Add(btnUpdate);
            y += 40;
            chkPublic = AddCheck(pBeta, ref y, L.T("Liste des domaines du secteur public (État, collectivités, hôpitaux…)"), cfg.PublicSectorList,
                L.T("Liste ouverte de la DINUM (environ 100 000 domaines), téléchargée chaque mois : un message authentifié d’un organisme public n’est pas pris pour un faux. Les domaines .gouv.fr sont reconnus même sans la liste."));
            chkOpenPhish = AddCheck(pBeta, ref y, L.T("Liste OpenPhish des pages de phishing actives"), cfg.BetaOpenPhish,
                L.T("Téléchargée toutes les 12 h depuis openphish.com ; la comparaison des liens se fait sur votre poste."));
            chkTranco = AddCheck(pBeta, ref y, L.T("Classement Tranco des sites les plus visités"), cfg.BetaTranco,
                L.T("Téléchargé chaque semaine (environ 10 Mo) : reconnaît les domaines très fréquentés et réduit les faux positifs."));
            chkDns = AddCheck(pBeta, ref y, L.T("Vérifier le domaine de l’expéditeur dans le DNS (existence, MX, SPF, DMARC, BIMI)"), cfg.BetaDnsChecks,
                L.T("Utilise le serveur DNS de votre entreprise, comme une navigation normale. Vérifie aussi si un domaine qui ressemble à une marque lui appartient (géré par ses serveurs DNS)."));
            chkCert = AddCheck(pBeta, ref y, L.T("Âge du premier certificat HTTPS des domaines (crt.sh)"), cfg.BetaCertAge,
                L.T("Envoie le nom du domaine à crt.sh (journaux publics des certificats)."));
            y += 6;
            pBeta.Controls.Add(new Label { Text = L.T("Avec une clé gratuite (laisser vide pour désactiver)"), Location = new Point(12, y), AutoSize = true, Font = new Font(Font, FontStyle.Bold) });
            y += 22;
            AddHint(pBeta, ref y, L.T("Les clés sont rangées dans le Gestionnaire d’identification de Windows : chiffrées pour votre compte, jamais écrites en clair, et conservées lors des mises à jour."));
            y += 14;
            txtVt = AddKey(pBeta, ref y, "VirusTotal", cfg.VirusTotalKey, "https://www.virustotal.com/gui/join-us",
                L.T("Réputation des pièces jointes (empreinte SHA-256 seulement, le fichier n’est jamais envoyé). Version gratuite : 4 requêtes par minute."));
            txtAbuseCh = AddKey(pBeta, ref y, "abuse.ch (URLhaus + ThreatFox)", cfg.AbuseChKey, "https://auth.abuse.ch/",
                L.T("Domaines et fichiers connus pour diffuser des logiciels malveillants."));
            txtAbuseIpdb = AddKey(pBeta, ref y, "AbuseIPDB", cfg.AbuseIpdbKey, "https://www.abuseipdb.com/register",
                L.T("Réputation de l’adresse IP d’origine du message."));
            lblBeta = new Label { Location = new Point(12, y), Size = new Size(500, 70), ForeColor = SystemColors.GrayText, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            pBeta.Controls.Add(lblBeta);
            if (cfg.ExpertMode) tabs.TabPages.Add(pBeta);
            RefreshBetaStatus();
            RefreshListStatus();
            var listTimer = new Timer { Interval = 1500 };
            listTimer.Tick += (s, e) => { if (!Blocklists.IsDownloading) RefreshListStatus(); RefreshBetaStatus(); };
            listTimer.Start();
            FormClosed += (s, e) => listTimer.Dispose();

            // ---------------- À propos ----------------
            var pAbout = Page(L.T("À propos"));
            AboutPage.Fill(pAbout, cfg, false);
            tabs.TabPages.Add(pAbout);

            // ---------------- Boutons ----------------
            var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 46, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(8) };
            var btnCancel = new Button { Text = L.T("Annuler"), DialogResult = DialogResult.Cancel, AutoSize = true, Height = 30 };
            var btnOk = new Button { Text = L.T("Enregistrer"), AutoSize = true, Height = 30 };
            btnOk.Click += (s, e) => { if (Save()) { DialogResult = DialogResult.OK; Close(); } };
            var btnLog = new Button { Text = L.T("Ouvrir le dossier PhishGuard"), AutoSize = true, Height = 30 };
            btnLog.Click += (s, e) => { try { System.Diagnostics.Process.Start("explorer.exe", "\"" + Blocklists.DataDir + "\""); } catch (Exception) { } };
            bar.Controls.AddRange(new Control[] { btnCancel, btnOk, btnLog });
            AcceptButton = btnOk;
            CancelButton = btnCancel;

            Controls.Add(tabs);
            Controls.Add(bar);
        }

        /// <summary>Ajoute des lignes absentes (sans tenir compte de la casse) à une zone de texte multiligne.</summary>
        static int AddLines(TextBox t, IEnumerable<string> values)
        {
            var existing = Lines(t, false);
            int added = 0;
            foreach (var v in values)
            {
                if (existing.Any(x => string.Equals(x, v, StringComparison.OrdinalIgnoreCase))) continue;
                string cur = t.Text.TrimEnd();
                t.Text = cur.Length == 0 ? v : cur + Environment.NewLine + v;
                existing.Add(v);
                added++;
            }
            return added;
        }

        static string WatchStatus()
        {
            var map = DomainAudit.LoadWatch();
            DomainAudit.WatchEntry last;
            if (!map.TryGetValue("*", out last))
                return L.T("Sécurité email, dirigeants, sosies déjà enregistrés. La surveillance bloque ensuite les sosies qui apparaissent (DNS uniquement).");
            int blocked = map.Values.Count(x => x.Status == "new" || x.Status == "cert");
            return L.F("Dernière vérification des sosies : {0} — {1} domaine(s) bloqué(s) par la surveillance.", last.Date.ToString("dd/MM/yyyy"), blocked);
        }

        void OpenAudit()
        {
            var domains = Lines(txtDomains, true).Select(d => d.TrimStart('@')).ToList();
            if (domains.Count == 0 && mailboxDomain.Length > 0 && !Lists.FreemailDomains.Contains(mailboxDomain)) domains.Add(mailboxDomain);
            using (var f = new DomainAuditForm(domains, Icon))
            {
                f.BlockDomains = list => AddLines(txtCustom, list);
                f.AddCompanyDomains = list => AddLines(txtDomains, list);
                f.AddCompany = c => AddCompanyInfo(c);
                f.ShowDialog(this);
            }
        }

        /// <summary>Liste des entreprises et, en lecture seule, l'ensemble de leurs dirigeants.</summary>
        void RefreshCompanies()
        {
            lvCompanies.Items.Clear();
            foreach (var c in companies)
                lvCompanies.Items.Add(new ListViewItem(new[] { c.Name, c.Country, c.Id, string.Join(", ", c.Directors.ToArray()) }));
            var vips = new List<string>();
            foreach (var d in companies.SelectMany(c => c.Directors))
                if (!vips.Any(v => string.Equals(v, d, StringComparison.OrdinalIgnoreCase))) vips.Add(d);
            txtVips.Text = string.Join(Environment.NewLine, vips.ToArray());
        }

        /// <summary>Ajoute (ou met à jour) une entreprise trouvée, et propose ses domaines.</summary>
        void AddCompanyInfo(CompanyInfo c)
        {
            var existing = companies.FirstOrDefault(x => (x.Id.Length > 0 && x.Id == c.Siren) || string.Equals(x.Name, c.Name, StringComparison.OrdinalIgnoreCase));
            if (existing == null) { existing = new CompanyEntry(); companies.Add(existing); }
            existing.Name = c.Country == "FR" ? CompanyLookup.Title(c.Name) : c.Name;
            existing.Country = c.Country;
            existing.Id = c.Siren;
            existing.Directors = new List<string>(c.Directors);
            if (c.Website.Length > 0) AddLines(txtDomains, new[] { c.Website });
            else if (c.Country == "FR" && companies.Count == 1 && mailboxDomain.Length > 0 && !Lists.FreemailDomains.Contains(mailboxDomain))
                AddLines(txtDomains, new[] { mailboxDomain });
            RefreshCompanies();
        }

        /// <summary>Modifier une entreprise : nom, pays, identifiant et dirigeants (ceux que les annuaires ne connaissent pas).</summary>
        void EditCompany()
        {
            if (lvCompanies.SelectedIndices.Count == 0) return;
            using (var m = new CompanyEditForm(companies[lvCompanies.SelectedIndices[0]]))
                if (m.ShowDialog(this) == DialogResult.OK) RefreshCompanies();
        }

        void AddCompanyDialog()
        {
            using (var f = new CompanyAddForm())
            {
                if (f.ShowDialog(this) != DialogResult.OK) return;
                if (f.Selected != null) AddCompanyInfo(f.Selected);
                else if (f.ManualName.Length > 0)
                {
                    var entry = new CompanyEntry { Name = f.ManualName };
                    using (var m = new CompanyEditForm(entry))
                        if (m.ShowDialog(this) != DialogResult.OK) return;
                    companies.Add(entry);
                    RefreshCompanies();
                }
            }
        }

        void RefreshListStatus()
        {
            int n = Blocklists.RedFlagCount;
            lblLists.Text = n > 0
                ? L.F("{0} domaines, mise à jour le {1}", n.ToString("N0"), Blocklists.RedFlagUpdated.ToString("dd/MM/yyyy HH:mm"))
                : L.T("Liste non chargée") + (string.IsNullOrEmpty(Blocklists.LastError) ? "" : " : " + Blocklists.LastError);
        }

        void RefreshBetaStatus()
        {
            var parts = new List<string>();
            if (Feeds.OpenPhishCount > 0) parts.Add(L.F("OpenPhish : {0} adresses ({1})", Feeds.OpenPhishCount.ToString("N0"), Feeds.OpenPhishUpdated.ToString("g")));
            if (Feeds.PublicSectorCount > 0) parts.Add(L.F("Secteur public : {0} domaines ({1})", Feeds.PublicSectorCount.ToString("N0"), Feeds.PublicSectorUpdated.ToString("d")));
            if (Feeds.TrancoCount > 0) parts.Add(L.F("Tranco : {0} domaines ({1})", Feeds.TrancoCount.ToString("N0"), Feeds.TrancoUpdated.ToString("d")));
            if (!string.IsNullOrEmpty(Feeds.LastError)) parts.Add(L.T("Dernière erreur : ") + Feeds.LastError);
            if (!string.IsNullOrEmpty(Intel.LastError)) parts.Add(L.T("Dernière erreur : ") + Intel.LastError);
            lblBeta.Text = string.Join("\n", parts.ToArray());
        }

        /// <summary>Champ de clé d'API masqué, avec un lien pour en obtenir une.</summary>
        TextBox AddKey(TabPage page, ref int y, string name, string value, string signupUrl, string hint)
        {
            page.Controls.Add(new Label { Text = name, Location = new Point(12, y + 3), AutoSize = true, Font = new Font(Font, FontStyle.Bold) });
            var link = new LinkLabel { Text = L.T("Obtenir une clé gratuite"), Location = new Point(300, y + 3), AutoSize = true, Anchor = AnchorStyles.Top | AnchorStyles.Right };
            link.LinkClicked += (s, e) => { try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(signupUrl) { UseShellExecute = true }); } catch (Exception) { } };
            page.Controls.Add(link);
            y += 24;
            var t = new TextBox { Text = value ?? "", Location = new Point(12, y), Width = 500, UseSystemPasswordChar = true, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            page.Controls.Add(t);
            y += t.Height + 4;
            AddHint(page, ref y, hint);
            y += 12;
            return t;
        }

        CheckBox AddCheck(TabPage page, ref int y, string text, bool value, string hint)
        {
            var c = new CheckBox { Text = text, Checked = value, Location = new Point(12, y), AutoSize = true };
            page.Controls.Add(c);
            y += 24;
            if (!string.IsNullOrEmpty(hint))
            {
                page.Controls.Add(new Label { Text = hint, Location = new Point(30, y), AutoSize = true, ForeColor = SystemColors.GrayText, MaximumSize = new Size(480, 0) });
                y += Math.Max(20, TextHeight(hint, 480) + 10);
            }
            else y += 6;
            return c;
        }

        static TabPage Page(string title)
        {
            return new TabPage(title) { AutoScroll = true, Padding = new Padding(8), UseVisualStyleBackColor = true };
        }

        TextBox AddText(TabPage page, ref int y, string label, string value, bool multiline, int height, string hint)
        {
            page.Controls.Add(new Label { Text = label, Location = new Point(12, y), AutoSize = true, Font = new Font(Font, FontStyle.Bold) });
            y += 22;
            var t = new TextBox
            {
                Text = value ?? "",
                Location = new Point(12, y),
                Width = 500,
                Multiline = multiline,
                ScrollBars = multiline ? ScrollBars.Vertical : ScrollBars.None,
                AcceptsReturn = multiline,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            if (multiline) t.Height = height;
            page.Controls.Add(t);
            y += (multiline ? height : t.Height) + 4;
            if (!string.IsNullOrEmpty(hint)) AddHint(page, ref y, hint);
            y += 10;
            return t;
        }

        static readonly Font UiFont = new Font("Segoe UI", 9f);

        /// <summary>Hauteur réelle d'un texte replié sur la largeur donnée (évite les chevauchements).</summary>
        static int TextHeight(string text, int width)
        {
            return TextRenderer.MeasureText(text ?? "", UiFont, new Size(width, 0), TextFormatFlags.WordBreak).Height;
        }

        static void AddHint(Control page, ref int y, string text)
        {
            page.Controls.Add(new Label { Text = text, Location = new Point(12, y), AutoSize = true, ForeColor = SystemColors.GrayText, MaximumSize = new Size(500, 0) });
            y += Math.Max(20, TextHeight(text, 500) + 4);
        }

        static List<string> Lines(TextBox t, bool lower)
        {
            var list = new List<string>();
            foreach (var raw in t.Text.Split(new[] { '\r', '\n', ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string v = raw.Trim();
                if (lower) v = v.ToLowerInvariant();
                if (v.Length > 0 && !list.Contains(v)) list.Add(v);
            }
            return list;
        }

        bool Save()
        {
            string report = txtReport.Text.Trim();
            if (report.Length > 0 && !System.Text.RegularExpressions.Regex.IsMatch(report, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
            {
                MessageBox.Show(this, L.T("L’adresse de l’équipe sécurité n’est pas valide."), "PhishGuard", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
            cfg.Companies = companies;
            cfg.CompanyName = "";
            cfg.CompanyDomains = Lines(txtDomains, true).Select(d => d.TrimStart('@')).ToList();
            cfg.VipNames = new List<string>();   // recalculés à partir des entreprises (NormalizeCompanies)
            cfg.ReportAddress = report;
            cfg.TrustedDomains = Lines(txtTrusted, true);
            cfg.AutoAnalyze = chkAuto.Checked;
            cfg.AlertLevel = AlertValues[Math.Max(0, cboAlert.SelectedIndex)];
            cfg.Language = LangValues[Math.Max(0, cboLang.SelectedIndex)];
            cfg.AutoHashMaxMB = (int)numHash.Value;
            cfg.RedFlagEnabled = chkRedFlag.Checked;
            cfg.ShowExplanations = chkExplain.Checked;
            cfg.KnownCorrespondents = chkCorr.Checked;
            cfg.DomainAgeLookup = chkAge.Checked;
            cfg.TagCategory = chkTag.Checked;
            cfg.MoveAfterReport = chkMove.Checked;
            cfg.ScoreLog = chkLog.Checked;
            cfg.TrustedSenders = Lines(txtTrustedSenders, true).Where(x => x.Contains("@")).ToList();
            cfg.SharedBlocklistPath = txtShared.Text.Trim();
            cfg.WatchDomains = chkWatch.Checked;
            cfg.ExpertMode = cboMode.SelectedIndex == 1;
            cfg.PublicSectorList = chkPublic.Checked;
            cfg.BetaOpenPhish = chkOpenPhish.Checked;
            cfg.BetaTranco = chkTranco.Checked;
            cfg.BetaDnsChecks = chkDns.Checked;
            cfg.BetaCertAge = chkCert.Checked;
            cfg.VirusTotalKey = txtVt.Text.Trim();
            cfg.AbuseChKey = txtAbuseCh.Text.Trim();
            cfg.AbuseIpdbKey = txtAbuseIpdb.Text.Trim();
            try
            {
                cfg.SaveUser(Connect.UserConfigPath);
                var custom = new StringBuilder();
                custom.AppendLine("# Domaines malveillants ajoutés depuis Outlook (bouton Paramètres de PhishGuard)");
                foreach (var d in Lines(txtCustom, true)) if (!d.StartsWith("#")) custom.AppendLine(d);
                File.WriteAllText(Blocklists.UserCustomPath, custom.ToString(), new UTF8Encoding(true));
                return true;
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, L.T("Enregistrement impossible :") + "\n" + ex.Message, "PhishGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        }
    }

    /// <summary>Ajout d'une entreprise : recherche dans l'Annuaire des Entreprises (France) ou Wikidata (autres pays).</summary>
    internal class CompanyAddForm : Form
    {
        readonly TextBox txtName;
        readonly ComboBox cboSource;
        readonly Button btnSearch, btnOk;
        readonly ListView list;
        readonly Label lblInfo;
        List<CompanyInfo> items = new List<CompanyInfo>();
        public CompanyInfo Selected;
        public string ManualName = "";

        public CompanyAddForm()
        {
            Text = L.T("PhishGuard - Ajouter une entreprise");
            Size = new Size(780, 440);
            StartPosition = FormStartPosition.CenterParent;
            Font = new Font("Segoe UI", 9f);
            MinimizeBox = false; MaximizeBox = false; ShowInTaskbar = false;

            var top = new Panel { Dock = DockStyle.Top, Height = 74 };
            top.Controls.Add(new Label { Text = L.T("Nom de l’entreprise (ou SIREN)"), Location = new Point(10, 12), AutoSize = true });
            txtName = new TextBox { Location = new Point(10, 34), Width = 300 };
            cboSource = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Location = new Point(320, 33), Width = 290 };
            cboSource.Items.AddRange(new object[] { L.T("France (Annuaire des Entreprises)"), L.T("Autre pays (Wikidata)") });
            cboSource.SelectedIndex = 0;
            btnSearch = new Button { Text = L.T("Rechercher"), Location = new Point(620, 32), AutoSize = true };
            btnSearch.Click += (s, e) => Search();
            top.Controls.AddRange(new Control[] { txtName, cboSource, btnSearch });

            lblInfo = new Label { Dock = DockStyle.Top, Height = 26, Padding = new Padding(10, 4, 10, 0), ForeColor = SystemColors.GrayText,
                Text = L.T("Choisissez la bonne entreprise parmi les résultats : son nom et ses dirigeants seront surveillés.") };
            list = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = false, HideSelection = false };
            list.Columns.Add(L.T("Entreprise"), 210);
            list.Columns.Add(L.T("Lieu"), 110);
            list.Columns.Add(L.T("Identifiant"), 90);
            list.Columns.Add(L.T("Dirigeants"), 330);
            list.DoubleClick += (s, e) => Accept();

            var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 44, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(8) };
            var cancel = new Button { Text = L.T("Annuler"), DialogResult = DialogResult.Cancel, AutoSize = true };
            btnOk = new Button { Text = L.T("Ajouter"), AutoSize = true, Enabled = false };
            btnOk.Click += (s, e) => Accept();
            var manual = new Button { Text = L.T("Ajouter sans recherche"), AutoSize = true };
            manual.Click += (s, e) =>
            {
                ManualName = txtName.Text.Trim();
                if (ManualName.Length == 0) return;
                DialogResult = DialogResult.OK;
                Close();
            };
            bar.Controls.AddRange(new Control[] { cancel, btnOk, manual });
            AcceptButton = btnSearch; CancelButton = cancel;
            Controls.Add(list); Controls.Add(lblInfo); Controls.Add(top); Controls.Add(bar);
        }

        void Search()
        {
            string name = txtName.Text.Trim();
            if (name.Length < 2) return;
            bool world = cboSource.SelectedIndex == 1;
            btnSearch.Enabled = false;
            lblInfo.Text = L.T("Recherche…");
            list.Items.Clear();
            string lang = L.English ? "en" : "fr";
            var t = new System.Threading.Thread(() =>
            {
                List<CompanyInfo> found = null;
                string error = null;
                try { found = world ? CompanyLookup.SearchWorld(name, lang) : CompanyLookup.Search(name); }
                catch (Exception ex) { error = ex.Message; }
                try { BeginInvoke(new Action(() => ShowResults(found, error, world))); } catch (Exception) { }
            });
            t.IsBackground = true;
            t.Start();
        }

        void ShowResults(List<CompanyInfo> found, string error, bool world)
        {
            btnSearch.Enabled = true;
            items = found ?? new List<CompanyInfo>();
            if (error != null) { lblInfo.Text = (world ? L.T("Wikidata est injoignable : ") : L.T("L’Annuaire des Entreprises est injoignable :") + " ") + error; return; }
            if (items.Count == 0)
            {
                lblInfo.Text = world ? L.T("Aucune entreprise trouvée. Wikidata ne connaît que les entreprises assez connues : utilisez « Ajouter sans recherche ».")
                    : L.T("Aucune entreprise trouvée. Vérifiez le nom ou utilisez « Ajouter sans recherche ».");
                return;
            }
            lblInfo.Text = world ? L.T("Source : Wikidata. Choisissez la bonne entreprise ; son site officiel sera ajouté aux domaines.")
                : L.T("Source : Annuaire des Entreprises (INSEE, RNE). Choisissez la bonne entreprise.");
            foreach (var c in items)
            {
                var it = new ListViewItem(new[] { c.Name + (c.Active ? "" : " " + L.T("(fermée)")), c.City, c.Siren, string.Join(", ", c.Roles.ToArray()) });
                if (!c.Active) it.ForeColor = SystemColors.GrayText;
                list.Items.Add(it);
            }
            list.Items[0].Selected = true;
            btnOk.Enabled = true;
            AcceptButton = btnOk;
        }

        void Accept()
        {
            if (list.SelectedIndices.Count == 0) return;
            Selected = items[list.SelectedIndices[0]];
            DialogResult = DialogResult.OK;
            Close();
        }
    }

    /// <summary>Saisie ou modification d'une entreprise à la main (filiale étrangère, entreprise absente des annuaires).</summary>
    internal class CompanyEditForm : Form
    {
        readonly CompanyEntry entry;
        readonly TextBox txtName, txtCountry, txtId, txtDirectors;

        public CompanyEditForm(CompanyEntry e)
        {
            entry = e;
            Text = L.T("PhishGuard - Entreprise");
            Size = new Size(460, 400);
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            Font = new Font("Segoe UI", 9f);
            MinimizeBox = false; MaximizeBox = false; ShowInTaskbar = false;
            int y = 12;
            txtName = Field(L.T("Nom de l’entreprise"), e.Name, ref y, false);
            txtCountry = Field(L.T("Pays"), e.Country, ref y, false);
            txtId = Field(L.T("Identifiant (SIREN, numéro du registre…), facultatif"), e.Id, ref y, false);
            txtDirectors = Field(L.T("Dirigeants (un nom par ligne)"), string.Join(Environment.NewLine, e.Directors.ToArray()), ref y, true);
            var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 44, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(8) };
            var cancel = new Button { Text = L.T("Annuler"), DialogResult = DialogResult.Cancel, AutoSize = true };
            var ok = new Button { Text = L.T("Enregistrer"), AutoSize = true };
            ok.Click += (s, ev) =>
            {
                if (txtName.Text.Trim().Length == 0) return;
                entry.Name = txtName.Text.Trim();
                entry.Country = txtCountry.Text.Trim();
                entry.Id = txtId.Text.Trim();
                entry.Directors = txtDirectors.Text.Split(new[] { '\r', '\n', ',', ';' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(d => d.Trim()).Where(d => d.Length > 0).Distinct().ToList();
                DialogResult = DialogResult.OK;
                Close();
            };
            bar.Controls.AddRange(new Control[] { cancel, ok });
            Controls.Add(bar);
            AcceptButton = ok; CancelButton = cancel;
        }

        TextBox Field(string label, string value, ref int y, bool multiline)
        {
            Controls.Add(new Label { Text = label, Location = new Point(12, y), AutoSize = true });
            y += 20;
            var t = new TextBox { Text = value ?? "", Location = new Point(12, y), Width = 420, Multiline = multiline, AcceptsReturn = multiline, ScrollBars = multiline ? ScrollBars.Vertical : ScrollBars.None };
            if (multiline) t.Height = 110;
            Controls.Add(t);
            y += t.Height + 12;
            return t;
        }
    }
}
