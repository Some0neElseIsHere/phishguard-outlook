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
        readonly TextBox txtCompany, txtDomains, txtReport, txtVips, txtTrusted, txtCustom, txtTrustedSenders, txtShared;
        readonly CheckBox chkAuto, chkRedFlag, chkExplain, chkCorr, chkAge, chkTag, chkMove, chkLog;
        readonly ComboBox cboAlert, cboLang;
        readonly NumericUpDown numHash;
        readonly Label lblLists;

        static readonly string[] AlertValues = { "dangerous", "suspicious", "none" };
        static readonly string[] LangValues = { "auto", "fr", "en" };

        public SettingsForm(PhishGuardConfig current, Icon icon)
        {
            cfg = current;
            Text = L.T("PhishGuard - Paramètres");
            var alertLabels = new[] { L.T("Messages dangereux uniquement"), L.T("Messages suspects et dangereux"), L.T("Aucune alerte") };
            var langLabels = new[] { L.T("Automatique (langue de Windows)"), "Français", "English" };
            Size = new Size(580, 680);
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
            txtCompany = AddText(pGeneral, ref y, L.T("Nom de l’entreprise"), cfg.CompanyName, false, 0,
                L.T("Repéré dans le nom affiché des expéditeurs externes."));
            txtDomains = AddText(pGeneral, ref y, L.T("Domaines de l’entreprise (un par ligne)"), string.Join(Environment.NewLine, cfg.CompanyDomains.ToArray()), true, 70,
                L.T("Un domaine qui les imite (mon-entreprlse.fr, mon-entreprise-fr.com...) est classé critique."));
            txtVips = AddText(pGeneral, ref y, L.T("Dirigeants et personnes sensibles (un nom par ligne)"), string.Join(Environment.NewLine, cfg.VipNames.ToArray()), true, 70,
                L.T("Un email externe affichant l’un de ces noms est signalé (fraude au président)."));
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
            y += 40;
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
            chkTag = AddCheck(pAnalyse, ref y, L.T("Ajouter une catégorie de couleur aux messages suspects et dangereux"), cfg.TagCategory,
                L.T("Visible directement dans la liste des messages (boîte de réception)."));
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
            chkRedFlag = new CheckBox { Text = L.T("Utiliser la liste Red Flag Domains (nouveaux domaines .fr suspects)"), Checked = cfg.RedFlagEnabled, Location = new Point(12, y), AutoSize = true };
            pLists.Controls.Add(chkRedFlag);
            y += 26;
            lblLists = new Label { Location = new Point(28, y), Size = new Size(380, 34), ForeColor = SystemColors.GrayText };
            pLists.Controls.Add(lblLists);
            var btnUpdate = new Button { Text = L.T("Mettre à jour"), Location = new Point(410, y - 2), AutoSize = true, Anchor = AnchorStyles.Top | AnchorStyles.Right };
            btnUpdate.Click += (s, e) => { Blocklists.StartDownload(cfg.RedFlagUrl); lblLists.Text = L.T("Téléchargement en cours…"); };
            pLists.Controls.Add(btnUpdate);
            tabs.TabPages.Add(pLists);
            RefreshListStatus();
            var listTimer = new Timer { Interval = 1500 };
            listTimer.Tick += (s, e) => { if (!Blocklists.IsDownloading) RefreshListStatus(); };
            listTimer.Start();
            FormClosed += (s, e) => listTimer.Dispose();

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

        void RefreshListStatus()
        {
            int n = Blocklists.RedFlagCount;
            lblLists.Text = n > 0
                ? L.F("{0} domaines, mise à jour le {1}", n.ToString("N0"), Blocklists.RedFlagUpdated.ToString("dd/MM/yyyy HH:mm"))
                : L.T("Liste non chargée") + (string.IsNullOrEmpty(Blocklists.LastError) ? "" : " : " + Blocklists.LastError);
        }

        CheckBox AddCheck(TabPage page, ref int y, string text, bool value, string hint)
        {
            var c = new CheckBox { Text = text, Checked = value, Location = new Point(12, y), AutoSize = true };
            page.Controls.Add(c);
            y += 24;
            if (!string.IsNullOrEmpty(hint))
            {
                page.Controls.Add(new Label { Text = hint, Location = new Point(30, y), AutoSize = true, ForeColor = SystemColors.GrayText, MaximumSize = new Size(480, 0) });
                y += 34;
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

        static void AddHint(Control page, ref int y, string text)
        {
            page.Controls.Add(new Label { Text = text, Location = new Point(12, y), AutoSize = true, ForeColor = SystemColors.GrayText, MaximumSize = new Size(500, 0) });
            y += 20;
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
            cfg.CompanyName = txtCompany.Text.Trim();
            cfg.CompanyDomains = Lines(txtDomains, true).Select(d => d.TrimStart('@')).ToList();
            cfg.VipNames = Lines(txtVips, false);
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
}
