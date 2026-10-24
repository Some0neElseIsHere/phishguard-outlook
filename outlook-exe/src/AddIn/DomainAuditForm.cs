// PhishGuard - fenêtre « Analyser mon domaine » (Paramètres → Entreprise).
// Lance DomainAudit.Run en arrière-plan puis présente : sécurité de la messagerie, entreprise (SIREN, dirigeants),
// sosies enregistrés, certificats récents contenant la marque, domaines liés. Les choix de l'utilisateur sont
// renvoyés à la fenêtre des paramètres (rien n'est enregistré avant « Enregistrer »), sauf le point de départ
// de la surveillance hebdomadaire.

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace PhishGuard.AddIn
{
    internal class DomainAuditForm : Form
    {
        readonly ComboBox cboDomain;
        readonly Button btnRun, btnCopy, btnBlock, btnAddDomains;
        readonly Label lblStatus;
        readonly ProgressBar progress;
        readonly ListView lvEmail, lvDomains;
        readonly TabControl tabs;
        readonly List<string> companyDomains;
        DomainReport report;

        /// <summary>Domaines cochés à bloquer (liste interne).</summary>
        public Action<List<string>> BlockDomains;
        /// <summary>Domaines liés cochés à ajouter aux domaines de l'entreprise.</summary>
        public Action<List<string>> AddCompanyDomains;
        /// <summary>Dirigeants trouvés et nom officiel de l'entreprise.</summary>
        public Action<CompanyInfo> AddCompany;

        public DomainAuditForm(List<string> domains, Icon icon)
        {
            companyDomains = domains;
            Text = L.T("PhishGuard - Analyser mon domaine");
            Size = new Size(860, 600);
            MinimumSize = new Size(640, 440);
            StartPosition = FormStartPosition.CenterParent;
            Font = new Font("Segoe UI", 9f);
            MinimizeBox = false;
            ShowInTaskbar = false;
            if (icon != null) Icon = icon;

            var top = new Panel { Dock = DockStyle.Top, Height = 62, Padding = new Padding(10, 10, 10, 0) };
            top.Controls.Add(new Label { Text = L.T("Domaine :"), Location = new Point(10, 15), AutoSize = true });
            cboDomain = new ComboBox { Location = new Point(80, 11), Width = 260 };
            foreach (var d in domains) cboDomain.Items.Add(d);
            if (cboDomain.Items.Count > 0) cboDomain.SelectedIndex = 0;
            btnRun = new Button { Text = L.T("Analyser"), Location = new Point(350, 10), AutoSize = true };
            btnRun.Click += (s, e) => Start();
            lblStatus = new Label { Location = new Point(10, 40), AutoSize = true, ForeColor = SystemColors.GrayText,
                Text = L.T("Ne sont envoyés que des noms de domaine (DNS, crt.sh). Durée : deux à trois minutes.") };
            // Recherche en cours : barre animée à côté du bouton, et le pointeur indique l'attente
            progress = new ProgressBar { Location = new Point(450, 14), Size = new Size(220, 16), Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 30, Visible = false };
            top.Controls.AddRange(new Control[] { cboDomain, btnRun, progress, lblStatus });

            tabs = new ThemedTabControl { Dock = DockStyle.Fill, Padding = new Point(12, 4) };

            // ---- Messagerie ----
            var pMail = new TabPage(L.T("Messagerie")) { Padding = new Padding(6) };
            lvEmail = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, HeaderStyle = ColumnHeaderStyle.Nonclickable, ShowItemToolTips = true };
            lvEmail.Columns.Add(L.T("État"), 110);
            lvEmail.Columns.Add(L.T("Contrôle"), 330);
            lvEmail.Columns.Add(L.T("Détail"), 360);
            pMail.Controls.Add(lvEmail);
            tabs.TabPages.Add(pMail);

            // ---- Domaines ----
            var pDom = new TabPage(L.T("Sosies du domaine")) { Padding = new Padding(6) };
            // En mode sombre, les titres de groupe sont dessinés en bleu par Windows (illisibles) : sans groupes, la colonne Type suffit
            lvDomains = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, CheckBoxes = true, ShowItemToolTips = true, ShowGroups = !Theme.Dark };
            lvDomains.Columns.Add(L.T("Domaine"), 230);
            lvDomains.Columns.Add(L.T("Type"), 170);
            lvDomains.Columns.Add(L.T("Détail"), 380);
            var domBar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 40, FlowDirection = FlowDirection.LeftToRight, Padding = new Padding(0, 6, 0, 0) };
            btnBlock = new Button { Text = L.T("Bloquer les sosies cochés"), AutoSize = true, Enabled = false };
            btnBlock.Click += (s, e) => ApplyBlock();
            btnAddDomains = new Button { Text = L.T("Ajouter les domaines cochés à l’entreprise"), AutoSize = true, Enabled = false };
            btnAddDomains.Click += (s, e) => ApplyRelated();
            var btnAll = new Button { Text = L.T("Tout cocher"), AutoSize = true };
            btnAll.Click += (s, e) => { foreach (ListViewItem i in lvDomains.Items) if (i.Tag is FoundDomain) i.Checked = true; };
            var btnNone = new Button { Text = L.T("Tout décocher"), AutoSize = true };
            btnNone.Click += (s, e) => { foreach (ListViewItem i in lvDomains.Items) i.Checked = false; };
            domBar.Controls.AddRange(new Control[] { btnAll, btnNone, btnBlock, btnAddDomains });
            lvDomains.ItemChecked += (s, e) => UpdateButtons();
            pDom.Controls.Add(lvDomains);
            pDom.Controls.Add(domBar);
            tabs.TabPages.Add(pDom);


            var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 44, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(8) };
            var btnClose = new Button { Text = L.T("Fermer"), DialogResult = DialogResult.Cancel, AutoSize = true };
            btnCopy = new Button { Text = L.T("Copier le rapport"), AutoSize = true, Enabled = false };
            btnCopy.Click += (s, e) => { try { if (report != null) Clipboard.SetText(DomainAudit.FormatReport(report)); } catch (Exception) { } };
            bar.Controls.AddRange(new Control[] { btnClose, btnCopy });
            CancelButton = btnClose;

            Controls.Add(tabs);
            Controls.Add(top);
            Controls.Add(bar);
            ThemeUi.Attach(this);
            Shown += (s, e) => { if (cboDomain.Text.Trim().Length > 0) Start(); };
        }

        void Start()
        {
            string domain = PhishGuard.Domains.RegistrableDomain(cboDomain.Text.Trim().ToLowerInvariant().TrimStart('@'));
            if (domain.Length == 0 || !domain.Contains("."))
            {
                lblStatus.Text = L.T("Saisissez un domaine, par exemple votre-entreprise.fr.");
                return;
            }
            btnRun.Enabled = false; btnCopy.Enabled = false; btnBlock.Enabled = false; btnAddDomains.Enabled = false;
            progress.Visible = true; UseWaitCursor = true;
            lvEmail.Items.Clear(); lvDomains.Items.Clear(); lvDomains.Groups.Clear();
            var others = companyDomains.ToList();
            var t = new System.Threading.Thread(() =>
            {
                DomainReport r = null;
                try { r = DomainAudit.Run(domain, others, msg => Ui(() => lblStatus.Text = msg)); }
                catch (Exception ex) { Ui(() => lblStatus.Text = L.T("Analyse impossible : ") + ex.Message); }
                Ui(() => ShowReport(r));
            });
            t.IsBackground = true;
            t.Start();
        }

        void Ui(Action a)
        {
            try { if (!IsDisposed) BeginInvoke(a); } catch (Exception) { }
        }

        void ShowReport(DomainReport r)
        {
            btnRun.Enabled = true;
            progress.Visible = false; UseWaitCursor = false;
            if (r == null) return;
            report = r;
            btnCopy.Enabled = true;

            // Messagerie
            foreach (var i in r.Email)
            {
                string st = i.Status == "ok" ? "✓ " + L.T("Bon") : i.Status == "warn" ? "! " + L.T("À améliorer") : i.Status == "bad" ? "✗ " + L.T("Problème") : "i " + L.T("Info");
                var it = new ListViewItem(new[] { st, i.Title, i.Detail }) { ToolTipText = i.Title + "\n" + i.Detail };
                it.ForeColor = ThemeUi.Fore(i.Status == "ok" ? Color.FromArgb(16, 124, 65) : i.Status == "warn" ? Color.FromArgb(168, 91, 0) : i.Status == "bad" ? Color.FromArgb(196, 22, 34) : SystemColors.GrayText);
                lvEmail.Items.Add(it);
            }
            foreach (var e in r.Errors) lvEmail.Items.Add(new ListViewItem(new[] { "? " + L.T("Erreur"), e, "" }) { ForeColor = ThemeUi.Fore(SystemColors.GrayText) });

            // Sosies et domaines
            var gLook = new ListViewGroup(L.F("Sosies enregistrés ({0} sur {1} variantes vérifiées)", r.Lookalikes.Count, r.VariantsChecked));
            var gCert = new ListViewGroup(L.F("Certificats récents (90 jours) contenant « {0} » sur un autre domaine ({1})", PhishGuard.Domains.ParseHost(r.Domain).Label, r.BrandCerts.Count));
            var gRel = new ListViewGroup(L.F("Domaines présents sur vos certificats ({0})", r.Related.Count));
            lvDomains.Groups.AddRange(new[] { gLook, gCert, gRel });
            foreach (var f in r.Lookalikes)
            {
                string detail = f.LikelyOwned ? L.T("Même serveur de messagerie que votre domaine : probablement à vous (à ajouter aux domaines de l’entreprise).")
                    : f.HasMx ? L.T("Peut envoyer et recevoir des emails.") : L.T("Enregistré, sans serveur de messagerie.");
                var it = new ListViewItem(new[] { f.Domain, f.Technique, detail }, gLook) { Tag = f, Checked = !f.LikelyOwned && f.HasMx };
                if (f.LikelyOwned) it.ForeColor = ThemeUi.Fore(SystemColors.GrayText);
                lvDomains.Items.Add(it);
            }
            foreach (var f in r.BrandCerts)
                lvDomains.Items.Add(new ListViewItem(new[] { f.Domain, L.T("certificat récent"), f.Technique + (f.Seen.HasValue ? " — " + f.Seen.Value.ToString("dd/MM/yyyy") : "") }, gCert) { Tag = f, Checked = true });
            foreach (var f in r.Related)
                lvDomains.Items.Add(new ListViewItem(new[] { f.Domain, L.T("domaine lié"), L.F("Sur {0} certificat(s) de votre domaine : probablement à vous.", f.Count) }, gRel) { Tag = f, Checked = true });
            UpdateButtons();
            if (lvDomains.Items.Count == 0) lvDomains.Items.Add(new ListViewItem(new[] { L.T("Aucun sosie enregistré trouvé."), "", "" }));


            int bad = r.Email.Count(x => x.Status == "bad"), warn = r.Email.Count(x => x.Status == "warn");
            int susp = r.Lookalikes.Count(x => !x.LikelyOwned) + r.BrandCerts.Count;
            lblStatus.Text = L.F("Terminé : {0} problème(s), {1} point(s) à améliorer, {2} domaine(s) suspect(s).", bad, warn, susp);

            // Point de départ de la surveillance hebdomadaire
            try { DomainAudit.RecordBaseline(r.Domain, r.Lookalikes); } catch (Exception) { }
        }

        List<FoundDomain> CheckedDomains()
        {
            return lvDomains.Items.Cast<ListViewItem>().Where(i => i.Checked && i.Tag is FoundDomain).Select(i => (FoundDomain)i.Tag).ToList();
        }

        /// <summary>Les boutons suivent les cases cochées : bloquer les sosies, ou déclarer comme vôtres les domaines que vous possédez.</summary>
        void UpdateButtons()
        {
            if (report == null) { btnBlock.Enabled = btnAddDomains.Enabled = false; return; }
            var c = CheckedDomains();
            btnBlock.Enabled = c.Any(f => f.Kind != "related" && !f.LikelyOwned);
            btnAddDomains.Enabled = c.Count > 0;
        }

        void ApplyBlock()
        {
            var list = lvDomains.Items.Cast<ListViewItem>()
                .Where(i => i.Checked && i.Tag is FoundDomain && ((FoundDomain)i.Tag).Kind != "related" && !((FoundDomain)i.Tag).LikelyOwned)
                .Select(i => ((FoundDomain)i.Tag).Domain).ToList();
            if (list.Count == 0 || BlockDomains == null) return;
            BlockDomains(list);
            lblStatus.Text = L.F("{0} domaine(s) ajouté(s) à la liste de blocage (onglet Listes). Cliquez sur « Enregistrer » dans les paramètres.", list.Count);
        }

        void ApplyRelated()
        {
            var chosen = CheckedDomains();
            if (chosen.Count == 0 || AddCompanyDomains == null) return;
            // Un domaine de l'entreprise est traité comme sûr : déclarer par erreur le sosie d'un escroc lui ouvrirait la porte
            var doubtful = chosen.Where(f => f.Kind != "related" && !f.LikelyOwned).Select(f => f.Domain).ToList();
            if (doubtful.Count > 0)
            {
                string names = string.Join("\n", doubtful.Take(10).Select(d => "  • " + d).ToArray()) + (doubtful.Count > 10 ? "\n  …" : "");
                var ans = MessageBox.Show(this, L.F("Rien n’indique que ces domaines sont à vous :\n\n{0}\n\nUn domaine de l’entreprise est considéré comme sûr : si l’un d’eux appartient à un escroc, ses messages ne seront plus signalés. Les ajouter quand même ?", names),
                    "PhishGuard", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
                if (ans != DialogResult.Yes) return;
            }
            var list = chosen.Select(f => f.Domain).ToList();
            AddCompanyDomains(list);
            lblStatus.Text = L.F("{0} domaine(s) ajouté(s) aux domaines de l’entreprise. Cliquez sur « Enregistrer » dans les paramètres.", list.Count);
        }
    }
}
