// PhishGuard - assistant de démarrage, page par page. À la première installation : la pastille, la langue et
// l'affichage, puis l'usage (entreprise ou personnel). En entreprise : nom et domaines, adresse de l'équipe sécurité,
// réseau interne. Enfin les sources de réputation, expliquées une par une. Après une mise à jour, seules les étapes
// ajoutées depuis sont proposées (les étapes déjà vues sont mémorisées dans SetupDone).

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace PhishGuard.AddIn
{
    internal class FirstRunForm : Form
    {
        /// <summary>Étapes de l'assistant, dans l'ordre. Ajouter une étape ici la fait proposer aux utilisateurs existants.</summary>
        public static readonly string[] Steps = { "intro", "language", "company", "report", "mode", "usage", "network", "reputation" };

        const int W = 640, Inner = 600, X = 20, FieldX = 230;

        readonly PhishGuardConfig cfg;
        readonly ICollection<string> steps;
        readonly bool welcome;
        readonly Panel host;
        readonly Button btnBack, btnNext, btnLater;
        readonly Label lblPage;
        readonly List<Panel> pages = new List<Panel>();
        readonly Dictionary<Panel, string> pageKind = new Dictionary<Panel, string>();
        int pageIndex;

        ComboBox cboLang;
        RadioButton rbSimple, rbExpert, rbCompany, rbPersonal;
        TextBox txtCompany, txtDomain, txtReport, txtMailServers, txtRelays, txtWorkstations;
        CheckBox chkRedFlag, chkPublic, chkOpenPhish, chkTranco, chkDns, chkCert, chkAge;
        static readonly string[] LangValues = { "auto", "fr", "en" };

        public FirstRunForm(PhishGuardConfig current, string mailboxDomain, Icon icon, ICollection<string> stepsToShow)
        {
            cfg = current;
            steps = stepsToShow;
            welcome = steps.Contains("intro");
            Text = welcome ? L.T("Bienvenue dans PhishGuard") : L.T("Nouveautés de PhishGuard");
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false; MinimizeBox = false;
            Font = new Font("Segoe UI", 9.5f);
            BackColor = Color.White;
            if (icon != null) Icon = icon;
            ClientSize = new Size(W, 560);

            var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 50, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(12, 10, 12, 8), BackColor = Color.FromArgb(247, 249, 251) };
            btnNext = new Button { AutoSize = true, Height = 30, Font = new Font(Font, FontStyle.Bold) };
            btnBack = new Button { Text = L.T("Précédent"), AutoSize = true, Height = 30 };
            btnLater = new Button { Text = L.T("Plus tard"), AutoSize = true, Height = 30, DialogResult = DialogResult.Cancel };
            lblPage = new Label { AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(0, 8, 16, 0) };
            btnNext.Click += (s, e) => Next();
            btnBack.Click += (s, e) => ShowPage(pageIndex - 1);
            bar.Controls.AddRange(new Control[] { btnNext, btnBack, btnLater, lblPage });
            host = new Panel { Dock = DockStyle.Fill };
            Controls.Add(host);
            Controls.Add(bar);
            AcceptButton = btnNext; CancelButton = btnLater;

            // Une page n'est construite que si l'une de ses questions reste à poser
            if (welcome || steps.Contains("language") || steps.Contains("mode")) AddPage("welcome", BuildWelcome());
            if (steps.Contains("usage")) AddPage("usage", BuildUsage());
            if (steps.Contains("company") || steps.Contains("report")) AddPage("company", BuildCompany(mailboxDomain));
            if (steps.Contains("network")) AddPage("network", BuildNetwork());
            if (steps.Contains("reputation")) AddPage("reputation", BuildReputation());
            if (pages.Count == 0) AddPage("welcome", BuildWelcome());
            ThemeUi.Attach(this);
            ShowPage(0);
        }

        // ------------------------------------------------------------------ navigation

        void AddPage(string kind, Panel p)
        {
            p.Dock = DockStyle.Fill; p.AutoScroll = true; p.Visible = false;
            host.Controls.Add(p);
            pages.Add(p);
            pageKind[p] = kind;
        }

        /// <summary>Usage choisi : sur cette page, ou déjà connu (réglage ou domaines de l'entreprise renseignés).</summary>
        bool Company
        {
            get
            {
                if (rbCompany != null) return rbCompany.Checked;
                return cfg.Usage != "personal";
            }
        }

        /// <summary>Les pages Entreprise et Réseau interne ne concernent pas un usage personnel.</summary>
        bool Applies(Panel p)
        {
            string k = pageKind[p];
            return Company || (k != "company" && k != "network");
        }

        List<Panel> VisiblePages() { return pages.Where(Applies).ToList(); }

        void ShowPage(int index)
        {
            var vis = VisiblePages();
            index = Math.Max(0, Math.Min(index, vis.Count - 1));
            pageIndex = index;
            foreach (var p in pages) p.Visible = p == vis[index];
            vis[index].AutoScrollPosition = new Point(0, 0);
            btnBack.Visible = index > 0;
            bool last = index == vis.Count - 1;
            btnNext.Text = last ? (welcome ? L.T("Commencer") : L.T("Enregistrer")) : L.T("Suivant");
            lblPage.Text = vis.Count > 1 ? L.F("Étape {0} sur {1}", index + 1, vis.Count) : "";
        }

        /// <summary>Pour les captures d'écran.</summary>
        internal void GoTo(int index) { ShowPage(index); }

        void Next()
        {
            var vis = VisiblePages();
            if (!Validate(vis[pageIndex])) return;
            if (pageIndex < vis.Count - 1) { ShowPage(pageIndex + 1); return; }
            Apply();
            DialogResult = DialogResult.OK;
            Close();
        }

        // ------------------------------------------------------------------ pages

        Panel BuildWelcome()
        {
            var p = new Panel();
            int y = Title(p, welcome ? L.T("Bienvenue dans PhishGuard") : L.T("Nouveautés de PhishGuard"), 16);
            if (welcome)
            {
                y = Para(p, L.T("PhishGuard vérifie chaque email que vous ouvrez et affiche son niveau de risque dans le ruban d’Outlook :"), y);
                y = Legend(p, Color.FromArgb(16, 124, 65), L.T("Vert : aucun danger détecté (avec une coche : expéditeur vérifié)."), y);
                y = Legend(p, Color.FromArgb(214, 120, 0), L.T("Orange : message suspect, vérifiez avant d’agir."), y);
                y = Legend(p, Color.FromArgb(196, 22, 34), L.T("Rouge : message dangereux, ne cliquez sur rien et signalez-le."), y);
                y = Para(p, L.T("Cliquez sur la pastille pour savoir pourquoi et quoi faire. L’analyse se fait sur votre poste : le contenu de vos messages n’est envoyé nulle part."), y + 6);
                y = Para(p, L.T("Quelques réglages pour commencer, tous modifiables plus tard dans Paramètres :"), y + 4);
            }
            else
                y = Para(p, L.T("PhishGuard a été mis à jour. Quelques réglages ont été ajoutés depuis votre dernière visite (modifiables plus tard dans Paramètres) :"), y);
            y += 6;
            if (steps.Contains("language"))
            {
                Field(p, L.T("Langue"), y);
                cboLang = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Location = new Point(FieldX, y), Width = Inner + X - FieldX };
                cboLang.Items.AddRange(new object[] { L.T("Automatique (langue de Windows)"), "Français", "English" });
                int li = Array.IndexOf(LangValues, (cfg.Language ?? "auto").ToLowerInvariant());
                cboLang.SelectedIndex = li < 0 ? 0 : li;
                p.Controls.Add(cboLang);
                y += 36;
            }
            if (steps.Contains("mode"))
            {
                Field(p, L.T("Affichage"), y);
                rbSimple = new RadioButton { Text = L.T("Simple : le verdict et quoi faire (recommandé)"), Location = new Point(FieldX, y), AutoSize = true, Checked = !cfg.ExpertMode };
                rbExpert = new RadioButton { Text = L.T("Expert : analyse technique détaillée"), Location = new Point(FieldX, y + 24), AutoSize = true, Checked = cfg.ExpertMode };
                p.Controls.Add(rbSimple); p.Controls.Add(rbExpert);
                y += 52;
                y = Para(p, L.T("Le mode expert ajoute aussi aux paramètres les listes, les clés de réputation et l’analyse de votre domaine."), y, FieldX);
            }
            return p;
        }

        Panel BuildUsage()
        {
            var p = new Panel();
            int y = Title(p, L.T("Utilisation"), 16);
            y = Para(p, L.T("Utilisez-vous PhishGuard dans le cadre d’une entreprise ou d’une organisation ?"), y);
            y += 6;
            rbCompany = new RadioButton { Text = L.T("Oui, en entreprise"), Location = new Point(X + 10, y), AutoSize = true, Font = new Font(Font, FontStyle.Bold), Checked = cfg.Usage != "personal" };
            p.Controls.Add(rbCompany);
            y += 26;
            y = Para(p, L.T("PhishGuard repère alors les messages qui imitent votre entreprise (fraude au président, faux domaines), les faux messages « internes » fabriqués depuis le réseau, et envoie les messages douteux à votre équipe sécurité. Les deux pages suivantes vous demandent de quoi le faire."), y, X + 28);
            y += 8;
            rbPersonal = new RadioButton { Text = L.T("Non, à titre personnel"), Location = new Point(X + 10, y), AutoSize = true, Font = new Font(Font, FontStyle.Bold), Checked = cfg.Usage == "personal" };
            p.Controls.Add(rbPersonal);
            y += 26;
            Para(p, L.T("Pas d’entreprise, d’équipe sécurité ni de réseau interne à déclarer : le bouton « Signaler » déplace simplement le message dans le courrier indésirable."), y, X + 28);
            rbCompany.CheckedChanged += (s, e) => ShowPage(pageIndex);   // met à jour le nombre d'étapes
            return p;
        }

        Panel BuildCompany(string mailboxDomain)
        {
            var p = new Panel();
            int y = Title(p, L.T("Votre entreprise"), 16);
            if (steps.Contains("company"))
            {
                Field(p, L.T("Nom de l’entreprise"), y);
                txtCompany = Box(p, cfg.CompanyName, y, false, 0);
                y += 30;
                y = Para(p, L.T("Repéré dans le nom affiché des expéditeurs externes : un inconnu qui signe « Direction de Votre Entreprise » est suspect."), y, FieldX);
                y += 4;
                Field(p, L.T("Domaines de l’entreprise"), y);
                string dom = cfg.CompanyDomains.Count > 0 ? string.Join(", ", cfg.CompanyDomains.ToArray())
                    : (mailboxDomain ?? "").Length > 0 && !Lists.FreemailDomains.Contains(mailboxDomain) ? mailboxDomain : "";
                txtDomain = Box(p, dom, y, false, 0);
                y += 30;
                y = Para(p, L.T("Celui de vos adresses email, et les autres s’il y en a, séparés par des virgules (exemple : entreprise.fr, entreprise.com). Un domaine qui les imite (entreprlse.fr, entreprise-fr.com…) est classé critique."), y, FieldX);
                y += 8;
            }
            if (steps.Contains("report"))
            {
                Field(p, L.T("Adresse de l’équipe sécurité"), y);
                txtReport = Box(p, cfg.ReportAddress, y, false, 0);
                y += 30;
                Para(p, L.T("Le bouton « Signaler à la sécurité » lui transfère les messages douteux avec le rapport d’analyse. Demandez-la à votre service informatique ; laissez vide si vous n’en avez pas."), y, FieldX);
            }
            return p;
        }

        Panel BuildNetwork()
        {
            var p = new Panel();
            int y = Title(p, L.T("Réseau interne"), 16);
            y = Para(p, L.T("Pour repérer un faux message « interne » : quelqu’un sur le réseau (un collègue malveillant, un poste ou un équipement piraté) qui envoie un email au nom d’un collègue sans passer par la messagerie. Ces informations se trouvent auprès de votre service informatique ; une rubrique laissée vide n’est simplement pas vérifiée."), y);
            y = Para(p, L.T("Une ligne par élément : adresse IP (10.0.0.5), plage (10.0.0.0/24 ; /32 pour une seule adresse) ou nom complet (mail01.entreprise.local), traduit en adresse par votre DNS."), y + 2);
            y += 8;
            y = Section(p, L.T("Serveurs de messagerie internes"), y);
            txtMailServers = Box(p, string.Join(Environment.NewLine, cfg.MailServers.ToArray()), y, true, 52, X);
            y += 58;
            y = Para(p, L.T("Exchange, passerelle de filtrage, relais SMTP : tous ceux par lesquels passent vos messages. Exemple : 10.0.0.5 ou mail01.entreprise.local"), y);
            y += 8;
            y = Section(p, L.T("Équipements qui envoient des mails (alertes, copieurs, applications)"), y);
            txtRelays = Box(p, string.Join(Environment.NewLine, cfg.InternalRelays.ToArray()), y, true, 70, X);
            y += 76;
            y = Para(p, L.T("L’adresse IP ou le nom de l’équipement, puis les seules adresses d’expéditeur qu’il a le droit d’utiliser. Exemple : 10.0.50.12 alertes@entreprise.fr. S’il écrit au nom d’une autre adresse, le message est critique (équipement piraté)."), y);
            y += 8;
            y = Section(p, L.T("Réseaux des postes de travail (VLAN)"), y);
            txtWorkstations = Box(p, string.Join(Environment.NewLine, cfg.WorkstationNets.ToArray()), y, true, 52, X);
            y += 58;
            y = Para(p, L.T("Exemple : 10.20.30.0/24 (de 10.20.30.0 à 10.20.30.255). Un message parti directement d’un de ces réseaux, sans l’authentification de la messagerie, est critique."), y);
            if (cfg.IsLocked("mailservers")) txtMailServers.Enabled = false;
            if (cfg.IsLocked("internalrelays")) txtRelays.Enabled = false;
            if (cfg.IsLocked("workstationnets")) txtWorkstations.Enabled = false;
            p.Controls.Add(new Label { Location = new Point(0, y + 10), Size = new Size(1, 1) });   // marge sous le défilement
            return p;
        }

        Panel BuildReputation()
        {
            var p = new Panel();
            int y = Title(p, L.T("Réputation"), 16);
            y = Para(p, L.T("L’analyse du message se fait sur votre poste. Ces sources externes ajoutent ce que le message seul ne dit pas : un domaine connu pour du phishing, un site très fréquenté, un domaine tout neuf. Aucune n’envoie le contenu, l’objet ou les destinataires de vos messages."), y);
            y += 6;
            y = Section(p, L.T("Listes téléchargées (rien n’est envoyé, la comparaison se fait sur votre poste)"), y);
            chkRedFlag = Check(p, ref y, L.T("Red Flag Domains"), cfg.RedFlagEnabled, "redflagenabled",
                L.T("Nouveaux domaines .fr repérés comme suspects, mis à jour chaque jour."));
            chkPublic = Check(p, ref y, L.T("Domaines du secteur public"), cfg.PublicSectorList, "publicsectorlist",
                L.T("Liste de l’État (environ 100 000 domaines), chaque mois : un vrai message d’une mairie ou d’un hôpital n’est pas pris pour un faux."));
            chkOpenPhish = Check(p, ref y, L.T("OpenPhish"), cfg.BetaOpenPhish, "betaopenphish",
                L.T("Pages de phishing actives dans le monde, toutes les 12 heures."));
            chkTranco = Check(p, ref y, L.T("Classement Tranco"), cfg.BetaTranco, "betatranco",
                L.T("Sites les plus visités (environ 10 Mo par semaine) : évite de signaler à tort les grands sites."));
            y += 4;
            y = Section(p, L.T("Requêtes à la demande (seul un nom de domaine est envoyé)"), y);
            chkDns = Check(p, ref y, L.T("DNS du domaine de l’expéditeur"), cfg.BetaDnsChecks, "betadnschecks",
                L.T("Le domaine existe-t-il, est-il protégé contre l’usurpation ? Passe par le DNS de votre poste, comme une navigation normale."));
            chkCert = Check(p, ref y, L.T("Âge du premier certificat (crt.sh)"), cfg.BetaCertAge, "betacertage",
                L.T("Un site créé il y a quelques jours est suspect. Le nom du domaine est envoyé à crt.sh, journal public des certificats."));
            chkAge = Check(p, ref y, L.T("Âge des domaines, automatiquement (RDAP)"), cfg.DomainAgeLookup, "domainageauto",
                L.T("Le nom du domaine est envoyé au registre de son extension. Sinon, la recherche se fait d’un clic dans l’onglet Réputation de l’analyse détaillée."));
            y += 4;
            y = Section(p, L.T("Avec une clé gratuite (plus tard)"), y);
            y = Para(p, L.T("VirusTotal (pièces jointes, par leur empreinte : le fichier n’est jamais envoyé), abuse.ch (domaines et fichiers malveillants) et AbuseIPDB (adresse IP d’origine) demandent une inscription gratuite. Les clés se saisissent en mode expert, dans Paramètres → Réputation, et sont rangées chiffrées dans le Gestionnaire d’identification de Windows."), y);
            p.Controls.Add(new Label { Location = new Point(0, y + 10), Size = new Size(1, 1) });
            return p;
        }

        // ------------------------------------------------------------------ contrôles

        int Title(Panel p, string text, int y)
        {
            p.Controls.Add(new Label { Text = text, Font = new Font("Segoe UI", 15f, FontStyle.Bold), Location = new Point(X, y), AutoSize = true });
            return y + 42;
        }

        int Section(Panel p, string text, int y)
        {
            p.Controls.Add(new Label { Text = text, Font = new Font(Font, FontStyle.Bold), Location = new Point(X, y), MaximumSize = new Size(Inner, 0), AutoSize = true });
            return y + TextRenderer.MeasureText(text, new Font(Font, FontStyle.Bold), new Size(Inner, 0), TextFormatFlags.WordBreak).Height + 6;
        }

        int Para(Panel p, string text, int y) { return Para(p, text, y, X); }

        int Para(Panel p, string text, int y, int x)
        {
            int w = Inner + X - x - 8;
            p.Controls.Add(new Label { Text = text, Location = new Point(x, y), MaximumSize = new Size(w, 0), AutoSize = true, ForeColor = Color.FromArgb(43, 53, 66) });
            return y + TextRenderer.MeasureText(text, Font, new Size(w, 0), TextFormatFlags.WordBreak).Height + 6;
        }

        int Legend(Panel p, Color c, string text, int y)
        {
            p.Controls.Add(new Panel { BackColor = c, Location = new Point(28, y + 4), Size = new Size(14, 14) });
            return Para(p, text, y, 50) - 2;
        }

        void Field(Panel p, string label, int y)
        {
            p.Controls.Add(new Label { Text = label, Location = new Point(X, y + 3), AutoSize = true, Font = new Font(Font, FontStyle.Bold) });
        }

        TextBox Box(Panel p, string value, int y, bool multiline, int height) { return Box(p, value, y, multiline, height, FieldX); }

        TextBox Box(Panel p, string value, int y, bool multiline, int height, int x)
        {
            var t = new TextBox { Text = value ?? "", Location = new Point(x, y), Width = Inner + X - x - 8, Multiline = multiline, AcceptsReturn = multiline, ScrollBars = multiline ? ScrollBars.Vertical : ScrollBars.None };
            if (multiline) t.Height = height;
            p.Controls.Add(t);
            return t;
        }

        CheckBox Check(Panel p, ref int y, string text, bool value, string key, string hint)
        {
            var c = new CheckBox { Text = text, Checked = value, Location = new Point(X + 4, y), AutoSize = true, Font = new Font(Font, FontStyle.Bold), Enabled = !cfg.IsLocked(key) };
            p.Controls.Add(c);
            y += 24;
            y = Para(p, hint, y, X + 22);
            return c;
        }

        // ------------------------------------------------------------------ enregistrement

        bool Validate(Panel page)
        {
            string kind = pageKind[page];
            if (kind == "company" && txtReport != null)
            {
                string report = txtReport.Text.Trim();
                if (report.Length > 0 && !System.Text.RegularExpressions.Regex.IsMatch(report, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
                {
                    MessageBox.Show(this, L.T("L’adresse de l’équipe sécurité n’est pas valide."), "PhishGuard", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return false;
                }
            }
            if (kind == "network" && txtRelays != null)
            {
                var bad = SettingsForm.BadRelayLines(SettingsForm.RelayLines(txtRelays));
                if (bad.Count > 0)
                {
                    MessageBox.Show(this, L.T("Équipements : après l’adresse IP ou le nom, indiquez seulement des adresses d’expéditeur (alertes@entreprise.fr). Lignes à corriger :") + "\n\n" + string.Join("\n", bad.ToArray()),
                        "PhishGuard", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return false;
                }
            }
            return true;
        }

        void Apply()
        {
            bool company = Company;
            if (rbCompany != null) cfg.Usage = company ? "company" : "personal";
            if (cboLang != null) cfg.Language = LangValues[Math.Max(0, cboLang.SelectedIndex)];
            if (rbExpert != null) cfg.ExpertMode = rbExpert.Checked;
            if (company)
            {
                if (txtCompany != null) cfg.CompanyName = txtCompany.Text.Trim();
                if (txtDomain != null)
                    cfg.CompanyDomains = txtDomain.Text.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(d => d.Trim().TrimStart('@').ToLowerInvariant()).Where(d => d.Contains(".")).Distinct().ToList();
                if (txtReport != null) cfg.ReportAddress = txtReport.Text.Trim();
                if (txtMailServers != null && txtMailServers.Enabled) cfg.MailServers = SettingsForm.Lines(txtMailServers, false);
                if (txtRelays != null && txtRelays.Enabled) cfg.InternalRelays = SettingsForm.RelayLines(txtRelays);
                if (txtWorkstations != null && txtWorkstations.Enabled) cfg.WorkstationNets = SettingsForm.Lines(txtWorkstations, false);
            }
            if (chkRedFlag != null)
            {
                cfg.RedFlagEnabled = chkRedFlag.Checked;
                cfg.PublicSectorList = chkPublic.Checked;
                cfg.BetaOpenPhish = chkOpenPhish.Checked;
                cfg.BetaTranco = chkTranco.Checked;
                cfg.BetaDnsChecks = chkDns.Checked;
                cfg.BetaCertAge = chkCert.Checked;
                cfg.DomainAgeLookup = chkAge.Checked;
            }
        }
    }
}
