// PhishGuard - assistant de démarrage. À la première installation, il explique la pastille et demande l'essentiel
// (langue, entreprise, adresse de l'équipe sécurité, mode d'affichage). Après une mise à jour, il ne pose que les
// questions ajoutées depuis (les étapes déjà vues sont mémorisées dans SetupDone).

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
        public static readonly string[] Steps = { "intro", "language", "company", "report", "mode" };

        readonly PhishGuardConfig cfg;
        readonly ICollection<string> steps;
        ComboBox cboLang;
        TextBox txtCompany, txtDomain, txtReport;
        RadioButton rbSimple, rbExpert;
        static readonly string[] LangValues = { "auto", "fr", "en" };

        public FirstRunForm(PhishGuardConfig current, string mailboxDomain, Icon icon, ICollection<string> stepsToShow)
        {
            cfg = current;
            steps = stepsToShow;
            bool welcome = steps.Contains("intro");
            Text = welcome ? L.T("Bienvenue dans PhishGuard") : L.T("Nouveautés de PhishGuard");
            Width = 600;
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false; MinimizeBox = false;
            Font = new Font("Segoe UI", 9.5f);
            BackColor = Color.White;
            if (icon != null) Icon = icon;

            int y = 16;
            Controls.Add(new Label { Text = Text, Font = new Font("Segoe UI", 15f, FontStyle.Bold), Location = new Point(20, y), AutoSize = true });
            y += 40;
            if (welcome)
            {
                y = Para(L.T("PhishGuard vérifie chaque email que vous ouvrez et affiche son niveau de risque dans le ruban d’Outlook :"), y);
                y = Legend(Color.FromArgb(16, 124, 65), L.T("Vert : aucun danger détecté (avec une coche : expéditeur vérifié)."), y);
                y = Legend(Color.FromArgb(214, 120, 0), L.T("Orange : message suspect, vérifiez avant d’agir."), y);
                y = Legend(Color.FromArgb(196, 22, 34), L.T("Rouge : message dangereux, ne cliquez sur rien et signalez-le."), y);
                y = Para(L.T("Cliquez sur la pastille pour savoir pourquoi et quoi faire. Quelques réglages pour commencer (modifiables plus tard dans Paramètres) :"), y + 6);
            }
            else
                y = Para(L.T("PhishGuard a été mis à jour. Quelques réglages ont été ajoutés depuis votre dernière visite (modifiables plus tard dans Paramètres) :"), y);
            y += 4;

            if (steps.Contains("language"))
            {
                Field(L.T("Langue"), y);
                cboLang = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Location = new Point(200, y), Width = 360 };
                cboLang.Items.AddRange(new object[] { L.T("Automatique (langue de Windows)"), "Français", "English" });
                int li = Array.IndexOf(LangValues, (cfg.Language ?? "auto").ToLowerInvariant());
                cboLang.SelectedIndex = li < 0 ? 0 : li;
                Controls.Add(cboLang);
                y += 34;
            }
            if (steps.Contains("company"))
            {
                Field(L.T("Nom de l’entreprise"), y);
                txtCompany = Box(cfg.CompanyName, y);
                y += 34;
                Field(L.T("Domaine de l’entreprise"), y);
                string dom = cfg.CompanyDomains.Count > 0 ? string.Join(", ", cfg.CompanyDomains.ToArray())
                    : (mailboxDomain ?? "").Length > 0 && !Lists.FreemailDomains.Contains(mailboxDomain) ? mailboxDomain : "";
                txtDomain = Box(dom, y);
                y += 34;
            }
            if (steps.Contains("report"))
            {
                Field(L.T("Adresse de l’équipe sécurité"), y);
                txtReport = Box(cfg.ReportAddress, y);
                y += 30;
                y = Para(L.T("Le bouton « Signaler à la sécurité » lui envoie les messages douteux. Laissez vide si vous ne savez pas."), y, 200);
            }
            if (steps.Contains("mode"))
            {
                y += 6;
                Field(L.T("Affichage"), y);
                rbSimple = new RadioButton { Text = L.T("Simple : le verdict et quoi faire (recommandé)"), Location = new Point(200, y), AutoSize = true, Checked = !cfg.ExpertMode };
                rbExpert = new RadioButton { Text = L.T("Expert : analyse technique détaillée"), Location = new Point(200, y + 24), AutoSize = true, Checked = cfg.ExpertMode };
                Controls.Add(rbSimple); Controls.Add(rbExpert);
                y += 56;
            }

            var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 50, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(12, 10, 12, 8), BackColor = Color.FromArgb(247, 249, 251) };
            var ok = new Button { Text = welcome ? L.T("Commencer") : L.T("Enregistrer"), AutoSize = true, Height = 30, Font = new Font(Font, FontStyle.Bold) };
            var later = new Button { Text = L.T("Plus tard"), AutoSize = true, Height = 30, DialogResult = DialogResult.Cancel };
            ok.Click += (s, e) => { if (Apply()) { DialogResult = DialogResult.OK; Close(); } };
            bar.Controls.AddRange(new Control[] { ok, later });
            Controls.Add(bar);
            AcceptButton = ok; CancelButton = later;
            ClientSize = new Size(ClientSize.Width, y + 20 + bar.Height);
        }

        int Para(string text, int y) { return Para(text, y, 20); }

        int Para(string text, int y, int x)
        {
            int w = 560 - x;
            Controls.Add(new Label { Text = text, Location = new Point(x, y), MaximumSize = new Size(w, 0), AutoSize = true, ForeColor = Color.FromArgb(43, 53, 66) });
            return y + TextRenderer.MeasureText(text, Font, new Size(w, 0), TextFormatFlags.WordBreak).Height + 6;
        }

        int Legend(Color c, string text, int y)
        {
            Controls.Add(new Panel { BackColor = c, Location = new Point(28, y + 4), Size = new Size(14, 14) });
            return Para(text, y, 50) - 2;
        }

        void Field(string label, int y)
        {
            Controls.Add(new Label { Text = label, Location = new Point(20, y + 3), AutoSize = true, Font = new Font(Font, FontStyle.Bold) });
        }

        TextBox Box(string value, int y)
        {
            var t = new TextBox { Text = value ?? "", Location = new Point(200, y), Width = 360 };
            Controls.Add(t);
            return t;
        }

        bool Apply()
        {
            string report = txtReport == null ? cfg.ReportAddress : txtReport.Text.Trim();
            if (txtReport != null && report.Length > 0 && !System.Text.RegularExpressions.Regex.IsMatch(report, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
            {
                MessageBox.Show(this, L.T("L’adresse de l’équipe sécurité n’est pas valide."), "PhishGuard", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
            if (cboLang != null) cfg.Language = LangValues[Math.Max(0, cboLang.SelectedIndex)];
            if (txtCompany != null) cfg.CompanyName = txtCompany.Text.Trim();
            if (txtDomain != null)
                cfg.CompanyDomains = txtDomain.Text.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(d => d.Trim().TrimStart('@').ToLowerInvariant()).Where(d => d.Contains(".")).Distinct().ToList();
            if (txtReport != null) cfg.ReportAddress = report;
            if (rbExpert != null) cfg.ExpertMode = rbExpert.Checked;
            return true;
        }
    }
}
