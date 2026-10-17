// PhishGuard - assistant de premier lancement : explique la pastille et demande l'essentiel
// (langue, entreprise, adresse de l'équipe sécurité, mode d'affichage). Affiché une seule fois.

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace PhishGuard.AddIn
{
    internal class FirstRunForm : Form
    {
        readonly PhishGuardConfig cfg;
        readonly ComboBox cboLang;
        readonly TextBox txtCompany, txtDomain, txtReport;
        readonly RadioButton rbSimple, rbExpert;
        static readonly string[] LangValues = { "auto", "fr", "en" };

        public FirstRunForm(PhishGuardConfig current, string mailboxDomain, Icon icon)
        {
            cfg = current;
            Text = L.T("Bienvenue dans PhishGuard");
            Size = new Size(600, 620);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false; MinimizeBox = false;
            Font = new Font("Segoe UI", 9.5f);
            BackColor = Color.White;
            if (icon != null) Icon = icon;

            int y = 16;
            Controls.Add(new Label { Text = L.T("Bienvenue dans PhishGuard"), Font = new Font("Segoe UI", 15f, FontStyle.Bold), Location = new Point(20, y), AutoSize = true });
            y += 40;
            y = Para(L.T("PhishGuard vérifie chaque email que vous ouvrez et affiche son niveau de risque dans le ruban d’Outlook :"), y);
            y = Legend(Color.FromArgb(16, 124, 65), L.T("Vert : aucun danger détecté (avec une coche : expéditeur vérifié)."), y);
            y = Legend(Color.FromArgb(214, 120, 0), L.T("Orange : message suspect, vérifiez avant d’agir."), y);
            y = Legend(Color.FromArgb(196, 22, 34), L.T("Rouge : message dangereux, ne cliquez sur rien et signalez-le."), y);
            y = Para(L.T("Cliquez sur la pastille pour savoir pourquoi et quoi faire. Quelques réglages pour commencer (modifiables plus tard dans Paramètres) :"), y + 6);

            y += 4;
            Field(L.T("Langue"), ref y);
            cboLang = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Location = new Point(200, y - 32), Width = 360 };
            cboLang.Items.AddRange(new object[] { L.T("Automatique (langue de Windows)"), "Français", "English" });
            int li = Array.IndexOf(LangValues, (cfg.Language ?? "auto").ToLowerInvariant());
            cboLang.SelectedIndex = li < 0 ? 0 : li;
            Controls.Add(cboLang);

            Field(L.T("Nom de l’entreprise"), ref y);
            txtCompany = Box(cfg.CompanyName, y);
            Field(L.T("Domaine de l’entreprise"), ref y);
            string dom = cfg.CompanyDomains.Count > 0 ? string.Join(", ", cfg.CompanyDomains.ToArray())
                : (mailboxDomain ?? "").Length > 0 && !Lists.FreemailDomains.Contains(mailboxDomain) ? mailboxDomain : "";
            txtDomain = Box(dom, y);
            Field(L.T("Adresse de l’équipe sécurité"), ref y);
            txtReport = Box(cfg.ReportAddress, y);
            y = Para(L.T("Le bouton « Signaler à la sécurité » lui envoie les messages douteux. Laissez vide si vous ne savez pas."), y, 200);

            y += 6;
            Controls.Add(new Label { Text = L.T("Affichage"), Location = new Point(20, y + 2), AutoSize = true, Font = new Font(Font, FontStyle.Bold) });
            rbSimple = new RadioButton { Text = L.T("Simple : le verdict et quoi faire (recommandé)"), Location = new Point(200, y), AutoSize = true, Checked = !cfg.ExpertMode };
            rbExpert = new RadioButton { Text = L.T("Expert : analyse technique détaillée"), Location = new Point(200, y + 24), AutoSize = true, Checked = cfg.ExpertMode };
            Controls.Add(rbSimple); Controls.Add(rbExpert);

            var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 50, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(12, 10, 12, 8), BackColor = Color.FromArgb(247, 249, 251) };
            var ok = new Button { Text = L.T("Commencer"), AutoSize = true, Height = 30, Font = new Font(Font, FontStyle.Bold) };
            var later = new Button { Text = L.T("Plus tard"), AutoSize = true, Height = 30, DialogResult = DialogResult.Cancel };
            ok.Click += (s, e) => { if (Apply()) { DialogResult = DialogResult.OK; Close(); } };
            bar.Controls.AddRange(new Control[] { ok, later });
            Controls.Add(bar);
            AcceptButton = ok; CancelButton = later;
        }

        int Para(string text, int y) { return Para(text, y, 20); }

        int Para(string text, int y, int x)
        {
            int w = 560 - x;
            var l = new Label { Text = text, Location = new Point(x, y), MaximumSize = new Size(w, 0), AutoSize = true, ForeColor = Color.FromArgb(43, 53, 66) };
            Controls.Add(l);
            return y + TextRenderer.MeasureText(text, Font, new Size(w, 0), TextFormatFlags.WordBreak).Height + 6;
        }

        int Legend(Color c, string text, int y)
        {
            Controls.Add(new Panel { BackColor = c, Location = new Point(28, y + 4), Size = new Size(14, 14) });
            return Para(text, y, 50) - 2;
        }

        void Field(string label, ref int y)
        {
            Controls.Add(new Label { Text = label, Location = new Point(20, y + 3), AutoSize = true, Font = new Font(Font, FontStyle.Bold) });
            y += 32;
        }

        TextBox Box(string value, int y)
        {
            var t = new TextBox { Text = value ?? "", Location = new Point(200, y - 32), Width = 360 };
            Controls.Add(t);
            return t;
        }

        bool Apply()
        {
            string report = txtReport.Text.Trim();
            if (report.Length > 0 && !System.Text.RegularExpressions.Regex.IsMatch(report, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
            {
                MessageBox.Show(this, L.T("L’adresse de l’équipe sécurité n’est pas valide."), "PhishGuard", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
            cfg.Language = LangValues[Math.Max(0, cboLang.SelectedIndex)];
            cfg.CompanyName = txtCompany.Text.Trim();
            cfg.CompanyDomains = txtDomain.Text.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(d => d.Trim().TrimStart('@').ToLowerInvariant()).Where(d => d.Contains(".")).Distinct().ToList();
            cfg.ReportAddress = report;
            cfg.ExpertMode = rbExpert.Checked;
            return true;
        }
    }
}
