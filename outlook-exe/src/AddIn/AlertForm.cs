// PhishGuard - petite alerte en bas à droite de l'écran quand un message dangereux est affiché.
// Elle ne prend pas le focus (on peut continuer à taper), disparaît seule, et s'ouvre en détail au clic.

using System;
using System.Drawing;
using System.Windows.Forms;

namespace PhishGuard.AddIn
{
    internal class AlertForm : Form
    {
        readonly Timer closeTimer = new Timer();
        public event EventHandler DetailsRequested;

        protected override bool ShowWithoutActivation { get { return true; } }

        protected override CreateParams CreateParams
        {
            get
            {
                var cp = base.CreateParams;
                cp.ExStyle |= 0x08000000 | 0x00000080; // WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW (pas dans la barre des tâches)
                return cp;
            }
        }

        public AlertForm(AnalysisResult r, string subject)
        {
            FormBorderStyle = FormBorderStyle.None;
            StartPosition = FormStartPosition.Manual;
            ShowInTaskbar = false;
            TopMost = true;
            BackColor = Color.White;
            Size = new Size(380, 116);
            Font = new Font("Segoe UI", 9f);
            Cursor = Cursors.Hand;

            Color accent = r.Level == "dangerous" ? Color.FromArgb(180, 20, 30) : Color.FromArgb(196, 106, 0);

            var bar = new Panel { Dock = DockStyle.Left, Width = 6, BackColor = accent };
            var title = new Label
            {
                Text = (r.Level == "dangerous" ? L.F("PhishGuard : message dangereux (score {0}/100)", r.Score) : L.F("PhishGuard : message suspect (score {0}/100)", r.Score)),
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                ForeColor = accent,
                Location = new Point(16, 10),
                Size = new Size(340, 20),
                AutoEllipsis = true
            };
            var subj = new Label
            {
                Text = string.IsNullOrEmpty(subject) ? L.T("(sans objet)") : subject,
                Location = new Point(16, 32),
                Size = new Size(350, 18),
                AutoEllipsis = true,
                ForeColor = Color.FromArgb(27, 31, 36)
            };
            string top = r.Findings.Count > 0 ? r.Findings[0].Title : r.Advice;
            var reason = new Label
            {
                Text = top,
                Location = new Point(16, 52),
                Size = new Size(350, 34),
                AutoEllipsis = true,
                ForeColor = Color.FromArgb(93, 102, 115)
            };
            var hint = new Label
            {
                Text = L.T("Cliquez pour voir le détail"),
                Location = new Point(16, 90),
                Size = new Size(250, 18),
                ForeColor = Color.FromArgb(15, 108, 189)
            };
            var close = new Label
            {
                Text = "✕",
                Location = new Point(356, 6),
                Size = new Size(18, 18),
                ForeColor = Color.FromArgb(93, 102, 115),
                TextAlign = ContentAlignment.MiddleCenter
            };

            Controls.Add(title);
            Controls.Add(subj);
            Controls.Add(reason);
            Controls.Add(hint);
            Controls.Add(close);
            Controls.Add(bar);

            EventHandler open = (s, e) => { var h = DetailsRequested; if (h != null) h(this, EventArgs.Empty); Close(); };
            foreach (Control c in new Control[] { this, title, subj, reason, hint, bar }) c.Click += open;
            close.Click += (s, e) => Close();

            // Bordure fine
            Paint += (s, e) => { using (var p = new Pen(ThemeUi.Border(Color.FromArgb(225, 228, 232)))) e.Graphics.DrawRectangle(p, 0, 0, Width - 1, Height - 1); };

            ThemeUi.Attach(this);
            var area = Screen.PrimaryScreen.WorkingArea;
            Location = new Point(area.Right - Width - 16, area.Bottom - Height - 16);

            closeTimer.Interval = 12000;
            closeTimer.Tick += (s, e) => { closeTimer.Stop(); Close(); };
            closeTimer.Start();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) closeTimer.Dispose();
            base.Dispose(disposing);
        }
    }
}
