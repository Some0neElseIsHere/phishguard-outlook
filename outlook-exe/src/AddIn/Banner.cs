// PhishGuard - bandeau coloré en haut des fenêtres Outlook (volet Office « personnalisé », ancré en haut).
// Un bandeau par fenêtre (explorateur et messages ouverts). Il affiche le verdict du message affiché,
// les principaux indices et les boutons Détail / Signaler. Désactivable dans les paramètres.
//
// Le contenu du volet est un contrôle WinForms exposé en COM (PhishGuard.Banner), enregistré par l'installeur.

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace PhishGuard.AddIn
{
    [ComVisible(true)]
    [Guid("8B1E4F52-3C7A-4D9E-A1F6-2E5B7C9D0A43")]
    [ProgId("PhishGuard.Banner")]
    [ClassInterface(ClassInterfaceType.AutoDispatch)]
    public class BannerControl : UserControl
    {
        internal static BannerControl LastCreated;
        internal event EventHandler DetailsRequested, ReportRequested, CloseRequested;

        readonly Button btnDetails, btnReport;
        readonly Label btnClose;
        string scoreText = "", title = "", reasons = "";
        Color accent = Color.FromArgb(95, 107, 122);

        public BannerControl()
        {
            LastCreated = this;
            DoubleBuffered = true;
            SetStyle(ControlStyles.ResizeRedraw | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer, true);
            Font = new Font("Segoe UI", 9f);
            BackColor = accent;
            ForeColor = Color.White;
            MinimumSize = new Size(200, 36);

            btnDetails = MakeButton();
            btnReport = MakeButton();
            btnClose = new Label { Text = "✕", AutoSize = false, Size = new Size(22, 22), TextAlign = ContentAlignment.MiddleCenter, ForeColor = Color.White, Cursor = Cursors.Hand, BackColor = Color.Transparent };
            btnDetails.Click += (s, e) => Raise(DetailsRequested);
            btnReport.Click += (s, e) => Raise(ReportRequested);
            btnClose.Click += (s, e) => Raise(CloseRequested);
            Controls.Add(btnDetails);
            Controls.Add(btnReport);
            Controls.Add(btnClose);
            Resize += (s, e) => LayoutButtons();
            Click += (s, e) => Raise(DetailsRequested);
            Cursor = Cursors.Hand;
            ShowPending();
        }

        void Raise(EventHandler h)
        {
            if (h != null) h(this, EventArgs.Empty);
        }

        static Button MakeButton()
        {
            var b = new Button { FlatStyle = FlatStyle.Flat, ForeColor = Color.White, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Height = 26, Cursor = Cursors.Hand, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Padding = new Padding(6, 0, 6, 0) };
            b.FlatAppearance.BorderColor = Color.FromArgb(235, 255, 255, 255);
            return b;
        }

        void LayoutButtons()
        {
            int x = Width - 8;
            btnClose.Location = new Point(x - btnClose.Width, (Height - btnClose.Height) / 2);
            x = btnClose.Left - 8;
            if (btnReport.Visible) { btnReport.Location = new Point(x - btnReport.Width, (Height - btnReport.Height) / 2); x = btnReport.Left - 8; }
            btnDetails.Location = new Point(x - btnDetails.Width, (Height - btnDetails.Height) / 2);
            Invalidate();
        }

        void Apply(Color c)
        {
            accent = c;
            BackColor = c;
            var dark = Color.FromArgb(Math.Max(0, c.R - 35), Math.Max(0, c.G - 35), Math.Max(0, c.B - 35));
            foreach (var b in new[] { btnDetails, btnReport })
            {
                b.BackColor = dark;
                b.FlatAppearance.MouseOverBackColor = Color.FromArgb(Math.Max(0, c.R - 60), Math.Max(0, c.G - 60), Math.Max(0, c.B - 60));
            }
            btnDetails.Text = L.T("Voir le détail");
            btnReport.Text = L.T("Signaler");
            LayoutButtons();
        }

        /// <summary>Message pas encore analysé (analyse automatique désactivée ou en cours).</summary>
        internal void ShowPending()
        {
            scoreText = "";
            title = "PhishGuard";
            reasons = L.T("Cliquez pour analyser ce message.");
            btnReport.Visible = false;
            Apply(Color.FromArgb(95, 107, 122));
        }

        internal void ShowResult(AnalysisResult r)
        {
            scoreText = r.Score.ToString();
            if (r.Level == "dangerous") title = L.T("PhishGuard : message dangereux");
            else if (r.Level == "suspicious") title = L.T("PhishGuard : message suspect");
            else title = L.T("PhishGuard : aucun indice important");
            var top = r.Findings.Where(f => f.Severity != Severity.Info).Take(3).Select(f => f.Title).ToArray();
            reasons = top.Length > 0 ? string.Join("  ·  ", top) : L.T("Restez vigilant : aucun outil ne détecte 100 % des attaques.");
            btnReport.Visible = r.Level != "safe";
            Apply(r.Level == "dangerous" ? Color.FromArgb(196, 38, 46) : r.Level == "suspicious" ? Color.FromArgb(184, 98, 0) : Color.FromArgb(19, 128, 74));
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
            int x = 12;
            int mid = Height / 2;
            if (scoreText.Length > 0)
            {
                using (var bold = new Font("Segoe UI", 9.5f, FontStyle.Bold))
                {
                    var sz = TextRenderer.MeasureText(scoreText, bold);
                    var pill = new Rectangle(x, mid - 11, Math.Max(30, sz.Width + 10), 22);
                    using (var path = Rounded(pill, 11))
                    using (var white = new SolidBrush(Color.White))
                        g.FillPath(white, path);
                    TextRenderer.DrawText(g, scoreText, bold, pill, accent, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
                    x = pill.Right + 10;
                }
            }
            int right = (btnDetails.Visible ? btnDetails.Left : Width) - 12;
            using (var bold = new Font("Segoe UI", 9.5f, FontStyle.Bold))
            {
                var tsz = TextRenderer.MeasureText(title, bold);
                var tr = new Rectangle(x, 0, Math.Min(tsz.Width + 4, Math.Max(0, right - x)), Height);
                TextRenderer.DrawText(g, title, bold, tr, Color.White, TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
                x = tr.Right + 10;
            }
            if (right - x > 40)
            {
                var rr = new Rectangle(x, 0, right - x, Height);
                TextRenderer.DrawText(g, reasons, Font, rr, Color.FromArgb(240, 245, 248), TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
            }
        }

        static GraphicsPath Rounded(Rectangle r, int radius)
        {
            var p = new GraphicsPath();
            int d = radius * 2;
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }
    }

    public partial class Connect : ICustomTaskPaneConsumer
    {
        const int OlExplorerClass = 34, OlInspectorClass = 35;
        const int DockTop = 1, DockRestrictNoChange = 1;

        object ctpFactory;
        bool bannerFailed;

        class Pane
        {
            public object Window;
            public object Ctp;
            public BannerControl Control;
            public bool IsInspector;
            public object Mail;
            public string MailKey = "\u0001";
            public string Signature = "\u0001";
        }

        readonly List<Pane> panes = new List<Pane>();

        public void CTPFactoryAvailable(object CTPFactoryInst)
        {
            ctpFactory = CTPFactoryInst;
            Log("Volets personnalisés disponibles (bandeau)");
        }

        /// <summary>Appelé par la minuterie : un bandeau par fenêtre, mis à jour selon le message affiché.</summary>
        void BannerTick()
        {
            if (ctpFactory == null || application == null || bannerFailed) return;
            if (!config.ShowBanner) { RemoveAllPanes(); return; }
            var windows = new List<object>();
            dynamic app = application;
            try
            {
                dynamic exps = app.Explorers;
                int n = exps.Count;
                for (int i = 1; i <= n; i++) windows.Add((object)exps.Item(i));
            }
            catch (Exception) { }
            try
            {
                dynamic ins = app.Inspectors;
                int n = ins.Count;
                for (int i = 1; i <= n; i++)
                {
                    object w = ins.Item(i);
                    object item = null;
                    try { item = ((dynamic)w).CurrentItem; } catch (Exception) { }
                    if (IsMail(item)) windows.Add(w);
                }
            }
            catch (Exception) { }

            for (int i = panes.Count - 1; i >= 0; i--)
            {
                var p = panes[i];
                if (!windows.Any(w => SameCom(w, p.Window))) { DeletePane(p); panes.RemoveAt(i); }
            }
            foreach (var w in windows)
            {
                var p = panes.FirstOrDefault(x => SameCom(x.Window, w));
                if (p == null)
                {
                    p = CreatePane(w);
                    if (p == null) return;
                    panes.Add(p);
                }
                try { UpdatePane(p); } catch (Exception ex) { Log("Bandeau : " + ex.Message); }
            }
        }

        static bool SameCom(object a, object b)
        {
            if (ReferenceEquals(a, b)) return true;
            if (a == null || b == null) return false;
            IntPtr pa = IntPtr.Zero, pb = IntPtr.Zero;
            try
            {
                pa = Marshal.GetIUnknownForObject(a);
                pb = Marshal.GetIUnknownForObject(b);
                return pa == pb;
            }
            catch (Exception) { return false; }
            finally
            {
                if (pa != IntPtr.Zero) Marshal.Release(pa);
                if (pb != IntPtr.Zero) Marshal.Release(pb);
            }
        }

        Pane CreatePane(object window)
        {
            try
            {
                BannerControl.LastCreated = null;
                dynamic factory = ctpFactory;
                dynamic ctp = factory.CreateCTP("PhishGuard.Banner", "PhishGuard", window);
                ctp.DockPosition = DockTop;
                ctp.DockPositionRestrict = DockRestrictNoChange;
                try { ctp.Height = 46; } catch (Exception) { }
                BannerControl ctl = null;
                try { ctl = ctp.ContentControl as BannerControl; } catch (Exception) { }
                if (ctl == null) ctl = BannerControl.LastCreated;
                if (ctl == null)
                {
                    try { ctp.Delete(); } catch (Exception) { }
                    throw new Exception("contrôle du bandeau introuvable");
                }
                int cls = 0;
                try { cls = (int)((dynamic)window).Class; } catch (Exception) { }
                var p = new Pane { Window = window, Ctp = ctp, Control = ctl, IsInspector = cls == OlInspectorClass };
                ctl.DetailsRequested += (s, e) =>
                {
                    try { if (p.Mail != null) OpenDetails(p.Mail); } catch (Exception ex) { Log("Bandeau, détail : " + ex.Message); }
                };
                ctl.ReportRequested += (s, e) =>
                {
                    try
                    {
                        if (p.Mail == null) return;
                        var c = AnalyzeCached(p.Mail, true);
                        Report(p.Mail, c.Data, c.Result);
                    }
                    catch (Exception ex) { Log("Bandeau, signalement : " + ex.Message); }
                };
                ctl.CloseRequested += (s, e) => { try { ((dynamic)p.Ctp).Visible = false; } catch (Exception) { } };
                return p;
            }
            catch (Exception ex)
            {
                // Bandeau indisponible (stratégie, enregistrement incomplet...) : le reste du complément continue.
                bannerFailed = true;
                Log("Bandeau indisponible : " + ex);
                return null;
            }
        }

        void UpdatePane(Pane p)
        {
            object mail = null;
            string key = "";
            dynamic w = p.Window;
            try
            {
                object item = null;
                if (p.IsInspector) item = w.CurrentItem;
                else
                {
                    dynamic sel = w.Selection;
                    if (sel.Count > 0) item = sel.Item(1);
                }
                if (IsMail(item)) { mail = item; key = KeyOf(item); }
            }
            catch (Exception) { /* vue sans sélection (calendrier, contacts...) */ }

            AnalysisResult r = null;
            if (mail != null)
            {
                Cached c;
                if (cache.TryGetValue(key, out c)) r = c.Result;
                else if (config.AutoAnalyze && AutoAllowed(mail))
                {
                    c = AnalyzeCached(mail, false);
                    if (c != null) r = c.Result;
                }
            }
            string sig = key + "|" + (r == null ? "" : r.Score + r.Level + r.Findings.Count) + "|" + (L.English ? "en" : "fr");
            if (sig == p.Signature) return;
            bool mailChanged = key != p.MailKey;
            p.Signature = sig;
            p.MailKey = key;
            p.Mail = mail;
            dynamic ctp = p.Ctp;
            if (mail == null) { ctp.Visible = false; return; }
            if (r == null) p.Control.ShowPending(); else p.Control.ShowResult(r);
            if (mailChanged) ctp.Visible = true;
        }

        void DeletePane(Pane p)
        {
            try { ((dynamic)p.Ctp).Delete(); } catch (Exception) { }
        }

        void RemoveAllPanes()
        {
            foreach (var p in panes) DeletePane(p);
            panes.Clear();
        }
    }
}
