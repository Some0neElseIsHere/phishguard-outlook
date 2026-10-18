using System;
using System.Collections.Generic;
using System.Drawing;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Win32;

namespace PhishGuard.AddIn
{
    /// <summary>Fenêtre qui doit être redessinée quand le thème change (page HTML, par exemple).</summary>
    internal interface IThemed
    {
        void ThemeChanged();
    }

    /// <summary>
    /// Thème clair ou sombre des fenêtres WinForms, selon le réglage Theme et le thème des applications de Windows
    /// (Paramètres → Personnalisation → Couleurs). Les couleurs d'origine sont conservées pour pouvoir revenir au clair.
    /// </summary>
    internal static class ThemeUi
    {
        static string setting = "auto";
        static bool listening, everDark;

        /// <summary>Thème des applications de Windows : true si « Sombre ».</summary>
        public static bool SystemDark()
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"))
                {
                    object v = k == null ? null : k.GetValue("AppsUseLightTheme");
                    if (v is int) return (int)v == 0;
                }
            }
            catch (Exception) { }
            return false;
        }

        /// <summary>Recalcule le thème. true s'il a changé.</summary>
        public static bool Refresh(string themeSetting)
        {
            setting = themeSetting ?? "auto";
            bool dark = Theme.Resolve(setting, SystemDark());
            if (dark == Theme.Dark) return false;
            Theme.Dark = dark;
            return true;
        }

        /// <summary>Suit les changements de thème de Windows pendant qu'Outlook est ouvert.</summary>
        public static void Listen()
        {
            if (listening) return;
            try { SystemEvents.UserPreferenceChanged += OnPreferenceChanged; listening = true; }
            catch (Exception) { }
        }

        public static void StopListening()
        {
            if (!listening) return;
            try { SystemEvents.UserPreferenceChanged -= OnPreferenceChanged; } catch (Exception) { }
            listening = false;
        }

        static void OnPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
        {
            if (e.Category != UserPreferenceCategory.General && e.Category != UserPreferenceCategory.VisualStyle && e.Category != UserPreferenceCategory.Color) return;
            if (Refresh(setting)) ApplyAll();
        }

        /// <summary>Applique le thème courant à toutes les fenêtres ouvertes de PhishGuard.</summary>
        public static void ApplyAll()
        {
            var forms = new List<Form>();
            foreach (Form f in Application.OpenForms) forms.Add(f);
            foreach (var f in forms)
            {
                var form = f;
                MethodInvoker run = () =>
                {
                    Apply(form);
                    var t = form as IThemed;
                    if (t != null) t.ThemeChanged();
                };
                try
                {
                    if (form.IsDisposed) continue;
                    if (form.InvokeRequired) form.BeginInvoke(run); else run();
                }
                catch (Exception) { }
            }
        }

        // ---------- Couleurs ----------

        public static Color Back(Color c) { return Map(c, Theme.Kind.Back); }
        public static Color Fore(Color c) { return Map(c, Theme.Kind.Text); }
        public static Color Border(Color c) { return Map(c, Theme.Kind.Border); }

        static Color Map(Color c, Theme.Kind k)
        {
            if (!Theme.Dark || c.IsEmpty || c.A == 0) return c;
            return Color.FromArgb(Theme.Map(c.ToArgb() & 0xFFFFFF, k) | unchecked((int)0xFF000000));
        }

        static readonly Color Surface = Color.FromArgb(0x2A, 0x2D, 0x32);
        static readonly Color Input = Color.FromArgb(0x2B, 0x2E, 0x33);
        static readonly Color ButtonBack = Color.FromArgb(0x33, 0x37, 0x3D);
        static readonly Color ButtonHover = Color.FromArgb(0x3D, 0x42, 0x49);
        static readonly Color ButtonDown = Color.FromArgb(0x47, 0x4D, 0x55);
        static readonly Color ButtonBorder = Color.FromArgb(0x55, 0x5C, 0x66);
        public static readonly Color PageBack = Color.FromArgb(0x20, 0x23, 0x27);
        public static readonly Color Text = Color.FromArgb(0xE6, 0xE9, 0xED);

        // ---------- Contrôles ----------

        class Original
        {
            public Color Back, Fore, FlatBorder, FlatOver, FlatDown, Link, ActiveLink, VisitedLink;
            public bool OwnBack, OwnFore, VisualBack, Themed;
            public FlatStyle Flat;
            public BorderStyle Border;
            public bool HasBorder;
        }

        static readonly ConditionalWeakTable<Control, Original> Originals = new ConditionalWeakTable<Control, Original>();

        /// <summary>Applique le thème à une fenêtre et suit les contrôles ajoutés plus tard.</summary>
        public static void Attach(Form f)
        {
            Apply(f);
            f.HandleCreated += (s, e) => { TitleBar(f); NativeThemes(f); };
        }

        public static void Apply(Control root)
        {
            Walk(root, root.Parent);
            var f = root as Form;
            if (f != null) TitleBar(f);
            NativeThemes(root);
            root.Invalidate(true);
        }

        static void Walk(Control c, Control parent)
        {
            if (c is WebBrowser) return;
            Original o;
            if (!Originals.TryGetValue(c, out o))
            {
                o = new Original
                {
                    Back = c.BackColor,
                    Fore = c.ForeColor,
                    OwnBack = parent == null || c.BackColor != parent.BackColor,
                    OwnFore = parent == null || c.ForeColor != parent.ForeColor
                };
                var b = c as ButtonBase;
                if (b != null)
                {
                    o.Flat = b.FlatStyle;
                    o.FlatBorder = b.FlatAppearance.BorderColor;
                    o.FlatOver = b.FlatAppearance.MouseOverBackColor;
                    o.FlatDown = b.FlatAppearance.MouseDownBackColor;
                }
                var cb = c as ComboBox;
                if (cb != null) o.Flat = cb.FlatStyle;
                var tp = c as TabPage;
                if (tp != null) o.VisualBack = tp.UseVisualStyleBackColor;
                var ll = c as LinkLabel;
                if (ll != null) { o.Link = ll.LinkColor; o.ActiveLink = ll.ActiveLinkColor; o.VisitedLink = ll.VisitedLinkColor; }
                Originals.Add(c, o);
                c.ControlAdded += (s, e) => { Walk(e.Control, c); NativeThemes(e.Control); };
                var list = c as ListView;
                if (list != null) DarkHeaders(list);
            }
            bool dark = Theme.Dark;
            // En thème clair, une fenêtre jamais passée en sombre n'est pas modifiée
            if (!dark && !o.Themed)
            {
                foreach (Control child in c.Controls) Walk(child, c);
                return;
            }
            o.Themed = dark;

            // Couleur du texte : seulement si le contrôle a la sienne (sinon il hérite de son parent)
            if (c is Form) c.ForeColor = dark ? Text : o.Fore;
            else if (o.OwnFore) c.ForeColor = dark ? Fore(o.Fore) : o.Fore;

            if (c is Form) c.BackColor = dark ? (o.Back.ToArgb() == Color.White.ToArgb() ? Surface : PageBack) : o.Back;
            else if (c is TextBoxBase || c is ListBox || c is ListView || c is TreeView || c is UpDownBase)
            {
                c.BackColor = dark ? (o.Back.ToArgb() == SystemColors.Control.ToArgb() ? PageBack : Input) : o.Back;
                c.ForeColor = !dark ? o.Fore : o.OwnFore ? Fore(o.Fore) : Text;
            }
            else if (c is TabPage)
            {
                var tp = (TabPage)c;
                tp.UseVisualStyleBackColor = dark ? false : o.VisualBack;
                tp.BackColor = dark ? PageBack : o.Back;
            }
            else if (o.OwnBack) c.BackColor = dark ? Back(o.Back) : o.Back;

            var btn = c as ButtonBase;
            if (btn is Button)
            {
                bool custom = o.Flat == FlatStyle.Flat && o.OwnBack;
                if (dark)
                {
                    btn.FlatStyle = FlatStyle.Flat;
                    if (custom)
                    {
                        btn.BackColor = Back(o.Back);
                        btn.FlatAppearance.BorderColor = Border(o.FlatBorder);
                        bool saturated = btn.BackColor.ToArgb() == o.Back.ToArgb();
                        btn.FlatAppearance.MouseOverBackColor = saturated ? o.FlatOver : ButtonHover;
                        btn.FlatAppearance.MouseDownBackColor = saturated ? o.FlatDown : ButtonDown;
                    }
                    else
                    {
                        btn.BackColor = ButtonBack;
                        btn.FlatAppearance.BorderColor = ButtonBorder;
                        btn.FlatAppearance.MouseOverBackColor = ButtonHover;
                        btn.FlatAppearance.MouseDownBackColor = ButtonDown;
                    }
                    if (!o.OwnFore) btn.ForeColor = Text;
                }
                else
                {
                    btn.FlatStyle = o.Flat;
                    btn.BackColor = o.Back;
                    btn.FlatAppearance.BorderColor = o.FlatBorder;
                    btn.FlatAppearance.MouseOverBackColor = o.FlatOver;
                    btn.FlatAppearance.MouseDownBackColor = o.FlatDown;
                    if (!o.OwnFore) btn.ForeColor = o.Fore;
                }
            }

            var combo = c as ComboBox;
            if (combo != null)
            {
                combo.FlatStyle = dark ? FlatStyle.Flat : o.Flat;
                combo.BackColor = dark ? Input : o.Back;
                combo.ForeColor = dark ? Text : o.Fore;
            }

            var link = c as LinkLabel;
            if (link != null)
            {
                link.LinkColor = dark ? Color.FromArgb(0x6C, 0xB4, 0xF0) : o.Link;
                link.ActiveLinkColor = dark ? Color.FromArgb(0x9C, 0xCD, 0xF6) : o.ActiveLink;
                link.VisitedLinkColor = dark ? Color.FromArgb(0xB4, 0x9C, 0xF0) : o.VisitedLink;
            }

            var lv = c as ListView;
            if (lv != null)
            {
                lv.OwnerDraw = dark && lv.View == View.Details;
                foreach (ListViewItem it in lv.Items) ThemeItem(it, lv);
            }

            var tabs = c as ThemedTabControl;
            if (tabs != null) tabs.Dark = dark;

            foreach (Control child in c.Controls) Walk(child, c);
        }

        /// <summary>En-têtes de colonnes dessinés en sombre (ceux de Windows restent clairs) ; les lignes restent dessinées par Windows.</summary>
        static void DarkHeaders(ListView lv)
        {
            lv.DrawItem += (s, e) => { e.DrawDefault = true; };
            lv.DrawSubItem += (s, e) => { e.DrawDefault = true; };
            lv.DrawColumnHeader += (s, e) =>
            {
                using (var b = new SolidBrush(Color.FromArgb(0x30, 0x34, 0x3A))) e.Graphics.FillRectangle(b, e.Bounds);
                using (var p = new Pen(Color.FromArgb(0x4B, 0x52, 0x5B)))
                {
                    e.Graphics.DrawLine(p, e.Bounds.Right - 1, e.Bounds.Top + 3, e.Bounds.Right - 1, e.Bounds.Bottom - 4);
                    e.Graphics.DrawLine(p, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
                }
                var r = new Rectangle(e.Bounds.X + 6, e.Bounds.Y, e.Bounds.Width - 8, e.Bounds.Height);
                TextRenderer.DrawText(e.Graphics, e.Header.Text, lv.Font, r, Color.FromArgb(0xB4, 0xBC, 0xC6),
                    TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine);
            };
        }

        /// <summary>Couleur d'une ligne de liste ajoutée après l'ouverture de la fenêtre.</summary>
        public static void ThemeItem(ListViewItem it, ListView lv)
        {
            if (!Theme.Dark || it.ForeColor.ToArgb() == lv.ForeColor.ToArgb()) return;
            it.ForeColor = Fore(it.ForeColor);
        }

        // ---------- Parties dessinées par Windows ----------

        [DllImport("dwmapi.dll")]
        static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
        static extern int SetWindowTheme(IntPtr hwnd, string app, string idList);

        [DllImport("user32.dll")]
        static extern IntPtr SendMessage(IntPtr hwnd, int msg, IntPtr w, IntPtr l);

        /// <summary>Barre de titre sombre (Windows 10 version 1809 et suivantes, Windows 11).</summary>
        static void TitleBar(Form f)
        {
            if (Theme.Dark) everDark = true;
            if (!f.IsHandleCreated || !everDark) return;
            try
            {
                int on = Theme.Dark ? 1 : 0;
                if (DwmSetWindowAttribute(f.Handle, 20, ref on, 4) != 0) DwmSetWindowAttribute(f.Handle, 19, ref on, 4);
            }
            catch (Exception) { }
        }

        /// <summary>Barres de défilement et en-têtes de colonnes sombres.</summary>
        static void NativeThemes(Control c)
        {
            if (Theme.Dark) everDark = true;
            if (c is WebBrowser || !everDark) return;
            try
            {
                if (c.IsHandleCreated && (c is TextBoxBase || c is ListBox || c is ListView || c is TreeView || (c is ScrollableControl && !(c is Form))))
                {
                    if (Theme.Dark) SetWindowTheme(c.Handle, "DarkMode_Explorer", null);
                    else SetWindowTheme(c.Handle, null, null);
                    var lv = c as ListView;
                    if (lv != null)
                    {
                        // Fond sombre de la barre d'en-têtes au-delà de la dernière colonne (le texte est dessiné par DarkHeaders)
                        IntPtr header = SendMessage(lv.Handle, 0x101F, IntPtr.Zero, IntPtr.Zero);   // LVM_GETHEADER
                        if (header != IntPtr.Zero)
                        {
                            if (Theme.Dark) SetWindowTheme(header, "DarkMode_ItemsView", null);
                            else SetWindowTheme(header, null, null);
                        }
                    }
                }
                else if (!c.IsHandleCreated)
                {
                    var target = c;
                    EventHandler once = null;
                    once = (s, e) => { target.HandleCreated -= once; NativeThemes(target); };
                    target.HandleCreated += once;
                }
            }
            catch (Exception) { }
            foreach (Control child in c.Controls) NativeThemes(child);
        }
    }

    /// <summary>Onglets dessinés par PhishGuard en thème sombre (ceux de Windows restent toujours clairs).</summary>
    internal class ThemedTabControl : TabControl
    {
        bool dark;

        public bool Dark
        {
            get { return dark; }
            set
            {
                if (dark == value) return;
                dark = value;
                SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, value);
                if (IsHandleCreated) { UpdateStyles(); Invalidate(); }
            }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            if (!dark) { base.OnPaint(e); return; }
            var g = e.Graphics;
            Color back = Parent != null ? Parent.BackColor : ThemeUi.PageBack;
            using (var b = new SolidBrush(back)) g.FillRectangle(b, ClientRectangle);
            Rectangle page = DisplayRectangle;
            page.Inflate(4, 4);
            using (var p = new Pen(Color.FromArgb(0x4B, 0x52, 0x5B))) g.DrawRectangle(p, page.X, page.Y, page.Width - 1, page.Height - 1);
            for (int i = 0; i < TabCount; i++)
            {
                Rectangle r = GetTabRect(i);
                bool selected = i == SelectedIndex;
                if (selected) r.Inflate(0, 2);
                using (var b = new SolidBrush(selected ? ThemeUi.PageBack : Color.FromArgb(0x2A, 0x2D, 0x32))) g.FillRectangle(b, r);
                using (var p = new Pen(Color.FromArgb(0x4B, 0x52, 0x5B))) g.DrawRectangle(p, r.X, r.Y, r.Width - 1, r.Height - (selected ? 0 : 1));
                if (selected)
                    using (var p = new Pen(Color.FromArgb(0x4A, 0x9E, 0xE6), 2f)) g.DrawLine(p, r.X + 1, r.Y + 1, r.Right - 2, r.Y + 1);
                TextRenderer.DrawText(g, TabPages[i].Text, Font, r, selected ? ThemeUi.Text : Color.FromArgb(0xB4, 0xBC, 0xC6),
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
            }
        }
    }
}
