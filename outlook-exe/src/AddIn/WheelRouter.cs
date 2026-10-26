// PhishGuard - molette de la souris dans les fenêtres à défilement (paramètres, assistant, analyse du domaine).
// Windows envoie la molette au contrôle placé sous la souris : en descendant une page, elle s'arrêtait sur chaque zone
// de saisie ou liste traversée. Ici, la molette fait défiler la page, sauf dans le contrôle où l'on a cliqué (il a le
// focus) quand son contenu dépasse : c'est alors lui qui défile.

using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace PhishGuard.AddIn
{
    internal static class WheelRouter
    {
        const int WM_MOUSEWHEEL = 0x020A, SB_VERT = 1, SIF_RANGE = 0x1, SIF_PAGE = 0x2;

        [StructLayout(LayoutKind.Sequential)]
        struct SCROLLINFO { public int cbSize, fMask, nMin, nMax, nPage, nPos, nTrackPos; }

        [DllImport("user32.dll")]
        static extern bool GetScrollInfo(IntPtr hwnd, int bar, ref SCROLLINFO info);

        [DllImport("user32.dll")]
        static extern IntPtr SendMessage(IntPtr hwnd, int msg, IntPtr w, IntPtr l);

        /// <summary>Suit tous les contrôles de la fenêtre, y compris ceux ajoutés plus tard (pages refaites de l'assistant).</summary>
        public static void Attach(Control root)
        {
            object done;
            if (hooked.TryGetValue(root, out done)) return;
            Hook(root);
            if (!hooked.TryGetValue(root, out done)) hooked.Add(root, null);
            root.ControlAdded += (s, e) => Attach(e.Control);
            foreach (Control c in root.Controls) Attach(c);
        }

        static readonly System.Runtime.CompilerServices.ConditionalWeakTable<Control, object> hooked = new System.Runtime.CompilerServices.ConditionalWeakTable<Control, object>();

        static void Hook(Control c)
        {
            if (!(c is TextBoxBase || c is ListView || c is ListBox || c is ComboBox)) return;
            object done;
            if (hooked.TryGetValue(c, out done)) return;   // une seule fois par contrôle (sinon la molette compterait double)
            hooked.Add(c, null);
            if (c.IsHandleCreated) new Router(c).AssignHandle(c.Handle);
            c.HandleCreated += (s, e) => new Router(c).AssignHandle(c.Handle);
        }

        /// <summary>Le contrôle a-t-il de quoi défiler verticalement ?</summary>
        static bool CanScroll(Control c)
        {
            if (c is ComboBox) return ((ComboBox)c).DroppedDown;
            var si = new SCROLLINFO { cbSize = Marshal.SizeOf(typeof(SCROLLINFO)), fMask = SIF_RANGE | SIF_PAGE };
            if (!GetScrollInfo(c.Handle, SB_VERT, ref si)) return false;
            return si.nPage > 0 && si.nMax - si.nMin + 1 > si.nPage;
        }

        /// <summary>Le conteneur qui fait défiler la page (onglet, panneau) : le plus proche qui a une barre de défilement.</summary>
        static Control ScrollingParent(Control c)
        {
            for (var p = c.Parent; p != null; p = p.Parent)
            {
                var sc = p as ScrollableControl;
                if (sc != null && sc.AutoScroll && sc.VerticalScroll.Visible) return p;
            }
            return null;
        }

        sealed class Router : NativeWindow
        {
            readonly Control control;
            public Router(Control c)
            {
                control = c;
                c.HandleDestroyed += (s, e) => ReleaseHandle();
            }

            protected override void WndProc(ref Message m)
            {
                if (m.Msg == WM_MOUSEWHEEL)
                {
                    try
                    {
                        if (!(control.Focused && CanScroll(control)))
                        {
                            var page = ScrollingParent(control);
                            if (page != null) { SendMessage(page.Handle, WM_MOUSEWHEEL, m.WParam, m.LParam); return; }
                        }
                    }
                    catch (Exception) { }
                }
                base.WndProc(ref m);
            }
        }
    }
}
