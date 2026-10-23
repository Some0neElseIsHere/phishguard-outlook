// PhishGuard - pont entre la page de l'analyse détaillée et le complément (window.external dans la page).
// Seules des actions nommées et sans paramètre libre sont acceptées.

using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace PhishGuard.AddIn
{
    [ComVisible(true)]
    [ClassInterface(ClassInterfaceType.AutoDispatch)]
    public class PageBridge
    {
        readonly ResultForm form;
        internal PageBridge(ResultForm form) { this.form = form; }

        /// <summary>Appelé par la page : window.external.Action('age').</summary>
        public void Action(string name)
        {
            if (name != "age") return;
            try { form.BeginInvoke((MethodInvoker)(() => form.PageAction(name, "script"))); }
            catch (Exception) { }
        }
    }
}
