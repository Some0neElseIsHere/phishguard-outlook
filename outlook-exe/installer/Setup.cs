// PhishGuard pour Outlook - programme d'installation (un seul .exe, sans droit administrateur).
// Les fichiers du complément sont intégrés à l'exe ; l'installation fait exactement ce que fait installer.cmd :
// copie dans %LOCALAPPDATA%\PhishGuard, enregistrement COM dans HKCU (vues 64 et 32 bits),
// déclaration du complément dans Outlook et entrée « Applications et fonctionnalités ».
//
//   PhishGuard-Outlook-Setup.exe             installation avec fenêtre
//   PhishGuard-Outlook-Setup.exe /quiet      installation silencieuse (GPO, script de connexion)
//   PhishGuard-Outlook-Setup.exe /uninstall  désinstallation

using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: AssemblyTitle("PhishGuard pour Outlook - installation")]
[assembly: AssemblyProduct("PhishGuard pour Outlook")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

namespace PhishGuard.Setup
{
    static class Program
    {
        const string ProgId = "PhishGuard.Connect";
        const string Clsid = "{6C3F2A1E-8B5D-4E7A-9F21-3D4B8C6E2A71}";
        const string AssemblyName = "PhishGuard, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null";
        static string DisplayVersion
        {
            get
            {
                try
                {
                    using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("Setup.version.txt"))
                        if (s != null) using (var r = new StreamReader(s)) { string v = r.ReadToEnd().Trim().TrimStart('v', 'V'); if (v.Length > 0) return v; }
                }
                catch (Exception) { }
                return "1.0.0";
            }
        }
        static readonly string[] Files = { "PhishGuard.dll", "config.ini", "custom.txt", "phishguard.ico", "installer.cmd", "desinstaller.cmd" };

        static string Dest { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhishGuard"); } }

        static bool French { get { return Thread.CurrentThread.CurrentUICulture.TwoLetterISOLanguageName == "fr"; } }
        static string T(string fr, string en) { return French ? fr : en; }

        [STAThread]
        static int Main(string[] args)
        {
            bool quiet = false, uninstall = false;
            foreach (var a in args)
            {
                string x = a.Trim().TrimStart('/', '-').ToLowerInvariant();
                if (x == "quiet" || x == "q" || x == "s" || x == "silent") quiet = true;
                if (x == "uninstall" || x == "u" || x == "remove") uninstall = true;
            }

            if (quiet)
            {
                try
                {
                    WaitForOutlookClosed(null);
                    if (uninstall) Uninstall(); else Install();
                    return 0;
                }
                catch (Exception ex)
                {
                    try { File.AppendAllText(Path.Combine(Path.GetTempPath(), "phishguard-setup.log"), DateTime.Now.ToString("s") + " " + ex + Environment.NewLine); }
                    catch (Exception) { }
                    return 1;
                }
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            using (var f = new SetupForm(uninstall)) Application.Run(f);
            return 0;
        }

        // -----------------------------------------------------------------
        // Outlook doit être fermé
        // -----------------------------------------------------------------

        static bool OutlookRunning()
        {
            return Process.GetProcessesByName("OUTLOOK").Length > 0;
        }

        /// <summary>Mode silencieux : attend la fermeture d'Outlook (au plus 10 minutes).</summary>
        static void WaitForOutlookClosed(object unused)
        {
            for (int i = 0; i < 120 && OutlookRunning(); i++) Thread.Sleep(5000);
            if (OutlookRunning()) throw new Exception("Outlook est toujours ouvert.");
        }

        // -----------------------------------------------------------------
        // Installation
        // -----------------------------------------------------------------

        internal static void Install()
        {
            Directory.CreateDirectory(Dest);
            var asm = Assembly.GetExecutingAssembly();
            foreach (var name in Files)
            {
                using (var s = asm.GetManifestResourceStream("Setup." + name))
                {
                    if (s == null)
                    {
                        if (name == "PhishGuard.dll") throw new Exception("PhishGuard.dll manquant dans l'installeur.");
                        continue;
                    }
                    string target = Path.Combine(Dest, name);
                    // Les réglages de l'administrateur déjà présents sont remplacés ; ceux de l'utilisateur
                    // (config.user.ini, custom.user.txt) ne sont jamais touchés.
                    using (var o = File.Create(target)) s.CopyTo(o);
                }
            }

            string dll = Path.Combine(Dest, "PhishGuard.dll");
            string codeBase = "file:///" + dll.Replace('\\', '/');
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                using (var root = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view))
                {
                    Set(root, @"Software\Classes\" + ProgId, null, ProgId);
                    Set(root, @"Software\Classes\" + ProgId + @"\CLSID", null, Clsid);
                    string ck = @"Software\Classes\CLSID\" + Clsid;
                    Set(root, ck, null, ProgId);
                    Set(root, ck + @"\ProgId", null, ProgId);
                    using (root.CreateSubKey(ck + @"\Implemented Categories\{62C8FE65-4EBB-45e7-B440-6E39B2CDBF29}")) { }
                    Set(root, ck + @"\InprocServer32", null, "mscoree.dll");
                    Set(root, ck + @"\InprocServer32", "ThreadingModel", "Both");
                    foreach (var k in new[] { ck + @"\InprocServer32", ck + @"\InprocServer32\1.0.0.0" })
                    {
                        Set(root, k, "Class", "PhishGuard.AddIn.Connect");
                        Set(root, k, "Assembly", AssemblyName);
                        Set(root, k, "RuntimeVersion", "v4.0.30319");
                        Set(root, k, "CodeBase", codeBase);
                    }
                }
            }

            using (var ak = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Office\Outlook\Addins\" + ProgId))
            {
                ak.SetValue("FriendlyName", "PhishGuard");
                ak.SetValue("Description", T("Analyse anti-phishing des emails reçus", "Anti-phishing analysis of received emails"));
                ak.SetValue("LoadBehavior", 3, RegistryValueKind.DWord);
            }
            // Évite qu'Outlook désactive le complément s'il juge son démarrage trop lent
            try
            {
                using (var rk = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Office\16.0\Outlook\Resiliency\DoNotDisableAddinList"))
                    rk.SetValue(ProgId, 1, RegistryValueKind.DWord);
            }
            catch (Exception) { }

            using (var uk = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\PhishGuard"))
            {
                uk.SetValue("DisplayName", T("PhishGuard pour Outlook", "PhishGuard for Outlook"));
                uk.SetValue("DisplayVersion", DisplayVersion);
                uk.SetValue("Publisher", "PhishGuard");
                uk.SetValue("InstallLocation", Dest);
                uk.SetValue("DisplayIcon", Path.Combine(Dest, "phishguard.ico"));
                uk.SetValue("UninstallString", "\"" + Path.Combine(Dest, "desinstaller.cmd") + "\"");
                uk.SetValue("NoModify", 1, RegistryValueKind.DWord);
                uk.SetValue("NoRepair", 1, RegistryValueKind.DWord);
            }
        }

        static void Set(RegistryKey root, string path, string name, string value)
        {
            using (var k = root.CreateSubKey(path)) k.SetValue(name ?? "", value);
        }

        // -----------------------------------------------------------------
        // Désinstallation
        // -----------------------------------------------------------------

        internal static void Uninstall()
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                using (var root = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view))
                {
                    root.DeleteSubKeyTree(@"Software\Classes\" + ProgId, false);
                    root.DeleteSubKeyTree(@"Software\Classes\CLSID\" + Clsid, false);
                }
            }
            Registry.CurrentUser.DeleteSubKeyTree(@"Software\Microsoft\Office\Outlook\Addins\" + ProgId, false);
            Registry.CurrentUser.DeleteSubKeyTree(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\PhishGuard", false);
            try
            {
                using (var rk = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Office\16.0\Outlook\Resiliency\DoNotDisableAddinList", true))
                    if (rk != null) rk.DeleteValue(ProgId, false);
            }
            catch (Exception) { }
            // Les fichiers du programme sont supprimés ; les réglages et journaux de l'utilisateur aussi (dossier entier).
            try { if (Directory.Exists(Dest)) Directory.Delete(Dest, true); } catch (Exception) { }
        }

        // -----------------------------------------------------------------
        // Fenêtre
        // -----------------------------------------------------------------

        sealed class SetupForm : Form
        {
            readonly bool uninstall;
            readonly Label message;
            readonly Button action, close;

            public SetupForm(bool uninstall)
            {
                this.uninstall = uninstall;
                Text = uninstall ? T("PhishGuard - désinstallation", "PhishGuard - uninstall") : T("PhishGuard pour Outlook - installation", "PhishGuard for Outlook - setup");
                Font = new Font("Segoe UI", 9.5f);
                FormBorderStyle = FormBorderStyle.FixedDialog;
                MaximizeBox = false;
                MinimizeBox = false;
                StartPosition = FormStartPosition.CenterScreen;
                ClientSize = new Size(480, 250);
                BackColor = Color.White;
                try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch (Exception) { }

                var band = new Panel { Dock = DockStyle.Top, Height = 64, BackColor = Color.FromArgb(15, 108, 189) };
                var title = new Label
                {
                    Text = uninstall ? T("Désinstaller PhishGuard", "Uninstall PhishGuard") : T("PhishGuard pour Outlook", "PhishGuard for Outlook"),
                    ForeColor = Color.White, Font = new Font("Segoe UI", 15f, FontStyle.Bold),
                    AutoSize = true, Location = new Point(20, 16), BackColor = Color.Transparent
                };
                band.Controls.Add(title);

                message = new Label
                {
                    Location = new Point(20, 80), Size = new Size(440, 110),
                    Text = uninstall
                        ? T("PhishGuard va être retiré d'Outlook pour votre compte Windows.", "PhishGuard will be removed from Outlook for your Windows account.")
                        : T("Analyse anti-phishing des emails, directement dans Outlook.\n\n"
                            + "Installation pour votre compte Windows uniquement : aucun droit administrateur n'est nécessaire. "
                            + "Outlook doit être fermé pendant l'installation.",
                            "Anti-phishing analysis of your emails, right inside Outlook.\n\n"
                            + "Installs for your Windows account only: no administrator rights needed. "
                            + "Outlook must be closed during setup.")
                };

                action = new Button
                {
                    Text = uninstall ? T("Désinstaller", "Uninstall") : T("Installer", "Install"),
                    Size = new Size(120, 34), Location = new Point(220, 200),
                    BackColor = Color.FromArgb(15, 108, 189), ForeColor = Color.White, FlatStyle = FlatStyle.Flat,
                    Font = new Font("Segoe UI", 9.5f, FontStyle.Bold)
                };
                action.FlatAppearance.BorderSize = 0;
                close = new Button { Text = T("Annuler", "Cancel"), Size = new Size(110, 34), Location = new Point(350, 200), FlatStyle = FlatStyle.System };

                action.Click += (s, e) => Run();
                close.Click += (s, e) => Close();
                Controls.Add(band);
                Controls.Add(message);
                Controls.Add(action);
                Controls.Add(close);
                AcceptButton = action;
                CancelButton = close;
            }

            void Run()
            {
                while (OutlookRunning())
                {
                    var r = MessageBox.Show(this,
                        T("Outlook est ouvert. Fermez Outlook, puis cliquez sur Réessayer.", "Outlook is running. Close Outlook, then click Retry."),
                        "PhishGuard", MessageBoxButtons.RetryCancel, MessageBoxIcon.Information);
                    if (r != DialogResult.Retry) return;
                }
                action.Enabled = false;
                Cursor = Cursors.WaitCursor;
                try
                {
                    if (uninstall)
                    {
                        Uninstall();
                        message.Text = T("PhishGuard a été désinstallé.", "PhishGuard has been uninstalled.");
                    }
                    else
                    {
                        Install();
                        message.Text = T("PhishGuard est installé.\n\n"
                            + "Ouvrez Outlook : le score de chaque email s'affiche dans l'onglet Accueil. "
                            + "Cliquez dessus pour le détail, le signalement et les paramètres.",
                            "PhishGuard is installed.\n\n"
                            + "Open Outlook: each email's score is shown on the Home tab. "
                            + "Click it for the details, reporting and settings.");
                    }
                    action.Visible = false;
                    close.Text = T("Terminer", "Finish");
                }
                catch (Exception ex)
                {
                    action.Enabled = true;
                    message.Text = T("L'opération a échoué : ", "Setup failed: ") + ex.Message;
                }
                finally { Cursor = Cursors.Default; }
            }
        }
    }
}
