// PhishGuard - zone d'alerte dans l'en-tête des messages dangereux (« zone de formulaire » Outlook, type adjoining).
//
// Outlook demande au complément :
//   1. le manifeste XML de la zone (GetFormRegionManifest) ;
//   2. pour chaque message affiché, la mise en page (GetFormRegionStorage) : PhishGuard ne la fournit que si le
//      message est dangereux, sinon la zone n'apparaît pas ;
//   3. juste avant l'affichage (BeforeFormRegionShow) : PhishGuard y place son contrôle (PhishGuard.Banner en mode zone).
// La mise en page (format Forms 2.0) est créée à la volée avec le moteur de formulaires d'Office (FM20.DLL).
// Si la zone ne peut pas être créée sur ce poste, le bandeau en haut de la fenêtre prend le relais.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace PhishGuard.AddIn
{
    public partial class Connect : _FormRegionStartup
    {
        public const string ZoneName = "PhishGuardZone";

        bool zoneFailed;
        bool zoneManifestRequested;   // Outlook a bien chargé la zone (sinon le bandeau prend le relais)
        byte[] zoneLayout;

        class Zone
        {
            public object Form;
            public object Ctrl;
            public BannerControl Control;
            public object Mail;
            public double Width;
        }

        readonly List<Zone> zones = new List<Zone>();

        public object GetFormRegionManifest(string FormRegionName, int LCID)
        {
            zoneManifestRequested = true;
            Log("Zone : manifeste demandé (" + FormRegionName + ")");
            return "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                 + "<FormRegion xmlns=\"http://schemas.microsoft.com/office/outlook/12/formregion.xsd\">"
                 + "<name>" + ZoneName + "</name>"
                 + "<title>PhishGuard</title>"
                 + "<formRegionType>adjoining</formRegionType>"
                 + "<showInspectorCompose>false</showInspectorCompose>"
                 + "<showInspectorRead>true</showInspectorRead>"
                 + "<showReadingPane>true</showReadingPane>"
                 + "<addin>PhishGuard.Connect</addin>"
                 + "</FormRegion>";
        }

        public object GetFormRegionIcon(string FormRegionName, int LCID, int Icon)
        {
            return null;
        }

        /// <summary>Renvoie la mise en page seulement pour un message dangereux (null = pas de zone).</summary>
        public object GetFormRegionStorage(string FormRegionName, object Item, int LCID, int FormRegionMode, int FormRegionSize)
        {
            try
            {
                if (!config.ShowBanner || zoneFailed || Item == null || !IsMail(Item) || !AutoAllowed(Item)) return null;
                var c = AnalyzeCached(Item, false);
                if (c == null || c.Result.Level != "dangerous") return null;
                if (zoneLayout == null) zoneLayout = BuildZoneLayout();
                return zoneLayout;
            }
            catch (Exception ex)
            {
                zoneFailed = true;
                Log("Zone indisponible (mise en page) : " + ex);
                return null;
            }
        }

        public void BeforeFormRegionShow(object FormRegion)
        {
            try
            {
                dynamic region = FormRegion;
                object item = region.Item;
                var c = AnalyzeCached(item, false);
                dynamic form = region.Form;
                BannerControl.LastCreated = null;
                dynamic ctrl = form.Controls.Add("PhishGuard.Banner", "PhishGuardZoneControl", true);
                double w = 600, h = 66;
                try { w = (double)form.InsideWidth; h = Math.Max(h, (double)form.InsideHeight); } catch (Exception) { }
                ctrl.Left = 0;
                ctrl.Top = 0;
                ctrl.Width = w;
                ctrl.Height = h;
                BannerControl bc = null;
                try { bc = ctrl.Object as BannerControl; } catch (Exception) { }
                if (bc == null) bc = BannerControl.LastCreated;
                if (bc == null) throw new Exception("contrôle de la zone introuvable");
                bc.ZoneMode = true;
                bc.ShowResult(c.Result);
                var z = new Zone { Form = (object)form, Ctrl = (object)ctrl, Control = bc, Mail = item, Width = w };
                bc.DetailsRequested += (s, e) => { try { OpenDetails(z.Mail); } catch (Exception ex) { Log("Zone, détail : " + ex.Message); } };
                bc.ReportRequested += (s, e) =>
                {
                    try { var cc = AnalyzeCached(z.Mail, true); Report(z.Mail, cc.Data, cc.Result); }
                    catch (Exception ex) { Log("Zone, signalement : " + ex.Message); }
                };
                bc.CloseRequested += (s, e) => { try { ((dynamic)FormRegion).Visible = false; } catch (Exception) { } };
                zones.Add(z);
            }
            catch (Exception ex)
            {
                zoneFailed = true;
                Log("Zone indisponible (affichage) : " + ex);
                try { ((dynamic)FormRegion).Visible = false; } catch (Exception) { }
            }
        }

        /// <summary>Minuterie : suit la largeur du volet de lecture et oublie les zones fermées.</summary>
        void ZoneTick()
        {
            for (int i = zones.Count - 1; i >= 0; i--)
            {
                var z = zones[i];
                try
                {
                    double w = (double)((dynamic)z.Form).InsideWidth;
                    if (Math.Abs(w - z.Width) > 1)
                    {
                        ((dynamic)z.Ctrl).Width = w;
                        z.Width = w;
                    }
                }
                catch (Exception) { zones.RemoveAt(i); }
            }
        }

        // -----------------------------------------------------------------
        // Mise en page Forms 2.0 vide (équivalent d'un fichier .ofs), créée en mémoire
        // -----------------------------------------------------------------

        [DllImport("ole32.dll")] static extern int CreateILockBytesOnHGlobal(IntPtr hGlobal, bool fDeleteOnRelease, out ILockBytes ppLkbyt);
        [DllImport("ole32.dll")] static extern int StgCreateDocfileOnILockBytes(ILockBytes plkbyt, uint grfMode, uint reserved, out IStorage ppstgOpen);
        [DllImport("ole32.dll")] static extern int WriteClassStg(IStorage pStg, ref Guid rclsid);
        [DllImport("ole32.dll")] static extern int GetHGlobalFromILockBytes(ILockBytes plkbyt, out IntPtr phglobal);
        [DllImport("kernel32.dll")] static extern IntPtr GlobalLock(IntPtr hMem);
        [DllImport("kernel32.dll")] static extern bool GlobalUnlock(IntPtr hMem);
        [DllImport("kernel32.dll")] static extern UIntPtr GlobalSize(IntPtr hMem);

        const uint StgmCreate = 0x1000, StgmReadWrite = 0x2, StgmShareExclusive = 0x10;
        static readonly Guid FormClsid = new Guid("C62A69F0-16DC-11CE-9E98-00AA00574A4F"); // Forms.Form.1 (FM20.DLL)

        static byte[] BuildZoneLayout()
        {
            Type t = Type.GetTypeFromProgID("Forms.Form.1");
            if (t == null) throw new Exception("Forms.Form.1 introuvable (FM20.DLL)");
            object form = Activator.CreateInstance(t);
            ILockBytes bytes = null;
            IStorage stg = null;
            try
            {
                Check(CreateILockBytesOnHGlobal(IntPtr.Zero, true, out bytes), "CreateILockBytesOnHGlobal");
                Check(StgCreateDocfileOnILockBytes(bytes, StgmCreate | StgmReadWrite | StgmShareExclusive, 0, out stg), "StgCreateDocfileOnILockBytes");
                var persist = (IPersistStorage)form;
                Check(persist.InitNew(stg), "InitNew");
                try
                {
                    // Taille de la zone : 600 x 66 pixels (en centièmes de millimètre)
                    var size = new SIZEL { cx = 15875, cy = 1746 };
                    ((IOleObject)form).SetExtent(1, ref size);
                }
                catch (Exception) { }
                Guid clsid = FormClsid;
                Check(WriteClassStg(stg, ref clsid), "WriteClassStg");
                Check(persist.Save(stg, true), "Save");
                persist.SaveCompleted(null);
                Check(stg.Commit(0), "Commit");

                IntPtr h;
                Check(GetHGlobalFromILockBytes(bytes, out h), "GetHGlobalFromILockBytes");
                int len = (int)GlobalSize(h).ToUInt32();
                var data = new byte[len];
                IntPtr p = GlobalLock(h);
                try { Marshal.Copy(p, data, 0, len); }
                finally { GlobalUnlock(h); }
                Log("Zone : mise en page créée (" + len + " octets)");
                return data;
            }
            finally
            {
                if (stg != null) Marshal.ReleaseComObject(stg);
                if (bytes != null) Marshal.ReleaseComObject(bytes);
                Marshal.ReleaseComObject(form);
            }
        }

        static void Check(int hr, string what)
        {
            if (hr < 0) throw new COMException(what + " a échoué", hr);
        }
    }
}
