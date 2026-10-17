// PhishGuard - interfaces COM d'Office déclarées à la main (aucune dépendance aux
// assemblys "Primary Interop" d'Office : le complément se compile avec le seul .NET Framework).

using System;
using System.Drawing;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Forms;

[assembly: AssemblyTitle("PhishGuard pour Outlook")]
[assembly: AssemblyDescription("Analyse anti-phishing des emails reçus")]
[assembly: AssemblyProduct("PhishGuard")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: ComVisible(false)]

namespace PhishGuard.AddIn
{
    public enum ext_ConnectMode { ext_cm_AfterStartup = 0, ext_cm_Startup = 1, ext_cm_External = 2, ext_cm_CommandLine = 3 }
    public enum ext_DisconnectMode { ext_dm_HostShutdown = 0, ext_dm_UserClosed = 1 }

    /// <summary>Interface de base de tout complément COM Office (Extensibility.IDTExtensibility2).</summary>
    [ComImport, Guid("B65AD801-ABAF-11D0-BB8B-00A0C90F2744"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    public interface IDTExtensibility2
    {
        // Outlook passe "custom" sous forme de SAFEARRAY de VARIANT : sans cet attribut, .NET
        // l'interprète comme un autre type d'objet, ce qui peut faire planter Outlook au démarrage.
        [DispId(1)] void OnConnection([In, MarshalAs(UnmanagedType.IDispatch)] object Application, [In] ext_ConnectMode ConnectMode,
                                      [In, MarshalAs(UnmanagedType.IDispatch)] object AddInInst,
                                      [In, MarshalAs(UnmanagedType.SafeArray, SafeArraySubType = VarEnum.VT_VARIANT)] ref Array custom);
        [DispId(2)] void OnDisconnection([In] ext_DisconnectMode RemoveMode,
                                         [In, MarshalAs(UnmanagedType.SafeArray, SafeArraySubType = VarEnum.VT_VARIANT)] ref Array custom);
        [DispId(3)] void OnAddInsUpdate([In, MarshalAs(UnmanagedType.SafeArray, SafeArraySubType = VarEnum.VT_VARIANT)] ref Array custom);
        [DispId(4)] void OnStartupComplete([In, MarshalAs(UnmanagedType.SafeArray, SafeArraySubType = VarEnum.VT_VARIANT)] ref Array custom);
        [DispId(5)] void OnBeginShutdown([In, MarshalAs(UnmanagedType.SafeArray, SafeArraySubType = VarEnum.VT_VARIANT)] ref Array custom);
    }

    /// <summary>Ruban Office (Microsoft.Office.Core.IRibbonExtensibility).</summary>
    [ComImport, Guid("000C0396-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    public interface IRibbonExtensibility
    {
        [DispId(1)]
        [return: MarshalAs(UnmanagedType.BStr)]
        string GetCustomUI([In, MarshalAs(UnmanagedType.BStr)] string RibbonID);
    }

    /// <summary>Volets personnalisés Office (Microsoft.Office.Core.ICustomTaskPaneConsumer) : sert au bandeau.</summary>
    [ComImport, Guid("000C033E-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    public interface ICustomTaskPaneConsumer
    {
        [DispId(1)] void CTPFactoryAvailable([In, MarshalAs(UnmanagedType.IDispatch)] object CTPFactoryInst);
    }

    /// <summary>
    /// Zones de formulaire Outlook fournies par un complément (Microsoft.Office.Interop.Outlook._FormRegionStartup).
    /// Ordre des méthodes et DispId relevés dans l'assembly d'interopérabilité d'Outlook 2013+.
    /// </summary>
    [ComImport, Guid("00063059-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    public interface _FormRegionStartup
    {
        [DispId(64310)]
        object GetFormRegionStorage([In, MarshalAs(UnmanagedType.BStr)] string FormRegionName, [In, MarshalAs(UnmanagedType.IDispatch)] object Item,
                                    [In] int LCID, [In] int FormRegionMode, [In] int FormRegionSize);
        [DispId(64317)]
        void BeforeFormRegionShow([In, MarshalAs(UnmanagedType.IDispatch)] object FormRegion);
        [DispId(64563)]
        object GetFormRegionManifest([In, MarshalAs(UnmanagedType.BStr)] string FormRegionName, [In] int LCID);
        [DispId(64564)]
        object GetFormRegionIcon([In, MarshalAs(UnmanagedType.BStr)] string FormRegionName, [In] int LCID, [In] int Icon);
    }

    // ---- Stockage OLE (création de la mise en page de la zone, format Forms 2.0) ----

    [ComImport, Guid("0000000A-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ILockBytes { }

    [ComImport, Guid("0000000B-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IStorage
    {
        void CreateStream();
        void OpenStream();
        void CreateStorage();
        void OpenStorage();
        void CopyTo();
        void MoveElementTo();
        [PreserveSig] int Commit(uint grfCommitFlags);
        void Revert();
        void EnumElements();
        void DestroyElement();
        void RenameElement();
        void SetElementTimes();
        void SetClass();
        void SetStateBits();
        void Stat();
    }

    [ComImport, Guid("0000010A-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IPersistStorage
    {
        void GetClassID(out Guid pClassID);
        [PreserveSig] int IsDirty();
        [PreserveSig] int InitNew(IStorage pStg);
        [PreserveSig] int Load(IStorage pStg);
        [PreserveSig] int Save(IStorage pStgSave, [MarshalAs(UnmanagedType.Bool)] bool fSameAsLoad);
        [PreserveSig] int SaveCompleted(IStorage pStgNew);
        [PreserveSig] int HandsOffStorage();
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SIZEL { public int cx; public int cy; }

    [ComImport, Guid("00000112-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IOleObject
    {
        void SetClientSite();
        void GetClientSite();
        void SetHostNames();
        void Close();
        void SetMoniker();
        void GetMoniker();
        void InitFromData();
        void GetClipboardData();
        void DoVerb();
        void EnumVerbs();
        void Update();
        void IsUpToDate();
        void GetUserClassID();
        void GetUserType();
        [PreserveSig] int SetExtent(uint dwDrawAspect, ref SIZEL psizel);
        [PreserveSig] int GetExtent(uint dwDrawAspect, out SIZEL psizel);
    }

    /// <summary>Convertit une image .NET en IPictureDisp pour les icônes du ruban.</summary>
    internal class PictureConverter : AxHost
    {
        private PictureConverter() : base(string.Empty) { }

        public static object ToPicture(Image image)
        {
            return GetIPictureDispFromPicture(image);
        }
    }
}
