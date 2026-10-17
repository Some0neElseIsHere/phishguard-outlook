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
