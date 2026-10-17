// PhishGuard - clés d'API rangées dans le Gestionnaire d'identification de Windows (coffre de l'utilisateur).
// - chiffrées par Windows pour ce compte (DPAPI), lisibles seulement par cet utilisateur sur ce poste ;
// - stockées hors du dossier de PhishGuard : une réinstallation ou une désinstallation ne les efface pas ;
// - visibles et supprimables dans Panneau de configuration → Gestionnaire d'identification → Informations
//   d'identification Windows → « PhishGuard:... ».

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace PhishGuard
{
    public static class Secrets
    {
        const uint CredTypeGeneric = 1;
        const uint CredPersistLocalMachine = 2;   // ce poste uniquement (pas d'itinérance du profil)

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct Credential
        {
            public uint Flags;
            public uint Type;
            public string TargetName;
            public string Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public uint CredentialBlobSize;
            public IntPtr CredentialBlob;
            public uint Persist;
            public uint AttributeCount;
            public IntPtr Attributes;
            public string TargetAlias;
            public string UserName;
        }

        [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CredWrite(ref Credential credential, uint flags);

        [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CredRead(string target, uint type, uint flags, out IntPtr credential);

        [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CredDelete(string target, uint type, uint flags);

        [DllImport("advapi32.dll")]
        static extern void CredFree(IntPtr buffer);

        static string Target(string name) { return "PhishGuard:" + name; }

        /// <summary>Clé enregistrée, ou "" si absente ou illisible.</summary>
        public static string Get(string name)
        {
            IntPtr p;
            try
            {
                if (!CredRead(Target(name), CredTypeGeneric, 0, out p)) return "";
            }
            catch (Exception) { return ""; }
            try
            {
                var c = (Credential)Marshal.PtrToStructure(p, typeof(Credential));
                if (c.CredentialBlob == IntPtr.Zero || c.CredentialBlobSize == 0) return "";
                var bytes = new byte[c.CredentialBlobSize];
                Marshal.Copy(c.CredentialBlob, bytes, 0, bytes.Length);
                return Encoding.Unicode.GetString(bytes);
            }
            catch (Exception) { return ""; }
            finally { CredFree(p); }
        }

        /// <summary>Enregistre (ou supprime si vide) une clé. Renvoie false si le coffre de Windows est indisponible.</summary>
        public static bool Set(string name, string value)
        {
            string v = (value ?? "").Trim();
            try
            {
                if (v.Length == 0)
                {
                    CredDelete(Target(name), CredTypeGeneric, 0);
                    return true;
                }
                byte[] bytes = Encoding.Unicode.GetBytes(v);
                IntPtr blob = Marshal.AllocHGlobal(bytes.Length);
                try
                {
                    Marshal.Copy(bytes, 0, blob, bytes.Length);
                    var c = new Credential
                    {
                        Type = CredTypeGeneric,
                        TargetName = Target(name),
                        Comment = "PhishGuard pour Outlook",
                        CredentialBlobSize = (uint)bytes.Length,
                        CredentialBlob = blob,
                        Persist = CredPersistLocalMachine,
                        UserName = "PhishGuard"
                    };
                    return CredWrite(ref c, 0);
                }
                finally
                {
                    // efface la copie en mémoire non gérée avant de la libérer
                    Marshal.Copy(new byte[bytes.Length], 0, blob, bytes.Length);
                    Marshal.FreeHGlobal(blob);
                }
            }
            catch (Exception) { return false; }
        }
    }
}
