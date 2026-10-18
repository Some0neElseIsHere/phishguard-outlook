// PhishGuard - stratégies d'entreprise : réglages poussés par GPO ou Intune dans le registre
// (HKLM ou HKCU \Software\Policies\PhishGuard). Seul un administrateur peut écrire sous « Policies » :
// l'utilisateur ne peut pas les modifier. Les noms de valeurs sont ceux de config.ini (modèle ADMX dans policies\).
// Les stratégies de l'ordinateur (HKLM) l'emportent sur celles de l'utilisateur (HKCU).

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Win32;

namespace PhishGuard.AddIn
{
    internal static class Policies
    {
        public const string KeyPath = @"Software\Policies\PhishGuard";

        public static List<KeyValuePair<string, string>> Read()
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            ReadHive(RegistryHive.CurrentUser, map);
            ReadHive(RegistryHive.LocalMachine, map);
            return map.ToList();
        }

        static void ReadHive(RegistryHive hive, Dictionary<string, string> map)
        {
            try
            {
                var view = Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default;
                using (var root = RegistryKey.OpenBaseKey(hive, view))
                using (var key = root.OpenSubKey(KeyPath))
                {
                    if (key == null) return;
                    foreach (var name in key.GetValueNames())
                    {
                        if (string.IsNullOrEmpty(name)) continue;
                        object v = key.GetValue(name);
                        if (v is int) map[name] = ((int)v).ToString();
                        else if (v is string[]) map[name] = string.Join(", ", (string[])v);
                        else if (v != null) map[name] = Convert.ToString(v);
                    }
                }
            }
            catch (Exception) { }
        }
    }
}
