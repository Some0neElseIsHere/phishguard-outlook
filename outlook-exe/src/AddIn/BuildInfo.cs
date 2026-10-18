// PhishGuard - informations de version. Le numéro est écrit au moment de la construction (construire.bat génère
// build\BuildVersion.cs à partir de PG_VERSION) ; sans lui (construction locale, captures d'écran) : « développement ».

namespace PhishGuard.AddIn
{
    internal static partial class BuildInfo
    {
        public const string Repository = "https://github.com/Some0neElseIsHere/phishguard-outlook";
        public const string Releases = Repository + "/releases";

        public static string Version
        {
            get
            {
                string v = null;
                Generated(ref v);
                return string.IsNullOrEmpty(v) || v == "dev" ? L.T("version de développement") : v;
            }
        }

        static partial void Generated(ref string version);
    }
}
