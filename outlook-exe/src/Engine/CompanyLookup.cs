// PhishGuard - recherche d'une entreprise française dans l'Annuaire des Entreprises de l'État
// (recherche-entreprises.api.gouv.fr : API publique, gratuite, sans clé, données INSEE et RNE).
// Sert à préremplir les dirigeants (fraude au président) depuis l'onglet Entreprise des paramètres.
// Seul le nom saisi est envoyé ; rien ne part sans un clic sur « Rechercher ».

using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Web.Script.Serialization;

namespace PhishGuard
{
    public class CompanyInfo
    {
        public string Name = "";
        public string Siren = "";
        public string City = "";
        public string Created = "";
        public bool Active = true;
        public List<string> Directors = new List<string>();   // « Prénom Nom »
        public List<string> Roles = new List<string>();       // « Prénom Nom (qualité) »
    }

    public static class CompanyLookup
    {
        public const string ApiUrl = "https://recherche-entreprises.api.gouv.fr/search?per_page=10&q=";

        /// <summary>Recherche par nom (ou SIREN). Lève une exception si le service est injoignable.</summary>
        public static List<CompanyInfo> Search(string name)
        {
            string q = (name ?? "").Trim();
            if (q.Length < 2) return new List<CompanyInfo>();
            return Parse(Intel.Http("GET", ApiUrl + Uri.EscapeDataString(q), null, null, null, 3000000));
        }

        public static List<CompanyInfo> Parse(string json)
        {
            var list = new List<CompanyInfo>();
            var root = new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.DeserializeObject(json ?? "") as Dictionary<string, object>;
            if (root == null) return list;
            var results = Get(root, "results") as IEnumerable;
            if (results == null) return list;
            foreach (var o in results)
            {
                var r = o as Dictionary<string, object>;
                if (r == null) continue;
                var c = new CompanyInfo
                {
                    Name = Str(Get(r, "nom_complet")),
                    Siren = Str(Get(r, "siren")),
                    Created = Str(Get(r, "date_creation")),
                    Active = Str(Get(r, "etat_administratif")) != "C"
                };
                var siege = Get(r, "siege") as Dictionary<string, object>;
                if (siege != null) c.City = Title(Str(Get(siege, "libelle_commune")));
                var dirs = Get(r, "dirigeants") as IEnumerable;
                if (dirs != null)
                    foreach (var d in dirs)
                    {
                        var p = d as Dictionary<string, object>;
                        if (p == null) continue;
                        string type = Str(Get(p, "type_dirigeant"));
                        string nom = Str(Get(p, "nom"));
                        if (type == "personne morale" || nom.Length == 0) continue;
                        string prenom = Str(Get(p, "prenoms")).Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
                        string full = (Title(prenom) + " " + Title(nom)).Trim();
                        if (c.Directors.Contains(full)) continue;
                        c.Directors.Add(full);
                        string q = Str(Get(p, "qualite"));
                        c.Roles.Add(q.Length > 0 ? full + " (" + q + ")" : full);
                    }
                list.Add(c);
            }
            // Entreprises en activité d'abord
            return list.OrderBy(x => x.Active ? 0 : 1).ToList();
        }

        static object Get(Dictionary<string, object> d, string key)
        {
            object v;
            return d.TryGetValue(key, out v) ? v : null;
        }

        static string Str(object o) { return o == null ? "" : Convert.ToString(o, CultureInfo.InvariantCulture).Trim(); }

        /// <summary>« JEAN-PIERRE » → « Jean-Pierre », « DE LA TOUR » → « De La Tour ».</summary>
        public static string Title(string s)
        {
            var chars = (s ?? "").ToLowerInvariant().ToCharArray();
            bool start = true;
            for (int i = 0; i < chars.Length; i++)
            {
                if (start && char.IsLetter(chars[i])) chars[i] = char.ToUpperInvariant(chars[i]);
                start = chars[i] == ' ' || chars[i] == '-' || chars[i] == '\'';
            }
            return new string(chars);
        }
    }
}
