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
        public string Country = "";       // FR pour l'Annuaire des Entreprises, sinon le pays donné par Wikidata
        public string Website = "";       // domaine du site officiel (Wikidata)
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
                    Country = "FR",
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

        // -----------------------------------------------------------------
        // Entreprises du monde entier : Wikidata (base libre, sans clé). Couvre surtout les entreprises connues.
        // -----------------------------------------------------------------

        const string WikidataApi = "https://www.wikidata.org/w/api.php?format=json&";
        // Propriétés : P169 directeur général, P488 président, P1037 directeur ou dirigeant, P17 pays, P856 site officiel
        static readonly string[][] RoleProps = { new[] { "P169", "directeur général" }, new[] { "P488", "président" }, new[] { "P1037", "dirigeant" } };

        public static List<CompanyInfo> SearchWorld(string name, string language)
        {
            string q = (name ?? "").Trim();
            if (q.Length < 2) return new List<CompanyInfo>();
            string lang = string.IsNullOrEmpty(language) ? "fr" : language;
            string search = Intel.Http("GET", WikidataApi + "action=wbsearchentities&type=item&limit=10&language=" + lang + "&uselang=" + lang + "&search=" + Uri.EscapeDataString(q), null, null, null, 2000000);
            var ids = SearchIds(search);
            if (ids.Count == 0) return new List<CompanyInfo>();
            string entities = Intel.Http("GET", WikidataApi + "action=wbgetentities&props=labels|claims&languages=" + lang + "|en&ids=" + string.Join("|", ids.ToArray()), null, null, null, 8000000);
            var refs = ReferencedIds(entities);
            string labels = refs.Count == 0 ? "{}" : Intel.Http("GET", WikidataApi + "action=wbgetentities&props=labels&languages=" + lang + "|en&ids=" + string.Join("|", refs.Take(50).ToArray()), null, null, null, 2000000);
            return ParseWikidata(ids, entities, labels, lang);
        }

        static Dictionary<string, object> Json(string json)
        {
            return new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.DeserializeObject(json ?? "") as Dictionary<string, object> ?? new Dictionary<string, object>();
        }

        public static List<string> SearchIds(string searchJson)
        {
            var ids = new List<string>();
            var results = Get(Json(searchJson), "search") as IEnumerable;
            if (results != null)
                foreach (var o in results)
                {
                    var d = o as Dictionary<string, object>;
                    string id = d == null ? "" : Str(Get(d, "id"));
                    if (id.StartsWith("Q") && !ids.Contains(id)) ids.Add(id);
                }
            return ids;
        }

        /// <summary>Valeurs actuelles d'une propriété (sans date de fin, rang « déprécié » exclu ; le rang « préféré » d'abord).</summary>
        static List<object> Current(Dictionary<string, object> claims, string prop)
        {
            var list = new List<object>();
            var arr = Get(claims, prop) as IEnumerable;
            if (arr == null) return list;
            var preferred = new List<object>();
            foreach (var o in arr)
            {
                var c = o as Dictionary<string, object>;
                if (c == null) continue;
                string rank = Str(Get(c, "rank"));
                var quals = Get(c, "qualifiers") as Dictionary<string, object>;
                if (rank == "deprecated" || (quals != null && quals.ContainsKey("P582"))) continue;   // P582 : date de fin
                var snak = Get(c, "mainsnak") as Dictionary<string, object>;
                var dv = snak == null ? null : Get(snak, "datavalue") as Dictionary<string, object>;
                if (dv == null) continue;
                object v = Get(dv, "value");
                var ent = v as Dictionary<string, object>;
                object value = ent != null ? (object)Str(Get(ent, "id")) : Str(v);
                (rank == "preferred" ? preferred : list).Add(value);
            }
            preferred.AddRange(list);
            return preferred;
        }

        static Dictionary<string, object> Entities(string json)
        {
            return Get(Json(json), "entities") as Dictionary<string, object> ?? new Dictionary<string, object>();
        }

        public static List<string> ReferencedIds(string entitiesJson)
        {
            var refs = new List<string>();
            foreach (var kv in Entities(entitiesJson))
            {
                var claims = Get(kv.Value as Dictionary<string, object> ?? new Dictionary<string, object>(), "claims") as Dictionary<string, object>;
                if (claims == null) continue;
                foreach (var p in RoleProps.Select(r => r[0]).Concat(new[] { "P17" }))
                    foreach (var v in Current(claims, p))
                    {
                        string id = v as string;
                        if (!string.IsNullOrEmpty(id) && id.StartsWith("Q") && !refs.Contains(id)) refs.Add(id);
                    }
            }
            return refs;
        }

        static string Label(Dictionary<string, object> entity, string lang)
        {
            var labels = Get(entity, "labels") as Dictionary<string, object>;
            if (labels == null) return "";
            foreach (var l in new[] { lang, "en" })
            {
                var d = Get(labels, l) as Dictionary<string, object>;
                if (d != null) return Str(Get(d, "value"));
            }
            return "";
        }

        /// <summary>Entreprises trouvées, celles qui ont un dirigeant ou un site officiel en premier.</summary>
        public static List<CompanyInfo> ParseWikidata(List<string> ids, string entitiesJson, string labelsJson, string lang)
        {
            var list = new List<CompanyInfo>();
            var ents = Entities(entitiesJson);
            var refLabels = Entities(labelsJson);
            Func<string, string> refLabel = id =>
            {
                object o;
                return refLabels.TryGetValue(id, out o) && o is Dictionary<string, object> ? Label((Dictionary<string, object>)o, lang) : "";
            };
            foreach (var id in ids)
            {
                object o;
                if (!ents.TryGetValue(id, out o)) continue;
                var ent = o as Dictionary<string, object>;
                if (ent == null) continue;
                var claims = Get(ent, "claims") as Dictionary<string, object> ?? new Dictionary<string, object>();
                var c = new CompanyInfo { Name = Label(ent, lang), Siren = id };
                c.Country = Current(claims, "P17").Select(v => refLabel(v as string ?? "")).FirstOrDefault(x => x.Length > 0) ?? "";
                c.City = c.Country;
                string site = Current(claims, "P856").Select(v => v as string ?? "").FirstOrDefault(x => x.Length > 0) ?? "";
                Uri u;
                if (Uri.TryCreate(site, UriKind.Absolute, out u)) c.Website = Domains.RegistrableDomain(u.Host);
                foreach (var role in RoleProps)
                    foreach (var v in Current(claims, role[0]))
                    {
                        string person = refLabel(v as string ?? "");
                        if (person.Length == 0 || c.Directors.Contains(person)) continue;
                        c.Directors.Add(person);
                        c.Roles.Add(person + " (" + L.T(role[1]) + ")");
                    }
                if (c.Name.Length > 0) list.Add(c);
            }
            // Les fiches avec dirigeants ou site officiel d'abord ; les autres restent proposées (petites entreprises peu renseignées)
            return list.OrderBy(x => x.Directors.Count > 0 || x.Website.Length > 0 ? 0 : 1).ToList();
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
