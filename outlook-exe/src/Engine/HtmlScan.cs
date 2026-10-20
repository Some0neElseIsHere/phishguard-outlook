using System;
using System.Collections.Generic;
using System.Net;
using System.Text.RegularExpressions;

namespace PhishGuard
{
    /// <summary>
    /// Lecture des liens et des champs de formulaire du HTML d'un message, en temps linéaire.
    /// Une expression régulière unique « &lt;a ...&gt;(.*?)&lt;/a&gt; » est quadratique : un message de 200 Ko composé
    /// de « &lt;a href=x&gt; » sans balise fermante la faisait tourner plusieurs dizaines de secondes, et Outlook restait
    /// figé pendant ce temps (l'analyse a lieu à la sélection du message). Ici chaque balise est lue une seule fois,
    /// avec des longueurs bornées.
    /// </summary>
    public static class HtmlScan
    {
        public const int MaxHtml = 4 * 1024 * 1024;   // au-delà, le reste du HTML n'est pas lu
        const int MaxTag = 4000;                       // longueur maximale d'une balise ouvrante
        const int MaxText = 4000;                      // texte d'un lien conservé
        const int MaxLinks = 3000;

        static readonly Regex HrefRe = new Regex(@"\bhref\s*=\s*(?:""([^""]*)""|'([^']*)'|([^\s>]+))", RegexOptions.IgnoreCase);
        static readonly Regex TagRe = new Regex(@"<[^>]{0,4000}>");
        static readonly Regex SpaceRe = new Regex(@"\s+");
        static readonly Regex PasswordTypeRe = new Regex(@"\btype\s*=\s*[""']?password", RegexOptions.IgnoreCase);

        static string Cap(string html)
        {
            if (html == null) return "";
            return html.Length > MaxHtml ? html.Substring(0, MaxHtml) : html;
        }

        /// <summary>« &lt;nom » suivi d'une fin de mot (espace, « &gt; », « / »…), comme \b.</summary>
        static bool TagStart(string s, int afterName)
        {
            if (afterName >= s.Length) return false;
            char c = s[afterName];
            return !char.IsLetterOrDigit(c) && c != '_';
        }

        /// <summary>Premier « > » à partir de pos, en réutilisant la recherche précédente (temps linéaire sur tout le HTML).</summary>
        static int NextGt(string s, int pos, ref int gt)
        {
            if (gt == int.MaxValue) return -1;
            if (gt < pos) gt = s.IndexOf('>', pos);
            if (gt < 0) { gt = int.MaxValue; return -1; }
            return gt;
        }

        /// <summary>Positions de toutes les balises fermantes « &lt;/a &gt; » (espaces permis avant « &gt; »).</summary>
        static List<int> Closings(string s)
        {
            var list = new List<int>();
            int i = 0;
            while ((i = s.IndexOf("</a", i, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                int j = i + 3;
                while (j < s.Length && j - i < 64 && char.IsWhiteSpace(s[j])) j++;
                if (j < s.Length && s[j] == '>') list.Add(i);
                i += 3;
            }
            return list;
        }

        /// <summary>Liens &lt;a href&gt; du HTML, avec leur texte affiché (balises retirées, entités décodées).</summary>
        public static List<LinkInfo> Links(string htmlIn)
        {
            var links = new List<LinkInfo>();
            string html = Cap(htmlIn);
            if (html.Length == 0) return links;
            var closings = Closings(html);
            var seen = new HashSet<string>();
            int i = 0, ci = 0, gt = -1;
            while (links.Count < MaxLinks && (i = html.IndexOf("<a", i, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                int after = i + 2;
                if (!TagStart(html, after)) { i = after; continue; }
                int end = NextGt(html, after, ref gt);
                if (end < 0) break;                              // plus aucun « > » : plus aucune balise complète
                if (end - after > MaxTag) { i = after; continue; }
                var h = HrefRe.Match(html, i, end - i + 1);
                // Première balise fermante après la balise ouvrante (comme « (.*?)</a> ») : recherche qui ne revient jamais en arrière
                while (ci < closings.Count && closings[ci] <= end) ci++;
                if (!h.Success || ci >= closings.Count) { i = end + 1; continue; }
                int close = closings[ci];
                string href = h.Groups[1].Success ? h.Groups[1].Value : h.Groups[2].Success ? h.Groups[2].Value : h.Groups[3].Value;
                href = WebUtility.HtmlDecode(href).Trim();
                int len = Math.Min(close - (end + 1), MaxText);
                string text = WebUtility.HtmlDecode(TagRe.Replace(html.Substring(end + 1, len), " "));
                text = SpaceRe.Replace(text, " ").Trim();
                if (seen.Add(href + "|" + text)) links.Add(new LinkInfo(href, text));
                i = close + 3;
            }
            return links;
        }

        /// <summary>Le HTML contient-il une balise &lt;form&gt; ?</summary>
        public static bool HasForm(string htmlIn)
        {
            string html = Cap(htmlIn);
            int i = 0;
            while ((i = html.IndexOf("<form", i, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                if (TagStart(html, i + 5)) return true;
                i += 5;
            }
            return false;
        }

        /// <summary>Le HTML contient-il un champ « mot de passe » (&lt;input type=password&gt;) ?</summary>
        public static bool HasPasswordInput(string htmlIn)
        {
            string html = Cap(htmlIn);
            int i = 0, gt = -1;
            while ((i = html.IndexOf("<input", i, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                int after = i + 6;
                if (TagStart(html, after))
                {
                    int end = NextGt(html, after, ref gt);
                    int len = Math.Min(MaxTag, (end < 0 ? html.Length : end) - i);
                    if (PasswordTypeRe.IsMatch(html.Substring(i, len))) return true;
                }
                i = after;
            }
            return false;
        }
    }
}
