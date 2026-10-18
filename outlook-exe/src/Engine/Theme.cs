using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace PhishGuard
{
    /// <summary>
    /// Thème clair ou sombre des fenêtres. Le thème sombre est obtenu en convertissant les couleurs du thème clair :
    /// une table pour les couleurs de l'interface, et une règle générale (luminosité inversée, teinte conservée)
    /// pour les autres. Le rapport envoyé à l'équipe sécurité reste toujours en clair.
    /// </summary>
    public static class Theme
    {
        /// <summary>true : les couleurs sont converties pour le thème sombre.</summary>
        public static bool Dark;

        public enum Kind { Back, Text, Border }

        /// <summary>Réglage Theme (auto, light ou dark) combiné au thème de Windows.</summary>
        public static bool Resolve(string setting, bool systemDark)
        {
            string s = (setting ?? "").Trim().ToLowerInvariant();
            if (s == "dark") return true;
            if (s == "light") return false;
            return systemDark;
        }

        // Fonds : page, cartes, encadrés teintés
        static readonly Dictionary<int, int> BackMap = Table(
            0xFFFFFF, 0x2A2D32,   // carte, fenêtre
            0xF3F5F8, 0x1E2024,   // fond de page
            0xF0F0F0, 0x202327,   // fond des fenêtres Windows (Control)
            0xF7F9FB, 0x30343A, 0xFAFBFC, 0x30343A, 0xF5F9FD, 0x2E3946,
            0xEEF1F5, 0x3A3F46, 0xE7EBF0, 0x3A3F46, 0xE6E6E6, 0x3A3F46,
            0xE3EFFA, 0x1F3A55, 0xEEF5FC, 0x1D3247,
            0xE7F5EE, 0x1D3A2B, 0xF6FBF8, 0x233129,
            0xFDECED, 0x43242A, 0xFFF7F7, 0x33262A, 0xFFF8F8, 0x33262A,
            0xFFF3E0, 0x42321B, 0xFFFAF2, 0x332C21, 0xFFFAF3, 0x332C21, 0xFFF4E5, 0x42321B);

        // Textes : du plus foncé au plus discret, puis les couleurs des verdicts
        static readonly Dictionary<int, int> TextMap = Table(
            0x000000, 0xE6E9ED, 0x17202B, 0xE6E9ED, 0x1B1F24, 0xE6E9ED,
            0x2B3542, 0xCFD4DA, 0x4A5563, 0xB4BCC6, 0x5F6B7A, 0x9BA5B1, 0x5D6673, 0x9BA5B1, 0x6D6D6D, 0x9BA5B1,
            0x8A95A3, 0x8792A0,
            0x0F6CBD, 0x6CB4F0, 0x1B3A57, 0xB9D5F0, 0x0066CC, 0x6CB4F0, 0x0000FF, 0x6CB4F0,
            0x13804A, 0x56C98F, 0x106B3D, 0x56C98F, 0x107C41, 0x56C98F, 0x3D6B52, 0x8FCAA8,
            0xC4262E, 0xF2787E, 0xB01F27, 0xF2787E, 0xC41622, 0xF2787E, 0xB4141E, 0xF2787E,
            0xA85B00, 0xF0A64E, 0x9A5200, 0xF0A64E, 0x8C5000, 0xF0A64E, 0xD67800, 0xF0A64E, 0xC46A00, 0xF0A64E,
            0xFFFFFF, 0xFFFFFF);

        // Bordures et séparateurs
        static readonly Dictionary<int, int> BorderMap = Table(
            0xE3E7ED, 0x3A3F46, 0xE9EDF2, 0x3A3F46, 0xEEF1F5, 0x353A41, 0xF0F2F5, 0x353A41, 0xE1E4E8, 0x3A3F46,
            0xD3D9E1, 0x4B525B, 0xDBE2EA, 0x4B525B, 0xC8CFD8, 0x4B525B,
            0xCFE0F1, 0x2F4D6B, 0xE3EFFA, 0x2F4D6B, 0x0F6CBD, 0x4A9EE6, 0x17202B, 0xE6E9ED);

        static Dictionary<int, int> Table(params int[] pairs)
        {
            var d = new Dictionary<int, int>();
            for (int i = 0; i + 1 < pairs.Length; i += 2) d[pairs[i]] = pairs[i + 1];
            return d;
        }

        /// <summary>Couleur (0xRRGGBB) à utiliser pour le thème courant.</summary>
        public static int Map(int rgb, Kind kind)
        {
            if (!Dark) return rgb;
            return ToDark(rgb & 0xFFFFFF, kind);
        }

        /// <summary>Conversion vers le thème sombre, quel que soit le thème courant.</summary>
        public static int ToDark(int rgb, Kind kind)
        {
            int mapped;
            var table = kind == Kind.Back ? BackMap : kind == Kind.Text ? TextMap : BorderMap;
            if (table.TryGetValue(rgb, out mapped)) return mapped;
            double h, s, l;
            ToHsl(rgb, out h, out s, out l);
            switch (kind)
            {
                case Kind.Back:
                    // Fonds clairs : fond sombre de même teinte ; fonds saturés (boutons, pastilles) : inchangés
                    if (l < 0.80) return rgb;
                    return FromHsl(h, Math.Min(s, 0.30), s > 0.15 ? 0.19 : 0.17);
                case Kind.Text:
                    if (l >= 0.55) return rgb;
                    if (s > 0.30) return FromHsl(h, Math.Min(s, 0.75), Math.Max(l, 0.66));
                    return FromHsl(h, s, Math.Max(0.58, Math.Min(0.92, 1 - l * 0.8)));
                default:
                    if (l < 0.72) return rgb;
                    return FromHsl(h, Math.Min(s, 0.25), 0.28);
            }
        }

        static void ToHsl(int rgb, out double h, out double s, out double l)
        {
            double r = ((rgb >> 16) & 255) / 255.0, g = ((rgb >> 8) & 255) / 255.0, b = (rgb & 255) / 255.0;
            double max = Math.Max(r, Math.Max(g, b)), min = Math.Min(r, Math.Min(g, b));
            l = (max + min) / 2;
            h = 0; s = 0;
            if (max == min) return;
            double d = max - min;
            s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
            if (max == r) h = (g - b) / d + (g < b ? 6 : 0);
            else if (max == g) h = (b - r) / d + 2;
            else h = (r - g) / d + 4;
            h /= 6;
        }

        static int FromHsl(double h, double s, double l)
        {
            double r, g, b;
            if (s == 0) r = g = b = l;
            else
            {
                double q = l < 0.5 ? l * (1 + s) : l + s - l * s, p = 2 * l - q;
                r = Hue(p, q, h + 1.0 / 3); g = Hue(p, q, h); b = Hue(p, q, h - 1.0 / 3);
            }
            return (Byte(r) << 16) | (Byte(g) << 8) | Byte(b);
        }

        static double Hue(double p, double q, double t)
        {
            if (t < 0) t += 1;
            if (t > 1) t -= 1;
            if (t < 1.0 / 6) return p + (q - p) * 6 * t;
            if (t < 0.5) return q;
            if (t < 2.0 / 3) return p + (q - p) * (2.0 / 3 - t) * 6;
            return p;
        }

        static int Byte(double v) { return Math.Max(0, Math.Min(255, (int)Math.Round(v * 255))); }

        static readonly Regex HexRe = new Regex(@"#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})(?![0-9a-fA-F])", RegexOptions.Compiled);
        static readonly Regex DeclRe = new Regex(@"(?<=[{;])([a-z-]+):([^;}]*)", RegexOptions.Compiled);

        /// <summary>Couleur CSS (#rgb ou #rrggbb) pour le thème courant.</summary>
        public static string Hex(string css, Kind kind)
        {
            if (!Dark || string.IsNullOrEmpty(css)) return css;
            return HexRe.Replace(css, m => "#" + Map(ParseHex(m.Groups[1].Value), kind).ToString("x6", CultureInfo.InvariantCulture));
        }

        static int ParseHex(string v)
        {
            if (v.Length == 3) v = new string(new[] { v[0], v[0], v[1], v[1], v[2], v[2] });
            return int.Parse(v, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }

        /// <summary>Feuille de style pour le thème courant : chaque couleur est convertie selon la propriété qui l'utilise.</summary>
        public static string Css(string css)
        {
            if (!Dark) return css;
            string converted = DeclRe.Replace(css, m =>
            {
                string prop = m.Groups[1].Value;
                Kind k = prop.StartsWith("background") ? Kind.Back : prop == "color" ? Kind.Text
                    : prop == "fill" ? Kind.Back : prop == "stroke" ? Kind.Border : prop.StartsWith("border") || prop.StartsWith("outline") ? Kind.Border : Kind.Text;
                return prop + ":" + Hex(m.Groups[2].Value, k);
            });
            // Barres de défilement d'Internet Explorer (fenêtre d'analyse)
            return converted + "html{scrollbar-face-color:#4b525b;scrollbar-track-color:#1e2024;scrollbar-arrow-color:#9ba5b1;"
                + "scrollbar-shadow-color:#4b525b;scrollbar-highlight-color:#4b525b;scrollbar-3dlight-color:#1e2024;scrollbar-darkshadow-color:#1e2024;"
                + "scrollbar-base-color:#1e2024;color-scheme:dark}";
        }
    }
}
