// PhishGuard - onglet « À propos » des paramètres :
// version, liens vers le projet, ce qui sort du poste, sources et licences, informations pour le support.
// Aucune donnée personnelle : ni nom, ni adresse, ni chemin contenant le nom d'utilisateur.

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

namespace PhishGuard.AddIn
{
    internal static partial class BuildInfo
    {
        public const string Issues = Repository + "/issues";
        public static string OutlookVersion = "";   // renseignée au chargement du complément
    }

    internal static class AboutPage
    {
        static readonly Font UiFont = new Font("Segoe UI", 9f);
        const int Width = 500;

        public static void Fill(Control page, PhishGuardConfig cfg)
        {
            int y = 12;
            page.Controls.Add(new Label { Text = "PhishGuard pour Outlook", Location = new Point(12, y), AutoSize = true, Font = new Font("Segoe UI", 13f, FontStyle.Bold) });
            y += 32;
            page.Controls.Add(new Label { Text = L.T("Version : ") + BuildInfo.Version, Location = new Point(12, y), AutoSize = true });
            y += 26;
            y += 4;
            y = Link(page, y, L.T("Code source, documentation et questions fréquentes"), BuildInfo.Repository);
            y = Link(page, y, L.T("Nouveautés et dernière version"), BuildInfo.Releases);
            y = Link(page, y, L.T("Signaler un problème"), BuildInfo.Issues);
            y = Text(page, y - 4, L.T("Attention : cette page est publique. N’y collez jamais un email, une adresse ou une capture contenant des informations personnelles ou de votre entreprise."), Color.FromArgb(160, 90, 0), false);
            y += 10;

            y = Title(page, y, L.T("Ce qui sort de votre poste"));
            y = Bullet(page, y, L.T("Le contenu de vos messages : jamais. L’analyse se fait entièrement sur votre poste."));
            y = Bullet(page, y, L.T("Listes téléchargées (Red Flag Domains, secteur public, OpenPhish, Tranco) : comparées sur votre poste, rien n’est envoyé."));
            y = Bullet(page, y, L.T("Sources activées dans l’onglet Réputation : seulement des noms de domaine, des adresses de liens, des empreintes de fichiers ou une adresse IP."));
            y += 8;

            y = Title(page, y, L.T("Sources et licences"));
            y = Bullet(page, y, L.T("PhishGuard : logiciel libre et gratuit, licence GNU GPL v3."));
            y = Bullet(page, y, L.T("Red Flag Domains : licence CC BY-NC-SA 4.0 (usage non commercial)."));
            y = Bullet(page, y, L.T("Domaines du secteur public : DINUM, Licence Ouverte 2.0."));
            y = Bullet(page, y, L.T("Dirigeants : Annuaire des Entreprises (INSEE, RNE, Licence Ouverte) et Wikidata (CC0)."));
            y = Bullet(page, y, L.T("Lecture des QR codes : ZXing.Net, licence Apache 2.0."));
            y = Bullet(page, y, L.T("OpenPhish, Tranco, crt.sh, VirusTotal, abuse.ch, AbuseIPDB : selon leurs propres conditions d’utilisation."));
            y += 10;

            var btn = new Button { Text = L.T("Copier les informations pour le support"), Location = new Point(12, y), AutoSize = true };
            var done = new Label { Location = new Point(12, y + 34), AutoSize = true, ForeColor = SystemColors.GrayText };
            btn.Click += (s, e) =>
            {
                try { Clipboard.SetText(SupportText(cfg)); done.Text = L.T("Copié. Collez-le dans votre message au support : il ne contient aucune donnée personnelle."); }
                catch (Exception) { done.Text = L.T("Impossible d’accéder au presse-papiers."); }
            };
            page.Controls.Add(btn);
            page.Controls.Add(done);
        }

        /// <summary>Résumé technique pour le support : versions, réglages et état des listes, sans donnée personnelle.</summary>
        public static string SupportText(PhishGuardConfig cfg)
        {
            Func<bool, string> yn = b => b ? L.T("oui") : L.T("non");
            var sb = new StringBuilder();
            sb.AppendLine("PhishGuard pour Outlook " + BuildInfo.Version);
            sb.AppendLine("Outlook " + (BuildInfo.OutlookVersion.Length > 0 ? BuildInfo.OutlookVersion : "?") + ", " + (IntPtr.Size * 8) + " bits");
            sb.AppendLine("Windows " + Environment.OSVersion.Version + ", .NET " + Environment.Version);
            sb.AppendLine(L.T("Langue : ") + (L.English ? "en" : "fr") + " ; " + L.T("mode : ") + (cfg.ExpertMode ? "expert" : L.T("simple")));
            sb.AppendLine("Red Flag Domains : " + (cfg.RedFlagEnabled ? Blocklists.RedFlagCount.ToString("N0") + " (" + Blocklists.RedFlagUpdated.ToString("yyyy-MM-dd") + ")" : L.T("désactivée")));
            sb.AppendLine(L.T("Secteur public : ") + (cfg.PublicSectorList ? Feeds.PublicSectorCount.ToString("N0") + " (" + Feeds.PublicSectorUpdated.ToString("yyyy-MM-dd") + ")" : L.T("désactivée")));
            sb.AppendLine("OpenPhish : " + (cfg.BetaOpenPhish ? Feeds.OpenPhishCount.ToString("N0") : L.T("désactivé")) + " ; Tranco : " + (cfg.BetaTranco ? Feeds.TrancoCount.ToString("N0") : L.T("désactivé")));
            sb.AppendLine("DNS : " + yn(cfg.BetaDnsChecks) + " ; crt.sh : " + yn(cfg.BetaCertAge) + " ; " + L.T("clés VirusTotal / abuse.ch / AbuseIPDB renseignées : ")
                + yn(!string.IsNullOrEmpty(cfg.VirusTotalKey)) + " / " + yn(!string.IsNullOrEmpty(cfg.AbuseChKey)) + " / " + yn(!string.IsNullOrEmpty(cfg.AbuseIpdbKey)));
            sb.AppendLine(L.T("Analyse automatique : ") + yn(cfg.AutoAnalyze) + " ; " + L.T("correspondants connus : ") + yn(cfg.KnownCorrespondents) + " ; " + L.T("âge des domaines : ") + yn(cfg.DomainAgeLookup));
            foreach (var err in new[] { Blocklists.LastError, Feeds.LastError, Intel.LastError })
                if (!string.IsNullOrEmpty(err)) sb.AppendLine(L.T("Dernière erreur : ") + err);
            return sb.ToString();
        }

        static int TextHeight(string text, int width, Font f)
        {
            return TextRenderer.MeasureText(text ?? "", f, new Size(width, 0), TextFormatFlags.WordBreak).Height;
        }

        static int Text(Control page, int y, string text, Color color, bool bold)
        {
            var f = bold ? new Font(UiFont, FontStyle.Bold) : UiFont;
            page.Controls.Add(new Label { Text = text, Location = new Point(12, y), AutoSize = true, ForeColor = color, Font = f, MaximumSize = new Size(Width, 0) });
            return y + TextHeight(text, Width, f) + 6;
        }

        static int Title(Control page, int y, string text)
        {
            page.Controls.Add(new Label { Text = text, Location = new Point(12, y), AutoSize = true, Font = new Font(UiFont, FontStyle.Bold) });
            return y + 24;
        }

        static int Bullet(Control page, int y, string text)
        {
            page.Controls.Add(new Label { Text = "•", Location = new Point(14, y), AutoSize = true, Font = UiFont });
            page.Controls.Add(new Label { Text = text, Location = new Point(28, y), AutoSize = true, Font = UiFont, MaximumSize = new Size(Width - 16, 0) });
            return y + TextHeight(text, Width - 16, UiFont) + 4;
        }

        static int Link(Control page, int y, string text, string url)
        {
            var link = new LinkLabel { Text = text, Location = new Point(12, y), AutoSize = true, Font = UiFont };
            link.LinkClicked += (s, e) => { try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true }); } catch (Exception) { } };
            page.Controls.Add(link);
            page.Controls.Add(new Label { Text = url, Location = new Point(28, y + 19), AutoSize = true, ForeColor = SystemColors.GrayText, Font = UiFont });
            return y + 44;
        }
    }
}
