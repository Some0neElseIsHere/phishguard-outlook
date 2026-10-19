// PhishGuard - rapport de signalement envoyé à l'équipe sécurité (bouton « Signaler à la sécurité »).
// HTML compatible Outlook (moteur Word) : tableaux et styles en ligne uniquement, aucune image ni script,
// aucun lien cliquable vers le message suspect (adresses désarmées : hxxps://exemple[.]com).

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace PhishGuard
{
    public static class ReportHtml
    {
        const string Font = "font-family:Segoe UI,Arial,sans-serif;";
        const string Mono = "font-family:Consolas,Courier New,monospace;font-size:12px;";

        static string H(string s) { return WebUtility.HtmlEncode(s ?? ""); }

        static string SevColor(Severity s)
        {
            switch (s)
            {
                case Severity.Critical: return "#a1141c";
                case Severity.High: return "#d13438";
                case Severity.Medium: return "#c26a00";
                case Severity.Low: return "#6b7685";
            }
            return "#8a95a3";
        }

        static string LevelColor(string level)
        {
            return level == "dangerous" ? "#c4262e" : level == "suspicious" ? "#c26a00" : "#13804a";
        }

        static string Section(string title)
        {
            return "<tr><td style='padding:18px 0 6px 0;" + Font + "font-size:12px;font-weight:bold;letter-spacing:1px;text-transform:uppercase;color:#5f6b7a'>" + H(title) + "</td></tr>";
        }

        static string Row(string k, string v)
        {
            return "<tr><td style='padding:5px 10px;" + Font + "font-size:12px;color:#5f6b7a;white-space:nowrap;vertical-align:top;width:150px;border-top:1px solid #eef1f5'>" + H(k)
                + "</td><td style='padding:5px 10px;" + Font + "font-size:13px;color:#17202b;vertical-align:top;border-top:1px solid #eef1f5'>" + v + "</td></tr>";
        }

        static string Box(string inner)
        {
            return "<tr><td><table width='100%' cellpadding='0' cellspacing='0' style='border:1px solid #e3e7ed;background:#ffffff'>" + inner + "</table></td></tr>";
        }

        static string Chip(string label, string value)
        {
            string v = (value ?? "").ToLowerInvariant();
            string bg = v == "pass" ? "#e7f5ee" : v == "fail" || v == "softfail" || v == "permerror" ? "#fdeced" : "#eef1f5";
            string fg = v == "pass" ? "#13804a" : v == "fail" || v == "softfail" || v == "permerror" ? "#c4262e" : "#5f6b7a";
            return "<span style='background:" + bg + ";color:" + fg + ";" + Font + "font-size:12px;font-weight:bold;padding:2px 8px'>"
                + H(label) + "&nbsp;" + H(string.IsNullOrEmpty(value) ? L.T("absent") : value) + "</span>&nbsp;&nbsp; ";
        }

        /// <summary>Désarme toutes les adresses web d'un texte (copie du message d'origine).</summary>
        public static string DefangText(string text)
        {
            string t = Regex.Replace(text ?? "", @"\b(?:https?|ftp)://[^\s<>""']+", m => Analyzer.Defang(m.Value), RegexOptions.IgnoreCase);
            return Regex.Replace(t, @"\bwww\.", "www[.]", RegexOptions.IgnoreCase);
        }

        public static string Build(AnalysisResult r, EmailData e, string reporter)
        {
            var d = r.Details ?? new HeaderDetails();
            var doubts = r.Findings.Where(f => f.Severity >= Severity.Low).ToList();
            var sb = new StringBuilder();
            sb.Append("<html><head><meta http-equiv='Content-Type' content='text/html; charset=utf-8'></head>");
            sb.Append("<body style='margin:0;padding:0;background:#f3f5f8'>");
            sb.Append("<table width='100%' cellpadding='0' cellspacing='0' style='background:#f3f5f8'><tr><td align='center' style='padding:16px'>");
            sb.Append("<table width='700' cellpadding='0' cellspacing='0' style='max-width:700px'>");

            // ---- Bandeau ----
            string col = LevelColor(r.Level);
            sb.Append("<tr><td style='background:" + col + ";padding:16px 20px'>");
            sb.Append("<div style='" + Font + "font-size:12px;color:#ffffff;letter-spacing:1px;text-transform:uppercase'>" + H(L.T("Signalement PhishGuard")) + "</div>");
            sb.Append("<div style='" + Font + "font-size:22px;font-weight:bold;color:#ffffff;margin-top:4px'>" + H(r.LevelLabel) + " &middot; " + H(L.F("score {0}/100", r.Score)) + "</div>");
            sb.Append("<div style='" + Font + "font-size:13px;color:#ffffff;margin-top:6px'>"
                + H(L.F("Signalé par {0} le {1}", string.IsNullOrEmpty(reporter) ? L.T("un utilisateur") : reporter, DateTime.Now.ToString("dd/MM/yyyy HH:mm"))) + "</div>");
            sb.Append("</td></tr>");

            // ---- En bref ----
            sb.Append("<tr><td style='background:#ffffff;padding:14px 20px;border:1px solid #e3e7ed;border-top:0'>");
            sb.Append("<div style='" + Font + "font-size:14px;font-weight:bold;color:#17202b'>" + H(L.T("En bref")) + "</div>");
            if (doubts.Count == 0)
                sb.Append("<div style='" + Font + "font-size:13px;color:#2b3542;margin-top:4px'>" + H(L.T("PhishGuard n’a relevé aucun indice : l’utilisateur a signalé ce message de lui-même. À examiner manuellement.")) + "</div>");
            else
            {
                sb.Append("<ul style='margin:6px 0 0 18px;padding:0'>");
                foreach (var f in doubts.Take(5))
                    sb.Append("<li style='" + Font + "font-size:13px;color:#2b3542;margin:2px 0'><b style='color:" + SevColor(f.Severity) + "'>" + H(Analyzer.SeverityLabel(f.Severity)) + "</b> &middot; " + H(f.Title) + "</li>");
                sb.Append("</ul>");
                var counts = new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low }.Select(s => new { s, n = doubts.Count(f => f.Severity == s) }).Where(x => x.n > 0)
                    .Select(x => x.n + " " + Analyzer.SeverityLabel(x.s).ToLowerInvariant()).ToArray();
                sb.Append("<div style='" + Font + "font-size:12px;color:#5f6b7a;margin-top:6px'>" + H(L.F("{0} indice(s) au total : {1}.", doubts.Count, string.Join(", ", counts))) + "</div>");
            }
            sb.Append("</td></tr>");

            // ---- Message ----
            sb.Append(Section(L.T("Message signalé")));
            var msg = new StringBuilder();
            msg.Append(Row(L.T("De"), "<b>" + H(e.FromName) + "</b> <span style='" + Mono + "'>&lt;" + H(e.FromAddress) + "&gt;</span>"));
            if (!string.IsNullOrEmpty(e.SenderAddress) && !string.Equals(e.SenderAddress, e.FromAddress, StringComparison.OrdinalIgnoreCase))
                msg.Append(Row(L.T("Envoyé par"), "<span style='" + Mono + "'>" + H(e.SenderAddress) + "</span>"));
            if (e.ReplyTo.Count > 0) msg.Append(Row(L.T("Répondre à"), "<span style='" + Mono + "'>" + H(string.Join(", ", e.ReplyTo.ToArray())) + "</span>"));
            msg.Append(Row(L.T("Objet"), H(e.Subject)));
            foreach (var kv in d.Fields.Where(x => x.Key == L.T("À") || x.Key == L.T("Date") || x.Key == "Return-Path" || x.Key == "Message-ID" || x.Key == L.T("En réponse à") || x.Key == L.T("Logiciel d’envoi (X-Mailer)")))
                msg.Append(Row(kv.Key, "<span style='" + Mono + "'>" + H(kv.Value) + "</span>"));
            sb.Append(Box(msg.ToString()));

            // ---- Points de doute ----
            if (doubts.Count > 0)
            {
                sb.Append(Section(L.F("Points de doute ({0})", doubts.Count)));
                foreach (var f in doubts)
                {
                    sb.Append("<tr><td style='padding:0 0 6px 0'><table width='100%' cellpadding='0' cellspacing='0' style='background:#ffffff;border:1px solid #e3e7ed;border-left:4px solid " + SevColor(f.Severity) + "'><tr><td style='padding:8px 12px'>");
                    sb.Append("<span style='background:" + SevColor(f.Severity) + ";color:#ffffff;" + Font + "font-size:10px;font-weight:bold;padding:2px 7px;text-transform:uppercase'>" + H(Analyzer.SeverityLabel(f.Severity)) + "</span> ");
                    sb.Append("<span style='" + Font + "font-size:11px;color:#8a95a3'>" + H(Analyzer.CategoryLabel(f.Category)) + "</span>");
                    sb.Append("<div style='" + Font + "font-size:14px;font-weight:bold;color:#17202b;margin-top:4px'>" + H(f.Title) + "</div>");
                    if (f.Detail.Length > 0) sb.Append("<div style='" + Font + "font-size:12.5px;color:#4a5563;margin-top:2px'>" + H(f.Detail) + "</div>");
                    if (f.Evidence.Count > 0)
                    {
                        sb.Append("<div style='margin-top:4px'>");
                        foreach (var ev in f.Evidence.Take(6))
                            sb.Append("<span style='" + Mono + "background:#f3f5f8;border:1px solid #e9edf2;padding:1px 6px;margin-right:4px;color:#2b3542'>" + H(DefangText(ev)) + "</span> ");
                        sb.Append("</div>");
                    }
                    sb.Append("</td></tr></table></td></tr>");
                }
            }

            // ---- Authentification et origine ----
            sb.Append(Section(L.T("Authentification et origine")));
            var au = new StringBuilder();
            var a = d.Auth;
            if (d.All.Count == 0) au.Append(Row(L.T("En-têtes"), H(L.T("Indisponibles (message interne ou envoyé depuis cette boîte)."))));
            else
            {
                au.Append(Row(L.T("Résultats"), Chip("SPF", a.Spf) + Chip("DKIM", a.Dkim) + Chip("DMARC", a.DmarcShown) + (string.IsNullOrEmpty(a.CompAuth) ? "" : Chip("compauth", a.CompAuth + (string.IsNullOrEmpty(a.CompAuthReason) ? "" : " " + a.CompAuthReason)))));
                if (!string.IsNullOrEmpty(a.SpfMailFrom)) au.Append(Row(L.T("Enveloppe (SPF)"), "<span style='" + Mono + "'>" + H(a.SpfMailFrom) + "</span>"));
                if (!string.IsNullOrEmpty(a.DkimDomain)) au.Append(Row(L.T("Signature (DKIM)"), "<span style='" + Mono + "'>d=" + H(a.DkimDomain) + (string.IsNullOrEmpty(a.DkimSelector) ? "" : " s=" + H(a.DkimSelector)) + "</span>"));
                if (a.DmarcNote.Length > 0) au.Append(Row("DMARC", H(a.DmarcNote)));
                if (!string.IsNullOrEmpty(a.DmarcFrom)) au.Append(Row("DMARC header.from", "<span style='" + Mono + "'>" + H(a.DmarcFrom) + "</span>"));
                if (d.OriginIp.Length > 0) au.Append(Row(L.T("IP d’origine"), "<span style='" + Mono + "'>" + H(d.OriginIp) + "</span>" + (d.Country.Length > 0 ? " (" + H(d.Country) + ")" : "") + (d.OriginHost.Length > 0 && d.OriginHost != d.OriginIp ? " &middot; " + H(d.OriginHost) : "")));
                if (d.Hops.Count > 0) au.Append(Row(L.T("Parcours"), H(L.F("{0} serveur(s) : ", d.Hops.Count)) + "<span style='" + Mono + "'>" + H(string.Join(" → ", d.Hops.Select(h => h.FromHost.Length > 0 ? h.FromHost : h.ByHost).Where(x => x.Length > 0).Take(8).ToArray())) + "</span>"));
                if (d.Scl.Length > 0) au.Append(Row(L.T("Filtre Exchange"), H("SCL " + d.Scl + (d.Bcl.Length > 0 ? " · BCL " + d.Bcl : ""))));
            }
            sb.Append(Box(au.ToString()));

            // ---- Liens ----
            if (e.Links.Count > 0 || r.Urls.Count > 0)
            {
                sb.Append(Section(L.F("Liens ({0}, désarmés)", r.Urls.Count)));
                var lk = new StringBuilder();
                var shown = new HashSet<string>();
                foreach (var l in e.Links.Where(x => x.Href.StartsWith("http", StringComparison.OrdinalIgnoreCase)).Take(25))
                {
                    if (!shown.Add(l.Href)) continue;
                    string text = (l.Text ?? "").Trim();
                    string host = "";
                    Uri u; if (Uri.TryCreate(l.Href, UriKind.Absolute, out u)) host = Domains.HostOf(u);
                    lk.Append(Row(host.Length > 0 ? host : L.T("lien"), (text.Length > 0 && text != l.Href ? "<div style='" + Font + "font-size:12px;color:#5f6b7a'>" + H(L.T("Texte affiché : ") + DefangText(text.Length > 90 ? text.Substring(0, 90) + "…" : text)) + "</div>" : "")
                        + "<span style='" + Mono + "word-break:break-all'>" + H(Analyzer.Defang(l.Href.Length > 300 ? l.Href.Substring(0, 300) + "…" : l.Href)) + "</span>"));
                }
                foreach (var url in r.Urls.Where(x => !shown.Contains(x)).Take(15))
                    lk.Append(Row(L.T("destination réelle"), "<span style='" + Mono + "word-break:break-all'>" + H(Analyzer.Defang(url)) + "</span>"));
                sb.Append(Box(lk.ToString()));
            }

            // ---- Pièces jointes ----
            if (r.Attachments.Count > 0)
            {
                sb.Append(Section(L.F("Pièces jointes ({0})", r.Attachments.Count)));
                var at = new StringBuilder();
                foreach (var x in r.Attachments)
                {
                    string info = (x.Size >= 0 ? H(L.F("{0} octets", x.Size.ToString("N0"))) : "") + (x.Magic.Length > 0 ? " &middot; " + H(L.T("type réel : ") + Forensics.MagicLabel(x.Magic)) : "");
                    if (x.Sha256.Length > 0) info += "<div style='" + Mono + "word-break:break-all;color:#4a5563'>SHA256 " + H(x.Sha256) + "<br>MD5 " + H(x.Md5) + "</div>";
                    at.Append(Row(x.Name, info));
                }
                sb.Append(Box(at.ToString()));
            }

            // ---- Observables ----
            var iocs = new List<string>();
            if (!string.IsNullOrEmpty(e.FromAddress)) iocs.Add(e.FromAddress.Replace(".", "[.]"));
            foreach (var dom in new[] { r.SenderDomain }.Concat(r.LinkDomains).Where(x => !string.IsNullOrEmpty(x)).Distinct().Take(20)) iocs.Add(dom.Replace(".", "[.]"));
            if (d.OriginIp.Length > 0) iocs.Add(d.OriginIp.Replace(".", "[.]"));
            foreach (var x in r.Attachments.Where(x => x.Sha256.Length > 0)) iocs.Add(x.Sha256);
            if (iocs.Count > 0)
            {
                sb.Append(Section(L.T("Observables (à copier dans vos outils)")));
                sb.Append("<tr><td style='background:#ffffff;border:1px solid #e3e7ed;padding:10px 12px;" + Mono + "color:#2b3542;line-height:18px'>" + string.Join("<br>", iocs.Distinct().Select(H).ToArray()) + "</td></tr>");
            }

            // ---- Preuves de légitimité ----
            if (r.Trust.Count > 0)
            {
                sb.Append(Section(L.T("Preuves de légitimité relevées")));
                var tr = new StringBuilder();
                foreach (var t in r.Trust) tr.Append(Row("✓", H(t)));
                sb.Append(Box(tr.ToString()));
                if (doubts.Count > 0)
                    sb.Append("<tr><td style='" + Font + "font-size:12px;color:#5f6b7a;padding:4px 2px'>" + H(L.T("Elles ne compensent pas les indices : un compte piraté passe aussi ces contrôles.")) + "</td></tr>");
            }

            // ---- Copie du message d'origine ----
            string body = (e.BodyText ?? "").Trim();
            if (body.Length > 0)
            {
                sb.Append(Section(L.T("Copie du message d’origine (texte, liens désarmés)")));
                if (body.Length > 6000) body = body.Substring(0, 6000) + "\n[…]";
                sb.Append("<tr><td style='background:#ffffff;border:1px solid #e3e7ed;border-left:4px solid #8a95a3;padding:10px 12px;" + Font + "font-size:13px;color:#2b3542'>"
                    + H(DefangText(Regex.Replace(body, @"\n{3,}", "\n\n"))).Replace("\n", "<br>") + "</td></tr>");
            }

            // ---- Pied ----
            sb.Append("<tr><td style='padding:14px 2px;" + Font + "font-size:12px;color:#5f6b7a'>"
                + H(L.T("Le message d’origine est joint à ce signalement (fichier .msg avec tous ses en-têtes) : ouvrez-le avec prudence, sans cliquer sur ses liens.")) + "<br>"
                + H(L.T("Rapport généré automatiquement par PhishGuard pour Outlook.")) + "</td></tr>");
            sb.Append("</table></td></tr></table></body></html>");
            return sb.ToString();
        }
    }
}
