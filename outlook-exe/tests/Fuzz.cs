// PhishGuard - tests de robustesse : des milliers de messages malformés générés au hasard (graine fixe, donc
// reproductibles) passent par toutes les étapes de l'analyse. Aucune ne doit lever d'exception ni durer plus de 2 s :
// un message piégé ne doit jamais faire planter ni figer Outlook.
// Nombre de messages : variable d'environnement PG_FUZZ (400 par défaut ; le banc mensuel en lance davantage).

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace PhishGuard.Tests
{
    static class Fuzz
    {
        static readonly string[] HeaderNames = { "From", "To", "Cc", "Subject", "Reply-To", "Return-Path", "Received", "Authentication-Results",
            "ARC-Authentication-Results", "DKIM-Signature", "Received-SPF", "List-Id", "List-Post", "List-Unsubscribe", "Message-ID", "In-Reply-To",
            "References", "X-MS-Exchange-Organization-AuthAs", "X-Forefront-Antispam-Report", "X-Microsoft-Antispam", "X-Spam-Status", "Date",
            "Content-Type", "Auto-Submitted", "X-FEAS-DKIM", "Delivered-To" };

        static readonly string[] Fragments = { "spf=pass", "spf=fail", "dkim=pass", "dkim=fail", "dmarc=pass", "dmarc=fail action=quarantine", "compauth=pass reason=100",
            "header.d=", "header.i=@", "header.from=", "smtp.mailfrom=", "@", "@@", ";", ";;;", "(", "((((", ")", "<", "<<<<", ">", "\"", "'", "=?utf-8?B?",
            "=?utf-8?Q?=C3=A9?=", "?=", "\t", "\r\n", "\r\n\t", "\u202e", "\u200b", "\u0000", "é", "𝐏𝐫𝐨", "👋", "xn--", "xn--80ak6aa92e.com",
            "exemple-pme.fr", "acmetech.fr", "micros0ft.com", "paypal.fr", "gmail.com", "192.0.2.1", "[203.0.113.7]", "::1", "10.0.0.0/8", "fe80::/10",
            "CIP:203.0.113.9;", "SCL:5;", "by", "from", "with", "id", "for", "Mon, 19 Oct 2026 10:00:00 +0200", "99:99:99", "-0000",
            "bonjour", "virement", "urgent", "mot de passe", "identifiant", "confidentiel", "facture", "colis", "IBAN FR76 3000 6000 0112 3456 7890 189",
            "code 123456", "votre conseiller va vous appeler", "code reçu par SMS", "cryptogramme", "http://", "https://", "hxxp://", "javascript:alert(1)",
            "file:///C:/", "\\\\serveur\\partage", "www.", ".exe", ".pdf.exe", "%", "%%%", "%00", "&amp;", "&#x202e;", "&#99999999;" };

        static readonly string[] Html = { "<a href=", "<a href='", "<a href=\"", "<A HREF=", "\">", "'>", ">", "</a>", "</A >", "<a ", "<form>", "<input type=password>",
            "<input ", "<img src=x>", "<!--", "-->", "<script>", "</script>", "<style>", "<b>", "</b>", "&lt;", "<<<<", ">>>>", "<a\thref=x>", "</a\t>" };

        static readonly byte[][] Magics = { Encoding.ASCII.GetBytes("PK\u0003\u0004"), Encoding.ASCII.GetBytes("PK\u0001\u0002"), Encoding.ASCII.GetBytes("%PDF-1.4"),
            Encoding.ASCII.GetBytes("MZ"), Encoding.ASCII.GetBytes("<html>"), Encoding.ASCII.GetBytes("\u0089PNG\r\n\u001a\n"), Encoding.ASCII.GetBytes("GIF89a"),
            new byte[] { 0xFF, 0xD8, 0xFF }, new byte[] { 0xD0, 0xCF, 0x11, 0xE0 }, Encoding.ASCII.GetBytes("{\\rtf1"), Encoding.ASCII.GetBytes("/JavaScript /URI (") };

        static string Pick(Random r, string[] a) { return a[r.Next(a.Length)]; }

        static string Junk(Random r, int parts)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < parts; i++)
            {
                int k = r.Next(10);
                if (k < 6) sb.Append(Pick(r, Fragments));
                else if (k < 8) sb.Append((char)r.Next(1, 0xD7FF));
                else if (k < 9) sb.Append(new string(Pick(r, Fragments)[0], r.Next(1, 3000)));   // longues répétitions
                else sb.Append(' ');
            }
            return sb.ToString();
        }

        static string Headers(Random r)
        {
            var sb = new StringBuilder();
            int n = r.Next(0, 25);
            for (int i = 0; i < n; i++)
            {
                sb.Append(r.Next(15) == 0 ? Junk(r, 2) : Pick(r, HeaderNames)).Append(r.Next(20) == 0 ? "" : ": ").Append(Junk(r, r.Next(1, 12)));
                sb.Append(r.Next(10) == 0 ? "\n" : "\r\n");
            }
            return sb.ToString();
        }

        static EmailData Message(Random r)
        {
            var e = new EmailData
            {
                FromName = Junk(r, r.Next(0, 4)),
                FromAddress = r.Next(4) == 0 ? Junk(r, 2) : "x" + r.Next(1000) + "@" + Pick(r, new[] { "exemple-pme.fr", "acmetech.fr", "gmail.com", "micros0ft.com", "xn--80ak6aa92e.com", "", "a", ".." }),
                Subject = Junk(r, r.Next(0, 8)),
                BodyText = Junk(r, r.Next(0, 60)),
                RawHeaders = Headers(r),
                IsExchangeInternal = r.Next(10) == 0
            };
            int links = r.Next(0, 8);
            for (int i = 0; i < links; i++)
                e.Links.Add(new LinkInfo(Pick(r, new[] { "http://", "https://", "hxxp://", "", "javascript:", "mailto:", "file:///" }) + Junk(r, r.Next(1, 5)), Junk(r, r.Next(0, 4))));
            int atts = r.Next(0, 3);
            for (int i = 0; i < atts; i++)
            {
                var a = new AttachmentInfo { Name = Junk(r, 2) + Pick(r, new[] { ".pdf", ".zip", ".exe", ".html", ".docm", ".pdf.exe", ".img", "", ".png" }), ContentType = Junk(r, 1), Size = r.Next(-1, 100000) };
                byte[] data = Bytes(r);
                Forensics.ComputeHashes(a, data);
                Forensics.InspectContent(a, data);
                e.Attachments.Add(a);
            }
            e.ReplyTo.Add(Junk(r, 1));
            return e;
        }

        static byte[] Bytes(Random r)
        {
            var b = new List<byte>(Magics[r.Next(Magics.Length)]);
            int n = r.Next(0, 6000);
            for (int i = 0; i < n; i++) b.Add(r.Next(4) == 0 ? Encoding.ASCII.GetBytes(Pick(r, Fragments))[0] : (byte)r.Next(256));
            if (r.Next(3) == 0) b.AddRange(Encoding.UTF8.GetBytes(Junk(r, 20)));
            return b.ToArray();
        }

        static string HtmlJunk(Random r)
        {
            var sb = new StringBuilder();
            int n = r.Next(0, 400);
            for (int i = 0; i < n; i++) sb.Append(r.Next(3) == 0 ? Junk(r, 1) : Pick(r, Html));
            return sb.ToString();
        }

        /// <summary>Lance n messages aléatoires. Renvoie (exceptions, messages trop lents, temps le plus long en ms, description).</summary>
        public static void Run(int n, PhishGuardConfig cfg, Action<string, bool, string> check)
        {
            var r = new Random(20261020);
            int errors = 0, slow = 0; long worst = 0; string firstError = null, worstWhat = "";
            var sw = new Stopwatch();
            for (int i = 0; i < n; i++)
            {
                sw.Restart();
                string step = "génération";
                try
                {
                    var e = Message(r);
                    step = "analyse"; var res = Analyzer.Analyze(e, cfg);
                    if (res.Error != null) throw new Exception("analyse interrompue : " + res.Error);
                    step = "en-têtes"; Forensics.ParseHeaders(e.RawHeaders);
                    step = "liens HTML"; string h = HtmlJunk(r); HtmlScan.Links(h); HtmlScan.HasForm(h); HtmlScan.HasPasswordInput(h);
                    step = "mode simple"; SimpleView.Build(res, e, true);
                    step = "rapport"; ReportHtml.Build(res, e, Junk(r, 1));
                    step = "défang"; Analyzer.Defang(Junk(r, 3)); ReportHtml.DefangText(Junk(r, 5));
                }
                catch (Exception ex)
                {
                    errors++;
                    if (firstError == null) firstError = "message " + i + ", " + step + " : " + ex.GetType().Name + " " + ex.Message;
                }
                long ms = sw.ElapsedMilliseconds;
                if (ms > 2000) slow++;
                if (ms > worst) { worst = ms; worstWhat = "message " + i; }
            }
            check("robustesse : " + n + " messages malformés sans exception", errors == 0, firstError);
            check("robustesse : aucun message malformé ne dépasse 2 s", slow == 0, "le plus lent : " + worst + " ms (" + worstWhat + ")");
        }
    }
}
