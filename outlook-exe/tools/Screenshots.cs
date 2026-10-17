// PhishGuard - génère les captures d'écran du README à partir du vrai moteur et des vraies fenêtres
// (messages d'exemple fictifs). Lancé par .github/workflows/screenshots.yml : les pages HTML sont ensuite
// photographiées par Chrome en mode sans affichage, les fenêtres WinForms par DrawToBitmap.

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.IO;
using System.Text;
using System.Windows.Forms;
using PhishGuard.AddIn;

namespace PhishGuard.Tools
{
    static class Screenshots
    {
        const string FAIL = "Authentication-Results: mx.exemple-pme.fr; spf=fail smtp.mailfrom=micros0ft-support.com; dkim=none; dmarc=fail action=quarantine header.from=micros0ft-support.com;compauth=fail reason=000\r\nReceived: from mail.micros0ft-support.com (185.220.101.47) by mx.exemple-pme.fr";
        const string ALIGNED = "Authentication-Results: mx.exemple-pme.fr; spf=pass smtp.mailfrom=bounce@fournisseur-alpha.fr; dkim=pass (signature was verified) header.d=fournisseur-alpha.fr;dmarc=pass action=none header.from=fournisseur-alpha.fr;compauth=pass reason=100";

        [STAThread]
        static int Main(string[] args)
        {
            string outDir = args.Length > 0 ? args[0] : "shots";
            Directory.CreateDirectory(outDir);
            L.SetLanguage("fr");
            DomainAge.Enabled = false;
            Blocklists.SetForTests(new string[0], new string[0]);
            var cfg = new PhishGuardConfig
            {
                CompanyName = "Exemple SAS",
                CompanyDomains = new List<string> { "exemple-pme.fr" },
                VipNames = new List<string> { "Claire Martin" },
                ReportAddress = "securite@exemple-pme.fr",
                ExpertMode = true
            };

            // 1. Phishing : fausse alerte Microsoft
            var p = new EmailData
            {
                FromName = "Microsoft 365", FromAddress = "no-reply@micros0ft-support.com", Subject = "Action requise : votre boîte mail sera suspendue aujourd'hui",
                BodyText = "Bonjour,\n\nVotre compte sera suspendu dans les 24 heures suite à une activité inhabituelle.\nConnectez-vous immédiatement pour vérifier votre compte et conserver vos messages.\n\nL'équipe Microsoft 365",
                RawHeaders = FAIL
            };
            p.Links.Add(new LinkInfo("https://micros0ft-support.com/owa/login.php?u=claire", "https://login.microsoftonline.com"));
            var rp = Analyzer.Analyze(p, cfg);

            // 2. Suspect : changement de RIB depuis un sosie de fournisseur
            Correspondents.Set(new[] { "compta@fournisseur-alpha.fr" }, false);
            var s = new EmailData
            {
                FromName = "Comptabilité Fournisseur Alpha", FromAddress = "compta@fournisseur-alpba.fr", Subject = "RE: Facture 2026-0412 - nouvelles coordonnées bancaires",
                BodyText = "Bonjour,\n\nSuite à un changement de banque, merci d'utiliser désormais notre nouveau RIB pour le règlement de la facture 2026-0412 :\nFR76 3000 6000 0112 3456 7890 189\n\nMerci de traiter ce paiement rapidement.\nCordialement",
                RawHeaders = ALIGNED.Replace("fournisseur-alpha.fr", "fournisseur-alpba.fr")
            };
            var rs = Analyzer.Analyze(s, cfg);

            // 3. Expéditeur vérifié : correspondant connu, authentifié
            var v = new EmailData
            {
                FromName = "Comptabilité Fournisseur Alpha", FromAddress = "compta@fournisseur-alpha.fr", Subject = "Relevé de compte - octobre",
                BodyText = "Bonjour,\n\nVeuillez trouver ci-joint votre relevé de compte du mois d'octobre.\n\nBien cordialement,\nService comptabilité",
                RawHeaders = ALIGNED
            };
            var rv = Analyzer.Analyze(v, cfg);

            Write(outDir, "simple-dangereux.html", SimpleView.Build(rp, p, true));
            Write(outDir, "simple-suspect.html", SimpleView.Build(rs, s, true));
            Write(outDir, "simple-verifie.html", SimpleView.Build(rv, v, true));
            Write(outDir, "expert-dangereux.html", ResultForm.BuildHtml(rp, p, true));
            Write(outDir, "signalement.html", ReportHtml.Build(rp, p, "Claire Martin"));
            Console.WriteLine("Verdicts : " + rp.Level + " " + rp.Score + " / " + rs.Level + " " + rs.Score + " / " + rv.Level + " verified=" + rv.Verified);

            Func<AnalysisResult, string> label = r => r.Level == "dangerous" ? "Dangereux (" + r.Score + ")" : r.Level == "suspicious" ? "Suspect (" + r.Score + ")"
                : r.Verified ? "Expéditeur vérifié" : "Risque faible (" + r.Score + ")";
            Ribbon(outDir, new[] { rp, rs, rv }, new[] { label(rp), label(rs), label(rv) });

            Application.EnableVisualStyles();
            Capture(new FirstRunForm(new PhishGuardConfig(), "exemple-pme.fr", null, FirstRunForm.Steps), Path.Combine(outDir, "assistant.png"));
            Capture(new SettingsForm(cfg, null, "exemple-pme.fr"), Path.Combine(outDir, "parametres.png"));
            return 0;
        }

        static void Write(string dir, string name, string html)
        {
            File.WriteAllText(Path.Combine(dir, name), html, new UTF8Encoding(true));
        }

        /// <summary>Bandeau imitant le ruban d'Outlook avec les trois états du bouton PhishGuard.</summary>
        static void Ribbon(string dir, AnalysisResult[] results, string[] labels)
        {
            using (var bmp = new Bitmap(720, 120))
            using (var g = Graphics.FromImage(bmp))
            using (var font = new Font("Segoe UI", 10f))
            using (var small = new Font("Segoe UI", 8.5f))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
                g.Clear(Color.FromArgb(243, 242, 241));
                using (var line = new Pen(Color.FromArgb(214, 214, 214))) g.DrawLine(line, 0, 119, 720, 119);
                for (int i = 0; i < results.Length; i++)
                {
                    int x = 30 + i * 230;
                    using (var badge = Connect.ScoreBadge(results[i])) g.DrawImage(badge, x + 84, 18, 40, 40);
                    var rect = new RectangleF(x, 64, 208, 36);
                    using (var fmt = new StringFormat { Alignment = StringAlignment.Center })
                    {
                        g.DrawString(labels[i], font, Brushes.Black, rect, fmt);
                        g.DrawString("PhishGuard", small, Brushes.DimGray, new RectangleF(x, 84, 208, 20), fmt);
                    }
                }
                bmp.Save(Path.Combine(dir, "ruban.png"), ImageFormat.Png);
            }
        }

        static void Capture(Form f, string path)
        {
            f.StartPosition = FormStartPosition.Manual;
            f.Location = new Point(0, 0);
            f.ShowInTaskbar = false;
            f.Show();
            Application.DoEvents();
            using (var bmp = new Bitmap(f.Width, f.Height))
            {
                f.DrawToBitmap(bmp, new Rectangle(0, 0, f.Width, f.Height));
                bmp.Save(path, ImageFormat.Png);
            }
            f.Close();
        }
    }
}
