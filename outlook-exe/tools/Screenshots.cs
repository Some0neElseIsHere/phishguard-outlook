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
using System.Linq;
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
                Companies = new List<CompanyEntry> {
                    new CompanyEntry { Name = "Exemple SAS", Country = "FR", Id = "552100554", Directors = new List<string> { "Claire Martin", "Hugo Bernard" } },
                    new CompanyEntry { Name = "Exemple Iberia SL", Country = "Espagne", Directors = new List<string> { "Lucía Gómez" } } },
                ReportAddress = "securite@exemple-pme.fr",
                ExpertMode = true
            };

            cfg.NormalizeCompanies();

            // 1. Phishing : fausse alerte Microsoft
            var p = new EmailData
            {
                FromName = "Microsoft 365", FromAddress = "no-reply@micros0ft-support.com", Subject = "Action requise : votre boîte mail sera suspendue aujourd'hui",
                BodyText = "Bonjour,\n\nVotre compte sera suspendu dans les 24 heures suite à une activité inhabituelle.\nConnectez-vous immédiatement pour vérifier votre compte et conserver vos messages.\n\nL'équipe Microsoft 365",
                RawHeaders = FAIL
            };
            p.Links.Add(new LinkInfo("https://micros0ft-support.com/owa/login.php?u=claire", "https://login.microsoftonline.com"));
            var rp = Analyzer.Analyze(p, cfg);

            // 2. Suspect : premier message d'un inconnu, lien raccourci
            Correspondents.Set(new[] { "compta@fournisseur-alpha.fr" }, false);
            var s = new EmailData
            {
                FromName = "Service Livraison", FromAddress = "suivi@colis-livraison-express.fr", Subject = "Votre colis est en attente de livraison",
                BodyText = "Bonjour,\n\nVotre colis n'a pas pu être livré. Choisissez un nouveau créneau de livraison en suivant le lien ci-dessous.\n\nService client",
                RawHeaders = ALIGNED.Replace("fournisseur-alpha.fr", "colis-livraison-express.fr")
            };
            s.Links.Add(new LinkInfo("https://bit.ly/3xYzAbC", "Choisir un créneau"));
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
            var fAff = new SettingsForm(cfg, null, "exemple-pme.fr");
            foreach (var tc in fAff.Controls.OfType<TabControl>()) tc.SelectedIndex = 2;   // onglet Affichage
            Capture(fAff, Path.Combine(outDir, "parametres-affichage.png"));
            var cfgPol = new PhishGuardConfig { CompanyDomains = new List<string> { "exemple-pme.fr" }, ExpertMode = true };
            cfgPol.ApplyPolicies(new[] { new KeyValuePair<string, string>("ReportAddress", "securite@exemple-pme.fr"),
                new KeyValuePair<string, string>("Company1", "Exemple SAS | France | 552100554 | Claire Martin; Hugo Bernard"),
                new KeyValuePair<string, string>("CompanyDomains", "exemple-pme.fr"), new KeyValuePair<string, string>("ForceSimpleMode", "1") });
            Capture(new SettingsForm(cfgPol, null, "exemple-pme.fr"), Path.Combine(outDir, "parametres-strategies.png"));

            // Analyse approfondie (résultats fictifs, pour la mise en page)
            var dr = new DeepReport { Duration = TimeSpan.FromSeconds(23) };
            dr.Findings.Add(new Finding("deep-link-login", "links", Severity.High, L.T("Un lien mène à une page qui demande un mot de passe"),
                L.T("La page de destination contient un champ « mot de passe ». Ne vous connectez jamais depuis un lien reçu par email : passez par l’adresse habituelle du site."), new[] { "hxxps://micros0ft-support[.]com/owa/login" }));
            dr.Findings.Add(new Finding("deep-domain-new", "links", Severity.High, "Domaine créé il y a 3 jour(s) (destination réelle d’un lien)", "", new[] { "micros0ft-support.com" }));
            dr.Facts.Add(new DeepFact("links", "warn", "bit[.]ly → t[.]exemple-tracker[.]com → micros0ft-support[.]com"));
            dr.Facts.Add(new DeepFact("domains", "bad", "micros0ft-support.com (destination réelle d’un lien) : créé le 17/10/2026 (il y a 3 jours) ; premier certificat HTTPS le 17/10/2026"));
            dr.Facts.Add(new DeepFact("domains", "ok", "exemple-tracker.com (lien) : créé le 02/03/2019 (il y a 2 789 jours) ; premier certificat HTTPS le 04/03/2019"));
            dr.Facts.Add(new DeepFact("history", "warn", "Premier message reçu de no-reply@micros0ft-support.com dans votre boîte de réception"));
            dr.Facts.Add(new DeepFact("history", "bad", "Le nom « Microsoft 365 » vous a déjà écrit depuis : no-reply@microsoft.com"));
            dr.Sent.Add("Visite de bit[.]ly (sans cookie, sans exécuter de code)"); dr.Sent.Add("Nom de domaine micros0ft-support.com → rdap.org"); dr.Sent.Add("Nom de domaine micros0ft-support.com → crt.sh");
            dr.Unchecked.Add("Serveurs traversés : pas de clé AbuseIPDB");
            var rd = Analyzer.WithFindings(Analyzer.Analyze(p, cfg), dr.Findings, dr);
            dr.FollowedLinks = true;
            Write(outDir, "expert-approfondie.html", ResultForm.BuildHtml(rd, p, true, "s-deep", new DeepUi { CanFollow = true, CanUrls = true }));
            Write(outDir, "expert-approfondie-encours.html", ResultForm.BuildHtml(Analyzer.Analyze(p, cfg), p, true, "s-deep", new DeepUi { Running = true }));

            // Thème sombre (Windows en mode sombre)
            Theme.Dark = true;
            Write(outDir, "simple-dangereux-sombre.html", SimpleView.Build(rp, p, true));
            Write(outDir, "simple-suspect-sombre.html", SimpleView.Build(rs, s, true));
            Write(outDir, "simple-verifie-sombre.html", SimpleView.Build(rv, v, true));
            Write(outDir, "expert-dangereux-sombre.html", ResultForm.BuildHtml(rp, p, true));
            Capture(new FirstRunForm(new PhishGuardConfig(), "exemple-pme.fr", null, FirstRunForm.Steps), Path.Combine(outDir, "assistant-sombre.png"));
            Capture(new SettingsForm(cfg, null, "exemple-pme.fr"), Path.Combine(outDir, "parametres-sombre.png"));
            Capture(new SettingsForm(cfgPol, null, "exemple-pme.fr"), Path.Combine(outDir, "parametres-strategies-sombre.png"));
            Capture(new AlertForm(rp, p.Subject), Path.Combine(outDir, "alerte-sombre.png"));
            Theme.Dark = false;
            Capture(new AlertForm(rp, p.Subject), Path.Combine(outDir, "alerte.png"));
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
