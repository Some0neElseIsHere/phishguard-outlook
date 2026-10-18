// PhishGuard - tests du moteur (mêmes scénarios que la version JavaScript).
// Compilé et lancé automatiquement par construire.bat.

using System;
using System.Collections.Generic;
using System.Linq;

namespace PhishGuard.Tests
{
    static class Program
    {
        static int passed, failed;

        static void Check(string name, bool ok, string info)
        {
            if (ok) { passed++; return; }
            failed++;
            Console.WriteLine("  ECHEC : " + name + (string.IsNullOrEmpty(info) ? "" : " -> " + info));
        }
        static void Check(string name, bool ok) { Check(name, ok, null); }

        static string Desc(Lookalike l)
        {
            return l == null ? "null" : l.Brand + "/" + l.Technique + "/" + l.Severity;
        }

        const string PASS = "Authentication-Results: spf=pass smtp.mailfrom=x; dkim=pass header.d=x; dmarc=pass action=none header.from=x;compauth=pass";
        const string FAIL = "Authentication-Results: spf=fail smtp.mailfrom=x; dkim=none; dmarc=fail action=quarantine header.from=x;compauth=fail reason=000";

        static EmailData Base()
        {
            return new EmailData
            {
                FromName = "Paul", FromAddress = "paul@exemple-pme.fr", Subject = "Bonjour",
                BodyText = "Bonjour, voici le compte rendu de la réunion.", RawHeaders = PASS
            };
        }

        static List<string> Ids(AnalysisResult r) { return r.Findings.Select(f => f.Id).ToList(); }

        /// <summary>Archive ZIP minimale (répertoire central uniquement) pour les tests.</summary>
        static byte[] MakeZip(string name, bool encrypted)
        {
            var n = System.Text.Encoding.ASCII.GetBytes(name);
            var b = new byte[4 + 46 + n.Length];
            b[0] = 0x50; b[1] = 0x4B; b[2] = 0x03; b[3] = 0x04;      // signature locale (pour le type "zip")
            int o = 4;
            b[o] = 0x50; b[o + 1] = 0x4B; b[o + 2] = 0x01; b[o + 3] = 0x02;
            b[o + 8] = (byte)(encrypted ? 1 : 0);
            b[o + 28] = (byte)n.Length;
            Array.Copy(n, 0, b, o + 46, n.Length);
            return b;
        }

        static int Main()
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            var cfg = new PhishGuardConfig
            {
                CompanyName = "Acmetech",
                CompanyDomains = new List<string> { "acmetech.fr" },
                VipNames = new List<string> { "Claire Martin" },
                TrustedDomains = new List<string> { "partenaire-fiable.fr" }
            };
            var ctx = Domains.BuildContext(cfg);
            Func<string, Lookalike> look = h => Domains.DetectLookalike(h, ctx);
            Blocklists.SetForTests(new string[0], new string[0]);
            DomainAge.Enabled = false;      // pas d'appel réseau pendant les tests
            L.SetLanguage("fr");
            Correspondents.Reset();

            // Domaine enregistrable
            Check("registrable co.uk", Domains.ParseHost("login.microsoft.com.evil.co.uk").Registrable == "evil.co.uk");
            Check("registrable gouv.fr", Domains.ParseHost("impots.gouv.fr").Registrable == "impots.gouv.fr");
            Check("registrable web.app", Domains.ParseHost("microsoft-login.web.app").Registrable == "microsoft-login.web.app");

            // Typosquatting et homoglyphes
            var l1 = look("niicrosoft.com"); Check("niicrosoft.com", l1 != null && l1.Brand == "Microsoft" && l1.Technique == "typo", Desc(l1));
            var l2 = look("rnicrosoft.com"); Check("rnicrosoft.com", l2 != null && l2.Technique == "homoglyph", Desc(l2));
            var l3 = look("micros0ft.com"); Check("micros0ft.com", l3 != null && l3.Technique == "homoglyph", Desc(l3));
            var l4 = look("paypa1.com"); Check("paypa1.com", l4 != null && l4.Brand == "PayPal", Desc(l4));
            var l5 = look("arnazon.fr"); Check("arnazon.fr", l5 != null && l5.Brand == "Amazon", Desc(l5));
            var l6 = look("linkedln.com"); Check("linkedln.com", l6 != null && l6.Brand == "LinkedIn", Desc(l6));

            // Unicode (a cyrillique)
            string puny = Domains.ToAscii("pаypal.com");
            Check("punycode", puny.StartsWith("xn--"), puny);
            var l7 = look(puny); Check("pаypal.com (cyrillique)", l7 != null && l7.Brand == "PayPal" && l7.Technique == "unicode", Desc(l7));

            // Combosquatting et sous-domaine
            var l8 = look("microsoft-login-secure.com"); Check("microsoft-login-secure.com", l8 != null && l8.Technique == "combo", Desc(l8));
            var l9 = look("secure-paypal.xyz"); Check("secure-paypal.xyz", l9 != null && l9.Brand == "PayPal", Desc(l9));
            var l10 = look("login.microsoft.com.verify-acct.xyz"); Check("sous-domaine", l10 != null && l10.Technique == "subdomain", Desc(l10));
            var l11 = look("microsoft-login.web.app"); Check("microsoft-login.web.app", l11 != null && l11.Brand == "Microsoft", Desc(l11));

            // Domaine de l'entreprise
            var l12 = look("acrnetech.fr"); Check("acrnetech.fr critique", l12 != null && l12.IsCompany && l12.Severity == Severity.Critical, Desc(l12));
            var l13 = look("acmetech.com"); Check("acmetech.com élevé", l13 != null && l13.Severity == Severity.High, Desc(l13));

            // Pas de faux positifs
            foreach (var h in new[] { "microsoft.com", "login.microsoftonline.com", "gmail.com", "impots.gouv.fr", "acmetech.fr",
                "partenaire-fiable.fr", "groupes.fr", "updates.com", "window-shop.fr", "offices-paris.fr", "leboncoin.fr",
                "amazonie-voyages.fr", "cafe-de-paris.fr", "orange-mecanique.fr", "freelance.fr", "fnac.com", "google-analytics.com",
                "googlemaps.fr", "docusignal.com" })
            {
                var r = look(h);
                Check("pas de faux positif : " + h, r == null, Desc(r));
            }

            // Safe Links
            var u = Analyzer.UnwrapUrl("https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fniicrosoft.com%2Flogin&data=05", null);
            Check("Safe Links", u != null && u.Host == "niicrosoft.com", u == null ? "null" : u.Host);

            // Liens réécrits par les passerelles de sécurité
            u = Analyzer.UnwrapUrl("https://urldefense.com/v3/__https://www.sonema.com/__;!!AbCdEf12!xYz-123$", null);
            Check("Proofpoint v3", u != null && u.Host == "www.sonema.com", u == null ? "null" : u.AbsoluteUri);
            string v3 = Rewriters.ProofpointV3("https://urldefense.com/v3/__https://ex.fr/a?b=1*x**A__;IyYm!!tok$");
            Check("Proofpoint v3 caractères remplacés", v3 == "https://ex.fr/a?b=1#x&&", v3);
            u = Analyzer.UnwrapUrl("https://urldefense.proofpoint.com/v2/url?u=https-3A__niicrosoft.com_login-3Fa-3D1&d=DwMF&c=abc", null);
            Check("Proofpoint v2", u != null && u.Host == "niicrosoft.com" && u.Query == "?a=1", u == null ? "null" : u.AbsoluteUri);
            u = Analyzer.UnwrapUrl("https://linkprotect.cudasvc.com/url?a=https%3a%2f%2fniicrosoft.com%2f&c=E,1", null);
            Check("Barracuda", u != null && u.Host == "niicrosoft.com", u == null ? "null" : u.AbsoluteUri);

            var eRw = Base();
            eRw.Links.Add(new LinkInfo("https://urldefense.com/v3/__https://www.acmetech.fr/contact__;!!AbC!dEf$", "www.acmetech.fr"));
            var rRw = Analyzer.Analyze(eRw, cfg);
            Check("Proofpoint vers le bon site : pas d’alerte de lien trompeur", !Ids(rRw).Contains("link-text-mismatch") && !Ids(rRw).Contains("link-redirect"),
                string.Join(",", Ids(rRw).ToArray()));
            Check("Proofpoint signalé pour information", rRw.Findings.Any(f => f.Id == "link-rewritten" && f.Severity == Severity.Info));

            var eRw2 = Base();
            eRw2.Links.Add(new LinkInfo("https://urldefense.com/v3/__https://niicrosoft.com/login__;!!AbC!dEf$", "www.microsoft.com"));
            var rRw2 = Analyzer.Analyze(eRw2, cfg);
            Check("Proofpoint vers un sosie : lien trompeur détecté", Ids(rRw2).Contains("link-text-mismatch"), string.Join(",", Ids(rRw2).ToArray()));

            var eRw3 = Base();
            eRw3.Links.Add(new LinkInfo("https://protect-eu.mimecast.com/s/AbCdEfGh?domain=acmetech.fr", "www.acmetech.fr"));
            var rRw3 = Analyzer.Analyze(eRw3, cfg);
            Check("Mimecast illisible : pas de fausse alerte", !Ids(rRw3).Contains("link-text-mismatch") && Ids(rRw3).Contains("link-rewritten"),
                string.Join(",", Ids(rRw3).ToArray()));

            // Scénario légitime
            var e1 = Base();
            e1.Links.Add(new LinkInfo("https://acmetech.sharepoint.com/doc", "Voir le document"));
            e1.Attachments.Add(new AttachmentInfo { Name = "compte-rendu.pdf" });
            var r1 = Analyzer.Analyze(e1, cfg);
            Check("email légitime = sûr", r1.Level == "safe", string.Join(",", Ids(r1).ToArray()));

            // Phishing Microsoft
            var e2 = Base();
            e2.FromName = "Microsoft 365 Support"; e2.FromAddress = "no-reply@niicrosoft.com";
            e2.Subject = "Action requise : votre boîte mail est pleine";
            e2.BodyText = "Votre compte sera suspendu dans les 24 h. Connectez-vous pour vérifier votre compte.";
            e2.Links.Add(new LinkInfo("https://niicrosoft.com/owa/login.php", "https://login.microsoftonline.com"));
            e2.RawHeaders = FAIL;
            var r2 = Analyzer.Analyze(e2, cfg);
            Check("phishing Microsoft = dangereux", r2.Level == "dangerous");
            foreach (var id in new[] { "auth-dmarc", "sender-lookalike-typo", "links-lookalike-typo", "link-text-mismatch", "content-combo-cred" })
                Check("phishing Microsoft : " + id, Ids(r2).Contains(id), string.Join(",", Ids(r2).ToArray()));
            Check("rapport désarmé", Analyzer.FormatReport(r2, e2).Contains("hxxps://niicrosoft[.]com"));

            // Fraude au président
            var e3 = Base();
            e3.FromName = "Claire Martin"; e3.FromAddress = "claire.martin.dg@gmail.com"; e3.Subject = "Virement urgent";
            e3.BodyText = "Es-tu disponible ? J’ai besoin d’un virement aujourd’hui, en toute discrétion. Je suis en réunion.";
            var r3 = Analyzer.Analyze(e3, cfg);
            Check("fraude au président = dangereux", r3.Level == "dangerous", string.Join(",", Ids(r3).ToArray()));
            Check("fraude au président : sender-vip", Ids(r3).Contains("sender-vip"));
            Check("fraude au président : content-combo-bec", Ids(r3).Contains("content-combo-bec"));

            // Usurpation du domaine de l'entreprise
            var e4 = Base(); e4.FromName = "Compta"; e4.FromAddress = "compta@acmetech.fr"; e4.RawHeaders = FAIL;
            var r4 = Analyzer.Analyze(e4, cfg);
            Check("usurpation domaine entreprise", r4.Level == "dangerous" && r4.Findings.Any(f => f.Id == "auth-dmarc" && f.Severity == Severity.Critical));

            // Pièces jointes
            var e5 = Base();
            e5.Attachments.Add(new AttachmentInfo { Name = "Facture_2026.pdf.exe" });
            e5.Attachments.Add(new AttachmentInfo { Name = "scan.html" });
            e5.Attachments.Add(new AttachmentInfo { Name = "devis.xlsm" });
            e5.Attachments.Add(new AttachmentInfo { Name = "photo.png", IsInline = true, IsImage = true });
            var r5 = Analyzer.Analyze(e5, cfg);
            foreach (var id in new[] { "att-double", "att-html", "att-macro" }) Check("pièces jointes : " + id, Ids(r5).Contains(id));
            Check("pièces jointes = dangereux", r5.Level == "dangerous");

            // Reply-To
            var e6 = Base(); e6.RawHeaders = PASS + "\r\nReply-To: \"Service client\" <support.facture@outlook.fr>";
            var r6 = Analyzer.Analyze(e6, cfg);
            Check("Reply-To messagerie gratuite", r6.Findings.Any(f => f.Id == "sender-replyto" && f.Severity == Severity.High));

            // Message interne
            var e7 = Base(); e7.FromName = "RH"; e7.FromAddress = "rh@acmetech.fr"; e7.IsExchangeInternal = true; e7.RawHeaders = "";
            e7.BodyText = "Rappel urgent : mettez à jour votre mot de passe avant vendredi.";
            var r7 = Analyzer.Analyze(e7, cfg);
            Check("message interne = sûr", r7.Internal && r7.Level == "safe", r7.Level);

            // Listes de domaines malveillants
            var parsed = Blocklists.ParseList("Last update: 2026-10-15\n# commentaire\nfaux-impots-remboursement.fr\n0.0.0.0 colis-laposte-suivi.fr\nAMELI-carte-vitale.fr\n\nnot a domain\n||adguard-style.fr^");
            Check("lecture des listes", parsed.Count == 4 && parsed.Contains("colis-laposte-suivi.fr") && parsed.Contains("adguard-style.fr"), string.Join(",", parsed.ToArray()));
            Blocklists.SetForTests(new[] { "colis-suivi-livraison.fr", "mon-espace-sante-maj.fr" }, new[] { "fournisseur-faux.com" });
            var h1 = Blocklists.Lookup("www.track.colis-suivi-livraison.fr");
            Check("liste : sous-domaine", h1 != null && h1.Domain == "colis-suivi-livraison.fr");
            Check("liste : pas de faux positif", Blocklists.Lookup("suivi-livraison.fr") == null);
            var h2 = Blocklists.Lookup("fournisseur-faux.com");
            Check("liste interne = critique", h2 != null && h2.Severity == Severity.Critical);
            var e8 = Base(); e8.FromName = "Service Livraison"; e8.FromAddress = "info@mon-espace-sante-maj.fr";
            e8.Links.Add(new LinkInfo("https://www.colis-suivi-livraison.fr/track?id=1", "Suivre mon colis"));
            var r8 = Analyzer.Analyze(e8, cfg);
            Check("liste : expéditeur signalé", Ids(r8).Contains("sender-blocklist-redflagdomains"), string.Join(",", Ids(r8).ToArray()));
            Check("liste : lien signalé", Ids(r8).Contains("links-blocklist-redflagdomains"), string.Join(",", Ids(r8).ToArray()));
            Check("liste : dangereux", r8.Level == "dangerous");
            Blocklists.SetForTests(new string[0], new string[0]);

            // Données d'enquête : parcours, IP d'origine, authentification
            string raw =
                "Received: from mail.exemple.fr (10.0.0.5) by exch01.exemple.local (10.0.0.6) with Microsoft SMTP Server id 15.2; Thu, 15 Oct 2026 14:44:10 +0200\r\n" +
                "Received: from mx.evil-sender.xyz (mx.evil-sender.xyz [185.220.101.4])\r\n\tby mail.exemple.fr (Postfix) with ESMTPS id 4F2;\r\n\tThu, 15 Oct 2026 14:43:58 +0200 (CEST)\r\n" +
                "Received: from [192.168.1.20] (unknown [192.168.1.20]) by mx.evil-sender.xyz with ESMTPSA; Thu, 15 Oct 2026 12:43:50 +0000\r\n" +
                "Authentication-Results: mail.exemple.fr; spf=fail smtp.mailfrom=evil-sender.xyz; dkim=pass header.d=evil-sender.xyz header.s=sel1; dmarc=fail action=none header.from=niicrosoft.com\r\n" +
                "From: \"Microsoft\" <no-reply@niicrosoft.com>\r\nSubject: Test\r\nMessage-ID: <abc@evil-sender.xyz>\r\n";
            var det = Forensics.ParseHeaders(raw);
            Check("parcours : 3 sauts", det.Hops.Count == 3, det.Hops.Count.ToString());
            Check("parcours : ordre chronologique", det.Hops.Count == 3 && det.Hops[0].FromIp == "192.168.1.20" && det.Hops[1].FromIp == "185.220.101.4",
                string.Join(",", det.Hops.Select(x => x.FromIp).ToArray()));
            Check("IP d'origine publique", det.OriginIp == "185.220.101.4", det.OriginIp);
            Check("délai entre sauts", det.Hops.Count == 3 && det.Hops[1].Delay.HasValue && det.Hops[1].Delay.Value.TotalSeconds == 8,
                det.Hops.Count == 3 ? Forensics.FormatDelay(det.Hops[1].Delay) : "");
            Check("DKIM sélecteur", det.Auth.DkimSelector == "sel1" && det.Auth.DkimDomain == "evil-sender.xyz", det.Auth.DkimSelector + "/" + det.Auth.DkimDomain);
            Check("SPF mailfrom", det.Auth.Spf == "fail" && det.Auth.SpfMailFrom == "evil-sender.xyz");
            Check("champs principaux", det.Fields.Any(f => f.Key == "Message-ID"));
            Check("IP privée", !Forensics.IsPublicIp("192.168.1.20") && !Forensics.IsPublicIp("10.1.2.3") && Forensics.IsPublicIp("185.220.101.4"));

            // Type réel des pièces jointes
            var exeBytes = new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00 };
            var fake = new AttachmentInfo { Name = "Facture.pdf" };
            Forensics.ComputeHashes(fake, exeBytes);
            Check("signature exe", fake.Magic == "exe", fake.Magic);
            Check("SHA256 calculé", fake.Sha256.Length == 64 && fake.Md5.Length == 32);
            var mm = Forensics.MagicMismatch(fake);
            Check("programme déguisé en PDF", mm != null && mm.Id == "att-magic-exe" && mm.Severity == Severity.Critical, mm == null ? "null" : mm.Id);
            var okPdf = new AttachmentInfo { Name = "doc.pdf" };
            Forensics.ComputeHashes(okPdf, System.Text.Encoding.ASCII.GetBytes("%PDF-1.7 test"));
            Check("vrai PDF accepté", Forensics.MagicMismatch(okPdf) == null);
            var e9 = Base(); e9.Attachments.Add(fake);
            var r9 = Analyzer.Analyze(e9, cfg);
            Check("analyse : programme déguisé = dangereux", r9.Level == "dangerous" && Ids(r9).Contains("att-magic-exe"), string.Join(",", Ids(r9).ToArray()));
            Check("rapport complet : SHA256", Analyzer.FormatReport(r9, e9).Contains(fake.Sha256));


            // ---------- Email de test réel (Orange) : ARC, filtre antispam, encodage ----------
            string orange =
                "Return-Path: <g-1437@bounce.info.news-lb.org>\r\n" +
                "Received: from opmta1mti29aub ([10.79.5.102])\r\n\tby opme11ppr35nd1.nor.fr.intraorange with LMTP\r\n\tid x:T24\r\n\tfor <utilisateur@orange.fr>; Wed, 14 Oct 2026 10:35:28 +0200\r\n" +
                "Received: from novemduo.delta.eccluster.com ([195.140.185.92])\r\n\tby smtp.orange.fr with ESMTPS\r\n\tid GuQz; Wed, 14 Oct 2026 10:35:23 +0200\r\n" +
                "X-ME-Srv: suspect;10025\r\n" +
                "X-me-spamlevel: low\r\n" +
                "ARC-Authentication-Results: i=1; opmta1mti29aub; spf=pass (opmta1mti29aub: domain designates 195.140.185.92 as permited sender) smtp.mailfrom=g-1437@bounce.info.news-lb.org;\r\n\tarc=none;\r\n\tdkim=pass header.d=info.news-lb.org header.b=NJvB;\r\n\tdmarc=pass header.from=info.news-lb.org\r\n" +
                "Authentication-Results: opmta1mti29aub;\r\n\tarc=none;\r\n\tdkim=pass header.d=info.news-lb.org header.b=NJvB\r\n" +
                "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=info.news-lb.org; q=dns/txt; s=ecm1; bh=x; h=date:from; b=x\r\n" +
                "Received: from app12.muc.ec-messenger.com (app12.muc.ec-messenger.com [172.16.8.42])\r\n\t(envelope-from <g-1437@bounce.info.news-lb.org>)\r\n\tby gp13mtaq114 with ESMTP id ojRw\r\n\tfor <utilisateur@orange.fr>; Wed, 14 Oct 2026 10:06:32 +0200\r\n" +
                "From: Fabien <demande@info.news-lb.org>\r\n" +
                "Reply-To: reply-perf@ALTARES.COM\r\n" +
                "Subject: *** SPAM ***\r\n =?UTF-8?Q?=C3=89valuez_votre_visibilit=C3=A9_en_quelques_clics?=\r\n" +
                "Message-ID: <14t87h@info.news-lb.org>\r\n";
            var od = Forensics.ParseHeaders(orange);
            Check("ARC : SPF lu", od.Auth.Spf == "pass", od.Auth.Spf);
            Check("ARC : DMARC lu", od.Auth.Dmarc == "pass", od.Auth.Dmarc);
            Check("ARC : source", od.Auth.Source.Contains("ARC"), od.Auth.Source);
            Check("objet décodé", od.Fields.Any(f => f.Key == "Objet" && f.Value.Contains("Évaluez votre visibilité")), string.Join(" | ", od.Fields.Select(f => f.Value).ToArray()));
            Check("IP d'origine Orange", od.OriginIp == "195.140.185.92", od.OriginIp);
            Check("en-têtes de filtrage", od.FilterHeaders.Any(f => f.Key == "x-me-srv"));
            Check("décodage RFC 2047", Forensics.DecodeMimeWords("=?UTF-8?Q?=C3=89t=C3=A9?= =?UTF-8?B?w6l0w6k=?=") == "Étéété", Forensics.DecodeMimeWords("=?UTF-8?Q?=C3=89t=C3=A9?= =?UTF-8?B?w6l0w6k=?="));
            var eo = Base();
            eo.FromName = "Fabien"; eo.FromAddress = "demande@info.news-lb.org";
            eo.Subject = "*** SPAM *** Évaluez votre visibilité en quelques clics";
            eo.BodyText = "Découvrez notre offre.";
            eo.RawHeaders = orange;
            var ro = Analyzer.Analyze(eo, cfg);
            Check("Orange : tag SPAM détecté", Ids(ro).Contains("filter-subject-spam"), string.Join(",", Ids(ro).ToArray()));
            Check("Orange : filtre suspect", Ids(ro).Contains("filter-orange"));
            Check("Orange : SPF/DMARC valides", ro.Positives.Any(x => x.StartsWith("SPF")) && ro.Positives.Any(x => x.StartsWith("DMARC")), string.Join(" | ", ro.Positives.ToArray()));
            Check("Orange : pas d'échec DMARC", !Ids(ro).Contains("auth-dmarc"));

            // ---------- IBAN ----------
            Check("IBAN valide trouvé", Analyzer.FindIbans("Notre RIB : FR76 3000 6000 0112 3456 7890 189 merci").Count == 1);
            Check("IBAN invalide ignoré", Analyzer.FindIbans("FR76 3000 6000 0112 3456 7890 188").Count == 0);
            var ei = Base(); ei.BodyText = "Suite à un changement de banque, merci d'utiliser notre nouveau RIB : DE89 3704 0044 0532 0130 00";
            var ri = Analyzer.Analyze(ei, cfg);
            Check("changement de RIB détecté", Ids(ri).Contains("content-iban-change"), string.Join(",", Ids(ri).ToArray()));
            var ei2 = Base(); ei2.BodyText = "Voici l'IBAN DE89370400440532013000 pour la commande.";
            Check("IBAN étranger", Ids(Analyzer.Analyze(ei2, cfg)).Contains("content-iban-foreign"));

            // ---------- Correspondants connus ----------
            Correspondents.Set(new[] { "compta@fournisseur-alpha.fr", "paul@exemple-pme.fr" }, false);
            var ec = Base(); ec.FromName = "Comptabilité"; ec.FromAddress = "compta@fournisseur-alpba.fr";
            var rc = Analyzer.Analyze(ec, cfg);
            Check("sosie d'un correspondant", rc.Findings.Any(f => f.Id == "sender-correspondent-lookalike" && f.Severity == Severity.High), string.Join(",", Ids(rc).ToArray()));
            Check("premier contact", Ids(rc).Contains("sender-first-contact"));
            var ek = Base();  // paul@exemple-pme.fr est connu
            Check("correspondant connu : pas de premier contact", !Ids(Analyzer.Analyze(ek, cfg)).Contains("sender-first-contact"));
            var en = Base(); en.FromAddress = "noreply@planethoster.info"; en.FromName = "PlanetHoster";
            var rn = Analyzer.Analyze(en, cfg);
            Check("noreply authentifié : premier contact en information", !Ids(rn).Contains("sender-first-contact") && Ids(rn).Contains("sender-first-contact-auto"), string.Join(",", Ids(rn).ToArray()));
            var en2 = Base(); en2.FromAddress = "noreply@planethoster.info"; en2.RawHeaders = FAIL;
            Check("noreply non authentifié : premier contact signalé", Ids(Analyzer.Analyze(en2, cfg)).Contains("sender-first-contact"));
            Check("adresses automatiques", Analyzer.IsAutomatedAddress("no-reply@x.fr") && Analyzer.IsAutomatedAddress("account-security-noreply@x.com")
                && Analyzer.IsAutomatedAddress("notifications@x.com") && !Analyzer.IsAutomatedAddress("paul@x.fr"));
            var ef = Base(); ef.FromAddress = "inconnu@autre-societe.fr"; ef.BodyText = "Merci de régler la facture impayée par virement aujourd'hui.";
            Check("premier contact + demande financière", Ids(Analyzer.Analyze(ef, cfg)).Contains("content-first-contact-request"));
            Check("domaine légitime non signalé comme sosie", Domains.LookalikeOfKnown("fournisseur-alpha.fr", "fournisseur-alpha.fr") == null);
            Correspondents.Reset();

            // ---------- Âge du domaine ----------
            DomainAge.SetForTests("tout-neuf-livraison.fr", DateTime.UtcNow.AddDays(-4));
            DomainAge.SetForTests("ancien-domaine.fr", DateTime.UtcNow.AddYears(-8));
            var ea = Base(); ea.FromAddress = "info@tout-neuf-livraison.fr";
            Check("domaine récent", Ids(Analyzer.Analyze(ea, cfg)).Contains("sender-new-domain"));
            var eb = Base(); eb.FromAddress = "info@ancien-domaine.fr";
            Check("domaine ancien non signalé", !Ids(Analyzer.Analyze(eb, cfg)).Contains("sender-new-domain"));
            Check("RDAP : date d'enregistrement", DomainAge.ParseRdap("{\"events\":[{\"eventAction\":\"last changed\",\"eventDate\":\"2026-01-01T00:00:00Z\"},{\"eventDate\":\"2026-10-10T08:00:00Z\",\"eventAction\":\"registration\"}]}") == new DateTime(2026, 10, 10, 8, 0, 0));
            DomainAge.ClearForTests();

            // ---------- Contenu des pièces jointes ----------
            var zipFake = new AttachmentInfo { Name = "documents.zip" };
            Forensics.ComputeHashes(zipFake, MakeZip("Facture_2026.pdf.exe", false));
            Check("ZIP : programme déguisé", zipFake.ContentFindings.Any(f => f.Id == "att-content-zip-double"), string.Join(",", zipFake.ContentFindings.Select(f => f.Id).ToArray()));
            var zipEnc = new AttachmentInfo { Name = "scan.zip" };
            Forensics.ComputeHashes(zipEnc, MakeZip("scan.pdf", true));
            Check("ZIP : chiffré", zipEnc.ContentFindings.Any(f => f.Id == "att-content-zip-encrypted"));
            var pdf = new AttachmentInfo { Name = "facture.pdf" };
            Forensics.ComputeHashes(pdf, System.Text.Encoding.ASCII.GetBytes("%PDF-1.4\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\n2 0 obj << /A << /S /URI /URI (https://micros0ft.xyz/a) >> >>"));
            Check("PDF : JavaScript", pdf.ContentFindings.Any(f => f.Id == "att-content-pdf-js"));
            Check("PDF : lien extrait", pdf.EmbeddedUrls.Contains("https://micros0ft.xyz/a"), string.Join(",", pdf.EmbeddedUrls.ToArray()));
            var ep = Base(); ep.Attachments.Add(pdf);
            var rp = Analyzer.Analyze(ep, cfg);
            Check("PDF : lien analysé (sosie)", Ids(rp).Any(x => x.StartsWith("links-lookalike")), string.Join(",", Ids(rp).ToArray()));
            var html = new AttachmentInfo { Name = "message.htm" };
            Forensics.ComputeHashes(html, System.Text.Encoding.UTF8.GetBytes("<html><form action='https://x.top/p'><input type=\"password\" name=p></form></html>"));
            Check("HTML : fausse page de connexion", html.ContentFindings.Any(f => f.Id == "att-content-html-password"));

            // ---------- Expéditeur de confiance ----------
            var cfgT = new PhishGuardConfig { CompanyDomains = new List<string> { "acmetech.fr" }, TrustedSenders = new List<string> { "newsletter@gmail.com" } };
            var et = Base(); et.FromName = "Microsoft News"; et.FromAddress = "newsletter@gmail.com";
            var rt = Analyzer.Analyze(et, cfgT);
            Check("expéditeur de confiance : indices neutralisés", rt.Level == "safe" && rt.Positives.Any(x => x.Contains("confiance")), rt.Level + " " + string.Join(",", Ids(rt).ToArray()));
            var et2 = Base(); et2.FromAddress = "newsletter@gmail.com"; et2.RawHeaders = FAIL;
            Check("expéditeur de confiance usurpé", Ids(Analyzer.Analyze(et2, cfgT)).Contains("sender-trusted-spoof"));

            // ---------- Explications ----------
            Check("explication par préfixe", Lessons.For("sender-lookalike-typo") != null && Lessons.For("filter-orange") != null && Lessons.For("inconnu") == null);

            // ---------- Sources externes (bêta) : lecture des réponses ----------
            var vt = Intel.ParseVirusTotal("{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"harmless\":60,\"malicious\":5,\"suspicious\":1,\"undetected\":4,\"timeout\":0}}}}");
            Check("VirusTotal : statistiques", vt.Found && vt.Malicious == 5 && vt.Suspicious == 1 && vt.Total == 70, vt.Malicious + "/" + vt.Total);
            Check("VirusTotal : inconnu", !Intel.ParseVirusTotal("{\"notfound\":true}").Found);
            var crt = Intel.ParseCrt("[{\"not_before\":\"2026-10-10T08:00:00\"},{\"not_before\":\"2019-03-01T00:00:00\"}]");
            Check("crt.sh : premier certificat", crt.Date.HasValue && crt.Date.Value.Year == 2019, crt.Date.HasValue ? crt.Date.Value.ToString("s") : "null");
            var uh = Intel.ParseUrlhaus("{\"query_status\":\"ok\",\"url_count\":\"12\",\"urls\":[]}");
            Check("URLhaus : domaine listé", uh.Found && uh.Total == 12);
            Check("URLhaus : rien", !Intel.ParseUrlhaus("{\"query_status\":\"no_results\"}").Found);
            var tf = Intel.ParseThreatFox("{\"query_status\":\"ok\",\"data\":[{\"ioc\":\"x.top\",\"malware_printable\":\"Emotet\"}]}");
            Check("ThreatFox : indicateur", tf.Found && tf.Label == "Emotet", tf.Label);
            var ab = Intel.ParseAbuseIpdb("{\"data\":{\"ipAddress\":\"1.2.3.4\",\"abuseConfidenceScore\":87,\"countryCode\":\"RU\",\"totalReports\":41}}");
            Check("AbuseIPDB : score", ab.Malicious == 87 && ab.Total == 41 && ab.Label == "RU");
            // Coffre de Windows : indisponible sur certains serveurs d'intégration (pas de session interactive)
            if (Secrets.Set("Test-PhishGuard", "cle-de-test-456"))
            {
                Check("coffre Windows : lecture", Secrets.Get("Test-PhishGuard") == "cle-de-test-456");
                Secrets.Set("Test-PhishGuard", "");
                Check("coffre Windows : suppression", Secrets.Get("Test-PhishGuard") == "");
            }
            Check("clé chiffrée (DPAPI)", PhishGuardConfig.Unprotect(PhishGuardConfig.Protect("cle-secrete-123")) == "cle-secrete-123" && PhishGuardConfig.Protect("abc").StartsWith("dpapi:"));

            // ---------- Sources externes (bêta) : listes et résultats dans l'analyse ----------
            Feeds.LoadOpenPhish("https://evil-login.top/office365/\nhttps://sites.google.com/view/fake-sso\n", DateTime.Now);
            Feeds.OpenPhishEnabled = true;
            Check("OpenPhish : adresse exacte", Feeds.OpenPhishMatch("https://evil-login.top/office365") == "url");
            Check("OpenPhish : sous-page", Feeds.OpenPhishMatch("https://evil-login.top/office365/step2?x=1") == "url");
            Check("OpenPhish : même serveur", Feeds.OpenPhishMatch("https://evil-login.top/autre") == "host");
            Check("OpenPhish : hébergeur partagé ignoré", Feeds.OpenPhishMatch("https://sites.google.com/view/autre-site") == null);
            Feeds.LoadTranco(new[] { "1,google.com", "2,microsoft.com", "57,exemple-pme.fr" }, DateTime.Now);
            Feeds.TrancoEnabled = true;
            Check("Tranco : rang", Feeds.TrancoRank("microsoft.com") == 2 && Feeds.TrancoRank("inconnu-xyz.fr") == 0);

            var eI = Base();
            eI.Links.Add(new LinkInfo("https://evil-login.top/office365/", "Se connecter"));
            eI.Links.Add(new LinkInfo("https://malware-cdn.xyz/f.zip", "Télécharger"));
            eI.Attachments.Add(new AttachmentInfo { Name = "facture.pdf", Sha256 = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90" });
            var cfgI = new PhishGuardConfig { CompanyDomains = new List<string> { "acmetech.fr" }, BetaDnsChecks = true, BetaCertAge = true };
            Intel.Settings = new IntelSettings { VirusTotalKey = "test" };
            Intel.SetForTests("dns:exemple-pme.fr|exemple-pme.fr", new IntelResult { Ok = true, Exists = false });
            Intel.SetForTests("crt:evil-login.top", new IntelResult { Ok = true, Found = true, Date = DateTime.UtcNow.AddDays(-2) });
            Intel.SetForTests("crt:malware-cdn.xyz", new IntelResult { Ok = true, Found = false });
            Intel.SetForTests("crt:exemple-pme.fr", new IntelResult { Ok = true, Found = true, Date = DateTime.UtcNow.AddYears(-5) });
            Intel.SetForTests("vtf:a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90", new IntelResult { Ok = true, Found = true, Malicious = 9, Total = 70 });
            var rI = Analyzer.Analyze(eI, cfgI);
            foreach (var id in new[] { "links-intel-openphish", "links-intel-cert-new", "att-intel-vt" })
                Check("bêta : " + id, Ids(rI).Contains(id), string.Join(",", Ids(rI).ToArray()));
            Check("bêta : Tranco ignore les vérifications d’un domaine très fréquenté", !Ids(rI).Contains("sender-intel-dns-nxdomain") && rI.Positives.Any(p => p.Contains("Tranco")),
                string.Join(",", Ids(rI).ToArray()));
            Feeds.LoadTranco(new string[0], DateTime.Now);
            var rI2 = Analyzer.Analyze(eI, cfgI);
            Check("bêta : domaine expéditeur inexistant", Ids(rI2).Contains("sender-intel-dns-nxdomain"), string.Join(",", Ids(rI2).ToArray()));
            Check("bêta : aucune vérification en attente", !Ids(rI2).Contains("intel-pending"), string.Join(",", Ids(rI2).ToArray()));
            Check("bêta : état des sources", rI2.Sources.Any(x => x.Name == "VirusTotal" && x.State == "ok") && rI2.Sources.Any(x => x.Name == "AbuseIPDB" && x.State == "off")
                && rI2.Sources.Any(x => x.Name == "OpenPhish" && x.State == "ok"), string.Join(", ", rI2.Sources.Select(x => x.Name + "=" + x.State).ToArray()));
            Check("bêta : indices regroupés", rI2.Findings.Where(f => Analyzer.IsBetaFinding(f)).Count() >= 3);
            Intel.Settings = new IntelSettings();
            Intel.ClearForTests();
            Feeds.OpenPhishEnabled = false;
            Feeds.TrancoEnabled = false;

            // ---------- Preuves de légitimité ----------
            const string ALIGNED = "Authentication-Results: spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=bounce@mail.exemple-pme.fr; dkim=pass (signature was verified) header.d=exemple-pme.fr;dmarc=pass action=none header.from=exemple-pme.fr;compauth=pass reason=100";
            Correspondents.Set(new[] { "paul@exemple-pme.fr" }, false);
            var eV = Base(); eV.RawHeaders = ALIGNED;
            var rV = Analyzer.Analyze(eV, cfg);
            Check("légitimité : expéditeur vérifié", rV.Verified, string.Join(",", Ids(rV).ToArray()) + " | " + string.Join(" ; ", rV.Trust.ToArray()));
            Check("légitimité : DKIM aligné", rV.Trust.Any(x => x.Contains("DKIM") && x.Contains("exemple-pme.fr")));
            Check("légitimité : SPF aligné", rV.Trust.Any(x => x.Contains("SPF aligné")));
            Check("légitimité : compauth 1xx", rV.Trust.Any(x => x.Contains("raison 100")));
            Check("légitimité : pas d'indice DKIM tiers", !Ids(rV).Contains("auth-dkim-thirdparty"));
            var rTp = Analyzer.Analyze(Base(), cfg);   // header.d=x : signature d'un prestataire
            Check("légitimité : signature DKIM d'un tiers", rTp.Findings.Any(f => f.Id == "auth-dkim-thirdparty" && f.Severity == Severity.Info));
            var eV2 = Base(); eV2.RawHeaders = ALIGNED; eV2.FromAddress = "contact@exemple-pme.fr";
            Check("légitimité : domaine connu = vérifié", Analyzer.Analyze(eV2, cfg).Verified);
            var eV3 = Base(); eV3.RawHeaders = ALIGNED; eV3.BodyText = "Merci de régler la facture impayée par virement aujourd'hui, c'est urgent.";
            Check("légitimité : un indice empêche la vérification", !Analyzer.Analyze(eV3, cfg).Verified);
            Correspondents.Reset();
            Check("légitimité : inconnu non vérifié", !Analyzer.Analyze(eV, cfg).Verified);

            // compauth : codes de raison
            var eC1 = Base(); eC1.RawHeaders = "Authentication-Results: spf=none; dkim=none; dmarc=none action=none header.from=exemple-pme.fr;compauth=fail reason=001";
            Check("compauth 001 : moyen", Analyzer.Analyze(eC1, cfg).Findings.Any(f => f.Id == "auth-compauth" && f.Severity == Severity.Medium));
            var eC2 = Base(); eC2.RawHeaders = "Authentication-Results: spf=none; dkim=none; dmarc=none action=none header.from=exemple-pme.fr;compauth=fail reason=601";
            Check("compauth 6xx : usurpation interne", Analyzer.Analyze(eC2, cfg).Findings.Any(f => f.Id == "auth-compauth-intra" && f.Severity == Severity.Critical));
            Check("compauth 000 : élevé", Analyzer.Analyze(e2, cfg).Findings.Any(f => f.Id == "auth-compauth" && f.Severity == Severity.High));

            // Envoi en nombre conforme
            var eB = Base(); eB.RawHeaders = ALIGNED + "\nList-Unsubscribe: <https://exemple-pme.fr/u?x=1>, <mailto:u@exemple-pme.fr>\nList-Unsubscribe-Post: List-Unsubscribe=One-Click";
            Check("envoi en nombre conforme", Analyzer.Analyze(eB, cfg).Trust.Any(x => x.Contains("un clic")));
            var eB2 = Base(); eB2.RawHeaders = FAIL + "\nList-Unsubscribe: <https://x.fr/u>\nList-Unsubscribe-Post: List-Unsubscribe=One-Click";
            Check("envoi en nombre sans DMARC : non conforme", !Analyzer.Analyze(eB2, cfg).Trust.Any(x => x.Contains("un clic")));

            // Réponse à l'un de vos messages / détournement de fil
            var sent = new Dictionary<string, HashSet<string>>();
            sent["<ABC123@mail.acmetech.fr>"] = new HashSet<string> { "fournisseur-alpha.fr" };
            Correspondents.Set(new[] { "compta@fournisseur-alpha.fr" }, false);
            Correspondents.SetThreads(sent, false);
            var eR = Base(); eR.FromAddress = "compta@fournisseur-alpha.fr";
            eR.RawHeaders = ALIGNED.Replace("exemple-pme.fr", "fournisseur-alpha.fr") + "\nIn-Reply-To: <abc123@mail.acmetech.fr>\nReferences: <old@x> <abc123@mail.acmetech.fr>";
            var rR = Analyzer.Analyze(eR, cfg);
            Check("réponse à votre message", rR.Trust.Any(x => x.Contains("vous avez envoyé")) && rR.Verified, string.Join(",", Ids(rR).ToArray()));
            var eH = Base(); eH.FromAddress = "compta@fournisseur-alpha-fr.com";
            eH.RawHeaders = ALIGNED.Replace("exemple-pme.fr", "fournisseur-alpha-fr.com") + "\nReferences: <abc123@mail.acmetech.fr>";
            var rH = Analyzer.Analyze(eH, cfg);
            Check("détournement de fil", rH.Findings.Any(f => f.Id == "sender-thread-hijack" && f.Severity == Severity.High) && !rH.Verified, string.Join(",", Ids(rH).ToArray()));
            var eN = Base(); eN.FromAddress = "compta@fournisseur-alpha-fr.com"; eN.RawHeaders = ALIGNED + "\nIn-Reply-To: <inconnu@ailleurs>";
            Check("fil inconnu : rien", !Ids(Analyzer.Analyze(eN, cfg)).Contains("sender-thread-hijack"));
            Check("Message-ID normalisé", Correspondents.NormalizeMessageId(" <AbC@X> ") == "abc@x");
            Correspondents.Reset();
            Check("fils effacés", Correspondents.ThreadRecipients("abc123@mail.acmetech.fr") == null);

            // DMARC (politique) et BIMI par DNS (bêta)
            Check("DMARC p=reject", Intel.ParseDmarcPolicy("v=DMARC1; p=reject; rua=mailto:x@y", false) == "reject");
            Check("DMARC sp= pour un sous-domaine", Intel.ParseDmarcPolicy("v=DMARC1; p=reject; sp=none", true) == "none" && Intel.ParseDmarcPolicy("v=DMARC1; p=quarantine", true) == "quarantine");
            Check("BIMI avec certificat", Intel.ParseBimi("v=BIMI1; l=https://x/logo.svg; a=https://x/vmc.pem") == "vmc");
            Check("BIMI sans certificat", Intel.ParseBimi("v=BIMI1; l=https://x/logo.svg; a=;") == "logo" && Intel.ParseBimi("") == "");
            var cfgD = new PhishGuardConfig { CompanyDomains = new List<string> { "acmetech.fr" }, BetaDnsChecks = true };
            Intel.Settings = new IntelSettings { DnsChecks = true };
            Intel.SetForTests("dns:exemple-pme.fr|exemple-pme.fr", new IntelResult { Ok = true, Exists = true, HasMx = true, HasSpf = true, HasDmarc = true, DmarcPolicy = "reject", Bimi = "vmc" });
            var rD = Analyzer.Analyze(eV, cfgD);
            Check("bêta : DMARC strict et marque vérifiée", rD.Trust.Any(x => x.Contains("p=reject")) && rD.Trust.Any(x => x.Contains("BIMI")), string.Join(" ; ", rD.Trust.ToArray()));
            Intel.SetForTests("dns:exemple-pme.fr|exemple-pme.fr", new IntelResult { Ok = true, Exists = true, HasMx = true, HasSpf = true, HasDmarc = true, DmarcPolicy = "none" });
            Check("bêta : DMARC p=none", Ids(Analyzer.Analyze(eV, cfgD)).Contains("sender-intel-dmarc-none"));
            Intel.Settings = new IntelSettings();
            Intel.ClearForTests();

            // ---------- Annuaire des Entreprises ----------
            const string ANNUAIRE = "{\"results\":[{\"siren\":\"111\",\"nom_complet\":\"ACME (FERMEE)\",\"etat_administratif\":\"C\",\"siege\":{\"libelle_commune\":\"LYON\"},\"dirigeants\":[]},"
                + "{\"siren\":\"449397173\",\"nom_complet\":\"SONEMA\",\"etat_administratif\":\"A\",\"siege\":{\"libelle_commune\":\"FREJUS\"},\"dirigeants\":["
                + "{\"nom\":\"DUFOURCQ\",\"prenoms\":\"CHARLES AUGUSTIN MARIE\",\"qualite\":\"Gérant\",\"type_dirigeant\":\"personne physique\"},"
                + "{\"siren\":\"999\",\"denomination\":\"HOLDING X\",\"qualite\":\"Président\",\"type_dirigeant\":\"personne morale\"},"
                + "{\"nom\":\"GORIN-TRIANA\",\"prenoms\":\"JEAN-PIERRE\",\"type_dirigeant\":\"personne physique\"}]}],\"total_results\":2}";
            var co = CompanyLookup.Parse(ANNUAIRE);
            Check("annuaire : entreprises lues", co.Count == 2, co.Count.ToString());
            Check("annuaire : active en premier", co.Count == 2 && co[0].Name == "SONEMA" && co[0].City == "Frejus" && !co[1].Active);
            Check("annuaire : dirigeants personnes physiques", co.Count == 2 && co[0].Directors.Count == 2 && co[0].Directors[0] == "Charles Dufourcq"
                && co[0].Directors[1] == "Jean-Pierre Gorin-Triana" && co[0].Roles[0] == "Charles Dufourcq (Gérant)", co.Count > 0 ? string.Join(" | ", co[0].Directors.ToArray()) : "");
            Check("annuaire : réponse vide", CompanyLookup.Parse("{}").Count == 0 && CompanyLookup.Parse("{\"results\":[]}").Count == 0);

            // ---------- Analyse de votre domaine ----------
            var va = DomainAudit.Variants("sonema.com");
            Func<string, bool> hasV = d => va.Any(x => x.Key == d);
            Check("variantes : extension, caractère, faute, mot", hasV("sonema.fr") && hasV("s0nema.com") && hasV("sonerna.com") && hasV("sonnema.com")
                && hasV("snoema.com") && hasV("sonema-paiement.com") && hasV("sonema-fr.com") && hasV("sonema-com.fr"), va.Count.ToString());
            Check("variantes : sans le domaine lui-même ni doublon", !hasV("sonema.com") && va.Select(x => x.Key).Distinct().Count() == va.Count);
            Check("variantes : nombre raisonnable", va.Count > 80 && va.Count < 400, va.Count.ToString());
            Check("variantes : pas de touche voisine", !hasV("sinema.com"));
            Check("SIREN : clé de Luhn", DomainAudit.IsValidSiren("449397173") && !DomainAudit.IsValidSiren("449397174") && !DomainAudit.IsValidSiren("12345"));
            Check("SIREN : RCS", DomainAudit.FindSiren("<footer>SONEMA SAS au capital de 10&nbsp;000 € – RCS Fréjus 449 397 173</footer>") == "449397173");
            Check("SIREN : SIRET", DomainAudit.FindSiren("<p>SIRET : <b>449 397 173 00047</b></p>") == "449397173");
            Check("SIREN : TVA", DomainAudit.FindSiren("N° TVA intracommunautaire : FR 12 449397173") == "449397173");
            Check("SIREN : numéro invalide ignoré", DomainAudit.FindSiren("Téléphone 04 94 12 34 56 – SIREN 449 397 174") == "");
            var ll = DomainAudit.LegalLinks("<a href='/fr/contact'>Contact</a><a href=\"/mentions-legales/\">Mentions légales</a><a href='https://autre.fr/legal'>x</a><a href='cgv.html'>CGV</a>", "https://www.sonema.com/");
            Check("mentions légales : liens", ll.Count == 2 && ll[0] == "https://www.sonema.com/mentions-legales/" && ll[1] == "https://www.sonema.com/cgv.html", string.Join(" ", ll.ToArray()));
            var snd = new List<string>();
            var au = DomainAudit.AuditRecords("sonema.com", new List<string> { "sonema-com.mail.protection.outlook.com" },
                new List<string> { "v=spf1 include:spf.protection.outlook.com include:spf.sendinblue.com -all", "google-site-verification=x" },
                new List<string> { "v=DMARC1; p=reject; rua=mailto:dmarc@sonema.com" }, new List<string>(), new List<string>(), new List<string>(), new List<string> { "selector1" }, snd);
            Check("bilan email : domaine protégé", au[0].Status == "ok" && !au.Any(x => x.Status == "bad"), string.Join(" | ", au.Select(x => x.Status + ":" + x.Title).ToArray()));
            Check("bilan email : services autorisés", snd.Contains("Microsoft 365") && snd.Contains("Brevo"), string.Join(",", snd.ToArray()));
            var au2 = DomainAudit.AuditRecords("x.fr", new List<string>(), new List<string> { "v=spf1 +all" }, new List<string>(), new List<string>(), new List<string>(), new List<string>(), new List<string>(), new List<string>());
            Check("bilan email : domaine usurpable", au2[0].Status == "bad" && au2.Any(x => x.Title.Contains("+all")) && au2.Any(x => x.Title == "Pas de DMARC"));
            var au3 = DomainAudit.AuditRecords("x.fr", new List<string> { "mx.x.fr" }, new List<string> { "v=spf1 mx ~all" }, new List<string> { "v=DMARC1; p=none" },
                new List<string>(), new List<string>(), new List<string>(), new List<string>(), new List<string>());
            Check("bilan email : p=none à améliorer", au3[0].Status == "warn" && au3.Any(x => x.Title.Contains("p=none")));
            const string CRT = "[{\"name_value\":\"sonema.com\\nwww.sonema.com\\nsonema.fr\",\"not_before\":\"2026-10-10T08:00:00\"},"
                + "{\"name_value\":\"*.sonema.com\\nsonema-group.com\",\"not_before\":\"2026-01-01T00:00:00\"},"
                + "{\"name_value\":\"a.com\\nb.com\\nc.com\\nd.com\\ne.com\\nsonema.com\",\"not_before\":\"2026-01-01T00:00:00\"},"
                + "{\"name_value\":\"sonema-paiement.net\\nwww.sonema-paiement.net\",\"not_before\":\"2026-10-12T00:00:00\"},"
                + "{\"name_value\":\"personema.com\",\"not_before\":\"2026-10-12T00:00:00\"}]";
            var rel = DomainAudit.ParseRelated(CRT, new[] { "sonema.com" });
            Check("certificats : domaines liés", rel.Count == 2 && rel.Any(x => x.Domain == "sonema.fr") && rel.Any(x => x.Domain == "sonema-group.com"), string.Join(",", rel.Select(x => x.Domain).ToArray()));
            var bc = DomainAudit.ParseBrandCerts(CRT, "sonema", new[] { "sonema.com" }, new DateTime(2026, 10, 1));
            Check("certificats : marque sur un autre domaine", bc.Count == 2 && bc.Any(x => x.Domain == "sonema-paiement.net") && bc.Any(x => x.Domain == "sonema.fr") && !bc.Any(x => x.Domain == "personema.com"),
                string.Join(",", bc.Select(x => x.Domain).ToArray()));
            Check("marque dans un nom", DomainAudit.BrandInHost("sonema-paiement.com", "sonema") && DomainAudit.BrandInHost("sonema.secure-login.net", "sonema")
                && DomainAudit.BrandInHost("compte-sonema.fr", "sonema") && !DomainAudit.BrandInHost("personema.com", "sonema"));
            Blocklists.SetForTests(new string[0], new string[0], new[] { "sonema-pay.com" });
            var eW = Base(); eW.FromAddress = "compta@sonema-pay.com";
            Check("surveillance : sosie apparu bloqué", Analyzer.Analyze(eW, cfg).Findings.Any(f => f.Id == "sender-blocklist-watch" && f.Severity == Severity.High), string.Join(",", Ids(Analyzer.Analyze(eW, cfg)).ToArray()));
            Blocklists.SetForTests(new string[0], new string[0]);

            // ---------- Rapport de signalement HTML ----------
            var e2b = Base(); e2b.FromName = e2.FromName; e2b.FromAddress = e2.FromAddress; e2b.Subject = e2.Subject; e2b.RawHeaders = FAIL;
            e2b.BodyText = "Connectez-vous ici : https://niicrosoft.com/owa/login.php avant ce soir.";
            e2b.Links.Add(new LinkInfo("https://niicrosoft.com/owa/login.php", "https://login.microsoftonline.com"));
            var rh = Analyzer.Analyze(e2b, cfg);
            string rhtml = ReportHtml.Build(rh, e2b, "Alex Test");
            Check("rapport HTML : points de doute", rhtml.Contains("Points de doute") && rhtml.Contains("En bref") && rhtml.Contains("Alex Test"));
            Check("rapport HTML : liens désarmés", rhtml.Contains("hxxps://niicrosoft[.]com") && !rhtml.Contains("https://niicrosoft.com") && !rhtml.Contains("<a "), rhtml.Length.ToString());
            Check("rapport HTML : copie du message", rhtml.Contains("Copie du message") && rhtml.Contains("Connectez-vous ici"));
            Check("rapport HTML : texte échappé", !ReportHtml.Build(rh, new EmailData { FromName = "<script>x</script>", FromAddress = "a@b.fr" }, "").Contains("<script>"));
            Check("désarmement du texte", ReportHtml.DefangText("voir http://a.b/c et https://x.y") == "voir hxxp://a[.]b/c et hxxps://x[.]y");

            // ---------- Plusieurs Authentication-Results du même serveur ----------
            var hd = Forensics.ParseHeaders("Authentication-Results: mx.sonema.com; dkim=pass header.d=x.fr\r\nAuthentication-Results: mx.sonema.com; spf=pass smtp.mailfrom=x.fr; dmarc=pass header.from=x.fr\r\nAuthentication-Results: mx.attaquant.net; spf=pass");
            Check("AR multiples : regroupés", hd.Auth.Spf == "pass" && hd.Auth.Dkim == "pass" && hd.Auth.Dmarc == "pass", hd.Auth.Spf + "/" + hd.Auth.Dkim + "/" + hd.Auth.Dmarc);
            var hd2 = Forensics.ParseHeaders("Authentication-Results: mx.sonema.com; dkim=pass header.d=x.fr\r\nAuthentication-Results: mx.attaquant.net; spf=pass; dmarc=pass");
            Check("AR d'un autre serveur ignoré", hd2.Auth.Spf == null && hd2.Auth.Dmarc == null);
            Check("rapport HTML : contrôles séparés", ReportHtml.Build(Analyzer.Analyze(Base(), cfg), Base(), "").Contains("</span>&nbsp;&nbsp; "));

            // ---------- Liens qui imitent un fichier ----------
            Func<string, string, AnalysisResult> withLink = (href, text) => { var x = Base(); x.Links.Add(new LinkInfo(href, text)); return Analyzer.Analyze(x, cfg); };
            Func<AnalysisResult, string, Severity, bool> hasSev = (rr, id, sev) => rr.Findings.Any(f => f.Id == id && f.Severity == sev);
            var lf1 = withLink("file://partage.attaquant.net/docs/fichier.txt.lnk", @"C:\hahkauz\fichier.txt");
            Check("lien file:// vers un raccourci", hasSev(lf1, "link-local-file", Severity.Critical), string.Join(",", Ids(lf1).ToArray()));
            Check("lien UNC externe", hasSev(withLink(@"\\srv.attaquant.net\partage\doc.docx", ""), "link-local-file", Severity.High));
            var lf2 = withLink("https://cdn.attaquant.xyz/f/fichier.lnk", @"C:\hahkauz\fichier.txt");
            Check("texte en forme de chemin", hasSev(lf2, "link-text-path", Severity.Critical), string.Join(",", Ids(lf2).ToArray()));
            Check("texte fichier .pdf, téléchargement .exe", hasSev(withLink("https://x-transfert.com/dl/facture.exe", "facture.pdf"), "link-text-filename", Severity.Critical));
            Check("document annoncé = document téléchargé", !Ids(withLink("https://x-transfert.com/dl/rapport.pdf", "rapport.pdf")).Contains("link-text-filename"));
            Check("lien search-ms:", hasSev(withLink(@"search-ms:query=facture&crumb=location:\\attaquant.net@SSL\DavWWWRoot", "Voir la facture"), "link-protocol", Severity.Critical));
            Check("lien ms-word distant", Ids(withLink("ms-word:ofe|u|https://attaquant.net/doc.docx", "Contrat")).Contains("link-office-remote"));

            // ---------- Mode simple ----------
            var sv = SimpleView.Build(r2, e2, true);
            Check("mode simple : verdict en clair", sv.Contains("Ce message est dangereux") && sv.Contains("Que dois-je faire ?") && sv.Contains("Pourquoi ?"));
            Check("mode simple : pas de jargon", !sv.Contains("DKIM") && !sv.Contains("SPF") && !sv.Contains("DMARC") && !sv.Contains("s-headers"));
            Check("mode simple : texte du message échappé", !SimpleView.Build(r2, new EmailData { FromName = "<script>x</script>", FromAddress = "a@b.fr" }, true).Contains("<script>x"));
            var eMoney = Base(); eMoney.BodyText = "Suite à un changement de banque, merci d'utiliser notre nouveau RIB : DE89 3704 0044 0532 0130 00";
            var rMoney = Analyzer.Analyze(eMoney, cfg);
            Check("mode simple : conseil coordonnées bancaires", rMoney.Level == "safe" || SimpleView.Actions(rMoney).Any(x => x.Key.Contains("bancaires")), rMoney.Level);
            Check("mode simple : message sain", SimpleView.Build(Analyzer.Analyze(Base(), cfg), Base(), true).Contains("Aucun danger"));   // HtmlEncode transforme les accents en entités

            // ---------- QR codes dans les images ----------
            Func<string, System.Drawing.Imaging.ImageFormat, bool, byte[]> qrImage = (text, fmt, inverted) =>
            {
                var qm = new ZXing.QrCode.QRCodeWriter().encode(text, ZXing.BarcodeFormat.QR_CODE, 240, 240);
                using (var qbmp = new System.Drawing.Bitmap(qm.Width + 80, qm.Height + 60))
                {
                    for (int qyy = 0; qyy < qbmp.Height; qyy++)
                        for (int qxx = 0; qxx < qbmp.Width; qxx++)
                        {
                            int qmx = qxx - 40, qmy = qyy - 30;
                            bool black = qmx >= 0 && qmy >= 0 && qmx < qm.Width && qmy < qm.Height && qm[qmx, qmy];
                            if (inverted) black = !black;
                            qbmp.SetPixel(qxx, qyy, black ? System.Drawing.Color.Black : System.Drawing.Color.White);
                        }
                    using (var qms = new System.IO.MemoryStream()) { qbmp.Save(qms, fmt); return qms.ToArray(); }
                }
            };
            var qd = QrScan.Decode(qrImage("https://quish.attaquant-test.com/login?id=42", System.Drawing.Imaging.ImageFormat.Png, false));
            Check("QR code lu dans un PNG", qd.Count == 1 && qd[0] == "https://quish.attaquant-test.com/login?id=42", string.Join("|", qd.ToArray()));
            Check("QR code lu dans un JPEG", QrScan.Decode(qrImage("https://x.fr/a", System.Drawing.Imaging.ImageFormat.Jpeg, false)).Contains("https://x.fr/a"));
            Check("QR code inversé (clair sur sombre)", QrScan.Decode(qrImage("https://x.fr/b", System.Drawing.Imaging.ImageFormat.Png, true)).Contains("https://x.fr/b"));
            using (var plain = new System.Drawing.Bitmap(200, 120))
            using (var ms2 = new System.IO.MemoryStream())
            {
                using (var qg = System.Drawing.Graphics.FromImage(plain)) qg.Clear(System.Drawing.Color.SteelBlue);
                plain.Save(ms2, System.Drawing.Imaging.ImageFormat.Png);
                Check("image sans QR code", QrScan.Decode(ms2.ToArray()).Count == 0);
            }
            Check("données qui ne sont pas une image", QrScan.Decode(new byte[5000]).Count == 0);
            var eQr = Base(); eQr.BodyText = "Scannez le code ci-dessous pour réactiver votre messagerie.";
            eQr.Attachments.Add(new AttachmentInfo { Name = "image001.png", IsInline = true, IsImage = true, QrCodes = new List<string> { "https://microsoft-verif.attaquant-test.com/login" } });
            var rQr = Analyzer.Analyze(eQr, cfg);
            Check("QR code : finding et lien analysé", Ids(rQr).Contains("link-qr-image") && rQr.Urls.Any(qu => qu.Contains("microsoft-verif.attaquant-test.com")), string.Join(",", Ids(rQr).ToArray()));

            // ---------- Assistant de démarrage ----------
            string[] setupSteps = { "intro", "language", "company", "report", "mode" };
            var cNew = new PhishGuardConfig();
            Check("assistant : première installation", cNew.PendingSetup(setupSteps, false).Count == 5);
            var cOld = new PhishGuardConfig { ReportAddress = "secu@x.fr", CompanyDomains = new List<string> { "x.fr" } };
            var pOld = cOld.PendingSetup(setupSteps, true);
            Check("assistant : mise à jour, seulement les nouveautés", pOld.Count == 1 && pOld[0] == "mode", string.Join(",", pOld.ToArray()));
            var cDone = new PhishGuardConfig { SetupKeyPresent = true, SetupDone = new List<string>(setupSteps) };
            Check("assistant : déjà vu", cDone.PendingSetup(setupSteps, true).Count == 0 && cDone.PendingSetup(setupSteps.Concat(new[] { "nouveau" }), true).SequenceEqual(new[] { "nouveau" }));

            // ---------- Plusieurs entreprises ----------
            var ceTest = CompanyEntry.Parse("Sonema | FR | 449397173 | Charles Dufourcq; Jean-Pierre Gorin");
            Check("entreprise : lecture", ceTest != null && ceTest.Name == "Sonema" && ceTest.Country == "FR" && ceTest.Id == "449397173" && ceTest.Directors.Count == 2);
            Check("entreprise : écriture", CompanyEntry.Parse(ceTest.Serialize()).Directors[1] == "Jean-Pierre Gorin");
            string tmpDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "pg-tests-" + Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(tmpDir);
            string adminIni = System.IO.Path.Combine(tmpDir, "config.ini"), userIni = System.IO.Path.Combine(tmpDir, "config.user.ini");
            System.IO.File.WriteAllText(adminIni, "CompanyName = Groupe Admin\r\nVipNames = Paul Admin\r\n");
            System.IO.File.WriteAllText(userIni, "CompanyName = Ancienne Société\r\nVipNames = Marie Dupont, Luc Martin\r\n");
            var cm = PhishGuardConfig.LoadMerged(adminIni, userIni);
            Check("entreprises : ancien format migré", cm.Companies.Count == 1 && cm.Companies[0].Name == "Ancienne Société" && cm.VipNames.Count == 2,
                string.Join(",", cm.Companies.Select(x => x.Name).ToArray()) + " / " + string.Join(",", cm.VipNames.ToArray()));
            cm.Companies.Add(new CompanyEntry { Name = "Filiale GmbH", Country = "Allemagne", Id = "Q1", Directors = new List<string> { "Hans Muster" } });
            cm.SaveUser(userIni);
            var cm2 = PhishGuardConfig.LoadMerged(adminIni, userIni);
            Check("entreprises : plusieurs, dirigeants réunis", cm2.Companies.Count == 2 && cm2.VipNames.Contains("Hans Muster") && cm2.VipNames.Contains("Marie Dupont") && cm2.CompanyName == "Ancienne Société",
                string.Join(",", cm2.VipNames.ToArray()));
            System.IO.File.WriteAllText(userIni, "Language = fr\r\n");
            var cm3 = PhishGuardConfig.LoadMerged(adminIni, userIni);
            Check("entreprises : celles de config.ini sans réglage utilisateur", cm3.Companies.Count == 1 && cm3.Companies[0].Name == "Groupe Admin" && cm3.VipNames.Contains("Paul Admin"));
            try { System.IO.Directory.Delete(tmpDir, true); } catch (Exception) { }
            var cfgMulti = new PhishGuardConfig { CompanyDomains = new List<string> { "acmetech.fr" } };
            cfgMulti.Companies.Add(new CompanyEntry { Name = "Acmetech" });
            cfgMulti.Companies.Add(new CompanyEntry { Name = "Nordwind Logistik" });
            cfgMulti.NormalizeCompanies();
            var eMulti = Base(); eMulti.FromName = "Nordwind Logistik - Buchhaltung"; eMulti.FromAddress = "buchhaltung@nordwind-rechnung.com";
            Check("entreprises : nom d'une filiale repéré", Ids(Analyzer.Analyze(eMulti, cfgMulti)).Contains("sender-company-name"));

            // Wikidata
            const string WD_SEARCH = "{\"search\":[{\"id\":\"Q2311\",\"label\":\"Airbus\"},{\"id\":\"Q999\",\"label\":\"Airbus (homonyme)\"}],\"success\":1}";
            const string WD_ENT = "{\"entities\":{\"Q2311\":{\"id\":\"Q2311\",\"labels\":{\"fr\":{\"language\":\"fr\",\"value\":\"Airbus\"}},\"claims\":{"
                + "\"P169\":[{\"mainsnak\":{\"datavalue\":{\"value\":{\"id\":\"Q100\"},\"type\":\"wikibase-entityid\"}},\"rank\":\"normal\"},"
                + "{\"mainsnak\":{\"datavalue\":{\"value\":{\"id\":\"Q101\"},\"type\":\"wikibase-entityid\"}},\"rank\":\"normal\",\"qualifiers\":{\"P582\":[{}]}}],"
                + "\"P17\":[{\"mainsnak\":{\"datavalue\":{\"value\":{\"id\":\"Q142\"},\"type\":\"wikibase-entityid\"}},\"rank\":\"normal\"}],"
                + "\"P856\":[{\"mainsnak\":{\"datavalue\":{\"value\":\"https://www.airbus.com/fr\",\"type\":\"string\"}},\"rank\":\"normal\"}]}},"
                + "\"Q999\":{\"id\":\"Q999\",\"labels\":{\"fr\":{\"language\":\"fr\",\"value\":\"Airbus (homonyme)\"}},\"claims\":{}}}}";
            const string WD_LAB = "{\"entities\":{\"Q100\":{\"labels\":{\"fr\":{\"value\":\"Guillaume Faury\"}}},\"Q101\":{\"labels\":{\"fr\":{\"value\":\"Ancien Dirigeant\"}}},\"Q142\":{\"labels\":{\"fr\":{\"value\":\"France\"}}}}}";
            var wdIds = CompanyLookup.SearchIds(WD_SEARCH);
            Check("wikidata : recherche", wdIds.Count == 2 && wdIds[0] == "Q2311");
            Check("wikidata : dirigeants actuels seulement", CompanyLookup.ReferencedIds(WD_ENT).Contains("Q100") && !CompanyLookup.ReferencedIds(WD_ENT).Contains("Q101"));
            var wdRes = CompanyLookup.ParseWikidata(wdIds, WD_ENT, WD_LAB, "fr");
            Check("wikidata : entreprise, pays, site, dirigeant (fiche renseignée en premier)", wdRes.Count == 2 && wdRes[1].Name == "Airbus (homonyme)" && wdRes[0].Name == "Airbus" && wdRes[0].Country == "France" && wdRes[0].Website == "airbus.com"
                && wdRes[0].Directors.Count == 1 && wdRes[0].Directors[0] == "Guillaume Faury", wdRes.Count > 0 ? wdRes[0].Name + "|" + wdRes[0].Country + "|" + wdRes[0].Website + "|" + string.Join(",", wdRes[0].Directors.ToArray()) : "aucun");

            // ---------- Contrôles issus du banc d'essai (corpus publics) ----------
            Correspondents.Set(new[] { "client@client-connu.fr" }, false);
            var bl = Base(); bl.FromAddress = "auteur@exemple-dev.org";
            bl.RawHeaders = PASS + "\r\nTo: dev@liste.apache.org\r\nList-Id: <dev.liste.apache.org>\r\nList-Post: <mailto:dev@liste.apache.org>\r\nReply-To: dev@liste.apache.org";
            bl.ReplyTo.Add("dev@liste.apache.org");
            var rbl = Analyzer.Analyze(bl, cfg);
            Check("liste de diffusion : ni Reply-To suspect ni premier contact", Ids(rbl).Contains("sender-replyto-list") && Ids(rbl).Contains("sender-first-contact-list")
                && !Ids(rbl).Contains("sender-replyto") && !Ids(rbl).Contains("sender-first-contact") && rbl.Level == "safe", string.Join(",", Ids(rbl).ToArray()) + " " + rbl.Level);
            var bl2 = Base(); bl2.FromAddress = "auteur@exemple-dev.org";
            bl2.RawHeaders = PASS + "\r\nTo: vous@acmetech.fr\r\nList-Id: <fausse.liste>\r\nList-Post: <mailto:attaquant@pirate.example>";
            Check("fausse liste (adressée à vous) : premier contact conservé", Ids(Analyzer.Analyze(bl2, cfg)).Contains("sender-first-contact"));

            var mb = Base(); mb.FromAddress = "it-desk@serveur-inconnu.example"; mb.Subject = "Incoming messages failed for vous@acmetech.fr";
            mb.RawHeaders = PASS + "\r\nTo: vous@acmetech.fr";
            mb.BodyText = "Dear vous@acmetech.fr, 6 incoming messages are placed on hold. Sign in to release pending messages immediately.";
            mb.Links.Add(new LinkInfo("https://site-pirate.example/owa", "Release messages"));
            var rmb = Analyzer.Analyze(mb, cfg);
            Check("fausse alerte de messagerie : adresse dans l'objet, combinaison, dangereux", Ids(rmb).Contains("content-recipient-subject") && Ids(rmb).Contains("content-mailbox")
                && Ids(rmb).Contains("content-combo-mailbox") && rmb.Level == "dangerous", string.Join(",", Ids(rmb).ToArray()) + " " + rmb.Score);
            var gr = Base(); gr.FromAddress = "x@inconnu.example"; gr.RawHeaders = PASS + "\r\nTo: vous@acmetech.fr"; gr.BodyText = "Hello vous@acmetech.fr, see attached.";
            Check("salutation par l'adresse", Ids(Analyzer.Analyze(gr, cfg)).Contains("content-recipient-greeting"));
            var cap = Base(); cap.FromAddress = "x@inconnu.example"; cap.Subject = "Action requise";
            cap.BodyText = "Votre compte sera suspendu. Connectez-vous immédiatement pour vérifier votre compte et votre mot de passe.";
            var rcap = Analyzer.Analyze(cap, cfg);
            Check("combinaison décisive hors plafond du contenu", Ids(rcap).Contains("content-combo-cred") && rcap.Score > 8 + 30, rcap.Score.ToString());
            // Vrais mails de marques authentifiés (cas difficiles du banc d'essai)
            var li = Base(); li.FromName = "LinkedIn"; li.FromAddress = "security-noreply@linkedin.com"; li.Subject = "Voici le lien pour réinitialiser votre mot de passe";
            li.RawHeaders = "Authentication-Results: spf=pass smtp.mailfrom=bounce.linkedin.com; dkim=pass header.d=linkedin.com;dmarc=pass action=none header.from=linkedin.com;compauth=pass reason=100";
            li.BodyText = "Nous avons reçu une demande de réinitialisation du mot de passe. Ce lien expirera dans 24 heures, connectez-vous immédiatement.";
            li.Links.Add(new LinkInfo("https://www.linkedin.com/e/v2?e=abc", "Réinitialiser mon mot de passe"));
            var rli = Analyzer.Analyze(li, cfg);
            Check("marque authentifiée : réinitialisation de mot de passe = vert", rli.Level == "safe" && !Ids(rli).Contains("content-first-contact-request"), rli.Level + " " + string.Join(",", Ids(rli).ToArray()));
            var fakeLi = Base(); fakeLi.FromName = "LinkedIn"; fakeLi.FromAddress = "security@linkedin-secure.example"; fakeLi.Subject = li.Subject; fakeLi.BodyText = li.BodyText;
            fakeLi.RawHeaders = PASS; fakeLi.Links.Add(new LinkInfo("https://linkedin-secure.example/login", "Réinitialiser"));
            Check("même texte depuis un autre domaine = alerte", Analyzer.Analyze(fakeLi, cfg).Level != "safe");
            var hot = Base(); hot.FromName = "Microsoft"; hot.FromAddress = "support.microsoft@outlook.fr"; hot.Subject = li.Subject; hot.BodyText = li.BodyText;
            hot.RawHeaders = "Authentication-Results: spf=pass smtp.mailfrom=outlook.fr; dkim=pass header.d=outlook.fr;dmarc=pass action=none header.from=outlook.fr;compauth=pass reason=100";
            Check("messagerie gratuite d'une marque : pas de passe-droit", Analyzer.Analyze(hot, cfg).Level != "safe");
            var ds = Base(); ds.FromName = "Cabinet Lefèvre via DocuSign"; ds.FromAddress = "dse_NA4@docusign.net"; ds.Subject = "Veuillez signer : contrat";
            ds.RawHeaders = "Authentication-Results: spf=pass smtp.mailfrom=docusign.net; dkim=pass header.d=docusign.net;dmarc=pass action=none header.from=docusign.net;compauth=pass reason=100\r\nReply-To: contact@cabinet-lefevre.fr";
            ds.ReplyTo.Add("contact@cabinet-lefevre.fr"); ds.BodyText = "Cabinet Lefèvre vous a envoyé un document à signer via DocuSign.";
            var rds = Analyzer.Analyze(ds, cfg);
            Check("plateforme de signature : Reply-To faible, vert", rds.Level == "safe" && rds.Findings.Any(f => f.Id == "sender-replyto" && f.Severity == Severity.Low), rds.Level + " " + rds.Score);
            var gd = Base(); gd.FromName = "Inconnu (via Google Drive)"; gd.FromAddress = "drive-shares-dm-noreply@google.com";
            gd.Subject = "Item shared with you: \"We Have Limited Your Login ID Due to Unrecognized Sign-In\"";
            gd.RawHeaders = "Authentication-Results: spf=pass smtp.mailfrom=google.com; dkim=pass header.d=google.com;dmarc=pass action=none header.from=google.com;compauth=pass reason=100\r\nReply-To: attaquant@exemple-inconnu.example";
            gd.ReplyTo.Add("attaquant@exemple-inconnu.example"); gd.BodyText = "Inconnu a partagé un document avec vous.";
            var rgd = Analyzer.Analyze(gd, cfg);
            Check("vrai partage Google Drive dont le titre est une fausse alerte = alerte", rgd.Level != "safe" && Ids(rgd).Contains("content-combo-platform"), rgd.Level + " " + string.Join(",", Ids(rgd).ToArray()));
            var tech = Base(); tech.FromName = "Jane Doe via dev"; tech.FromAddress = "jane.doe@salesforce.com.invalid"; tech.Subject = "Re: consumer not receiving messages";
            tech.RawHeaders = PASS + "\r\nTo: dev@liste.apache.org\r\nList-Id: <dev.liste.apache.org>\r\nList-Post: <mailto:dev@liste.apache.org>";
            tech.BodyText = "Try http://localhost:8083/connectors and check the password in your SSL config.";
            tech.Links.Add(new LinkInfo("http://localhost:8083/connectors", "")); tech.Links.Add(new LinkInfo("http://127.0.0.1:9092", ""));
            Correspondents.Set(new[] { "client@client-connu.fr" }, false);
            var rtech = Analyzer.Analyze(tech, cfg);
            Check("liste technique : localhost et adresse .invalid ne sont pas des indices", rtech.Level == "safe" && !Ids(rtech).Any(i => i.StartsWith("link-") || i.Contains("lookalike")),
                rtech.Level + " " + string.Join(",", Ids(rtech).ToArray()));
            // Vrai code de connexion (service inconnu, boîte Orange : DMARC dans ARC) et ses imitations
            Func<string, EmailData> riot = link =>
            {
                var m = Base(); m.FromName = "Riot Games"; m.FromAddress = "noreply@mail.accounts.riotgames.com"; m.Subject = "Login Code: 360928";
                m.RawHeaders = "Authentication-Results: opmta1mti36nd1;\r\n\tarc=none;\r\n\tdkim=pass header.d=mail.accounts.riotgames.com\r\n"
                    + "ARC-Authentication-Results: i=1; opmta1mti36nd1; spf=pass smtp.mailfrom=bounces@sg.mail.accounts.riotgames.com; dkim=pass header.d=mail.accounts.riotgames.com; dmarc=pass header.from=mail.accounts.riotgames.com\r\n"
                    + "To: claire.martin@orange.fr";
                m.BodyText = "Here's your sign-in code: 360928. This code will expire soon. If this request did not come from you, change your account password immediately to prevent further unauthorized access.";
                m.Links.Add(new LinkInfo(link, "Account Management"));
                // logo et pixel d'espacement hébergés par la plateforme d'envoi, recopiés dans la version texte par Outlook
                m.Links.Add(new LinkInfo("https://cdn.mcauto-images-production.sendgrid.net/6c2047/e457af/8x8.png", ""));
                return m;
            };
            Correspondents.Set(new[] { "client@client-connu.fr" }, false);
            var rriot = Analyzer.Analyze(riot("https://links.riotgames.com/ls/click?upn=abc"), cfg);
            Check("vrai code de connexion (anglais) = vert", rriot.Level == "safe" && Ids(rriot).Contains("content-code-message") && !Ids(rriot).Contains("content-combo-cred"),
                rriot.Level + " " + rriot.Score + " " + string.Join(",", Ids(rriot).ToArray()));
            var rriotEvil = Analyzer.Analyze(riot("https://riot-account-secure.example/login"), cfg);
            Check("même texte avec un lien vers un autre site = alerte", rriotEvil.Level != "safe" && !Ids(rriotEvil).Contains("content-code-message"), rriotEvil.Level + " " + rriotEvil.Score);
            var vin = Base(); vin.FromName = "Vinted"; vin.FromAddress = "no-reply@vinted.fr"; vin.Subject = "Votre code de vérification Vinted";
            vin.RawHeaders = "Authentication-Results: spf=pass smtp.mailfrom=bounce.vinted.fr; dkim=pass header.d=vinted.fr;dmarc=pass action=none header.from=vinted.fr;compauth=pass reason=100";
            vin.BodyText = "Voici votre code de vérification : 482 913. Si vous n’êtes pas à l’origine de cette demande, modifiez immédiatement votre mot de passe.";
            vin.Links.Add(new LinkInfo("https://www.vinted.fr/help", "Centre d’aide"));
            var rvin = Analyzer.Analyze(vin, cfg);
            Check("vrai code de vérification (français) = vert", rvin.Level == "safe" && Ids(rvin).Contains("content-code-message"), rvin.Level + " " + rvin.Score);
            vin.Attachments.Add(new AttachmentInfo { Name = "verification.html", ContentType = "text/html" });
            Check("même message avec une pièce jointe : plus de passe-droit", !Ids(Analyzer.Analyze(vin, cfg)).Contains("content-code-message"));
            Correspondents.Reset();
            Correspondents.Set(new[] { "client@client-connu.fr" }, false);
            foreach (var local in new[] { "no_reply", "do_not_reply", "ne_pas_repondre", "do-not-reply" })
            {
                var nr = Base(); nr.FromAddress = local + "@service-exemple.example"; nr.RawHeaders = PASS;
                Check("adresse automatique reconnue : " + local, Ids(Analyzer.Analyze(nr, cfg)).Contains("sender-first-contact-auto"));
            }
            Correspondents.Reset();
            // Organismes publics : .gouv.fr (réservé à l'État) et liste du secteur public
            Correspondents.Set(new[] { "client@client-connu.fr" }, false);
            var gv = Base(); gv.FromName = "Service des amendes"; gv.FromAddress = "ne-pas-repondre@amendes.exemple.gouv.fr"; gv.Subject = "Avis de paiement disponible";
            gv.RawHeaders = "Authentication-Results: spf=pass smtp.mailfrom=amendes.exemple.gouv.fr; dkim=pass header.d=exemple.gouv.fr;dmarc=pass action=none header.from=exemple.gouv.fr;compauth=pass reason=100";
            gv.BodyText = "Un avis de paiement de 35 EUR est disponible. Connectez-vous à votre espace pour régler l'amende avant 45 jours.";
            var rgv = Analyzer.Analyze(gv, cfg);
            Check(".gouv.fr authentifié = vert, organisme public reconnu", rgv.Level == "safe" && rgv.Trust.Any(x => x.Contains(".gouv.fr")), rgv.Level + " " + rgv.Score + " " + string.Join(",", Ids(rgv).ToArray()));
            var gvFake = Base(); gvFake.FromName = "Service des amendes"; gvFake.FromAddress = "ne-pas-repondre@amendes-gouv.example"; gvFake.Subject = gv.Subject; gvFake.BodyText = gv.BodyText; gvFake.RawHeaders = PASS;
            Check("même texte hors .gouv.fr : pas de passe-droit", !Analyzer.Analyze(gvFake, cfg).Trust.Any(x => x.Contains("gouv")));
            Feeds.LoadPublicSector(new[] { "name,http_status,https_status,SIREN,type,sources,script", "mairie-exemple.fr,200 OK,,,Commune,,", "www.hopital-exemple.fr,,,,Santé,,", "commune-x.wixsite.com,,,,Commune,," }, DateTime.Now);
            Feeds.PublicSectorEnabled = true;
            Check("liste du secteur public : domaine, sous-domaine, www retiré", Feeds.IsPublicSector("mairie-exemple.fr") && Feeds.IsPublicSector("mail.mairie-exemple.fr") && Feeds.IsPublicSector("hopital-exemple.fr"));
            Check("liste du secteur public : hébergements partagés écartés", !Feeds.IsPublicSector("commune-x.wixsite.com") && !Feeds.IsPublicSector("wixsite.com") && !Feeds.IsPublicSector("autre-exemple.fr"));
            var mr = Base(); mr.FromName = "Mairie"; mr.FromAddress = "accueil@mairie-exemple.fr"; mr.Subject = "Votre facture de cantine";
            mr.RawHeaders = "Authentication-Results: spf=pass smtp.mailfrom=mairie-exemple.fr; dkim=pass header.d=mairie-exemple.fr;dmarc=pass action=none header.from=mairie-exemple.fr;compauth=pass reason=100";
            mr.BodyText = "Votre facture est disponible. Paiement en ligne par carte bancaire avant le 15.";
            var rmr = Analyzer.Analyze(mr, cfg);
            Check("organisme de la liste, authentifié = vert", rmr.Level == "safe" && rmr.Trust.Any(x => x.Contains("organisme public")), rmr.Level + " " + rmr.Score);
            Feeds.LoadPublicSector(new string[0], DateTime.MinValue); Feeds.PublicSectorEnabled = false;

            // Domaine qui ressemble à votre entreprise, mais géré par ses serveurs DNS : même propriétaire
            Check("preuve de propriétaire : serveurs DNS de la marque", Intel.OwnerProof("acmetech.eu", new[] { "ns1.acmetech.fr." }, "", new HashSet<string> { "acmetech.fr" }, d => false).Found);
            Check("preuve de propriétaire : hébergeur DNS partagé = pas de preuve", !Intel.OwnerProof("acmetech.eu", new[] { "lara.ns.cloudflare.com" }, "", new HashSet<string> { "acmetech.fr" }, d => true).Found);
            Check("preuve de propriétaire : rapports DMARC autorisés par le domaine officiel", Intel.OwnerProof("acmetech.eu", new string[0], "v=DMARC1; p=reject; rua=mailto:rua@dmarc.acmetech.fr", new HashSet<string> { "acmetech.fr" }, d => d == "dmarc.acmetech.fr").Found
                && !Intel.OwnerProof("acmetech.eu", new string[0], "v=DMARC1; p=reject; rua=mailto:rua@dmarc.acmetech.fr", new HashSet<string> { "acmetech.fr" }, d => false).Found);
            var ow = Base(); ow.FromName = "Acmetech"; ow.FromAddress = "no-reply@acmetech.eu"; ow.Subject = "Confirmation de votre commande";
            ow.RawHeaders = "Authentication-Results: spf=pass smtp.mailfrom=acmetech.eu; dkim=pass header.d=acmetech.eu;dmarc=pass action=none header.from=acmetech.eu;compauth=pass reason=100";
            ow.BodyText = "Votre commande est confirmée.";
            Intel.Settings.DnsChecks = true;
            var rowBefore = Analyzer.Analyze(ow, cfg);
            Intel.SetForTests(Intel.OwnerKey("acmetech.eu", new[] { "acmetech.fr" }), new IntelResult { Ok = true, Found = true, Label = "serveur DNS ns1.acmetech.fr" });
            var rowAfter = Analyzer.Analyze(ow, cfg);
            Check("sosie de l'entreprise signalé tant que la preuve n'est pas arrivée", Ids(rowBefore).Any(i => i.Contains("lookalike")), string.Join(",", Ids(rowBefore).ToArray()));
            Check("sosie de l'entreprise géré par ses serveurs DNS : rattaché, plus signalé", Ids(rowAfter).Contains("sender-owner-proven") && !Ids(rowAfter).Any(i => i.Contains("lookalike")),
                rowAfter.Level + " " + string.Join(",", Ids(rowAfter).ToArray()));
            var owSpoof = Base(); owSpoof.FromName = ow.FromName; owSpoof.FromAddress = ow.FromAddress; owSpoof.Subject = ow.Subject; owSpoof.BodyText = ow.BodyText; owSpoof.RawHeaders = FAIL;
            Check("même domaine mais authentification en échec : preuve ignorée", !Ids(Analyzer.Analyze(owSpoof, cfg)).Contains("sender-owner-proven"));
            Intel.Settings.DnsChecks = false; Intel.ClearForTests();
            Correspondents.Reset();
            var orf = Base(); orf.FromName = "Orange"; orf.FromAddress = "facture@orange.fr"; orf.Subject = "Votre facture est disponible";
            orf.RawHeaders = "Authentication-Results: spf=pass smtp.mailfrom=mail.orange.fr; dkim=pass header.d=orange.fr;dmarc=pass action=none header.from=orange.fr;compauth=pass reason=100";
            Check("Orange depuis une adresse de service authentifiée", !Ids(Analyzer.Analyze(orf, cfg)).Contains("sender-brand-name"));
            orf.FromAddress = "orange.service.clients2026@orange.fr";
            Check("Orange depuis une boîte orange.fr quelconque = signalé", Ids(Analyzer.Analyze(orf, cfg)).Contains("sender-brand-name"));
            Correspondents.Reset();
            L.SetLanguage("en");
            Check("anglais : nouveaux indices traduits", rmb.Findings.Count > 0 && Analyzer.Analyze(mb, cfg).Findings.All(f => !f.Title.Contains("’")),
                string.Join(" | ", Analyzer.Analyze(mb, cfg).Findings.Select(f => f.Title).ToArray()));
            L.SetLanguage("fr");

            // ---------- Langue anglaise ----------
            L.SetLanguage("en");
            var rEn = Analyzer.Analyze(e2, cfg);
            Check("anglais : verdict", rEn.LevelLabel == "Dangerous", rEn.LevelLabel);
            Check("anglais : libellés", Analyzer.SeverityLabel(Severity.High) == "High" && L.T("Paramètres") == "Settings" && L.F("{0} liens", 3) == "3 links");
            Check("anglais : indices traduits", rEn.Findings.All(f => !f.Title.Contains("’")), string.Join(" | ", rEn.Findings.Select(f => f.Title).ToArray()));
            Check("anglais : explications", Lessons.For("auth-dmarc").StartsWith("DMARC checks"));
            Check("anglais : texte inconnu inchangé", L.T("texte absent du dictionnaire") == "texte absent du dictionnaire");
            L.SetLanguage("fr");
            Check("retour au français", Analyzer.Analyze(e2, cfg).LevelLabel == "Dangereux" && L.T("Paramètres") == "Paramètres");
            Check("traductions chargées", L.Count > 400, L.Count.ToString());

            Console.WriteLine();
            Console.WriteLine("Tests : " + passed + " réussis, " + failed + " en échec.");
            try { System.IO.File.WriteAllText(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "tests-result.txt"), failed.ToString()); }
            catch (Exception) { }
            return failed == 0 ? 0 : 1;
        }
    }
}
