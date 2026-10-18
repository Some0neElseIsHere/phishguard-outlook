// PhishGuard - moteur d'analyse : authentification, expéditeur, liens, pièces jointes, contenu, score.
// Portage fidèle de src/engine/*.js (C# 5).

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace PhishGuard
{
    public static class Analyzer
    {
        public static readonly Dictionary<string, string> CategoryLabels = new Dictionary<string, string>
        {
            { "auth", "Authentification" }, { "sender", "Expéditeur" }, { "links", "Liens" },
            { "attachments", "Pièces jointes" }, { "content", "Contenu" }, { "filter", "Filtres de messagerie" }
        };

        static int Points(Severity s)
        {
            switch (s)
            {
                case Severity.Low: return 8;
                case Severity.Medium: return 20;
                case Severity.High: return 40;
                case Severity.Critical: return 70;
            }
            return 0;
        }

        /// <summary>Libellé traduit d'une catégorie (auth, sender, links...).</summary>
        public static string CategoryLabel(string key)
        {
            string label;
            return CategoryLabels.TryGetValue(key ?? "", out label) ? L.T(label) : key;
        }

        public static string SeverityLabel(Severity s)
        {
            switch (s)
            {
                case Severity.Critical: return L.T("Critique");
                case Severity.High: return L.T("Élevé");
                case Severity.Medium: return L.T("Moyen");
                case Severity.Low: return L.T("Faible");
            }
            return L.T("Info");
        }

        class Ctx
        {
            public PhishGuardConfig Config;
            public DomainContext Domains;
            public bool Internal;
            public bool IsFreemail;
            public bool IsCompany;
            public string FromOrg = "";
            public bool HasArchive;
            public bool FirstContact;
            public bool SenderTrusted;
            public bool AuthOk;          // DMARC valide, ou SPF et DKIM valides
            // Preuves de légitimité (affichées dans la fenêtre d'analyse ; ne masquent jamais un indice Élevé ou Critique)
            public List<string> Trust = new List<string>();
            public bool AuthProof;       // l'expéditeur affiché est authentifié (DMARC, DKIM aligné, compauth 1xx)
            public bool RelationProof;   // relation établie avec vous : correspondant connu, réponse à votre message, expéditeur de confiance
            public bool BulkCompliant;   // envoi en nombre conforme (désabonnement en un clic + DMARC)
            public bool BrandSender;     // authentifié sur le domaine officiel d'une marque (hors messageries gratuites et plateformes)
            public bool Platform;        // plateforme qui relaie les messages de ses clients (partage, signature…), authentifiée
        }

        // =====================================================================
        // Point d'entrée
        // =====================================================================

        public static AnalysisResult Analyze(EmailData e, PhishGuardConfig config)
        {
            var ctx = new Ctx { Config = config, Domains = PhishGuard.Domains.BuildContext(config) };
            var headers = ParseHeaders(e.RawHeaders);
            var findings = new List<Finding>();
            var positives = new List<string>();

            AnalyzeAuth(e, headers, ctx, findings, positives);
            AnalyzeSender(e, headers, ctx, findings, positives);
            AnalyzeThread(e, headers, ctx, findings);
            var urls = new List<string>();
            var linkDomains = new List<string>();
            AnalyzeLinks(e, ctx, findings, urls, linkDomains);
            var attNames = new List<string>();
            AnalyzeAttachments(e, ctx, findings, attNames);
            AnalyzeContent(e, headers, ctx, findings);
            AnalyzeFilters(e, headers, ctx, findings);
            var details = Forensics.ParseHeaders(e.RawHeaders);
            var sources = new List<SourceStatus>();
            AnalyzeIntel(e, ctx, details, findings, positives, urls, linkDomains, sources);

            // Envoi en nombre conforme aux règles Gmail/Yahoo/Microsoft : le ton commercial n'est pas un indice
            if (ctx.BulkCompliant && !ctx.Internal)
                foreach (var f in findings)
                    if (f.Category == "content" && f.Severity == Severity.Low) f.Severity = Severity.Info;

            // Domaine officiel d'une marque, authentifié : le texte (code, facture, mot de passe) est celui de la marque elle-même
            if (ctx.BrandSender)
                foreach (var f in findings)
                    if (f.Category == "content" && f.Severity != Severity.Critical)
                        f.Severity = f.Severity > Severity.Low ? Severity.Low : Severity.Info;

            if (ctx.Internal)
            {
                foreach (var f in findings)
                    if (f.Category == "content" && f.Severity != Severity.Critical)
                        f.Severity = f.Severity > Severity.Low ? Severity.Low : Severity.Info;
            }

            // Expéditeur marqué « de confiance » par l'utilisateur
            if (ctx.SenderTrusted)
            {
                bool authFailed = findings.Any(f => f.Category == "auth" && f.Severity >= Severity.Medium);
                if (authFailed)
                    findings.Add(new Finding("sender-trusted-spoof", "sender", Severity.High, L.T("Expéditeur de confiance, mais authentification en échec"),
                        L.T("Vous faites confiance à cet expéditeur, mais ce message n’a pas été envoyé par ses serveurs : possible usurpation."), new[] { e.FromAddress }));
                else
                {
                    foreach (var f in findings)
                        if ((f.Category == "sender" || f.Category == "content" || f.Category == "filter") && f.Severity < Severity.Critical) f.Severity = Severity.Info;
                    positives.Add(L.T("Expéditeur marqué de confiance par vous"));
                    ctx.Trust.Add(L.T("Expéditeur marqué de confiance par vous"));
                    ctx.RelationProof = true;
                }
            }

            findings = findings.OrderByDescending(f => (int)f.Severity).ToList();

            // Les mots-clés de contenu sont plafonnés (un message commercial en contient beaucoup) ; les combinaisons
            // décisives (identifiants + urgence, paiement + discrétion, fausse alerte de messagerie, changement de RIB) ne le sont pas.
            // Barème validé sur des corpus publics : voir docs/banc-essai.md.
            int score = 0, contentScore = 0;
            foreach (var f in findings)
            {
                if (f.Category == "content" && !IsDecisiveContent(f.Id)) contentScore += Points(f.Severity);
                else score += Points(f.Severity);
            }
            score = Math.Min(100, score + Math.Min(30, contentScore));

            bool hasCritical = findings.Any(f => f.Severity == Severity.Critical);
            string level = hasCritical || score >= 50 ? "dangerous" : score >= 20 ? "suspicious" : "safe";
            // « Expéditeur vérifié » : authentifié ET connu (relation ou réputation), sans aucun indice Faible ou plus
            bool verified = !ctx.Internal && ctx.AuthProof && ctx.RelationProof && level == "safe"
                && !findings.Any(f => f.Severity >= Severity.Low);

            var r = new AnalysisResult
            {
                Score = score,
                Level = level,
                Internal = ctx.Internal,
                Findings = findings,
                Positives = positives.Distinct().ToList(),
                Urls = urls.Distinct().ToList(),
                LinkDomains = linkDomains.Distinct().ToList(),
                AttachmentNames = attNames,
                SenderAddress = (e.FromAddress ?? "").ToLowerInvariant(),
                Details = details,
                Sources = sources,
                Attachments = e.Attachments.Where(a => !(a.IsInline && a.IsImage)).ToList(),
                FirstContact = ctx.FirstContact,
                Trust = ctx.Trust.Distinct().ToList(),
                Verified = verified,
                SenderDomain = PhishGuard.Domains.DomainOfAddress(e.FromAddress)
            };
            if (level == "dangerous") { r.LevelLabel = L.T("Dangereux"); r.Advice = L.T("Ne cliquez sur aucun lien, n’ouvrez aucune pièce jointe et signalez ce message."); }
            else if (level == "suspicious") { r.LevelLabel = L.T("Suspect"); r.Advice = L.T("Ne cliquez pas et n’ouvrez rien avant d’avoir vérifié l’expéditeur par un autre moyen."); }
            else { r.LevelLabel = L.T("Aucun indice important"); r.Advice = L.T("Restez vigilant : aucun outil ne détecte 100 % des attaques."); }
            return r;
        }

        // =====================================================================
        // Outils
        // =====================================================================

        static readonly Regex BrandServiceLocal = new Regex(@"^(no-?reply|ne-?pas-?repondre|ne_pas_repondre|noreply|facture|factures|facturation|service-?client|serviceclient|info|infos|information|notifications?|alertes?|securite|security|contact|newsletter)([._+-].*)?$",
            RegexOptions.IgnoreCase);

        static bool IsPlatformSender(string fromDomain)
        {
            string org = PhishGuard.Domains.RegistrableDomain(fromDomain ?? "");
            if (org == "google.com") return !(fromDomain ?? "").Equals("accounts.google.com", StringComparison.OrdinalIgnoreCase);
            return Lists.PlatformSenders.Contains(org);
        }

        static bool IsDecisiveContent(string id)
        {
            return id.StartsWith("content-combo-") || id == "content-iban-change";
        }

        public static string NormalizeText(string s)
        {
            string t = PhishGuard.Domains.RemoveDiacritics((s ?? "").ToLowerInvariant());
            t = Regex.Replace(t, "[’'`]", " ");
            return Regex.Replace(t, @"\s+", " ").Trim();
        }

        public static List<KeyValuePair<string, string>> ParseHeaders(string raw)
        {
            var list = new List<KeyValuePair<string, string>>();
            if (string.IsNullOrEmpty(raw)) return list;
            foreach (var line in raw.Replace("\r\n", "\n").Split('\n'))
            {
                if (line.Length > 0 && (line[0] == ' ' || line[0] == '\t') && list.Count > 0)
                {
                    var last = list[list.Count - 1];
                    list[list.Count - 1] = new KeyValuePair<string, string>(last.Key, last.Value + " " + line.Trim());
                }
                else
                {
                    int i = line.IndexOf(':');
                    if (i > 0) list.Add(new KeyValuePair<string, string>(line.Substring(0, i).Trim().ToLowerInvariant(), line.Substring(i + 1).Trim()));
                }
            }
            return list;
        }

        static List<string> HeaderValues(List<KeyValuePair<string, string>> headers, string name)
        {
            string n = name.ToLowerInvariant();
            return headers.Where(h => h.Key == n).Select(h => h.Value).ToList();
        }

        static readonly Regex AddressRe = new Regex(@"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}");

        static List<string> AddressesIn(string value)
        {
            var list = new List<string>();
            foreach (Match m in AddressRe.Matches(value ?? "")) list.Add(m.Value.ToLowerInvariant());
            return list;
        }

        static string ExtensionOf(string name)
        {
            string n = (name ?? "").ToLowerInvariant().Trim();
            int i = n.LastIndexOf('.');
            return i >= 0 ? n.Substring(i + 1) : "";
        }

        static string Pick(string pattern, string s)
        {
            var m = Regex.Match(s ?? "", pattern, RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value.ToLowerInvariant() : null;
        }

        static bool WordMatch(string haystack, string needle)
        {
            string n = Regex.Escape(NormalizeText(needle));
            return Regex.IsMatch(haystack, "(^|[^a-z0-9])" + n + "($|[^a-z0-9])");
        }

        static Finding LookalikeFinding(Lookalike look, string where, string category)
        {
            string target = look.IsCompany ? L.T("votre domaine ") + look.Target : look.Brand + " (" + look.Target + ")";
            string shown = look.UnicodeHost != look.Host ? look.UnicodeHost + " (" + look.Host + ")" : look.Host;
            return new Finding(category + "-lookalike-" + look.Technique, category, look.Severity,
                where + L.T(" imite ") + target, L.T("Technique : ") + look.TechniqueText + ".", new[] { shown });
        }

        static Finding BlocklistFinding(BlocklistHit hit, string title, string category, IEnumerable<string> evidence)
        {
            string date = hit.SourceId == "redflagdomains" && hit.Updated > DateTime.MinValue ? L.F(" (liste du {0})", hit.Updated.ToString("dd/MM/yyyy")) : "";
            return new Finding(category + "-blocklist-" + hit.SourceId, category, hit.Severity, title,
                L.T("Source : ") + L.T(hit.SourceName) + date + ".", evidence);
        }

        // =====================================================================
        // Authentification (SPF, DKIM, DMARC, compauth)
        // =====================================================================

        static void AnalyzeAuth(EmailData e, List<KeyValuePair<string, string>> headers, Ctx ctx, List<Finding> findings, List<string> positives)
        {
            string fromDomain = PhishGuard.Domains.DomainOfAddress(e.FromAddress);
            string fromOrg = PhishGuard.Domains.RegistrableDomain(fromDomain);
            bool fromCompany = ctx.Domains.CompanyDomains.Contains(fromOrg);

            string authAs = (HeaderValues(headers, "x-ms-exchange-organization-authas").FirstOrDefault() ?? "").ToLowerInvariant();
            if (e.IsExchangeInternal || authAs == "internal")
            {
                positives.Add(L.T("Message interne, authentifié par votre serveur Exchange"));
                ctx.Internal = true;
                return;
            }
            if (headers.Count == 0)
            {
                findings.Add(new Finding("auth-noheaders", "auth", Severity.Info, L.T("En-têtes Internet indisponibles"),
                    L.T("Les contrôles SPF/DKIM/DMARC n’ont pas pu être vérifiés."), null));
                return;
            }

            string arSource;
            string ar = Forensics.AuthResultsText(headers, out arSource);
            string spf = Pick(@"\bspf=([a-z]+)", ar);
            string dkim = Pick(@"\bdkim=([a-z]+)", ar);
            string dmarc = Pick(@"\bdmarc=([a-z]+)", ar);
            string compauth = Pick(@"\bcompauth=([a-z]+)", ar);
            string headerFrom = Pick(@"header\.from=([^\s;]+)", ar);
            if (spf == null)
            {
                string rspf = HeaderValues(headers, "received-spf").FirstOrDefault();
                if (rspf != null) spf = Pick(@"^\s*([a-z]+)", rspf);
            }

            if (ar.Length == 0 && spf == null)
            {
                findings.Add(new Finding("auth-missing", "auth", Severity.Low, L.T("Aucun résultat d’authentification"),
                    L.T("Le message ne contient pas d’en-tête Authentication-Results : impossible de vérifier l’expéditeur."), null));
                return;
            }

            if (dmarc == "fail")
                findings.Add(new Finding("auth-dmarc", "auth", fromCompany ? Severity.Critical : Severity.High,
                    fromCompany ? L.T("Usurpation de votre propre domaine (DMARC en échec)") : L.T("Échec DMARC : l’expéditeur affiché n’est pas authentifié"),
                    L.T("Le domaine affiché dans « De » n’a pas autorisé ce message. C’est le signe classique d’une usurpation."), new[] { fromDomain }));
            string reason = Pick(@"\breason=(\d+)", ar) ?? "";
            if (compauth == "fail")
            {
                string why = reason.Length > 0 ? L.F(" (raison {0})", reason) : "";
                if (reason == "010" || reason.StartsWith("6"))
                    findings.Add(new Finding("auth-compauth-intra", "auth", Severity.Critical, L.T("Microsoft détecte une usurpation de votre propre domaine"),
                        L.T("Exchange (compauth=fail") + why + L.T(") : le message se présente comme venant de votre organisation sans en venir."), new[] { fromDomain }));
                else if (reason == "001")
                    findings.Add(new Finding("auth-compauth", "auth", Severity.Medium, L.T("Authentification Microsoft insuffisante"),
                        L.T("Exchange (compauth=fail, raison 001) n’a pas pu relier ce message au domaine affiché, qui n’a pas de DMARC strict. Courant pour les petits domaines mal configurés, suspect si d’autres indices existent."), new[] { fromDomain }));
                else if (reason == "002")
                    findings.Add(new Finding("auth-compauth", "auth", Severity.High, L.T("Envoi interdit par le propriétaire du domaine"),
                        L.T("Exchange (compauth=fail, raison 002) : votre organisation bloque explicitement les messages de ce domaine sans authentification."), new[] { fromDomain }));
                else
                    findings.Add(new Finding("auth-compauth", "auth", Severity.High, L.T("Microsoft signale une authentification composite en échec"),
                        L.T("Exchange (compauth=fail") + why + L.T(") estime que l’expéditeur ne peut pas être authentifié."), new[] { fromDomain }));
            }
            if (spf == "fail")
                findings.Add(new Finding("auth-spf", "auth", dmarc == "fail" ? Severity.Low : Severity.Medium, L.T("Échec SPF"),
                    L.T("Le serveur qui a envoyé ce message n’est pas autorisé par le domaine de l’expéditeur."), null));
            else if (spf == "softfail")
                findings.Add(new Finding("auth-spf-soft", "auth", Severity.Low, L.T("SPF « softfail »"),
                    L.T("Le serveur d’envoi n’est pas clairement autorisé par le domaine de l’expéditeur."), null));
            if (dkim == "fail")
                findings.Add(new Finding("auth-dkim", "auth", Severity.Medium, L.T("Signature DKIM invalide"),
                    L.T("Le message a pu être modifié en chemin, ou la signature est falsifiée."), null));
            if (fromCompany && dmarc != "pass" && spf != "pass" && dkim != "pass")
                findings.Add(new Finding("auth-company-unauth", "auth", Severity.Critical, L.T("Message « interne » venant de l’extérieur"),
                    L.T("L’expéditeur utilise un domaine de votre entreprise mais le message vient de l’extérieur et n’est pas authentifié."), new[] { fromDomain }));

            if (spf == "pass") positives.Add(L.T("SPF valide"));
            if (dkim == "pass") positives.Add(L.T("Signature DKIM valide"));
            if (dmarc == "pass") positives.Add(L.T("DMARC valide pour ") + (headerFrom ?? fromDomain));
            ctx.AuthOk = dmarc == "pass" || (spf == "pass" && dkim == "pass" && dmarc != "fail");

            // Alignement : la signature DKIM / l'enveloppe SPF appartiennent-elles au domaine affiché ?
            var dkimPass = new List<string>();
            foreach (Match m in Regex.Matches(ar, @"\bdkim=pass\b[^;]*?\bheader\.d=([^\s;]+)", RegexOptions.IgnoreCase))
                dkimPass.Add(m.Groups[1].Value.ToLowerInvariant().TrimEnd('.'));
            bool dkimAligned = fromOrg.Length > 0 && dkimPass.Any(d => PhishGuard.Domains.RegistrableDomain(d) == fromOrg);
            string mailFrom = Pick(@"smtp\.mailfrom=([^\s;]+)", ar) ?? "";
            string mailFromDomain = mailFrom.Contains("@") ? PhishGuard.Domains.DomainOfAddress(mailFrom) : mailFrom.TrimEnd('.');
            bool spfAligned = spf == "pass" && fromOrg.Length > 0 && PhishGuard.Domains.RegistrableDomain(mailFromDomain) == fromOrg;
            bool dmarcOk = dmarc == "pass";
            bool compStrong = compauth == "pass" && reason.StartsWith("1");

            if (dkimAligned && dmarc != "fail")
                ctx.Trust.Add(L.F("Signé (DKIM) par le domaine de l’expéditeur : {0}", dkimPass.First(d => PhishGuard.Domains.RegistrableDomain(d) == fromOrg)));
            else if (dkimPass.Count > 0 && fromOrg.Length > 0)
                findings.Add(new Finding("auth-dkim-thirdparty", "auth", Severity.Info, L.T("Signature DKIM d’un autre domaine que l’expéditeur"),
                    L.T("Normal pour un envoi par un prestataire (newsletter, outil d’emailing) : cette signature ne prouve pas l’identité de l’expéditeur affiché."),
                    dkimPass.Take(3).Select(d => "d=" + d)));
            if (dmarcOk)
                ctx.Trust.Add(L.F("DMARC valide : le domaine {0} a autorisé ce message", headerFrom ?? fromDomain));
            if (spfAligned && dmarc != "fail")
                ctx.Trust.Add(L.T("Serveur d’envoi autorisé par le domaine de l’expéditeur (SPF aligné)"));
            if (compStrong)
                ctx.Trust.Add(reason == "130" ? L.T("Microsoft : authentification validée par une chaîne ARC de confiance (raison 130)")
                    : L.F("Microsoft : authentification composite réussie (raison {0})", reason));
            else if ((compauth == "pass" || compauth == "softpass") && reason.StartsWith("7"))
                ctx.Trust.Add(L.F("Microsoft : expéditeur reconnu d’après son historique d’envoi (raison {0})", reason));
            ctx.AuthProof = dmarc != "fail" && compauth != "fail" && (dmarcOk || compStrong || dkimAligned);

            // Envoi en nombre conforme : désabonnement en un clic (RFC 8058) et DMARC valide
            string unsub = string.Join(" ", HeaderValues(headers, "list-unsubscribe").ToArray());
            string unsubPost = string.Join(" ", HeaderValues(headers, "list-unsubscribe-post").ToArray());
            if (dmarcOk && unsub.IndexOf("https://", StringComparison.OrdinalIgnoreCase) >= 0
                && unsubPost.IndexOf("List-Unsubscribe=One-Click", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                ctx.BulkCompliant = true;
                ctx.Trust.Add(L.T("Envoi en nombre conforme (désabonnement en un clic, DMARC valide)"));
            }

            string rp = AddressesIn(HeaderValues(headers, "return-path").FirstOrDefault()).FirstOrDefault();
            string rpOrg = PhishGuard.Domains.RegistrableDomain(PhishGuard.Domains.DomainOfAddress(rp));
            if (!string.IsNullOrEmpty(rp) && fromOrg.Length > 0 && rpOrg.Length > 0 && rpOrg != fromOrg)
                findings.Add(new Finding("auth-returnpath", "auth", Severity.Info, L.T("Adresse de retour différente de l’expéditeur"),
                    L.T("Courant pour les envois de masse (newsletters), mais à garder en tête si d’autres indices existent."), new[] { rp }));
        }

        // =====================================================================
        // Fil de discussion : réponse à l'un de vos messages ?
        // =====================================================================

        static void AnalyzeThread(EmailData e, List<KeyValuePair<string, string>> headers, Ctx ctx, List<Finding> findings)
        {
            if (ctx.Internal || ctx.FromOrg.Length == 0) return;
            var ids = new List<string>();
            foreach (var h in HeaderValues(headers, "in-reply-to"))
                foreach (Match m in Regex.Matches(h, @"<([^<>\s]+)>")) ids.Add(m.Groups[1].Value);
            var refs = new List<string>();
            foreach (var h in HeaderValues(headers, "references"))
                foreach (Match m in Regex.Matches(h, @"<([^<>\s]+)>")) refs.Add(m.Groups[1].Value);
            refs.Reverse();   // le plus récent d'abord
            ids.AddRange(refs);

            string[] orgs = null;
            foreach (var id in ids.Take(30)) { orgs = Correspondents.ThreadRecipients(id); if (orgs != null) break; }
            if (orgs == null) return;

            string fromAddr = (e.FromAddress ?? "").ToLowerInvariant();
            string sentTo = string.Join(", ", orgs.Take(4).ToArray());
            if (orgs.Contains(ctx.FromOrg) || ctx.IsCompany)
            {
                ctx.Trust.Add(L.F("Réponse à un message que vous avez envoyé ({0})", sentTo));
                ctx.RelationProof = true;
            }
            else if (!ctx.SenderTrusted && !Correspondents.IsKnownAddress(fromAddr) && (ctx.IsFreemail || !Correspondents.IsKnownDomain(ctx.FromOrg)))
                findings.Add(new Finding("sender-thread-hijack", "sender", Severity.High, L.T("Réponse à votre message, mais depuis une autre organisation"),
                    L.T("Ce message répond à un email que vous avez envoyé à d’autres destinataires. Les fraudeurs reprennent de vraies conversations pour faire changer un RIB ou payer une facture : vérifiez par téléphone."),
                    new[] { L.T("Envoyé à : ") + sentTo, L.T("Réponse de : ") + fromAddr }));
        }

        // =====================================================================
        // Expéditeur
        // =====================================================================

        static void AnalyzeSender(EmailData e, List<KeyValuePair<string, string>> headers, Ctx ctx, List<Finding> findings, List<string> positives)
        {
            var cfg = ctx.Config;
            string fromAddr = (e.FromAddress ?? "").ToLowerInvariant();
            string fromName = e.FromName ?? "";
            string fromDomain = PhishGuard.Domains.DomainOfAddress(fromAddr);
            string fromOrg = PhishGuard.Domains.RegistrableDomain(fromDomain);
            bool isCompany = ctx.Domains.CompanyDomains.Contains(fromOrg);
            bool isFreemail = Lists.FreemailDomains.Contains(fromDomain);
            string nameNorm = NormalizeText(fromName);
            ctx.IsFreemail = isFreemail; ctx.IsCompany = isCompany; ctx.FromOrg = fromOrg;
            if (fromAddr.Length == 0) return;
            ctx.SenderTrusted = cfg.TrustedSenders.Contains(fromAddr)
                || (!isFreemail && cfg.TrustedDomains.Any(t => PhishGuard.Domains.RegistrableDomain(t) == fromOrg));

            // Premier contact et sosies de vos correspondants (fournisseurs, clients...)
            if (cfg.KnownCorrespondents && Correspondents.Loaded && !isCompany && !ctx.Internal && !e.IsExchangeInternal)
            {
                bool knownAddr = Correspondents.IsKnownAddress(fromAddr);
                bool knownDomain = !isFreemail && Correspondents.IsKnownDomain(fromOrg);
                // Liste de diffusion : le message est adressé à la liste (son adresse de publication figure dans À/Cc), pas à vous
                var postAddrs = AddressesIn(string.Join(",", HeaderValues(headers, "list-post")));
                var toCc = AddressesIn(string.Join(",", HeaderValues(headers, "to").Concat(HeaderValues(headers, "cc"))));
                bool mailingList = HeaderValues(headers, "list-id").Count > 0 && postAddrs.Any(a => toCc.Contains(a));
                if (!knownAddr && !knownDomain && mailingList)
                    findings.Add(new Finding("sender-first-contact-list", "sender", Severity.Info, L.T("Message d’une liste de diffusion"),
                        L.T("Adressé à la liste, pas directement à vous : ne pas connaître l’auteur est normal."), new[] { postAddrs.First(a => toCc.Contains(a)) }));
                else if (!knownAddr && !knownDomain)
                {
                    ctx.FirstContact = true;
                    // Adresse automatique (noreply, notification...) authentifiée : normal de ne jamais lui avoir écrit.
                    // Le premier contact reste pris en compte si le message demande un paiement ou des identifiants.
                    if ((IsAutomatedAddress(fromAddr) || IsPlatformSender(fromDomain)) && ctx.AuthOk)
                        findings.Add(new Finding("sender-first-contact-auto", "sender", Severity.Info, L.T("Premier message de cette adresse automatique"),
                            L.T("Adresse d’envoi automatique authentifiée : ne pas lui avoir écrit est normal."), new[] { fromAddr }));
                    else
                        findings.Add(new Finding("sender-first-contact", "sender", Severity.Low, L.T("Premier message d’un expéditeur inconnu"),
                            L.T("Vous n’avez jamais écrit à cette adresse ni à ce domaine."), new[] { fromAddr }));
                }
                else if (!knownAddr)
                    findings.Add(new Finding("sender-new-address", "sender", Severity.Info, L.T("Nouvelle adresse d’un domaine connu"), "", new[] { fromAddr }));
                if (knownAddr) { ctx.Trust.Add(L.F("Vous avez déjà écrit à {0}", fromAddr)); ctx.RelationProof = true; }
                else if (knownDomain) { ctx.Trust.Add(L.F("Vous avez déjà écrit à ce domaine ({0})", fromOrg)); ctx.RelationProof = true; }
                if (!knownDomain && !ctx.Domains.Legit.Contains(fromOrg))
                    CheckCorrespondentLookalike(fromDomain, L.T("Le domaine de l’expéditeur"), findings);
            }

            // Âge du domaine (RDAP)
            CheckDomainAge(fromOrg, L.T("Le domaine de l’expéditeur"), "sender-new-domain", ctx, findings);

            var look = PhishGuard.Domains.DetectLookalike(fromDomain, ctx.Domains);
            if (look != null) findings.Add(LookalikeFinding(look, L.T("Le domaine de l’expéditeur"), "sender"));
            var listed = Blocklists.Lookup(fromDomain);
            if (listed != null) findings.Add(BlocklistFinding(listed, L.T("Le domaine de l’expéditeur figure dans une liste de domaines malveillants"), "sender", new[] { PhishGuard.Domains.ToUnicode(listed.Domain) }));

            if (fromDomain.EndsWith(".onmicrosoft.com") && !cfg.CompanyDomains.Contains(fromDomain))
                findings.Add(new Finding("sender-onmicrosoft", "sender", Severity.Medium, L.T("Envoyé depuis un tenant Microsoft 365 générique"),
                    L.T("Les adresses *.onmicrosoft.com sont créées en quelques minutes ; les entreprises sérieuses utilisent leur propre domaine."), new[] { fromDomain }));

            var nameAddrs = AddressesIn(fromName).Where(a => a != fromAddr).ToList();
            if (nameAddrs.Count > 0)
                findings.Add(new Finding("sender-name-address", "sender", Severity.High, L.T("Le nom affiché contient une autre adresse"),
                    L.T("Le nom affiché montre une adresse qui n’est pas l’adresse réelle de l’expéditeur."), new[] { L.T("Affiché : ") + nameAddrs[0], L.T("Réel : ") + fromAddr }));

            foreach (var b in Lists.Brands)
            {
                if (!b.Names.Any(n => WordMatch(nameNorm, n))) continue;
                bool brandDomain = b.Domains.Any(d => PhishGuard.Domains.RegistrableDomain(d) == fromOrg);
                // Opérateur qui est aussi une messagerie gratuite (orange.fr, free.fr…) : seules ses adresses de service authentifiées comptent
                bool owns = brandDomain && (!isFreemail || (ctx.AuthOk && BrandServiceLocal.IsMatch(fromAddr.Split('@')[0])));
                if (!owns)
                {
                    findings.Add(new Finding("sender-brand-name", "sender", ctx.Internal ? Severity.Info : isFreemail ? Severity.High : Severity.Medium,
                        L.T("Se présente comme « ") + b.Name + L.T(" » sans utiliser un domaine ") + b.Name,
                        isFreemail ? L.T("Le message vient d’une messagerie gratuite.") : L.T("Le domaine d’envoi n’appartient pas à cette marque."),
                        new[] { fromName + " <" + fromAddr + ">" }));
                    break;
                }
            }

            if (!isCompany)
            {
                string vip = cfg.VipNames.FirstOrDefault(v => !string.IsNullOrEmpty(v) && WordMatch(nameNorm, v));
                if (vip != null)
                    findings.Add(new Finding("sender-vip", "sender", Severity.High, L.T("Le nom affiché est celui de ") + vip + L.T(", mais l’adresse est externe"),
                        L.T("Technique typique de la « fraude au président » : vérifiez par téléphone avant toute action."), new[] { fromAddr }));
                else if (cfg.CompanyNames().Any(cn => NormalizeText(cn).Length >= 3 && WordMatch(nameNorm, cn)))
                {
                    string companyShown = cfg.CompanyNames().First(cn => NormalizeText(cn).Length >= 3 && WordMatch(nameNorm, cn));
                    findings.Add(new Finding("sender-company-name", "sender", Severity.Medium, L.T("Le nom affiché mentionne ") + companyShown + L.T(", mais l’adresse est externe"),
                        "", new[] { fromAddr }));
                }
            }

            ctx.Platform = ctx.AuthOk && IsPlatformSender(fromDomain);
            ctx.BrandSender = ctx.AuthProof && !isFreemail && !ctx.Internal && !ctx.Platform && look == null
                && Lists.Brands.Any(b => b.Domains.Any(d => PhishGuard.Domains.RegistrableDomain(d) == fromOrg));
            if (ctx.BrandSender)
            {
                var brand = Lists.Brands.First(b => b.Domains.Any(d => PhishGuard.Domains.RegistrableDomain(d) == fromOrg));
                ctx.Trust.Add(L.F("Envoyé et authentifié par un domaine officiel de {0}", brand.Name));
                positives.Add(L.F("Envoyé et authentifié par un domaine officiel de {0}", brand.Name));
                ctx.RelationProof = true;   // réputation de la marque : suffit pour « Expéditeur vérifié » s'il n'y a aucun indice
            }

            var replyTo = new List<string>();
            foreach (var r in e.ReplyTo) if (!string.IsNullOrEmpty(r)) replyTo.Add(r.ToLowerInvariant());
            replyTo.AddRange(AddressesIn(string.Join(",", HeaderValues(headers, "reply-to"))));
            var listPost = AddressesIn(string.Join(",", HeaderValues(headers, "list-post")));
            foreach (var rt in replyTo.Distinct())
            {
                string rtDomain = PhishGuard.Domains.DomainOfAddress(rt);
                string rtOrg = PhishGuard.Domains.RegistrableDomain(rtDomain);
                if (rtOrg.Length == 0 || rtOrg == fromOrg) continue;
                // Liste de diffusion : les réponses vont à la liste elle-même (son adresse de publication)
                if (listPost.Contains(rt))
                {
                    findings.Add(new Finding("sender-replyto-list", "sender", Severity.Info, L.T("Les réponses partiront vers la liste de diffusion"),
                        "", new[] { L.T("Réponse vers : ") + rt }));
                    continue;
                }
                bool rtFree = Lists.FreemailDomains.Contains(rtDomain);
                // Partage ou signature électronique : la plateforme met l'adresse de la personne qui envoie le document
                var rtSev = ctx.Platform ? (rtFree ? Severity.Medium : Severity.Low) : rtFree || isCompany ? Severity.High : Severity.Medium;
                findings.Add(new Finding("sender-replyto", "sender", rtSev,
                    L.T("Les réponses partiront vers une autre adresse (Reply-To)"),
                    rtFree ? L.T("L’adresse de réponse est une messagerie gratuite.") : L.T("Le domaine de réponse est différent du domaine de l’expéditeur."),
                    new[] { L.T("Réponse vers : ") + rt }));
                CheckDomainAge(rtOrg, L.T("Le domaine de réponse"), "sender-new-replyto-domain", ctx, findings);
                if (cfg.KnownCorrespondents && Correspondents.Loaded && !Correspondents.IsKnownDomain(rtOrg) && !ctx.Domains.Legit.Contains(rtOrg))
                    CheckCorrespondentLookalike(rtDomain, L.T("Le domaine de réponse"), findings);
                var rtListed = Blocklists.Lookup(rtDomain);
                if (rtListed != null) findings.Add(BlocklistFinding(rtListed, L.T("Le domaine de réponse figure dans une liste de domaines malveillants"), "sender", new[] { rtListed.Domain }));
                var rtLook = PhishGuard.Domains.DetectLookalike(rtDomain, ctx.Domains);
                if (rtLook != null) findings.Add(LookalikeFinding(rtLook, L.T("Le domaine de réponse"), "sender"));
                break;
            }

            string senderAddr = (e.SenderAddress ?? "").ToLowerInvariant();
            if (senderAddr.Length > 0 && senderAddr != fromAddr && PhishGuard.Domains.RegistrableDomain(PhishGuard.Domains.DomainOfAddress(senderAddr)) != fromOrg)
                findings.Add(new Finding("sender-onbehalf", "sender", Severity.Info, L.T("Envoyé « de la part de » une autre adresse"), "",
                    new[] { L.T("Expéditeur technique : ") + senderAddr }));

            if (isCompany) positives.Add(L.T("Domaine de l’expéditeur : votre entreprise"));
            else if (ctx.Domains.Legit.Contains(fromOrg) && look == null) positives.Add(L.T("Domaine connu : ") + PhishGuard.Domains.ToUnicode(fromOrg));
        }


        // =====================================================================
        // Correspondants connus et âge des domaines
        // =====================================================================

        static readonly System.Text.RegularExpressions.Regex AutomatedLocal = new System.Text.RegularExpressions.Regex(
            @"^(no-?reply|ne-?pas-?repondre|do-?not-?reply|donotreply|noreponse|notifications?|alerts?|mailer-daemon|bounce[s]?|newsletter|news|info|mailing|system|automated|account-security-noreply)([._+-].*)?$",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

        /// <summary>Adresse d'envoi automatique (noreply@, notification@...) à laquelle on n'écrit jamais.</summary>
        public static bool IsAutomatedAddress(string address)
        {
            string a = (address ?? "").Trim();
            int at = a.IndexOf('@');
            if (at <= 0) return false;
            string local = a.Substring(0, at);
            return AutomatedLocal.IsMatch(local) || local.IndexOf("noreply", StringComparison.OrdinalIgnoreCase) >= 0
                || local.IndexOf("no-reply", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        static void CheckCorrespondentLookalike(string host, string where, List<Finding> findings)
        {
            foreach (var known in Correspondents.LookalikeTargets())
            {
                string t = PhishGuard.Domains.LookalikeOfKnown(host, known);
                if (t == null) continue;
                findings.Add(new Finding("sender-correspondent-lookalike", "sender", t == "tld" ? Severity.Medium : Severity.High,
                    where + L.T(" imite celui d’un de vos correspondants"),
                    L.T("Technique : ") + PhishGuard.Domains.TechniqueLabel(t) + L.T(". Vérifiez par téléphone avant tout paiement ou changement de coordonnées."),
                    new[] { L.T("Reçu : ") + PhishGuard.Domains.ToUnicode(PhishGuard.Domains.RegistrableDomain(host)), L.T("Votre correspondant : ") + known }));
                return;
            }
        }

        static void CheckDomainAge(string registrable, string where, string id, Ctx ctx, List<Finding> findings)
        {
            if (!ctx.Config.DomainAgeLookup || string.IsNullOrEmpty(registrable)) return;
            if (ctx.Domains.Legit.Contains(registrable) || ctx.Domains.CompanyDomains.Contains(registrable) || Lists.FreemailDomains.Contains(registrable)) return;
            DateTime? created;
            if (!DomainAge.TryGetCreated(registrable, out created)) { DomainAge.Request(registrable); return; }
            if (!created.HasValue) return;
            int days = (int)(DateTime.UtcNow - created.Value).TotalDays;
            if (days < 0) days = 0;
            string when = L.F("créé le {0} (il y a {1} jour{2})", created.Value.ToLocalTime().ToString("dd/MM/yyyy"), days, days > 1 ? "s" : "");
            if (days < 30)
                findings.Add(new Finding(id, id.StartsWith("link") ? "links" : "sender", Severity.High, where + L.T(" a été créé très récemment"),
                    L.T("Les domaines de phishing sont souvent utilisés dans les jours qui suivent leur création."), new[] { registrable + " : " + when }));
            else if (days < 90)
                findings.Add(new Finding(id, id.StartsWith("link") ? "links" : "sender", Severity.Low, where + L.T(" est récent"), "", new[] { registrable + " : " + when }));
        }

        // =====================================================================
        // Liens
        // =====================================================================

        static readonly string[] RedirectParams = { "url", "u", "q", "target", "redirect", "redirect_uri", "redirecturl", "dest", "destination", "next", "goto", "link", "r" };

        static Uri SafeUri(string href)
        {
            string h = (href ?? "").Trim();
            if (h.Length == 0) return null;
            if (h.StartsWith("www.", StringComparison.OrdinalIgnoreCase)) h = "http://" + h;
            if (!Regex.IsMatch(h, "^https?://", RegexOptions.IgnoreCase)) return null;
            Uri u;
            return Uri.TryCreate(h, UriKind.Absolute, out u) ? u : null;
        }

        static string QueryParam(Uri u, string name)
        {
            string q = u.Query;
            if (q.StartsWith("?")) q = q.Substring(1);
            foreach (var pair in q.Split('&'))
            {
                int i = pair.IndexOf('=');
                string k = i >= 0 ? pair.Substring(0, i) : pair;
                if (!string.Equals(Uri.UnescapeDataString(k.Replace('+', ' ')), name, StringComparison.OrdinalIgnoreCase)) continue;
                return i >= 0 ? Uri.UnescapeDataString(pair.Substring(i + 1).Replace('+', ' ')) : "";
            }
            return null;
        }

        static string HostOf(Uri u)
        {
            string h;
            try { h = u.IdnHost; } catch (Exception) { h = u.Host; }
            return (h ?? "").ToLowerInvariant().Trim('[', ']');
        }

        public static Uri UnwrapUrl(string href, List<string> chain)
        {
            string opaque;
            return UnwrapUrl(href, chain, out opaque);
        }

        /// <summary>
        /// Retire les réécritures des passerelles de sécurité (Proofpoint, Safe Links...), les redirections
        /// Google et les redirections ouvertes. Dans chain, les services de sécurité sont notés « sec:Nom ».
        /// opaque reçoit le nom du service quand celui-ci ne laisse pas lire la vraie destination.
        /// </summary>
        public static Uri UnwrapUrl(string href, List<string> chain, out string opaque)
        {
            opaque = null;
            var url = SafeUri(href);
            for (int i = 0; url != null && i < 5; i++)
            {
                string host = HostOf(url);
                string next = null, kind = null;
                var rw = Rewriters.Decode(url, host, (x, n) => QueryParam(x, n));
                if (rw != null)
                {
                    if (rw.Target == null) { opaque = rw.Service; break; }
                    next = rw.Target; kind = "sec:" + rw.Service;
                }
                else if (Regex.IsMatch(host, @"(^|\.)google\.[a-z.]+$") && url.AbsolutePath == "/url") { next = QueryParam(url, "q") ?? QueryParam(url, "url"); kind = "google"; }
                else
                {
                    foreach (var p in RedirectParams)
                    {
                        string v = QueryParam(url, p);
                        if (v != null && Regex.IsMatch(v, "^https?://", RegexOptions.IgnoreCase)) { next = v; kind = "redirect"; break; }
                    }
                }
                var nextUrl = next != null ? SafeUri(next) : null;
                if (nextUrl == null) break;
                if (chain != null) chain.Add(kind == "redirect" ? host : kind);
                url = nextUrl;
            }
            return url;
        }

        static readonly Regex DomainInText = new Regex(@"\b((?:https?://)?(?:[a-z0-9¡-￿-]+\.)+[a-z¡-￿]{2,})(?:[/:?#]|\b)", RegexOptions.IgnoreCase);

        static bool HostMatches(string host, IEnumerable<string> list)
        {
            foreach (var d in list) if (host == d || host.EndsWith("." + d)) return true;
            return false;
        }

        // Protocoles qui lancent une application Windows au lieu d'ouvrir une page web
        static readonly HashSet<string> DangerousSchemes = new HashSet<string>(new[] {
            "search-ms", "search", "ms-msdt", "ms-officecmd", "ms-appinstaller", "ms-cxh", "ms-cxh-full", "mk", "its", "ms-its",
            "ms-search", "ms-settings", "shell", "ms-excel-addin", "vbefile", "jar", "ms-distributed-transaction-coordinator", "ms-diagnostics" });
        static readonly HashSet<string> OfficeSchemes = new HashSet<string>(new[] { "ms-word", "ms-excel", "ms-powerpoint", "ms-visio", "ms-access", "ms-project", "ms-publisher", "ms-spd", "ms-infopath" });
        static readonly Regex PathTextRe = new Regex(@"^(?:[a-z]:[\\/]|\\\\[^\\\s]+\\|file:)", RegexOptions.IgnoreCase);
        static readonly Regex FileNameTextRe = new Regex(@"^[^\\/:*?""<>|]{1,100}\.[a-z0-9]{2,5}$", RegexOptions.IgnoreCase);

        class Issue { public Severity Severity; public string Title; public string Detail; public List<string> Evidence = new List<string>(); }

        static void AnalyzeLinks(EmailData e, Ctx ctx, List<Finding> findings, List<string> urls, List<string> domains)
        {
            var issues = new Dictionary<string, Issue>();
            var order = new List<string>();
            Action<string, Severity, string, string, string> add = (id, sev, title, detail, ev) =>
            {
                Issue it;
                if (!issues.TryGetValue(id, out it)) { it = new Issue { Severity = sev, Title = title, Detail = detail }; issues[id] = it; order.Add(id); }
                if (!string.IsNullOrEmpty(ev) && !it.Evidence.Contains(ev)) it.Evidence.Add(ev);
            };
            var lookalikes = new Dictionary<string, Lookalike>();
            var listedBySource = new Dictionary<string, List<string>>();
            var firstHitBySource = new Dictionary<string, BlocklistHit>();
            var sourceOrder = new List<string>();

            var fileExts = new HashSet<string>(Lists.ExtExecutable.Concat(Lists.ExtDiskImage).Concat(Lists.ExtHtml).Concat(Lists.ExtMacro)
                .Concat(Lists.ExtOneNote).Concat(Lists.ExtArchive).Concat(Lists.ExtDocument).Concat(new[] { "php", "asp", "aspx", "jsp" }));
            fileExts.Remove("com");
            var downloadExts = new HashSet<string>(Lists.ExtExecutable.Concat(Lists.ExtDiskImage).Concat(Lists.ExtHtml).Concat(Lists.ExtMacro).Concat(Lists.ExtArchive));
            downloadExts.ExceptWith(new[] { "htm", "html", "shtml" });

            var allLinks = new List<LinkInfo>(e.Links);
            foreach (var att in e.Attachments)
                foreach (var u in att.EmbeddedUrls) allLinks.Add(new LinkInfo(u, ""));
            // QR codes trouvés dans les images : l'adresse est analysée comme un lien (« quishing »)
            foreach (var att in e.Attachments)
                foreach (var q in att.QrCodes)
                {
                    string qt = (q ?? "").Trim();
                    bool isUrl = Regex.IsMatch(qt, @"^(https?://|www\.)", RegexOptions.IgnoreCase);
                    string ev = (isUrl ? Defang(qt) : qt).Length > 100 ? (isUrl ? Defang(qt) : qt).Substring(0, 100) + "…" : (isUrl ? Defang(qt) : qt);
                    if (isUrl)
                    {
                        allLinks.Add(new LinkInfo(qt.StartsWith("www.", StringComparison.OrdinalIgnoreCase) ? "https://" + qt : qt, ""));
                        add("link-qr-image", ctx.Internal ? Severity.Low : Severity.Medium, L.T("QR code à scanner dans une image"),
                            L.T("Scanner un QR code avec son téléphone contourne les protections de l’entreprise : c’est la technique du « quishing ». L’adresse qu’il contient est analysée avec les autres liens."), ev);
                    }
                    else
                        add("link-qr-image-text", Severity.Info, L.T("QR code dans une image (sans adresse web)"), "", ev);
                }
            var ageChecked = new HashSet<string>();
            var corrChecked = new HashSet<string>();
            var rewrittenBy = new List<string>();
            var opaqueServices = new List<string>();

            foreach (var link in allLinks)
            {
                string raw = (link.Href ?? "").Trim();
                if (raw.Length == 0 || Regex.IsMatch(raw, "^(mailto:|tel:|cid:|#|data:image)", RegexOptions.IgnoreCase)) continue;
                string ltext = Regex.Replace(link.Text ?? "", @"\s+", " ").Trim();
                string rawShort = raw.Length > 100 ? raw.Substring(0, 100) + "…" : raw;
                string shownEv = ltext.Length > 0 && ltext != raw ? L.T("Affiché : ") + (ltext.Length > 60 ? ltext.Substring(0, 60) + "…" : ltext) + L.T(" → Réel : ") + rawShort : rawShort;
                // Texte qui imite un fichier : chemin (C:\…, \\serveur\…) ou nom de document (facture.pdf, fichier.txt)
                bool textIsPath = PathTextRe.IsMatch(ltext);
                string textExt = ExtensionOf(ltext);
                bool textIsFileName = !textIsPath && FileNameTextRe.IsMatch(ltext) && (Lists.ExtDocument.Contains(textExt) || Lists.ExtHtml.Contains(textExt));
                var schemeMatch = Regex.Match(raw, @"^([a-z][a-z0-9+.\-]{1,40}):", RegexOptions.IgnoreCase);
                string scheme = schemeMatch.Success ? schemeMatch.Groups[1].Value.ToLowerInvariant() : "";

                // Lien vers un fichier du poste ou d'un partage réseau (file://, \\serveur\partage, C:\…)
                if (scheme == "file" || raw.StartsWith(@"\\") || Regex.IsMatch(raw, @"^[a-z]:[\\/]", RegexOptions.IgnoreCase))
                {
                    string target = raw;
                    try { target = Uri.UnescapeDataString(raw); } catch (Exception) { }
                    string tExt = ExtensionOf(target.TrimEnd('/', '\\'));
                    bool risky = Lists.ExtExecutable.Contains(tExt) || Lists.ExtDiskImage.Contains(tExt) || Lists.ExtMacro.Contains(tExt) || tExt.Length == 0;
                    Severity sev = ctx.Internal ? (risky ? Severity.High : Severity.Low)
                        : risky || textIsPath || textIsFileName ? Severity.Critical : Severity.High;
                    add("link-local-file", sev, L.T("Lien vers un fichier du poste ou d’un partage réseau"),
                        L.T("Ce lien n’ouvre pas une page web : il lance un fichier (raccourci, programme, script) depuis un dossier ou un serveur. Venant de l’extérieur, c’est un piège classique ; il peut aussi transmettre votre identifiant Windows au serveur distant."), shownEv);
                    continue;
                }
                if (DangerousSchemes.Contains(scheme))
                {
                    add("link-protocol", Severity.Critical, L.F("Lien qui ouvre une application Windows ({0}:)", scheme),
                        L.T("Ce lien lance une recherche Windows, un outil système ou un installeur au lieu d’une page web : technique utilisée pour faire ouvrir un programme piégé."), shownEv);
                    continue;
                }
                if (OfficeSchemes.Contains(scheme))
                {
                    // ms-word:ofe|u|https://… : ouvre un document distant dans Office
                    var inner = Regex.Match(raw, @"https?://[^\s|]+", RegexOptions.IgnoreCase);
                    Uri iu;
                    string ih = inner.Success && Uri.TryCreate(inner.Value, UriKind.Absolute, out iu) ? PhishGuard.Domains.RegistrableDomain(iu.Host) : "";
                    if (ih.Length == 0 || !(ctx.Domains.Legit.Contains(ih) || ctx.Domains.CompanyDomains.Contains(ih)))
                        add("link-office-remote", Severity.Medium, L.T("Lien qui ouvre directement un document Office distant"),
                            L.T("Le document s’ouvre dans Word ou Excel sans passer par le navigateur : vérifiez sa provenance avant d’autoriser les macros ou le contenu."), shownEv);
                    continue;
                }
                if (Regex.IsMatch(raw, "^(javascript|data|vbscript):", RegexOptions.IgnoreCase))
                {
                    add("link-scheme", Severity.High, L.T("Lien utilisant un protocole dangereux"), L.T("Un lien exécute du code ou ouvre un fichier local."), raw.Length > 80 ? raw.Substring(0, 80) : raw);
                    continue;
                }
                var chain = new List<string>();
                string opaqueService;
                var url = UnwrapUrl(raw, chain, out opaqueService);
                if (url == null) continue;
                foreach (var step in chain)
                    if (step.StartsWith("sec:")) rewrittenBy.Add(step.Substring(4));
                if (opaqueService != null)
                {
                    // Destination illisible : on ne peut ni la comparer au texte du lien ni la vérifier.
                    rewrittenBy.Add(opaqueService);
                    opaqueServices.Add(opaqueService);
                    continue;
                }

                string host = HostOf(url);
                var p = PhishGuard.Domains.ParseHost(host);
                if (p == null) continue;
                string display = PhishGuard.Domains.ToUnicode(host);
                bool legit = ctx.Domains.Legit.Contains(p.Registrable);
                urls.Add(url.AbsoluteUri);
                domains.Add(p.Registrable);

                // Texte du lien ≠ vraie destination
                string text = (link.Text ?? "").Trim();
                bool looksLikeUrl = Regex.IsMatch(text, @"(https?://|www\.)", RegexOptions.IgnoreCase) || Regex.IsMatch(text, @"^[^\s@]+\.[a-z]{2,24}(/\S*)?$", RegexOptions.IgnoreCase);
                var m = looksLikeUrl ? DomainInText.Match(text) : Match.Empty;
                if (m.Success)
                {
                    string shownText = m.Groups[1].Value;
                    string shownTld = shownText.Substring(shownText.LastIndexOf('.') + 1).ToLowerInvariant();
                    if (!fileExts.Contains(shownTld))
                    {
                        var shown = PhishGuard.Domains.ParseHost(Regex.Replace(shownText, "^https?://", "", RegexOptions.IgnoreCase).ToLowerInvariant());
                        if (shown != null && shown.Registrable.Contains(".") && shown.Registrable != p.Registrable && !legit)
                            add("link-text-mismatch", Severity.High, L.T("Le texte d’un lien ne correspond pas à sa vraie destination"),
                                L.T("Le lien affiche une adresse mais vous envoie ailleurs."), L.T("Affiché : ") + shownText + L.T(" → Réel : ") + display);
                    }
                }

                // Texte qui imite un fichier local ou un document, alors que le lien mène sur le web
                string urlExt = ExtensionOf(url.AbsolutePath);
                if (textIsPath)
                    add("link-text-path", downloadExts.Contains(urlExt) ? Severity.Critical : Severity.High, L.T("Le texte du lien imite un chemin de fichier"),
                        L.T("Le lien affiche un chemin comme « C:\\… » ou « \\\\serveur\\… » mais ouvre autre chose : un vrai fichier de votre poste ne s’ouvre jamais depuis un email."),
                        L.T("Affiché : ") + ltext + L.T(" → Réel : ") + display + url.AbsolutePath);
                else if (textIsFileName && downloadExts.Contains(urlExt) && urlExt != textExt)
                    add("link-text-filename", Severity.Critical, L.F("Le lien affiche un fichier « .{0} » mais télécharge un fichier « .{1} »", textExt, urlExt),
                        L.T("Le nom affiché fait croire à un document ; le fichier réellement téléchargé est un programme, un raccourci ou une archive."),
                        L.T("Affiché : ") + ltext + L.T(" → Réel : ") + display + url.AbsolutePath);

                var redirects = chain.Where(c => !c.StartsWith("sec:") && c != "google").ToList();
                if (redirects.Count > 0)
                    add("link-redirect", Severity.Low, L.T("Lien passant par une redirection"), L.T("La destination finale est cachée derrière un autre site."),
                        string.Join(" → ", chain.Where(c => !c.StartsWith("sec:")).ToArray()) + " → " + display);

                var listed = Blocklists.Lookup(host);
                if (listed != null)
                {
                    List<string> l;
                    if (!listedBySource.TryGetValue(listed.SourceId, out l))
                    {
                        l = new List<string>();
                        listedBySource[listed.SourceId] = l;
                        firstHitBySource[listed.SourceId] = listed;
                        sourceOrder.Add(listed.SourceId);
                    }
                    string u = PhishGuard.Domains.ToUnicode(listed.Domain);
                    if (!l.Contains(u)) l.Add(u);
                }

                if (p.IsIp)
                {
                    add("link-ip", Severity.High, L.T("Lien vers une adresse IP au lieu d’un nom de domaine"), L.T("Les sites légitimes utilisent un nom de domaine."), host);
                    continue;
                }
                if (!string.IsNullOrEmpty(url.UserInfo))
                    add("link-userinfo", Severity.High, L.T("Lien contenant « @ » pour masquer la destination"), L.T("Tout ce qui est avant « @ » est ignoré par le navigateur."),
                        url.AbsoluteUri.Length > 100 ? url.AbsoluteUri.Substring(0, 100) : url.AbsoluteUri);

                if (!legit && !p.IsIp && ageChecked.Count < 4 && ageChecked.Add(p.Registrable))
                    CheckDomainAge(p.Registrable, L.T("Le domaine d’un lien"), "link-new-domain", ctx, findings);
                if (!legit && ctx.Config.KnownCorrespondents && Correspondents.Loaded && corrChecked.Add(p.Registrable) && !Correspondents.IsKnownDomain(p.Registrable))
                {
                    var before = findings.Count;
                    CheckCorrespondentLookalike(host, L.T("Le domaine d’un lien"), findings);
                    if (findings.Count > before) findings[findings.Count - 1].Category = "links";
                }

                Lookalike look = legit ? null : PhishGuard.Domains.DetectLookalike(host, ctx.Domains);
                if (look != null) { if (!lookalikes.ContainsKey(p.Registrable)) lookalikes[p.Registrable] = look; }
                else if (PhishGuard.Domains.HasNonAscii(display))
                    add("link-idn", Severity.Medium, L.T("Lien vers un domaine contenant des caractères non latins"), "", display + " (" + host + ")");

                if (HostMatches(host, Lists.Shorteners))
                    add("link-shortener", Severity.Medium, L.T("Lien raccourci (destination masquée)"), L.T("Ne cliquez pas : la destination réelle n’est pas visible."), host);
                if (HostMatches(host, Lists.AbusedHosting) && !(ctx.Platform && p.Registrable == ctx.FromOrg))
                    add("link-hosting", Severity.Medium, L.T("Lien vers un hébergement gratuit souvent utilisé pour le phishing"),
                        L.T("Le service est légitime, mais n’importe qui peut y publier une fausse page de connexion."), display);
                string tld = host.Substring(host.LastIndexOf('.') + 1);
                if (Lists.SuspiciousTlds.Contains(tld) && !legit)
                    add("link-tld", Severity.Low, L.T("Extension de domaine très utilisée par les campagnes de phishing"), "", display);
                if (url.Scheme == "http" && !legit)
                    add("link-http", Severity.Low, L.T("Lien non chiffré (http)"), "", display);
                if (!url.IsDefaultPort && url.Port != 80 && url.Port != 443)
                    add("link-port", Severity.Medium, L.T("Lien utilisant un port inhabituel"), "", display + ":" + url.Port);
                string ext = ExtensionOf(url.AbsolutePath);
                if (downloadExts.Contains(ext))
                {
                    string ev = display + url.AbsolutePath;
                    add("link-download", Severity.Medium, L.T("Lien de téléchargement direct d’un fichier à risque"), "", ev.Length > 100 ? ev.Substring(0, 100) : ev);
                }
            }

            foreach (var src in sourceOrder)
            {
                var doms = listedBySource[src];
                string title = doms.Count > 1
                    ? doms.Count + L.T(" liens pointent vers des domaines qui figurent dans une liste de domaines malveillants")
                    : L.T("Un lien pointe vers un domaine qui figure dans une liste de domaines malveillants");
                findings.Add(BlocklistFinding(firstHitBySource[src], title, "links", doms.Take(6)));
            }
            foreach (var look in lookalikes.Values) findings.Add(LookalikeFinding(look, L.T("Un lien"), "links"));
            foreach (var id in order)
            {
                var it = issues[id];
                findings.Add(new Finding(id, "links", it.Severity, it.Title, it.Detail, it.Evidence.Take(6)));
            }
            var services = rewrittenBy.Distinct().ToList();
            if (services.Count > 0)
            {
                var readable = services.Where(x => !opaqueServices.Contains(x)).ToList();
                var opaque = opaqueServices.Distinct().ToList();
                string detail = readable.Count > 0 ? L.T("PhishGuard a retrouvé et analysé la vraie destination de ces liens.") : "";
                if (opaque.Count > 0)
                    detail = (detail.Length > 0 ? detail + " " : "") + L.T("Destination illisible pour ") + string.Join(", ", opaque.ToArray())
                        + L.T(" : ces liens n’ont pas pu être vérifiés.");
                findings.Add(new Finding("link-rewritten", "links", Severity.Info,
                    L.T("Liens réécrits par un service de sécurité (") + string.Join(", ", services.ToArray()) + ")", detail, null));
            }
        }

        // =====================================================================
        // Pièces jointes
        // =====================================================================

        static readonly Regex Rtlo = new Regex("[\u202a-\u202e\u2066-\u2069]");

        // =====================================================================
        // Sources externes (bêta) : OpenPhish, Tranco, DNS, crt.sh, VirusTotal, abuse.ch, Safe Browsing, AbuseIPDB
        // =====================================================================

        /// <summary>true pour les indices issus des sources externes (affichés dans l'onglet Bêta).</summary>
        public static bool IsBetaFinding(Finding f)
        {
            return f.Id == "intel-pending" || f.Id.Contains("-intel-");
        }

        class SourceCount { public int Checked, Pending, Errors; }

        static void AnalyzeIntel(EmailData e, Ctx ctx, HeaderDetails details, List<Finding> findings, List<string> positives, List<string> urls, List<string> linkDomains, List<SourceStatus> sources)
        {
            var cfg = ctx.Config;
            var s = Intel.Settings;
            var counts = new Dictionary<string, SourceCount>();
            Func<string, string, IntelResult> ask = (key, service) =>
            {
                SourceCount c;
                if (!counts.TryGetValue(service, out c)) { c = new SourceCount(); counts[service] = c; }
                var r = Intel.GetOrRequest(key);
                if (r == null) c.Pending++;
                else if (!r.Ok) c.Errors++;
                else c.Checked++;
                return r != null && r.Ok ? r : null;
            };
            var byId = new Dictionary<string, Finding>();
            Action<string, string, Severity, string, string, string> add = (id, cat, sev, title, detail, ev) =>
            {
                Finding f;
                if (!byId.TryGetValue(id, out f)) { f = new Finding(id, cat, sev, title, detail, null); byId[id] = f; findings.Add(f); }
                else if (sev > f.Severity) f.Severity = sev;
                if (!string.IsNullOrEmpty(ev) && !f.Evidence.Contains(ev) && f.Evidence.Count < 6) f.Evidence.Add(ev);
            };

            // ---- Liens : OpenPhish (adresse complète, comparée sur le poste) ----
            int opChecked = 0;
            foreach (var u in urls)
            {
                if (!Feeds.OpenPhishEnabled) break;
                opChecked++;
                string op = Feeds.OpenPhishMatch(u);
                if (op == "url")
                    add("links-intel-openphish", "links", Severity.Critical, L.T("Lien vers une page de phishing connue (OpenPhish)"),
                        L.T("Cette adresse figure dans le flux OpenPhish des pages de phishing actives."), Defang(u));
                else if (op == "host")
                    add("links-intel-openphish-host", "links", Severity.High, L.T("Lien vers un serveur qui héberge des pages de phishing (OpenPhish)"), "", Defang(u));
            }

            // ---- Domaines : expéditeur puis liens ----
            string fromDomain = PhishGuard.Domains.DomainOfAddress(e.FromAddress);
            string fromOrg = PhishGuard.Domains.RegistrableDomain(fromDomain);
            var domains = new List<KeyValuePair<string, string>>();   // domaine, catégorie
            if (fromOrg.Length > 0 && !ctx.Internal) domains.Add(new KeyValuePair<string, string>(fromOrg, "sender"));
            foreach (var d in linkDomains.Take(8))
                if (!domains.Any(x => x.Key == d)) domains.Add(new KeyValuePair<string, string>(d, "links"));

            int crtCount = 0, ranked = 0;
            foreach (var kv in domains)
            {
                string d = kv.Key, cat = kv.Value;
                if (PhishGuard.Domains.IsIpHost(d)) continue;
                bool trusted = ctx.Domains.Legit.Contains(d) || ctx.Domains.CompanyDomains.Contains(d) || Lists.FreemailDomains.Contains(d)
                    || cfg.TrustedDomains.Contains(d);
                int rank = Feeds.TrancoRank(d);
                if (rank > 0) ranked++;
                bool personal = Lists.FreemailDomains.Contains(d) || ctx.Domains.CompanyDomains.Contains(d);
                if (rank > 0 && cat == "sender" && !personal)
                {
                    string txt = L.F("Domaine très fréquenté : {0} (n° {1} mondial, classement Tranco)", PhishGuard.Domains.ToUnicode(d), rank.ToString("N0"));
                    positives.Add(txt);
                    ctx.Trust.Add(txt);
                }
                string shown = PhishGuard.Domains.ToUnicode(d);
                string where = cat == "sender" ? L.T("Le domaine de l’expéditeur") : L.T("Le domaine d’un lien");

                // DNS : seulement pour l'expéditeur (domaine qui envoie des emails).
                // Les preuves (DMARC strict, BIMI) valent aussi pour les domaines connus ; les indices négatifs, non.
                IntelResult dnsR = null;
                if (cfg.BetaDnsChecks && cat == "sender" && !personal)
                {
                    dnsR = ask("dns:" + fromDomain + "|" + fromOrg, "dns");
                    if (dnsR != null && dnsR.Exists)
                    {
                        if (dnsR.DmarcPolicy == "reject" || dnsR.DmarcPolicy == "quarantine")
                            ctx.Trust.Add(L.F("Domaine protégé contre l’usurpation (DMARC p={0})", dnsR.DmarcPolicy));
                        if (dnsR.Bimi == "vmc" && ctx.AuthProof)
                        {
                            ctx.Trust.Add(L.T("Marque vérifiée : logo BIMI avec certificat VMC/CMC"));
                        }
                        else if (dnsR.Bimi == "logo" && ctx.AuthProof)
                            ctx.Trust.Add(L.T("Logo de marque publié (BIMI, sans certificat)"));
                    }
                }
                if (trusted) continue;

                if (dnsR != null && rank == 0)
                {
                    var r = dnsR;
                    {
                        if (!r.Exists)
                            add("sender-intel-dns-nxdomain", cat, Severity.High, L.T("Le domaine de l’expéditeur n’existe pas"),
                                L.T("Le DNS ne connaît pas ce domaine : l’adresse d’expédition est inventée."), fromDomain);
                        else
                        {
                            if (!r.HasMx)
                                add("sender-intel-dns-nomx", cat, Severity.Medium, L.T("Le domaine de l’expéditeur ne peut pas recevoir d’emails (aucun MX)"),
                                    L.T("Une vraie organisation reçoit des emails sur son domaine ; celui-ci n’a aucun serveur de messagerie."), fromDomain);
                            if (!r.HasSpf && !r.HasDmarc)
                                add("sender-intel-dns-noauth", cat, Severity.Low, L.T("Le domaine de l’expéditeur n’a ni SPF ni DMARC"),
                                    L.T("N’importe qui peut envoyer des emails en son nom."), fromDomain);
                            else if (r.DmarcPolicy == "none")
                                add("sender-intel-dmarc-none", cat, Severity.Info, L.T("Politique DMARC non appliquée (p=none)"),
                                    L.T("Le domaine surveille les usurpations mais ne demande pas de les bloquer."), fromDomain);
                        }
                    }
                }

                // crt.sh : âge du premier certificat HTTPS
                if (cfg.BetaCertAge && rank == 0 && crtCount < 3)
                {
                    crtCount++;
                    var r = ask("crt:" + d, "crt");
                    if (r != null && r.Date.HasValue)
                    {
                        int days = Math.Max(0, (int)(DateTime.UtcNow - r.Date.Value).TotalDays);
                        if (days < 30)
                            add(cat + "-intel-cert-new", cat, days < 7 ? Severity.High : Severity.Medium,
                                L.F("{0} a obtenu son premier certificat HTTPS il y a {1} jour(s)", where, days),
                                L.T("Un site tout juste mis en ligne : fréquent pour les pages de phishing."), shown);
                    }
                }

                if (s.AbuseChKey.Length > 0)
                {
                    var r = ask("uhh:" + d, "abusech");
                    if (r != null && r.Found)
                        add(cat + "-intel-urlhaus", cat, Severity.High, L.T("URLhaus : ce domaine diffuse des logiciels malveillants"),
                            r.Total > 0 ? L.F("{0} adresses malveillantes recensées sur ce domaine.", r.Total) : "", shown);
                    var t = ask("tfi:" + d, "abusech");
                    if (t != null && t.Found)
                        add(cat + "-intel-threatfox", cat, Severity.High, L.T("ThreatFox : domaine connu comme indicateur de menace"),
                            t.Label.Length > 0 ? L.F("Associé à : {0}.", t.Label) : "", shown);
                }
            }

            // ---- Pièces jointes (empreinte SHA-256 : le fichier n'est jamais envoyé) ----
            foreach (var a in e.Attachments.Where(x => x.Sha256.Length > 0 && !(x.IsInline && x.IsImage)).Take(5))
            {
                if (s.VirusTotalKey.Length > 0)
                {
                    var r = ask("vtf:" + a.Sha256, "vt");
                    if (r != null && r.Found && r.Malicious > 0)
                        add("att-intel-vt", "attachments", r.Malicious >= 3 ? Severity.Critical : Severity.High,
                            L.F("VirusTotal : pièce jointe détectée par {0} antivirus sur {1}", r.Malicious, r.Total),
                            L.T("Le fichier est déjà connu comme malveillant. Ne l’ouvrez pas."), a.Name);
                }
                if (s.AbuseChKey.Length > 0)
                {
                    var r = ask("uhp:" + a.Sha256, "abusech");
                    var t = ask("tfh:" + a.Sha256, "abusech");
                    if ((r != null && r.Found) || (t != null && t.Found))
                    {
                        string fam = t != null && t.Found && t.Label.Length > 0 ? t.Label : (r != null ? r.Label : "");
                        add("att-intel-abusech", "attachments", Severity.Critical, L.T("Pièce jointe identifiée comme logiciel malveillant (abuse.ch)"),
                            fam.Length > 0 ? L.F("Famille : {0}.", fam) : "", a.Name);
                    }
                }
            }

            // ---- IP d'origine ----
            if (s.AbuseIpdbKey.Length > 0 && details != null && details.OriginIp.Length > 0 && Forensics.IsPublicIp(details.OriginIp))
            {
                var r = ask("ip:" + details.OriginIp, "abuseipdb");
                if (r != null && r.Malicious >= 25)
                    add("sender-intel-abuseipdb", "sender", r.Malicious >= 75 ? Severity.High : Severity.Medium,
                        L.F("L’IP d’origine est signalée pour abus (AbuseIPDB : {0}/100, {1} signalements)", r.Malicious, r.Total), "", details.OriginIp);
                else if (r != null)
                    add("sender-intel-abuseipdb-info", "sender", Severity.Info, L.F("AbuseIPDB : IP d’origine {0}, score {1}/100", details.OriginIp, r.Malicious), "", null);
            }

            // ---- État de chaque source (onglet Bêta) ----
            Action<string, string, bool, string> status = (service, name, enabled, offDetail) =>
            {
                SourceCount c;
                counts.TryGetValue(service, out c);
                var st = new SourceStatus { Name = name };
                if (!enabled) { st.State = "off"; st.Detail = offDetail; }
                else if (c == null) { st.State = "ok"; st.Detail = L.T("Rien à vérifier pour ce message"); }
                else if (c.Pending > 0) { st.State = "pending"; st.Detail = L.F("{0} vérification(s) en cours", c.Pending); }
                else if (c.Errors > 0) { st.State = "error"; st.Detail = L.T("Service injoignable ou clé refusée") + (Intel.LastError.Length > 0 ? " (" + Intel.LastError + ")" : ""); }
                else { st.State = "ok"; st.Detail = L.F("{0} élément(s) vérifié(s)", c.Checked); }
                sources.Add(st);
            };
            string notEnabled = L.T("Désactivé (Paramètres → Réputation)");
            string noKey = L.T("Pas de clé (Paramètres → Réputation)");
            sources.Add(new SourceStatus
            {
                Name = "OpenPhish",
                State = !Feeds.OpenPhishEnabled ? "off" : Feeds.OpenPhishCount == 0 ? "pending" : "ok",
                Detail = !Feeds.OpenPhishEnabled ? notEnabled : Feeds.OpenPhishCount == 0
                    ? L.T("Liste en cours de téléchargement") + (Feeds.LastError.Length > 0 ? " (" + Feeds.LastError + ")" : "")
                    : L.F("{0} lien(s) comparé(s) à {1} adresses", opChecked, Feeds.OpenPhishCount.ToString("N0"))
            });
            sources.Add(new SourceStatus
            {
                Name = "Tranco",
                State = !Feeds.TrancoEnabled ? "off" : Feeds.TrancoCount == 0 ? "pending" : "ok",
                Detail = !Feeds.TrancoEnabled ? notEnabled : Feeds.TrancoCount == 0
                    ? L.T("Liste en cours de téléchargement") + (Feeds.LastError.Length > 0 ? " (" + Feeds.LastError + ")" : "")
                    : L.F("{0} domaine(s) parmi les sites les plus visités", ranked)
            });
            status("dns", L.T("DNS (MX, SPF, DMARC, BIMI)"), cfg.BetaDnsChecks, notEnabled);
            status("crt", "crt.sh", cfg.BetaCertAge, notEnabled);
            status("vt", "VirusTotal", s.VirusTotalKey.Length > 0, noKey);
            status("abusech", "abuse.ch (URLhaus, ThreatFox)", s.AbuseChKey.Length > 0, noKey);
            status("abuseipdb", "AbuseIPDB", s.AbuseIpdbKey.Length > 0, noKey);

            int pendingTotal = counts.Values.Sum(c => c.Pending);
            if (pendingTotal > 0)
                findings.Add(new Finding("intel-pending", "links", Severity.Info, L.T("Vérifications externes en cours"),
                    L.T("Le résultat s’affichera automatiquement dans quelques secondes."), null));
        }

        static void AnalyzeAttachments(EmailData e, Ctx ctx, List<Finding> findings, List<string> names)
        {
            var byId = new Dictionary<string, Finding>();
            var order = new List<string>();
            Action<string, Severity, string, string, string> add = (id, sev, title, detail, ev) =>
            {
                Finding f;
                if (!byId.TryGetValue(id, out f)) { f = new Finding(id, "attachments", sev, title, detail, null); byId[id] = f; order.Add(id); }
                if (f.Evidence.Count < 6) f.Evidence.Add(ev);
            };

            foreach (var a in e.Attachments)
            {
                if (a.IsInline && a.IsImage) continue;
                string name = a.Name ?? "";
                names.Add(name);
                string lower = name.ToLowerInvariant().Trim();
                string ext = ExtensionOf(lower);
                var parts = lower.Split('.');
                string prevExt = parts.Length > 2 ? parts[parts.Length - 2] : "";

                if (Rtlo.IsMatch(name))
                {
                    add("att-rtlo", Severity.Critical, L.T("Nom de fichier inversé (caractère de contrôle Unicode)"),
                        L.T("Le nom affiché est trompeur : « facture[RLO]fdp.exe » s’affiche « facture.exe.pdf » mais reste un programme."), name);
                    continue;
                }
                bool dangerous = Lists.ExtExecutable.Contains(ext) || Lists.ExtDiskImage.Contains(ext);
                if (dangerous && Lists.ExtDocument.Contains(prevExt))
                    add("att-double", Severity.Critical, L.T("Double extension : programme déguisé en document"), L.T("Le fichier se fait passer pour un document mais c’est un programme."), name);
                else if (Lists.ExtExecutable.Contains(ext))
                    add("att-exec", Severity.High, L.T("Pièce jointe exécutable"), L.T("Ce type de fichier peut lancer un programme sur votre poste."), name);
                else if (Lists.ExtDiskImage.Contains(ext))
                    add("att-image", Severity.High, L.T("Image disque (ISO, IMG, VHD)"), L.T("Format souvent utilisé pour contourner les protections et livrer un logiciel malveillant."), name);
                else if (Lists.ExtHtml.Contains(ext))
                    add("att-html", ext == "svg" ? Severity.Medium : Severity.High, L.T("Pièce jointe HTML ou SVG"), L.T("Ces fichiers ouvrent souvent une fausse page de connexion directement dans le navigateur."), name);
                else if (Lists.ExtMacro.Contains(ext))
                    add("att-macro", Severity.High, L.T("Document Office avec macros"), L.T("N’activez jamais les macros d’un document reçu par email."), name);
                else if (Lists.ExtOneNote.Contains(ext))
                    add("att-onenote", Severity.High, L.T("Fichier OneNote"), L.T("Format détourné pour cacher des scripts derrière un faux bouton."), name);
                else if (Lists.ExtArchive.Contains(ext))
                {
                    add("att-archive", Severity.Low, L.T("Archive compressée"), L.T("Son contenu n’est pas analysé par les filtres s’il est protégé par mot de passe."), name);
                    ctx.HasArchive = true;
                }
                else if (ext.Length == 0 && lower.Length > 0)
                    add("att-noext", Severity.Low, L.T("Pièce jointe sans extension"), "", name);
                var magic = Forensics.MagicMismatch(a);
                if (magic != null && !byId.ContainsKey(magic.Id)) { byId[magic.Id] = magic; order.Add(magic.Id); }
                else if (magic != null && byId[magic.Id].Evidence.Count < 6) byId[magic.Id].Evidence.Add(name);
                if (Regex.IsMatch(name, @"\s{5,}"))
                    add("att-spaces", Severity.High, L.T("Nom de fichier rempli d’espaces pour cacher l’extension"), "", Regex.Replace(name, @"\s{5,}", " … "));
            }
            foreach (var a in e.Attachments)
            {
                foreach (var cf in a.ContentFindings)
                {
                    Finding existing;
                    if (byId.TryGetValue(cf.Id, out existing)) { foreach (var ev in cf.Evidence) if (!existing.Evidence.Contains(ev) && existing.Evidence.Count < 6) existing.Evidence.Add(ev); }
                    else { var copy = new Finding(cf.Id, "attachments", cf.Severity, cf.Title, cf.Detail, cf.Evidence); byId[cf.Id] = copy; order.Add(cf.Id); }
                }
            }
            foreach (var id in order) findings.Add(byId[id]);
        }

        // =====================================================================
        // Contenu
        // =====================================================================

        static List<string> MatchRule(string text, Lists.ContentRule rule)
        {
            var hits = new List<string>();
            foreach (var p in rule.Patterns)
            {
                if (Regex.IsMatch(text, "(^|[^a-z0-9])" + Regex.Escape(p) + "($|[^a-z0-9])")) hits.Add(p);
                if (hits.Count >= 4) break;
            }
            return hits;
        }

        static void AnalyzeContent(EmailData e, List<KeyValuePair<string, string>> headers, Ctx ctx, List<Finding> findings)
        {
            string subject = NormalizeText(e.Subject);
            string body = NormalizeText(e.BodyText);
            if (body.Length > 50000) body = body.Substring(0, 50000);
            string text = subject + " " + body;

            var hits = new Dictionary<string, List<string>>();
            foreach (var rule in Lists.ContentRules)
            {
                hits[rule.Key] = MatchRule(text, rule);
                if (hits[rule.Key].Count > 0)
                    findings.Add(new Finding("content-" + rule.Key, "content", rule.Key == "qrcode" ? Severity.Medium : Severity.Low, L.T(rule.Label), "",
                        hits[rule.Key].Select(h => L.T("« ") + h + L.T(" »"))));
            }

            bool cred = hits["credentials"].Count > 0, urg = hits["urgency"].Count > 0, fin = hits["financial"].Count > 0, sec = hits["secrecy"].Count > 0;
            bool mailbox = hits["mailbox"].Count > 0;
            if (mailbox && (cred || urg))
                findings.Add(new Finding("content-combo-mailbox", "content", Severity.High, L.T("Fausse alerte de votre messagerie"),
                    L.T("Messages bloqués, boîte pleine, mot de passe qui expire : prétexte n° 1 pour voler les identifiants. Votre service informatique ne vous demande jamais de vous reconnecter par un lien."), null));

            // Votre propre adresse dans l'objet ou en guise de salutation : personnalisation automatique typique des campagnes
            if (!ctx.Internal)
            {
                var rcpts = new List<string>();
                foreach (var h in new[] { "delivered-to", "x-original-to", "envelope-to", "to" })
                    foreach (var a in AddressesIn(string.Join(",", HeaderValues(headers, h))))
                        if (!rcpts.Contains(a) && a.IndexOf('@') >= 3) rcpts.Add(a);
                string rawSubject = (e.Subject ?? "").ToLowerInvariant();
                string inSubject = rcpts.FirstOrDefault(a => rawSubject.Contains(a));
                if (inSubject != null)
                    findings.Add(new Finding("content-recipient-subject", "content", Severity.Medium, L.T("Votre adresse email figure dans l’objet"),
                        L.T("Les vrais services vous appellent par votre nom ; les campagnes d’hameçonnage insèrent automatiquement l’adresse pour faire « officiel »."), new[] { inSubject }));
                else
                {
                    string greet = rcpts.FirstOrDefault(a => Regex.IsMatch(body, @"(^|[\s,.;:])(dear|hello|hi|bonjour|cher|chere|hola|estimado|attention|attn)\s*:?,?\s*" + Regex.Escape(a)));
                    if (greet != null)
                        findings.Add(new Finding("content-recipient-greeting", "content", Severity.Low, L.T("Le message vous salue par votre adresse email"),
                            L.T("Un expéditeur qui vous connaît utilise votre nom, pas votre adresse."), new[] { greet }));
                }
            }
            if (cred && urg)
                findings.Add(new Finding("content-combo-cred", "content", Severity.High, L.T("Demande d’identifiants sous pression"),
                    L.T("Un vrai service ne vous demande jamais de vous reconnecter « en urgence » par email."), null));
            if (fin && (sec || urg))
                findings.Add(new Finding("content-combo-bec", "content", Severity.High, L.T("Demande de paiement urgente ou confidentielle"),
                    L.T("Schéma de fraude au virement ou au président : confirmez toujours par téléphone, avec un numéro que vous connaissez."), null));
            if (ctx.IsFreemail && (fin || cred))
                findings.Add(new Finding("content-freemail-request", "content", Severity.Medium, L.T("Demande sensible envoyée depuis une messagerie gratuite"),
                    L.T("Une banque, une administration ou un fournisseur n’écrit pas depuis Gmail, Outlook.com ou Orange."), null));
            if (ctx.FirstContact && (fin || cred) && !ctx.BrandSender)
                findings.Add(new Finding("content-first-contact-request", "content", Severity.Medium, L.T("Demande sensible dès le premier message"),
                    L.T("Un inconnu qui demande un paiement ou des identifiants dès son premier email : prudence maximale."), null));

            // Coordonnées bancaires (IBAN valides)
            var ibans = FindIbans(e.BodyText);
            if (ibans.Count > 0)
            {
                var foreign = ibans.Where(i => !i.StartsWith("FR") && !i.StartsWith("MC")).ToList();
                string norm = text;
                bool change = Regex.IsMatch(norm, @"(nouveau rib|nouvelles coordonnees|changement de (rib|banque|coordonnees)|nouveau compte|new bank|bank details have changed|changed our bank)");
                if (change)
                    findings.Add(new Finding("content-iban-change", "content", Severity.High, L.T("Demande de changement de coordonnées bancaires"),
                        L.T("Fraude très répandue : vérifiez toujours par téléphone, avec un numéro déjà connu, avant de modifier un RIB."), ibans.Select(x => MaskIban(x))));
                else if (foreign.Count > 0)
                    findings.Add(new Finding("content-iban-foreign", "content", Severity.Medium, L.T("IBAN étranger (") + foreign[0].Substring(0, 2) + L.T(") dans le message"),
                        "", foreign.Select(x => MaskIban(x))));
                else
                    findings.Add(new Finding("content-iban", "content", Severity.Low, L.T("Coordonnées bancaires (IBAN) dans le message"), "", ibans.Select(x => MaskIban(x))));
            }

            if (ctx.HasArchive && Regex.IsMatch(body, @"(mot de passe|password|code)\s*:?\s*\S{3,}"))
                findings.Add(new Finding("content-archive-password", "content", Severity.High, L.T("Archive protégée avec mot de passe dans le message"),
                    L.T("Technique pour empêcher l’antivirus d’analyser le contenu de l’archive."), null));

            if (e.HasPasswordInput)
                findings.Add(new Finding("content-form-password", "content", Severity.Critical, L.T("Champ « mot de passe » directement dans le message"),
                    L.T("Aucun service légitime ne demande votre mot de passe dans le corps d’un email."), null));
            else if (e.HasForm)
                findings.Add(new Finding("content-form", "content", Severity.Medium, L.T("Formulaire intégré dans le message"), "", null));

            if (headers.Count > 0 && Regex.IsMatch(e.Subject ?? "", @"^\s*(re|tr|fw|fwd)\s*:", RegexOptions.IgnoreCase)
                && HeaderValues(headers, "in-reply-to").Count == 0 && HeaderValues(headers, "references").Count == 0)
                findings.Add(new Finding("content-fake-reply", "content", Severity.Low, L.T("Faux « RE: » ou « TR: »"),
                    L.T("L’objet fait croire à une réponse, mais le message ne répond à aucun email existant."), null));
        }


        // =====================================================================
        // IBAN
        // =====================================================================

        static readonly Regex IbanRe = new Regex(@"\b([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?)\b");

        public static List<string> FindIbans(string text)
        {
            var list = new List<string>();
            foreach (Match m in IbanRe.Matches((text ?? "").ToUpperInvariant()))
            {
                string iban = m.Groups[1].Value.Replace(" ", "");
                if (iban.Length < 15 || iban.Length > 34 || list.Contains(iban)) continue;
                if (IbanValid(iban)) list.Add(iban);
                if (list.Count >= 5) break;
            }
            return list;
        }

        static bool IbanValid(string iban)
        {
            string r = iban.Substring(4) + iban.Substring(0, 4);
            int mod = 0;
            foreach (char c in r)
            {
                if (char.IsDigit(c)) mod = (mod * 10 + (c - '0')) % 97;
                else if (c >= 'A' && c <= 'Z') { int v = c - 'A' + 10; mod = (mod * 100 + v) % 97; }
                else return false;
            }
            return mod == 1;
        }

        static string MaskIban(string iban)
        {
            return iban.Length < 10 ? iban : iban.Substring(0, 4) + " …" + iban.Substring(iban.Length - 4);
        }

        // =====================================================================
        // Filtres de messagerie (passerelle antispam, Exchange, FortiMail, fournisseur)
        // =====================================================================

        static readonly Regex SpamTag = new Regex(@"^\s*(\*+\s*spam\s*\*+|\[\s*\**\s*spam\s*\**\s*\]|\{\s*spam\??\s*\}|spam\s*:|\(\s*spam\s*\))", RegexOptions.IgnoreCase);
        static readonly Regex DangerTag = new Regex(@"^\s*(\*+\s*(phishing|virus|suspect|suspicious|fraud)\s*\*+|\[\s*(phishing|phish|virus|malware|suspect|suspicious|fraud|fraude)\s*\])", RegexOptions.IgnoreCase);

        static void AnalyzeFilters(EmailData e, List<KeyValuePair<string, string>> headers, Ctx ctx, List<Finding> findings)
        {
            string subject = Forensics.DecodeMimeWords(e.Subject ?? "");
            if (DangerTag.IsMatch(subject))
                findings.Add(new Finding("filter-subject-danger", "filter", Severity.High, L.T("Votre filtre de messagerie a marqué ce message comme dangereux"),
                    L.T("L’objet a été modifié par le filtre de votre entreprise ou de votre fournisseur."), new[] { subject.Length > 80 ? subject.Substring(0, 80) + "…" : subject }));
            else if (SpamTag.IsMatch(subject))
                findings.Add(new Finding("filter-subject-spam", "filter", Severity.Medium, L.T("Votre filtre de messagerie a marqué ce message comme spam"),
                    L.T("L’objet a été modifié par le filtre de votre entreprise ou de votre fournisseur."), new[] { subject.Length > 80 ? subject.Substring(0, 80) + "…" : subject }));

            foreach (var kv in headers)
            {
                string k = kv.Key, v = kv.Value.Trim(), vl = v.ToLowerInvariant();
                if (k == "x-spam-flag" && vl.StartsWith("yes"))
                    findings.Add(new Finding("filter-spamassassin", "filter", Severity.Medium, L.T("Classé spam par le filtre (X-Spam-Flag)"), "", new[] { k + ": " + v }));
                else if (k == "x-spam-status" && vl.StartsWith("yes"))
                    findings.Add(new Finding("filter-spamassassin", "filter", Severity.Medium, L.T("Classé spam par le filtre (X-Spam-Status)"), "", new[] { k + ": " + (v.Length > 80 ? v.Substring(0, 80) + "…" : v) }));
                else if (k == "x-me-srv" && vl.Contains("suspect"))
                    findings.Add(new Finding("filter-orange", "filter", Severity.Low, L.T("Le filtre d’Orange juge ce message suspect"), "", new[] { k + ": " + v }));
                else if (k == "x-me-spamlevel" && (vl.StartsWith("high") || vl.StartsWith("medium")))
                    findings.Add(new Finding("filter-orange-level", "filter", vl.StartsWith("high") ? Severity.Medium : Severity.Low, L.T("Niveau de spam élevé selon le filtre d’Orange"), "", new[] { k + ": " + v }));
                else if (k == "x-ms-exchange-organization-scl")
                {
                    int scl;
                    if (int.TryParse(v, out scl) && scl >= 5)
                        findings.Add(new Finding("filter-exchange-scl", "filter", scl >= 9 ? Severity.High : Severity.Medium, L.T("Exchange classe ce message comme spam (SCL ") + scl + ")", "", new[] { k + ": " + v }));
                }
                else if ((k.StartsWith("x-feas") || k.StartsWith("x-fe-") || k.Contains("forti")) && Regex.IsMatch(vl, @"\b(spam|phish|phishing|virus|malware|suspicious)\b") && !Regex.IsMatch(vl, @"^(no|none|clean|not|0)\b"))
                    findings.Add(new Finding("filter-fortimail", "filter", Severity.Medium, L.T("FortiMail a signalé ce message"), "", new[] { k + ": " + (v.Length > 80 ? v.Substring(0, 80) + "…" : v) }));
            }
        }

        // =====================================================================
        // Rapport texte
        // =====================================================================

        public static string Defang(string u)
        {
            return Regex.Replace(u ?? "", "^http", "hxxp", RegexOptions.IgnoreCase).Replace(".", "[.]");
        }

        public static string FormatReport(AnalysisResult r, EmailData e)
        {
            var d = r.Details ?? new HeaderDetails();
            var sb = new StringBuilder();
            sb.AppendLine(L.T("=== PhishGuard - rapport d'analyse ==="));
            sb.AppendLine(L.T("Verdict : ") + r.LevelLabel + L.T(" (score ") + r.Score + "/100)");
            sb.AppendLine(L.T("Expéditeur : ") + e.FromName + " <" + r.SenderAddress + ">");
            sb.AppendLine(L.T("Objet : ") + e.Subject);
            if (d.OriginIp.Length > 0) sb.AppendLine(L.T("IP d'origine : ") + d.OriginIp + (d.Country.Length > 0 ? " (" + d.Country + ")" : "") + " - " + d.OriginSource);
            var a = d.Auth;
            sb.AppendLine(L.T("Authentification : SPF=") + (a.Spf ?? L.T("absent")) + (a.SpfMailFrom != null ? " (" + a.SpfMailFrom + ")" : "")
                + " ; DKIM=" + (a.Dkim ?? L.T("absent")) + (a.DkimDomain != null ? " (d=" + a.DkimDomain + (a.DkimSelector != null ? ", s=" + a.DkimSelector : "") + ")" : "")
                + " ; DMARC=" + (a.Dmarc ?? L.T("absent")) + (a.DmarcFrom != null ? " (" + a.DmarcFrom + ")" : ""));
            sb.AppendLine();
            sb.AppendLine(L.T("--- Indices ---"));
            foreach (var f in r.Findings.Where(x => x.Severity != Severity.Info))
                sb.AppendLine("- [" + SeverityLabel(f.Severity).ToUpperInvariant() + "] " + f.Title + (f.Evidence.Count > 0 ? " : " + string.Join(" ; ", f.Evidence.ToArray()) : ""));
            if (r.Trust.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine(r.Verified ? L.T("--- Preuves de légitimité (expéditeur vérifié) ---") : L.T("--- Preuves de légitimité ---"));
                foreach (var t in r.Trust) sb.AppendLine("+ " + t);
            }

            if (d.Fields.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine(L.T("--- En-têtes principaux ---"));
                foreach (var kv in d.Fields) sb.AppendLine(kv.Key + " : " + kv.Value);
            }
            if (d.Hops.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine(L.T("--- Parcours (du premier au dernier serveur) ---"));
                foreach (var h in d.Hops)
                    sb.AppendLine(h.Number + ". " + h.FromHost + (h.FromIp.Length > 0 ? " [" + h.FromIp + "]" : "") + " -> " + h.ByHost
                        + (h.Date.HasValue ? " | " + h.Date.Value.ToString("yyyy-MM-dd HH:mm:ss zzz") : "")
                        + (h.Delay.HasValue ? " | +" + Forensics.FormatDelay(h.Delay) : ""));
            }
            if (r.Urls.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine(L.T("--- URL (désarmées) ---"));
                foreach (var u in r.Urls.Take(50)) sb.AppendLine("- " + Defang(u));
            }
            if (r.Attachments.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine(L.T("--- Pièces jointes ---"));
                foreach (var at in r.Attachments)
                {
                    sb.AppendLine("- " + at.Name + (at.Size >= 0 ? " (" + at.Size + L.T(" octets)") : "") + (at.Magic.Length > 0 ? L.T(" - type réel : ") + Forensics.MagicLabel(at.Magic) : ""));
                    if (at.Sha256.Length > 0)
                    {
                        sb.AppendLine("    MD5    " + at.Md5);
                        sb.AppendLine("    SHA1   " + at.Sha1);
                        sb.AppendLine("    SHA256 " + at.Sha256);
                    }
                }
            }
            return sb.ToString();
        }
    }
}
