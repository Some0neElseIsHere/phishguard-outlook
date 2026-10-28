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
            public string InternalHow = "";   // exchange (authentifié par Exchange) ou relay (équipement interne déclaré)
            public bool IsFreemail;
            public bool IsCompany;
            public string FromOrg = "";
            public bool HasArchive;
            public bool FirstContact;
            public bool SenderTrusted;
            public bool AuthOk;          // DMARC valide, ou SPF et DKIM valides
            public string RelayProof = "";   // équipement déclaré qui a reconnu le message : IP et adresses autorisées
            public bool InternalForged;  // message à votre nom parti d'une machine du réseau interne sans authentification
            // Preuves de légitimité (affichées dans la fenêtre d'analyse ; ne masquent jamais un indice Élevé ou Critique)
            public List<string> Trust = new List<string>();
            public string DmarcDerived;   // DMARC absent des en-têtes, mais SPF ou DKIM aligné : « dkim » ou « spf »
            public bool AuthProof;       // l'expéditeur affiché est authentifié (DMARC, DKIM aligné, compauth 1xx)
            public bool RelationProof;   // relation établie avec vous : correspondant connu, réponse à votre message, expéditeur de confiance
            public bool BulkCompliant;   // envoi en nombre conforme (désabonnement en un clic + DMARC)
            public bool BrandSender;     // authentifié sur le domaine officiel d'une marque (hors messageries gratuites et plateformes)
            public bool PublicBody;      // domaine d'un organisme public (.gouv.fr ou liste officielle du secteur public)
            public string ProvenBrand;
            public bool ProvenCompany;
            public bool PublicListed;    // organisme de la liste du secteur public (hors .gouv.fr), authentifié   // domaine prouvé de votre entreprise (autre extension, ancien nom…)   // domaine sosie dont l'appartenance à la marque est prouvée (ses serveurs DNS la gèrent)
            public bool CodeMessage;     // vrai message de code (connexion, vérification) : authentifié, liens chez l'expéditeur
            public bool MailingList;     // message adressé à une liste de diffusion dont vous êtes membre
            public bool Platform;        // plateforme qui relaie les messages de ses clients (partage, signature…), authentifiée
        }

        // =====================================================================
        // Point d'entrée
        // =====================================================================

        /// <summary>
        /// Analyse d'un message. Ne lève jamais d'exception : un message construit pour faire échouer l'analyse
        /// (données invalides) ne doit pas échapper à l'alerte. Il est alors classé « suspect », avec la raison.
        /// </summary>
        public static AnalysisResult Analyze(EmailData e, PhishGuardConfig config)
        {
            try { return AnalyzeCore(e, config); }
            catch (Exception ex)
            {
                var f = new Finding("engine-error", "content", Severity.Medium, L.T("Analyse incomplète : le message contient des données anormales"),
                    L.T("PhishGuard n’a pas pu analyser entièrement ce message. Un message construit pour tromper les outils de sécurité peut produire cet effet : soyez prudent."),
                    new[] { ex.GetType().Name });
                f.Severity = Severity.High;
                return new AnalysisResult
                {
                    Score = 40, Level = "suspicious", LevelLabel = L.T("Suspect"),
                    Advice = L.T("Ne cliquez pas et n’ouvrez rien avant d’avoir vérifié l’expéditeur par un autre moyen."),
                    Findings = new List<Finding> { f },
                    SenderAddress = ((e == null ? null : e.FromAddress) ?? "").ToLowerInvariant(),
                    Attachments = e == null ? new List<AttachmentInfo>() : e.Attachments,
                    Error = ex.GetType().Name + " : " + ex.Message
                };
            }
        }

        static AnalysisResult AnalyzeCore(EmailData e, PhishGuardConfig config)
        {
            var ctx = new Ctx { Config = config, Domains = PhishGuard.Domains.BuildContext(config) };
            var headers = ParseHeaders(e.RawHeaders);
            var findings = new List<Finding>();
            var positives = new List<string>();

            AnalyzeAuth(e, headers, ctx, findings, positives);
            AnalyzeSender(e, headers, ctx, findings, positives);
            AnalyzeThread(e, headers, ctx, findings);
            AnalyzeHiddenRecipients(e, headers, ctx, findings);
            var urls = new List<string>();
            var linkDomains = new List<string>();
            AnalyzeLinks(e, ctx, findings, urls, linkDomains);
            AnalyzeBodyAddresses(e, headers, ctx, findings);
            AnalyzeMixedScripts(e, ctx, findings);
            var attNames = new List<string>();
            AnalyzeAttachments(e, ctx, findings, attNames);
            AnalyzeContent(e, headers, ctx, findings);
            AnalyzeFilters(e, headers, ctx, findings);
            var details = Forensics.ParseHeaders(e.RawHeaders);
            details.Auth.DmarcDerived = ctx.DmarcDerived;
            var sources = new List<SourceStatus>();
            AnalyzeIntel(e, ctx, details, findings, positives, urls, linkDomains, sources);

            // Envoi en nombre conforme aux règles Gmail/Yahoo/Microsoft : le ton commercial n'est pas un indice
            if (ctx.BulkCompliant && !ctx.Internal)
                foreach (var f in findings)
                    if (f.Category == "content" && f.Severity == Severity.Low) f.Severity = Severity.Info;

            // Domaine officiel d'une marque, authentifié : le texte (code, facture, mot de passe) est celui de la marque elle-même
            if (ctx.BrandSender || ctx.CodeMessage)
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
                InternalHow = ctx.InternalHow,
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

        // « code : 360928 », « Login Code: 360 928 », « votre code de vérification est 4829 13 »
        static readonly Regex CodeRe = new Regex(@"\b(code|codes|otp|pin|passcode|one-time password|mot de passe a usage unique)\b[^0-9]{0,40}?(?<![0-9])(\d{3}[ -]?\d{3}|\d{4,8})(?![0-9])", RegexOptions.IgnoreCase);

        /// <summary>Vrai message de code : il contient un code, est authentifié sur le domaine affiché, ne présente aucun indice
        /// d'usurpation (sosie, nom de marque, Reply-To…) et tous ses liens mènent au domaine de l'expéditeur. Un phishing,
        /// lui, a besoin d'envoyer la victime ailleurs.</summary>
        static bool IsCodeMessage(EmailData e, string normText, Ctx ctx, List<Finding> findings)
        {
            if (!ctx.AuthProof || ctx.Platform || ctx.Internal || ctx.FromOrg.Length == 0) return false;
            if (!CodeRe.IsMatch(normText)) return false;
            if (findings.Any(f => (f.Category == "sender" || f.Category == "auth" || f.Category == "links" || f.Category == "attachments") && f.Severity >= Severity.Medium)) return false;
            if (findings.Any(f => f.Id.Contains("new-domain") || f.Id.Contains("blocklist"))) return false;   // domaine récent ou listé : un vrai service n'en a pas
            if (e.HasForm || e.HasPasswordInput) return false;
            if (e.Attachments.Any(a => !(a.IsInline && a.IsImage))) return false;
            foreach (var l in e.Links)
            {
                string href = (l.Href ?? "").Trim();
                if (href.Length == 0 || href.StartsWith("#") || href.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase) || href.StartsWith("tel:", StringComparison.OrdinalIgnoreCase)) continue;
                Uri u;
                if (!Uri.TryCreate(href, UriKind.Absolute, out u) || (u.Scheme != "https" && u.Scheme != "http")) return false;
                // Adresse d'une image (logo, pixel d'espacement) recopiée dans la version texte par Outlook : ce n'est pas un lien cliquable
                if (string.IsNullOrEmpty(l.Text) && ImagePathRe.IsMatch(u.AbsolutePath)) continue;
                if (PhishGuard.Domains.RegistrableDomain(PhishGuard.Domains.HostOf(u)) != ctx.FromOrg) return false;
            }
            return true;
        }

        static readonly Regex ImagePathRe = new Regex(@"\.(png|jpe?g|gif|bmp|webp|svg|ico)$", RegexOptions.IgnoreCase);

        /// <summary>Le poste lui-même (localhost, 127.x) ou une adresse privée du réseau local (10.x, 172.16-31.x, 192.168.x).</summary>
        internal static bool IsLocalHost(string host)
        {
            string h = (host ?? "").ToLowerInvariant().Trim('[', ']');
            if (h == "localhost" || h.EndsWith(".localhost") || h == "::1") return true;
            var m = Regex.Match(h, @"^(\d+)\.(\d+)\.\d+\.\d+$");
            if (!m.Success) return false;
            int a = int.Parse(m.Groups[1].Value), b = int.Parse(m.Groups[2].Value);
            return a == 127 || a == 10 || (a == 192 && b == 168) || (a == 172 && b >= 16 && b <= 31);
        }

        static bool IsDecisiveContent(string id)
        {
            return id.StartsWith("content-combo-") || id == "content-iban-change";
        }

        // Lettres cyrilliques et grecques identiques à l'œil à une lettre latine (homoglyphes)
        static readonly Dictionary<char, char> Confusables = BuildConfusables();

        static Dictionary<char, char> BuildConfusables()
        {
            const string from = "\u0430\u0435\u043E\u0440\u0441\u0443\u0445\u0456\u0458\u0455\u0501\u04BB\u04CF\u051B\u051D"   // а е о р с у х і ј ѕ ԁ һ ӏ ԛ ԝ
                + "\u0410\u0412\u0415\u041A\u041C\u041D\u041E\u0420\u0421\u0422\u0425\u0423\u0406\u0408\u0405"                   // А В Е К М Н О Р С Т Х У І Ј Ѕ
                + "\u03BF\u03BD\u03C1\u03B9\u03BA\u03C7"                                                                                    // ο ν ρ ι κ χ
                + "\u0391\u0392\u0395\u0396\u0397\u0399\u039A\u039C\u039D\u039F\u03A1\u03A4\u03A5\u03A7";                         // Α Β Ε Ζ Η Ι Κ Μ Ν Ο Ρ Τ Υ Χ
            const string to = "aeopcyxijsdhlqw" + "ABEKMHOPCTXYIJS" + "ovpikx" + "ABEZHIKMNOPTYX";
            var d = new Dictionary<char, char>();
            for (int i = 0; i < from.Length; i++) d[from[i]] = to[i];
            return d;
        }

        static readonly Regex WordRe = new Regex(@"\p{L}+");

        static bool IsLatinLetter(char c) { return c < 0x250 && char.IsLetter(c); }

        /// <summary>
        /// Mot latin dont certaines lettres sont des homoglyphes cyrilliques ou grecs (« Micrоsoft » avec un « о » cyrillique) :
        /// procédé pour tromper les filtres. Un mot entièrement cyrillique ou grec n'est pas concerné, ni une lettre grecque
        /// sans équivalent latin (µ, Δ…).
        /// </summary>
        static bool IsMixedWord(string w)
        {
            bool latin = false, fake = false;
            foreach (char c in w)
            {
                if (IsLatinLetter(c)) latin = true;
                else if (Confusables.ContainsKey(c)) fake = true;
                else return false;
            }
            return latin && fake && w.Length >= 3;
        }

        public static List<string> MixedWords(string s)
        {
            var res = new List<string>();
            foreach (Match m in WordRe.Matches(s ?? ""))
                if (IsMixedWord(m.Value) && !res.Contains(m.Value)) res.Add(m.Value);
            return res;
        }

        /// <summary>Remplace les homoglyphes par la lettre latine qu'ils imitent, dans les mots mélangés seulement.</summary>
        public static string FoldConfusables(string s)
        {
            if (string.IsNullOrEmpty(s)) return s ?? "";
            return WordRe.Replace(s, m =>
            {
                if (!IsMixedWord(m.Value)) return m.Value;
                var sb = new StringBuilder(m.Value.Length);
                foreach (char c in m.Value) { char l; sb.Append(Confusables.TryGetValue(c, out l) ? l : c); }
                return sb.ToString();
            });
        }

        public static string NormalizeText(string s)
        {
            string t = PhishGuard.Domains.RemoveDiacritics(FoldConfusables(s ?? "").ToLowerInvariant());
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

        static readonly Regex AddressRe = new Regex(@"[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}");   // longueurs bornées : temps linéaire sur un en-tête piégé

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
            return WordContains(haystack ?? "", NormalizeText(needle));
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

        /// <summary>Équipement déclaré qui écrit au nom d'une adresse qui n'est pas la sienne : équipement piraté ou détourné.</summary>
        /// <returns>true si l'expéditeur est autorisé pour cet équipement.</returns>
        static bool CheckRelaySender(EmailData e, string ip, Ctx ctx, List<Finding> findings)
        {
            List<string> allowed;
            if (InternalNet.SenderAllowed(ip, e.FromAddress, ctx.Config.InternalRelays, out allowed))
            {
                // Montré dans l'analyse détaillée : on voit quelle déclaration a reconnu le message
                if (!findings.Any(f => f.Id == "auth-internal-relay"))
                    findings.Add(new Finding("auth-internal-relay", "auth", Severity.Info, L.T("Équipement interne de l’entreprise"),
                        allowed.Count > 0 ? L.T("Équipement déclaré dans Paramètres → Entreprise, qui écrit au nom d’une adresse autorisée.")
                                          : L.T("Équipement déclaré dans Paramètres → Entreprise sans adresse d’expéditeur : il peut écrire au nom de n’importe qui. Ajoutez son adresse après l’IP pour repérer un équipement piraté."),
                        new[] { L.T("Équipement : ") + ip, L.T("Au nom de : ") + e.FromAddress, L.T("Adresses autorisées : ") + (allowed.Count > 0 ? string.Join(", ", allowed.ToArray()) : L.T("toutes")) }));
                ctx.RelayProof = allowed.Count > 0
                    ? L.F("Équipement interne déclaré ({0}), autorisé à écrire au nom de : {1}", ip, string.Join(", ", allowed.ToArray()))
                    : L.F("Équipement interne déclaré ({0}), sans restriction d’expéditeur", ip);
                ctx.Trust.Add(ctx.RelayProof);
                ctx.Internal = true;
                ctx.InternalHow = "relay";
                return true;
            }
            ctx.InternalForged = true;
            if (findings.Any(f => f.Id == "auth-internal-relay-sender")) return false;
            findings.Add(new Finding("auth-internal-relay-sender", "auth", Severity.Critical, L.T("Un équipement déclaré écrit au nom d’une adresse qui n’est pas la sienne"),
                L.T("Cet équipement (alertes, copieur, application) n’a le droit d’écrire qu’au nom des adresses déclarées dans Paramètres → Entreprise. Un message au nom d’une autre personne venant de lui signale un équipement piraté ou détourné. Ne cliquez sur rien et prévenez le service informatique."),
                new[] { L.T("Équipement : ") + ip, L.T("Au nom de : ") + e.FromAddress, L.T("Adresses autorisées : ") + string.Join(", ", allowed.ToArray()) }));
            return false;
        }

        /// <summary>Origine d'un message au nom de l'entreprise : poste de travail, machine non déclarée, ou serveur de messagerie.</summary>
        /// <returns>true si le message vient d'un équipement déclaré, autorisé : l'authentification n'a pas à être examinée.</returns>
        static bool CheckInternalOrigin(EmailData e, List<KeyValuePair<string, string>> headers, string authAs, string authMech, Ctx ctx, List<Finding> findings)
        {
            var origin = InternalNet.Origin(headers);
            string ip = origin != null ? origin.FromIp : "";
            if (ip.Length == 0) return false;
            var cfg = ctx.Config;
            bool workstation = InternalNet.Matches(ip, cfg.WorkstationNets);
            // Serveur ou équipement déclaré ; dans un réseau de postes, seule une adresse déclarée une par une compte (pas une grande plage)
            if (workstation ? InternalNet.MatchesExact(ip, cfg.MailServers) : InternalNet.Matches(ip, cfg.MailServers)) return false;
            if (workstation ? InternalNet.MatchesExact(ip, cfg.InternalRelays) : InternalNet.Matches(ip, cfg.InternalRelays))
            {
                return CheckRelaySender(e, ip, ctx, findings);   // équipement déclaré : seulement au nom des adresses prévues
            }
            if (Forensics.IsPublicIp(ip) && !workstation) return false;                                                   // venu de l'extérieur : contrôles habituels
            // AuthMechanism 10 : Exchange a fait confiance à l'adresse IP de la machine (connecteur de relais « Externally Secured »),
            // sans identifiants. Le message passe pour interne mais n'importe quel expéditeur a pu être écrit : pas une authentification.
            bool relayTrust = authMech == "10";
            bool exchangeAuth = (e.IsExchangeInternal || authAs == "internal") && !relayTrust;
            bool declared = cfg.MailServers.Count > 0 || cfg.WorkstationNets.Count > 0;
            string where = ip + (origin.FromHost.Length > 0 && origin.FromHost != ip ? " (" + L.T("annoncé comme ") + origin.FromHost + ")" : "");
            var ev = new[] { L.T("Parti de : ") + where, L.T("Au nom de : ") + e.FromAddress };
            if (workstation && !exchangeAuth)
            {
                findings.Add(new Finding("auth-internal-workstation", "auth", Severity.Critical, L.T("Message « interne » fabriqué depuis un poste de travail"),
                    L.T("Ce message est parti directement d’un poste du réseau interne, sans passer par l’authentification de votre messagerie : quelqu’un sur le réseau l’a fabriqué. Ne cliquez sur rien et prévenez le service informatique en lui indiquant l’adresse du poste."), ev));
                ctx.InternalForged = true;
            }
            else if (workstation)
                // Authentifié, mais envoyé en SMTP depuis un poste et non depuis Outlook : logiciel de messagerie autre qu'Outlook,
                // script, ou relais interne qui fait passer n'importe quel message pour un message authentifié
                findings.Add(new Finding("auth-internal-smtp", "auth", Severity.Medium, L.T("Message interne envoyé directement depuis un poste, sans passer par Outlook"),
                    L.T("Votre serveur l’a accepté comme interne, mais il a été déposé en SMTP par un poste de travail. Normal pour un logiciel de messagerie autre qu’Outlook ou un script connu ; sinon, quelqu’un a pu le fabriquer au nom de cet expéditeur. En cas de doute, vérifiez auprès de lui par un autre moyen."), ev));
            else if (exchangeAuth) return false;   // message Exchange : ses serveurs ne sont pas forcément tous déclarés
            else if (declared)
            {
                findings.Add(new Finding("auth-internal-undeclared", "auth", Severity.Critical, L.T("Message « interne » venu d’une machine non déclarée"),
                    (relayTrust ? L.T("Votre serveur l’a accepté comme interne sur la seule foi de l’adresse IP de la machine (relais sans identifiants) : n’importe quel expéditeur a pu être écrit.") + " " : "")
                    + L.T("Ce message ne vient ni d’un serveur de messagerie ni d’un équipement déclaré : possible message fabriqué depuis le réseau. Si c’est un équipement légitime (alertes, application), déclarez-le dans Paramètres → Entreprise avec son adresse d’expéditeur."), ev));
                ctx.InternalForged = true;
            }
            else if (authAs == "anonymous" || relayTrust)
            {
                ctx.InternalForged = relayTrust;   // pas une authentification : le message n'est pas traité comme interne
                findings.Add(new Finding("auth-internal-anonymous", "auth", Severity.Medium, L.T("Message non authentifié venu du réseau interne"),
                    L.T("Le serveur de messagerie l’a reçu sans authentification d’une machine interne. Normal pour un copieur ou une application ; sinon, il a pu être fabriqué depuis un poste. Déclarez vos serveurs, équipements et réseaux des postes dans Paramètres → Entreprise pour un diagnostic sûr."), ev));
            }
            return false;
        }

        static void AnalyzeAuth(EmailData e, List<KeyValuePair<string, string>> headers, Ctx ctx, List<Finding> findings, List<string> positives)
        {
            string fromDomain = PhishGuard.Domains.DomainOfAddress(e.FromAddress);
            string fromOrg = PhishGuard.Domains.RegistrableDomain(fromDomain);
            bool fromCompany = ctx.Domains.CompanyDomains.Contains(fromOrg);

            string authAs = (HeaderValues(headers, "x-ms-exchange-organization-authas").FirstOrDefault() ?? "").ToLowerInvariant();
            // Message à votre nom parti d'une machine du réseau interne : quelqu'un l'a fabriqué depuis un poste (envoi SMTP direct).
            // Vérifié avant tout le reste : un connecteur de relais interne peut faire passer un tel message pour un message Exchange.
            string authMech = (HeaderValues(headers, "x-ms-exchange-organization-authmechanism").FirstOrDefault() ?? "").Trim();
            // Compte IMAP/POP (Gmail, Orange…) : ces en-têtes ne sont pas écrits par votre Exchange, l'expéditeur a pu les ajouter
            // pour faire passer son message pour interne. Ils sont ignorés.
            if (e.NonExchangeStore) { authAs = ""; authMech = ""; }
            // Quel que soit l'expéditeur affiché : une machine du réseau peut aussi écrire au nom d'une adresse externe
            // (fausse alerte Microsoft) ou d'un nom de machine (supervision@serveur)
            if (CheckInternalOrigin(e, headers, authAs, authMech, ctx, findings))
            {
                positives.Add(ctx.RelayProof);
                return;
            }

            if ((e.IsExchangeInternal || authAs == "internal") && !ctx.InternalForged)
            {
                positives.Add(L.T("Message interne, authentifié par votre serveur Exchange"));
                ctx.Internal = true;
                ctx.InternalHow = "exchange";
                return;
            }
            // Copieur, application ou serveur interne déclaré, qui envoie au nom de l'entreprise sans s'authentifier
            if (fromCompany && ctx.Config.InternalRelays.Count > 0 && !ctx.InternalForged)
            {
                // L'équipement est la machine d'où le message est parti (ou le client vu par Microsoft 365), pas un serveur
                // traversé : un serveur de messagerie déclaré comme équipement (rapports Exchange) ne doit pas juger les
                // messages qui ne font que passer par lui.
                var relays = InternalNet.Expand(ctx.Config.InternalRelays);
                var originHop = InternalNet.Origin(headers);
                string cip = Forensics.ClientIp(headers);
                string relayIp = cip.Length > 0 && Forensics.IpInList(cip, relays) ? cip
                    : originHop != null && Forensics.IpInList(originHop.FromIp, relays) ? originHop.FromIp : null;
                if (relayIp == null)
                {
                    // Relais intermédiaire (serveur qui collecte les envois des copieurs) : accepté seulement s'il n'est pas limité à ses propres adresses
                    string transit = Forensics.InternalRelayIp(headers, relays);
                    List<string> none;
                    if (transit != null && InternalNet.SenderAllowed(transit, "", ctx.Config.InternalRelays, out none)) relayIp = transit;
                }
                if (relayIp != null && CheckRelaySender(e, relayIp, ctx, findings))
                {
                    positives.Add(ctx.RelayProof);
                    return;
                }
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
                // Au nom de votre entreprise, venu d'Internet, et rien ne prouve qu'il est authentique
                var o = InternalNet.Origin(headers);
                if (fromCompany && o != null && Forensics.IsPublicIp(o.FromIp))
                    findings.Add(new Finding("auth-company-noauth", "auth", Severity.High, L.T("Message au nom de votre entreprise venu d’Internet, sans authentification"),
                        L.T("Il se présente comme venant de votre entreprise, mais il est arrivé de l’extérieur et aucun contrôle (SPF, DKIM, DMARC) ne le confirme. Vérifiez auprès de l’expéditeur par un autre moyen."), new[] { L.T("Parti de : ") + o.FromIp }));
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
                    L.T("L’expéditeur utilise un domaine de votre entreprise mais le message vient de l’extérieur et n’est pas authentifié.")
                    + (ctx.Config.InternalRelays.Count > 0 ? " " + L.T("Il ne vient d’aucun équipement interne déclaré.") : ""), new[] { fromDomain }));

            // Ni SPF ni DKIM : rien ne relie le message au domaine affiché. Les envois en nombre légitimes sont tous authentifiés
            // (exigence de Gmail, Yahoo et Microsoft depuis 2024)
            bool noSpf = spf == null || spf == "none" || spf == "temperror" || spf == "permerror";
            bool noDkim = dkim == null || dkim == "none";
            // Listes de diffusion exclues : elles réécrivent le message et ses résultats d'authentification sont souvent perdus
            bool mailingList = HeaderValues(headers, "list-id").Any() || HeaderValues(headers, "list-post").Any() || HeaderValues(headers, "mailing-list").Any();
            if (!fromCompany && !mailingList && noSpf && noDkim && dmarc != "pass" && compauth != "pass")
            {
                bool bulk = HeaderValues(headers, "precedence").Any(v => v.Trim().ToLowerInvariant() == "bulk") || HeaderValues(headers, "list-unsubscribe").Any();
                findings.Add(new Finding("auth-none", "auth", bulk ? Severity.Medium : Severity.Low, L.T("Aucune authentification de l’expéditeur"),
                    bulk ? L.T("Ni SPF ni DKIM pour un envoi en nombre : les vraies lettres d’information et notifications sont toutes authentifiées. Rien ne prouve que le message vient du domaine affiché.")
                         : L.T("Ni SPF ni DKIM : rien ne prouve que le message vient du domaine affiché."), new[] { "spf=" + (spf ?? "?") + " dkim=" + (dkim ?? "?") + " dmarc=" + (dmarc ?? "?") }));
            }

            if (spf == "pass") positives.Add(L.T("SPF valide"));
            if (dkim == "pass") positives.Add(L.T("Signature DKIM valide"));
            if (dmarc == "pass") positives.Add(L.T("DMARC valide pour ") + (headerFrom ?? fromDomain));
            ctx.AuthOk = !ctx.InternalForged && (dmarc == "pass" || (spf == "pass" && dkim == "pass" && dmarc != "fail"));

            // Alignement : la signature DKIM / l'enveloppe SPF appartiennent-elles au domaine affiché ?
            var dkimPass = Forensics.DkimPassDomains(ar);
            bool dkimAligned = fromOrg.Length > 0 && dkimPass.Any(d => PhishGuard.Domains.RegistrableDomain(d) == fromOrg);
            string mailFrom = Pick(@"smtp\.mailfrom=([^\s;]+)", ar) ?? "";
            string mailFromDomain = mailFrom.Contains("@") ? PhishGuard.Domains.DomainOfAddress(mailFrom) : mailFrom.TrimEnd('.');
            bool spfAligned = spf == "pass" && fromOrg.Length > 0 && PhishGuard.Domains.RegistrableDomain(mailFromDomain) == fromOrg;
            bool dmarcOk = dmarc == "pass";
            bool compStrong = compauth == "pass" && reason.StartsWith("1");
            // Passerelle qui vérifie SPF et DKIM sans écrire de résultat DMARC (FortiMail, par exemple) :
            // DMARC réussit dès que l'un des deux est valide ET aligné sur le domaine affiché (RFC 7489). Affiché, sans changer le score.
            if (dmarc == null && (dkimAligned || spfAligned)) ctx.DmarcDerived = dkimAligned ? "dkim" : "spf";

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
            // Organisme public : domaine .gouv.fr (réservé à l'État) ou présent dans la liste officielle du secteur public
            ctx.PublicBody = !isFreemail && Feeds.IsPublicSector(fromDomain);
            if (ctx.PublicBody) ctx.Domains.Legit.Add(fromOrg);

            // Premier contact et sosies de vos correspondants (fournisseurs, clients...)
            // Liste de diffusion : le message est adressé à la liste (son adresse de publication figure dans À/Cc), pas à vous
            var postAddrs = AddressesIn(string.Join(",", HeaderValues(headers, "list-post")));
            var toCc = AddressesIn(string.Join(",", HeaderValues(headers, "to").Concat(HeaderValues(headers, "cc"))));
            bool mailingList = HeaderValues(headers, "list-id").Count > 0 && postAddrs.Any(a => toCc.Contains(a));
            ctx.MailingList = mailingList;
            // Adresse réécrite par la liste (« nom@entreprise.com.invalid ») pour respecter DMARC : ce n'est pas un sosie
            bool listMunged = mailingList && fromDomain.EndsWith(".invalid");

            if (cfg.KnownCorrespondents && Correspondents.Loaded && !isCompany && !ctx.Internal && !e.IsExchangeInternal)
            {
                bool knownAddr = Correspondents.IsKnownAddress(fromAddr);
                bool knownDomain = !isFreemail && Correspondents.IsKnownDomain(fromOrg);
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
                if (!knownDomain && !ctx.Domains.Legit.Contains(fromOrg) && !listMunged)
                    CheckCorrespondentLookalike(fromDomain, L.T("Le domaine de l’expéditeur"), findings);
            }

            // Âge du domaine (RDAP)
            CheckDomainAge(fromOrg, L.T("Le domaine de l’expéditeur"), "sender-new-domain", ctx, findings);

            // Domaine qui ne peut pas exister, ou nom tiré au hasard (envois jetables en masse)
            if (fromDomain.Length > 0 && !isCompany && !ctx.Internal)
            {
                if (!PhishGuard.Domains.IsSyntaxValid(fromDomain))
                    findings.Add(new Finding("sender-invalid-domain", "sender", Severity.High, L.T("Le domaine de l’expéditeur ne peut pas exister"),
                        L.T("Ce nom de domaine est invalide (tiret au début ou à la fin, caractère interdit) : il n’existe dans aucun registre. L’adresse est fabriquée, aucune réponse ne peut y arriver."), new[] { fromDomain }));
                else if (!isFreemail && !ctx.Domains.Legit.Contains(fromOrg) && PhishGuard.Domains.LooksRandom(fromOrg))
                    findings.Add(new Finding("sender-random-domain", "sender", Severity.Medium, L.T("Nom de domaine de l’expéditeur tiré au hasard"),
                        L.T("Une suite de lettres et de chiffres sans signification : typique des domaines jetables utilisés pour les envois en masse (spam, phishing)."), new[] { fromOrg }));
            }

            var look = listMunged ? null : PhishGuard.Domains.DetectLookalike(fromDomain, ctx.Domains);
            // Sosie d'une marque ou de votre entreprise, mais message authentifié : le domaine est peut-être le sien
            // (autre extension, ancien nom). Preuve vérifiable : ses serveurs DNS sont ceux de la marque.
            if (look != null && ctx.AuthProof && !isFreemail && Intel.Settings.DnsChecks)
            {
                var officials = look.IsCompany ? ctx.Domains.CompanyDomains.ToList()
                    : Lists.Brands.Where(b => b.Name == look.Brand).SelectMany(b => b.Domains).Select(d => PhishGuard.Domains.RegistrableDomain(d)).Distinct().ToList();
                var proof = officials.Count == 0 ? null : Intel.GetOrRequest(Intel.OwnerKey(fromOrg, officials));
                if (proof != null && proof.Ok && proof.Found)
                {
                    string who = look.IsCompany ? L.T("votre entreprise") : look.Brand;
                    ctx.ProvenBrand = look.IsCompany ? null : look.Brand;
                    ctx.ProvenCompany = look.IsCompany;
                    ctx.Domains.Legit.Add(fromOrg);
                    findings.Add(new Finding("sender-owner-proven", "sender", Severity.Info, L.F("Domaine rattaché à {0}", who),
                        L.T("Il ressemble à un domaine officiel, mais il est géré par les mêmes serveurs que celui-ci : il appartient au même propriétaire."),
                        new[] { fromOrg + " : " + proof.Label }));
                    ctx.Trust.Add(L.F("Domaine rattaché à {0} : géré par ses propres serveurs ({1})", who, proof.Label));
                    positives.Add(L.F("Domaine rattaché à {0}", who));
                    look = null;
                }
            }
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
                if ((ctx.PublicBody && ctx.AuthOk) || ctx.ProvenBrand == b.Name) break;   // organisme public authentifié, ou domaine prouvé de la marque
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

            if (!isCompany && !ctx.ProvenCompany)
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
            var ownBrand = Lists.Brands.FirstOrDefault(b => b.Domains.Any(d => PhishGuard.Domains.RegistrableDomain(d) == fromOrg));
            bool gouv = fromOrg == "gouv.fr" || fromOrg.EndsWith(".gouv.fr");
            // Les petites structures publiques de la liste (communes, écoles…) se font souvent pirater leur messagerie :
            // elles sont reconnues (ni sosie, ni « inconnu »), mais leur texte n'est pas adouci comme celui d'une marque ou de l'État.
            ctx.PublicListed = ctx.PublicBody && !gouv && ctx.AuthProof && !ctx.Internal && look == null && ownBrand == null;
            ctx.BrandSender = ctx.AuthProof && !isFreemail && !ctx.Internal && !ctx.Platform && look == null
                && (ownBrand != null || ctx.ProvenBrand != null || (ctx.PublicBody && gouv));
            if (ctx.BrandSender)
            {
                string why = ownBrand != null ? L.F("Envoyé et authentifié par un domaine officiel de {0}", ownBrand.Name)
                    : ctx.ProvenBrand != null ? L.F("Envoyé et authentifié par un domaine rattaché à {0}", ctx.ProvenBrand)
                    : L.T("Envoyé et authentifié par un domaine .gouv.fr (réservé aux services de l’État)");
                ctx.Trust.Add(why);
                positives.Add(why);
                ctx.RelationProof = true;   // réputation de la marque ou de l'organisme : suffit pour « Expéditeur vérifié » s'il n'y a aucun indice
            }
            else if (ctx.PublicListed)
            {
                string why = L.T("Envoyé et authentifié par un organisme public (liste officielle des domaines du secteur public)");
                ctx.Trust.Add(why);
                positives.Add(why);
                ctx.RelationProof = true;
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
            @"^(no[-_]?reply|ne[-_]?pas[-_]?repondre|do[-_]?not[-_]?reply|donotreply|noreponse|notifications?|alerts?|mailer-daemon|bounce[s]?|newsletter|news|info|mailing|system|automated|account-security-noreply)([._+-].*)?$",
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

        // Lien « Répondre / Contactez-nous » (texte du lien)
        static readonly Regex ReplyLinkTextRe = new Regex(@"\b(r[ée]pond(re|ez|ez-nous)|reply|respond|contact(ez|er)?(-nous)?|contact us|[ée]crivez(-nous)?|write to us|nous [ée]crire)\b", RegexOptions.IgnoreCase);
        static readonly Regex UnsubscribeRe = new Regex(@"unsubscribe|d[ée]sinscri|d[ée]sabonn|opt[-_]?out|^(leave|remove|list)[-_.+]", RegexOptions.IgnoreCase);

        /// <summary>
        /// Adresses email écrites dans le message ou dans un lien mailto: (« écrivez-nous à … », bouton « Répondre ») :
        /// arnaques sans lien qui demandent d'écrire à une autre adresse (faux support, fausse facture, fraude au président).
        /// </summary>
        static void AnalyzeBodyAddresses(EmailData e, List<KeyValuePair<string, string>> headers, Ctx ctx, List<Finding> findings)
        {
            // Liste de diffusion : les messages citent et proposent d'écrire aux autres membres
            bool mailingList = HeaderValues(headers, "list-id").Any() || HeaderValues(headers, "list-post").Any() || HeaderValues(headers, "mailing-list").Any();
            string fromAddr = (e.FromAddress ?? "").Trim().ToLowerInvariant();
            string fromOrg = PhishGuard.Domains.RegistrableDomain(PhishGuard.Domains.DomainOfAddress(fromAddr));
            var mailtos = new List<KeyValuePair<string, string>>();   // adresse, texte du lien
            foreach (var l in e.Links)
            {
                string href = (l.Href ?? "").Trim();
                if (!href.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase)) continue;
                if (UnsubscribeRe.IsMatch(href) || UnsubscribeRe.IsMatch(l.Text ?? "")) continue;   // désinscription d'une lettre d'information
                string decoded = href;
                try { decoded = Uri.UnescapeDataString(href); } catch (Exception) { }
                foreach (var a in AddressesIn(decoded.Split('?')[0])) mailtos.Add(new KeyValuePair<string, string>(a, Regex.Replace(l.Text ?? "", @"\s+", " ").Trim()));
            }
            var mailtoSet = new HashSet<string>(mailtos.Select(m => m.Key));
            // Extensions réservées (.invalid, .example…) : adresses volontairement factices (listes Apache, exemples)
            var all = AddressesIn(e.BodyText ?? "").Concat(mailtos.Select(m => m.Key)).Distinct()
                .Where(a => !Regex.IsMatch(a, @"\.(invalid|example|test|localhost|local)$")).ToList();
            // Adresses de l'expéditeur, de l'entreprise ou d'un domaine connu : rien à vérifier. Une messagerie gratuite
            // (gmail.com…) est un domaine connu, mais n'importe qui y crée une adresse : elle reste vérifiée.
            Func<string, bool> foreign = a =>
            {
                string dom = PhishGuard.Domains.DomainOfAddress(a);
                string org = PhishGuard.Domains.RegistrableDomain(dom);
                bool free = Lists.FreemailDomains.Contains(dom) || Lists.FreemailDomains.Contains(org);
                return org.Length > 0 && org != fromOrg && !ctx.Domains.CompanyDomains.Contains(org) && (free || !ctx.Domains.Legit.Contains(org)) && !UnsubscribeRe.IsMatch(a);
            };
            var others = all.Where(foreign).Take(12).ToList();
            if (others.Count == 0) return;
            string where = L.T("Une adresse email du message");

            // Sosie, liste de domaines malveillants, domaine récent, sosie d'un correspondant : une seule alerte par contrôle
            int ages = 0;
            bool look = false, listed = false, corr = false;
            foreach (var a in others)
            {
                string dom = PhishGuard.Domains.DomainOfAddress(a);
                string org = PhishGuard.Domains.RegistrableDomain(dom);
                bool free = Lists.FreemailDomains.Contains(dom) || Lists.FreemailDomains.Contains(org);
                if (!look)
                {
                    var lk = PhishGuard.Domains.DetectLookalike(dom, ctx.Domains);
                    // Adresse écrite dans le texte : seules les imitations nettes comptent (votre entreprise, caractère
                    // trompeur, autre extension) ; les fautes de frappe ou ajouts tombent sur de vrais domaines (email.com…)
                    bool strong = lk != null && (mailtoSet.Contains(a) || lk.IsCompany || lk.Technique == "homoglyph" || lk.Technique == "unicode" || lk.Technique == "tld");
                    if (strong) { var f = LookalikeFinding(lk, where, "content"); f.Evidence.Add(a); findings.Add(f); look = true; }
                }
                if (!listed)
                {
                    var hit = Blocklists.Lookup(dom);
                    if (hit != null) { findings.Add(BlocklistFinding(hit, L.T("Une adresse email du message utilise un domaine malveillant connu"), "content", new[] { a })); listed = true; }
                }
                if (!free && ages < 2) { ages++; CheckDomainAge(org, L.T("Le domaine d’une adresse du message"), "content-address-new-domain", ctx, findings); }
                if (!free && !corr && !mailingList && ctx.Config.KnownCorrespondents && Correspondents.Loaded && !Correspondents.IsKnownDomain(org))
                {
                    int before = findings.Count;
                    CheckCorrespondentLookalike(dom, L.T("Le domaine d’une adresse du message"), findings);
                    corr = findings.Count > before;
                }
            }
            if (ctx.Internal || mailingList) return;
            bool senderFree = Lists.FreemailDomains.Contains(PhishGuard.Domains.DomainOfAddress(fromAddr));

            // Lien « Répondre » ou « Contactez-nous » vers une autre adresse que l'expéditeur
            var reply = mailtos.FirstOrDefault(m => foreign(m.Key) && ReplyLinkTextRe.IsMatch(m.Value));
            if (reply.Key != null && !senderFree)   // d'une messagerie gratuite à une autre : une personne, pas un service usurpé
            {
                bool free = Lists.FreemailDomains.Contains(PhishGuard.Domains.DomainOfAddress(reply.Key));
                findings.Add(new Finding("content-mailto-other", "content", free ? Severity.High : Severity.Medium,
                    L.F("Le lien « {0} » écrit à une autre adresse que l’expéditeur", reply.Value.Length > 40 ? reply.Value.Substring(0, 40) + "…" : reply.Value),
                    free ? L.T("Votre réponse partirait vers une messagerie gratuite, pas vers l’expéditeur.") : L.T("Votre réponse partirait vers un autre domaine que celui de l’expéditeur."),
                    new[] { L.T("Écrire à : ") + reply.Key, L.T("Expéditeur : ") + fromAddr }));
            }

            // Se présente comme une marque, mais demande d'écrire à une messagerie gratuite
            string nameNorm = NormalizeText(e.FromName ?? ""), subjNorm = NormalizeText(e.Subject ?? "");
            var brand = Lists.Brands.FirstOrDefault(b => b.Names.Any(n => WordMatch(nameNorm, n) || (!b.Generic && WordMatch(subjNorm, n))));
            string freeContact = others.FirstOrDefault(a => Lists.FreemailDomains.Contains(PhishGuard.Domains.DomainOfAddress(a)));
            if (brand != null && freeContact != null && ctx.ProvenBrand != brand.Name)
                findings.Add(new Finding("content-brand-freemail-contact", "content", Severity.High,
                    L.F("Se présente comme « {0} » mais demande d’écrire à une messagerie gratuite", brand.Name),
                    L.F("Un vrai service {0} ne vous fait jamais écrire à une adresse Gmail, Outlook.com ou similaire.", brand.Name),
                    new[] { freeContact }));
        }

        /// <summary>Mots écrits avec des lettres cyrilliques ou grecques déguisées en lettres latines.</summary>
        static void AnalyzeMixedScripts(EmailData e, Ctx ctx, List<Finding> findings)
        {
            Func<string, string> shown = w =>
            {
                var fake = w.Where(c => Confusables.ContainsKey(c)).Distinct().Select(c => "« " + c + " »").ToArray();
                return w + L.F(" (lettre(s) {0} non latine(s))", string.Join(", ", fake));
            };
            var inName = MixedWords(e.FromName);
            var inSubject = MixedWords(e.Subject);
            var inBody = MixedWords(e.BodyText).Take(3).ToList();
            string detail = L.T("Des lettres cyrilliques ou grecques identiques à l’œil remplacent des lettres latines : le mot paraît normal mais n’est plus reconnu par les filtres. Un message légitime ne fait jamais ça.");
            if (inName.Count > 0)
                findings.Add(new Finding("sender-mixed-script", "sender", ctx.Internal ? Severity.Medium : Severity.High,
                    L.T("Le nom de l’expéditeur est écrit avec des lettres déguisées"), detail, inName.Take(3).Select(shown)));
            if (inSubject.Count > 0 || inBody.Count > 0)
            {
                var words = inSubject.Concat(inBody).Distinct().Take(3).ToList();
                findings.Add(new Finding("content-mixed-script", "content", inSubject.Count > 0 && !ctx.Internal ? Severity.High : Severity.Medium,
                    inSubject.Count > 0 ? L.T("L’objet contient des mots écrits avec des lettres déguisées") : L.T("Le message contient des mots écrits avec des lettres déguisées"),
                    detail, words.Select(shown)));
            }
        }

        /// <summary>
        /// Destinataires cachés : « À » ne contient que l'expéditeur lui-même (ou « destinataires non divulgués ») et vous
        /// recevez le message en copie cachée. Façon d'envoyer en masse depuis une boîte piratée sans montrer la liste.
        /// Aussi employé par des associations : indice faible, qui ne compte qu'avec d'autres.
        /// </summary>
        static void AnalyzeHiddenRecipients(EmailData e, List<KeyValuePair<string, string>> headers, Ctx ctx, List<Finding> findings)
        {
            if (ctx.Internal || e.IsExchangeInternal || headers.Count == 0) return;
            if (HeaderValues(headers, "list-id").Any() || HeaderValues(headers, "list-post").Any() || HeaderValues(headers, "mailing-list").Any()) return;
            if (!HeaderValues(headers, "received").Any()) return;   // copie locale (éléments envoyés…) : pas un message reçu
            string fromAddr = (e.FromAddress ?? "").Trim().ToLowerInvariant();
            if (fromAddr.Length == 0) return;
            string toRaw = string.Join(",", HeaderValues(headers, "to"));
            var toCc = AddressesIn(toRaw + "," + string.Join(",", HeaderValues(headers, "cc")));
            bool undisclosed = Regex.IsMatch(toRaw, @"undisclosed|non divulgu|non d[ée]voil|destinataires masqu|recipient list suppressed", RegexOptions.IgnoreCase)
                || (toRaw.Trim().Length == 0 && toCc.Count == 0);
            bool selfOnly = toCc.Count > 0 && toCc.All(a => a == fromAddr);
            if (!undisclosed && !selfOnly) return;
            findings.Add(new Finding("sender-hidden-recipients", "sender", Severity.Low,
                selfOnly ? L.T("L’expéditeur s’écrit à lui-même : vous êtes en copie cachée") : L.T("Destinataires masqués : vous êtes en copie cachée"),
                L.T("La liste des destinataires est cachée : envoi en nombre, parfois depuis une boîte piratée. Seul, ce n’est pas grave (des associations font ainsi) ; avec d’autres indices, c’est un signe de plus."),
                new[] { L.T("À : ") + (toRaw.Trim().Length > 0 ? toRaw.Trim() : L.T("(vide)")) }));
        }

        static void CheckDomainAge(string registrable, string where, string id, Ctx ctx, List<Finding> findings)
        {
            if (string.IsNullOrEmpty(registrable)) return;
            if (ctx.Domains.Legit.Contains(registrable) || ctx.Domains.CompanyDomains.Contains(registrable) || Lists.FreemailDomains.Contains(registrable)) return;
            DateTime? created;
            // Recherche automatique si l'option est active ; sinon seulement l'âge déjà récupéré d'un clic (onglet Réputation)
            if (!DomainAge.TryGetCreated(registrable, out created)) { if (ctx.Config.DomainAgeLookup) DomainAge.Request(registrable); return; }
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
            return PhishGuard.Domains.HostOf(u);
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
                    string ih = inner.Success && Uri.TryCreate(inner.Value, UriKind.Absolute, out iu) ? PhishGuard.Domains.RegistrableDomain(PhishGuard.Domains.HostOf(iu)) : "";
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
                // Poste ou réseau local : pas une page qu'un escroc peut héberger sur Internet. Le lien est listé (sans
                // vérification en ligne : l'adresse interne ne sort pas du poste) ; seul le réseau local fait l'objet d'un indice.
                if (IsLocalHost(host))
                {
                    urls.Add(url.AbsoluteUri);
                    string h = host.Trim('[', ']').ToLowerInvariant();
                    bool loopback = h == "localhost" || h.EndsWith(".localhost") || h == "::1" || h.StartsWith("127.");
                    if (!loopback)
                    {
                        if (ctx.Internal)
                            add("link-local-network", Severity.Info, L.T("Lien vers un équipement du réseau interne"),
                                L.T("Adresse d’un équipement de votre réseau (imprimante, serveur…) : elle ne s’ouvre que depuis l’intérieur de l’entreprise."), shownEv);
                        else
                            add("link-local-network", Severity.Low, L.T("Lien vers une adresse du réseau local"),
                                L.T("Un message venu de l’extérieur vous envoie vers une adresse de votre réseau local (box, imprimante, serveur) : un lien piégé peut ainsi modifier les réglages d’un équipement à votre insu. Vérifiez avant de cliquer."), shownEv);
                    }
                    continue;
                }
                string display = PhishGuard.Domains.ToUnicode(host);
                bool legit = ctx.Domains.Legit.Contains(p.Registrable) || Feeds.IsPublicSector(host);
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
                    // Accusé de lecture : un sous-domaine unique par destinataire (x7k2.domaine-arnaque.com) permettrait à son
                    // propriétaire de savoir quand le message est ouvert. Pour un domaine inconnu, seul le domaine principal est interrogé.
                    bool reputed = Feeds.TrancoRank(fromOrg) > 0 || Feeds.IsPublicSector(fromOrg) || Lists.Brands.Any(b => b.Domains.Contains(fromOrg));
                    string dnsDomain = reputed ? fromDomain : fromOrg;
                    dnsR = ask("dns:" + dnsDomain + "|" + fromOrg, "dns");
                    if (dnsR != null && dnsR.Exists)
                    {
                        if ((dnsR.DmarcPolicy == "reject" || dnsR.DmarcPolicy == "quarantine") && dnsR.DmarcPct >= 100)
                            ctx.Trust.Add(L.F("Le domaine demande d’écarter les messages usurpés (politique DMARC publiée : p={0})", dnsR.DmarcPolicy));
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
                            else if ((r.DmarcPolicy == "reject" || r.DmarcPolicy == "quarantine") && r.DmarcPct < 100)
                                add("sender-intel-dmarc-partial", cat, Severity.Info, L.F("Politique DMARC appliquée à {0} % des messages seulement", r.DmarcPct),
                                    L.T("Les autres messages usurpant ce domaine sont livrés normalement."), fromDomain);
                            if (r.SpfAll == "+")
                                add("sender-intel-spf-open", cat, Severity.Medium, L.T("Le domaine de l’expéditeur autorise n’importe quel serveur à envoyer en son nom (SPF +all)"),
                                    L.T("Avec « +all », le contrôle SPF réussit pour tout le monde : il ne prouve rien. Configuration jamais utilisée par une organisation sérieuse."), fromDomain);
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
                else if (c.Errors > 0)
                {
                    st.State = "error";
                    string err = Intel.LastErrorFor(service);
                    bool keyless = service == "dns" || service == "crt";
                    st.Detail = !keyless && Intel.KeyRefused(service) ? L.T("Clé refusée : vérifiez-la dans Paramètres → Réputation")
                        : L.T("Service momentanément indisponible, nouvel essai automatique dans 10 minutes")
                          + (service == "crt" ? " " + L.T("(crt.sh, service gratuit, est souvent surchargé)") : "");
                    if (err.Length > 0) st.Detail += " — " + err;
                }
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

        static readonly Regex IncomingMoneyRe = new Regex(@"\b(vous avez recu (un|le) (virement|versement)|virement recu|(a|ont) ete (credites?|verses?|vires?) sur votre compte|(sera|seront) (credites?|verses?|vires?) sur votre compte)\b", RegexOptions.Compiled);   // français uniquement : « payment received » est la formule des fausses factures à rappeler
        static readonly Regex PaymentRequestRe = new Regex(@"\b(merci de (regler|payer|proceder|effectuer|confirmer|valider|renseigner)|veuillez (regler|payer|proceder|effectuer|confirmer|valider|renseigner|remplir)|reglez|payez|effectuer (le|un|votre) (paiement|virement|reglement)|frais (de|a)|a regler|coordonnees bancaires|carte bancaire|numero de carte|rib|iban|eligible|formulaire|pour (recevoir|percevoir|obtenir|debloquer)|confirm|verify|update your|fee)\b", RegexOptions.Compiled);

        static readonly Regex CardAskRe = new Regex(@"\b((saisi(r|ssez)|indiqu(er|ez)|renseign(er|ez)|entr(er|ez)|confirm(er|ez)|communiqu(er|ez)|verifi(er|ez)) (votre |le |les |vos )?(numero de (votre )?carte( bancaire)?|cryptogramme|code cvv|donnees de (votre )?carte|coordonnees de (votre )?carte)|cryptogramme visuel|enter your (credit |debit )?card (number|details)|card verification (code|value))\b", RegexOptions.Compiled);
        // Numéros français (01 23 45 67 89, +33 1 23 45 67 89) et nord-américains (+1 (808) 555-0147, 1-888-555-0147)
        static readonly Regex PhoneNumberRe = new Regex(@"(?:\+33\s?(?:\(0\)\s?)?|\b0)[1-9](?:[\s.\-]?\d{2}){4}\b|(?:\+?\b1[\s.\-]?)?\(?\b[2-9]\d{2}\)?[\s.\-]\d{3}[\s.\-]\d{4}\b", RegexOptions.Compiled);
        static readonly Regex CallbackDisputeRe = new Regex(@"\b(si (vous n (etes|avez) pas|ce n est pas vous qui (avez|etes))\s?(a l origine|autorise|effectue|passe|commande|fait|demande|reconnaissez)?|vous n etes pas a l origine|vous ne reconnaissez pas|pour (annuler|contester|stopper|arreter|bloquer|resilier) (cette|la|ce|votre|le) (commande|transaction|paiement|prelevement|renouvellement|abonnement|achat|operation|debit)|(obtenir|demander) (un|le|votre) remboursement|did not (authorize|make|place|request|recognize)|didn t (authorize|make|place|request|recognize)|not authorized by you|(if|in case) (you|this) (wasn t|was not|weren t)|to cancel (this|the|your) (order|transaction|subscription|renewal|payment|charge)|(for|request|claim) (a|any|your) refund|dispute (this|the) (charge|transaction))\b", RegexOptions.Compiled);
        static readonly Regex CallbackChargeRe = new Regex(@"\b(factur\w*|commande|abonnement|renouvel\w*|prelev\w*|debit\w*|paiement|transaction|achat|invoice|order|subscription|renewal|renewed|charged?|payment|purchase)\b", RegexOptions.Compiled);
        static readonly Regex AmountRe = new Regex(@"\d[\d\s.,]{0,12}\s?(€|eur\b|euros?\b|\$|usd\b)|(\$|€|usd)\s?\d", RegexOptions.Compiled);
        static readonly Regex CallbackBrandRe = new Regex(@"\b(norton|mcafee|geek ?squad|best ?buy|paypal|avast|kaspersky|bitdefender|windows defender|lifelock|microsoft|apple|amazon|coinbase|binance|ebay)\b", RegexOptions.Compiled);

        static readonly Regex[] GamblingRes =
        {
            new Regex(@"\b(casinos?|machines? a sous|slots?|roulette|blackjack|jackpots?)\b", RegexOptions.Compiled),
            new Regex(@"\b(\d+ )?(tours|spins) (gratuits|offerts|free)\b|\bfree ?spins\b|\bfreespins\b", RegexOptions.Compiled),
            new Regex(@"\bbonus (de )?(bienvenue|\d+ ?%)|\b\d+ ?% (de bonus|bonus)\b", RegexOptions.Compiled),
            new Regex(@"\b(premier|1er) depot\b|\bdeposez\b|\bdepot (minimum|de \d+)", RegexOptions.Compiled)
        };

        static readonly Regex PhoneCallRe = new Regex(@"\b((votre |un )?conseiller (va|vous) (vous )?(appeler|rappeler|contacter|telephoner)|vous (allez|aller) (recevoir|etre) (un )?appel|vous serez (appele|contacte|rappele)|nous allons vous (appeler|rappeler))\b", RegexOptions.Compiled);
        static readonly Regex PhoneFraudRe = new Regex(@"\b(code (recu|envoye|que vous recevrez) par sms|code sms|valider une (operation|transaction)|valider l operation|securiser (vos fonds|votre compte|votre argent|votre epargne)|compte (de securite|securise|refuge)|ne raccrochez pas)\b", RegexOptions.Compiled);
        static readonly Regex NeverAskRe = new Regex(@"\b(ne vous (demander(a|ons|ont)|demande) jamais|ne (communiquez|donnez|transmettez|saisissez) jamais|n.?(est|a) jamais besoin|will never ask)\b", RegexOptions.Compiled);
        static readonly Regex AttachmentLinkLureRe = new Regex(@"\b((le |un )?(lien|bouton) (du|dans le|contenu dans le|present dans le|figurant dans le) (document|fichier|pdf)|cliquez (sur le lien|sur le bouton) (du|dans le) (document|fichier|pdf)|click the (link|button) in the (attached |)(document|file|pdf)|ouvrez (le|la) (document|fichier|piece jointe) (joint |)et cliquez)\b", RegexOptions.Compiled);

        static List<string> MatchRule(string text, Lists.ContentRule rule)
        {
            var hits = new List<string>();
            foreach (var p in rule.Patterns)
            {
                if (WordContains(text, p)) hits.Add(p);
                if (hits.Count >= 4) break;
            }
            return hits;
        }

        /// <summary>Le texte (déjà normalisé en minuscules) contient l'expression entière, pas au milieu d'un mot.
        /// Recherche directe : bien plus rapide que de construire une expression régulière par mot-clé et par message.</summary>
        static bool WordContains(string text, string p)
        {
            if (string.IsNullOrEmpty(p)) return false;
            int idx = 0;
            while ((idx = text.IndexOf(p, idx, StringComparison.Ordinal)) >= 0)
            {
                int end = idx + p.Length;
                if ((idx == 0 || !IsAsciiAlnum(text[idx - 1])) && (end >= text.Length || !IsAsciiAlnum(text[end]))) return true;
                idx++;
            }
            return false;
        }

        static bool IsAsciiAlnum(char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); }

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
            bool mailbox = hits["mailbox"].Count > 0, account = hits["account"].Count > 0;
            // Message qui DONNE un code de connexion ou de vérification : son avertissement habituel (« si ce n'est pas vous,
            // changez immédiatement votre mot de passe ») n'est pas une demande d'identifiants
            ctx.CodeMessage = IsCodeMessage(e, subject + " " + body, ctx, findings);
            if (ctx.CodeMessage)
            {
                ctx.Trust.Add(L.T("Code de connexion ou de vérification authentifié, dont tous les liens restent chez l’expéditeur"));
                findings.Add(new Finding("content-code-message", "content", Severity.Info, L.T("Message qui vous donne un code de connexion ou de vérification"),
                    L.T("Authentifié, sans lien vers un autre site : c’est un vrai code. Ne le communiquez jamais à personne, même à quelqu’un qui se présente comme le support."), null));
            }
            // Vrai partage (Google Drive, OneDrive, DocuSign…) dont le titre est une fausse alerte : le message est authentique, le document est le piège
            if (ctx.Platform && (account || mailbox || cred))
                findings.Add(new Finding("content-combo-platform", "content", Severity.High, L.T("Document partagé qui imite une alerte de sécurité"),
                    L.T("Les escrocs partagent un document depuis un vrai service (Google Drive, OneDrive, DocuSign…) dont le titre est une fausse alerte de compte. Le message est authentique, le document est un piège."), null));
            if (mailbox && (cred || urg) && !ctx.CodeMessage)
                findings.Add(new Finding("content-combo-mailbox", "content", Severity.High, L.T("Fausse alerte de votre messagerie"),
                    L.T("Messages bloqués, boîte pleine, mot de passe qui expire : prétexte n° 1 pour voler les identifiants. Votre service informatique ne vous demande jamais de vous reconnecter par un lien."), null));

            // Casino en ligne : interdit en France (seuls paris sportifs, hippiques et poker agréés ANJ)
            if (!ctx.Internal)
            {
                int g = GamblingRes.Count(rx => rx.IsMatch(text));
                if (g >= 2 && (GamblingRes[0].IsMatch(text) || GamblingRes[1].IsMatch(text)))
                    findings.Add(new Finding("content-gambling", "content", ctx.AuthOk ? Severity.Low : Severity.Medium, L.T("Publicité pour un casino en ligne"),
                        L.T("En France, les jeux de casino en ligne (machines à sous, roulette, blackjack) sont interdits : seuls les paris sportifs, hippiques et le poker sont autorisés, sur les sites agréés par l’ANJ. Ces offres de bonus viennent de sites illégaux : vos dépôts et vos données bancaires n’y sont pas protégés."), null));
            }

            // Données de carte bancaire demandées par email (faux acheteur, faux remboursement, faux frais de livraison)
            if (CardAskRe.IsMatch(text) && ctx.FirstContact && !ctx.BrandSender && !ctx.CodeMessage && !ctx.Internal && !NeverAskRe.IsMatch(text))
                findings.Add(new Finding("content-combo-card", "content", Severity.High, L.T("Demande de vos données de carte bancaire"),
                    L.T("Pour vous payer ou vous rembourser, personne n’a besoin de votre numéro de carte ni de son cryptogramme. Ne les saisissez jamais depuis un lien reçu par email."), null));
            // Préparation d'une arnaque au faux conseiller : « votre conseiller va vous appeler, validez l'opération avec le code reçu par SMS »
            if (PhoneCallRe.IsMatch(text) && PhoneFraudRe.IsMatch(text) && !ctx.Internal && !NeverAskRe.IsMatch(text))
                findings.Add(new Finding("content-combo-phone", "content", Severity.High, L.T("Annonce d’un appel d’un faux conseiller"),
                    L.T("Arnaque au faux conseiller bancaire : un appel suit le message et vous fait valider une opération ou dicter un code reçu par SMS. Votre banque ne vous le demande jamais : raccrochez et appelez le numéro de votre carte."), null));
            // Fausse facture à rappeler (« callback phishing ») : un débit inventé, un numéro de téléphone pour l'annuler, souvent aucun lien.
            // Au téléphone, le faux support fait installer un logiciel de prise en main à distance ou dicter des codes bancaires.
            if (!ctx.Internal && !(ctx.AuthOk && ctx.RelationProof) && !ctx.CodeMessage)
            {
                var phone = PhoneNumberRe.Match(text);
                if (phone.Success && CallbackDisputeRe.IsMatch(text) && CallbackChargeRe.IsMatch(text) && AmountRe.IsMatch(text))
                {
                    string fromDom = PhishGuard.Domains.DomainOfAddress(e.FromAddress);
                    bool freemail = Lists.FreemailDomains.Contains(fromDom);
                    bool brandMention = CallbackBrandRe.IsMatch(text) && !ctx.BrandSender;
                    var sev = !ctx.AuthOk || freemail || brandMention ? Severity.High : Severity.Low;
                    findings.Add(new Finding("content-callback", "content", sev, L.T("Fausse facture : on vous demande d’appeler un numéro pour annuler un paiement"),
                        L.T("Arnaque au faux support : le débit est inventé pour vous faire appeler. Au téléphone, l’escroc vous fait installer un logiciel de prise en main à distance ou donner vos codes bancaires. N’appelez jamais le numéro du message : vérifiez vos comptes vous-même, sur le site ou l’application officiels."),
                        new[] { L.T("Numéro : ") + phone.Value.Trim() }));
                }
            }

            // Lien caché dans la pièce jointe : technique pour échapper aux filtres qui analysent les liens du message
            if (!ctx.Internal && e.Attachments.Any(a => a.EmbeddedUrls.Count > 0) && AttachmentLinkLureRe.IsMatch(text))
                findings.Add(new Finding("content-attachment-link", "content", Severity.Medium, L.T("Le message vous envoie vers un lien caché dans la pièce jointe"),
                    L.T("Mettre le lien dans un PDF plutôt que dans le message permet d’échapper aux filtres de messagerie. Vérifiez l’adresse avant de cliquer, ou passez par le site officiel."),
                    e.Attachments.Where(a => a.EmbeddedUrls.Count > 0).SelectMany(a => a.EmbeddedUrls).Take(2).Select(u => Defang(u))));

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
            if (cred && urg && !ctx.CodeMessage)
                findings.Add(new Finding("content-combo-cred", "content", Severity.High, L.T("Demande d’identifiants sous pression"),
                    L.T("Un vrai service ne vous demande jamais de vous reconnecter « en urgence » par email."), null));
            if (fin && (sec || urg))
                findings.Add(new Finding("content-combo-bec", "content", Severity.High, L.T("Demande de paiement urgente ou confidentielle"),
                    L.T("Schéma de fraude au virement ou au président : confirmez toujours par téléphone, avec un numéro que vous connaissez."), null));
            if (ctx.IsFreemail && (fin || cred) && !ctx.MailingList)
                findings.Add(new Finding("content-freemail-request", "content", Severity.Medium, L.T("Demande sensible envoyée depuis une messagerie gratuite"),
                    L.T("Une banque, une administration ou un fournisseur n’écrit pas depuis Gmail, Outlook.com ou Orange."), null));
            // Avis d'argent reçu (virement reçu, remboursement versé) : une information, pas une demande, tant que rien n'est réclamé
            bool moneyNotice = fin && !cred && !sec && IncomingMoneyRe.IsMatch(text) && !PaymentRequestRe.IsMatch(text);
            if (ctx.FirstContact && (fin || cred) && !moneyNotice && !ctx.BrandSender && !ctx.CodeMessage && !ctx.PublicListed)
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
                + " ; DMARC=" + (a.DmarcShown ?? L.T("absent")) + (a.DmarcNote.Length > 0 ? " (" + a.DmarcNote + ")" : "") + (a.DmarcFrom != null ? " (" + a.DmarcFrom + ")" : ""));
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
