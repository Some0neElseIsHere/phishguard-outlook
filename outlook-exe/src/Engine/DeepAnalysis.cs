using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace PhishGuard
{
    /// <summary>Un résultat de l'analyse approfondie : uniquement ce que l'analyse courante n'a pas déjà montré.</summary>
    public class DeepFact
    {
        public string Section;   // att, domains, links, hops, history
        public string Status;    // ok, info, warn, bad
        public string Text;
        public DeepFact(string section, string status, string text) { Section = section; Status = status; Text = text ?? ""; }
    }

    public class DeepReport
    {
        public List<Finding> Findings = new List<Finding>();
        public List<DeepFact> Facts = new List<DeepFact>();
        public List<string> Unchecked = new List<string>();   // ce qui n'a pas pu être vérifié, et pourquoi
        public List<string> Sent = new List<string>();        // ce qui est sorti du poste (récapitulatif)
        public List<string> ExtraLinks = new List<string>();  // destinations découvertes (redirections), analysées ensuite comme des liens
        public DateTime When = DateTime.Now;
        public TimeSpan Duration;
        public bool FollowedLinks, SentUrls;                 // vérifications faites avec l'accord de l'utilisateur
    }

    /// <summary>État de l'onglet « Approfondie » de la fenêtre d'analyse.</summary>
    public class DeepUi
    {
        public bool Running;            // analyse en cours : l'onglet se mettra à jour à la fin
        public bool CanFollow, CanUrls; // vérifications proposées (autorisées par la stratégie, clé disponible)
    }

    public class DeepOptions
    {
        public bool DomainAge = true, Certificates = true, Hashes = true, HopIps = true;
        public bool FollowLinks;      // contacte les sites (accord explicite à chaque analyse)
        public bool SendUrls;         // adresse complète des liens à VirusTotal (accord explicite)
    }

    public static class DeepAnalysis
    {
        public static string Host(string url)
        {
            Uri u;
            return Uri.TryCreate((url ?? "").StartsWith("www.", StringComparison.OrdinalIgnoreCase) ? "http://" + url : url, UriKind.Absolute, out u) ? Domains.HostOf(u) : "";
        }

        static bool AlreadyFlagged(AnalysisResult r, string needle)
        {
            if (string.IsNullOrEmpty(needle)) return false;
            return r.Findings.Any(f => f.Severity >= Severity.Low && f.Evidence.Any(x => x.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0));
        }

        /// <summary>
        /// Analyse approfondie (hors du fil d'Outlook : peut durer plusieurs dizaines de secondes).
        /// files : contenu des pièces jointes, lu par le complément. progress : texte d'avancement.
        /// </summary>
        public static DeepReport Run(EmailData e, AnalysisResult r, IList<KeyValuePair<AttachmentInfo, byte[]>> files, DeepOptions o,
            PhishGuardConfig cfg, IntelSettings keys, Action<string> progress, DeepReport rep)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            rep = rep ?? new DeepReport();
            rep.FollowedLinks = o.FollowLinks;
            rep.SentUrls = o.SendUrls && keys.VirusTotalKey.Length > 0;
            Action<string> say = s => { if (progress != null) try { progress(s); } catch (Exception) { } };
            var company = new HashSet<string>(cfg.CompanyDomains.Select(Domains.RegistrableDomain));

            // ---- 1. Pièces jointes (sur le poste) ----
            int ai = 0;
            foreach (var kv in files)
            {
                ai++;
                say(L.F("Lecture du contenu des pièces jointes ({0}/{1})…", ai, files.Count));
                DeepScan.Inspect(kv.Key, kv.Value, rep);
                foreach (var q in QrInside(kv.Key, kv.Value)) if (!kv.Key.QrCodes.Contains(q)) { kv.Key.QrCodes.Add(q); rep.Facts.Add(new DeepFact("att", "warn", L.F("{0} : QR code trouvé → {1}", kv.Key.Name, Analyzer.Defang(q)))); }
            }
            if (files.Count == 0 && e.Attachments.Any(x => !(x.IsInline && x.IsImage))) rep.Unchecked.Add(L.T("Pièces jointes : contenu non disponible"));
            // Liens trouvés dans les pièces jointes (parties compressées, structure des documents) : conservés pour les réanalyses
            foreach (var a in e.Attachments) foreach (var u in a.EmbeddedUrls.Concat(a.QrCodes)) if (u.StartsWith("http", StringComparison.OrdinalIgnoreCase) && !rep.ExtraLinks.Contains(u)) rep.ExtraLinks.Add(u);

            // ---- 2. Liens : jusqu'à leur destination réelle (avec accord) ----
            var linkUrls = new List<string>();
            foreach (var l in e.Links)
            {
                string h = l.Href ?? "";
                if (!h.StartsWith("http", StringComparison.OrdinalIgnoreCase)) continue;
                Uri un = null;
                try { un = Analyzer.UnwrapUrl(h, null); } catch (Exception) { }
                linkUrls.Add(un != null ? un.AbsoluteUri : h);
            }
            foreach (var a in e.Attachments) linkUrls.AddRange(a.EmbeddedUrls.Where(u => u.StartsWith("http", StringComparison.OrdinalIgnoreCase)));
            foreach (var a in e.Attachments) linkUrls.AddRange(a.QrCodes.Where(u => u.StartsWith("http", StringComparison.OrdinalIgnoreCase)));
            linkUrls = linkUrls.Distinct().ToList();
            var finals = new List<string>();
            if (o.FollowLinks)
            {
                var byHost = linkUrls.GroupBy(Host).Where(g => g.Key.Length > 0 && !company.Contains(Domains.RegistrableDomain(g.Key))).Select(g => g.First())
                    .OrderByDescending(u => Lists.Shorteners.Any(s => Host(u) == s || Host(u).EndsWith("." + s))).Take(8).ToList();
                int li = 0;
                foreach (var u in byHost)
                {
                    li++;
                    say(L.F("Suivi des liens jusqu’à leur destination ({0}/{1})…", li, byHost.Count));
                    var fr = Redirects.Follow(u);
                    rep.Sent.Add(L.F("Visite de {0} (sans cookie, sans exécuter de code)", Analyzer.Defang(Host(u))));
                    if (fr.Error != null) { rep.Unchecked.Add(L.F("{0} : destination non obtenue ({1})", Analyzer.Defang(Host(u)), fr.Error)); continue; }
                    string fh = Host(fr.Final);
                    bool moved = fr.Chain.Count > 1 && !string.Equals(Domains.RegistrableDomain(fh), Domains.RegistrableDomain(Host(u)), StringComparison.OrdinalIgnoreCase);
                    if (moved)
                    {
                        rep.Facts.Add(new DeepFact("links", "warn", string.Join(" → ", fr.Chain.Select(c => Analyzer.Defang(Host(c))).ToArray())));
                        finals.Add(fr.Final);
                        rep.ExtraLinks.Add(fr.Final);
                    }
                    else rep.Facts.Add(new DeepFact("links", "ok", L.F("{0} : reste sur le même site", Analyzer.Defang(Host(u)))));
                    if (fr.PasswordForm)
                        rep.Findings.Add(new Finding("deep-link-login", "links", Severity.High, L.T("Un lien mène à une page qui demande un mot de passe"),
                            L.T("La page de destination contient un champ « mot de passe ». Ne vous connectez jamais depuis un lien reçu par email : passez par l’adresse habituelle du site."),
                            new[] { Analyzer.Defang(fr.Final.Length > 120 ? fr.Final.Substring(0, 120) + "…" : fr.Final) }));
                    if (fr.Download)
                        rep.Findings.Add(new Finding("deep-link-download", "links", Severity.High, L.T("Un lien télécharge directement un fichier"),
                            L.T("Le lien ne mène pas à une page mais à un fichier à enregistrer."), new[] { Analyzer.Defang(fr.Final.Length > 120 ? fr.Final.Substring(0, 120) + "…" : fr.Final) + (fr.ContentType.Length > 0 ? " (" + fr.ContentType + ")" : "") }));
                }
            }

            // ---- 3. Tous les domaines : âge et premier certificat ----
            var domains = new List<KeyValuePair<string, string>>();   // domaine, rôle
            Action<string, string> addD = (host, role) =>
            {
                string reg = Domains.RegistrableDomain((host ?? "").ToLowerInvariant().TrimEnd('.'));
                if (reg.Length < 4 || !reg.Contains(".") || Domains.IsIpHost(reg) || company.Contains(reg) || Lists.FreemailDomains.Contains(reg)) return;
                if (domains.Any(x => x.Key == reg)) return;
                domains.Add(new KeyValuePair<string, string>(reg, role));
            };
            addD(Domains.DomainOfAddress(e.FromAddress), L.T("expéditeur"));
            foreach (var rt in e.ReplyTo) addD(Domains.DomainOfAddress(rt), L.T("réponse"));
            if (r.Details != null)
            {
                foreach (var kv in r.Details.Fields.Where(f => f.Key == "Return-Path")) addD(Domains.DomainOfAddress(kv.Value.Trim('<', '>', ' ')), L.T("enveloppe"));
                if (!string.IsNullOrEmpty(r.Details.Auth.DkimDomain)) addD(r.Details.Auth.DkimDomain, L.T("signature DKIM"));
            }
            foreach (var u in finals) addD(Host(u), L.T("destination réelle d’un lien"));
            foreach (var u in linkUrls) addD(Host(u), L.T("lien"));
            if (domains.Count > 20) { rep.Unchecked.Add(L.F("{0} domaines : seuls les 20 premiers ont été vérifiés", domains.Count)); domains = domains.Take(20).ToList(); }
            int di = 0;
            foreach (var kv in domains)
            {
                di++;
                say(L.F("Vérification des domaines ({0}/{1})…", di, domains.Count));
                string d = kv.Key;
                var parts = new List<string>();
                string status = "ok";
                if (o.DomainAge)
                {
                    bool ok;
                    var created = DomainAge.LookupNow(d, out ok);
                    if (!ok) parts.Add(L.T("date de création : service injoignable"));
                    else if (!created.HasValue) parts.Add(L.T("date de création non publiée"));
                    else
                    {
                        int days = Math.Max(0, (int)(DateTime.UtcNow - created.Value).TotalDays);
                        parts.Add(L.F("créé le {0} (il y a {1} jours)", created.Value.ToLocalTime().ToString("dd/MM/yyyy"), days.ToString("N0")));
                        if (days < 30) status = "bad"; else if (days < 180 && status == "ok") status = "warn";
                        if (days < 30 && !AlreadyFlagged(r, d))
                            rep.Findings.Add(new Finding("deep-domain-new", kv.Value == L.T("lien") || kv.Value == L.T("destination réelle d’un lien") ? "links" : "sender", Severity.High,
                                L.F("Domaine créé il y a {0} jour(s) ({1})", days, kv.Value), L.T("Les domaines de phishing servent en général dans les jours qui suivent leur création."), new[] { d }));
                    }
                    rep.Sent.Add(L.F("Nom de domaine {0} → rdap.org", d));
                }
                if (o.Certificates)
                {
                    var c = Intel.FetchNow("crt:" + d);
                    if (c == null || !c.Ok) parts.Add(L.T("certificats : crt.sh injoignable"));
                    else if (c.Date.HasValue)
                    {
                        int cd = Math.Max(0, (int)(DateTime.UtcNow - c.Date.Value).TotalDays);
                        parts.Add(L.F("premier certificat HTTPS le {0}", c.Date.Value.ToLocalTime().ToString("dd/MM/yyyy")));
                        if (cd < 14 && status != "bad") status = "warn";
                    }
                    else parts.Add(L.T("aucun certificat HTTPS connu"));
                    rep.Sent.Add(L.F("Nom de domaine {0} → crt.sh", d));
                }
                if (parts.Count > 0) rep.Facts.Add(new DeepFact("domains", status, d + " (" + kv.Value + ") : " + string.Join(" ; ", parts.ToArray())));
            }

            // ---- 4. Serveurs traversés : réputation de chaque adresse IP ----
            if (o.HopIps && keys.AbuseIpdbKey.Length > 0 && r.Details != null)
            {
                var ips = r.Details.Hops.Select(h => h.FromIp).Where(ip => ip.Length > 0 && Forensics.IsPublicIp(ip) && ip != r.Details.OriginIp).Distinct().Take(6).ToList();
                foreach (var ip in ips)
                {
                    say(L.F("Réputation des serveurs traversés ({0})…", ip));
                    var res = Intel.FetchNow("ip:" + ip);
                    rep.Sent.Add(L.F("Adresse IP {0} → AbuseIPDB", ip));
                    if (res == null || !res.Ok) { rep.Unchecked.Add(L.F("IP {0} : AbuseIPDB injoignable", ip)); continue; }
                    rep.Facts.Add(new DeepFact("hops", res.Malicious >= 25 ? "bad" : "ok", L.F("{0} : score d’abus {1}/100 ({2} signalements)", ip, res.Malicious, res.Total)));
                    if (res.Malicious >= 50)
                        rep.Findings.Add(new Finding("deep-hop-abuse", "sender", Severity.Medium, L.T("Un serveur traversé est signalé pour abus"), "", new[] { ip + " : " + res.Malicious + "/100" }));
                }
            }
            else if (o.HopIps && keys.AbuseIpdbKey.Length == 0) rep.Unchecked.Add(L.T("Serveurs traversés : pas de clé AbuseIPDB"));

            // ---- 5. Empreintes de toutes les pièces jointes ----
            int vtBudget = 4;
            if (o.Hashes)
            {
                foreach (var a in e.Attachments.Where(x => x.Sha256.Length > 0 && !(x.IsInline && x.IsImage)))
                {
                    say(L.F("Réputation des pièces jointes ({0})…", a.Name));
                    if (keys.VirusTotalKey.Length > 0 && vtBudget > 0)
                    {
                        vtBudget--;
                        var v = Intel.FetchNow("vtf:" + a.Sha256);
                        rep.Sent.Add(L.F("Empreinte de {0} → VirusTotal", a.Name));
                        if (v == null || !v.Ok) rep.Unchecked.Add(L.F("{0} : VirusTotal injoignable", a.Name));
                        else if (!v.Found) rep.Facts.Add(new DeepFact("att", "info", L.F("{0} : inconnu de VirusTotal (fichier jamais analysé, ou créé pour vous)", a.Name)));
                        else
                        {
                            rep.Facts.Add(new DeepFact("att", v.Malicious > 0 ? "bad" : "ok", L.F("{0} : VirusTotal, {1} moteur(s) sur {2} le jugent malveillant", a.Name, v.Malicious, v.Total)));
                            if (v.Malicious >= 3 && !AlreadyFlagged(r, a.Sha256) && !AlreadyFlagged(r, a.Name))
                                rep.Findings.Add(new Finding("deep-hash-vt", "attachments", Severity.Critical, L.F("Pièce jointe détectée comme malveillante ({0} antivirus)", v.Malicious), "", new[] { a.Name }));
                        }
                    }
                    if (keys.AbuseChKey.Length > 0)
                    {
                        var m = Intel.FetchNow("mb:" + a.Sha256);
                        rep.Sent.Add(L.F("Empreinte de {0} → MalwareBazaar", a.Name));
                        if (m != null && m.Ok && m.Found)
                        {
                            rep.Facts.Add(new DeepFact("att", "bad", L.F("{0} : connu de MalwareBazaar{1}", a.Name, m.Label.Length > 0 ? " (" + m.Label + ")" : "")));
                            rep.Findings.Add(new Finding("deep-hash-mb", "attachments", Severity.Critical, L.T("Pièce jointe répertoriée comme logiciel malveillant (MalwareBazaar)"), "", new[] { a.Name + (m.Label.Length > 0 ? " : " + m.Label : "") }));
                        }
                        else if (m != null && m.Ok) rep.Facts.Add(new DeepFact("att", "info", L.F("{0} : inconnu de MalwareBazaar", a.Name)));
                    }
                }
                if (keys.VirusTotalKey.Length == 0 && keys.AbuseChKey.Length == 0 && e.Attachments.Any(x => x.Sha256.Length > 0))
                    rep.Unchecked.Add(L.T("Réputation des pièces jointes : pas de clé VirusTotal ni abuse.ch"));
            }

            // ---- 6. Adresses complètes des liens à VirusTotal (avec accord) ----
            if (o.SendUrls && keys.VirusTotalKey.Length > 0)
            {
                foreach (var u in finals.Concat(linkUrls).Distinct().Take(Math.Max(0, Math.Min(vtBudget, 3))))
                {
                    say(L.T("Consultation de VirusTotal pour les liens…"));
                    var v = Intel.FetchNow("vtu:" + u);
                    rep.Sent.Add(L.F("Adresse complète {0} → VirusTotal", Analyzer.Defang(u.Length > 80 ? u.Substring(0, 80) + "…" : u)));
                    if (v == null || !v.Ok) { rep.Unchecked.Add(L.F("{0} : VirusTotal injoignable", Analyzer.Defang(Host(u)))); continue; }
                    if (!v.Found) { rep.Facts.Add(new DeepFact("links", "info", L.F("{0} : lien jamais analysé par VirusTotal", Analyzer.Defang(Host(u))))); continue; }
                    rep.Facts.Add(new DeepFact("links", v.Malicious > 0 ? "bad" : "ok", L.F("{0} : VirusTotal, {1} moteur(s) sur {2} le jugent malveillant", Analyzer.Defang(Host(u)), v.Malicious, v.Total)));
                    if (v.Malicious >= 2)
                        rep.Findings.Add(new Finding("deep-url-vt", "links", Severity.High, L.F("Lien signalé comme malveillant ({0} moteurs VirusTotal)", v.Malicious), "", new[] { Analyzer.Defang(Host(u)) }));
                }
            }
            else if (o.SendUrls) rep.Unchecked.Add(L.T("Liens sur VirusTotal : pas de clé VirusTotal"));

            sw.Stop();
            rep.Duration = sw.Elapsed;
            return rep;
        }

        /// <summary>QR codes dans les images jointes que l'analyse courante n'a pas lues (au-delà de 5 images ou de 3 Mo).</summary>
        static List<string> QrInside(AttachmentInfo a, byte[] d)
        {
            if (!a.IsImage || d == null || d.Length > 15 * 1024 * 1024 || a.QrCodes.Count > 0) return new List<string>();
            return QrScan.Decode(d);
        }

        /// <summary>Résultat final : le message est réanalysé avec ce que l'analyse approfondie a découvert (destinations
        /// réelles des liens, liens cachés dans les pièces jointes), puis ses indices propres sont ajoutés.</summary>
        public static AnalysisResult Complete(EmailData e, DeepReport rep, PhishGuardConfig cfg)
        {
            var e2 = new EmailData
            {
                FromName = e.FromName, FromAddress = e.FromAddress, SenderAddress = e.SenderAddress, IsExchangeInternal = e.IsExchangeInternal,
                Subject = e.Subject, BodyText = e.BodyText, HasForm = e.HasForm, HasPasswordInput = e.HasPasswordInput,
                Links = new List<LinkInfo>(e.Links), Attachments = e.Attachments, ReplyTo = e.ReplyTo, RawHeaders = e.RawHeaders
            };
            foreach (var u in rep.ExtraLinks)
                if (!e2.Links.Any(l => l.Href == u) && !e.Attachments.Any(a => a.EmbeddedUrls.Contains(u) || a.QrCodes.Contains(u))) e2.Links.Add(new LinkInfo(u, ""));
            var r = Analyzer.Analyze(e2, cfg);
            return Analyzer.WithFindings(r, rep.Findings, rep);
        }
    }

    /// <summary>Suivi d'un lien jusqu'à sa destination, sans cookie ni exécution de code (lecture du début de chaque page).</summary>
    public static class Redirects
    {
        public class Result
        {
            public List<string> Chain = new List<string>();
            public string Final = "";
            public string Error;
            public bool PasswordForm, Download;
            public string ContentType = "";
        }

        static readonly Regex MetaRe = new Regex(@"<meta\b[^>]{0,300}http-equiv\s*=\s*[""']?refresh[^>]{0,300}url\s*=\s*['""]?([^'"">\s]{4,1000})", RegexOptions.IgnoreCase);
        static readonly Regex JsRe = new Regex(@"(?:window|document|top|self)\.location(?:\.href)?\s*(?:=|\.replace\s*\(|\.assign\s*\()\s*[""']([^""'\s]{4,1000})", RegexOptions.IgnoreCase);

        /// <summary>Destination indiquée par une page de redirection (balise meta refresh ou script location), ou null.</summary>
        public static string PageRedirect(string html, Uri baseUri)
        {
            if (string.IsNullOrEmpty(html)) return null;
            var m = MetaRe.Match(html);
            if (!m.Success) m = JsRe.Match(html);
            if (!m.Success) return null;
            Uri u;
            string target = WebUtility.HtmlDecode(m.Groups[1].Value);
            if (Uri.TryCreate(baseUri, target, out u) && (u.Scheme == "http" || u.Scheme == "https")) return u.AbsoluteUri;
            return null;
        }

        public static Result Follow(string url)
        {
            var res = new Result();
            string current = url;
            try
            {
                ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072;
                for (int hop = 0; hop < 8; hop++)
                {
                    res.Chain.Add(current);
                    var req = (HttpWebRequest)WebRequest.Create(current);
                    req.Method = "GET";
                    req.AllowAutoRedirect = false;
                    req.CookieContainer = null;
                    req.Proxy = WebRequest.GetSystemWebProxy();
                    req.Proxy.Credentials = CredentialCache.DefaultCredentials;
                    req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";
                    req.Accept = "text/html,*/*;q=0.8";
                    req.Timeout = 8000; req.ReadWriteTimeout = 8000;
                    HttpWebResponse resp;
                    try { resp = (HttpWebResponse)req.GetResponse(); }
                    catch (WebException we) { resp = we.Response as HttpWebResponse; if (resp == null) throw; }
                    using (resp)
                    {
                        int code = (int)resp.StatusCode;
                        string loc = resp.Headers["Location"];
                        if (code >= 300 && code < 400 && !string.IsNullOrEmpty(loc))
                        {
                            Uri next;
                            if (!Uri.TryCreate(new Uri(current), loc, out next) || (next.Scheme != "http" && next.Scheme != "https")) break;
                            current = next.AbsoluteUri;
                            continue;
                        }
                        res.ContentType = (resp.ContentType ?? "").Split(';')[0].Trim().ToLowerInvariant();
                        string disp = resp.Headers["Content-Disposition"] ?? "";
                        if (disp.IndexOf("attachment", StringComparison.OrdinalIgnoreCase) >= 0 || (res.ContentType.Length > 0 && !res.ContentType.StartsWith("text/")
                            && !res.ContentType.Contains("html") && !res.ContentType.Contains("json") && !res.ContentType.Contains("xml") && !res.ContentType.StartsWith("image/")))
                        { res.Download = code < 400; break; }
                        string body = "";
                        using (var s = resp.GetResponseStream())
                        using (var r = new StreamReader(s, Encoding.UTF8))
                        {
                            var buf = new char[96 * 1024];
                            int n = r.ReadBlock(buf, 0, buf.Length);
                            body = new string(buf, 0, n);
                        }
                        if (HtmlScan.HasPasswordInput(body)) res.PasswordForm = true;
                        string page = body.Length < 20000 ? PageRedirect(body, new Uri(current)) : null;
                        if (page != null && page != current) { current = page; continue; }
                        break;
                    }
                }
                res.Final = current;
            }
            catch (Exception ex) { res.Error = ex.Message; res.Final = current; }
            return res;
        }
    }
}
