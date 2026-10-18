// PhishGuard - banc d'essai du moteur sur des corpus publics d'emails (fichiers mbox ou dossiers de messages RFC 822).
// Lancé par .github/workflows/bench.yml. Hors ligne : aucune source externe (DNS, âge des domaines, listes),
// car les domaines des vieux phishings ont disparu depuis. Sortie : un CSV par message avec les indices
// (identifiant, gravité, catégorie) pour pouvoir recalculer d'autres barèmes sans relancer le moteur.
//
// Usage : Bench.exe sortie.csv libellé=chemin[|domaine-entreprise] ...
// Les messages de tests/legitimes portent X-PhishGuard-Attendu (vert / orange), X-PhishGuard-Cas et X-PhishGuard-Connu
// (expéditeur déjà dans vos correspondants) : voir tools/gen-legitimes.py.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace PhishGuard.Tools
{
    static class Bench
    {
        static readonly Regex AnchorRe = new Regex(@"<a\b[^>]*?\bhref\s*=\s*(?:""([^""]*)""|'([^']*)'|([^\s>]+))[^>]*>(.*?)</a\s*>",
            RegexOptions.IgnoreCase | RegexOptions.Singleline);
        static readonly Regex TagRe = new Regex(@"<[^>]+>", RegexOptions.Singleline);
        static readonly Regex PlainUrlRe = new Regex(@"\bhttps?://[^\s<>""')]+", RegexOptions.IgnoreCase);

        static int Main(string[] args)
        {
            if (args.Length < 2) { Console.WriteLine("Usage : Bench.exe sortie.csv libellé=chemin[|domaine] ..."); return 2; }
            // Aucune expression régulière du moteur ne doit pouvoir s'emballer sur un message piégé : délai maximal,
            // et chaque dépassement est signalé (il figerait Outlook)
            AppDomain.CurrentDomain.SetData("REGEX_DEFAULT_MATCH_TIMEOUT", TimeSpan.FromSeconds(3));
            string progressPath = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(args[0])), "progress.txt");
            AppDomain.CurrentDomain.UnhandledException += (s, ev) =>
            {
                Console.WriteLine("::error::Plantage du banc : " + ev.ExceptionObject.ToString().Replace("\r", " ").Replace("\n", " "));
                try { File.AppendAllText(progressPath, "PLANTAGE " + ev.ExceptionObject + Environment.NewLine); } catch (Exception) { }
            };
            int warnings = 0;
            Action<string> warn = msg => { if (warnings++ < 40) Console.WriteLine("::warning::" + msg.Replace("\r", " ").Replace("\n", " ")); };
            L.SetLanguage("fr");
            DomainAge.Enabled = false;
            Blocklists.SetForTests(new string[0], new string[0]);
            // Liste du secteur public (téléchargée par le workflow), comme sur un poste où elle est activée par défaut
            string publicList = Environment.GetEnvironmentVariable("PG_PUBLIC_SECTOR");
            if (!string.IsNullOrEmpty(publicList) && File.Exists(publicList))
            {
                Feeds.LoadPublicSector(File.ReadAllLines(publicList), DateTime.Now);
                Feeds.PublicSectorEnabled = true;
                Console.WriteLine("Secteur public : " + Feeds.PublicSectorCount + " domaines");
            }

            using (var w = new StreamWriter(args[0], false, new UTF8Encoding(false)) { AutoFlush = true })
            {
                w.WriteLine("corpus,mode,idx,year,auth,level,score,verified,fromdomain,subject,nlinks,natt,bodylen,hosts,atts,findings,attendu,cas");
                for (int a = 1; a < args.Length; a++)
                {
                    string spec = args[a];
                    int eq = spec.IndexOf('=');
                    string label = spec.Substring(0, eq), path = spec.Substring(eq + 1), company = "";
                    // chemin[|domaine-entreprise[|nombre-maximal]] : au-delà du maximum, échantillon régulier
                    int max = 0;
                    var parts = path.Split('|');
                    path = parts[0];
                    if (parts.Length > 1) company = parts[1];
                    if (parts.Length > 2) int.TryParse(parts[2], out max);
                    var cfg = new PhishGuardConfig();
                    if (company.Length > 0) cfg.CompanyDomains = new List<string> { company };
                    int n = 0, err = 0;
                    foreach (var raw in Messages(path, max))
                    {
                        n++;
                        try { File.WriteAllText(progressPath, label + " #" + n + " (" + raw.Length + " octets) " + DateTime.Now.ToString("HH:mm:ss")); } catch (Exception) { }
                        if (raw.Length > 15 * 1024 * 1024) { warn(label + " #" + n + " ignoré : " + raw.Length / 1048576 + " Mo"); continue; }
                        EmailData e;
                        int year;
                        var sw = System.Diagnostics.Stopwatch.StartNew();
                        try { e = Parse(raw, out year); }
                        catch (Exception ex) { err++; if (ex is RegexMatchTimeoutException) warn(label + " #" + n + " : lecture trop longue (" + ex.Message + ")"); continue; }
                        string expected = Regex.Match(e.RawHeaders, @"(?im)^X-PhishGuard-Attendu:\s*(\S+)").Groups[1].Value;
                        string cas = Regex.Match(e.RawHeaders, @"(?im)^X-PhishGuard-Cas:\s*(\S+)").Groups[1].Value;
                        bool known = Regex.IsMatch(e.RawHeaders, @"(?im)^X-PhishGuard-Connu:\s*oui");
                        bool auth = Regex.IsMatch(e.RawHeaders, @"^Authentication-Results:", RegexOptions.IgnoreCase | RegexOptions.Multiline);
                        // « inconnus » : carnet de correspondants chargé, l'expéditeur n'y est pas (cas d'un vrai poste)
                        // « neutre » : carnet non chargé (aucun indice de premier contact)
                        foreach (string mode in new[] { "inconnus", "neutre" })
                        {
                            if (mode == "inconnus") Correspondents.Set(known ? new[] { "personne@exemple.invalid", e.FromAddress } : new[] { "personne@exemple.invalid" }, false); else Correspondents.Reset();
                            AnalysisResult r;
                            var swa = System.Diagnostics.Stopwatch.StartNew();
                            try { r = Analyzer.Analyze(Clone(e), cfg); }
                            catch (Exception ex)
                            {
                                err++;
                                warn(label + " #" + n + " (" + Trunc(e.Subject, 60) + ") : " + ex.GetType().Name + " " + Trunc(ex.Message, 200) + " @ " + Trunc((ex.StackTrace ?? "").Replace(Environment.NewLine, " | "), 400));
                                continue;
                            }
                            if (swa.ElapsedMilliseconds > 2000) warn(label + " #" + n + " (" + Trunc(e.Subject, 60) + ") : analyse lente, " + swa.ElapsedMilliseconds + " ms");
                            string f = string.Join(" ", r.Findings.Select(x => x.Id + ":" + (int)x.Severity + ":" + x.Category).ToArray());
                            w.WriteLine(string.Join(",", new[] { label, mode, n.ToString(), year.ToString(), auth ? "1" : "0", r.Level, r.Score.ToString(),
                                r.Verified ? "1" : "0", Csv(r.SenderDomain), Csv(Trunc(e.Subject, 90)), e.Links.Count.ToString(), e.Attachments.Count.ToString(), e.BodyText.Length.ToString(),
                                Csv(string.Join(" ", e.Links.Select(l => Host(l.Href)).Distinct().Take(4).ToArray())),
                                Csv(string.Join(" ", e.Attachments.Select(x => x.Name + "/" + x.ContentType + "/" + x.Magic).Take(4).ToArray())), Csv(f), expected, cas }));
                        }
                    }
                    Console.WriteLine(label + " : " + n + " messages, " + err + " erreurs");
                }
            }
            return 0;
        }

        static EmailData Clone(EmailData e)
        {
            // L'analyse peut modifier les indices des pièces jointes : on repart d'une copie à chaque passage
            var c = new EmailData { FromName = e.FromName, FromAddress = e.FromAddress, Subject = e.Subject, BodyText = e.BodyText, HasForm = e.HasForm,
                HasPasswordInput = e.HasPasswordInput, RawHeaders = e.RawHeaders };
            c.Links.AddRange(e.Links);
            c.ReplyTo.AddRange(e.ReplyTo);
            foreach (var a in e.Attachments)
            {
                var b = new AttachmentInfo { Name = a.Name, IsInline = a.IsInline, IsImage = a.IsImage, IsEmbeddedMessage = a.IsEmbeddedMessage, Size = a.Size,
                    ContentType = a.ContentType, Magic = a.Magic, Md5 = a.Md5, Sha1 = a.Sha1, Sha256 = a.Sha256 };
                b.ContentFindings.AddRange(a.ContentFindings);
                b.EmbeddedUrls.AddRange(a.EmbeddedUrls);
                b.ArchiveEntries.AddRange(a.ArchiveEntries);
                b.QrCodes.AddRange(a.QrCodes);
                c.Attachments.Add(b);
            }
            return c;
        }

        static string Host(string href)
        {
            Uri u;
            return Uri.TryCreate(href ?? "", UriKind.Absolute, out u) ? u.Scheme + ":" + Domains.HostOf(u) : Trunc(href, 30);
        }

        static string Trunc(string s, int n) { s = s ?? ""; return s.Length > n ? s.Substring(0, n) : s; }

        static string Csv(string s)
        {
            s = Regex.Replace(s ?? "", @"[\r\n]+", " ");
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        }

        // ------------------------------------------------------------------
        // Lecture des corpus
        // ------------------------------------------------------------------

        static readonly Encoding Latin1 = Encoding.GetEncoding(28591);

        static IEnumerable<byte[]> Messages(string path, int max)
        {
            if (Directory.Exists(path))
            {
                var files = Directory.GetFiles(path, "*", SearchOption.AllDirectories)
                    .Where(f => { string n = Path.GetFileName(f); return !n.StartsWith(".") && !n.Equals("cmds", StringComparison.OrdinalIgnoreCase) && f.IndexOf(Path.DirectorySeparatorChar + ".git" + Path.DirectorySeparatorChar) < 0; })
                    .OrderBy(x => x, StringComparer.Ordinal).ToList();
                // Dossier de .eml (dépôt avec README, licence…) : seulement les messages
                var eml = files.Where(f => f.EndsWith(".eml", StringComparison.OrdinalIgnoreCase)).ToList();
                if (eml.Count > 0) files = eml;
                if (max > 0 && files.Count > max)
                {
                    double step = (double)files.Count / max;
                    files = Enumerable.Range(0, max).Select(i => files[(int)(i * step)]).ToList();
                }
                foreach (var f in files) yield return File.ReadAllBytes(f);
                yield break;
            }
            // mbox : un message commence par une ligne « From » précédée d'une ligne vide (ou en début de fichier)
            string all = Latin1.GetString(File.ReadAllBytes(path)).Replace("\r\n", "\n");
            var starts = new List<int>();
            if (all.StartsWith("From ")) starts.Add(0);
            foreach (Match m in Regex.Matches(all, @"\n\nFrom [^\n]*\n")) starts.Add(m.Index + 2);
            for (int i = 0; i < starts.Count; i++)
            {
                int s = all.IndexOf('\n', starts[i]) + 1;
                int end = i + 1 < starts.Count ? starts[i + 1] : all.Length;
                string msg = Regex.Replace(all.Substring(s, end - s), @"(?m)^>(>*From )", "$1");
                yield return Latin1.GetBytes(msg);
            }
        }

        // ------------------------------------------------------------------
        // Décodage MIME (assez pour reproduire ce que l'Outlook objet fournit)
        // ------------------------------------------------------------------

        class Part
        {
            public List<KeyValuePair<string, string>> Headers = new List<KeyValuePair<string, string>>();
            public string RawHeaders = "";
            public byte[] Body;
            public string H(string name)
            {
                foreach (var kv in Headers) if (kv.Key.Equals(name, StringComparison.OrdinalIgnoreCase)) return kv.Value;
                return "";
            }
        }

        static Part ParsePart(byte[] data)
        {
            string text = Latin1.GetString(data);
            int sep = text.IndexOf("\n\n", StringComparison.Ordinal);
            int sep2 = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            int hdrEnd, bodyStart;
            if (sep2 >= 0 && (sep < 0 || sep2 < sep)) { hdrEnd = sep2; bodyStart = sep2 + 4; }
            else if (sep >= 0) { hdrEnd = sep; bodyStart = sep + 2; }
            else { hdrEnd = text.Length; bodyStart = text.Length; }
            var p = new Part { RawHeaders = text.Substring(0, hdrEnd).Replace("\r\n", "\n").Replace("\n", "\r\n") };
            string cur = null;
            foreach (var line in p.RawHeaders.Split(new[] { "\r\n" }, StringSplitOptions.None))
            {
                if (line.Length > 0 && (line[0] == ' ' || line[0] == '\t')) { if (cur != null) cur += " " + line.Trim(); continue; }
                if (cur != null) Add(p, cur);
                cur = line;
            }
            if (cur != null) Add(p, cur);
            p.Body = new byte[data.Length - Math.Min(bodyStart, data.Length)];
            Array.Copy(data, Math.Min(bodyStart, data.Length), p.Body, 0, p.Body.Length);
            return p;
        }

        static void Add(Part p, string line)
        {
            int c = line.IndexOf(':');
            if (c > 0) p.Headers.Add(new KeyValuePair<string, string>(line.Substring(0, c).Trim(), line.Substring(c + 1).Trim()));
        }

        static string Param(string header, string name)
        {
            var m = Regex.Match(header ?? "", @"(?:^|;)\s*" + name + @"\*?\s*=\s*(?:""([^""]*)""|([^;\s]+))", RegexOptions.IgnoreCase);
            if (!m.Success) return "";
            string v = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
            // RFC 2231 : charset''valeur%20encodée
            var r = Regex.Match(v, @"^([\w-]+)''(.*)$");
            if (r.Success) { try { v = Uri.UnescapeDataString(r.Groups[2].Value); } catch (Exception) { } }
            return DecodeWords(v);
        }

        static Encoding Charset(string name)
        {
            if (string.IsNullOrEmpty(name)) return Latin1;
            try { return Encoding.GetEncoding(name.Trim().Trim('"')); }
            catch (Exception) { return name.ToLowerInvariant().Contains("utf") ? Encoding.UTF8 : Latin1; }
        }

        static readonly Regex WordRe = new Regex(@"=\?([^?]+)\?([bBqQ])\?([^?]*)\?=");

        /// <summary>Mots encodés RFC 2047 (=?utf-8?B?...?=).</summary>
        static string DecodeWords(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            s = Regex.Replace(s, @"(\?=)\s+(=\?)", "$1$2");
            return WordRe.Replace(s, m =>
            {
                try
                {
                    var enc = Charset(m.Groups[1].Value.Split('*')[0]);
                    byte[] b = m.Groups[2].Value.ToUpperInvariant() == "B" ? Convert.FromBase64String(PadB64(m.Groups[3].Value))
                        : QpDecode(Latin1.GetBytes(m.Groups[3].Value.Replace('_', ' ')));
                    return enc.GetString(b);
                }
                catch (Exception) { return m.Value; }
            });
        }

        /// <summary>Les en-têtes bruts sont lus en Latin-1 ; un en-tête en UTF-8 non encodé est réinterprété.</summary>
        static string Utf8IfValid(string latin)
        {
            var bytes = Latin1.GetBytes(latin);
            try { return new UTF8Encoding(false, true).GetString(bytes); } catch (Exception) { return latin; }
        }

        static string PadB64(string s)
        {
            s = Regex.Replace(s, @"[^A-Za-z0-9+/]", "");
            return s + new string('=', (4 - s.Length % 4) % 4);
        }

        static byte[] QpDecode(byte[] b)
        {
            var o = new MemoryStream();
            for (int i = 0; i < b.Length; i++)
            {
                if (b[i] == '=' && i + 1 < b.Length && (b[i + 1] == '\n' || b[i + 1] == '\r'))
                {
                    i++;
                    if (b[i] == '\r' && i + 1 < b.Length && b[i + 1] == '\n') i++;
                    continue;
                }
                if (b[i] == '=' && i + 2 < b.Length && Uri.IsHexDigit((char)b[i + 1]) && Uri.IsHexDigit((char)b[i + 2]))
                {
                    o.WriteByte(Convert.ToByte(((char)b[i + 1]).ToString() + (char)b[i + 2], 16));
                    i += 2;
                    continue;
                }
                o.WriteByte(b[i]);
            }
            return o.ToArray();
        }

        static byte[] Decoded(Part p)
        {
            string cte = p.H("Content-Transfer-Encoding").ToLowerInvariant();
            try
            {
                if (cte.Contains("base64")) return Convert.FromBase64String(PadB64(Latin1.GetString(p.Body)));
                if (cte.Contains("quoted-printable")) return QpDecode(p.Body);
            }
            catch (Exception) { }
            return p.Body;
        }

        class Collected
        {
            public StringBuilder Plain = new StringBuilder(), Html = new StringBuilder();
            public List<AttachmentInfo> Atts = new List<AttachmentInfo>();
            public int QrScanned;
        }

        static void Walk(Part p, Collected c, int depth)
        {
            string ct = p.H("Content-Type");
            string type = (ct.Split(';')[0].Trim().ToLowerInvariant());
            if (type.Length == 0) type = "text/plain";
            string disp = p.H("Content-Disposition");
            string name = Param(disp, "filename");
            if (name.Length == 0) name = Param(ct, "name");

            if (type.StartsWith("multipart/") && depth < 10)
            {
                string boundary = Param(ct, "boundary");
                if (boundary.Length == 0) return;
                string body = Latin1.GetString(p.Body);
                string marker = "--" + boundary;
                var pieces = body.Split(new[] { marker }, StringSplitOptions.None);
                for (int i = 1; i < pieces.Length; i++)
                {
                    string piece = pieces[i];
                    if (piece.StartsWith("--")) break;
                    piece = piece.TrimStart('\r').TrimStart('\n');
                    Walk(ParsePart(Latin1.GetBytes(piece)), c, depth + 1);
                }
                return;
            }
            bool attachment = name.Length > 0 || disp.ToLowerInvariant().StartsWith("attachment") || type == "message/rfc822";
            if (!attachment && (type == "text/plain" || type == "text/html"))
            {
                string s = Charset(Param(ct, "charset")).GetString(Decoded(p));
                (type == "text/html" ? c.Html : c.Plain).Append(s).Append("\n");
                return;
            }
            if (!attachment && !type.StartsWith("image/") && !type.StartsWith("application/")) return;
            var data = Decoded(p);
            var info = new AttachmentInfo { Name = name.Length > 0 ? name : (type == "message/rfc822" ? "message.eml" : "piece"), ContentType = type };
            info.IsInline = p.H("Content-ID").Length > 0 && !disp.ToLowerInvariant().StartsWith("attachment");
            info.IsImage = type.StartsWith("image/") || Regex.IsMatch(info.Name, @"\.(png|jpe?g|gif|bmp)$", RegexOptions.IgnoreCase);
            info.IsEmbeddedMessage = type == "message/rfc822";
            info.Size = data.LongLength;
            if (!(info.IsInline && info.IsImage)) { try { Forensics.ComputeHashes(info, data); } catch (Exception) { } }
            if (info.IsImage && c.QrScanned < 5 && info.Size >= 1024 && info.Size <= 3 * 1024 * 1024)
            {
                try { info.QrCodes = QrScan.Decode(data); c.QrScanned++; } catch (Exception) { }
            }
            c.Atts.Add(info);
        }

        static EmailData Parse(byte[] raw, out int year)
        {
            var top = ParsePart(raw);
            var e = new EmailData { RawHeaders = top.RawHeaders };
            year = 0;
            DateTime d;
            string date = Regex.Replace(top.H("Date"), @"\s*\([^)]*\)\s*$", "");
            if (DateTime.TryParse(Regex.Replace(date, @"^\w{3},\s*", ""), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AllowWhiteSpaces, out d)) year = d.Year;
            else { var ym = Regex.Match(date, @"\b(19|20)\d\d\b"); if (ym.Success) year = int.Parse(ym.Value); }

            string from = Utf8IfValid(DecodeWords(top.H("From")));
            var am = Regex.Match(from, @"<\s*([^<>\s]+@[^<>\s]+)\s*>");
            if (am.Success) { e.FromAddress = am.Groups[1].Value; e.FromName = from.Substring(0, am.Index).Trim().Trim('"').Trim(); }
            else
            {
                var bm = Regex.Match(from, @"[^\s<>""()]+@[^\s<>""()]+");
                e.FromAddress = bm.Success ? bm.Value : "";
                var nm = Regex.Match(from, @"\(([^)]*)\)");
                e.FromName = nm.Success ? nm.Groups[1].Value : "";
            }
            e.Subject = Utf8IfValid(DecodeWords(top.H("Subject")));
            foreach (Match m in Regex.Matches(top.H("Reply-To"), @"[^\s<>,""]+@[^\s<>,""]+")) e.ReplyTo.Add(m.Value);
            if (e.ReplyTo.Count == 0 && e.FromAddress.Length > 0) e.ReplyTo.Add(e.FromAddress);   // Outlook renvoie l'expéditeur quand il n'y a pas de Reply-To

            var c = new Collected();
            Walk(top, c, 0);
            string html = c.Html.ToString();
            string plain = c.Plain.ToString();
            if (plain.Trim().Length == 0 && html.Length > 0) plain = HtmlToText(html);
            e.BodyText = plain;

            var seen = new HashSet<string>();
            foreach (Match m in AnchorRe.Matches(html))
            {
                string href = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Success ? m.Groups[2].Value : m.Groups[3].Value;
                href = WebUtility.HtmlDecode(href).Trim();
                string text = WebUtility.HtmlDecode(TagRe.Replace(m.Groups[4].Value, " "));
                text = Regex.Replace(text, @"\s+", " ").Trim();
                if (seen.Add(href + "|" + text)) e.Links.Add(new LinkInfo(href, text));
            }
            e.HasForm = Regex.IsMatch(html, @"<form\b", RegexOptions.IgnoreCase);
            e.HasPasswordInput = Regex.IsMatch(html, @"<input\b[^>]*\btype\s*=\s*[""']?password", RegexOptions.IgnoreCase);
            foreach (Match m in PlainUrlRe.Matches(e.BodyText))
            {
                string u = m.Value.TrimEnd('.', ',', ';', '>');
                bool known = e.Links.Any(l => l.Href.StartsWith(u, StringComparison.OrdinalIgnoreCase));
                if (!known && seen.Add(u + "|")) e.Links.Add(new LinkInfo(u, ""));
            }
            e.Attachments.AddRange(c.Atts);
            return e;
        }

        static string HtmlToText(string html)
        {
            string s = Regex.Replace(html, @"<(script|style|head)\b.*?</\1\s*>", " ", RegexOptions.IgnoreCase | RegexOptions.Singleline);
            s = Regex.Replace(s, @"<(br|/p|/div|/tr|/li|/h\d)\b[^>]*>", "\n", RegexOptions.IgnoreCase);
            s = TagRe.Replace(s, " ");
            s = WebUtility.HtmlDecode(s);
            s = Regex.Replace(s, @"[ \t ]+", " ");
            return Regex.Replace(s, @"\n\s*\n+", "\n\n").Trim();
        }
    }
}
