using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace PhishGuard
{
    /// <summary>
    /// Analyse approfondie des pièces jointes, sur le poste : ce que l'analyse courante ne lit pas (contenu compressé).
    /// Documents Office (modèles et objets distants, champs DDE, code des macros), parties compressées des PDF,
    /// archives imbriquées, pages HTML qui fabriquent un fichier. Rien n'est exécuté ni enregistré sur le disque ;
    /// les tailles lues sont bornées (protection contre les bombes de décompression).
    /// </summary>
    public static class DeepScan
    {
        const long MaxEntryBytes = 10L * 1024 * 1024;    // par fichier décompressé
        const long MaxTotalBytes = 40L * 1024 * 1024;    // pour une pièce jointe
        const int MaxEntries = 300;
        const int MaxRatio = 200;                         // taux de compression au-delà duquel on soupçonne une bombe

        static Finding F(string id, Severity s, string title, string detail, params string[] ev)
        {
            return new Finding(id, "attachments", s, title, detail, ev);
        }

        static string Ext(string name)
        {
            int i = (name ?? "").LastIndexOf('.');
            return i >= 0 ? name.Substring(i + 1).ToLowerInvariant() : "";
        }

        /// <summary>Inspecte une pièce jointe. Les liens découverts sont ajoutés à a.EmbeddedUrls (et vérifiés ensuite en ligne).</summary>
        public static void Inspect(AttachmentInfo a, byte[] d, DeepReport rep)
        {
            if (a == null || d == null || d.Length == 0) return;
            string name = a.Name ?? "";
            string magic = a.Magic.Length > 0 ? a.Magic : Forensics.DetectMagic(d);
            try
            {
                if (magic == "zip")
                {
                    if (IsOoxml(d)) InspectOoxml(a, d, rep);
                    else InspectArchive(a, d, rep, 0);
                }
                else if (magic == "pdf") InspectPdf(a, d, rep);
                else if (magic == "ole") InspectVba(a, d, rep, L.T("document Office ancien format"));
                else if (magic == "html" || magic == "svg" || Lists.ExtHtml.Contains(Ext(name))) InspectHtml(a, Encoding.UTF8.GetString(d, 0, Math.Min(d.Length, 5 * 1024 * 1024)), rep);
                else if (magic == "iso" || Lists.ExtDiskImage.Contains(Ext(name)))
                    rep.Unchecked.Add(L.F("{0} : image disque, son contenu n’est pas lu (ouvrez-la seulement si vous l’attendiez)", name));
            }
            catch (Exception ex) { rep.Unchecked.Add(L.F("{0} : lecture interrompue ({1})", name, ex.GetType().Name)); }
        }

        // ------------------------------------------------------------------ Office (docx, xlsx, pptx…)

        static bool IsOoxml(byte[] d)
        {
            string s = Encoding.ASCII.GetString(d, 0, Math.Min(d.Length, 64 * 1024));
            return s.Contains("[Content_Types].xml") || s.Contains("word/") || s.Contains("xl/") || s.Contains("ppt/");
        }

        static readonly Regex RelRe = new Regex(@"<Relationship\b[^>]{0,2000}>", RegexOptions.IgnoreCase);
        static readonly Regex AttrRe = new Regex(@"\b(Type|Target|TargetMode)\s*=\s*""([^""]{0,2000})""", RegexOptions.IgnoreCase);

        static string ReadEntry(ZipArchiveEntry e, ref long total)
        {
            if (e.Length > MaxEntryBytes || total + e.Length > MaxTotalBytes) return null;
            if (e.CompressedLength > 0 && e.Length / e.CompressedLength > MaxRatio && e.Length > 1024 * 1024) return null;
            total += e.Length;
            using (var s = e.Open())
            using (var r = new StreamReader(s, Encoding.UTF8))
            {
                var buf = new char[(int)Math.Min(e.Length + 16, MaxEntryBytes)];
                int n = r.ReadBlock(buf, 0, buf.Length);
                return new string(buf, 0, n);
            }
        }

        static byte[] ReadEntryBytes(ZipArchiveEntry e, ref long total)
        {
            if (e.Length > MaxEntryBytes || total + e.Length > MaxTotalBytes) return null;
            if (e.CompressedLength > 0 && e.Length / e.CompressedLength > MaxRatio && e.Length > 1024 * 1024) return null;
            total += e.Length;
            using (var s = e.Open())
            using (var m = new MemoryStream())
            {
                var buf = new byte[81920]; int n; long read = 0;
                while ((n = s.Read(buf, 0, buf.Length)) > 0) { read += n; if (read > MaxEntryBytes) return null; m.Write(buf, 0, n); }
                return m.ToArray();
            }
        }

        static void InspectOoxml(AttachmentInfo a, byte[] d, DeepReport rep)
        {
            long total = 0;
            int external = 0;
            var embedded = new List<string>();
            using (var zip = new ZipArchive(new MemoryStream(d), ZipArchiveMode.Read))
            {
                foreach (var e in zip.Entries.Take(MaxEntries))
                {
                    string n = e.FullName;
                    if (n.EndsWith(".rels", StringComparison.OrdinalIgnoreCase))
                    {
                        string xml = ReadEntry(e, ref total);
                        if (xml == null) continue;
                        foreach (Match m in RelRe.Matches(xml))
                        {
                            string type = "", target = "", mode = "";
                            foreach (Match at in AttrRe.Matches(m.Value))
                            {
                                string k = at.Groups[1].Value.ToLowerInvariant(), v = System.Net.WebUtility.HtmlDecode(at.Groups[2].Value);
                                if (k == "type") type = v; else if (k == "target") target = v; else mode = v;
                            }
                            if (!mode.Equals("External", StringComparison.OrdinalIgnoreCase) || target.Length == 0) continue;
                            external++;
                            string kind = type.Substring(type.LastIndexOf('/') + 1).ToLowerInvariant();
                            bool unc = target.StartsWith("\\\\") || target.StartsWith("file:", StringComparison.OrdinalIgnoreCase);
                            if (unc)
                                rep.Findings.Add(F("deep-office-unc", Severity.High, L.T("Le document contacte un serveur réseau à son ouverture"),
                                    L.T("Il charge un élément depuis un partage réseau extérieur : Windows peut alors envoyer votre identifiant et une empreinte de votre mot de passe à ce serveur."), a.Name, Analyzer.Defang(target)));
                            else if (kind == "attachedtemplate" || kind == "frame" || kind == "subdocument" || kind == "oleobject")
                                rep.Findings.Add(F("deep-office-remote", Severity.High, L.T("Le document télécharge du contenu sur Internet à son ouverture"),
                                    L.T("Modèle, cadre ou objet distant : technique courante pour charger des macros ou exploiter Office sans que le fichier joint contienne de code."), a.Name, kind + " : " + Analyzer.Defang(target)));
                            if (target.StartsWith("http", StringComparison.OrdinalIgnoreCase) && !a.EmbeddedUrls.Contains(target) && a.EmbeddedUrls.Count < 60)
                                a.EmbeddedUrls.Add(target);
                        }
                    }
                    else if (n.StartsWith("word/document", StringComparison.OrdinalIgnoreCase) && n.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)
                        || n.StartsWith("xl/externalLinks", StringComparison.OrdinalIgnoreCase))
                    {
                        string xml = ReadEntry(e, ref total);
                        if (xml != null && Regex.IsMatch(xml, @"\bDDE(AUTO)?\b") && Regex.IsMatch(xml, @"instrText|ddeLink|fldSimple", RegexOptions.IgnoreCase))
                            rep.Findings.Add(F("deep-office-dde", Severity.High, L.T("Le document contient un champ DDE"),
                                L.T("Ce champ peut lancer un programme à l’ouverture, après une simple demande de mise à jour des liaisons. Répondez « Non »."), a.Name));
                    }
                    else if (n.IndexOf("/embeddings/", StringComparison.OrdinalIgnoreCase) >= 0)
                        embedded.Add(n.Substring(n.LastIndexOf('/') + 1));
                    else if (n.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase))
                    {
                        var vba = ReadEntryBytes(e, ref total);
                        if (vba != null) InspectVba(a, vba, rep, L.T("macros du document"));
                    }
                }
            }
            if (embedded.Count > 0)
                rep.Facts.Add(new DeepFact("att", "info", L.F("{0} : {1} objet(s) incorporé(s) — {2}", a.Name, embedded.Count, string.Join(", ", embedded.Take(6).ToArray()))));
            if (external > 0)
                rep.Facts.Add(new DeepFact("att", "warn", L.F("{0} : {1} lien(s) externe(s) dans la structure du document", a.Name, external)));
            else
                rep.Facts.Add(new DeepFact("att", "ok", L.F("{0} : structure du document lue, aucun contenu distant chargé à l’ouverture", a.Name)));
        }

        // ------------------------------------------------------------------ Macros VBA (code source compressé, MS-OVBA)

        static readonly string[] AutoExec = { "autoopen", "auto_open", "document_open", "workbook_open", "autoexec", "autoclose", "document_close", "auto_close", "workbook_activate", "document_new" };
        static readonly string[] Dangerous = { "shell", "wscript.shell", "createobject", "urldownloadtofile", "powershell", "cmd.exe", "xmlhttp", "winhttp", "adodb.stream", "callbyname", "environ", "kill ", "savetofile", "shellexecute", "mshta", "regsvr32", "rundll32", "certutil", "bitsadmin" };

        static void InspectVba(AttachmentInfo a, byte[] d, DeepReport rep, string what)
        {
            var source = new StringBuilder();
            int tries = 0;
            for (int i = 0; i + 3 < d.Length && tries < 300 && source.Length < 2 * 1024 * 1024; i++)
            {
                if (d[i] != 1) continue;
                int header = d[i + 1] | (d[i + 2] << 8);
                if (((header >> 12) & 7) != 3) continue;   // signature d'un bloc compressé
                tries++;
                string s = Decompress(d, i);
                if (s != null && s.IndexOf("Attribute VB_", StringComparison.Ordinal) >= 0) { source.Append(s).Append('\n'); }
            }
            if (source.Length == 0) return;
            string code = source.ToString().ToLowerInvariant();
            var auto = AutoExec.Where(k => Regex.IsMatch(code, @"\b(sub|function)\s+" + Regex.Escape(k) + @"\b")).ToList();
            var bad = Dangerous.Where(k => code.Contains(k)).ToList();
            int modules = Regex.Matches(code, @"attribute vb_name\s*=").Count;
            rep.Facts.Add(new DeepFact("att", bad.Count > 0 ? "bad" : "warn", L.F("{0} : code des macros lu ({1}, {2} module(s))", a.Name, what, modules)
                + (auto.Count > 0 ? " — " + L.F("lancement automatique : {0}", string.Join(", ", auto.ToArray())) : "")
                + (bad.Count > 0 ? " — " + L.F("instructions sensibles : {0}", string.Join(", ", bad.Take(8).ToArray())) : "")));
            if (auto.Count > 0 && bad.Count > 0)
                rep.Findings.Add(F("deep-vba-dropper", Severity.Critical, L.T("Macro qui se lance à l’ouverture et peut exécuter ou télécharger un programme"),
                    L.T("C’est le fonctionnement d’un document piégé : n’activez surtout pas le contenu."), a.Name, string.Join(", ", auto.Concat(bad).Take(6).ToArray())));
            else if (auto.Count > 0)
                rep.Findings.Add(F("deep-vba-autoexec", Severity.Medium, L.T("Macro qui se lance automatiquement à l’ouverture"), "", a.Name, string.Join(", ", auto.ToArray())));
            else if (bad.Count > 0)
                rep.Findings.Add(F("deep-vba-dangerous", Severity.High, L.T("Macro capable d’exécuter ou de télécharger un programme"), "", a.Name, string.Join(", ", bad.Take(6).ToArray())));
        }

        /// <summary>Décompression MS-OVBA (code source des macros). Renvoie null si les données ne sont pas un bloc valide.</summary>
        public static string Decompress(byte[] d, int pos)
        {
            try
            {
                if (pos >= d.Length || d[pos] != 1) return null;
                var o = new List<byte>(4096);
                int p = pos + 1, chunks = 0;
                while (p + 1 < d.Length && chunks < 64)
                {
                    int header = d[p] | (d[p + 1] << 8);
                    int size = (header & 0x0FFF) + 3;
                    if (((header >> 12) & 7) != 3) break;
                    bool compressed = (header & 0x8000) != 0;
                    int end = Math.Min(d.Length, p + size);
                    p += 2;
                    int start = o.Count;
                    chunks++;
                    if (!compressed)
                    {
                        for (int k = 0; k < 4096 && p < d.Length; k++) o.Add(d[p++]);
                        continue;
                    }
                    while (p < end)
                    {
                        byte flags = d[p++];
                        for (int bit = 0; bit < 8 && p < end; bit++)
                        {
                            if ((flags & (1 << bit)) == 0) { o.Add(d[p++]); continue; }
                            if (p + 1 >= d.Length) return null;
                            int token = d[p] | (d[p + 1] << 8); p += 2;
                            int dpos = o.Count - start;
                            if (dpos <= 0) return null;
                            int bitCount = 4;
                            while ((1 << bitCount) < dpos) bitCount++;
                            if (bitCount > 12) bitCount = 12;
                            int lengthMask = 0xFFFF >> bitCount;
                            int length = (token & lengthMask) + 3;
                            int offset = (token >> (16 - bitCount)) + 1;
                            int src = o.Count - offset;
                            if (src < start) return null;
                            for (int k = 0; k < length; k++) o.Add(o[src + k]);
                        }
                    }
                    if (o.Count > 4 * 1024 * 1024) break;
                }
                return o.Count < 16 ? null : Encoding.GetEncoding(1252).GetString(o.ToArray());
            }
            catch (Exception) { return null; }
        }

        // ------------------------------------------------------------------ PDF : parties compressées

        static readonly Regex StreamRe = new Regex(@"/FlateDecode[^\n]{0,400}?>>\s*stream\r?\n", RegexOptions.Compiled);
        static readonly Regex PdfUriRe = new Regex(@"/URI\s*\(((?:\\.|[^\\)]){4,500})\)");

        public static void InspectPdf(AttachmentInfo a, byte[] d, DeepReport rep)
        {
            string raw = Encoding.GetEncoding(28591).GetString(d, 0, Math.Min(d.Length, 30 * 1024 * 1024));
            var parts = new StringBuilder();
            int streams = 0, inflated = 0; long total = 0;
            foreach (Match m in StreamRe.Matches(raw))
            {
                if (++streams > 400 || total > MaxTotalBytes) break;
                int start = m.Index + m.Length;
                int end = raw.IndexOf("endstream", start, Math.Min(raw.Length - start, 8 * 1024 * 1024), StringComparison.Ordinal);
                if (end < 0) continue;
                var text = Inflate(d, start, end - start, ref total);
                if (text == null) continue;
                inflated++;
                // Seules les parties qui ressemblent à des objets PDF (pas le texte des pages) sont gardées
                if (text.Contains("/URI") || text.Contains("/JavaScript") || text.Contains("/JS") || text.Contains("/Launch") || text.Contains("/OpenAction")
                    || text.Contains("/AA") || text.Contains("/SubmitForm") || text.Contains("/EmbeddedFile") || text.Contains("/GoToR"))
                    parts.Append(text).Append('\n');
            }
            string all = raw + "\n" + parts;
            int before = a.EmbeddedUrls.Count;
            foreach (Match m in PdfUriRe.Matches(parts.ToString()))
            {
                string u = Regex.Replace(m.Groups[1].Value, @"\\(.)", "$1").Trim();
                if (Regex.IsMatch(u, "^(https?://|www\\.)", RegexOptions.IgnoreCase) && !a.EmbeddedUrls.Contains(u) && a.EmbeddedUrls.Count < 60) a.EmbeddedUrls.Add(u);
            }
            int hidden = a.EmbeddedUrls.Count - before;
            bool js = Regex.IsMatch(parts.ToString(), @"/(JavaScript|JS)\b"), launch = parts.ToString().Contains("/Launch");
            bool auto = Regex.IsMatch(all, @"/OpenAction|/AA\s*<<");
            bool submit = all.Contains("/SubmitForm"), remote = all.Contains("/GoToR") || all.Contains("/GoToE");
            if (all.Contains("/Encrypt"))
                rep.Unchecked.Add(L.F("{0} : PDF chiffré, ses parties compressées n’ont pas pu être lues", a.Name));
            if (auto && (js || launch || Regex.IsMatch(all, @"/OpenAction\s*<<[^>]{0,300}/URI")))
                rep.Findings.Add(F("deep-pdf-autoaction", Severity.High, L.T("Le PDF agit tout seul à son ouverture"),
                    L.T("Il lance du code, un programme ou une page web dès qu’on l’ouvre, sans clic de votre part."), a.Name));
            if ((js || launch) && !a.ContentFindings.Any(f => f.Id == "att-content-pdf-js" || f.Id == "att-content-pdf-launch"))
                rep.Findings.Add(F("deep-pdf-hidden-code", Severity.High, L.T("Code caché dans les parties compressées du PDF"),
                    L.T("Invisible à une lecture simple du fichier : technique pour passer les filtres."), a.Name));
            if (submit)
                rep.Facts.Add(new DeepFact("att", "warn", L.F("{0} : formulaire qui envoie les données saisies sur Internet", a.Name)));
            if (remote)
                rep.Facts.Add(new DeepFact("att", "warn", L.F("{0} : ouvre un autre document à distance", a.Name)));
            if (hidden > 0)
                rep.Facts.Add(new DeepFact("att", "warn", L.F("{0} : {1} lien(s) caché(s) dans les parties compressées", a.Name, hidden)));
            rep.Facts.Add(new DeepFact("att", "info", L.F("{0} : {1} partie(s) compressée(s) lue(s) sur {2}", a.Name, inflated, Math.Min(streams, 400))));
        }

        static string Inflate(byte[] d, int start, int len, ref long total)
        {
            if (len < 3 || start + len > d.Length) return null;
            int skip = (d[start] & 0x0F) == 8 ? 2 : 0;   // en-tête zlib
            try
            {
                using (var src = new MemoryStream(d, start + skip, len - skip))
                using (var z = new DeflateStream(src, CompressionMode.Decompress))
                using (var m = new MemoryStream())
                {
                    var buf = new byte[65536]; int n;
                    while ((n = z.Read(buf, 0, buf.Length)) > 0)
                    {
                        m.Write(buf, 0, n);
                        if (m.Length > 4 * 1024 * 1024 || (long)m.Length > (long)len * MaxRatio + 65536) break;
                    }
                    total += m.Length;
                    return Encoding.GetEncoding(28591).GetString(m.GetBuffer(), 0, (int)m.Length);
                }
            }
            catch (Exception) { return null; }
        }

        // ------------------------------------------------------------------ Archives (zip non Office) et archives imbriquées

        static readonly HashSet<string> ArchiveExt = new HashSet<string> { "zip", "rar", "7z", "gz", "tar", "cab", "arj", "ace", "iso", "img", "vhd", "vhdx" };

        static void InspectArchive(AttachmentInfo a, byte[] d, DeepReport rep, int depth)
        {
            long total = 0;
            int files = 0, bomb = 0, locked = 0;
            var danger = new List<string>();
            var nested = new List<string>();
            using (var zip = new ZipArchive(new MemoryStream(d), ZipArchiveMode.Read))
            {
                foreach (var e in zip.Entries.Take(MaxEntries))
                {
                    if (e.FullName.EndsWith("/")) continue;
                    files++;
                    string x = Ext(e.Name);
                    if (e.CompressedLength > 0 && e.Length / Math.Max(1, e.CompressedLength) > MaxRatio && e.Length > 10 * 1024 * 1024) { bomb++; continue; }
                    if (ArchiveExt.Contains(x))
                    {
                        nested.Add(e.FullName);
                        if (x == "zip" && depth < 2)
                        {
                            byte[] inner = null;
                            try { inner = ReadEntryBytes(e, ref total); } catch (Exception) { locked++; }
                            if (inner != null)
                            {
                                var sub = new AttachmentInfo { Name = a.Name + " › " + e.FullName };
                                var subRep = new DeepReport();
                                InspectArchive(sub, inner, subRep, depth + 1);
                                rep.Facts.AddRange(subRep.Facts);
                                foreach (var f in subRep.Findings) rep.Findings.Add(f);
                            }
                        }
                    }
                    bool dangerous = Lists.ExtExecutable.Contains(x) || Lists.ExtHtml.Contains(x) || Lists.ExtMacro.Contains(x) || Lists.ExtOneNote.Contains(x) || x == "lnk" || x == "url";
                    if (dangerous && depth > 0) danger.Add(e.FullName);
                }
            }
            if (bomb > 0)
                rep.Findings.Add(F("deep-archive-bomb", Severity.Medium, L.T("Archive anormalement compressée"),
                    L.T("Un fichier minuscule qui se décompresse en un volume énorme : technique pour saturer les antivirus."), a.Name));
            if (danger.Count > 0)
                rep.Findings.Add(F("deep-archive-nested-danger", Severity.High, L.T("Programme ou script caché dans une archive à l’intérieur de l’archive"),
                    L.T("Les archives imbriquées servent à échapper aux filtres qui n’en ouvrent qu’un niveau."), danger.Take(5).ToArray()));
            rep.Facts.Add(new DeepFact("att", nested.Count > 0 ? "warn" : "info",
                L.F("{0} : {1} fichier(s)", a.Name, files) + (nested.Count > 0 ? " — " + L.F("archive(s) imbriquée(s) : {0}", string.Join(", ", nested.Take(5).ToArray())) : "")
                + (locked > 0 ? " — " + L.F("{0} protégée(s) par mot de passe", locked) : "")));
        }

        // ------------------------------------------------------------------ HTML : fabrication de fichier (contrebande HTML), redirections

        static readonly Regex BigBase64 = new Regex(@"[A-Za-z0-9+/]{20000,}={0,2}", RegexOptions.Compiled);
        static readonly Regex MetaRefresh = new Regex(@"<meta\b[^>]{0,300}http-equiv\s*=\s*[""']?refresh[^>]{0,300}url\s*=\s*['""]?([^'"">\s]{4,500})", RegexOptions.IgnoreCase);
        static readonly Regex JsLocation = new Regex(@"(?:window|document|top|self)\.location(?:\.href)?\s*=\s*[""'](https?://[^""'\s]{4,500})", RegexOptions.IgnoreCase);
        static readonly Regex FormAction = new Regex(@"<form\b[^>]{0,500}action\s*=\s*[""']?(https?://[^""'\s>]{4,500})", RegexOptions.IgnoreCase);

        public static void InspectHtml(AttachmentInfo a, string s, DeepReport rep)
        {
            bool blob = Regex.IsMatch(s, @"new\s+Blob\s*\(|msSaveOrOpenBlob|createObjectURL\s*\(", RegexOptions.IgnoreCase);
            bool download = Regex.IsMatch(s, @"\.download\s*=|\bdownload\s*=\s*[""']", RegexOptions.IgnoreCase);
            bool payload = BigBase64.IsMatch(s);
            if (blob && (download || payload))
                rep.Findings.Add(F("deep-html-smuggling", Severity.High, L.T("La page fabrique un fichier dès son ouverture (contrebande HTML)"),
                    L.T("Le fichier dangereux est caché dans la page et assemblé par votre navigateur : il échappe ainsi aux filtres de messagerie."), a.Name));
            foreach (var re in new[] { MetaRefresh, JsLocation, FormAction })
                foreach (Match m in re.Matches(s))
                {
                    string u = System.Net.WebUtility.HtmlDecode(m.Groups[1].Value);
                    if (u.StartsWith("http", StringComparison.OrdinalIgnoreCase) && !a.EmbeddedUrls.Contains(u) && a.EmbeddedUrls.Count < 60)
                    {
                        a.EmbeddedUrls.Add(u);
                        rep.Facts.Add(new DeepFact("att", "warn", re == FormAction ? L.F("{0} : les données saisies partent vers {1}", a.Name, DeepAnalysis.Host(u))
                            : L.F("{0} : renvoie automatiquement vers {1}", a.Name, DeepAnalysis.Host(u))));
                    }
                }
        }
    }
}
