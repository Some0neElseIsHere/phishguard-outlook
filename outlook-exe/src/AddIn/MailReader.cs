// PhishGuard - lecture d'un message Outlook (liaison tardive "dynamic", sans assembly d'interop).

using System;
using System.Collections.Generic;
using System.Net;
using System.Text.RegularExpressions;

namespace PhishGuard.AddIn
{
    internal static class MailReader
    {
        const string PR_TRANSPORT_MESSAGE_HEADERS = "http://schemas.microsoft.com/mapi/proptag/0x007D001F";
        const string PR_ATTACH_CONTENT_ID = "http://schemas.microsoft.com/mapi/proptag/0x3712001F";
        const string PR_ATTACHMENT_HIDDEN = "http://schemas.microsoft.com/mapi/proptag/0x7FFE000B";
        const string PR_ATTACH_MIME_TAG = "http://schemas.microsoft.com/mapi/proptag/0x370E001F";
        public const int OlMail = 43;

        static readonly Regex AnchorRe = new Regex(@"<a\b[^>]*?\bhref\s*=\s*(?:""([^""]*)""|'([^']*)'|([^\s>]+))[^>]*>(.*?)</a\s*>",
            RegexOptions.IgnoreCase | RegexOptions.Singleline);
        static readonly Regex TagRe = new Regex(@"<[^>]+>", RegexOptions.Singleline);
        static readonly Regex PlainUrlRe = new Regex(@"\bhttps?://[^\s<>""')]+", RegexOptions.IgnoreCase);

        static string Str(Func<object> getter)
        {
            try { object v = getter(); return v == null ? "" : v.ToString(); }
            catch (Exception) { return ""; }
        }

        /// <summary>Adresse SMTP de l'expéditeur, y compris pour un expéditeur Exchange interne (type "EX").</summary>
        static string SmtpOfSender(object mailObj, out bool isExchange)
        {
            dynamic mail = mailObj;
            isExchange = false;
            string type = Str(() => mail.SenderEmailType);
            if (type == "EX")
            {
                isExchange = true;
                try
                {
                    dynamic sender = mail.Sender;
                    if (sender != null)
                    {
                        dynamic exUser = sender.GetExchangeUser();
                        if (exUser != null)
                        {
                            string smtp = Str(() => exUser.PrimarySmtpAddress);
                            if (smtp.Length > 0) return smtp;
                        }
                    }
                }
                catch (Exception) { }
                try
                {
                    // Repli : propriété PR_SENT_REPRESENTING_SMTP_ADDRESS
                    string smtp = Str(() => mail.PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x5D02001F"));
                    if (smtp.Length > 0) return smtp;
                }
                catch (Exception) { }
            }
            return Str(() => mail.SenderEmailAddress);
        }

        const string PR_ATTACH_DATA_BIN = "http://schemas.microsoft.com/mapi/proptag/0x37010102";
        public const long FullHashSize = 40L * 1024 * 1024;

        /// <summary>Contenu binaire d'une pièce jointe (lu en mémoire, ou via un fichier temporaire supprimé aussitôt).</summary>
        static byte[] ReadAttachmentBytes(object attObj, string name, long maxBytes)
        {
            dynamic a = attObj;
            long size = 0;
            try { size = (long)a.Size; } catch (Exception) { }
            if (size > maxBytes) return null;
            try
            {
                object v = a.PropertyAccessor.GetProperty(PR_ATTACH_DATA_BIN);
                var bytes = v as byte[];
                if (bytes != null && bytes.Length > 0) return bytes;
            }
            catch (Exception) { }

            string dir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "PhishGuard", Guid.NewGuid().ToString("N"));
            string safe = Regex.Replace(string.IsNullOrEmpty(name) ? "piece-jointe" : name, @"[\\/:*?""<>|\u0000-\u001f\u202a-\u202e\u2066-\u2069]", "_");
            if (safe.Length > 100) safe = safe.Substring(safe.Length - 100);
            string path = System.IO.Path.Combine(dir, safe);
            try
            {
                System.IO.Directory.CreateDirectory(dir);
                a.SaveAsFile(path);
                return System.IO.File.ReadAllBytes(path);
            }
            finally
            {
                try { System.IO.Directory.Delete(dir, true); } catch (Exception) { }
            }
        }

        public static EmailData Read(object mailObj)
        {
            return Read(mailObj, FullHashSize);
        }

        /// <param name="maxHashBytes">taille maximale des pièces jointes dont on calcule les empreintes</param>
        public static EmailData Read(object mailObj, long maxHashBytes)
        {
            dynamic mail = mailObj;
            var e = new EmailData();
            bool isExchange;
            e.FromAddress = SmtpOfSender(mailObj, out isExchange);
            e.IsExchangeInternal = isExchange;
            e.FromName = Str(() => mail.SenderName);
            e.Subject = Str(() => mail.Subject);
            e.BodyText = Str(() => mail.Body);
            e.RawHeaders = Str(() => mail.PropertyAccessor.GetProperty(PR_TRANSPORT_MESSAGE_HEADERS));

            // Adresses de réponse
            try
            {
                dynamic recips = mail.ReplyRecipients;
                int n = recips.Count;
                for (int i = 1; i <= n; i++)
                {
                    dynamic r = recips.Item(i);
                    string addr = Str(() => r.Address);
                    if (addr.Contains("@")) e.ReplyTo.Add(addr);
                }
            }
            catch (Exception) { }

            // Liens et formulaires (dans le HTML)
            string html = Str(() => mail.HTMLBody);
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

            // URL écrites en clair dans le texte
            foreach (Match m in PlainUrlRe.Matches(e.BodyText))
            {
                string u = m.Value.TrimEnd('.', ',', ';', '>');
                bool known = false;
                foreach (var l in e.Links) if (l.Href.StartsWith(u, StringComparison.OrdinalIgnoreCase)) { known = true; break; }
                if (!known && seen.Add(u + "|")) e.Links.Add(new LinkInfo(u, ""));
            }

            // Pièces jointes (noms uniquement)
            try
            {
                dynamic atts = mail.Attachments;
                int n = atts.Count;
                for (int i = 1; i <= n; i++)
                {
                    dynamic a = atts.Item(i);
                    var info = new AttachmentInfo { Name = Str(() => a.FileName) };
                    if (info.Name.Length == 0) info.Name = Str(() => a.DisplayName);
                    string cid = Str(() => a.PropertyAccessor.GetProperty(PR_ATTACH_CONTENT_ID));
                    string hidden = Str(() => a.PropertyAccessor.GetProperty(PR_ATTACHMENT_HIDDEN));
                    string mime = Str(() => a.PropertyAccessor.GetProperty(PR_ATTACH_MIME_TAG));
                    info.IsInline = cid.Length > 0 || hidden.Equals("True", StringComparison.OrdinalIgnoreCase);
                    info.IsImage = mime.StartsWith("image/", StringComparison.OrdinalIgnoreCase)
                        || Regex.IsMatch(info.Name, @"\.(png|jpe?g|gif|bmp)$", RegexOptions.IgnoreCase);
                    info.ContentType = mime;
                    int type = 0;
                    try { type = (int)a.Type; } catch (Exception) { }
                    info.IsEmbeddedMessage = type == 5;
                    try { info.Size = (long)a.Size; } catch (Exception) { }
                    // Contenu : empreintes MD5/SHA1/SHA256 et type réel (jamais exécuté)
                    if (!(info.IsInline && info.IsImage))
                    {
                        try { Forensics.ComputeHashes(info, ReadAttachmentBytes((object)a, info.Name, maxHashBytes)); }
                        catch (Exception) { }
                    }
                    e.Attachments.Add(info);
                }
            }
            catch (Exception) { }

            return e;
        }
    }
}
