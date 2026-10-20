// PhishGuard - modèles de données du moteur d'analyse.
// Code compatible C# 5 (compilateur intégré à Windows : .NET Framework 4.x).

using System.Collections.Generic;

namespace PhishGuard
{
    public enum Severity { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 }

    public class Finding
    {
        public string Id;
        public string Category;   // auth, sender, links, attachments, content
        public Severity Severity;
        public string Title;
        public string Detail;
        public List<string> Evidence = new List<string>();

        public Finding(string id, string category, Severity severity, string title, string detail, IEnumerable<string> evidence)
        {
            Id = id; Category = category; Severity = severity; Title = title; Detail = detail ?? "";
            if (evidence != null)
                foreach (var e in evidence) if (!string.IsNullOrEmpty(e)) Evidence.Add(e);
        }
    }

    public class LinkInfo
    {
        public string Text;
        public string Href;
        public LinkInfo(string href, string text) { Href = href; Text = text ?? ""; }
    }

    public class AttachmentInfo
    {
        public string Name;
        public bool IsInline;
        public bool IsImage;
        public bool IsEmbeddedMessage;   // message Outlook joint
        public long Size = -1;
        public string ContentType = "";
        public string Magic = "";        // type réel détecté (exe, zip, pdf, html...)
        public string Md5 = "", Sha1 = "", Sha256 = "";
        public List<Finding> ContentFindings = new List<Finding>();   // indices trouvés DANS le fichier
        public List<string> EmbeddedUrls = new List<string>();        // liens trouvés dans le fichier (PDF, HTML)
        public List<string> ArchiveEntries = new List<string>();      // contenu d'une archive ZIP
        public List<string> QrCodes = new List<string>();             // texte des QR codes trouvés dans l'image
    }

    public class EmailData
    {
        public string FromName = "";
        public string FromAddress = "";
        public string SenderAddress = "";
        public bool IsExchangeInternal;          // expéditeur interne authentifié par Exchange (type "EX")
        public string Subject = "";
        public string BodyText = "";
        public bool HasForm;
        public bool HasPasswordInput;
        public List<LinkInfo> Links = new List<LinkInfo>();
        public List<AttachmentInfo> Attachments = new List<AttachmentInfo>();
        public List<string> ReplyTo = new List<string>();
        public string RawHeaders = "";
    }

    /// <summary>État d'une source externe (onglet Bêta de la fenêtre d'analyse).</summary>
    public class SourceStatus
    {
        public string Name;
        public string State;    // off, ok, pending, error
        public string Detail = "";
    }

    public class AnalysisResult
    {
        public int Score;
        public string Level;          // safe, suspicious, dangerous
        public string LevelLabel;
        public string Advice;
        public bool Internal;
        public string InternalHow = "";   // exchange ou relay : pourquoi il n'y a pas d'authentification SPF/DKIM/DMARC
        public string Error;              // analyse interrompue par une erreur (le message est alors classé suspect)
        public List<Finding> Findings = new List<Finding>();
        public List<string> Positives = new List<string>();
        public List<string> LinkDomains = new List<string>();
        public List<string> Urls = new List<string>();
        public List<string> AttachmentNames = new List<string>();
        public string SenderAddress = "";
        public string SenderDomain = "";
        public HeaderDetails Details = new HeaderDetails();
        public List<AttachmentInfo> Attachments = new List<AttachmentInfo>();
        public bool FirstContact;
        public List<SourceStatus> Sources = new List<SourceStatus>();
        public List<string> Trust = new List<string>();   // preuves de légitimité
        public bool Verified;                              // « Expéditeur vérifié »
    }
}
