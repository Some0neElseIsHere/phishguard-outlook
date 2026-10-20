using System;
using System.Collections.Generic;
using System.Linq;

namespace PhishGuard.AddIn
{
    /// <summary>
    /// Analyse approfondie, dans la boîte de l'utilisateur (rien ne sort du poste) : cet expéditeur a-t-il déjà écrit,
    /// son nom a-t-il été utilisé avec une autre adresse, la conversation à laquelle il répond existe-t-elle ?
    /// Doit être appelé sur le fil d'Outlook.
    /// </summary>
    internal static class MailHistory
    {
        const int OlFolderSentMail = 5, OlFolderInbox = 6;
        const string PR_INTERNET_MESSAGE_ID = "http://schemas.microsoft.com/mapi/proptag/0x1035001F";

        static string Str(Func<object> getter)
        {
            try { object v = getter(); return v == null ? "" : v.ToString(); } catch (Exception) { return ""; }
        }

        static string Quote(string s) { return (s ?? "").Replace("'", "''"); }

        public static void Explore(object app, object mailObj, EmailData e, DeepReport rep)
        {
            dynamic session;
            try { session = ((dynamic)app).Session; } catch (Exception) { rep.Unchecked.Add(L.T("Historique : boîte aux lettres inaccessible")); return; }
            dynamic inbox = null, sent = null;
            try { inbox = session.GetDefaultFolder(OlFolderInbox); } catch (Exception) { }
            try { sent = session.GetDefaultFolder(OlFolderSentMail); } catch (Exception) { }
            string addr = (e.FromAddress ?? "").Trim();
            string entryId = Str(() => ((dynamic)mailObj).EntryID);

            // ---- Messages déjà reçus de cette adresse ----
            if (inbox != null && addr.Contains("@"))
            {
                try
                {
                    // Pas de parcours des messages (lent dans une grosse boîte) : le nombre, et le plus ancien après tri
                    dynamic items = inbox.Items.Restrict("[SenderEmailAddress] = '" + Quote(addr) + "'");
                    items.Sort("[ReceivedTime]", false);
                    int total = items.Count;
                    int count = total; DateTime? first = null;
                    for (int i = 1; i <= total && i <= 3; i++)
                    {
                        dynamic it = items.Item(i);
                        if (Str(() => it.EntryID) == entryId) { count--; continue; }
                        if (first == null) { try { first = (DateTime)it.ReceivedTime; } catch (Exception) { } }
                    }
                    if (total > 3)
                    {
                        // Le message affiché peut être n'importe où : il est retiré du compte s'il est dans la boîte de réception
                        try { if (Str(() => ((dynamic)mailObj).Parent.EntryID) == Str(() => inbox.EntryID)) count--; } catch (Exception) { }
                    }
                    if (count == 0)
                        rep.Facts.Add(new DeepFact("history", "warn", L.F("Premier message reçu de {0} dans votre boîte de réception", addr)));
                    else
                        rep.Facts.Add(new DeepFact("history", "ok", L.F("{0} autre(s) message(s) reçu(s) de cette adresse{1}", count,
                            first.HasValue ? " " + L.F("depuis le {0}", first.Value.ToString("dd/MM/yyyy")) : "")));
                }
                catch (Exception ex) { rep.Unchecked.Add(L.T("Historique de l’expéditeur : ") + ex.Message); }
            }

            // ---- Même nom affiché, autre adresse : usurpation d'un correspondant connu ----
            string name = (e.FromName ?? "").Trim();
            if (inbox != null && name.Length >= 4 && !name.Contains("@"))
            {
                try
                {
                    dynamic items = inbox.Items.Restrict("[SenderName] = '" + Quote(name) + "'");
                    var others = new List<string>();
                    int total = items.Count;
                    for (int i = 1; i <= total && i <= 40; i++)
                    {
                        dynamic it = items.Item(i);
                        string a = Str(() => it.SenderEmailAddress);
                        if (Str(() => it.SenderEmailType) == "EX") { try { a = Str(() => it.Sender.GetExchangeUser().PrimarySmtpAddress); } catch (Exception) { } }
                        a = a.Trim().ToLowerInvariant();
                        if (a.Contains("@") && !a.Equals(addr, StringComparison.OrdinalIgnoreCase) && !others.Contains(a)) others.Add(a);
                    }
                    if (others.Count > 0)
                    {
                        string fromOrg = Domains.RegistrableDomain(Domains.DomainOfAddress(addr));
                        bool otherDomain = others.Any(o => Domains.RegistrableDomain(Domains.DomainOfAddress(o)) != fromOrg);
                        rep.Facts.Add(new DeepFact("history", otherDomain ? "bad" : "info", L.F("Le nom « {0} » vous a déjà écrit depuis : {1}", name, string.Join(", ", others.Take(4).ToArray()))));
                        if (otherDomain)
                            rep.Findings.Add(new Finding("deep-history-name", "sender", Severity.Medium, L.T("Ce nom d’expéditeur vous écrivait jusqu’ici depuis une autre adresse"),
                                L.T("Un escroc reprend le nom d’un collègue, d’un dirigeant ou d’un fournisseur avec une nouvelle adresse. Vérifiez par téléphone, avec un numéro que vous connaissez."),
                                new[] { L.T("Habituellement : ") + others[0], L.T("Ce message : ") + addr }));
                    }
                }
                catch (Exception ex) { rep.Unchecked.Add(L.T("Historique du nom : ") + ex.Message); }
            }

            // ---- La conversation citée existe-t-elle ? (réponse fabriquée) ----
            string inReply = "";
            foreach (var line in (e.RawHeaders ?? "").Split('\n'))
                if (line.StartsWith("In-Reply-To:", StringComparison.OrdinalIgnoreCase)) { inReply = line.Substring(12).Trim(); break; }
            if (inReply.StartsWith("<") && inReply.Contains(">"))
            {
                inReply = inReply.Substring(0, inReply.IndexOf('>') + 1);
                bool found = false;
                foreach (dynamic f in new[] { (object)sent, (object)inbox })
                {
                    if (f == null || found) continue;
                    try
                    {
                        dynamic items = f.Items.Restrict("@SQL=\"" + PR_INTERNET_MESSAGE_ID + "\" = '" + Quote(inReply) + "'");
                        if (items.Count > 0) found = true;
                    }
                    catch (Exception) { }
                }
                if (found) rep.Facts.Add(new DeepFact("history", "ok", L.T("Le message auquel il répond se trouve bien dans votre boîte")));
                else
                {
                    rep.Facts.Add(new DeepFact("history", "warn", L.T("Le message auquel il prétend répondre est introuvable dans votre boîte de réception et vos éléments envoyés")));
                    rep.Findings.Add(new Finding("deep-history-thread", "sender", Severity.Low, L.T("La conversation citée est introuvable dans votre boîte"),
                        L.T("Les escrocs fabriquent de fausses réponses (« RE: ») pour paraître légitimes. Si vous n’avez jamais écrit à ce sujet, méfiance."), null));
                }
            }
        }
    }
}
