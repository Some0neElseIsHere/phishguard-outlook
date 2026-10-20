using System;
using System.Collections.Generic;
using System.Linq;

namespace PhishGuard.AddIn
{
    /// <summary>
    /// Analyse approfondie, dans la boîte de l'utilisateur (rien ne sort du poste) : cet expéditeur a-t-il déjà écrit,
    /// son nom a-t-il été utilisé avec une autre adresse, la conversation à laquelle il répond existe-t-elle ?
    /// Recherche d'Outlook (Items.Restrict) dans chaque dossier de la boîte du message : les messages ne sont pas lus un par un.
    /// Doit être appelé sur le fil d'Outlook.
    /// </summary>
    internal static class MailHistory
    {
        const int OlFolderSentMail = 5, OlFolderInbox = 6, OlFolderJunk = 23;
        const int MaxFolders = 400, BudgetMs = 6000;
        const string PR_INTERNET_MESSAGE_ID = "http://schemas.microsoft.com/mapi/proptag/0x1035001F";

        static string Str(Func<object> getter)
        {
            try { object v = getter(); return v == null ? "" : v.ToString(); } catch (Exception) { return ""; }
        }

        static string Quote(string s) { return (s ?? "").Replace("'", "''"); }

        /// <summary>Dossiers de courrier de la boîte qui contient le message : son dossier, la réception, les envoyés, puis tous les autres
        /// (sous-dossiers, archives de la boîte, éléments supprimés), sans le courrier indésirable. Plafonné pour rester rapide.</summary>
        static List<object> MailFolders(dynamic session, object mailObj, out string scope)
        {
            var list = new List<object>(); var seen = new HashSet<string>();
            dynamic store = null, parent = null;
            try { parent = ((dynamic)mailObj).Parent; } catch (Exception) { }
            try { store = parent != null ? parent.Store : session.DefaultStore; } catch (Exception) { }
            if (store == null) { try { store = session.DefaultStore; } catch (Exception) { } }
            string junk = "";
            try { junk = Str(() => store.GetDefaultFolder(OlFolderJunk).EntryID); } catch (Exception) { }
            Action<object> add = f =>
            {
                if (f == null || list.Count >= MaxFolders) return;
                string id = Str(() => ((dynamic)f).EntryID);
                if (id.Length == 0 || id == junk || !seen.Add(id)) return;
                list.Add(f);
            };
            add(parent);
            try { add(store.GetDefaultFolder(OlFolderInbox)); } catch (Exception) { }
            try { add(store.GetDefaultFolder(OlFolderSentMail)); } catch (Exception) { }
            bool capped = false;
            try
            {
                var stack = new Stack<object>(); stack.Push(store.GetRootFolder());
                while (stack.Count > 0)
                {
                    dynamic f = stack.Pop();
                    int kind = -1; try { kind = (int)f.DefaultItemType; } catch (Exception) { }
                    if (kind == 0) { if (list.Count >= MaxFolders) { capped = true; break; } add(f); }
                    try { foreach (object sub in f.Folders) stack.Push(sub); } catch (Exception) { }
                }
            }
            catch (Exception) { }
            string storeName = Str(() => store.DisplayName);
            scope = capped ? L.F("les {0} premiers dossiers de « {1} »", list.Count, storeName)
                           : L.F("les {0} dossiers de « {1} »", list.Count, storeName);
            return list;
        }

        static string FolderName(object f) { return Str(() => ((dynamic)f).Name); }

        public static void Explore(object app, object mailObj, EmailData e, DeepReport rep)
        {
            dynamic session;
            try { session = ((dynamic)app).Session; } catch (Exception) { rep.Unchecked.Add(L.T("Historique : boîte aux lettres inaccessible")); return; }
            string scope;
            var folders = MailFolders(session, mailObj, out scope);
            if (folders.Count == 0) { rep.Unchecked.Add(L.T("Historique : boîte aux lettres inaccessible")); return; }
            var clock = System.Diagnostics.Stopwatch.StartNew();
            string addr = (e.FromAddress ?? "").Trim();
            string entryId = Str(() => ((dynamic)mailObj).EntryID);
            string ownFolder = Str(() => ((dynamic)mailObj).Parent.EntryID);
            rep.Unchecked.Add(L.F("Historique : recherche dans {0}, hors courrier indésirable ; les autres comptes et les archives .pst ne sont pas consultés", scope));

            // ---- Messages déjà reçus de cette adresse (recherche d'Outlook dans chaque dossier, sans lire les messages) ----
            if (addr.Contains("@"))
            {
                var raw = new List<string> { addr };
                string own = Str(() => ((dynamic)mailObj).SenderEmailAddress).Trim();
                if (own.Length > 0 && !own.Equals(addr, StringComparison.OrdinalIgnoreCase)) raw.Add(own);   // expéditeur Exchange (adresse X500)
                string filter = string.Join(" OR ", raw.Select(a => "[SenderEmailAddress] = '" + Quote(a) + "'").ToArray());
                int count = 0, searched = 0; DateTime? first = null; string where = null; bool timedOut = false;
                foreach (dynamic f in folders)
                {
                    if (clock.ElapsedMilliseconds > BudgetMs) { timedOut = true; break; }
                    try
                    {
                        dynamic items = f.Items.Restrict(filter);
                        searched++;
                        int total = items.Count;
                        bool mine = Str(() => f.EntryID) == ownFolder;
                        int others = mine ? Math.Max(0, total - 1) : total;
                        if (others == 0) continue;
                        count += others;
                        if (where == null) where = FolderName(f);
                        items.Sort("[ReceivedTime]", false);
                        for (int i = 1; i <= total && i <= 2; i++)
                        {
                            dynamic it = items.Item(i);
                            if (Str(() => it.EntryID) == entryId) continue;
                            try { DateTime d = (DateTime)it.ReceivedTime; if (first == null || d < first.Value) first = d; } catch (Exception) { }
                            break;
                        }
                    }
                    catch (Exception) { }
                }
                if (count == 0)
                    rep.Facts.Add(new DeepFact("history", timedOut ? "info" : "warn", timedOut
                        ? L.F("Aucun autre message de {0} trouvé dans les {1} dossiers explorés (recherche arrêtée au bout de quelques secondes)", addr, searched)
                        : L.F("Aucun autre message de {0} dans {1} (hors courrier indésirable)", addr, scope)));
                else
                    rep.Facts.Add(new DeepFact("history", "ok", L.F("{0} autre(s) message(s) reçu(s) de cette adresse{1}, par exemple dans « {2} »", count,
                        first.HasValue ? " " + L.F("depuis le {0}", first.Value.ToString("dd/MM/yyyy")) : "", where)));
            }

            // ---- Même nom affiché, autre adresse : usurpation d'un correspondant connu ----
            string name = (e.FromName ?? "").Trim();
            if (name.Length >= 4 && !name.Contains("@"))
            {
                var others = new List<string>();
                foreach (dynamic f in folders)
                {
                    if (others.Count >= 4 || clock.ElapsedMilliseconds > BudgetMs * 2) break;
                    try
                    {
                        dynamic items = f.Items.Restrict("[SenderName] = '" + Quote(name) + "'");
                        int total = items.Count;
                        for (int i = 1; i <= total && i <= 20 && others.Count < 4; i++)
                        {
                            dynamic it = items.Item(i);
                            string a = Str(() => it.SenderEmailAddress);
                            if (Str(() => it.SenderEmailType) == "EX") { try { a = Str(() => it.Sender.GetExchangeUser().PrimarySmtpAddress); } catch (Exception) { } }
                            a = a.Trim().ToLowerInvariant();
                            if (a.Contains("@") && !a.Equals(addr, StringComparison.OrdinalIgnoreCase) && !others.Contains(a)) others.Add(a);
                        }
                    }
                    catch (Exception) { }
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

            // ---- La conversation citée existe-t-elle ? (réponse fabriquée) ----
            string inReply = "";
            foreach (var line in (e.RawHeaders ?? "").Split('\n'))
                if (line.StartsWith("In-Reply-To:", StringComparison.OrdinalIgnoreCase)) { inReply = line.Substring(12).Trim(); break; }
            if (inReply.StartsWith("<") && inReply.Contains(">"))
            {
                inReply = inReply.Substring(0, inReply.IndexOf('>') + 1);
                bool found = false, complete = true;
                foreach (dynamic f in folders)
                {
                    if (found) break;
                    if (clock.ElapsedMilliseconds > BudgetMs * 3) { complete = false; break; }
                    try
                    {
                        dynamic items = f.Items.Restrict("@SQL=\"" + PR_INTERNET_MESSAGE_ID + "\" = '" + Quote(inReply) + "'");
                        if (items.Count > 0) found = true;
                    }
                    catch (Exception) { }
                }
                if (found) rep.Facts.Add(new DeepFact("history", "ok", L.T("Le message auquel il répond se trouve bien dans votre boîte")));
                else if (!complete) rep.Unchecked.Add(L.T("Conversation citée : recherche arrêtée au bout de quelques secondes"));
                else
                {
                    rep.Facts.Add(new DeepFact("history", "warn", L.F("Le message auquel il prétend répondre est introuvable dans {0}", scope)));
                    rep.Findings.Add(new Finding("deep-history-thread", "sender", Severity.Low, L.T("La conversation citée est introuvable dans votre boîte"),
                        L.T("Les escrocs fabriquent de fausses réponses (« RE: ») pour paraître légitimes. Si vous n’avez jamais écrit à ce sujet, méfiance."), null));
                }
            }
        }
    }
}
