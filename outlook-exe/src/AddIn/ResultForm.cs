// PhishGuard - fenêtre d'analyse, en deux modes :
// - simple (par défaut) : verdict en clair, les raisons principales et « Que dois-je faire ? » ;
// - expert : onglets d'enquête (Résumé, En-têtes, Parcours, URL, Pièces jointes, Source, Réputation).
//
// Sécurité de l'affichage (le rapport est une page HTML locale affichée par le moteur d'Internet Explorer) :
// - tout texte venant du message est encodé (H) avant affichage : aucun code du message ne peut s'exécuter ;
// - le HTML du message n'est jamais affiché, seulement son texte brut ;
// - aucune ressource externe (image, police, script) n'est chargée : la page est entièrement locale ;
// - la navigation est bloquée, sauf les liens vers les services de vérification connus (ouverts dans le
//   navigateur par défaut) ; l'ouverture de nouvelles fenêtres est refusée ;
// - le seul script est celui des onglets, écrit ici.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Text;
using System.Windows.Forms;

namespace PhishGuard.AddIn
{
    internal class ResultForm : Form, IThemed
    {
        readonly WebBrowser browser;
        readonly Button btnReport, btnClose, btnTrust, btnSettings, btnMode;
        readonly Label status;
        AnalysisResult result;
        EmailData email;

        public event EventHandler ReportRequested;
        public event EventHandler NotPhishingRequested;
        public event EventHandler SettingsRequested;
        /// <summary>false : mode simple imposé par une stratégie de l'entreprise (pas de bouton « Analyse détaillée »).</summary>
        public bool AllowExpert = true;
        /// <summary>L'utilisateur a changé de mode (Expert contient le nouveau mode).</summary>
        public event EventHandler ModeChanged;

        /// <summary>true : analyse détaillée (onglets) ; false : mode simple.</summary>
        public bool Expert;
        string lastListStatus = "";
        bool lastShowExplanations = true;
        public AnalysisResult CurrentResult { get { return result; } }

        static readonly Color Accent = Color.FromArgb(15, 108, 189);
        static readonly Color Line = Color.FromArgb(227, 231, 237);

        public ResultForm(Icon icon)
        {
            Size = new Size(900, 840);
            MinimumSize = new Size(520, 440);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Segoe UI", 9f);
            ShowInTaskbar = true;
            BackColor = Color.White;
            if (icon != null) Icon = icon;

            browser = new WebBrowser
            {
                Dock = DockStyle.Fill,
                AllowWebBrowserDrop = false,
                IsWebBrowserContextMenuEnabled = true,   // copier/coller du texte
                WebBrowserShortcutsEnabled = true,
                ScriptErrorsSuppressed = true,
                AllowNavigation = true
            };
            browser.Navigating += OnNavigating;
            browser.NewWindow += (s, e) => e.Cancel = true;

            var bar = new FlowLayoutPanel
            {
                Dock = DockStyle.Bottom,
                Height = 54,
                Padding = new Padding(12, 11, 12, 8),
                FlowDirection = FlowDirection.LeftToRight,
                BackColor = Color.White,
                WrapContents = false
            };
            bar.Paint += (s, e) => { using (var p = new Pen(ThemeUi.Border(Line))) e.Graphics.DrawLine(p, 0, 0, bar.Width, 0); };

            btnReport = MakeButton(true);
            btnTrust = MakeButton(false);
            btnSettings = MakeButton(false);
            btnMode = MakeButton(false);
            btnClose = MakeButton(false);
            bar.Controls.AddRange(new Control[] { btnReport, btnTrust, btnMode, btnSettings, btnClose });

            status = new Label
            {
                Dock = DockStyle.Bottom,
                Height = 22,
                ForeColor = Color.FromArgb(95, 107, 122),
                BackColor = Color.White,
                TextAlign = ContentAlignment.MiddleLeft,
                Padding = new Padding(14, 0, 0, 0)
            };

            Controls.Add(browser);
            Controls.Add(status);
            Controls.Add(bar);
            ApplyTexts();
            ThemeUi.Attach(this);

            btnClose.Click += (s, e) => Hide();
            btnReport.Click += (s, e) => Raise(ReportRequested);
            btnTrust.Click += (s, e) => Raise(NotPhishingRequested);
            btnSettings.Click += (s, e) => Raise(SettingsRequested);
            btnMode.Click += (s, e) =>
            {
                Expert = !Expert;
                Raise(ModeChanged);
                if (result != null) ShowResult(result, email, lastListStatus, lastShowExplanations, false);
            };
            FormClosing += (s, e) => { if (e.CloseReason == CloseReason.UserClosing) { e.Cancel = true; Hide(); } };
        }

        /// <summary>Le thème de Windows a changé : la page est reconstruite avec les nouvelles couleurs.</summary>
        public void ThemeChanged()
        {
            if (result != null && Visible) ShowResult(result, email, lastListStatus, lastShowExplanations, false);
        }

        void Raise(EventHandler h)
        {
            if (h != null) h(this, EventArgs.Empty);
        }

        /// <summary>Textes de la fenêtre (rappelé à chaque affichage : la langue a pu changer).</summary>
        void ApplyTexts()
        {
            Text = L.T("PhishGuard - Analyse du message");
            btnReport.Text = L.T("Signaler à la sécurité");
            btnTrust.Text = L.T("Ce n’est pas du phishing");
            btnSettings.Text = L.T("Paramètres");
            btnClose.Text = L.T("Fermer");
            btnMode.Text = Expert ? L.T("Mode simple") : L.T("Analyse détaillée");
            btnMode.Visible = AllowExpert;
        }

        void CopyText(string text, string ok)
        {
            if (string.IsNullOrEmpty(text)) { status.Text = L.T("Rien à copier."); return; }
            try { Clipboard.SetText(text); status.Text = ok; }
            catch (Exception ex) { status.Text = L.T("Copie impossible : ") + ex.Message; }
        }

        /// <summary>Seuls les liens vers les services de vérification s'ouvrent (dans le navigateur par défaut).</summary>
        void OnNavigating(object sender, WebBrowserNavigatingEventArgs e)
        {
            string url = e.Url.ToString();
            if (url.StartsWith("about:")) return;
            e.Cancel = true;
            Uri u = e.Url;
            if ((u.Scheme == "https") && Forensics.LookupHosts.Contains(PhishGuard.Domains.HostOf(u)))
            {
                try { Process.Start(new ProcessStartInfo(u.AbsoluteUri) { UseShellExecute = true }); status.Text = L.T("Ouvert dans le navigateur : ") + PhishGuard.Domains.HostOf(u); }
                catch (Exception ex) { status.Text = L.T("Impossible d’ouvrir le navigateur : ") + ex.Message; }
            }
        }

        static Button MakeButton(bool primary)
        {
            var b = new Button
            {
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                MinimumSize = new Size(0, 32),
                Margin = new Padding(0, 0, 8, 0),
                Padding = new Padding(10, 0, 10, 0),
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                BackColor = primary ? Accent : Color.White,
                ForeColor = primary ? Color.White : Color.FromArgb(23, 32, 43)
            };
            b.FlatAppearance.BorderColor = primary ? Accent : Color.FromArgb(200, 207, 216);
            b.FlatAppearance.MouseOverBackColor = primary ? Color.FromArgb(17, 94, 163) : Color.FromArgb(243, 245, 248);
            b.FlatAppearance.MouseDownBackColor = primary ? Color.FromArgb(12, 74, 128) : Color.FromArgb(230, 234, 239);
            if (primary) b.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
            return b;
        }

        string shownSignature = "";

        /// <summary>Empreinte du résultat affiché : évite de recharger la page si rien n'a changé.</summary>
        static string Signature(AnalysisResult r)
        {
            return r.Score + "|" + string.Join(",", r.Findings.Select(f => f.Id + ":" + f.Severity + ":" + f.Evidence.Count).ToArray()) + "|" + r.Positives.Count + "|" + r.Trust.Count + "|" + r.Verified;
        }

        /// <summary>Mise à jour silencieuse (résultats externes arrivés) : sans prendre le focus.</summary>
        public void RefreshResult(AnalysisResult r, EmailData e, string listStatus, bool showExplanations)
        {
            if (!Visible || Signature(r) + "|" + Expert + "|" + Theme.Dark == shownSignature) return;
            ShowResult(r, e, listStatus, showExplanations, false);
        }

        public void ShowResult(AnalysisResult r, EmailData e, string listStatus, bool showExplanations)
        {
            ShowResult(r, e, listStatus, showExplanations, true);
        }

        void ShowResult(AnalysisResult r, EmailData e, string listStatus, bool showExplanations, bool activate)
        {
            result = r; email = e;
            lastListStatus = listStatus; lastShowExplanations = showExplanations;
            shownSignature = Signature(r) + "|" + Expert + "|" + Theme.Dark;
            ApplyTexts();
            btnTrust.Visible = r.Level != "safe";
            status.Text = Expert ? listStatus : "";
            browser.DocumentText = Expert ? BuildHtml(r, e, showExplanations) : SimpleView.Build(r, e, showExplanations);
            if (!activate) return;
            if (!Visible) Show();
            if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
            Activate();
        }

        public void SetStatus(string text) { status.Text = text; }

        // =================================================================
        // HTML
        // =================================================================

        /// <summary>Encodage HTML (y compris les apostrophes : sûr aussi dans les attributs).</summary>
        static string H(string s) { return WebUtility.HtmlEncode(s ?? ""); }

        static string DateFormat { get { return L.English ? "yyyy-MM-dd HH:mm:ss" : "dd/MM/yyyy HH:mm:ss"; } }

        static string Links(List<KeyValuePair<string, string>> links)
        {
            return "<span class='lks'>" + string.Join("", links.Select(l => "<a class='lk' href='" + H(l.Value) + "'>" + H(l.Key) + "</a>").ToArray()) + "</span>";
        }

        static string Badge(string value)
        {
            string v = (value ?? "").ToLowerInvariant();
            string cls = v == "pass" ? "ok" : (v == "fail" || v == "softfail" || v == "permerror" || v == "temperror") ? "bad" : v.Length == 0 ? "na" : "mid";
            return "<span class='b " + cls + "'>" + H(v.Length == 0 ? L.T("absent") : v) + "</span>";
        }

        static string AuthChip(string name, string value)
        {
            string v = (value ?? "").ToLowerInvariant();
            string cls = v == "pass" ? "ok" : (v == "fail" || v == "softfail" || v == "permerror" || v == "temperror") ? "bad" : v.Length == 0 ? "na" : "mid";
            string mark = cls == "ok" ? "\u2713" : cls == "bad" ? "\u2717" : "?";
            string meaning = cls == "ok" ? L.T("vérification réussie") : cls == "bad" ? L.T("vérification en échec") : L.T("pas de résultat");
            string tip = name + " : " + (v.Length == 0 ? L.T("absent") : v) + " (" + meaning + ")";
            return "<span class='ac " + cls + "' title='" + H(tip) + "'>" + H(name + " " + mark) + "</span>";
        }

        static string Row(string label, string valueHtml)
        {
            return "<tr><th>" + H(label) + "</th><td>" + valueHtml + "</td></tr>";
        }

        static string Empty(string text)
        {
            return "<div class='empty'>" + H(text) + "</div>";
        }

        static string FormatSize(long n)
        {
            if (n < 0) return "";
            if (n < 1024) return n + " " + L.T("o");
            if (n < 1024 * 1024) return (n / 1024.0).ToString("0.#") + " " + L.T("Ko");
            return (n / 1024.0 / 1024.0).ToString("0.#") + " " + L.T("Mo");
        }

        const string Css =
            "*{box-sizing:border-box}" +
            "body{font:13px/1.5 'Segoe UI',Arial,sans-serif;color:#17202b;background:#f3f5f8;margin:0}" +
            ".tabs{position:fixed;top:0;left:0;right:0;background:#fff;border-bottom:1px solid #e3e7ed;padding:0 12px;z-index:5;white-space:nowrap;overflow:hidden}" +
            ".tab{display:inline-block;padding:11px 12px 9px;color:#5f6b7a;text-decoration:none;font-weight:600;border-bottom:2px solid transparent;margin-right:2px}" +
            ".tab:hover{color:#17202b}.tab.on{color:#0f6cbd;border-bottom-color:#0f6cbd}" +
            ".tab .n{display:inline-block;min-width:18px;padding:0 5px;margin-left:5px;border-radius:9px;background:#eef1f5;color:#5f6b7a;font-size:11px;text-align:center;font-weight:600}" +
            ".tab.on .n{background:#e3effa;color:#0f6cbd}" +
            ".page{padding:60px 18px 18px;max-width:1000px;margin:0 auto}" +
            ".hero{background:#fff;border:1px solid #e3e7ed;border-radius:12px;padding:12px 16px;overflow:hidden;position:relative}" +
            ".hero:before{content:'';position:absolute;left:0;top:0;bottom:0;width:6px}" +
            ".hero.dangerous{background:#fff7f7}.hero.dangerous:before{background:#c4262e}" +
            ".hero.suspicious{background:#fffaf2}.hero.suspicious:before{background:#c26a00}" +
            ".hero.safe{background:#f6fbf8}.hero.safe:before{background:#13804a}" +
            ".gauge{float:left;width:72px;height:72px;margin-right:16px;position:relative}" +
            ".gauge .num{position:absolute;left:0;right:0;top:18px;text-align:center;font-size:22px;font-weight:700;line-height:24px}" +
            ".gauge .of{position:absolute;left:0;right:0;top:42px;text-align:center;font-size:10px;color:#5f6b7a}" +
            ".dangerous .num,.dangerous h1{color:#c4262e}.suspicious .num,.suspicious h1{color:#a85b00}.safe .num,.safe h1{color:#13804a}" +
            ".eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#5f6b7a;margin:6px 0 2px;font-weight:600}" +
            "h1{font-size:19px;margin:0;line-height:1.25}.advice{margin:3px 0 0;color:#2b3542;font-size:13px}" +
            ".counts{margin-top:6px}.cnt{display:inline-block;margin:0 6px 4px 0;padding:2px 9px;border-radius:12px;font-size:12px;font-weight:600;background:#fff;border:1px solid #e3e7ed}" +
            ".cnt i{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:0}" +
            ".card{background:#fff;border:1px solid #e3e7ed;border-radius:12px;padding:14px 16px;margin-top:12px}" +
            ".msg{padding:10px 14px}.msg .row{margin:2px 0;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}.msg .k{display:inline-block;width:118px;color:#5f6b7a;font-size:12px}" +
            ".meta{color:#5f6b7a;font-size:12px}.hv{overflow:hidden}" +
            ".ac{display:inline-block;margin:0 4px 0 0;border-radius:5px;font-size:12px;font-weight:600;padding:1px 7px;line-height:18px;cursor:help}" +
            ".ac.ok{background:#e7f5ee;color:#13804a}.ac.bad{background:#fdeced;color:#c4262e}.ac.mid{background:#fff3e0;color:#a85b00}.ac.na{background:#eef1f5;color:#5f6b7a}" +
            "h2{font-size:11.5px;text-transform:uppercase;letter-spacing:.07em;color:#5f6b7a;margin:14px 0 6px;font-weight:700}" +
            "h2 .c{display:inline-block;margin-left:6px;padding:0 6px;border-radius:9px;background:#e7ebf0;color:#5f6b7a;font-size:11px;letter-spacing:0}" +
            ".f{background:#fff;border:1px solid #e3e7ed;border-left:4px solid #8a95a3;border-radius:8px;padding:7px 12px;margin-bottom:6px}" +
            ".why{display:inline-block;width:16px;height:16px;margin-left:6px;border-radius:50%;background:#e3effa;color:#0f6cbd;font-size:11px;font-weight:700;text-align:center;line-height:16px;cursor:help;vertical-align:1px}" +
            ".f.Critical{border-left-color:#a1141c}.f.High{border-left-color:#d13438}.f.Medium{border-left-color:#d47b00}.f.Low{border-left-color:#8a95a3}" +
            ".pill{display:inline-block;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 7px;border-radius:10px;color:#fff;background:#8a95a3;margin-right:8px;vertical-align:1px}" +
            ".pill.Critical{background:#a1141c}.pill.High{background:#d13438}.pill.Medium{background:#d47b00}.pill.Low{background:#8a95a3}" +
            ".dot.Critical{background:#a1141c}.dot.High{background:#d13438}.dot.Medium{background:#d47b00}.dot.Low{background:#8a95a3}" +
            ".ft{font-weight:600;font-size:13px}.fd{color:#4a5563;margin:2px 0 0;font-size:12.5px}" +
            ".evs{margin-top:3px}.ev{display:inline-block;max-width:100%;background:#f3f5f8;border:1px solid #e9edf2;border-radius:6px;padding:1px 7px;margin:0 6px 4px 0;font:12px Consolas,'Courier New',monospace;word-wrap:break-word;word-break:break-all}" +
            ".lesson{margin:8px 0 2px;padding:8px 10px 8px 34px;background:#eef5fc;border-radius:8px;color:#1b3a57;font-size:12.5px;position:relative}" +
            ".lesson .q{position:absolute;left:10px;top:8px;width:16px;height:16px;border-radius:50%;background:#0f6cbd;color:#fff;font-size:11px;font-weight:700;text-align:center;line-height:16px}" +
            ".lesson b{font-weight:600}" +
            ".list{margin:0;padding:0;list-style:none}.list li{padding:5px 0 5px 24px;position:relative;border-top:1px solid #f0f2f5}.list li:first-child{border-top:0}" +
            ".list li .ic{position:absolute;left:0;top:5px;width:16px;height:16px;border-radius:50%;font-size:10px;font-weight:700;text-align:center;line-height:16px}" +
            ".ic.okc{background:#e7f5ee;color:#13804a}.ic.inf{background:#eef1f5;color:#5f6b7a}" +
            ".empty{background:#fff;border:1px dashed #d3d9e1;border-radius:12px;padding:22px;text-align:center;color:#5f6b7a;margin-top:12px}" +
            ".muted{color:#5f6b7a}.mono{font-family:Consolas,'Courier New',monospace;font-size:12px;word-wrap:break-word;word-break:break-all}" +
            ".tw{background:#fff;border:1px solid #e3e7ed;border-radius:12px;overflow:hidden;margin-top:4px}" +
            "table{border-collapse:collapse;width:100%}" +
            "th,td{text-align:left;vertical-align:top;padding:8px 12px;border-top:1px solid #eef1f5}tr:first-child th,tr:first-child td{border-top:0}" +
            "th{color:#5f6b7a;font-weight:600;white-space:nowrap;width:1%}" +
            "thead th{background:#f7f9fb;width:auto;font-size:11px;text-transform:uppercase;letter-spacing:.05em}" +
            "tbody tr:hover td{background:#fafbfc}" +
            ".b{display:inline-block;padding:1px 8px;border-radius:9px;font-weight:600;font-size:12px}" +
            ".b.ok{background:#e7f5ee;color:#13804a}.b.bad{background:#fdeced;color:#c4262e}.b.mid{background:#fff3e0;color:#a85b00}.b.na{background:#eef1f5;color:#5f6b7a}" +
            ".lks a.lk{display:inline-block;margin:0 4px 2px 0;padding:1px 8px;border:1px solid #cfe0f1;border-radius:10px;color:#0f6cbd;text-decoration:none;font-size:11.5px;white-space:nowrap;background:#f5f9fd}" +
            ".lks a.lk:hover{background:#e3effa}" +
            "pre{background:#fff;border:1px solid #e3e7ed;border-radius:12px;padding:12px 14px;font:12px/1.45 Consolas,'Courier New',monospace;white-space:pre-wrap;word-wrap:break-word;margin:4px 0 0}" +
            ".note{font-size:12px;color:#5f6b7a;margin:8px 2px}" +
            ".tl{position:relative;margin:4px 0 0 8px;padding-left:22px;border-left:2px solid #dbe2ea}" +
            ".hop{position:relative;background:#fff;border:1px solid #e3e7ed;border-radius:10px;padding:9px 12px;margin-bottom:10px}" +
            ".hop .nd{position:absolute;left:-32px;top:10px;width:18px;height:18px;border-radius:50%;background:#fff;border:2px solid #0f6cbd;color:#0f6cbd;font-size:10px;font-weight:700;text-align:center;line-height:14px}" +
            ".hop .route{font-weight:600}.hop .arrow{color:#8a95a3;margin:0 6px}.hop .hm{color:#5f6b7a;font-size:12px;margin-top:3px}" +
            ".hop .hm span{margin-right:12px;display:inline-block}.slow{color:#c4262e;font-weight:700}" +
            ".origin{border-left:4px solid #0f6cbd}" +
            ".att{background:#fff;border:1px solid #e3e7ed;border-radius:12px;margin-top:12px;overflow:hidden}" +
            ".att .ah{padding:10px 14px;border-bottom:1px solid #eef1f5;background:#f7f9fb}.att .an{font-weight:600;font-size:14px;word-wrap:break-word}" +
            ".vb{display:inline-block;margin:6px 0 0;padding:2px 10px 2px 6px;border-radius:12px;background:#13804a;color:#fff;font-size:12px;font-weight:700}" +
            ".vb i{display:inline-block;width:16px;height:16px;margin-right:5px;border-radius:50%;background:#fff;color:#13804a;font-style:normal;text-align:center;line-height:16px;font-size:11px}" +
            ".trust{padding:8px 14px}.trust .list li{padding:3px 0 3px 24px}.trust .list li .ic{top:3px}" +
            ".foot{font-size:11px;text-align:center;color:#8a95a3;margin:22px 0 4px}";

        const string Script =
            "function show(id){var p=document.getElementsByClassName('sec');for(var i=0;i<p.length;i++){p[i].style.display=(p[i].id==id)?'block':'none';}" +
            "var t=document.getElementsByClassName('tab');for(var j=0;j<t.length;j++){t[j].className=(t[j].getAttribute('data-t')==id)?'tab on':'tab';}" +
            "window.scrollTo(0,0);return false;}" +
            "window.onload=function(){show('s-resume');};";

        /// <summary>Jauge circulaire du score (SVG, sans ressource externe).</summary>
        static string Gauge(int score, string level)
        {
            const double r = 40;
            double c = 2 * Math.PI * r;
            double len = c * Math.Max(0, Math.Min(100, score)) / 100.0;
            string color = level == "dangerous" ? "#c4262e" : level == "suspicious" ? "#d47b00" : "#13804a";
            var ci = System.Globalization.CultureInfo.InvariantCulture;
            return "<div class='gauge'><svg width='72' height='72' viewBox='0 0 96 96'>"
                + "<circle cx='48' cy='48' r='40' fill='" + Theme.Hex("#fff", Theme.Kind.Back) + "' stroke='" + Theme.Hex("#e7ebf0", Theme.Kind.Border) + "' stroke-width='8'/>"
                + "<circle cx='48' cy='48' r='40' fill='none' stroke='" + color + "' stroke-width='8' stroke-linecap='round' "
                + "stroke-dasharray='" + len.ToString("0.##", ci) + " " + c.ToString("0.##", ci) + "' transform='rotate(-90 48 48)'/>"
                + "</svg><div class='num'>" + score + "</div><div class='of'>/ 100</div></div>";
        }

        internal static string BuildHtml(AnalysisResult r, EmailData e, bool showExplanations)
        {
            var d = r.Details ?? new HeaderDetails();
            var sb = new StringBuilder();
            sb.Append("<!DOCTYPE html><html><head><meta charset='utf-8'><meta http-equiv='X-UA-Compatible' content='IE=edge'>");
            sb.Append("<style>" + Theme.Css(Css) + "</style><script>" + Script + "</script></head><body>");

            int nUrls = r.Urls.Count, nAtt = r.Attachments.Count, nHops = d.Hops.Count;
            var allVisible = r.Findings.Where(f => f.Severity != Severity.Info).ToList();
            var visible = allVisible.Where(f => !Analyzer.IsBetaFinding(f)).ToList();
            var beta = allVisible.Where(f => Analyzer.IsBetaFinding(f)).ToList();
            sb.Append("<div class='tabs'>");
            Tab(sb, "s-resume", L.T("Résumé"), visible.Count);
            Tab(sb, "s-headers", L.T("En-têtes"), -1);
            Tab(sb, "s-hops", L.T("Parcours"), nHops);
            Tab(sb, "s-urls", L.T("URL"), nUrls);
            Tab(sb, "s-att", L.T("Pièces jointes"), nAtt);
            Tab(sb, "s-raw", L.T("Source"), -1);
            Tab(sb, "s-beta", L.T("Réputation"), beta.Count);
            sb.Append("</div><div class='page'>");

            // ---------------- Résumé ----------------
            sb.Append("<div class='sec' id='s-resume'>");
            sb.Append("<div class='hero " + H(r.Level) + "'>" + Gauge(r.Score, r.Level));
            sb.Append("<div class='hv'><p class='eyebrow'>" + H(L.T("Risque de phishing")) + "</p><h1>" + H(r.Verified ? L.T("Expéditeur vérifié") : r.LevelLabel) + "</h1><p class='advice'>"
                + H(r.Verified ? L.T("Authentifié et déjà en relation avec vous. Restez attentif à toute demande inhabituelle (changement de RIB, paiement urgent).") : r.Advice) + "</p>");
            if (r.Verified)
            {
                // Rappelle que le contenu a bien été analysé : la vérification ne remplace pas l'analyse
                int nL = r.Urls.Count, nA = r.Attachments.Count;
                string scanned = L.F("Contenu analysé : texte, {0}, {1} — aucun indice",
                    nL == 1 ? L.T("1 lien") : L.F("{0} liens", nL), nA == 1 ? L.T("1 pièce jointe") : L.F("{0} pièces jointes", nA));
                sb.Append("<span class='vb'><i>&#10003;</i>" + H(L.T("Expéditeur authentifié et connu")) + "</span> ");
                sb.Append("<span class='vb' title='" + H(L.T("Liens, pièces jointes, texte et en-têtes ont été contrôlés comme pour tout autre message.")) + "'><i>&#10003;</i>" + H(scanned) + "</span>");
            }
            if (allVisible.Count > 0)
            {
                sb.Append("<div class='counts'>");
                foreach (var sev in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low })
                {
                    int n = allVisible.Count(f => f.Severity == sev);
                    if (n > 0) sb.Append("<span class='cnt'><i class='dot " + sev + "'></i>" + H(Analyzer.SeverityLabel(sev)) + " <b>" + n + "</b></span>");
                }
                sb.Append("</div>");
            }
            sb.Append("</div></div>");

            // Carte du message : l'essentiel sur quatre lignes
            sb.Append("<div class='card msg'>");
            sb.Append("<div class='row'><span class='k'>" + H(L.T("De")) + "</span><b>" + H(string.IsNullOrEmpty(e.FromName) ? L.T("(sans nom)") : e.FromName)
                + "</b> <span class='mono muted'>&lt;" + H(e.FromAddress) + "&gt;</span></div>");
            sb.Append("<div class='row'><span class='k'>" + H(L.T("Objet")) + "</span>" + H(string.IsNullOrEmpty(e.Subject) ? L.T("(sans objet)") : e.Subject) + "</div>");
            if (d.All.Count > 0)
                sb.Append("<div class='row'><span class='k'>" + H(L.T("Authentification")) + "</span>" + AuthChip("SPF", d.Auth.Spf) + AuthChip("DKIM", d.Auth.Dkim) + AuthChip("DMARC", d.Auth.Dmarc)
                    + (string.IsNullOrEmpty(d.Auth.CompAuth) ? "" : AuthChip("Microsoft", d.Auth.CompAuth)) + "</div>");
            var meta = new List<string>();
            if (d.OriginIp.Length > 0) meta.Add(H(L.T("IP d’origine")) + " <span class='mono'>" + H(d.OriginIp) + "</span>" + (d.Country.Length > 0 ? " (" + H(d.Country) + ")" : ""));
            if (nHops > 0) meta.Add(H(nHops == 1 ? L.T("1 serveur traversé") : L.F("{0} serveurs traversés", nHops)));
            if (nUrls > 0) meta.Add(H(nUrls == 1 ? L.T("1 lien") : L.F("{0} liens", nUrls)));
            if (nAtt > 0) meta.Add(H(nAtt == 1 ? L.T("1 pièce jointe") : L.F("{0} pièces jointes", nAtt)));
            if (meta.Count > 0) sb.Append("<div class='row meta'><span class='k'>" + H(L.T("Détails")) + "</span>" + string.Join(" &middot; ", meta.ToArray()) + "</div>");
            sb.Append("</div>");

            // Preuves de légitimité : affichées ici seulement si aucun indice notable (elles ne compensent jamais un indice)
            if (r.Trust.Count > 0 && r.Level == "safe") TrustCard(sb, r);

            if (beta.Count > 0)
            {
                var worst = beta.Max(f => f.Severity);
                sb.Append("<div class='f " + worst + "'><div><span class='pill " + worst + "'>" + H(Analyzer.SeverityLabel(worst)) + "</span><span class='ft'>"
                    + H(beta.Count == 1 ? L.T("1 résultat des sources de réputation") : L.F("{0} résultats des sources de réputation", beta.Count)) + "</span></div>");
                sb.Append("<p class='fd'>" + H(string.Join(" · ", beta.Take(3).Select(f => f.Title).ToArray())) + "</p>");
                sb.Append("<p class='fd'><a href='#' onclick=\"return show('s-beta')\">" + H(L.T("Voir l’onglet Réputation")) + "</a></p></div>");
            }
            if (visible.Count == 0 && beta.Count == 0) sb.Append(Empty(L.T("Aucun indice suspect détecté.")));
            foreach (var cat in Analyzer.CategoryLabels.Keys)
            {
                var list = visible.Where(f => f.Category == cat).ToList();
                if (list.Count == 0) continue;
                sb.Append("<h2>" + H(Analyzer.CategoryLabel(cat)) + "<span class='c'>" + list.Count + "</span></h2>");
                foreach (var f in list) FindingCard(sb, f, showExplanations);
            }
            sb.Append("</div>");

            // ---------------- En-têtes ----------------
            sb.Append("<div class='sec' id='s-headers'>");
            if (r.Trust.Count > 0 && r.Level != "safe") TrustCard(sb, r);
            InfoList(sb, r.Findings.Where(f => f.Severity == Severity.Info && !Analyzer.IsBetaFinding(f)).ToList(), showExplanations);
            if (d.All.Count == 0)
                sb.Append(Empty(L.T("Aucun en-tête Internet : message interne, ou envoyé depuis cette boîte.")));
            else
            {
                sb.Append("<h2>" + H(L.T("Informations principales")) + "</h2><div class='tw'><table>");
                foreach (var kv in d.Fields) sb.Append(Row(kv.Key, "<span class='mono'>" + H(kv.Value) + "</span>"));
                sb.Append("</table></div>");

                // Domaines de l'expéditeur, de la réponse et du Return-Path, avec les liens de vérification
                var senderDomains = new List<string>();
                var senderAddrs = new List<string>();
                if (!string.IsNullOrEmpty(e.FromAddress)) senderAddrs.Add(e.FromAddress);
                senderAddrs.AddRange(e.ReplyTo);
                foreach (var kv in d.Fields.Where(f => f.Key == "Return-Path"))
                    foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(kv.Value, @"[^\s<>]+@[^\s<>]+")) senderAddrs.Add(m.Value);
                foreach (var ad in senderAddrs)
                {
                    string dd = PhishGuard.Domains.RegistrableDomain(PhishGuard.Domains.DomainOfAddress(ad.ToLowerInvariant()));
                    if (dd.Length > 0 && !senderDomains.Contains(dd)) senderDomains.Add(dd);
                }
                if (senderDomains.Count > 0)
                {
                    sb.Append("<h2>" + H(L.T("Vérifier les domaines de l’expéditeur")) + "</h2><div class='tw'><table>");
                    foreach (var dd in senderDomains) sb.Append("<tr><td class='mono'>" + H(PhishGuard.Domains.ToUnicode(dd)) + "</td><td style='text-align:right'>" + Links(Forensics.LookupsForDomain(dd)) + "</td></tr>");
                    sb.Append("</table></div>");
                }

                var a = d.Auth;
                sb.Append("<h2>" + H(L.T("Authentification")) + "</h2><div class='tw'><table>");
                sb.Append(Row("SPF", Badge(a.Spf) + (string.IsNullOrEmpty(a.SpfMailFrom) ? "" : " &nbsp;" + H(L.T("domaine d’envoi :")) + " <span class='mono'>" + H(a.SpfMailFrom) + "</span>")
                    + (string.IsNullOrEmpty(a.SpfIp) ? "" : " &nbsp;IP : <span class='mono'>" + H(a.SpfIp) + "</span>")));
                sb.Append(Row("DKIM", Badge(a.Dkim) + (string.IsNullOrEmpty(a.DkimDomain) ? "" : " &nbsp;" + H(L.T("domaine signataire :")) + " <span class='mono'>" + H(a.DkimDomain) + "</span>")
                    + (string.IsNullOrEmpty(a.DkimSelector) ? "" : " &nbsp;" + H(L.T("sélecteur :")) + " <span class='mono'>" + H(a.DkimSelector) + "</span>")));
                sb.Append(Row("DMARC", Badge(a.Dmarc) + (string.IsNullOrEmpty(a.DmarcFrom) ? "" : " &nbsp;" + H(L.T("domaine « De » :")) + " <span class='mono'>" + H(a.DmarcFrom) + "</span>")
                    + (string.IsNullOrEmpty(a.DmarcAction) ? "" : " &nbsp;" + H(L.T("action :")) + " " + H(a.DmarcAction))));
                if (!string.IsNullOrEmpty(a.CompAuth))
                    sb.Append(Row("Microsoft compauth", Badge(a.CompAuth) + (string.IsNullOrEmpty(a.CompAuthReason) ? "" : " &nbsp;" + H(L.T("raison")) + " " + H(a.CompAuthReason))));
                sb.Append(Row(L.T("Source des résultats"), H(string.IsNullOrEmpty(a.Source) ? L.T("aucun en-tête d’authentification") : a.Source)));
                sb.Append("</table></div>");

                if (d.FilterHeaders.Count > 0)
                {
                    sb.Append("<h2>" + H(L.T("Filtres de messagerie (passerelle, fournisseur, Exchange)")) + "</h2><div class='tw'><table>");
                    foreach (var kv in d.FilterHeaders) sb.Append(Row(kv.Key, "<span class='mono'>" + H(kv.Value) + "</span>"));
                    sb.Append("</table></div>");
                }
                if (d.Scl.Length > 0 || d.Bcl.Length > 0 || d.Country.Length > 0)
                {
                    sb.Append("<h2>" + H(L.T("Filtrage anti-spam")) + "</h2><div class='tw'><table>");
                    if (d.Scl.Length > 0) sb.Append(Row(L.T("SCL (indice de spam, -1 à 9)"), H(d.Scl)));
                    if (d.Bcl.Length > 0) sb.Append(Row(L.T("BCL (envoi en masse, 0 à 9)"), H(d.Bcl)));
                    if (d.Country.Length > 0) sb.Append(Row(L.T("Pays de l’IP d’envoi"), H(d.Country)));
                    sb.Append("</table></div>");
                }
            }
            sb.Append("</div>");

            // ---------------- Parcours ----------------
            sb.Append("<div class='sec' id='s-hops'>");
            if (d.OriginIp.Length > 0)
            {
                sb.Append("<div class='card origin'><span class='ft'>" + H(L.T("IP d’origine")) + " : </span><span class='mono'>" + H(d.OriginIp) + "</span>");
                if (d.OriginHost.Length > 0) sb.Append(" <span class='muted mono'>(" + H(d.OriginHost) + ")</span>");
                if (d.Country.Length > 0) sb.Append(" &nbsp;" + H(L.T("pays :")) + " " + H(d.Country));
                sb.Append("<div class='note'>" + H(L.T("Déterminée par :")) + " " + H(d.OriginSource) + "</div>");
                sb.Append("<div>" + Links(Forensics.LookupsForIp(d.OriginIp)) + "</div></div>");
            }
            if (nHops == 0) sb.Append(Empty(L.T("Aucun en-tête « Received ».")));
            else
            {
                sb.Append("<h2>" + H(L.T("Serveurs traversés (du premier au dernier)"))
                    + (d.TotalTransit.HasValue ? " &nbsp;<span class='c'>" + H(L.T("durée totale")) + " " + H(Forensics.FormatDelay(d.TotalTransit)) + "</span>" : "") + "</h2>");
                sb.Append("<div class='tl'>");
                foreach (var hop in d.Hops)
                {
                    sb.Append("<div class='hop'><span class='nd'>" + hop.Number + "</span>");
                    sb.Append("<div class='route'><span class='mono'>" + H(hop.FromHost.Length > 0 ? hop.FromHost : "?") + "</span><span class='arrow'>&rarr;</span><span class='mono'>"
                        + H(hop.ByHost.Length > 0 ? hop.ByHost : "?") + "</span></div>");
                    if (hop.FromDetail.Length > 0 && hop.FromDetail != hop.FromHost) sb.Append("<div class='hm mono'>" + H(hop.FromDetail) + "</div>");
                    sb.Append("<div class='hm'>");
                    if (hop.FromIp.Length > 0)
                        sb.Append("<span>IP <span class='mono'>" + H(hop.FromIp) + "</span>" + (Forensics.IsPublicIp(hop.FromIp) ? "" : " (" + H(L.T("privée")) + ")") + "</span>");
                    if (hop.With.Length > 0) sb.Append("<span>" + H(hop.With) + "</span>");
                    string date = hop.Date.HasValue ? hop.Date.Value.ToLocalTime().ToString(DateFormat) : hop.RawDate;
                    if (!string.IsNullOrEmpty(date)) sb.Append("<span>" + H(date) + "</span>");
                    string delay = Forensics.FormatDelay(hop.Delay);
                    bool slow = hop.Delay.HasValue && (hop.Delay.Value.TotalMinutes > 30 || hop.Delay.Value < TimeSpan.FromMinutes(-5));
                    if (!string.IsNullOrEmpty(delay)) sb.Append("<span" + (slow ? " class='slow'" : "") + ">+" + H(delay) + "</span>");
                    sb.Append("</div>");
                    if (hop.FromIp.Length > 0 && Forensics.IsPublicIp(hop.FromIp)) sb.Append("<div style='margin-top:4px'>" + Links(Forensics.LookupsForIp(hop.FromIp)) + "</div>");
                    sb.Append("</div>");
                }
                sb.Append("</div><p class='note'>" + H(L.T("Un délai négatif ou très long peut indiquer des en-têtes falsifiés ou un serveur mal réglé.")) + "</p>");
            }
            sb.Append("</div>");

            // ---------------- URL ----------------
            sb.Append("<div class='sec' id='s-urls'>");
            if (nUrls == 0) sb.Append(Empty(L.T("Aucun lien dans ce message.")));
            else
            {
                sb.Append("<p class='note'>" + H(L.T("Adresses « désarmées » (non cliquables). Les liens de vérification envoient uniquement l’adresse au service choisi.")) + "</p>");
                sb.Append("<div class='tw'><table><thead><tr><th>" + H(L.T("Domaine")) + "</th><th>URL</th><th>" + H(L.T("Vérifier")) + "</th></tr></thead><tbody>");
                foreach (var u in r.Urls)
                {
                    string host = "";
                    Uri parsed;
                    if (Uri.TryCreate(u, UriKind.Absolute, out parsed)) host = PhishGuard.Domains.ToUnicode(PhishGuard.Domains.HostOf(parsed));
                    sb.Append("<tr><td class='mono'><b>" + H(host) + "</b></td><td class='mono muted'>" + H(Analyzer.Defang(u)) + "</td><td>" + Links(Forensics.LookupsForUrl(u)) + "</td></tr>");
                }
                sb.Append("</tbody></table></div>");
                var linkDomains = r.LinkDomains.Where(x => !PhishGuard.Domains.IsIpHost(x)).Distinct().ToList();
                if (linkDomains.Count > 0)
                {
                    sb.Append("<h2>" + H(L.T("Vérifier les domaines des liens")) + "<span class='c'>" + linkDomains.Count + "</span></h2><div class='tw'><table>");
                    foreach (var dd in linkDomains) sb.Append("<tr><td class='mono'>" + H(PhishGuard.Domains.ToUnicode(dd)) + "</td><td style='text-align:right'>" + Links(Forensics.LookupsForDomain(dd)) + "</td></tr>");
                    sb.Append("</table></div>");
                }
            }
            sb.Append("</div>");

            // ---------------- Pièces jointes ----------------
            sb.Append("<div class='sec' id='s-att'>");
            if (nAtt == 0) sb.Append(Empty(L.T("Aucune pièce jointe.")));
            foreach (var att in r.Attachments)
            {
                sb.Append("<div class='att'><div class='ah'><div class='an'>" + H(att.Name) + "</div><div class='muted'>" + H(FormatSize(att.Size))
                    + (att.Magic.Length > 0 ? " &middot; " + H(Forensics.MagicLabel(att.Magic)) : "") + "</div></div><table>");
                if (att.ContentType.Length > 0) sb.Append(Row(L.T("Type déclaré"), "<span class='mono'>" + H(att.ContentType) + "</span>"));
                sb.Append(Row(L.T("Type réel"), H(att.Magic.Length > 0 ? Forensics.MagicLabel(att.Magic) : L.T("non reconnu"))));
                if (att.IsEmbeddedMessage) sb.Append(Row(L.T("Nature"), H(L.T("Message Outlook joint"))));
                if (att.Sha256.Length > 0)
                {
                    sb.Append(Row("MD5", "<span class='mono'>" + H(att.Md5) + "</span>"));
                    sb.Append(Row("SHA1", "<span class='mono'>" + H(att.Sha1) + "</span>"));
                    sb.Append(Row("SHA256", "<span class='mono'>" + H(att.Sha256) + "</span>"));
                    sb.Append(Row(L.T("Vérifier"), Links(Forensics.LookupsForHash(att.Sha256))));
                    var vt = Intel.Get("vtf:" + att.Sha256);
                    if (vt != null && vt.Ok)
                        sb.Append(Row("VirusTotal", !vt.Found ? H(L.T("inconnu : ce fichier n’a jamais été analysé par VirusTotal"))
                            : vt.Malicious > 0 ? "<span class='b bad'>" + H(L.F("{0} détection(s) sur {1}", vt.Malicious, vt.Total)) + "</span>"
                            : "<span class='b ok'>" + H(L.F("aucune détection sur {0} antivirus", vt.Total)) + "</span>"));
                    if (att.IsEmbeddedMessage)
                        sb.Append(Row("", "<span class='muted'>" + H(L.T("Message joint : son empreinte change à chaque enregistrement, VirusTotal ne le connaîtra pas.")) + "</span>"));
                }
                else sb.Append(Row(L.T("Empreintes"), "<span class='muted'>" + H(L.T("non calculées (fichier trop volumineux ou illisible)")) + "</span>"));
                if (att.ContentFindings.Count > 0)
                    sb.Append(Row(L.T("Contenu"), string.Join("<br>", att.ContentFindings.Select(cf => "<span class='pill " + cf.Severity + "'>" + H(Analyzer.SeverityLabel(cf.Severity)) + "</span>" + H(cf.Title)).ToArray())));
                if (att.QrCodes.Count > 0)
                    sb.Append(Row(L.T("QR code"), "<span class='mono'>" + string.Join("<br>", att.QrCodes.Select(x => H(Analyzer.Defang(x))).ToArray()) + "</span>"));
                if (att.ArchiveEntries.Count > 0)
                    sb.Append(Row(L.T("Fichiers de l’archive"), "<span class='mono'>" + string.Join("<br>", att.ArchiveEntries.Select(x => H(x)).ToArray()) + "</span>"));
                if (att.EmbeddedUrls.Count > 0)
                    sb.Append(Row(L.T("Liens dans le fichier"), "<span class='mono'>" + string.Join("<br>", att.EmbeddedUrls.Take(15).Select(x => H(Analyzer.Defang(x))).ToArray()) + "</span>"));
                sb.Append("</table></div>");
            }
            if (nAtt > 0) sb.Append("<p class='note'>" + H(L.T("La recherche par empreinte n’envoie pas le fichier : VirusTotal indique seulement s’il connaît déjà ce fichier.")) + " "
                + H(L.T("« Item not found » signifie qu’il ne l’a jamais analysé : ce n’est ni un bon ni un mauvais signe. C’est normal pour un document propre à votre échange (facture, devis…), mais un logiciel malveillant récent peut aussi être inconnu. N’envoyez pas sur VirusTotal un document confidentiel : il deviendrait accessible à ses abonnés.")) + "</p>");
            sb.Append("</div>");

            // ---------------- Source (en-têtes bruts) ----------------
            sb.Append("<div class='sec' id='s-raw'>");
            sb.Append(string.IsNullOrEmpty(e.RawHeaders) ? Empty(L.T("Aucun en-tête Internet.")) : "<pre>" + H(e.RawHeaders) + "</pre>");
            sb.Append("</div>");

            // ---------------- Bêta (sources externes) ----------------
            sb.Append("<div class='sec' id='s-beta'>");
            sb.Append("<p class='note'>" + H(L.T("Résultats des sources externes activées dans Paramètres → Réputation. Elles reçoivent seulement des domaines, des empreintes de fichiers ou une IP, jamais le contenu du message.")) + "</p>");
            if (r.Sources.Count > 0)
            {
                sb.Append("<h2>" + H(L.T("Sources")) + "</h2><div class='tw'><table><thead><tr><th>" + H(L.T("Source")) + "</th><th>" + H(L.T("État")) + "</th><th>" + H(L.T("Détail")) + "</th></tr></thead><tbody>");
                foreach (var src in r.Sources)
                {
                    string cls = src.State == "ok" ? "ok" : src.State == "error" ? "bad" : src.State == "pending" ? "mid" : "na";
                    string label = src.State == "ok" ? L.T("Vérifié") : src.State == "error" ? L.T("Erreur") : src.State == "pending" ? L.T("En cours") : L.T("Désactivé");
                    sb.Append("<tr><td><b>" + H(src.Name) + "</b></td><td><span class='b " + cls + "'>" + H(label) + "</span></td><td class='muted'>" + H(src.Detail) + "</td></tr>");
                }
                sb.Append("</tbody></table></div>");
            }
            if (beta.Count == 0) sb.Append(Empty(L.T("Aucune alerte des sources externes pour ce message.")));
            else
            {
                sb.Append("<h2>" + H(L.T("Alertes")) + "<span class='c'>" + beta.Count + "</span></h2>");
                foreach (var f in beta) FindingCard(sb, f, showExplanations);
            }
            InfoList(sb, r.Findings.Where(f => f.Severity == Severity.Info && Analyzer.IsBetaFinding(f)).ToList(), showExplanations);
            sb.Append("</div>");

            sb.Append("<p class='foot'>" + H(L.T("Analyse locale : le contenu du message ne quitte pas votre poste.")) + "</p>");
            sb.Append("</div></body></html>");
            return sb.ToString();
        }

        static void FindingCard(StringBuilder sb, Finding f, bool showExplanations)
        {
            string sev = f.Severity.ToString();
            // Explication pédagogique : au survol du « ? » (gain de place)
            string lesson = showExplanations ? Lessons.For(f.Id) : null;
            sb.Append("<div class='f " + sev + "'><div><span class='pill " + sev + "'>" + H(Analyzer.SeverityLabel(f.Severity)) + "</span><span class='ft'>" + H(f.Title) + "</span>"
                + (lesson != null ? "<span class='why' title='" + H(L.T("Pourquoi c’est important :") + " " + lesson) + "'>?</span>" : "") + "</div>");
            if (!string.IsNullOrEmpty(f.Detail)) sb.Append("<p class='fd'>" + H(f.Detail) + "</p>");
            if (f.Evidence.Count > 0)
            {
                sb.Append("<div class='evs'>");
                foreach (var ev in f.Evidence) sb.Append("<span class='ev'>" + H(ev) + "</span>");
                sb.Append("</div>");
            }
            sb.Append("</div>");
        }

        static void TrustCard(StringBuilder sb, AnalysisResult r)
        {
            sb.Append("<h2>" + H(L.T("Preuves de légitimité")) + "<span class='c'>" + r.Trust.Count + "</span></h2><div class='card trust'><ul class='list'>");
            foreach (var t in r.Trust) sb.Append("<li><span class='ic okc'>&#10003;</span>" + H(t) + "</li>");
            sb.Append("</ul>");
            if (r.Level != "safe") sb.Append("<p class='note'>" + H(L.T("Ces éléments ne compensent pas les indices relevés : un compte piraté passe aussi ces contrôles.")) + "</p>");
            sb.Append("</div>");
        }

        static void InfoList(StringBuilder sb, List<Finding> infos, bool showExplanations)
        {
            if (infos.Count == 0) return;
            sb.Append("<h2>" + H(L.T("Informations")) + "</h2><div class='card'><ul class='list'>");
            foreach (var f in infos)
            {
                sb.Append("<li><span class='ic inf'>i</span>" + H(f.Title));
                if (!string.IsNullOrEmpty(f.Detail)) sb.Append("<div class='muted'>" + H(f.Detail) + "</div>");
                if (f.Evidence.Count > 0) sb.Append("<div class='mono muted'>" + H(string.Join(" ; ", f.Evidence.ToArray())) + "</div>");
                if (showExplanations)
                {
                    string lesson = Lessons.For(f.Id);
                    if (lesson != null) sb.Append("<div class='lesson'><span class='q'>?</span>" + H(lesson) + "</div>");
                }
                sb.Append("</li>");
            }
            sb.Append("</ul></div>");
        }

        static void Tab(StringBuilder sb, string id, string label, int count)
        {
            sb.Append("<a class='tab' data-t='" + id + "' href='#' onclick=\"return show('" + id + "')\">" + H(label)
                + (count > 0 ? "<span class='n'>" + count + "</span>" : "") + "</a>");
        }
    }
}
