using System;
using System.Drawing;
using System.Windows.Forms;

namespace PhishGuard.AddIn
{
    /// <summary>Analyse approfondie : ce qui va être vérifié, et ce qui sortira du poste. Les actions délicates sont décochées par défaut.</summary>
    internal class DeepForm : Form
    {
        readonly CheckBox chkAge, chkCert, chkHash, chkHops, chkFollow, chkUrls;
        public DeepOptions Options = new DeepOptions();

        public DeepForm(PhishGuardConfig cfg, IntelSettings keys, Icon icon)
        {
            Text = L.T("PhishGuard - Analyse approfondie");
            Width = 620;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false; MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            Font = new Font("Segoe UI", 9f);
            if (icon != null) Icon = icon;
            int y = 14;
            Func<string, bool, int, Label> label = (t, bold, w) =>
            {
                var l = new Label { Text = t, Location = new Point(16, y), MaximumSize = new Size(w, 0), AutoSize = true };
                if (bold) l.Font = new Font(Font, FontStyle.Bold);
                Controls.Add(l);
                y += TextRenderer.MeasureText(t, l.Font, new Size(w - 30, 0), TextFormatFlags.WordBreak).Height + 6;
                return l;
            };
            label(L.T("L’analyse approfondie va plus loin que l’analyse habituelle et ne montre que ce qu’elle découvre en plus. Elle peut durer jusqu’à une minute."), false, 570);
            y += 4;
            label(L.T("Sur votre poste (rien ne sort)"), true, 570);
            label("•  " + L.T("Contenu des pièces jointes : macros, modèles et objets distants des documents Office, parties compressées des PDF, archives imbriquées, pages qui fabriquent un fichier, QR codes."), false, 560);
            label("•  " + L.T("Votre boîte : messages déjà reçus de cet expéditeur, son nom utilisé avec une autre adresse, conversation citée."), false, 560);
            y += 6;
            label(L.T("Services en ligne (seulement des noms de domaine, des empreintes de fichiers ou des adresses IP)"), true, 570);
            Func<string, bool, bool, CheckBox> check = (t, on, enabled) =>
            {
                int h = Math.Max(22, TextRenderer.MeasureText(t, Font, new Size(530, 0), TextFormatFlags.WordBreak).Height + 6);
                var c = new CheckBox { Text = t, Checked = on && enabled, Enabled = enabled, Location = new Point(20, y), AutoSize = false, Size = new Size(560, h),
                    CheckAlign = ContentAlignment.TopLeft, TextAlign = ContentAlignment.TopLeft };
                Controls.Add(c);
                y += h + 4;
                return c;
            };
            chkAge = check(L.T("Âge de tous les domaines du message (rdap.org)"), true, !(cfg.IsLocked("domainagelookup") && !cfg.DomainAgeLookup));
            chkCert = check(L.T("Premier certificat HTTPS de chaque domaine (crt.sh)"), true, !(cfg.IsLocked("betacertage") && !cfg.BetaCertAge));
            bool hashKeys = keys.VirusTotalKey.Length > 0 || keys.AbuseChKey.Length > 0;
            chkHash = check(L.T("Réputation de toutes les pièces jointes (VirusTotal, MalwareBazaar)") + (hashKeys ? "" : " — " + L.T("clé d’API requise")), true, hashKeys);
            chkHops = check(L.T("Réputation de chaque serveur traversé (AbuseIPDB)") + (keys.AbuseIpdbKey.Length > 0 ? "" : " — " + L.T("clé d’API requise")), true, keys.AbuseIpdbKey.Length > 0);
            y += 6;
            label(L.T("Avec votre accord seulement"), true, 570);
            chkFollow = check(L.T("Suivre les liens jusqu’à leur vraie destination. Les sites sont contactés (sans cookie, sans exécuter de code) : l’expéditeur peut savoir que le message a été ouvert.")
                + (cfg.AllowLinkFollowing ? "" : " — " + L.T("désactivé par votre service informatique")), false, cfg.AllowLinkFollowing);
            chkUrls = check(L.T("Envoyer l’adresse complète des liens à VirusTotal. Une adresse peut contenir un jeton personnel (lien de connexion, de réinitialisation).")
                + (!cfg.AllowUrlLookup ? " — " + L.T("désactivé par votre service informatique") : keys.VirusTotalKey.Length == 0 ? " — " + L.T("clé d’API requise") : ""), false, cfg.AllowUrlLookup && keys.VirusTotalKey.Length > 0);

            var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 50, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(12, 10, 12, 8) };
            var ok = new Button { Text = L.T("Lancer l’analyse approfondie"), AutoSize = true, Height = 30, Font = new Font(Font, FontStyle.Bold) };
            var cancel = new Button { Text = L.T("Annuler"), AutoSize = true, Height = 30, DialogResult = DialogResult.Cancel };
            ok.Click += (s, e) =>
            {
                Options = new DeepOptions
                {
                    DomainAge = chkAge.Checked, Certificates = chkCert.Checked, Hashes = chkHash.Checked, HopIps = chkHops.Checked,
                    FollowLinks = chkFollow.Checked, SendUrls = chkUrls.Checked
                };
                DialogResult = DialogResult.OK;
                Close();
            };
            bar.Controls.AddRange(new Control[] { ok, cancel });
            Controls.Add(bar);
            AcceptButton = ok; CancelButton = cancel;
            ClientSize = new Size(ClientSize.Width, y + 16 + bar.Height);
            ThemeUi.Attach(this);
        }
    }
}
