// Listes de référence utilisées par le moteur d'analyse.
// Elles sont volontairement embarquées (aucun appel réseau, aucune clé d'API).

/**
 * Marques fréquemment usurpées.
 * - domains  : domaines légitimes (domaine enregistrable, sans sous-domaine)
 * - keywords : mots servant à repérer les domaines "combinés" (microsoft-login.com)
 * - names    : formes à repérer dans le nom affiché de l'expéditeur
 * - generic  : true si le nom est un mot courant (pas de détection par mot-clé)
 */
export const BRANDS = [
  { name: 'Microsoft', domains: ['microsoft.com', 'office.com', 'office365.com', 'outlook.com', 'outlook.fr', 'live.com', 'live.fr', 'hotmail.com', 'hotmail.fr', 'microsoftonline.com', 'sharepoint.com', 'onedrive.com', 'windows.net', 'azure.com', 'msn.com', 'bing.com', 'skype.com', 'microsoft365.com', 'msauth.net', 'msftauth.net', 'aka.ms', 'cloud.microsoft', 'office.net', 'microsoftstore.com'], keywords: ['microsoft', 'office365', 'outlook', 'onedrive', 'sharepoint', 'microsoft365'], names: ['microsoft', 'office 365', 'microsoft 365', 'outlook', 'onedrive', 'sharepoint', 'microsoft teams'] },
  { name: 'Google', domains: ['google.com', 'google.fr', 'gmail.com', 'googleusercontent.com', 'gstatic.com', 'googleapis.com', 'googleadservices.com', 'googletagmanager.com', 'googlesyndication.com', 'google-analytics.com', 'googlegroups.com', 'doubleclick.net', 'youtube.com', 'goo.gl', 'g.co'], keywords: ['google', 'gmail'], names: ['google', 'gmail', 'google workspace'] },
  { name: 'Apple', domains: ['apple.com', 'icloud.com', 'me.com', 'mac.com', 'apple.fr'], keywords: ['apple', 'icloud', 'appleid'], names: ['apple', 'icloud', 'apple id', 'itunes'] },
  { name: 'PayPal', domains: ['paypal.com', 'paypal.fr', 'paypal.me', 'paypalobjects.com'], keywords: ['paypal'], names: ['paypal'] },
  { name: 'Amazon', domains: ['amazon.com', 'amazon.fr', 'amazon.de', 'amazon.co.uk', 'amazon.es', 'amazon.it', 'amazonaws.com', 'amazonses.com', 'primevideo.com'], keywords: ['amazon'], names: ['amazon', 'prime video'] },
  { name: 'DocuSign', domains: ['docusign.com', 'docusign.net'], keywords: ['docusign'], names: ['docusign'] },
  { name: 'Adobe', domains: ['adobe.com', 'adobesign.com', 'adobelogin.com'], keywords: ['adobe'], names: ['adobe', 'adobe sign', 'acrobat'] },
  { name: 'Dropbox', domains: ['dropbox.com', 'dropboxusercontent.com', 'dropboxmail.com'], keywords: ['dropbox'], names: ['dropbox'] },
  { name: 'WeTransfer', domains: ['wetransfer.com', 'we.tl'], keywords: ['wetransfer'], names: ['wetransfer'] },
  { name: 'LinkedIn', domains: ['linkedin.com', 'lnkd.in'], keywords: ['linkedin'], names: ['linkedin'] },
  { name: 'Meta', domains: ['facebook.com', 'facebookmail.com', 'fb.com', 'meta.com', 'instagram.com', 'whatsapp.com'], keywords: ['facebook', 'instagram', 'whatsapp'], names: ['facebook', 'instagram', 'whatsapp'] },
  { name: 'Netflix', domains: ['netflix.com'], keywords: ['netflix'], names: ['netflix'] },
  { name: 'Zoom', domains: ['zoom.us', 'zoom.com'], keywords: [], names: [], generic: true },
  { name: 'DHL', domains: ['dhl.com', 'dhl.fr', 'dhl.de'], keywords: ['dhl'], names: ['dhl'] },
  { name: 'UPS', domains: ['ups.com'], keywords: ['ups'], names: [] },
  { name: 'FedEx', domains: ['fedex.com'], keywords: ['fedex'], names: ['fedex'] },
  { name: 'La Poste', domains: ['laposte.fr', 'laposte.net', 'colissimo.fr', 'chronopost.fr', 'labanquepostale.fr'], keywords: ['laposte', 'colissimo', 'chronopost', 'labanquepostale'], names: ['la poste', 'colissimo', 'chronopost', 'banque postale'] },
  { name: 'Assurance Maladie (ameli)', domains: ['ameli.fr'], keywords: ['ameli'], names: ['ameli', 'assurance maladie'] },
  { name: 'Impots.gouv', domains: ['impots.gouv.fr'], keywords: ['impots', 'dgfip'], names: ['impots', 'dgfip', 'finances publiques'] },
  { name: 'ANTAI', domains: ['antai.gouv.fr'], keywords: ['antai'], names: ['antai', 'amende'] },
  { name: 'ANTS', domains: ['ants.gouv.fr'], keywords: ['ants'], names: [] },
  { name: 'CAF', domains: ['caf.fr'], keywords: ['caf'], names: ['caf', 'allocations familiales'] },
  { name: 'France Travail', domains: ['francetravail.fr', 'pole-emploi.fr'], keywords: ['francetravail', 'poleemploi', 'pole-emploi'], names: ['france travail', 'pole emploi'] },
  { name: 'Crédit Agricole', domains: ['credit-agricole.fr', 'credit-agricole.com'], keywords: ['credit-agricole', 'creditagricole'], names: ['credit agricole'] },
  { name: 'Société Générale', domains: ['societegenerale.fr', 'societegenerale.com'], keywords: ['societegenerale', 'societe-generale'], names: ['societe generale'] },
  { name: 'BNP Paribas', domains: ['bnpparibas.com', 'bnpparibas.fr', 'mabanque.bnpparibas'], keywords: ['bnpparibas', 'bnp-paribas'], names: ['bnp paribas', 'bnp'] },
  { name: 'LCL', domains: ['lcl.fr'], keywords: ['lcl'], names: [] },
  { name: 'Boursorama / BoursoBank', domains: ['boursorama.com', 'boursobank.com', 'boursorama-banque.com'], keywords: ['boursorama', 'boursobank'], names: ['boursorama', 'boursobank'] },
  { name: "Caisse d'Epargne", domains: ['caisse-epargne.fr'], keywords: ['caisse-epargne', 'caisseepargne'], names: ['caisse d epargne', 'caisse epargne'] },
  { name: 'Banque Populaire', domains: ['banquepopulaire.fr'], keywords: ['banquepopulaire', 'banque-populaire'], names: ['banque populaire'] },
  { name: 'Crédit Mutuel / CIC', domains: ['creditmutuel.fr', 'cic.fr'], keywords: ['creditmutuel', 'credit-mutuel'], names: ['credit mutuel'] },
  { name: 'Revolut', domains: ['revolut.com'], keywords: ['revolut'], names: ['revolut'] },
  { name: 'Orange', domains: ['orange.fr', 'orange.com', 'wanadoo.fr', 'orange-business.com'], keywords: [], names: ['orange'], generic: true },
  { name: 'SFR', domains: ['sfr.fr'], keywords: ['sfr'], names: [] },
  { name: 'Free', domains: ['free.fr'], keywords: [], names: [], generic: true },
  { name: 'Bouygues Telecom', domains: ['bouyguestelecom.fr'], keywords: ['bouyguestelecom', 'bouygues'], names: ['bouygues telecom'] },
  { name: 'EDF', domains: ['edf.fr', 'edf.com'], keywords: ['edf'], names: [] },
  { name: 'Engie', domains: ['engie.fr', 'engie.com'], keywords: ['engie'], names: ['engie'] },
  { name: 'TotalEnergies', domains: ['totalenergies.fr', 'totalenergies.com'], keywords: ['totalenergies'], names: ['totalenergies'] },
  { name: 'Binance', domains: ['binance.com'], keywords: ['binance'], names: ['binance'] },
  { name: 'Coinbase', domains: ['coinbase.com'], keywords: ['coinbase'], names: ['coinbase'] },
  { name: 'Salesforce', domains: ['salesforce.com', 'force.com'], keywords: ['salesforce'], names: ['salesforce'] },
  { name: 'Okta', domains: ['okta.com', 'oktacdn.com'], keywords: ['okta'], names: [] },
];

/**
 * Suffixes à plusieurs niveaux, pour calculer le "domaine enregistrable".
 * Comprend des plateformes d'hébergement gratuites : sur ces plateformes chaque
 * sous-domaine appartient à un client différent (souvent utilisé par les pirates).
 */
export const MULTI_LABEL_SUFFIXES = new Set([
  // Pays
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'ne.jp',
  'com.br', 'com.cn', 'com.hk', 'co.in', 'co.za', 'com.mx', 'com.ar', 'com.tr', 'co.kr', 'com.sg', 'com.my',
  'gouv.fr', 'asso.fr', 'nom.fr', 'gouv.ci', 'com.ng', 'com.pk', 'com.ua', 'com.ru', 'co.il',
  // Plateformes d'hébergement (Public Suffix List, section privée)
  'github.io', 'web.app', 'firebaseapp.com', 'pages.dev', 'workers.dev', 'herokuapp.com', 'azurewebsites.net',
  'blogspot.com', 'netlify.app', 'vercel.app', 'ngrok.io', 'ngrok-free.app', 'ngrok.app', 'glitch.me', 'repl.co',
  'replit.app', 'r2.dev', 'onrender.com', 'fly.dev', 'surge.sh', 'wixsite.com', 'weebly.com', 'webflow.io',
  'godaddysites.com', 'square.site', 'myshopify.com', 'framer.website', 'framer.app', 'carrd.co', 'gitbook.io',
  'notion.site', 'translate.goog', 'appspot.com', 'web.core.windows.net', 'blob.core.windows.net', 'trycloudflare.com',
]);

/** Hébergements légitimes mais très souvent détournés pour héberger des pages de phishing. */
export const ABUSED_HOSTING = [
  'firebasestorage.googleapis.com', 'storage.googleapis.com', 'sites.google.com', 'docs.google.com', 'forms.gle',
  'forms.office.com', 'forms.microsoft.com', 'sway.office.com', 'sway.cloud.microsoft', 'onedrive.live.com', '1drv.ms',
  'web.app', 'firebaseapp.com', 'pages.dev', 'workers.dev', 'r2.dev', 'blob.core.windows.net', 'web.core.windows.net',
  'azurewebsites.net', 'herokuapp.com', 'netlify.app', 'vercel.app', 'github.io', 'glitch.me', 'repl.co', 'replit.app',
  'ngrok.io', 'ngrok-free.app', 'ngrok.app', 'trycloudflare.com', 'ipfs.io', 'dweb.link', 'cloudflare-ipfs.com',
  'weebly.com', 'wixsite.com', 'webflow.io', 'godaddysites.com', 'square.site', 'notion.site', 'canva.site',
  'framer.website', 'framer.app', 'carrd.co', 'gitbook.io', 'appspot.com', 'translate.goog', 'onrender.com',
  'fly.dev', 'surge.sh', 'jotform.com', 'typeform.com', 'formstack.com', 'dropboxusercontent.com',
];

/** Raccourcisseurs d'URL (masquent la destination réelle). */
export const SHORTENERS = [
  'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at',
  'rb.gy', 't.ly', 'tiny.cc', 's.id', 'v.gd', 'qrco.de', 'qr.link', 'bl.ink', 'short.io', 'shorte.st', 'adf.ly',
  'goo.su', 'clck.ru', 'u.to', 'lnkd.in', 'surl.li', 'urlz.fr', 'link.infini.fr', 'me-qr.com',
];

/** Extensions de premier niveau très utilisées par les campagnes de phishing (gratuites ou très bon marché). */
export const SUSPICIOUS_TLDS = [
  'zip', 'mov', 'top', 'xyz', 'click', 'link', 'live', 'icu', 'cyou', 'rest', 'cfd', 'sbs', 'buzz', 'monster',
  'quest', 'bond', 'beauty', 'hair', 'makeup', 'skin', 'lat', 'autos', 'boats', 'yachts', 'motorcycles', 'tk',
  'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'su', 'ru', 'cn', 'work', 'support', 'online', 'site', 'website', 'fun',
  'shop', 'store', 'win', 'bid', 'loan', 'date', 'kim', 'country', 'stream', 'download', 'racing', 'review',
  'accountant', 'science', 'party', 'trade', 'webcam', 'men', 'help', 'digital', 'today', 'life', 'world', 'mom',
];

/** Messageries gratuites (un fournisseur ou une banque n'écrit pas depuis une adresse Gmail). */
export const FREEMAIL_DOMAINS = [
  'gmail.com', 'googlemail.com', 'outlook.com', 'outlook.fr', 'hotmail.com', 'hotmail.fr', 'live.com', 'live.fr',
  'msn.com', 'yahoo.com', 'yahoo.fr', 'ymail.com', 'aol.com', 'aol.fr', 'icloud.com', 'me.com', 'mac.com',
  'gmx.com', 'gmx.fr', 'gmx.de', 'web.de', 'mail.com', 'protonmail.com', 'proton.me', 'pm.me', 'tutanota.com',
  'tuta.io', 'yandex.com', 'yandex.ru', 'mail.ru', 'zoho.com', 'laposte.net', 'orange.fr', 'wanadoo.fr',
  'free.fr', 'sfr.fr', 'neuf.fr', 'bbox.fr', 'numericable.fr', 'aliceadsl.fr', 'qq.com', '163.com',
];

/** Pièces jointes : extensions par niveau de risque. */
export const ATTACHMENT_EXT = {
  executable: ['exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh',
    'hta', 'msi', 'msp', 'msix', 'appx', 'appxbundle', 'lnk', 'cpl', 'jar', 'reg', 'chm', 'dll', 'gadget', 'inf',
    'scf', 'url', 'website', 'application', 'xll', 'xbap', 'iqy', 'slk', 'settingcontent-ms', 'library-ms', 'search-ms'],
  diskImage: ['iso', 'img', 'vhd', 'vhdx'],
  html: ['html', 'htm', 'shtml', 'xhtml', 'mht', 'mhtml', 'svg'],
  macro: ['docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppam', 'ppsm', 'sldm'],
  oneNote: ['one', 'onepkg'],
  archive: ['zip', 'rar', '7z', 'gz', 'tgz', 'tar', 'bz2', 'xz', 'cab', 'ace', 'arj', 'lzh', 'z', 'uue', 'r00'],
  document: ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'odt', 'ods', 'txt', 'csv', 'jpg', 'jpeg',
    'png', 'gif', 'bmp', 'tif', 'tiff', 'heic', 'mp3', 'mp4', 'wav', 'ics', 'eml', 'msg', 'vcf', 'xml', 'json'],
};
