import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeEmail, formatReport } from '../src/engine/index.js';
import { detectLookalike, buildDomainContext, parseHost, toUnicode, skeleton } from '../src/engine/domains.js';
import { unwrapUrl } from '../src/engine/links.js';

const CONFIG = {
  companyName: 'Acmetech',
  companyDomains: ['acmetech.fr'],
  vipNames: ['Claire Martin'],
  trustedDomains: ['partenaire-fiable.fr'],
};
const ctx = buildDomainContext(CONFIG);
const look = (h) => detectLookalike(h, ctx);

const PASS = 'Authentication-Results: spf=pass smtp.mailfrom=x; dkim=pass header.d=x; dmarc=pass action=none header.from=x;compauth=pass';
const FAIL = 'Authentication-Results: spf=fail smtp.mailfrom=x; dkim=none; dmarc=fail action=quarantine header.from=x;compauth=fail reason=000';

const base = (over = {}) => ({
  from: { name: 'Paul', address: 'paul@exemple-pme.fr' },
  subject: 'Bonjour',
  bodyText: 'Bonjour, voici le compte rendu de la réunion.',
  links: [],
  attachments: [],
  headers: PASS,
  ...over,
});

// --- Domaines ---------------------------------------------------------------

test('domaine enregistrable', () => {
  assert.equal(parseHost('login.microsoft.com.evil.co.uk').registrable, 'evil.co.uk');
  assert.equal(parseHost('impots.gouv.fr').registrable, 'impots.gouv.fr');
  assert.equal(parseHost('microsoft-login.web.app').registrable, 'microsoft-login.web.app');
});

test('typosquatting : niicrosoft.com, rnicrosoft.com, micros0ft.com, paypa1.com', () => {
  assert.equal(look('niicrosoft.com')?.brand, 'Microsoft');
  assert.equal(look('niicrosoft.com')?.technique, 'typo');
  assert.equal(look('rnicrosoft.com')?.technique, 'homoglyph');
  assert.equal(look('micros0ft.com')?.technique, 'homoglyph');
  assert.equal(look('paypa1.com')?.brand, 'PayPal');
  assert.equal(look('arnazon.fr')?.brand, 'Amazon');
  assert.equal(look('linkedln.com')?.brand, 'LinkedIn');
});

test('homoglyphes Unicode (punycode)', () => {
  const host = new URL('http://pаypal.com').hostname; // "а" cyrillique
  assert.match(host, /^xn--/);
  assert.equal(toUnicode(host), 'pаypal.com');
  const r = look(host);
  assert.equal(r?.brand, 'PayPal');
  assert.equal(r?.technique, 'unicode');
});

test('combosquatting et sous-domaine', () => {
  assert.equal(look('microsoft-login-secure.com')?.technique, 'combo');
  assert.equal(look('secure-paypal.xyz')?.brand, 'PayPal');
  assert.equal(look('login.microsoft.com.verify-acct.xyz')?.technique, 'subdomain');
  assert.equal(look('microsoft-login.web.app')?.brand, 'Microsoft');
});

test('domaine de l’entreprise imité → critique', () => {
  const r = look('acrnetech.fr');
  assert.equal(r?.isCompany, true);
  assert.equal(r?.severity, 'critical');
  assert.equal(look('acmetech.com')?.severity, 'high'); // même nom, autre extension
});

test('pas de faux positifs sur les domaines légitimes ou sans rapport', () => {
  for (const h of ['microsoft.com', 'login.microsoftonline.com', 'gmail.com', 'impots.gouv.fr', 'acmetech.fr',
    'partenaire-fiable.fr', 'groupes.fr', 'updates.com', 'window-shop.fr', 'offices-paris.fr', 'leboncoin.fr',
    'amazonie-voyages.fr', 'cafe-de-paris.fr', 'orange-mecanique.fr', 'freelance.fr', 'fnac.com', 'google-analytics.com']) {
    assert.equal(look(h), null, `faux positif sur ${h} : ${JSON.stringify(look(h))}`);
  }
});

test('squelette visuel', () => {
  assert.equal(skeleton('rnicrosoft'), skeleton('microsoft'));
  assert.equal(skeleton('vvetransfer'), skeleton('wetransfer'));
});

// --- Liens ------------------------------------------------------------------

test('déballage Safe Links', () => {
  const safe = 'https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fniicrosoft.com%2Flogin&data=05';
  assert.equal(unwrapUrl(safe).url.hostname, 'niicrosoft.com');
});

// --- Scénarios complets -----------------------------------------------------

test('email légitime : verdict sûr', () => {
  const r = analyzeEmail(base({
    links: [{ text: 'Voir le document', href: 'https://acmetech.sharepoint.com/doc' }],
    attachments: [{ name: 'compte-rendu.pdf' }],
  }), CONFIG);
  assert.equal(r.level, 'safe', JSON.stringify(r.findings, null, 1));
});

test('phishing Microsoft classique : dangereux', () => {
  const r = analyzeEmail(base({
    from: { name: 'Microsoft 365 Support', address: 'no-reply@niicrosoft.com' },
    subject: 'Action requise : votre boîte mail est pleine',
    bodyText: 'Votre compte sera suspendu dans les 24 h. Connectez-vous pour vérifier votre compte.',
    links: [{ text: 'https://login.microsoftonline.com', href: 'https://niicrosoft.com/owa/login.php' }],
    headers: FAIL,
  }), CONFIG);
  assert.equal(r.level, 'dangerous');
  const ids = r.findings.map((f) => f.id);
  for (const id of ['auth-dmarc', 'sender-lookalike-typo', 'links-lookalike-typo', 'link-text-mismatch', 'content-combo-cred']) {
    assert.ok(ids.includes(id), `manque ${id} dans ${ids}`);
  }
  assert.ok(formatReport(r, { from: { name: 'x' }, subject: 's' }).includes('hxxps://niicrosoft[.]com'));
});

test('fraude au président : nom de dirigeant + Gmail + virement confidentiel', () => {
  const r = analyzeEmail(base({
    from: { name: 'Claire Martin', address: 'claire.martin.dg@gmail.com' },
    subject: 'Virement urgent',
    bodyText: 'Es-tu disponible ? J’ai besoin d’un virement aujourd’hui, en toute discrétion. Je suis en réunion.',
  }), CONFIG);
  assert.equal(r.level, 'dangerous');
  assert.ok(r.findings.some((f) => f.id === 'sender-vip'));
  assert.ok(r.findings.some((f) => f.id === 'content-combo-bec'));
});

test('usurpation du domaine de l’entreprise (DMARC en échec)', () => {
  const r = analyzeEmail(base({ from: { name: 'Compta', address: 'compta@acmetech.fr' }, headers: FAIL }), CONFIG);
  assert.equal(r.level, 'dangerous');
  assert.ok(r.findings.some((f) => f.id === 'auth-dmarc' && f.severity === 'critical'));
});

test('pièces jointes dangereuses', () => {
  const r = analyzeEmail(base({
    attachments: [{ name: 'Facture_2026.pdf.exe' }, { name: 'scan.html' }, { name: 'devis.xlsm' }, { name: 'photo.png', isInline: true, contentType: 'image/png' }],
  }), CONFIG);
  const ids = r.findings.map((f) => f.id);
  assert.ok(ids.includes('att-double'));
  assert.ok(ids.includes('att-html'));
  assert.ok(ids.includes('att-macro'));
  assert.equal(r.level, 'dangerous');
});

test('Reply-To vers une messagerie gratuite', () => {
  const r = analyzeEmail(base({
    headers: PASS + '\nReply-To: "Service client" <support.facture@outlook.fr>',
  }), CONFIG);
  assert.ok(r.findings.some((f) => f.id === 'sender-replyto' && f.severity === 'high'));
});

test('message interne authentifié : contenu atténué', () => {
  const r = analyzeEmail(base({
    from: { name: 'RH', address: 'rh@acmetech.fr' },
    bodyText: 'Rappel urgent : mettez à jour votre mot de passe avant vendredi.',
    headers: 'X-MS-Exchange-Organization-AuthAs: Internal',
  }), CONFIG);
  assert.equal(r.internal, true);
  assert.equal(r.level, 'safe');
});

// --- Listes de domaines malveillants ----------------------------------------

import { buildBlocklist } from '../src/engine/blocklist.js';
import { parseList } from '../tools/update-blocklists.mjs';

test('lecture des listes (texte brut, format hosts, en-tête)', () => {
  const txt = 'Last update: 2026-10-15\n# commentaire\nfaux-impots-remboursement.fr\n0.0.0.0 colis-laposte-suivi.fr\nAMELI-carte-vitale.fr\n\nnot a domain\n||adguard-style.fr^';
  assert.deepEqual(parseList(txt), ['adguard-style.fr', 'ameli-carte-vitale.fr', 'colis-laposte-suivi.fr', 'faux-impots-remboursement.fr']);
});

const BL = buildBlocklist({ sources: [
  { id: 'redflagdomains', name: 'Red Flag Domains', severity: 'high', updated: '2026-10-15T06:00:00Z', domains: ['colis-suivi-livraison.fr', 'mon-espace-sante-maj.fr'] },
  { id: 'custom', name: 'Liste interne', severity: 'critical', domains: ['fournisseur-faux.com'] },
] });

test('recherche dans les listes (sous-domaines inclus)', () => {
  assert.equal(BL.lookup('colis-suivi-livraison.fr')?.source.id, 'redflagdomains');
  assert.equal(BL.lookup('www.track.colis-suivi-livraison.fr')?.domain, 'colis-suivi-livraison.fr');
  assert.equal(BL.lookup('suivi-livraison.fr'), null);
  assert.equal(BL.lookup('fournisseur-faux.com')?.source.severity, 'critical');
});

test('domaine listé : expéditeur et liens signalés', () => {
  const r = analyzeEmail(base({
    from: { name: 'Service Livraison', address: 'info@mon-espace-sante-maj.fr' },
    links: [{ text: 'Suivre mon colis', href: 'https://www.colis-suivi-livraison.fr/track?id=1' }],
  }), { ...CONFIG, blocklist: BL });
  const ids = r.findings.map((f) => f.id);
  assert.ok(ids.includes('sender-blocklist-redflagdomains'), ids.join());
  assert.ok(ids.includes('links-blocklist-redflagdomains'), ids.join());
  assert.equal(r.level, 'dangerous');
});

test('sans liste chargée, le moteur fonctionne normalement', () => {
  const r = analyzeEmail(base(), CONFIG);
  assert.equal(r.level, 'safe');
});
