// Outils sur les noms de domaine : domaine enregistrable, punycode, homoglyphes,
// distance d'édition et détection des domaines qui imitent un domaine légitime.

import { BRANDS, MULTI_LABEL_SUFFIXES } from './lists.js';

// ---------------------------------------------------------------------------
// Domaine enregistrable
// ---------------------------------------------------------------------------

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

export function isIpHost(host) {
  const h = String(host || '').replace(/^\[|\]$/g, '');
  return IPV4.test(h) || h.includes(':') || /^\d+$/.test(h) || /^0x[0-9a-f]+$/i.test(h);
}

/**
 * Découpe un nom d'hôte.
 * parseHost('login.microsoft.com.evil.co.uk')
 *  → { host, registrable: 'evil.co.uk', label: 'evil', suffix: 'co.uk', subdomain: 'login.microsoft.com' }
 */
export function parseHost(host) {
  const h = String(host || '').trim().toLowerCase().replace(/\.$/, '');
  if (!h) return null;
  if (isIpHost(h)) return { host: h, registrable: h, label: h, suffix: '', subdomain: '', isIp: true };
  const labels = h.split('.').filter(Boolean);
  if (labels.length === 1) return { host: h, registrable: h, label: h, suffix: '', subdomain: '', isIp: false };

  let suffixLen = 1;
  for (let n = Math.min(4, labels.length - 1); n >= 2; n--) {
    if (MULTI_LABEL_SUFFIXES.has(labels.slice(-n).join('.'))) { suffixLen = n; break; }
  }
  if (labels.length <= suffixLen) suffixLen = labels.length - 1;
  const regLabels = labels.slice(-(suffixLen + 1));
  return {
    host: h,
    registrable: regLabels.join('.'),
    label: regLabels[0],
    suffix: labels.slice(-suffixLen).join('.'),
    subdomain: labels.slice(0, labels.length - suffixLen - 1).join('.'),
    isIp: false,
  };
}

export function registrableDomain(host) {
  const p = parseHost(host);
  return p ? p.registrable : '';
}

export function domainOfAddress(address) {
  const a = String(address || '').trim().toLowerCase();
  const at = a.lastIndexOf('@');
  return at >= 0 ? a.slice(at + 1).replace(/[>\s]+$/, '') : '';
}

// ---------------------------------------------------------------------------
// Punycode (RFC 3492) : xn--pypal-4ve.com → pаypal.com (avec un "а" cyrillique)
// ---------------------------------------------------------------------------

function adapt(delta, numPoints, firstTime) {
  let d = firstTime ? Math.floor(delta / 700) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > 455) { d = Math.floor(d / 35); k += 36; }
  return k + Math.floor((36 * d) / (d + 38));
}

function decodePunycodeLabel(input) {
  const output = [];
  let n = 128, i = 0, bias = 72;
  let basic = input.lastIndexOf('-');
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) output.push(input.charCodeAt(j));
  for (let index = basic > 0 ? basic + 1 : 0; index < input.length;) {
    const oldi = i;
    let w = 1;
    for (let k = 36; ; k += 36) {
      if (index >= input.length) throw new Error('punycode invalide');
      const cp = input.charCodeAt(index++);
      let digit = 36;
      if (cp >= 48 && cp <= 57) digit = cp - 22;
      else if (cp >= 65 && cp <= 90) digit = cp - 65;
      else if (cp >= 97 && cp <= 122) digit = cp - 97;
      if (digit >= 36) throw new Error('punycode invalide');
      i += digit * w;
      const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
      if (digit < t) break;
      w *= 36 - t;
    }
    const out = output.length + 1;
    bias = adapt(i - oldi, out, oldi === 0);
    n += Math.floor(i / out);
    i %= out;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

/** Convertit les labels "xn--" en Unicode (pour l'affichage et la détection d'homoglyphes). */
export function toUnicode(host) {
  return String(host || '').split('.').map((label) => {
    if (!/^xn--/i.test(label)) return label;
    try { return decodePunycodeLabel(label.slice(4).toLowerCase()); } catch { return label; }
  }).join('.');
}

export function hasNonAscii(s) {
  return /[^\x00-\x7f]/.test(s);
}

// ---------------------------------------------------------------------------
// "Squelette" visuel : deux chaînes qui se ressemblent à l'œil ont le même squelette.
// ---------------------------------------------------------------------------

const CONFUSABLES = {
  // Cyrillique
  'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c', 'т': 't',
  'у': 'y', 'х': 'x', 'ѕ': 's', 'і': 'i', 'ї': 'i', 'ј': 'j', 'ԁ': 'd', 'ӏ': 'l', 'ɡ': 'g', 'һ': 'h', 'ԛ': 'q',
  'ԝ': 'w', 'ү': 'y', 'ո': 'n', 'ս': 'u', 'օ': 'o',
  // Grec
  'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
  'ω': 'w', 'γ': 'y',
  // Divers
  'ı': 'i', 'ł': 'l', 'ƚ': 'l', 'ɩ': 'i', 'ⅼ': 'l', 'ℓ': 'l', 'ｍ': 'm', 'ⅿ': 'm', 'ß': 'b',
};

const DIGITS = { '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g', '!': 'l', '|': 'l' };

export function skeleton(s) {
  let out = '';
  for (const ch of String(s || '').toLowerCase()) out += CONFUSABLES[ch] ?? DIGITS[ch] ?? ch;
  out = out.normalize('NFD').replace(/[̀-ͯ]/g, '');
  return out
    .replace(/[-_.]/g, '')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/cl/g, 'd')
    .replace(/i/g, 'l');
}

// ---------------------------------------------------------------------------
// Distance de Damerau-Levenshtein (substitution, insertion, suppression, inversion)
// ---------------------------------------------------------------------------

export function editDistance(a, b) {
  a = String(a); b = String(b);
  const m = a.length, n = b.length;
  if (Math.abs(m - n) > 3) return Math.abs(m - n);
  const d = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) d[i][0] = i;
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[m][n];
}

// ---------------------------------------------------------------------------
// Contexte de détection : marques + domaines de l'entreprise + domaines de confiance
// ---------------------------------------------------------------------------

/**
 * Prépare la liste des domaines protégés.
 * @param {{companyName?:string, companyDomains?:string[], trustedDomains?:string[]}} config
 */
export function buildDomainContext(config = {}) {
  const legit = new Set();
  const targets = []; // { label, brand, domain, isCompany, generic, keyword }
  const seen = new Set();

  const addTarget = (label, brand, domain, isCompany, generic, keyword) => {
    const key = `${label}|${brand}`;
    if (!label || seen.has(key)) return;
    seen.add(key);
    targets.push({ label, brand, domain, isCompany, generic: !!generic, keyword: !!keyword });
  };

  for (const d of config.companyDomains || []) {
    const p = parseHost(d);
    if (!p) continue;
    legit.add(p.registrable);
    addTarget(p.label, config.companyName || p.registrable, p.registrable, true, false, false);
  }
  for (const b of BRANDS) {
    for (const d of b.domains) {
      const p = parseHost(d);
      legit.add(p.registrable);
      addTarget(p.label, b.name, p.registrable, false, b.generic, false);
    }
    for (const k of b.keywords || []) addTarget(k, b.name, b.domains[0], false, b.generic, true);
  }
  for (const d of config.trustedDomains || []) {
    const p = parseHost(d);
    if (p) legit.add(p.registrable);
  }
  return { legit, targets, companyDomains: new Set((config.companyDomains || []).map(registrableDomain)) };
}

// Labels de domaines légitimes qui sont aussi des mots courants : seule la détection
// d'homoglyphes s'applique (sinon trop de faux positifs : offices.fr, window.com...).
const GENERIC_LABELS = new Set(['office', 'live', 'windows', 'azure', 'bing', 'skype', 'force', 'apple', 'orange',
  'free', 'zoom', 'meta', 'me', 'mac', 'g', 'fb', 'we', 'aka', 'cloud', 'msn', 'okta', 'engie']);

export const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

// Mots que les pirates accolent à une marque : paypal-secure, microsoftonlinesupport, monespace-ameli...
const AFFIX_WORDS = ['login', 'logon', 'signin', 'sign', 'in', 'secure', 'security', 'securite', 'support', 'help',
  'helpdesk', 'verify', 'verification', 'verif', 'account', 'accounts', 'acct', 'update', 'service', 'services',
  'online', 'auth', 'sso', 'mail', 'email', 'web', 'webmail', 'portal', 'portail', 'id', 'alert', 'alerte', 'billing',
  'pay', 'payment', 'paiement', 'cloud', 'team', 'teams', 'check', 'confirm', 'client', 'clients', 'customer', 'connect',
  'connexion', 'access', 'acces', 'center', 'centre', 'app', 'apps', 'doc', 'docs', 'document', 'share', 'file', 'files',
  'drive', 'info', 'infos', 'notice', 'notification', 'france', 'fr', 'official', 'officiel', 'recover', 'recovery',
  'reset', 'unlock', 'member', 'user', 'my', 'mon', 'ma', 'espace', 'compte', 'assistance', 'aide', 'remboursement',
  'refund', 'livraison', 'delivery', 'colis', 'parcel', 'tracking', 'suivi', 'store', 'shop', 'prime', 'office', 'admin',
  'it', 'hr', 'rh', 'net', 'online', 'live', 'the', 'and', 'of', 'en', 'ligne', 'particulier', 'pro', 'banque', 'bank',
  'gouv', 'gov', 'impot', 'impots', 'amende', 'dossier', 'session', 'safe', 'safety', 'protect', 'protection', 'sync',
  'storage', 'quota', 'box', 'invoice', 'facture', 'paye', 'rib', 'iban', 'card', 'carte', 'wallet', 'cash', 'gift'];
const AFFIX_SET = new Set(AFFIX_WORDS);

function isAffixChain(s) {
  if (!s) return true;
  const ok = new Array(s.length + 1).fill(false);
  ok[0] = true;
  for (let i = 1; i <= s.length; i++) {
    for (let j = Math.max(0, i - 14); j < i && !ok[i]; j++) if (ok[j] && AFFIX_SET.has(s.slice(j, i))) ok[i] = true;
  }
  return ok[s.length];
}

/** Le label contient-il la marque comme "mot" (et non au milieu d'un autre mot comme "amazonie") ? */
function containsToken(label, kw) {
  const k = kw.replace(/-/g, '');
  if (new RegExp(`(^|[-0-9])${kw.replace(/-/g, '-?')}($|[-0-9])`).test(label)) return true;
  if (k.length < 5) return false;
  const l = label.replace(/-/g, '');
  const idx = l.indexOf(k);
  if (idx < 0) return false;
  const rest = (l.slice(0, idx) + '-' + l.slice(idx + k.length)).split(/[-0-9]+/);
  return rest.every(isAffixChain);
}

const TECHNIQUE_TEXT = {
  tld: 'même nom avec une autre extension',
  homoglyph: 'caractères visuellement identiques (homoglyphes)',
  unicode: 'caractères étrangers (Unicode) imitant des lettres latines',
  typo: 'faute de frappe volontaire (typosquatting)',
  combo: 'nom de marque combiné à d’autres mots',
  subdomain: 'nom de marque placé dans un sous-domaine',
};

/**
 * Cherche si un nom d'hôte imite un domaine protégé.
 * @returns {null | {technique, techniqueText, brand, target, isCompany, severity, host, unicodeHost}}
 */
export function detectLookalike(host, ctx) {
  const p = parseHost(host);
  if (!p || p.isIp) return null;
  if (ctx.legit.has(p.registrable)) return null;

  const uniReg = toUnicode(p.registrable);
  const uniLabel = uniReg.split('.')[0];
  const label = p.label.startsWith('xn--') ? uniLabel : p.label;
  const isUnicode = hasNonAscii(uniLabel);
  const skelLabel = skeleton(label);

  // "googlemaps" commence par "google" : c'est une extension du nom, pas une faute de frappe.
  const extendsOtherTarget = ctx.targets.some((t) => t.label.length >= 5 && label !== t.label && (label.startsWith(t.label) || label.endsWith(t.label)));

  let best = null;
  const consider = (technique, t, severity) => {
    const sev = t.isCompany ? (severity === 'medium' ? 'high' : 'critical') : severity;
    if (!best || SEVERITY_RANK[sev] > SEVERITY_RANK[best.severity]) {
      best = { technique, techniqueText: TECHNIQUE_TEXT[technique], brand: t.brand, target: t.domain, isCompany: t.isCompany, severity: sev, host: p.host, unicodeHost: toUnicode(p.host) };
    }
  };

  for (const t of ctx.targets) {
    const tl = t.label;
    if (GENERIC_LABELS.has(tl) && !t.isCompany) {
      if (label !== tl && skelLabel === skeleton(tl)) consider(isUnicode ? 'unicode' : 'homoglyph', t, 'high');
      continue;
    }
    if (label === tl) {
      if (!t.keyword) consider('tld', t, 'medium');
      continue;
    }
    if (skelLabel === skeleton(tl)) {
      consider(isUnicode ? 'unicode' : 'homoglyph', t, 'high');
      continue;
    }
    // "docusignal" contient "docusign" : ce n'est pas une faute de frappe, la règle "combo" s'en charge.
    const isExtension = label.startsWith(tl) || label.endsWith(tl) || extendsOtherTarget;
    if (tl.length >= 5 && !t.keyword && !isExtension) {
      const dist = editDistance(label, tl);
      const max = tl.length >= 8 ? 2 : 1;
      if (dist <= max || (tl.length >= 6 && editDistance(skelLabel, skeleton(tl)) <= 1)) {
        consider('typo', t, tl.length >= 7 ? 'high' : 'medium');
        continue;
      }
    }
    if (!t.generic && (tl.length >= 3) && containsToken(label, tl)) {
      consider('combo', t, 'medium');
    }
  }

  // Marque dans le sous-domaine : microsoft.com.secure-check.xyz, paypal-login.evil.top
  if (p.subdomain) {
    const sub = p.subdomain;
    for (const t of ctx.targets) {
      if (t.generic || t.label.length < 4) continue;
      const full = t.domain;
      if (sub === full || sub.endsWith('.' + full) || sub.includes(full + '.') || sub.endsWith(full)) {
        consider('subdomain', t, 'high');
      } else if (!GENERIC_LABELS.has(t.label) && sub.split(/[.-]/).includes(t.label)) {
        consider('subdomain', t, 'medium');
      }
    }
  }

  if (!best && isUnicode) {
    best = { technique: 'unicode', techniqueText: 'nom de domaine contenant des caractères non latins', brand: null, target: null, isCompany: false, severity: 'medium', host: p.host, unicodeHost: toUnicode(p.host) };
  }
  return best;
}
