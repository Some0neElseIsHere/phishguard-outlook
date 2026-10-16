// Analyse des liens du message.

import { finding, uniq, extensionOf } from './util.js';
import { parseHost, detectLookalike, toUnicode, hasNonAscii } from './domains.js';
import { SHORTENERS, SUSPICIOUS_TLDS, ABUSED_HOSTING, ATTACHMENT_EXT } from './lists.js';
import { lookalikeFinding } from './sender.js';
import { blocklistFinding } from './blocklist.js';

const REDIRECT_PARAMS = ['url', 'u', 'q', 'target', 'redirect', 'redirect_uri', 'redirecturl', 'dest', 'destination', 'next', 'goto', 'link', 'r'];

function safeUrl(href) {
  let h = String(href || '').trim();
  if (!h) return null;
  if (/^www\./i.test(h)) h = 'http://' + h;
  if (!/^https?:\/\//i.test(h)) return null;
  try { return new URL(h); } catch { return null; }
}

/**
 * Retire les "enveloppes" de réécriture (Microsoft Defender Safe Links, Google, redirections ouvertes)
 * pour analyser la vraie destination.
 * @returns {{ url: URL, chain: string[] }}
 */
export function unwrapUrl(href) {
  let url = safeUrl(href);
  const chain = [];
  for (let i = 0; url && i < 5; i++) {
    const host = url.hostname.toLowerCase();
    let next = null;
    let kind = null;
    if (host.endsWith('safelinks.protection.outlook.com')) { next = url.searchParams.get('url'); kind = 'safelinks'; }
    else if (/(^|\.)google\.[a-z.]+$/.test(host) && url.pathname === '/url') { next = url.searchParams.get('q') || url.searchParams.get('url'); kind = 'google'; }
    else {
      for (const p of REDIRECT_PARAMS) {
        const v = url.searchParams.get(p);
        if (v && /^https?:\/\//i.test(v)) { next = v; kind = 'redirect'; break; }
      }
    }
    const nextUrl = next ? safeUrl(next) : null;
    if (!nextUrl) break;
    chain.push(kind === 'redirect' ? host : kind);
    url = nextUrl;
  }
  return { url, chain };
}

const DOMAIN_IN_TEXT = /\b((?:https?:\/\/)?(?:[a-z0-9¡-￿-]+\.)+[a-z¡-￿]{2,})(?:[\/:?#]|\b)/i;

function hostMatchesList(host, list) {
  return list.find((d) => host === d || host.endsWith('.' + d));
}

export function analyzeLinks(email, ctx) {
  const findings = [];
  const issues = new Map(); // id → { severity, title, detail, evidence: Set }
  const add = (id, severity, title, detail, ev) => {
    if (!issues.has(id)) issues.set(id, { severity, title, detail, evidence: new Set() });
    const it = issues.get(id);
    if (ev) it.evidence.add(ev);
  };

  const urls = [];
  const domains = [];
  const lookalikes = new Map();
  const listedHits = new Map();
  const links = email.links || [];

  for (const link of links) {
    const raw = String(link.href || '').trim();
    if (!raw || /^(mailto:|tel:|cid:|#|data:image)/i.test(raw)) continue;
    if (/^(javascript|data|vbscript|file):/i.test(raw)) {
      add('link-scheme', 'high', 'Lien utilisant un protocole dangereux', 'Un lien exécute du code ou ouvre un fichier local.', raw.slice(0, 80));
      continue;
    }
    const { url, chain } = unwrapUrl(raw);
    if (!url) continue;

    const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    const p = parseHost(host);
    if (!p) continue;
    const display = toUnicode(host);
    urls.push(url.href);
    domains.push(p.registrable);

    // Le texte du lien montre un autre domaine que la destination réelle
    const text = String(link.text || '').trim();
    const looksLikeUrl = /(https?:\/\/|www\.)/i.test(text) || /^[^\s@]+\.[a-z]{2,24}(\/\S*)?$/i.test(text);
    const m = looksLikeUrl ? DOMAIN_IN_TEXT.exec(text) : null;
    const shownTld = m ? m[1].split('.').pop().toLowerCase() : '';
    const fileExts = Object.values(ATTACHMENT_EXT).flat().concat(['php', 'asp', 'aspx', 'jsp']).filter((e) => e !== 'com');
    if (m && !fileExts.includes(shownTld)) {
      const shown = parseHost(m[1].replace(/^https?:\/\//i, '').toLowerCase());
      if (shown && shown.registrable.includes('.') && shown.registrable !== p.registrable && !ctx.domains.legit.has(p.registrable)) {
        add('link-text-mismatch', 'high', 'Le texte d’un lien ne correspond pas à sa vraie destination',
          'Le lien affiche une adresse mais vous envoie ailleurs.', `Affiché : ${m[1]} → Réel : ${display}`);
      }
    }

    if (chain.some((c) => c !== 'safelinks' && c !== 'google')) {
      add('link-redirect', 'low', 'Lien passant par une redirection', 'La destination finale est cachée derrière un autre site.', `${chain.filter((c) => c !== 'safelinks').join(' → ')} → ${display}`);
    }

    const listed = ctx.blocklist.lookup(host);
    if (listed && !listedHits.has(listed.source.id)) listedHits.set(listed.source.id, { ...listed, all: new Set() });
    if (listed) listedHits.get(listed.source.id).all.add(toUnicode(listed.domain));

    if (p.isIp) {
      add('link-ip', 'high', 'Lien vers une adresse IP au lieu d’un nom de domaine', 'Les sites légitimes utilisent un nom de domaine.', host);
      continue;
    }
    if (url.username || url.password) {
      add('link-userinfo', 'high', 'Lien contenant « @ » pour masquer la destination', 'Tout ce qui est avant « @ » est ignoré par le navigateur.', url.href.slice(0, 100));
    }

    const look = ctx.domains.legit.has(p.registrable) ? null : detectLookalike(host, ctx.domains);
    if (look && !lookalikes.has(p.registrable)) lookalikes.set(p.registrable, look);
    else if (!look && hasNonAscii(display)) {
      add('link-idn', 'medium', 'Lien vers un domaine contenant des caractères non latins', '', `${display} (${host})`);
    }

    if (hostMatchesList(host, SHORTENERS)) {
      add('link-shortener', 'medium', 'Lien raccourci (destination masquée)', 'Ne cliquez pas : la destination réelle n’est pas visible.', host);
    }
    const abused = hostMatchesList(host, ABUSED_HOSTING);
    if (abused) {
      add('link-hosting', 'medium', 'Lien vers un hébergement gratuit souvent utilisé pour le phishing',
        'Le service est légitime, mais n’importe qui peut y publier une fausse page de connexion.', display);
    }
    const tld = host.split('.').pop();
    if (SUSPICIOUS_TLDS.includes(tld) && !ctx.domains.legit.has(p.registrable)) {
      add('link-tld', 'low', 'Extension de domaine très utilisée par les campagnes de phishing', '', display);
    }
    if (url.protocol === 'http:' && !ctx.domains.legit.has(p.registrable)) {
      add('link-http', 'low', 'Lien non chiffré (http)', '', display);
    }
    if (url.port && !['80', '443'].includes(url.port)) {
      add('link-port', 'medium', 'Lien utilisant un port inhabituel', '', `${display}:${url.port}`);
    }
    const ext = extensionOf(url.pathname);
    if ([...ATTACHMENT_EXT.executable, ...ATTACHMENT_EXT.diskImage, ...ATTACHMENT_EXT.html, ...ATTACHMENT_EXT.macro, ...ATTACHMENT_EXT.archive].includes(ext)
        && !['htm', 'html', 'shtml'].includes(ext)) {
      add('link-download', 'medium', 'Lien de téléchargement direct d’un fichier à risque', '', `${display}${url.pathname}`.slice(0, 100));
    }
  }

  for (const hit of listedHits.values()) {
    const f = blocklistFinding(hit, hit.all.size > 1 ? `${hit.all.size} liens pointent vers des domaines qui` : 'Un lien pointe vers un domaine qui', 'links');
    f.title = f.title.replace(' qui figure dans', hit.all.size > 1 ? ' qui figurent dans' : ' qui figure dans');
    f.evidence = [...hit.all].slice(0, 6);
    findings.push(f);
  }
  for (const look of lookalikes.values()) findings.push(lookalikeFinding(look, 'Un lien', 'links'));
  for (const [id, it] of issues) findings.push(finding(id, 'links', it.severity, it.title, it.detail, [...it.evidence].slice(0, 6)));

  const distinct = uniq(domains);
  return { findings, positives: [], meta: { urls: uniq(urls), domains: distinct, count: links.length } };
}
