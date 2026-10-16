/* global Office */
// Panneau latéral Outlook : lit le message ouvert, lance l'analyse et affiche le verdict.
// Sécurité : le contenu du message n'est JAMAIS injecté en HTML dans le panneau
// (uniquement textContent), pour éviter qu'un email piégé exécute du code ici.

import { analyzeEmail, formatReport, CATEGORY_LABELS } from '../engine/index.js';
import { domainOfAddress, registrableDomain, toUnicode } from '../engine/domains.js';
import { CONFIG } from '../config.js';
import { buildBlocklist, emptyBlocklist } from '../engine/blocklist.js';

const TRUST_KEY = 'trustedDomains';
const SEVERITY_LABELS = { critical: 'Critique', high: 'Élevé', medium: 'Moyen', low: 'Faible', info: 'Info' };

let current = { email: null, result: null };

const $ = (id) => document.getElementById(id);

Office.onReady((info) => {
  if (info.host !== Office.HostType.Outlook) return;
  document.addEventListener('click', onClick);
  // Panneau épinglé : on relance l'analyse à chaque changement de message
  if (Office.context.mailbox.addHandlerAsync) {
    Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, () => run());
  }
  run();
});

// ---------------------------------------------------------------------------
// Collecte des données du message
// ---------------------------------------------------------------------------

function asyncCall(fn, ...args) {
  return new Promise((resolve, reject) => {
    fn(...args, (res) => (res.status === Office.AsyncResultStatus.Succeeded ? resolve(res.value) : reject(res.error)));
  });
}

async function collectEmail(item) {
  const from = item.from || item.sender || {};
  const sender = item.sender || {};

  const html = await asyncCall(item.body.getAsync.bind(item.body), Office.CoercionType.Html).catch(() => '');
  let headers = '';
  if (typeof item.getAllInternetHeadersAsync === 'function') {
    headers = await asyncCall(item.getAllInternetHeadersAsync.bind(item)).catch(() => '');
  }

  const parsed = parseBody(html);
  return {
    from: { name: from.displayName || '', address: from.emailAddress || '' },
    sender: { name: sender.displayName || '', address: sender.emailAddress || '' },
    subject: item.subject || '',
    bodyText: parsed.text,
    html: { hasForm: parsed.hasForm, hasPasswordInput: parsed.hasPasswordInput },
    links: parsed.links,
    attachments: (item.attachments || []).map((a) => ({
      name: a.name, size: a.size, contentType: a.contentType || '', isInline: !!a.isInline, kind: a.attachmentType,
    })),
    headers,
  };
}

/** Analyse le HTML du corps dans un document inerte (DOMParser n'exécute pas les scripts). */
function parseBody(html) {
  const doc = new DOMParser().parseFromString(String(html || ''), 'text/html');
  doc.querySelectorAll('script, style, noscript').forEach((n) => n.remove());
  const links = [];
  const seen = new Set();
  doc.querySelectorAll('a[href], area[href]').forEach((a) => {
    const href = a.getAttribute('href') || '';
    const text = (a.textContent || a.getAttribute('title') || '').replace(/\s+/g, ' ').trim();
    const key = href + '|' + text;
    if (!seen.has(key)) { seen.add(key); links.push({ href, text }); }
  });
  // Texte du corps, nœud par nœud (sinon "…com</p><p>Voir" deviendrait "…comVoir")
  const parts = [];
  const plain = [];
  if (doc.body) {
    const walker = doc.createTreeWalker(doc.body, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const t = n.nodeValue.trim();
      if (!t) continue;
      parts.push(t);
      if (!n.parentElement?.closest('a')) plain.push(t);
    }
  }
  const text = parts.join(' ').replace(/\s+/g, ' ').trim();
  // URL écrites en clair (hors liens cliquables)
  for (const m of plain.join(' ').matchAll(/\bhttps?:\/\/[^\s<>"')]+/gi)) {
    if (![...seen].some((k) => k.startsWith(m[0]))) { seen.add(m[0]); links.push({ href: m[0], text: '' }); }
  }
  return {
    text,
    links,
    hasForm: !!doc.querySelector('form'),
    hasPasswordInput: !!doc.querySelector('input[type="password" i]'),
  };
}

// ---------------------------------------------------------------------------
// Domaines de confiance propres à l'utilisateur (stockés dans sa boîte mail)
// ---------------------------------------------------------------------------

function getUserTrusted() {
  try { return Office.context.roamingSettings.get(TRUST_KEY) || []; } catch { return []; }
}

function setUserTrusted(list) {
  return new Promise((resolve) => {
    Office.context.roamingSettings.set(TRUST_KEY, [...new Set(list)].slice(0, 500));
    Office.context.roamingSettings.saveAsync(() => resolve());
  });
}

function effectiveConfig(blocklist) {
  return { ...CONFIG, blocklist, trustedDomains: [...(CONFIG.trustedDomains || []), ...getUserTrusted()] };
}

// ---------------------------------------------------------------------------
// Listes de domaines malveillants (fichier mis à jour chaque jour sur le serveur du complément)
// ---------------------------------------------------------------------------

let blocklistPromise = null;

function loadBlocklist() {
  if (!blocklistPromise) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    blocklistPromise = fetch(new URL('../data/blocklist.json', import.meta.url), { signal: ctrl.signal, cache: 'no-cache' })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => (data ? buildBlocklist(data) : emptyBlocklist()))
      .catch(() => emptyBlocklist())
      .finally(() => clearTimeout(timer));
  }
  return blocklistPromise;
}

// ---------------------------------------------------------------------------
// Analyse et affichage
// ---------------------------------------------------------------------------

function show(state) {
  for (const s of ['loading', 'empty', 'error', 'result']) $(`state-${s}`).hidden = s !== state;
}

async function run() {
  const item = Office.context.mailbox.item;
  if (!item) { show('empty'); return; }
  show('loading');
  try {
    const [email, blocklist] = await Promise.all([collectEmail(item), loadBlocklist()]);
    const result = analyzeEmail(email, effectiveConfig(blocklist));
    current = { email, result };
    render(email, result, blocklist);
    show('result');
  } catch (err) {
    console.error(err);
    $('error-text').textContent = err?.message || String(err);
    show('error');
  }
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) if (c != null) node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return node;
}

function render(email, r, blocklist) {
  const verdict = $('verdict');
  verdict.className = `verdict ${r.level}`;
  $('verdict-label').textContent = r.levelLabel;
  $('verdict-advice').textContent = r.advice;
  $('score-value').textContent = r.score;
  $('score-arc').style.strokeDasharray = `${(r.score / 100) * 97.4} 100`;

  $('btn-report').hidden = !CONFIG.reportAddress;
  const senderOrg = registrableDomain(domainOfAddress(r.iocs.sender));
  const trusted = getUserTrusted();
  // Proposé seulement pour un message "suspect" (jamais "dangereux" ni pour un domaine sosie).
  const isLookalike = r.findings.some((f) => f.id.startsWith('sender-lookalike') || f.id.startsWith('sender-blocklist'));
  $('btn-trust').hidden = r.level !== 'suspicious' || isLookalike || !senderOrg || trusted.includes(senderOrg)
    || (CONFIG.companyDomains || []).includes(senderOrg);
  $('btn-trust').textContent = `Faire confiance à ${toUnicode(senderOrg)}`;
  $('toast').hidden = true;

  // Expéditeur
  const sc = $('sender-card');
  sc.replaceChildren(
    el('div', { class: 'name' }, email.from.name || '(sans nom)'),
    el('div', { class: 'addr' }, email.from.address),
  );

  // Indices groupés par catégorie
  const visible = r.findings.filter((f) => f.severity !== 'info');
  const container = $('findings');
  container.replaceChildren();
  if (!visible.length) {
    container.append(el('div', { class: 'card muted' }, 'Aucun indice suspect détecté.'));
  }
  for (const cat of Object.keys(CATEGORY_LABELS)) {
    const list = visible.filter((f) => f.category === cat);
    if (!list.length) continue;
    const group = el('section', { class: 'group' }, el('h2', {}, CATEGORY_LABELS[cat]));
    for (const f of list) group.append(renderFinding(f));
    container.append(group);
  }

  // Points rassurants
  $('positives').replaceChildren(...r.positives.map((p) => el('li', {}, p)));
  $('positives-block').hidden = !r.positives.length;

  // Domaines des liens
  const linkDomains = [...r.iocs.domains, ...r.iocs.ips];
  $('link-domains').replaceChildren(...linkDomains.map((d) => el('li', {}, toUnicode(d))));
  $('links-summary').textContent = `Domaines des liens (${linkDomains.length})`;
  $('links-block').hidden = !linkDomains.length;

  // Informations techniques
  const infos = r.findings.filter((f) => f.severity === 'info');
  $('info-list').replaceChildren(...infos.map((f) => el('li', {}, f.title + (f.evidence.length ? ` : ${f.evidence.join(' ; ')}` : ''))));
  $('info-block').hidden = !infos.length;

  // Domaines de confiance de l'utilisateur
  $('trusted-list').replaceChildren(...trusted.map((d) => el('li', {}, d, ' ',
    el('button', { type: 'button', class: 'btn-link', 'data-action': 'untrust', 'data-domain': d }, 'retirer'))));
  $('trusted-block').hidden = !trusted.length;

  // État des listes de domaines malveillants
  const remote = blocklist.sources.filter((s) => s.id !== 'custom' && s.count);
  $('lists-status').textContent = remote.length
    ? 'Listes : ' + remote.map((s) => `${s.name}, ${s.count.toLocaleString('fr-FR')} domaines, mise à jour le ${new Date(s.updated).toLocaleDateString('fr-FR')}`).join(' ; ')
    : 'Listes de domaines malveillants non chargées.';
}

function renderFinding(f) {
  const node = el('article', { class: `finding ${f.severity}` },
    el('div', { class: 'title' }, el('span', { class: `pill ${f.severity}` }, SEVERITY_LABELS[f.severity]), el('span', {}, f.title)));
  if (f.detail) node.append(el('p', { class: 'detail' }, f.detail));
  if (f.evidence.length) node.append(el('ul', { class: 'evidence' }, f.evidence.map((e) => el('li', {}, e))));
  return node;
}

function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.hidden = false;
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

async function onClick(ev) {
  const btn = ev.target.closest('[data-action]');
  if (!btn) return;
  const action = btn.getAttribute('data-action');
  if (action === 'retry') return run();
  if (!current.result) return;

  if (action === 'copy') {
    await copyText(formatReport(current.result, current.email));
    toast('Rapport copié dans le presse-papiers.');
  }

  if (action === 'report') reportMessage();

  if (action === 'trust') {
    const d = registrableDomain(domainOfAddress(current.result.iocs.sender));
    if (d) { await setUserTrusted([...getUserTrusted(), d]); await run(); toast(`${toUnicode(d)} ajouté à vos domaines de confiance.`); }
  }

  if (action === 'untrust') {
    const d = btn.getAttribute('data-domain');
    await setUserTrusted(getUserTrusted().filter((x) => x !== d));
    await run();
  }
}

function reportMessage() {
  const item = Office.context.mailbox.item;
  const report = formatReport(current.result, current.email);
  const escape = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const options = {
    toRecipients: [CONFIG.reportAddress],
    subject: `[Signalement phishing] ${item.subject || ''}`.slice(0, 250),
    htmlBody: `<p>Message suspect signalé via PhishGuard.</p><pre style="font-family:Consolas,monospace;font-size:12px">${escape(report)}</pre>`,
  };
  // Le message d'origine est joint (en tant qu'élément Outlook) quand c'est possible
  if (item.itemId) options.attachments = [{ type: 'item', name: (item.subject || 'message').slice(0, 100), itemId: item.itemId }];
  try {
    Office.context.mailbox.displayNewMessageForm(options);
  } catch (e) {
    delete options.attachments;
    Office.context.mailbox.displayNewMessageForm(options);
  }
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = el('textarea', { style: 'position:fixed;opacity:0' });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
}
