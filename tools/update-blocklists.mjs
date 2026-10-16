// Met à jour les listes de domaines malveillants utilisées par le panneau.
// À lancer une fois par jour sur le serveur qui héberge le complément (tâche planifiée).
//
//   node tools/update-blocklists.mjs
//
// Produit src/data/blocklist.json, lu par le panneau Outlook (même origine : pas de problème CORS).
// Si un téléchargement échoue, la liste précédente de cette source est conservée.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'src', 'data', 'blocklist.json');
const CUSTOM = path.join(ROOT, 'blocklists', 'custom.txt');

/**
 * Sources distantes. Format "plain" : un domaine par ligne (les lignes "# ..." et les en-têtes
 * sont ignorés ; le format hosts "0.0.0.0 domaine" est aussi accepté).
 */
const SOURCES = [
  {
    id: 'redflagdomains',
    name: 'Red Flag Domains',
    url: process.env.REDFLAG_URL || 'https://dl.red.flag.domains/red.flag.domains.txt',
    homepage: 'https://red.flag.domains/',
    license: 'CC BY-NC-SA 4.0',
    severity: 'high',
    fileEnv: 'REDFLAG_FILE',
  },
];

const DOMAIN_RE = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(xn--[a-z0-9-]{2,59}|[a-z]{2,63})$/;

export function parseList(text) {
  const out = new Set();
  for (let line of String(text).split(/\r?\n/)) {
    line = line.replace(/[#!;].*$/, '').trim().toLowerCase();
    if (!line) continue;
    const parts = line.split(/\s+/);
    let d = parts.length > 1 && /^(0\.0\.0\.0|127\.0\.0\.1|::1?)$/.test(parts[0]) ? parts[1] : parts[0];
    d = d.replace(/^\|\||\^$/g, '').replace(/^\*\./, '').replace(/\.$/, '');
    if (DOMAIN_RE.test(d)) out.add(d);
  }
  return [...out].sort();
}

async function download(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 60_000);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { 'User-Agent': 'PhishGuard-Outlook/1.0 (blocklist updater)' } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

async function main() {
  let previous = { sources: [] };
  try { previous = JSON.parse(fs.readFileSync(OUT, 'utf8')); } catch { /* première exécution */ }

  const sources = [];
  for (const s of SOURCES) {
    try {
      // Fichier déjà téléchargé par PowerShell (réseau d'entreprise) ou téléchargement direct
      const localFile = s.fileEnv && process.env[s.fileEnv];
      const text = localFile && fs.existsSync(localFile) ? fs.readFileSync(localFile, 'utf8') : await download(s.url);
      const domains = parseList(text);
      if (domains.length < 10) throw new Error(`liste anormalement courte (${domains.length})`);
      sources.push({ ...s, updated: new Date().toISOString(), count: domains.length, domains });
      console.log(`✔ ${s.name} : ${domains.length} domaines`);
    } catch (err) {
      const old = (previous.sources || []).find((p) => p.id === s.id);
      if (old) {
        sources.push(old);
        console.warn(`⚠ ${s.name} : échec (${err.message}), liste du ${old.updated} conservée`);
      } else {
        console.warn(`⚠ ${s.name} : échec (${err.message}), source ignorée`);
      }
    }
  }

  // Liste interne gérée par l'équipe sécurité
  let custom = [];
  try { custom = parseList(fs.readFileSync(CUSTOM, 'utf8')); } catch { /* pas de liste interne */ }
  sources.push({
    id: 'custom', name: 'Liste interne de l’équipe sécurité', severity: 'critical',
    updated: new Date().toISOString(), count: custom.length, domains: custom,
  });
  console.log(`✔ Liste interne : ${custom.length} domaines`);

  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify({ generated: new Date().toISOString(), sources }));
  console.log(`→ ${path.relative(ROOT, OUT)}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
