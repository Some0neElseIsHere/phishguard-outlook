// Listes de domaines malveillants connus (Red Flag Domains, liste interne...).
// Le fichier JSON est produit par tools/update-blocklists.mjs.

import { finding } from './util.js';
import { parseHost, toUnicode } from './domains.js';

/**
 * Prépare un index de recherche à partir du JSON { generated, sources:[{id,name,severity,updated,domains}] }.
 * @returns {{ lookup(host:string): null | {domain, source}, sources: object[], size: number }}
 */
export function buildBlocklist(data) {
  const index = new Map();
  const sources = [];
  for (const s of data?.sources || []) {
    const meta = { id: s.id, name: s.name, severity: s.severity || 'high', updated: s.updated, homepage: s.homepage, license: s.license, count: (s.domains || []).length };
    sources.push(meta);
    for (const d of s.domains || []) {
      const key = String(d).toLowerCase();
      const prev = index.get(key);
      // La liste interne (critique) l'emporte sur les autres
      if (!prev || (meta.severity === 'critical' && prev.severity !== 'critical')) index.set(key, meta);
    }
  }
  return {
    sources,
    size: index.size,
    generated: data?.generated || null,
    /** Cherche le nom d'hôte puis chaque domaine parent : a.b.evil.fr → b.evil.fr → evil.fr */
    lookup(host) {
      const p = parseHost(host);
      if (!p || p.isIp) return index.has(p?.host) ? { domain: p.host, source: index.get(p.host) } : null;
      const labels = p.host.split('.');
      const minLabels = p.registrable.split('.').length;
      for (let i = 0; labels.length - i >= minLabels; i++) {
        const cand = labels.slice(i).join('.');
        if (index.has(cand)) return { domain: cand, source: index.get(cand) };
      }
      return null;
    },
  };
}

export function emptyBlocklist() {
  return buildBlocklist({ sources: [] });
}

/** Indice pour un domaine trouvé dans une liste. */
export function blocklistFinding(hit, where, category) {
  const s = hit.source;
  const date = s.updated ? ` (liste du ${new Date(s.updated).toLocaleDateString('fr-FR')})` : '';
  return finding(`${category}-blocklist-${s.id}`, category, s.severity,
    `${where} figure dans une liste de domaines malveillants`,
    `Source : ${s.name}${date}.`, [toUnicode(hit.domain)]);
}
