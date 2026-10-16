export const SEVERITY_POINTS = { info: 0, low: 8, medium: 20, high: 40, critical: 70 };
export const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/**
 * Un indice relevé par le moteur.
 * @param {string} id        identifiant stable (ex. "link-ip")
 * @param {'auth'|'sender'|'links'|'attachments'|'content'} category
 * @param {'info'|'low'|'medium'|'high'|'critical'} severity
 * @param {string} title     phrase courte affichée à l'utilisateur
 * @param {string} [detail]  explication
 * @param {string[]} [evidence] éléments observés (domaines, noms de fichiers...)
 */
export function finding(id, category, severity, title, detail = '', evidence = []) {
  return { id, category, severity, title, detail, evidence: evidence.filter(Boolean) };
}

/** Minuscules, sans accents, espaces normalisés. */
export function normalizeText(s) {
  return String(s || '')
    .toLowerCase()
    .normalize('NFD').replace(/[̀-ͯ]/g, '')
    .replace(/[’'`]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export function uniq(arr) {
  return [...new Set(arr.filter(Boolean))];
}

/** Analyse une liste d'en-têtes bruts (string) en [{name, value}] avec les lignes repliées dépliées. */
export function parseHeaders(raw) {
  const out = [];
  if (!raw) return out;
  const lines = String(raw).replace(/\r\n/g, '\n').split('\n');
  for (const line of lines) {
    if (/^[ \t]/.test(line) && out.length) {
      out[out.length - 1].value += ' ' + line.trim();
    } else {
      const i = line.indexOf(':');
      if (i > 0) out.push({ name: line.slice(0, i).trim().toLowerCase(), value: line.slice(i + 1).trim() });
    }
  }
  return out;
}

export function headerValues(headers, name) {
  return headers.filter((h) => h.name === name.toLowerCase()).map((h) => h.value);
}

/** Extrait les adresses d'une valeur d'en-tête : '"Nom" <a@b.fr>, c@d.fr' */
export function addressesIn(value) {
  return (String(value || '').match(/[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g) || []).map((a) => a.toLowerCase());
}

export function extensionOf(name) {
  const n = String(name || '').toLowerCase().trim();
  const i = n.lastIndexOf('.');
  return i >= 0 ? n.slice(i + 1) : '';
}
