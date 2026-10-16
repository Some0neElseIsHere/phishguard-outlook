// Analyse des pièces jointes (noms et types uniquement : le contenu n'est jamais ouvert).

import { finding, extensionOf } from './util.js';
import { ATTACHMENT_EXT } from './lists.js';

const RTLO = /[\u202a-\u202e\u2066-\u2069]/;

export function analyzeAttachments(email) {
  const findings = [];
  const list = (email.attachments || []).filter((a) => !(a.isInline && /^image\//i.test(a.contentType || '')));
  const byId = new Map();
  const add = (id, severity, title, detail, ev) => {
    if (!byId.has(id)) byId.set(id, { severity, title, detail, evidence: [] });
    byId.get(id).evidence.push(ev);
  };

  for (const a of list) {
    const name = String(a.name || '');
    const lower = name.toLowerCase().trim();
    const ext = extensionOf(lower);
    const parts = lower.split('.');
    const prevExt = parts.length > 2 ? parts[parts.length - 2] : '';

    if (RTLO.test(name)) {
      add('att-rtlo', 'critical', 'Nom de fichier inversé (caractère de contrôle Unicode)',
        'Le nom affiché est trompeur : « facture[RLO]fdp.exe » s’affiche « facture.exe.pdf » mais reste un programme.', name);
      continue;
    }
    const dangerous = ATTACHMENT_EXT.executable.includes(ext) || ATTACHMENT_EXT.diskImage.includes(ext);
    if (dangerous && ATTACHMENT_EXT.document.includes(prevExt)) {
      add('att-double', 'critical', 'Double extension : programme déguisé en document',
        'Le fichier se fait passer pour un document mais c’est un programme.', name);
    } else if (ATTACHMENT_EXT.executable.includes(ext)) {
      add('att-exec', 'high', 'Pièce jointe exécutable', 'Ce type de fichier peut lancer un programme sur votre poste.', name);
    } else if (ATTACHMENT_EXT.diskImage.includes(ext)) {
      add('att-image', 'high', 'Image disque (ISO, IMG, VHD)', 'Format souvent utilisé pour contourner les protections et livrer un logiciel malveillant.', name);
    } else if (ATTACHMENT_EXT.html.includes(ext)) {
      add('att-html', ext === 'svg' ? 'medium' : 'high', 'Pièce jointe HTML ou SVG',
        'Ces fichiers ouvrent souvent une fausse page de connexion directement dans le navigateur.', name);
    } else if (ATTACHMENT_EXT.macro.includes(ext)) {
      add('att-macro', 'high', 'Document Office avec macros', 'N’activez jamais les macros d’un document reçu par email.', name);
    } else if (ATTACHMENT_EXT.oneNote.includes(ext)) {
      add('att-onenote', 'high', 'Fichier OneNote', 'Format détourné pour cacher des scripts derrière un faux bouton.', name);
    } else if (ATTACHMENT_EXT.archive.includes(ext)) {
      add('att-archive', 'low', 'Archive compressée', 'Son contenu n’est pas analysé par les filtres s’il est protégé par mot de passe.', name);
    } else if (/^\s*$/.test(ext) && lower) {
      add('att-noext', 'low', 'Pièce jointe sans extension', '', name);
    }
    if (/\s{5,}/.test(name)) {
      add('att-spaces', 'high', 'Nom de fichier rempli d’espaces pour cacher l’extension', '', name.replace(/\s{5,}/, ' … '));
    }
  }

  for (const [id, it] of byId) findings.push(finding(id, 'attachments', it.severity, it.title, it.detail, it.evidence.slice(0, 6)));
  return {
    findings,
    positives: [],
    meta: { names: list.map((a) => a.name), hasArchive: byId.has('att-archive') },
  };
}
