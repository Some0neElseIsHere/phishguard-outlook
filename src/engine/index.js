// Point d'entrée du moteur d'analyse. Aucune dépendance à Office.js : il peut être
// testé avec Node ou réutilisé côté serveur.
//
// Format attendu de `email` :
// {
//   from:        { name, address },
//   sender:      { name, address },           // facultatif ("de la part de")
//   replyTo:     ['adresse', ...],            // facultatif (sinon lu dans les en-têtes)
//   subject:     '...',
//   bodyText:    'texte brut du corps',
//   html:        { hasForm, hasPasswordInput },
//   links:       [{ text, href }],
//   attachments: [{ name, size, contentType, isInline }],
//   headers:     'en-têtes Internet bruts' | [{ name, value }]
// }

import { analyzeAuth } from './auth.js';
import { analyzeSender } from './sender.js';
import { analyzeLinks } from './links.js';
import { analyzeAttachments } from './attachments.js';
import { analyzeContent } from './content.js';
import { buildDomainContext, domainOfAddress, isIpHost } from './domains.js';
import { parseHeaders, SEVERITY_POINTS, SEVERITY_RANK, uniq } from './util.js';
import { emptyBlocklist } from './blocklist.js';

export const CATEGORY_LABELS = {
  auth: 'Authentification',
  sender: 'Expéditeur',
  links: 'Liens',
  attachments: 'Pièces jointes',
  content: 'Contenu',
};

export const LEVELS = {
  safe: { label: 'Aucun indice important', advice: 'Restez vigilant : aucun outil ne détecte 100 % des attaques.' },
  suspicious: { label: 'Suspect', advice: 'Ne cliquez pas et n’ouvrez rien avant d’avoir vérifié l’expéditeur par un autre moyen.' },
  dangerous: { label: 'Dangereux', advice: 'Ne cliquez sur aucun lien, n’ouvrez aucune pièce jointe et signalez ce message.' },
};

const CONTENT_CAP = 30;

/**
 * @param {object} email   voir le format ci-dessus
 * @param {object} config  { companyName, companyDomains, vipNames, trustedDomains, blocklist }
 *                         blocklist : objet renvoyé par buildBlocklist() (facultatif)
 */
export function analyzeEmail(email, config = {}) {
  const e = { ...email, headers: Array.isArray(email.headers) ? email.headers : parseHeaders(email.headers) };
  const ctx = { config, domains: buildDomainContext(config), blocklist: config.blocklist || emptyBlocklist() };

  const auth = analyzeAuth(e, ctx);
  const sender = analyzeSender(e, ctx);
  const links = analyzeLinks(e, ctx);
  const attachments = analyzeAttachments(e, ctx);
  ctx.attachmentsMeta = attachments.meta;
  const content = analyzeContent(e, ctx, sender.meta);

  let findings = [...auth.findings, ...sender.findings, ...links.findings, ...attachments.findings, ...content.findings];

  // Le message est interne et authentifié : on atténue les indices de contenu (faux positifs fréquents).
  if (auth.internal) {
    findings = findings.map((f) => (f.category === 'content' && f.severity !== 'critical'
      ? { ...f, severity: SEVERITY_RANK[f.severity] > 1 ? 'low' : 'info' } : f));
  }

  findings.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);

  let score = 0;
  let contentScore = 0;
  for (const f of findings) {
    const pts = SEVERITY_POINTS[f.severity];
    if (f.category === 'content') contentScore += pts;
    else score += pts;
  }
  score = Math.min(100, score + Math.min(CONTENT_CAP, contentScore));

  const hasCritical = findings.some((f) => f.severity === 'critical');
  const level = hasCritical || score >= 50 ? 'dangerous' : score >= 20 ? 'suspicious' : 'safe';

  const fromAddress = (e.from?.address || '').toLowerCase();
  return {
    score,
    level,
    levelLabel: LEVELS[level].label,
    advice: LEVELS[level].advice,
    findings,
    positives: uniq([...auth.positives, ...sender.positives]),
    auth: auth.auth,
    internal: auth.internal,
    iocs: {
      sender: fromAddress,
      senderDomain: domainOfAddress(fromAddress),
      domains: links.meta.domains.filter((d) => !isIpHost(d)),
      ips: links.meta.domains.filter((d) => isIpHost(d)),
      urls: links.meta.urls,
      attachments: attachments.meta.names,
    },
    stats: { links: links.meta.count, attachments: attachments.meta.names.length },
  };
}

/** Rapport texte (pour le signalement à l'équipe sécurité ou le presse-papiers). */
export function formatReport(result, email) {
  const lines = [];
  lines.push(`Verdict : ${result.levelLabel} (score ${result.score}/100)`);
  lines.push(`Expéditeur : ${email.from?.name || ''} <${result.iocs.sender}>`);
  lines.push(`Objet : ${email.subject || ''}`);
  lines.push('');
  lines.push('Indices :');
  for (const f of result.findings.filter((x) => x.severity !== 'info')) {
    lines.push(`- [${f.severity.toUpperCase()}] ${f.title}${f.evidence.length ? ' : ' + f.evidence.join(' ; ') : ''}`);
  }
  if (result.iocs.urls.length) {
    lines.push('', 'URL (désarmées) :');
    for (const u of result.iocs.urls.slice(0, 30)) lines.push('- ' + defang(u));
  }
  if (result.iocs.attachments.length) lines.push('', 'Pièces jointes : ' + result.iocs.attachments.join(', '));
  return lines.join('\n');
}

/** "Désarme" une URL pour qu'elle ne soit pas cliquable : https://evil.com → hxxps://evil[.]com */
export function defang(u) {
  return String(u).replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
}
