// Analyse de l'expéditeur : domaine sosie, nom affiché trompeur, Reply-To, messagerie gratuite.

import { finding, normalizeText, headerValues, addressesIn } from './util.js';
import { domainOfAddress, registrableDomain, detectLookalike, toUnicode } from './domains.js';
import { BRANDS, FREEMAIL_DOMAINS } from './lists.js';
import { blocklistFinding } from './blocklist.js';

function wordMatch(haystack, needle) {
  const n = normalizeText(needle).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(^|[^a-z0-9])${n}($|[^a-z0-9])`).test(haystack);
}

export function lookalikeFinding(look, where, category) {
  const target = look.isCompany ? `votre domaine ${look.target}` : `${look.brand} (${look.target})`;
  const shown = look.unicodeHost !== look.host ? `${look.unicodeHost} (${look.host})` : look.host;
  const id = `${category}-lookalike-${look.technique}`;
  return finding(id, category, look.severity,
    `${where} imite ${target}`,
    `Technique : ${look.techniqueText}.`, [shown]);
}

export function analyzeSender(email, ctx) {
  const findings = [];
  const positives = [];
  const cfg = ctx.config;
  const fromAddr = (email.from?.address || '').toLowerCase();
  const fromName = email.from?.name || '';
  const fromDomain = domainOfAddress(fromAddr);
  const fromOrg = registrableDomain(fromDomain);
  const isCompany = ctx.domains.companyDomains.has(fromOrg);
  const isFreemail = FREEMAIL_DOMAINS.includes(fromDomain);
  const nameNorm = normalizeText(fromName);

  if (!fromAddr) return { findings, positives, meta: {} };

  // 1. Domaine de l'expéditeur qui imite un domaine connu
  const look = detectLookalike(fromDomain, ctx.domains);
  if (look) findings.push(lookalikeFinding(look, 'Le domaine de l’expéditeur', 'sender'));
  const listed = ctx.blocklist.lookup(fromDomain);
  if (listed) findings.push(blocklistFinding(listed, 'Le domaine de l’expéditeur', 'sender'));

  // 2. Tenant Microsoft 365 générique (n'importe qui peut en créer un gratuitement)
  if (/\.onmicrosoft\.com$/.test(fromDomain) && !(cfg.companyDomains || []).some((d) => fromDomain === d)) {
    findings.push(finding('sender-onmicrosoft', 'sender', 'medium', 'Envoyé depuis un tenant Microsoft 365 générique',
      'Les adresses *.onmicrosoft.com sont créées en quelques minutes ; les entreprises sérieuses utilisent leur propre domaine.', [fromDomain]));
  }

  // 3. Le nom affiché contient une autre adresse email
  const nameAddrs = addressesIn(fromName).filter((a) => a !== fromAddr);
  if (nameAddrs.length) {
    findings.push(finding('sender-name-address', 'sender', 'high', 'Le nom affiché contient une autre adresse',
      'Le nom affiché montre une adresse qui n’est pas l’adresse réelle de l’expéditeur.', [`Affiché : ${nameAddrs[0]}`, `Réel : ${fromAddr}`]));
  }

  // 4. Le nom affiché cite une marque, mais le domaine n'appartient pas à cette marque
  for (const b of BRANDS) {
    const names = b.names || [];
    if (!names.some((n) => wordMatch(nameNorm, n))) continue;
    // Une adresse @outlook.com ou @gmail.com n'est pas "Microsoft" ou "Google" : n'importe qui peut en créer une.
    const owns = !isFreemail && b.domains.some((d) => registrableDomain(d) === fromOrg);
    if (!owns) {
      findings.push(finding('sender-brand-name', 'sender', isFreemail ? 'high' : 'medium',
        `Se présente comme « ${b.name} » sans utiliser un domaine ${b.name}`,
        isFreemail ? 'Le message vient d’une messagerie gratuite.' : 'Le domaine d’envoi n’appartient pas à cette marque.',
        [`${fromName} <${fromAddr}>`]));
      break;
    }
  }

  // 5. Usurpation d'un dirigeant ou du nom de l'entreprise depuis l'extérieur (fraude au président)
  if (!isCompany) {
    const vip = (cfg.vipNames || []).find((v) => v && wordMatch(nameNorm, v));
    if (vip) {
      findings.push(finding('sender-vip', 'sender', 'high', `Le nom affiché est celui de ${vip}, mais l’adresse est externe`,
        'Technique typique de la « fraude au président » : vérifiez par téléphone avant toute action.', [fromAddr]));
    } else if (cfg.companyName && normalizeText(cfg.companyName).length >= 3 && wordMatch(nameNorm, cfg.companyName)) {
      findings.push(finding('sender-company-name', 'sender', 'medium', `Le nom affiché mentionne ${cfg.companyName}, mais l’adresse est externe`,
        '', [fromAddr]));
    }
  }

  // 6. Reply-To : les réponses partiraient ailleurs
  const replyTo = uniqAddrs([...(email.replyTo || []), ...addressesIn(headerValues(email.headers || [], 'reply-to').join(','))]);
  for (const rt of replyTo) {
    const rtDomain = domainOfAddress(rt);
    const rtOrg = registrableDomain(rtDomain);
    if (!rtOrg || rtOrg === fromOrg) continue;
    const rtFree = FREEMAIL_DOMAINS.includes(rtDomain);
    findings.push(finding('sender-replyto', 'sender', rtFree || isCompany ? 'high' : 'medium',
      'Les réponses partiront vers une autre adresse (Reply-To)',
      rtFree ? 'L’adresse de réponse est une messagerie gratuite.' : 'Le domaine de réponse est différent du domaine de l’expéditeur.',
      [`Réponse vers : ${rt}`]));
    const rtListed = ctx.blocklist.lookup(rtDomain);
    if (rtListed) findings.push(blocklistFinding(rtListed, 'Le domaine de réponse', 'sender'));
    const rtLook = detectLookalike(rtDomain, ctx.domains);
    if (rtLook) findings.push(lookalikeFinding(rtLook, 'Le domaine de réponse', 'sender'));
    break;
  }

  // 7. Envoyé "de la part de" (Sender ≠ From)
  const senderAddr = (email.sender?.address || '').toLowerCase();
  if (senderAddr && senderAddr !== fromAddr && registrableDomain(domainOfAddress(senderAddr)) !== fromOrg) {
    findings.push(finding('sender-onbehalf', 'sender', 'info', 'Envoyé « de la part de » une autre adresse', '',
      [`Expéditeur technique : ${senderAddr}`]));
  }

  if (isCompany) positives.push('Domaine de l’expéditeur : votre entreprise');
  else if (ctx.domains.legit.has(fromOrg) && !look) positives.push(`Domaine connu : ${toUnicode(fromOrg)}`);

  return { findings, positives, meta: { fromDomain, fromOrg, isFreemail, isCompany } };
}

function uniqAddrs(list) {
  return [...new Set(list.map((a) => String(a || '').toLowerCase()).filter(Boolean))];
}
