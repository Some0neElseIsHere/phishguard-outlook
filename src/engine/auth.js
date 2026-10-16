// Analyse des en-têtes d'authentification (SPF, DKIM, DMARC, compauth Microsoft)
// et de la cohérence technique du message.

import { finding, headerValues, addressesIn } from './util.js';
import { domainOfAddress, registrableDomain } from './domains.js';

function pick(re, s) {
  const m = re.exec(s);
  return m ? m[1].toLowerCase() : null;
}

/** Lit le premier en-tête Authentication-Results (le plus haut = ajouté par votre serveur). */
export function readAuthResults(headers) {
  const values = headerValues(headers, 'authentication-results');
  const ar = values[0] || '';
  const res = {
    present: !!ar,
    spf: pick(/\bspf=([a-z]+)/i, ar),
    dkim: pick(/\bdkim=([a-z]+)/i, ar),
    dmarc: pick(/\bdmarc=([a-z]+)/i, ar),
    compauth: pick(/\bcompauth=([a-z]+)/i, ar),
    headerFrom: pick(/header\.from=([^\s;]+)/i, ar),
  };
  if (!res.spf) {
    const rspf = headerValues(headers, 'received-spf')[0];
    if (rspf) res.spf = pick(/^\s*([a-z]+)/i, rspf);
  }
  return res;
}

export function isInternalMessage(headers) {
  const authAs = (headerValues(headers, 'x-ms-exchange-organization-authas')[0] || '').toLowerCase();
  return authAs === 'internal';
}

export function analyzeAuth(email, ctx) {
  const findings = [];
  const positives = [];
  const headers = email.headers || [];
  const fromDomain = domainOfAddress(email.from?.address);
  const fromOrg = registrableDomain(fromDomain);
  const fromCompany = ctx.domains.companyDomains.has(fromOrg);

  if (!headers.length) {
    findings.push(finding('auth-noheaders', 'auth', 'info', 'En-têtes Internet indisponibles',
      'Les contrôles SPF/DKIM/DMARC n’ont pas pu être vérifiés (message interne ou version d’Outlook trop ancienne).'));
    return { findings, positives, auth: null, internal: false };
  }

  if (isInternalMessage(headers)) {
    positives.push('Message interne, authentifié par votre serveur Exchange');
    return { findings, positives, auth: null, internal: true };
  }

  const a = readAuthResults(headers);
  if (!a.present && !a.spf) {
    findings.push(finding('auth-missing', 'auth', 'low', 'Aucun résultat d’authentification',
      'Le message ne contient pas d’en-tête Authentication-Results : impossible de vérifier l’expéditeur.'));
    return { findings, positives, auth: a, internal: false };
  }

  if (a.dmarc === 'fail') {
    findings.push(finding('auth-dmarc', 'auth', fromCompany ? 'critical' : 'high',
      fromCompany ? 'Usurpation de votre propre domaine (DMARC en échec)' : 'Échec DMARC : l’expéditeur affiché n’est pas authentifié',
      'Le domaine affiché dans « De » n’a pas autorisé ce message. C’est le signe classique d’une usurpation.', [fromDomain]));
  }
  if (a.compauth === 'fail') {
    findings.push(finding('auth-compauth', 'auth', 'high', 'Microsoft signale une authentification composite en échec',
      'Exchange Online (compauth=fail) estime que l’expéditeur ne peut pas être authentifié.', [fromDomain]));
  }
  if (a.spf === 'fail') {
    findings.push(finding('auth-spf', 'auth', a.dmarc === 'fail' ? 'low' : 'medium', 'Échec SPF',
      'Le serveur qui a envoyé ce message n’est pas autorisé par le domaine de l’expéditeur.'));
  } else if (a.spf === 'softfail') {
    findings.push(finding('auth-spf-soft', 'auth', 'low', 'SPF « softfail »',
      'Le serveur d’envoi n’est pas clairement autorisé par le domaine de l’expéditeur.'));
  }
  if (a.dkim === 'fail') {
    findings.push(finding('auth-dkim', 'auth', 'medium', 'Signature DKIM invalide',
      'Le message a pu être modifié en chemin, ou la signature est falsifiée.'));
  }
  if (fromCompany && a.dmarc !== 'pass' && a.spf !== 'pass' && a.dkim !== 'pass') {
    findings.push(finding('auth-company-unauth', 'auth', 'critical', 'Message « interne » venant de l’extérieur',
      'L’expéditeur utilise un domaine de votre entreprise mais le message vient de l’extérieur et n’est pas authentifié.', [fromDomain]));
  }

  if (a.spf === 'pass') positives.push('SPF valide');
  if (a.dkim === 'pass') positives.push('Signature DKIM valide');
  if (a.dmarc === 'pass') positives.push('DMARC valide pour ' + (a.headerFrom || fromDomain));

  // Return-Path différent de l'expéditeur affiché : fréquent pour les newsletters, donc simple information.
  const rp = addressesIn(headerValues(headers, 'return-path')[0])[0];
  const rpOrg = registrableDomain(domainOfAddress(rp));
  if (rp && fromOrg && rpOrg && rpOrg !== fromOrg) {
    findings.push(finding('auth-returnpath', 'auth', 'info', 'Adresse de retour différente de l’expéditeur',
      'Courant pour les envois de masse (newsletters), mais à garder en tête si d’autres indices existent.', [rp]));
  }

  return { findings, positives, auth: a, internal: false };
}
