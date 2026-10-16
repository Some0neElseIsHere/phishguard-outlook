// Analyse du contenu (objet + corps) : urgence, demande d'identifiants, fraude au virement...
// Les expressions sont écrites sans accents : le texte est normalisé avant comparaison.

import { finding, normalizeText, headerValues } from './util.js';

export const CONTENT_RULES = {
  urgency: {
    label: 'Pression ou urgence',
    patterns: ['urgent', 'immediatement', 'sans delai', 'dans les 24 h', 'dans les 24h', 'dans les 48 h', 'dans les 48h',
      'sous 24 h', 'sous 24h', 'sous 48h', 'dernier avertissement', 'dernier rappel', 'derniere relance', 'action requise',
      'action immediate', 'expire aujourd hui', 'expirera', 'sera suspendu', 'sera supprime', 'sera desactive',
      'sera bloque', 'compte suspendu', 'compte bloque', 'acces restreint', 'avant la fin de la journee',
      'immediately', 'within 24 hours', 'within 48 hours', 'act now', 'final notice', 'final warning', 'action required',
      'account suspended', 'will be suspended', 'will be deleted', 'will be closed', 'expires today'],
  },
  credentials: {
    label: 'Demande d’identifiants',
    patterns: ['mot de passe', 'identifiant', 'identifiants', 'verifiez votre compte', 'verifier votre compte', 'confirmez votre identite',
      'confirmer votre identite', 'mettre a jour vos informations', 'mettez a jour vos informations', 'reactiver votre compte',
      'connectez-vous', 'connectez vous', 'code de verification', 'code de securite', 'authentification', 'boite mail est pleine',
      'boite aux lettres est pleine', 'quota de stockage', 'espace de stockage', 'messages en attente', 'courriers en attente',
      'verify your account', 'confirm your identity', 'update your information', 'password', 'sign in to', 'log in to',
      'mailbox is full', 'storage quota', 'pending messages', 'unusual sign-in', 'unusual activity', 'activite inhabituelle',
      'connexion inhabituelle'],
  },
  financial: {
    label: 'Demande financière ou bancaire',
    patterns: ['virement', 'rib', 'iban', 'coordonnees bancaires', 'changement de banque', 'nouveau compte bancaire',
      'nouvelles coordonnees', 'facture impayee', 'paiement en attente', 'regler la facture', 'carte cadeau', 'cartes cadeaux',
      'remboursement', 'numero de carte', 'carte bancaire', 'frais de livraison', 'frais de douane', 'amende', 'bitcoin',
      'wire transfer', 'bank details', 'gift card', 'invoice overdue', 'payment pending', 'refund', 'crypto'],
  },
  secrecy: {
    label: 'Demande de discrétion (fraude au président)',
    patterns: ['confidentiel', 'en toute discretion', 'discretion absolue', 'n en parlez a personne', 'ne pas en parler',
      'reste entre nous', 'operation confidentielle', 'es-tu disponible', 'etes-vous disponible', 'es tu disponible',
      'etes vous disponible', 'j ai besoin d un service', 'pouvez-vous me rendre un service', 'mon telephone ne marche pas',
      'je suis en reunion', 'keep this confidential', 'are you available', 'quick favor', 'i need a favor'],
  },
  lure: {
    label: 'Prétexte classique d’hameçonnage',
    patterns: ['votre colis', 'livraison en attente', 'echec de livraison', 'document partage', 'a partage un fichier',
      'a partage un document', 'message vocal', 'nouveau message vocal', 'fax recu', 'telecharger le document',
      'consulter le document', 'facture disponible', 'signature electronique', 'document a signer', 'docusign',
      'votre abonnement', 'renouvellement', 'gagnant', 'felicitations', 'vous avez gagne', 'impots', 'remboursement d impot',
      'shared a file', 'shared a document', 'voicemail', 'your package', 'delivery failed', 'review the document',
      'you have won', 'congratulations'],
  },
  qrcode: {
    label: 'Invitation à scanner un QR code',
    patterns: ['qr code', 'qrcode', 'code qr', 'scannez', 'scanner le code', 'scan the code', 'scan the qr'],
  },
};

function matchRule(text, rule) {
  const hits = [];
  for (const p of rule.patterns) {
    const re = new RegExp(`(^|[^a-z0-9])${p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}($|[^a-z0-9])`);
    if (re.test(text)) hits.push(p);
    if (hits.length >= 4) break;
  }
  return hits;
}

export function analyzeContent(email, ctx, senderMeta = {}) {
  const findings = [];
  const subject = normalizeText(email.subject);
  const body = normalizeText(email.bodyText).slice(0, 50000);
  const text = `${subject} ${body}`;

  const hits = {};
  for (const [key, rule] of Object.entries(CONTENT_RULES)) hits[key] = matchRule(text, rule);

  const add = (key, severity) => {
    if (hits[key].length) {
      findings.push(finding(`content-${key}`, 'content', severity, CONTENT_RULES[key].label, '', hits[key].map((h) => `« ${h} »`)));
    }
  };
  add('urgency', 'low');
  add('credentials', 'low');
  add('financial', 'low');
  add('secrecy', 'low');
  add('lure', 'low');
  add('qrcode', 'medium');

  // Combinaisons typiques : bien plus parlantes que les mots isolés
  if (hits.credentials.length && hits.urgency.length) {
    findings.push(finding('content-combo-cred', 'content', 'high', 'Demande d’identifiants sous pression',
      'Un vrai service ne vous demande jamais de vous reconnecter « en urgence » par email.'));
  }
  if (hits.financial.length && (hits.secrecy.length || hits.urgency.length)) {
    findings.push(finding('content-combo-bec', 'content', 'high', 'Demande de paiement urgente ou confidentielle',
      'Schéma de fraude au virement ou au président : confirmez toujours par téléphone, avec un numéro que vous connaissez.'));
  }
  if (senderMeta.isFreemail && (hits.financial.length || hits.credentials.length)) {
    findings.push(finding('content-freemail-request', 'content', 'medium', 'Demande sensible envoyée depuis une messagerie gratuite',
      'Une banque, une administration ou un fournisseur n’écrit pas depuis Gmail, Outlook.com ou Orange.'));
  }
  if (ctx.attachmentsMeta?.hasArchive && /(mot de passe|password|code)\s*:?\s*\S{3,}/.test(body)) {
    findings.push(finding('content-archive-password', 'content', 'high', 'Archive protégée avec mot de passe dans le message',
      'Technique pour empêcher l’antivirus d’analyser le contenu de l’archive.'));
  }

  // Formulaire intégré dans le message
  if (email.html?.hasPasswordInput) {
    findings.push(finding('content-form-password', 'content', 'critical', 'Champ « mot de passe » directement dans le message',
      'Aucun service légitime ne demande votre mot de passe dans le corps d’un email.'));
  } else if (email.html?.hasForm) {
    findings.push(finding('content-form', 'content', 'medium', 'Formulaire intégré dans le message', ''));
  }

  // Faux fil de discussion : "RE:" sans aucun message d'origine
  const headers = email.headers || [];
  if (headers.length && /^\s*(re|tr|fw|fwd)\s*:/i.test(email.subject || '')
      && !headerValues(headers, 'in-reply-to').length && !headerValues(headers, 'references').length) {
    findings.push(finding('content-fake-reply', 'content', 'low', 'Faux « RE: » ou « TR: »',
      'L’objet fait croire à une réponse, mais le message ne répond à aucun email existant.'));
  }

  return { findings, positives: [], meta: { hits } };
}
