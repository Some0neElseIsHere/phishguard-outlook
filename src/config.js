// =============================================================================
//  CONFIGURATION DE L'ENTREPRISE — à adapter avant le déploiement
// =============================================================================

export const CONFIG = {
  /** Nom de l'entreprise (repéré dans le nom affiché des expéditeurs externes). */
  companyName: 'Mon Entreprise',

  /**
   * Domaines de l'entreprise. Ils sont protégés en priorité :
   * un domaine qui les imite (mon-entreprlse.fr, monentreprise.com...) est classé critique.
   */
  companyDomains: ['mon-entreprise.fr'],

  /**
   * Dirigeants et personnes sensibles (direction, comptabilité, RH).
   * Un email externe qui affiche l'un de ces noms est signalé (fraude au président).
   */
  vipNames: [
    // 'Prénom Nom',
  ],

  /** Domaines de partenaires de confiance : jamais signalés comme sosies. */
  trustedDomains: [
    // 'partenaire.fr',
  ],

  /** Adresse de l'équipe sécurité pour le bouton « Signaler ». Laisser vide pour masquer le bouton. */
  reportAddress: 'securite@mon-entreprise.fr',
};
