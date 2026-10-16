// Génère le manifeste de production en remplaçant l'adresse de développement.
// Usage : node tools/build-manifest.mjs https://phishguard.mon-entreprise.fr
//      → crée manifest.prod.xml

import fs from 'node:fs';

const target = (process.argv[2] || '').replace(/\/+$/, '');
if (!/^https:\/\/[^/]+/.test(target)) {
  console.error('Indiquez l’adresse HTTPS de production, ex. : node tools/build-manifest.mjs https://phishguard.mon-entreprise.fr');
  process.exit(1);
}
const src = fs.readFileSync(new URL('../manifest.xml', import.meta.url), 'utf8');
const out = src.split('https://localhost:3000').join(target);
fs.writeFileSync(new URL('../manifest.prod.xml', import.meta.url), out);
console.log(`manifest.prod.xml généré pour ${target}`);
