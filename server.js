// Serveur HTTPS de développement (Outlook exige HTTPS, même en local).
// Les certificats sont créés et approuvés par : npx office-addin-dev-certs install
//
// Usage : node server.js            → https://localhost:3000
//         PORT=3443 node server.js

import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), 'src');
const PORT = Number(process.env.PORT || 3000);
const CERT_DIR = process.env.CERT_DIR || path.join(os.homedir(), '.office-addin-dev-certs');

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.xml': 'application/xml; charset=utf-8',
};

// 1) certificat créé par tools/creer-certificat.ps1 (demarrer.bat)  2) certificat office-addin-dev-certs
const PFX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'certs', 'localhost.pfx');
let tls;
try {
  if (fs.existsSync(PFX)) {
    tls = { pfx: fs.readFileSync(PFX), passphrase: 'phishguard' };
  } else {
    tls = { key: fs.readFileSync(path.join(CERT_DIR, 'localhost.key')), cert: fs.readFileSync(path.join(CERT_DIR, 'localhost.crt')) };
  }
} catch {
  console.error(`Certificat introuvable (${PFX}).\nRelancez demarrer.bat pour le créer.`);
  process.exit(1);
}

https.createServer(tls, (req, res) => {
  const urlPath = decodeURIComponent(new URL(req.url, 'https://localhost').pathname);
  const file = path.normalize(path.join(ROOT, urlPath === '/' ? '/taskpane/taskpane.html' : urlPath));
  if (!file.startsWith(ROOT)) { res.writeHead(403).end(); return; }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }).end('404'); return; }
    res.writeHead(200, {
      'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    });
    res.end(data);
  });
}).listen(PORT, () => {
  console.log(`PhishGuard servi sur https://localhost:${PORT}/taskpane/taskpane.html`);
});
