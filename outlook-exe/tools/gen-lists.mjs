// Génère src/Engine/Lists.cs à partir de ../src/engine/lists.js (même contenu pour les deux versions).
import { BRANDS, MULTI_LABEL_SUFFIXES, ABUSED_HOSTING, SHORTENERS, SUSPICIOUS_TLDS, FREEMAIL_DOMAINS, ATTACHMENT_EXT } from '../../src/engine/lists.js';
import fs from 'node:fs';
import { CONTENT_RULES } from '../../src/engine/content.js';
const q = (s) => '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
const arr = (a) => 'new string[] { ' + a.map(q).join(', ') + ' }';
const set = (a) => 'new HashSet<string>(' + arr([...a]) + ')';
let out = `// FICHIER GÉNÉRÉ par tools/gen-lists.mjs à partir de src/engine/lists.js - ne pas modifier à la main.
using System.Collections.Generic;

namespace PhishGuard
{
    public class Brand
    {
        public string Name; public string[] Domains; public string[] Keywords; public string[] Names; public bool Generic;
        public Brand(string name, string[] domains, string[] keywords, string[] names, bool generic)
        { Name = name; Domains = domains; Keywords = keywords; Names = names; Generic = generic; }
    }

    public static class Lists
    {
        public static readonly Brand[] Brands = new Brand[]
        {
${BRANDS.map((b) => `            new Brand(${q(b.name)}, ${arr(b.domains)}, ${arr(b.keywords || [])}, ${arr(b.names || [])}, ${b.generic ? 'true' : 'false'})`).join(',\n')}
        };

        public static readonly HashSet<string> MultiLabelSuffixes = ${set(MULTI_LABEL_SUFFIXES)};
        public static readonly string[] AbusedHosting = ${arr(ABUSED_HOSTING)};
        public static readonly string[] Shorteners = ${arr(SHORTENERS)};
        public static readonly HashSet<string> SuspiciousTlds = ${set(SUSPICIOUS_TLDS)};
        public static readonly HashSet<string> FreemailDomains = ${set(FREEMAIL_DOMAINS)};

        public class ContentRule { public string Key; public string Label; public string[] Patterns; public ContentRule(string k, string l, string[] p) { Key = k; Label = l; Patterns = p; } }
        public static readonly ContentRule[] ContentRules = new ContentRule[]
        {
${Object.entries(CONTENT_RULES).map(([k, r]) => `            new ContentRule(${q(k)}, ${q(r.label)}, ${arr(r.patterns)})`).join(',\n')}
        };
${Object.entries(ATTACHMENT_EXT).map(([k, v]) => `        public static readonly HashSet<string> Ext${k[0].toUpperCase() + k.slice(1)} = ${set(v)};`).join('\n')}
    }
}
`;
fs.writeFileSync(new URL('../src/Engine/Lists.cs', import.meta.url), out.replace(/\n/g, '\r\n'));
console.log('Lists.cs généré');
