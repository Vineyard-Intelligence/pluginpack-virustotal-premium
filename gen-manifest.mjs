// Regenerates plugins/virustotal-premium.manifest.json from dist/pack.mjs. Run: node gen-manifest.mjs
import { writeFileSync } from 'node:fs';
const pack = (await import('./dist/pack.mjs')).default;
const doc = { ...pack, plugins: pack.plugins.map((p) => p.manifest) };
writeFileSync(new URL('./plugins/virustotal-premium.manifest.json', import.meta.url), JSON.stringify(doc, null, 2) + '\n');
console.log(`wrote plugins/virustotal-premium.manifest.json — ${doc.plugins.length} plugins`);
