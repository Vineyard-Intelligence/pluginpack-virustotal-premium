// Bundles src/virustotal-premium.ts into dist/pack.mjs. Usage: node build.mjs
import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const here = dirname(fileURLToPath(import.meta.url));
mkdirSync(join(here, 'dist'), { recursive: true });
execFileSync('npx', ['esbuild', join(here, 'src', 'virustotal-premium.ts'),
    '--bundle', '--format=esm', '--target=es2022', '--platform=browser', '--minify',
    '--legal-comments=inline', '--log-level=warning', `--outfile=${join(here, 'dist', 'pack.mjs')}`],
    { stdio: 'inherit', cwd: here });
console.log('wrote dist/pack.mjs — run `node gen-manifest.mjs` next.');
