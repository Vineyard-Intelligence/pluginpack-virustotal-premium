// Unit tests for vt-core's boundary converters — the one place this pack turns VirusTotal's
// spellings into the type packs' (ASN, certificate fields, SSH fingerprints). No network.
//   Run: node test/core.test.mjs        (bundles src/vt-core.ts to a temp file first)
import { execFileSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { suite } from './harness.mjs';

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const out = join(mkdtempSync(join(tmpdir(), 'vt-core-')), 'vt-core.mjs');
execFileSync('npx', ['esbuild', join(root, 'src', 'vt-core.ts'), '--bundle', '--format=esm', '--platform=browser', '--log-level=warning', `--outfile=${out}`], { cwd: root });
const core = await import(pathToFileURL(out).href);
const t = suite('vt-core converters');

// ---- ASN: a bare integer in every field (infrastructure 3.0); any spelling in, the number out
for (const v of [14956, '14956', 'AS14956', 'as14956', ' AS 14956 ']) {
    t.check(`asnNumber(${JSON.stringify(v)}) → 14956`, core.asnNumber(v) === 14956);
}
for (const v of [0, 'AS0', -1, 1.5, 4294967296, 'ASX', '', null, undefined, 'AS14956 extra', {}]) {
    t.check(`asnNumber(${JSON.stringify(v)}) → null`, core.asnNumber(v) === null);
}
t.check('asnNumber: the 32-bit maximum is kept', core.asnNumber('AS4294967295') === 4294967295);

// nodeSpecFromVt writes the integer for an IP (a string is refused by the host)
{
    const spec = core.nodeSpecFromVt({ type: 'ip_address', id: '144.172.118.4', attributes: { asn: 14956, country: 'US', as_owner: 'RouterHosting LLC' } });
    t.check('ip node: asn written as the declared integer', spec.data.asn === 14956 && typeof spec.data.asn === 'number');
    t.check('core: no string-ASN helper left', !('asnLabel' in core));
    const zero = core.nodeSpecFromVt({ type: 'ip_address', id: '10.0.0.1', attributes: { asn: 0 } });
    t.check('ip node: AS0 (not routed) is not written', !('asn' in zero.data));
}

// ---- certificates: identical to the Community pack's vtCert (measured: 49.247.138.199's cert)
{
    const attrs = {
        thumbprint_sha256: '611595f46ea098519e971340ad6652f46c5e08c38e4d4fc69a28a092b15e3cfa',
        serial_number: 'bacaab0aa85cf5a0368f8d901a6c5ebd1e41a43',
        subject: { O: 'GoldTrade FX', CN: 'vpn-gw.internal.goldtrade-fx.com' },
        issuer: { O: 'GoldTrade FX', CN: 'vpn-gw.internal.goldtrade-fx.com' },
        validity: { not_after: '2029-01-05 02:47:39', not_before: '2026-10-03 02:47:39' },
        extensions: { subject_alternative_name: ['vpn-gw.internal.goldtrade-fx.com', 'gw2.goldtrade-fx.com', '*.gw2.goldtrade-fx.com', 'unifi.local', '10.0.0.1'] },
    };
    const d = core.certSpecFromVt(attrs);
    t.check('cert: thumbprint is the identity', d.fingerprint_sha256 === attrs.thumbprint_sha256);
    t.check('cert: subject_common_name (the type pack property, not subject_cn)', d.subject_common_name === 'vpn-gw.internal.goldtrade-fx.com' && !('subject_cn' in d));
    t.check("cert: issuer 'O — CN' like the Community pack", d.issuer === 'GoldTrade FX — vpn-gw.internal.goldtrade-fx.com');
    t.check('cert: serial kept as the hex string VT gives', d.serial_number === 'bacaab0aa85cf5a0368f8d901a6c5ebd1e41a43');
    t.check('cert: validity converted to ISO-8601 UTC', d.not_before === '2026-10-03T02:47:39Z' && d.not_after === '2029-01-05T02:47:39Z');
    t.check('cert: san_count counts public names only (wildcard folded, .local and IP dropped)', d.san_count === 2);
    t.check('cert: thumbprint falls back to the object id', core.certSpecFromVt({ subject: { CN: 'x.example' } }, attrs.thumbprint_sha256)?.fingerprint_sha256 === attrs.thumbprint_sha256);
    t.check('cert: no usable thumbprint → null', core.certSpecFromVt({ thumbprint_sha256: 'THUMB1' }) === null && core.certSpecFromVt({}, 'abc') === null);
    t.check('certTime: anything but VT\'s format → undefined', core.certTime('2026-10-03T02:47:39Z') === undefined && core.certTime(1791608973) === undefined);
}

// ---- SSH host keys: type pack = 64 hex, VT search = OpenSSH (measured K_A, the testbed's key)
{
    const OPENSSH = 'SHA256:93mvCQWDCdlDbpFrdWGQrQb4BKMSCsjp/x2tUsCTQbg';
    const HEX = 'f779af09058309d9436e916b756190ad06f804a3120ac8e9ff1dad52c09341b8';
    t.check('sshFpHex: OpenSSH → hex', core.sshFpHex(OPENSSH) === HEX);
    t.check('sshFpHex: bare base64 and padded base64 → hex', core.sshFpHex(OPENSSH.slice(7)) === HEX && core.sshFpHex(`${OPENSSH}=`) === HEX);
    t.check('sshFpHex: hex passes through lowercased', core.sshFpHex(HEX.toUpperCase()) === HEX);
    t.check('sshFpOpenSsh: hex → OpenSSH', core.sshFpOpenSsh(HEX) === OPENSSH);
    t.check('sshFpOpenSsh: OpenSSH round-trips', core.sshFpOpenSsh(OPENSSH) === OPENSSH);
    t.check('ssh: junk → null', core.sshFpHex('SHA256:KA') === null && core.sshFpHex('MD5:aa:bb') === null && core.sshFpOpenSsh('') === null);
}

t.report();
