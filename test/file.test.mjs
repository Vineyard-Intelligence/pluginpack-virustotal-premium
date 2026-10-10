// Mock tests for module C (src/file.ts): vt_file_network, vt_file_relatives, vt_file_behaviour.
//   Run: node test/file.test.mjs [bundle]
// Response bodies are TRIMMED copies of the measured VirusTotal Premium responses (2026-10-10,
// WannaCry ed01ebfb…41aa) in scratchpad/fixtures/<name>.json — each block names its fixture.
//
// Every run goes through hostGraph, which behaves like the app's host bridge where it matters:
// each createNode is validated against the REAL type packs (typepack-basic, mirroring
// validate-node.ts) and refused with a throw, same-identity creates merge into one node, and a second
// edge on a directed (from, to) pair is dropped as a duplicate. A plain mock let a numeric `asn`
// and a collapsed technique pass silently; this one fails the run the way the app would.
import { deepStrictEqual } from 'node:assert';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadPlugins, suite, makeGraph, makeNet, RUN, KEY, vtErr, hasEdge } from './harness.mjs';

const P = await loadPlugins();
const NET = P['run.vineyard.plugins.vt_file_network'];
const REL = P['run.vineyard.plugins.vt_file_relatives'];
const BEH = P['run.vineyard.plugins.vt_file_behaviour'];
const t = suite('module C (file network / relatives / behaviour)');

const same = (a, b) => {
    try {
        deepStrictEqual(a, b);
        return true;
    } catch {
        return false;
    }
};

// ---- the type packs the host validates against -------------------------------------------------
// VT_TYPEPACKS overrides; otherwise the nearest typepack-basic/typepacks above this file (the
// worktree and the main checkout both sit under the vineyard root).
function findTypepacks() {
    if (process.env.VT_TYPEPACKS) return process.env.VT_TYPEPACKS;
    for (let dir = dirname(fileURLToPath(import.meta.url)); ; dir = dirname(dir)) {
        const cand = join(dir, 'typepack-basic', 'typepacks');
        if (existsSync(join(cand, 'threat.json'))) return cand;
        if (dirname(dir) === dir) return null;
    }
}
const TP_DIR = findTypepacks();
t.check(`type packs found (${TP_DIR ?? 'set VT_TYPEPACKS'})`, !!TP_DIR);
const TYPES = {};
for (const f of TP_DIR ? ['infrastructure', 'threat'] : []) {
    for (const ty of JSON.parse(readFileSync(resolve(TP_DIR, `${f}.json`), 'utf8')).types) TYPES[`${ty.category}.${ty.name}`] = ty;
}

// validate-node.ts, ported: declared properties only, blanks absent, required on create.
const STRING_TYPES = new Set(['string', 'text', 'hash', 'color', 'url', 'email', 'ip', 'date', 'datetime']);
function validateNode(type, data) {
    const def = TYPES[type];
    if (!def) return `type "${type}" is not defined by any installed typepack`;
    const problems = [];
    for (const [name, value] of Object.entries(data || {})) {
        const p = def.properties?.[name];
        if (!p || value == null || value === '') continue;
        const v = typeof p.validator === 'string' ? { regex: p.validator } : p.validator;
        if (STRING_TYPES.has(p.type) && typeof value !== 'string') problems.push(`${name} is declared ${p.type}, which is a string, but got ${typeof value}`);
        else if (p.type === 'integer' && !Number.isInteger(value)) problems.push(`${name} is declared integer but got ${value}`);
        else if (p.type === 'number' && !(typeof value === 'number' && Number.isFinite(value))) problems.push(`${name} is declared number but got ${value}`);
        else if (p.type === 'boolean' && typeof value !== 'boolean') problems.push(`${name} is declared boolean but got ${value}`);
        else if (p.type === 'array' && !Array.isArray(value)) problems.push(`${name} is declared array`);
        else if (p.type === 'object' && (typeof value !== 'object' || Array.isArray(value))) problems.push(`${name} is declared object`);
        else if (p.type === 'enum' && Array.isArray(p.enum) && p.enum.length && !p.enum.includes(value)) problems.push(`${name} must be one of ${p.enum.join(', ')} — got ${value}`);
        if (v?.regex && typeof value === 'string' && value.length <= 4096 && !new RegExp(v.regex).test(value)) problems.push(`${name} does not match the format its type requires: ${value}`);
        if (typeof value === 'number' && v?.min != null && value < v.min) problems.push(`${name} must be at least ${v.min}`);
        if (typeof value === 'number' && v?.max != null && value > v.max) problems.push(`${name} must be at most ${v.max}`);
    }
    for (const [name, p] of Object.entries(def.properties || {})) {
        if (p.optional === false && (data?.[name] == null || data[name] === '')) problems.push(`${name} is required and was not set`);
    }
    return problems.length ? `${type}: ${problems.join('; ')}` : null;
}
// nodeIdentityKey, ported: type + label_property (folded when case_insensitive), else value, else name.
function identityOf(type, data) {
    const def = TYPES[type];
    const lp = def?.label_property;
    if (lp && data?.[lp] != null && data[lp] !== '') return `${type}\u0000${def.properties?.[lp]?.case_insensitive ? String(data[lp]).toLowerCase() : String(data[lp])}`;
    if (data?.value != null && data.value !== '') return `${type}\u0000${data.value}`;
    if (data?.name != null && data.name !== '') return `${type}\u0000${data.name}`;
    return null;
}
function hostGraph(seed) {
    const g = makeGraph(seed);
    const byIdentity = new Map();
    for (const n of Object.values(seed)) {
        const k = identityOf(n.type, n.data);
        if (k) byIdentity.set(k, n);
    }
    const pairs = new Set();
    g.rejected = [];
    g.duplicateEdges = [];
    const create = g.createNode;
    g.createNode = async (d) => {
        const bad = validateNode(d.type, d.data);
        if (bad) {
            g.rejected.push(bad);
            throw new Error(bad);
        }
        const k = identityOf(d.type, d.data);
        const prev = k && byIdentity.get(k);
        if (prev) {
            // mergeNodeData: incoming non-empty values overwrite, the rest is kept
            for (const [key, v] of Object.entries(d.data)) if (v != null && v !== '') prev.data = { ...prev.data, [key]: v };
            return prev;
        }
        const n = await create({ type: d.type, data: { ...d.data } });
        if (k) byIdentity.set(k, n);
        return n;
    };
    const edge = g.createEdge;
    g.createEdge = async (e) => {
        const k = `${e.from}\u0000${e.to}`;
        if (pairs.has(k)) {
            g.duplicateEdges.push(e);
            return;
        }
        pairs.add(k);
        await edge(e);
    };
    return g;
}
/** Run a plugin; a throw (a host refusal included) comes back as { error } so the checks can see it. */
const go = async (plugin, c) => {
    try {
        return await plugin.run(c);
    } catch (error) {
        return { error, counts: null, summary: '' };
    }
};
const hostClean = (graph, r) => !r.error && graph.rejected.length === 0 && graph.duplicateEdges.length === 0;

t.check('host mock: refuses a numeric asn on an IP (the type pack declares it a string)', /asn is declared string/.test(validateNode('infrastructure.ip_address', { ip_address: '1.2.3.4', asn: 24309 }) ?? ''));
t.check('host mock: refuses a malware without malware_type and an unknown tactic', !!validateNode('threat.malware', { name: 'x' }) && !!validateNode('threat.attack_pattern', { name: 'x', tactic: 'stealth' }));

const SRC = 'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa';
const SRC_MD5 = '84c82835a5d21bbcf75a61706d8ab549';
const OTHER = '109389eea7f9ed4900ba324b831a8a06e732e999e31331856ad65f1209026b1b';
const fileNode = (id, data) => ({ id, type: 'threat.file_hash', data });
const listBody = (data) => ({ status: 200, body: { data, meta: { count: data.length } } });
const relOf = (u) => u.pathname.split('/').pop();
const hashOf = (u) => u.pathname.split('/')[4];
const nodeBy = (graph, pred) => graph.createdNodes.find((n) => pred(n.data, n.type));
const noSelfLinks = (graph) => graph.createdEdges.every((e) => e.from !== e.to);
const ctx = (graph, net, selection, params = {}) => ({ ...RUN, config: KEY, input: { selection }, params, net, graph });

// ---- manifests -----------------------------------------------------------------------------
for (const [p, id, icon, labels] of [
    [NET, 'vt_file_network', 'network', ['contacts (sandbox)', 'embeds', 'distributed from (in the wild)']],
    [REL, 'vt_file_relatives', 'git-compare', ['similar to (VT)', 'executed', 'dropped', 'contains']],
    [BEH, 'vt_file_behaviour', 'activity', ['exhibits (sandbox)', 'matches YARA rule', 'matches Sigma rule', 'triggers IDS rule', 'classified as']],
]) {
    const m = p?.manifest;
    t.check(`${id}: present in the bundle`, !!m);
    if (!m) continue;
    t.check(`${id}: identifier/content_type/version`, m.identifier === `run.vineyard.plugins.${id}` && m.content_type === 'vineyard:plugin' && m.version === '0.2.0');
    t.check(`${id}: icon`, m.icon === icon);
    t.check(`${id}: description quotes every edge label`, labels.every((l) => m.description.includes(`'${l}'`)));
    t.check(`${id}: description ends with the Premium/desktop line`, m.description.endsWith('Needs a VirusTotal Premium key. Desktop only.'));
    t.check(`${id}: consumes file_hash`, same(m.io.consumes, [{ typepack: 'run.vineyard.typepacks.threat', category: 'threat', name: 'file_hash' }]));
    t.check(`${id}: GET-only VT network scope + secret api_key`, m.scopes.network.length === 1 && m.scopes.network[0].endpoint === 'https://www.virustotal.com/api/v3' && same(m.scopes.network[0].methods, ['GET']) && m.scopes.config[0].key === 'api_key' && m.scopes.config[0].secret === true);
    t.check(`${id}: desktop primary`, m.platforms.primary === 'desktop' && !!m.lifecycle);
}
t.check('network: description names the joined label for a twice-found entity', NET.manifest.description.includes("'contacts (sandbox); embeds'"));
t.check('relatives: description names the joined label for a twice-related file', REL.manifest.description.includes("'executed; contains'"));
t.check('network: produces ip/domain/url', same(NET.manifest.io.produces.map((r) => `${r.category}.${r.name}`), ['infrastructure.ip_address', 'infrastructure.domain', 'web.url']));
t.check('relatives: produces file_hash', same(REL.manifest.io.produces.map((r) => r.name), ['file_hash']));
t.check('behaviour: produces attack_pattern/signature/malware', same(BEH.manifest.io.produces.map((r) => r.name), ['attack_pattern', 'signature', 'malware']));
{
    const np = NET.manifest.params.properties;
    t.check('network params: three default-true booleans + limit 1..100 default 20', ['contacted', 'embedded', 'itw'].every((k) => np[k].type === 'boolean' && np[k].default === true && np[k].title && np[k].description) && np.limit.type === 'number' && np.limit.minimum === 1 && np.limit.maximum === 100 && np.limit.default === 20);
    const rp = REL.manifest.params.properties;
    t.check('relatives params: defaults similar/execution_parents/dropped on, compressed_parents/bundled off', rp.similar.default === true && rp.execution_parents.default === true && rp.dropped.default === true && rp.compressed_parents.default === false && rp.bundled.default === false && Object.keys(rp).filter((k) => k !== 'limit').every((k) => rp[k].type === 'boolean' && rp[k].title));
    const bp = BEH.manifest.params.properties;
    t.check('behaviour params: ids off by default, the rest on, max_per_kind 1..100 default 25', bp.mitre.default === true && bp.yara.default === true && bp.sigma.default === true && bp.ids.default === false && bp.classification.default === true && bp.max_per_kind.minimum === 1 && bp.max_per_kind.maximum === 100 && bp.max_per_kind.default === 25);
}

// =============================================================================================
// C1. vt_file_network
// =============================================================================================
const NET_RESP = {
    // file_contacted_ips.json (2 of 3)
    contacted_ips: [
        { type: 'ip_address', id: '103.16.203.232', attributes: { country: 'IN', asn: 24309, as_owner: 'Atria Convergence Technologies Pvt. Ltd. Broadband Internet Service Provider INDIA', last_analysis_stats: { malicious: 0, suspicious: 0, undetected: 38, harmless: 54 } } },
        { type: 'ip_address', id: '104.112.185.183', attributes: { country: 'US', asn: 20940, as_owner: 'Akamai International B.V.', last_analysis_stats: { malicious: 0, suspicious: 0, undetected: 38, harmless: 54 } } },
    ],
    // file_contacted_domains.json — every measured hit is the sandbox's own PTR lookup
    contacted_domains: [{ type: 'domain', id: '129.214.248.87.in-addr.arpa', attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, undetected: 41, harmless: 51 } } }],
    // file_contacted_urls.json
    contacted_urls: [{ type: 'url', id: '69b1d41239160438fedb94b898c09e6820b06260002b8deafaef94f9a4f79ff4', attributes: { url: 'http://x1.c.lencr.org/', title: '', last_http_response_code: 200, last_final_url: 'http://x1.c.lencr.org/', last_analysis_stats: { malicious: 0, suspicious: 0, undetected: 32, harmless: 61 } } }],
    // file_embedded_ips.json — measured empty
    embedded_ips: [],
    // file_embedded_domains.json
    embedded_domains: [{ type: 'domain', id: 'dn5t.aw', attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, undetected: 39, harmless: 53 } } }],
    // file_embedded_urls.json
    embedded_urls: [{ type: 'url', id: '065577ed1c151a1ef14f0e2093f879511e15f49bf074eec0793e785b5736927a', attributes: { url: 'https://outlook.com/', title: 'Microsoft Outlook Personal Email and Calendar | Microsoft 365', last_http_response_code: 200, last_final_url: 'https://www.microsoft.com/en-us/microsoft-365/outlook/email-and-calendar-software-microsoft-outlook?deeplink=%2Fmail%2F&sdf=0&sessionId=553a57ae-13e0-4f15-821c-7178c120157f', last_analysis_stats: { malicious: 1, suspicious: 0, undetected: 31, harmless: 61 } } }],
    // file_itw_ips.json
    itw_ips: [{ type: 'ip_address', id: '101.35.24.177', attributes: { country: 'CN', asn: 45090, as_owner: 'Shenzhen Tencent Computer Systems Company Limited', last_analysis_stats: { malicious: 0, suspicious: 0, undetected: 37, harmless: 55 } } }],
    // file_itw_domains.json — the second "domain" carries a path and must be dropped
    itw_domains: [
        { type: 'domain', id: '000webhostapp.com', attributes: { last_analysis_stats: { malicious: 1, suspicious: 0, undetected: 32, harmless: 59 } } },
        { type: 'domain', id: '000webhostapp.com/asacubebotnetcontrolpanel', attributes: {} },
    ],
    // file_itw_urls.json
    itw_urls: [{ type: 'url', id: '0335cb7a9874a0ece659d5840db6a2beeb991532b44b2e99086db4fb4587eef8', attributes: { url: `http://161.132.38.128/malware/${SRC}.exe`, title: '', last_http_response_code: 200, last_final_url: `http://161.132.38.128/malware/${SRC}.exe`, last_analysis_stats: { malicious: 14, suspicious: 1, undetected: 21, harmless: 57 } } }],
};
const netRespond = (overrides = {}) => (u) => {
    const rel = relOf(u);
    if (overrides[rel]) return overrides[rel];
    if (overrides[hashOf(u)]) return overrides[hashOf(u)];
    return NET_RESP[rel] ? listBody(NET_RESP[rel]) : { status: 404, body: vtErr('NotFoundError') };
};
const ALL_NET_RELS = ['contacted_ips', 'contacted_domains', 'contacted_urls', 'embedded_ips', 'embedded_domains', 'embedded_urls', 'itw_ips', 'itw_domains', 'itw_urls'];

// happy path: every relationship, exact nodes / edges / counts
{
    const net = makeNet(netRespond());
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }), x: { id: 'x', type: 'infrastructure.domain', data: { domain_name: 'ignored.example' } } });
    const r = await go(NET, ctx(graph, net, ['f', 'x']));
    t.check('network: run completes, every node passes the host type-pack check, no duplicate pairs', hostClean(graph, r));
    const rels = net.calls.map((c) => relOf(new URL(c.url)));
    t.check('network: reads all nine relationships under /files/<sha256>', same(rels, ALL_NET_RELS) && net.calls.every((c) => new URL(c.url).pathname.startsWith(`/api/v3/files/${SRC}/`)));
    t.check('network: default limit 20 on every call', net.calls.every((c) => new URL(c.url).searchParams.get('limit') === '20'));
    t.check('network: key only in the x-apikey header', net.calls.every((c) => c.headers['x-apikey'] === 'k' && !/apikey|k=k/i.test(new URL(c.url).search)));
    const ip = nodeBy(graph, (d) => d.ip_address === '103.16.203.232');
    t.check("network: IP node mapped exactly (asn as the type pack's string 'AS24309')", ip?.type === 'infrastructure.ip_address' && same(ip.data, { ip_address: '103.16.203.232', country_code: 'IN', asn: 'AS24309', organization: 'Atria Convergence Technologies Pvt. Ltd. Broadband Internet Service Provider INDIA', vt_malicious: 0, vt_suspicious: 0, vt_harmless: 54, vt_undetected: 38 }));
    const dom = nodeBy(graph, (d) => d.domain_name === 'dn5t.aw');
    t.check('network: domain node mapped exactly', dom?.type === 'infrastructure.domain' && same(dom.data, { domain_name: 'dn5t.aw', vt_malicious: 0, vt_suspicious: 0, vt_harmless: 53, vt_undetected: 39 }));
    const url = nodeBy(graph, (d) => d.url === 'https://outlook.com/');
    t.check('network: URL node mapped exactly (title, status, final_url)', url?.type === 'web.url' && same(url.data, { url: 'https://outlook.com/', page_title: 'Microsoft Outlook Personal Email and Calendar | Microsoft 365', http_status: 200, final_url: NET_RESP.embedded_urls[0].attributes.last_final_url, vt_malicious: 1, vt_suspicious: 0, vt_harmless: 61, vt_undetected: 31 }));
    t.check('network: in-addr.arpa PTR name dropped', !graph.createdNodes.some((n) => /in-addr\.arpa/.test(String(n.data.domain_name))));
    t.check('network: path-carrying pseudo-domain dropped', !graph.createdNodes.some((n) => String(n.data.domain_name ?? '').includes('/')));
    const id = (pred) => nodeBy(graph, pred)?.id;
    t.check("network: contacted IP linked file → ip 'contacts (sandbox)'", hasEdge(graph, 'f', id((d) => d.ip_address === '104.112.185.183'), 'contacts (sandbox)'));
    t.check("network: contacted URL linked 'contacts (sandbox)'", hasEdge(graph, 'f', id((d) => d.url === 'http://x1.c.lencr.org/'), 'contacts (sandbox)'));
    t.check("network: embedded domain + URL linked 'embeds'", hasEdge(graph, 'f', dom?.id, 'embeds') && hasEdge(graph, 'f', url?.id, 'embeds'));
    t.check("network: itw IP/domain/URL linked 'distributed from (in the wild)'", ['101.35.24.177', '000webhostapp.com', `http://161.132.38.128/malware/${SRC}.exe`].every((v) => hasEdge(graph, 'f', id((d) => d.ip_address === v || d.domain_name === v || d.url === v), 'distributed from (in the wild)')));
    t.check('network: every edge starts at the file', graph.createdEdges.length === 8 && graph.createdEdges.every((e) => e.from === 'f'));
    t.check('network: counts', same(r.counts, { checked: 1, contacted: 3, embedded: 2, itw: 3, ips: 3, domains: 2, urls: 3, misses: 0 }));
    t.check('network: summary', r.summary === '1 file(s): 3 contacted, 2 embedded, 3 in-the-wild link(s) — 3 IP(s), 2 domain(s), 3 URL(s)');
    t.check('network: no self-links', noSelfLinks(graph));
}
// one entity in two groups: ONE edge naming both (the host keeps one edge per directed pair).
// Synthetic overlap built from measured objects: the contacted IP also listed as embedded, the
// in-the-wild domain also listed as embedded.
{
    const resp = { embedded_ips: listBody([NET_RESP.contacted_ips[0]]), embedded_domains: listBody([...NET_RESP.embedded_domains, NET_RESP.itw_domains[0]]) };
    const net = makeNet(netRespond(resp));
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    const r = await go(NET, ctx(graph, net, ['f']));
    t.check('network overlap: run clean, no second create on any pair', hostClean(graph, r));
    const ip = nodeBy(graph, (d) => d.ip_address === '103.16.203.232');
    const dom = nodeBy(graph, (d) => d.domain_name === '000webhostapp.com');
    t.check("network overlap: contacted + embedded IP → one edge 'contacts (sandbox); embeds'", graph.createdEdges.filter((e) => e.to === ip?.id).length === 1 && hasEdge(graph, 'f', ip?.id, 'contacts (sandbox); embeds'));
    t.check("network overlap: embedded + in-the-wild domain → one edge 'embeds; distributed from (in the wild)'", graph.createdEdges.filter((e) => e.to === dom?.id).length === 1 && hasEdge(graph, 'f', dom?.id, 'embeds; distributed from (in the wild)'));
    t.check('network overlap: one edge per distinct entity (8)', graph.createdEdges.length === 8);
    t.check('network overlap: each group counts the entity, the kinds count it once', same(r.counts, { checked: 1, contacted: 3, embedded: 4, itw: 3, ips: 3, domains: 2, urls: 3, misses: 0 }));
}
// booleans off + limit param
{
    const net = makeNet(netRespond());
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    const r = await go(NET, ctx(graph, net, ['f'], { contacted: false, itw: false, limit: 5 }));
    t.check('network: contacted/itw off → only embedded_* read', same(net.calls.map((c) => relOf(new URL(c.url))), ['embedded_ips', 'embedded_domains', 'embedded_urls']));
    t.check('network: limit param reaches the request', net.calls.every((c) => new URL(c.url).searchParams.get('limit') === '5'));
    t.check('network: counts with two groups off', same(r.counts, { checked: 1, contacted: 0, embedded: 2, itw: 0, ips: 0, domains: 1, urls: 1, misses: 0 }));
    t.check("network: no 'contacts (sandbox)' / in-the-wild edges", graph.createdEdges.length === 2 && graph.createdEdges.every((e) => e.label === 'embeds'));
}
{
    const net = makeNet(netRespond());
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    const r = await go(NET, ctx(graph, net, ['f'], { embedded: false, contacted: false }));
    t.check('network: only itw on → only itw_* read, only in-the-wild edges', same(net.calls.map((c) => relOf(new URL(c.url))), ['itw_ips', 'itw_domains', 'itw_urls']) && graph.createdEdges.length === 3 && graph.createdEdges.every((e) => e.label === 'distributed from (in the wild)') && r.counts.itw === 3);
}
{
    const net = makeNet(netRespond());
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    await go(NET, ctx(graph, net, ['f'], { embedded: false, itw: false, limit: 500 }));
    t.check('network: limit clamps to 100 (paged at 40)', net.calls.length === 3 && net.calls.every((c) => new URL(c.url).searchParams.get('limit') === '40'));
}
// 403 on one relationship skips only that one
{
    const net = makeNet(netRespond({ contacted_urls: { status: 403, body: vtErr('ForbiddenError') } }));
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    const r = await go(NET, ctx(graph, net, ['f']));
    t.check('network: 403 on contacted_urls → counted miss, other eight still read', net.calls.length === 9 && r.counts?.misses === 1 && r.counts.contacted === 2 && r.counts.embedded === 2 && r.counts.itw === 3);
    t.check('network: nothing from the refused relationship', !graph.createdNodes.some((n) => n.data.url === 'http://x1.c.lencr.org/'));
    t.check('network: summary names the miss', /1 miss/.test(r.summary));
}
// 400 on a middle relationship: that one is lost, the later ones are still read
{
    const net = makeNet(netRespond({ embedded_domains: { status: 400, body: vtErr('InvalidArgumentError') } }));
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    const r = await go(NET, ctx(graph, net, ['f']));
    t.check('network: 400 on embedded_domains → one miss, all nine read', same(net.calls.map((c) => relOf(new URL(c.url))), ALL_NET_RELS) && r.counts?.misses === 1);
    t.check('network: relationships after the 400 still land', same(r.counts, { checked: 1, contacted: 3, embedded: 1, itw: 3, ips: 3, domains: 1, urls: 3, misses: 1 }) && !graph.createdNodes.some((n) => n.data.domain_name === 'dn5t.aw'));
}
// 404 on a later relationship after earlier reads proved the file exists: skip, not stop
{
    const net = makeNet(netRespond({ contacted_urls: { status: 404, body: vtErr('NotFoundError') } }));
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    const r = await go(NET, ctx(graph, net, ['f']));
    t.check('network: 404 after a successful read skips only that relationship', net.calls.length === 9 && r.counts?.misses === 1 && r.counts.embedded === 2 && r.counts.itw === 3);
}
// 404 node (VT has no such file): one request, then the next file still runs
{
    const UNKNOWN = 'a'.repeat(64);
    const net = makeNet(netRespond({ [UNKNOWN]: { status: 404, body: vtErr('NotFoundError') } }));
    const graph = hostGraph({ u: fileNode('u', { sha256: UNKNOWN }), f: fileNode('f', { sha256: SRC }) });
    const r = await go(NET, ctx(graph, net, ['u', 'f']));
    t.check('network: 404 file costs one request and one miss', net.calls.filter((c) => hashOf(new URL(c.url)) === UNKNOWN).length === 1 && r.counts?.misses === 1);
    t.check('network: the next file is still read in full', r.counts?.checked === 2 && net.calls.filter((c) => hashOf(new URL(c.url)) === SRC).length === 9 && r.counts.itw === 3);
    t.check('network: nothing linked to the unknown file', !graph.createdEdges.some((e) => e.from === 'u' || e.to === 'u'));
}
// a node with no usable hash is not checked and costs no request
{
    const net = makeNet(netRespond());
    const graph = hostGraph({ b: fileNode('b', { sha256: 'not-a-hash' }) });
    const r = await go(NET, ctx(graph, net, ['b']));
    t.check('network: node without a valid hash skipped, no request', net.calls.length === 0 && r.counts?.checked === 0);
}
// a non-VT error (401) ends the run
{
    const net = makeNet(() => ({ status: 401, body: vtErr('WrongCredentialsError') }));
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    const r = await go(NET, ctx(graph, net, ['f']));
    t.check('network: 401 rethrows (not swallowed as a miss)', !!r.error && /rejected this API key/.test(r.error.message));
}

// =============================================================================================
// C2. vt_file_relatives
// =============================================================================================
const F = {
    // file_similar_files.json — the first hit IS the source file
    self: { type: 'file', id: SRC, attributes: { sha256: SRC, sha1: '5ff465afaabcbf0150d1a3ab2c2e74f3a4426467', md5: SRC_MD5, size: 3514368, type_description: 'Win32 EXE', meaningful_name: 'diskpart.exe', last_analysis_stats: { malicious: 68, suspicious: 0, undetected: 4, harmless: 0 }, times_submitted: 29430, first_submission_date: 1494574270 } },
    tasksche: { type: 'file', id: OTHER, attributes: { sha256: OTHER, sha1: 'e9e093e055d55127c900542228d56ad6656b1c8e', md5: '10d37df6dbc4a62f3872a1302e284201', size: 3514368, type_description: 'Win32 EXE', meaningful_name: 'C:\\Windows\\tasksche.exe', last_analysis_stats: { malicious: 63, suspicious: 0, undetected: 9, harmless: 0 }, times_submitted: 1, first_submission_date: 1791598980, tags: ['exploit', 'cve-2017-0147', 'peexe', 'payload'] } },
    sim2: { type: 'file', id: '2f0e80333daf2c11e76ddd758ef400c465d8b2b037838796f4ef0bd9e6f67be9', attributes: { sha256: '2f0e80333daf2c11e76ddd758ef400c465d8b2b037838796f4ef0bd9e6f67be9', sha1: '88e3628e2fdbcccfe79decdf3657cf2a16376fe2', md5: '48b818f9b7b8244fe5fb5440ba00df6e', size: 3514368, type_description: 'Win32 EXE', last_analysis_stats: { malicious: 63, suspicious: 0, undetected: 9, harmless: 0 }, times_submitted: 1, first_submission_date: 1791592451 } },
    // file_execution_parents.json
    rar: { type: 'file', id: '00483be3ba0a131f09008a488325cc6061450123a85b01409a508537339c7af7', attributes: { sha256: '00483be3ba0a131f09008a488325cc6061450123a85b01409a508537339c7af7', sha1: 'adf2bd1a84af5a1dba2a5c53b99d5fb782ae8f2a', md5: 'a72ac07026eb610f97bb0a05d0565b4c', size: 3484637, type_description: 'RAR', last_analysis_stats: { malicious: 49, suspicious: 0, undetected: 12, harmless: 0 } } },
    // an unreported hash as relationships list it (measured by module A on host relationships): no attributes
    unreported: { type: 'file', id: '0000000000000000000000000000000010000000000000000000000000000000', error: { code: 'NotFoundError' } },
    // file_dropped_files.json
    lnk: { type: 'file', id: '0032a8d1d526430147b33583b62f0b736d1bd9bc92d0d149e24822f5909e1d08', attributes: { sha256: '0032a8d1d526430147b33583b62f0b736d1bd9bc92d0d149e24822f5909e1d08', md5: 'b54146c7c7a433de2c3f230804c25743', size: 577, type_description: 'Windows shortcut', meaningful_name: 'C:\\ProgramData\\Microsoft\\AppV\\Setup\\@WanaDecryptor@.exe.lnk' } },
    // file_compressed_parents.json
    zip: { type: 'file', id: 'a897345b68191fd36f8cefb52e6a77acb2367432abb648b9ae0a9d708406de5b', attributes: { sha256: 'a897345b68191fd36f8cefb52e6a77acb2367432abb648b9ae0a9d708406de5b', size: 3481530, type_description: 'ZIP' } },
    // file_bundled_files.json is measured EMPTY for this sample; a bundled hit is the same file object
    // shape, so a measured dropped-file object (file_dropped_files.json) stands in for one.
    bundled: { type: 'file', id: '0053042ff3c11085ad0fc076520501e721e0246ae2cc8bc4fcd4aa56482c63ce', attributes: { sha256: '0053042ff3c11085ad0fc076520501e721e0246ae2cc8bc4fcd4aa56482c63ce', size: 1026, type_description: 'DOS EXE' } },
};
const REL_RESP = {
    similar_files: [F.self, F.tasksche, F.sim2],
    execution_parents: [F.rar, F.unreported],
    dropped_files: [F.lnk],
    compressed_parents: [F.zip],
    bundled_files: [F.bundled],
};
const relRespond = (overrides = {}) => (u) => {
    const rel = relOf(u);
    if (overrides[rel]) return overrides[rel];
    if (overrides[hashOf(u)]) return overrides[hashOf(u)];
    return REL_RESP[rel] ? listBody(REL_RESP[rel]) : { status: 404, body: vtErr('NotFoundError') };
};

// defaults; the source is selected with an UPPER-CASE sha256 (self-hit must still be recognised)
{
    const net = makeNet(relRespond());
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC.toUpperCase() }) });
    const r = await go(REL, ctx(graph, net, ['f']));
    t.check('relatives: run completes, every file node passes the host type-pack check, no duplicate pairs', hostClean(graph, r));
    t.check('relatives: defaults read similar_files, execution_parents, dropped_files', same(net.calls.map((c) => relOf(new URL(c.url))), ['similar_files', 'execution_parents', 'dropped_files']));
    t.check('relatives: the source file itself is never minted or linked (case-insensitive sha256)', !graph.createdNodes.some((n) => n.data.sha256 === SRC) && noSelfLinks(graph));
    const ts = nodeBy(graph, (d) => d.sha256 === OTHER);
    t.check('relatives: file node mapped exactly', ts?.type === 'threat.file_hash' && same(ts.data, { sha256: OTHER, sha1: 'e9e093e055d55127c900542228d56ad6656b1c8e', md5: '10d37df6dbc4a62f3872a1302e284201', size: 3514368, type_description: 'Win32 EXE', tags: 'exploit, cve-2017-0147, peexe, payload', malicious_count: 63, suspicious_count: 0, undetected_count: 9, times_submitted: 1, first_seen: new Date(1791598980 * 1000).toISOString(), vt_name: 'C:\\Windows\\tasksche.exe' }));
    t.check("relatives: similar hit → source 'similar to (VT)'", hasEdge(graph, ts?.id, 'f', 'similar to (VT)') && hasEdge(graph, nodeBy(graph, (d) => d.sha256 === F.sim2.id)?.id, 'f', 'similar to (VT)'));
    t.check("relatives: execution parent → source 'executed'", hasEdge(graph, nodeBy(graph, (d) => d.sha256 === F.rar.id)?.id, 'f', 'executed'));
    t.check('relatives: object without attributes (unreported hash) skipped', !graph.createdNodes.some((n) => n.data.sha256 === F.unreported.id));
    t.check("relatives: source → dropped child 'dropped'", hasEdge(graph, 'f', nodeBy(graph, (d) => d.sha256 === F.lnk.id)?.id, 'dropped'));
    t.check('relatives: one edge per related file (4)', graph.createdEdges.length === 4);
    t.check('relatives: counts', same(r.counts, { checked: 1, similar: 2, parents: 1, dropped: 1, compressed_parents: 0, bundled: 0, misses: 0 }));
    t.check('relatives: summary', r.summary === '1 file(s): 2 similar, 1 execution parent(s), 1 dropped');
}
// the default-off pair on, the default-on three off
{
    const net = makeNet(relRespond());
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    const r = await go(REL, ctx(graph, net, ['f'], { similar: false, execution_parents: false, dropped: false, compressed_parents: true, bundled: true }));
    t.check('relatives: booleans flip which relationships are read', same(net.calls.map((c) => relOf(new URL(c.url))), ['compressed_parents', 'bundled_files']));
    t.check("relatives: compressed parent → source 'contains'", hasEdge(graph, nodeBy(graph, (d) => d.sha256 === F.zip.id)?.id, 'f', 'contains'));
    t.check("relatives: source → bundled child 'contains'", hasEdge(graph, 'f', nodeBy(graph, (d) => d.sha256 === F.bundled.id)?.id, 'contains'));
    t.check('relatives: counts with the off-by-default pair', same(r.counts, { checked: 1, similar: 0, parents: 0, dropped: 0, compressed_parents: 1, bundled: 1, misses: 0 }));
    t.check('relatives: summary lists the extra kinds', /1 compressed parent\(s\), 1 bundled/.test(r.summary));
}
// one file related two ways. Synthetic overlap built from measured objects: the RAR execution
// parent also listed as a compressed parent (same direction → ONE edge naming both), and tasksche
// also listed as dropped (opposite direction → its own edge).
{
    const net = makeNet(relRespond({ compressed_parents: listBody([F.zip, F.rar]), dropped_files: listBody([F.lnk, F.tasksche]) }));
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    const r = await go(REL, ctx(graph, net, ['f'], { compressed_parents: true }));
    t.check('relatives overlap: run clean, no second create on any pair', hostClean(graph, r));
    const rar = nodeBy(graph, (d) => d.sha256 === F.rar.id);
    const ts = nodeBy(graph, (d) => d.sha256 === OTHER);
    t.check("relatives overlap: execution + compressed parent → one edge 'executed; contains'", graph.createdEdges.filter((e) => e.from === rar?.id).length === 1 && hasEdge(graph, rar?.id, 'f', 'executed; contains'));
    t.check("relatives overlap: similar AND dropped → two edges, one each way", hasEdge(graph, ts?.id, 'f', 'similar to (VT)') && hasEdge(graph, 'f', ts?.id, 'dropped'));
    t.check('relatives overlap: every relationship counts its file', same(r.counts, { checked: 1, similar: 2, parents: 1, dropped: 2, compressed_parents: 2, bundled: 0, misses: 0 }));
}
// selected by MD5 only: path uses the md5, and the self-hit is still recognised by md5
{
    const net = makeNet(relRespond());
    const graph = hostGraph({ m: fileNode('m', { md5: SRC_MD5 }) });
    const r = await go(REL, ctx(graph, net, ['m'], { execution_parents: false, dropped: false }));
    t.check('relatives: md5-only node reads /files/<md5>/similar_files', net.calls.length === 1 && new URL(net.calls[0].url).pathname === `/api/v3/files/${SRC_MD5}/similar_files`);
    t.check('relatives: md5-only node never linked to its own sha256 twin', !graph.createdNodes.some((n) => n.data.sha256 === SRC) && r.counts?.similar === 2 && noSelfLinks(graph));
}
// limit param
{
    const net = makeNet(relRespond());
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    await go(REL, ctx(graph, net, ['f'], { limit: 3 }));
    t.check('relatives: limit param reaches the request', net.calls.every((c) => new URL(c.url).searchParams.get('limit') === '3'));
}
// 403 on one relationship
{
    const net = makeNet(relRespond({ execution_parents: { status: 403, body: vtErr('ForbiddenError') } }));
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    const r = await go(REL, ctx(graph, net, ['f']));
    t.check('relatives: 403 on execution_parents → miss, similar + dropped still added', net.calls.length === 3 && r.counts?.misses === 1 && r.counts.parents === 0 && r.counts.similar === 2 && r.counts.dropped === 1);
}
// 404 on a later relationship once the file is known to exist: only that one is skipped
{
    const net = makeNet(relRespond({ execution_parents: { status: 404, body: vtErr('NotFoundError') } }));
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    const r = await go(REL, ctx(graph, net, ['f']));
    t.check('relatives: 404 after a successful read → miss, dropped_files still read', net.calls.length === 3 && r.counts?.misses === 1 && r.counts.similar === 2 && r.counts.dropped === 1);
}
// 404 node
{
    const UNKNOWN = 'b'.repeat(64);
    const net = makeNet(relRespond({ [UNKNOWN]: { status: 404, body: vtErr('NotFoundError') } }));
    const graph = hostGraph({ u: fileNode('u', { sha256: UNKNOWN }), f: fileNode('f', { sha256: SRC }) });
    const r = await go(REL, ctx(graph, net, ['u', 'f']));
    t.check('relatives: 404 file costs one request and one miss; next file still read', net.calls.filter((c) => hashOf(new URL(c.url)) === UNKNOWN).length === 1 && r.counts?.misses === 1 && r.counts.checked === 2 && r.counts.similar === 2);
    t.check('relatives: no self-links', noSelfLinks(graph));
}

// =============================================================================================
// C3. vt_file_behaviour
// =============================================================================================
// file_report.json — trimmed to the fields vt_file_behaviour reads
const T1129_DESC =
    'Adversaries may execute malicious payloads via loading shared modules. Shared modules are executable files that are loaded into processes to provide access to reusable code, such as specific custom functions or invoking OS API functions (i.e., Native API).\nAdversaries may use this functionality as a way to execute arbitrary payloads on a victim system.';
const REPORT = {
    data: {
        type: 'file',
        id: SRC,
        attributes: {
            sha256: SRC,
            popular_threat_classification: {
                popular_threat_name: [{ count: 12, value: 'wannacry' }, { count: 6, value: 'wannacryptor' }, { count: 5, value: 'wanna' }],
                suggested_threat_label: 'ransomware.wannacry/wannacryptor',
                popular_threat_category: [{ count: 29, value: 'ransomware' }, { count: 27, value: 'trojan' }],
            },
            sandbox_verdicts: {
                'NSFOCUS POMA': { category: 'malicious', sandbox_name: 'NSFOCUS POMA', malware_classification: ['TROJAN', 'RANSOM'] },
                'Dr.Web vxCube': { category: 'malicious', sandbox_name: 'Dr.Web vxCube', malware_classification: ['MALWARE'] },
                Zenbox: { category: 'malicious', malware_classification: ['MALWARE', 'RANSOM'], sandbox_name: 'Zenbox', malware_names: ['Wannacry'], confidence: 60 },
            },
            crowdsourced_yara_results: [
                { ruleset_id: '000fd39f0d', rule_name: 'WannaCry_Ransomware', ruleset_name: 'crime_wannacry', description: 'Detects WannaCry Ransomware', author: 'Florian Roth (Nextron Systems) (with the help of binar.ly)', source: 'https://github.com/Neo23x0/signature-base' },
                { ruleset_id: '0056142681', rule_name: 'Win32_Ransomware_WannaCry', ruleset_name: 'Win32.Ransomware.WannaCry', description: 'Yara rule that detects WannaCry ransomware.', author: 'ReversingLabs', source: 'https://github.com/reversinglabs/reversinglabs-yara-rules' },
            ],
            // entries 0, 1, 2, 14, 15 (a duplicate title) and 17 of the measured 18
            sigma_analysis_results: [
                { rule_level: 'critical', rule_source: 'Joe Security Rule Set (GitHub)', rule_title: 'Add file from suspicious location to autostart registry', rule_description: 'Add file from suspicious location to autostart registry' },
                { rule_level: 'critical', rule_source: 'Sigma Integrated Rule Set (GitHub)', rule_title: 'WannaCry Ransomware Activity', rule_description: 'Detects WannaCry ransomware activity' },
                { rule_level: 'critical', rule_source: 'Joe Security Rule Set (GitHub)', rule_title: 'Delete shadow copy via WMIC', rule_description: 'Delete shadow copy via WMIC' },
                { rule_level: 'medium', rule_source: 'Sigma Integrated Rule Set (GitHub)', rule_title: 'Direct Autorun Keys Modification', rule_description: 'Detects direct modification of autostart extensibility point (ASEP) in registry using reg.exe.' },
                { rule_level: 'medium', rule_source: 'Sigma Integrated Rule Set (GitHub)', rule_title: 'Direct Autorun Keys Modification', rule_description: 'Detects direct modification of autostart extensibility point (ASEP) in registry using reg.exe.' },
                { rule_level: 'low', rule_source: 'Sigma Integrated Rule Set (GitHub)', rule_title: 'Creation of an Executable by an Executable', rule_description: 'Detects the creation of an executable by another executable.' },
            ],
            // entries 0, 3, 19, 20 (a duplicate message) and 127 of the measured 130
            crowdsourced_ids_results: [
                { rule_category: 'attempted-recon', alert_severity: 'medium', rule_msg: '(icmp4) ICMP destination unreachable communication administratively prohibited', rule_id: '116:441', rule_source: 'Snort registered user ruleset' },
                { rule_category: 'Misc Attack', alert_severity: 'medium', rule_msg: 'ET TOR Known Tor Exit Node Traffic group 30', rule_id: '1:2520029', rule_source: 'Proofpoint Emerging Threats Open' },
                { alert_severity: 'medium', rule_msg: 'ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 160', rule_id: '1:2522159', rule_source: 'Proofpoint Emerging Threats Open' },
                { alert_severity: 'medium', rule_msg: 'ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 160', rule_id: '1:2522159', rule_source: 'Proofpoint Emerging Threats Open' },
                { alert_severity: 'low', rule_msg: 'PROTOCOL-ICMP Destination Unreachable Host Unreachable', rule_id: '1:399', rule_source: 'Snort registered user ruleset' },
            ],
        },
    },
};
// file_behaviour_mitre_trees.json — CAPA, Zenbox and CAPE Sandbox, a few techniques each
const tech = (id, name, description = '') => ({ id, name, link: `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`, description });
const MITRE = {
    data: {
        CAPA: {
            tactics: [
                { id: 'TA0002', name: 'Execution', techniques: [tech('T1129', 'Shared Modules', T1129_DESC)] },
                { id: 'TA0007', name: 'Discovery', techniques: [tech('T1082', 'System Information Discovery')] },
                { id: 'TA0005', name: 'Stealth', techniques: [tech('T1027', 'Obfuscated Files or Information')] },
                { id: 'TA0003', name: 'Persistence', techniques: [tech('T1543', 'Create or Modify System Process'), tech('T1543.003', 'Windows Service')] },
                { id: 'TA0004', name: 'Privilege Escalation', techniques: [tech('T1543', 'Create or Modify System Process'), tech('T1543.003', 'Windows Service')] },
            ],
        },
        Zenbox: {
            tactics: [
                { id: 'TA0007', name: 'Discovery', techniques: [tech('T1082', 'System Information Discovery')] },
                { id: 'TA0040', name: 'Impact', techniques: [tech('T1486', 'Data Encrypted for Impact')] },
                { id: 'TA0112', name: 'Defense Impairment', techniques: [tech('T1222', 'File and Directory Permissions Modification')] },
            ],
        },
        'CAPE Sandbox': {
            tactics: [
                { id: 'TA0007', name: 'Discovery', techniques: [tech('T1082', 'System Information Discovery')] },
                { id: 'TA0040', name: 'Impact', techniques: [tech('T1486', 'Data Encrypted for Impact')] },
            ],
        },
    },
};
// file_behaviour_mitre_trees.json — every technique the measured trees name under TWO IDs: Yomi
// Hunter reports the IDs ATT&CK retired into sub-techniques (T1060, T1158, T1107, T1081), the other
// sandboxes the current ones. Descriptions trimmed to their opening words.
const HIDDEN_NEW = 'Adversaries may set files and directories to be hidden to evade detection mechanisms.';
const HIDDEN_OLD = 'To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a hidden file.';
const MITRE_RETIRED = {
    data: {
        'CAPE Sandbox': {
            tactics: [
                { id: 'TA0006', name: 'Credential Access', techniques: [tech('T1552.001', 'Credentials In Files', 'Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials.')] },
                { id: 'TA0003', name: 'Persistence', techniques: [tech('T1547.001', 'Registry Run Keys / Startup Folder', 'Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.')] },
                { id: 'TA0004', name: 'Privilege Escalation', techniques: [tech('T1547.001', 'Registry Run Keys / Startup Folder', 'Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.')] },
            ],
        },
        'Yomi Hunter': {
            tactics: [
                { id: 'TA0005', name: 'Stealth', techniques: [tech('T1107', 'File Deletion', 'Adversaries may delete files left behind by the actions of their intrusion activity.'), tech('T1158', 'Hidden Files and Directories', HIDDEN_OLD)] },
                { id: 'TA0006', name: 'Credential Access', techniques: [tech('T1081', 'Credentials in Files', 'Adversaries may search local file systems and remote file shares for files containing passwords.')] },
                { id: 'TA0003', name: 'Persistence', techniques: [tech('T1158', 'Hidden Files and Directories', HIDDEN_OLD), tech('T1060', 'Registry Run Keys / Startup Folder', 'Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.')] },
            ],
        },
        Zenbox: {
            tactics: [
                { id: 'TA0005', name: 'Stealth', techniques: [tech('T1070.004', 'File Deletion', 'Adversaries may delete files left behind by the actions of their intrusion activity.'), tech('T1564.001', 'Hidden Files and Directories', HIDDEN_NEW)] },
                { id: 'TA0004', name: 'Privilege Escalation', techniques: [tech('T1547.001', 'Registry Run Keys / Startup Folder')] },
                { id: 'TA0003', name: 'Persistence', techniques: [tech('T1547.001', 'Registry Run Keys / Startup Folder')] },
            ],
        },
    },
};
// Yomi Hunter's tree alone (same fixture): only the retired IDs
const MITRE_YOMI_ONLY = { data: { 'Yomi Hunter': MITRE_RETIRED.data['Yomi Hunter'] } };

const behRespond = (overrides = {}) => (u) => {
    const rel = relOf(u);
    const isReport = u.pathname === `/api/v3/files/${hashOf(u)}`;
    if (isReport && overrides.report) return overrides.report;
    if (!isReport && overrides[rel]) return overrides[rel];
    if (overrides[hashOf(u)]) return overrides[hashOf(u)];
    if (rel === 'behaviour_mitre_trees') return { status: 200, body: MITRE };
    if (isReport) return { status: 200, body: REPORT };
    return { status: 404, body: vtErr('NotFoundError') };
};
const sigs = (graph, type) => graph.createdNodes.filter((n) => n.type === 'threat.signature' && (type === undefined || n.data.signature_type === type));
const techsOf = (graph) => graph.createdNodes.filter((n) => n.type === 'threat.attack_pattern');

// defaults: mitre + yara + sigma + classification, ids off
{
    const net = makeNet(behRespond());
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    const r = await go(BEH, ctx(graph, net, ['f']));
    t.check('behaviour: run completes, every node passes the host type-pack check, no duplicate pairs', hostClean(graph, r));
    t.check('behaviour: two GETs — the report and behaviour_mitre_trees', same(net.calls.map((c) => new URL(c.url).pathname), [`/api/v3/files/${SRC}`, `/api/v3/files/${SRC}/behaviour_mitre_trees`]));
    const techs = techsOf(graph);
    t.check('behaviour: techniques deduped across sandboxes by ID (7 distinct)', techs.length === 7 && new Set(techs.map((n) => n.data.technique_id)).size === 7);
    t.check('behaviour: most-corroborated technique first (T1082 ×3, T1486 ×2)', techs[0]?.data.technique_id === 'T1082' && techs[1]?.data.technique_id === 'T1486');
    const t1129 = techs.find((n) => n.data.technique_id === 'T1129');
    t.check('behaviour: technique node exact (name, id, tactic, vt_tactics, 300-char description)', same(t1129?.data, { name: 'Shared Modules', technique_id: 'T1129', tactic: 'execution', vt_tactics: 'Execution', description: T1129_DESC.slice(0, 300) }));
    const t1543 = techs.find((n) => n.data.technique_id === 'T1543');
    t.check('behaviour: multi-tactic technique → first tactic in the enum, all names in vt_tactics', t1543?.data.tactic === 'persistence' && t1543?.data.vt_tactics === 'Persistence, Privilege Escalation');
    t.check("behaviour: 'Stealth' (TA0005) and 'Defense Impairment' (TA0112) map to defense-evasion", techs.find((n) => n.data.technique_id === 'T1027')?.data.tactic === 'defense-evasion' && techs.find((n) => n.data.technique_id === 'T1222')?.data.tactic === 'defense-evasion' && techs.find((n) => n.data.technique_id === 'T1222')?.data.vt_tactics === 'Defense Impairment');
    t.check('behaviour: a technique under one ID carries no vt_technique_ids', techs.every((n) => !('vt_technique_ids' in n.data)));
    t.check("behaviour: file → technique 'exhibits (sandbox)'", techs.every((n) => hasEdge(graph, 'f', n.id, 'exhibits (sandbox)')));
    const yara = sigs(graph, 'yara');
    t.check('behaviour: YARA signature exact', yara.length === 2 && same(yara[0].data, { name: 'WannaCry_Ransomware', signature_type: 'yara', rule: 'crime_wannacry', description: 'Detects WannaCry Ransomware — Florian Roth (Nextron Systems) (with the help of binar.ly)' }));
    t.check("behaviour: file → YARA rule 'matches YARA rule'", yara.every((n) => hasEdge(graph, 'f', n.id, 'matches YARA rule')));
    const sigma = sigs(graph, 'sigma');
    t.check('behaviour: Sigma deduped by title (6 hits → 5)', sigma.length === 5 && new Set(sigma.map((n) => n.data.name)).size === 5);
    t.check('behaviour: Sigma signature exact', same(sigma[0].data, { name: 'Add file from suspicious location to autostart registry', signature_type: 'sigma', description: 'critical — Joe Security Rule Set (GitHub)' }));
    t.check("behaviour: file → Sigma rule 'matches Sigma rule'", sigma.every((n) => hasEdge(graph, 'f', n.id, 'matches Sigma rule')));
    t.check('behaviour: IDS off by default', !graph.createdEdges.some((e) => e.label === 'triggers IDS rule') && r.counts?.ids === 0);
    const mal = graph.createdNodes.filter((n) => n.type === 'threat.malware');
    t.check('behaviour: top 3 family names as Malware', same(mal.map((n) => n.data.name), ['wannacry', 'wannacryptor', 'wanna']));
    t.check('behaviour: malware node exact (is_family, malware_type from top category)', same(mal[0]?.data, { name: 'wannacry', is_family: true, malware_type: 'ransomware' }));
    t.check("behaviour: file → malware 'classified as'", mal.every((n) => hasEdge(graph, 'f', n.id, 'classified as')));
    t.check('behaviour: one edge per created node', graph.createdEdges.length === graph.createdNodes.length);
    t.check('behaviour: one update on the file with label/category/verdicts/sandboxes', graph.updates.length === 1 && graph.updates[0].id === 'f' && same(graph.updates[0].data, {
        vt_mitre_sandboxes: 'CAPA, Zenbox, CAPE Sandbox',
        vt_threat_label: 'ransomware.wannacry/wannacryptor',
        vt_threat_category: 'ransomware, trojan',
        vt_sandbox_verdicts: 'NSFOCUS POMA: malicious (TROJAN, RANSOM), Dr.Web vxCube: malicious (MALWARE), Zenbox: malicious (MALWARE, RANSOM)',
    }));
    t.check('behaviour: counts', same(r.counts, { checked: 1, techniques: 7, yara: 2, sigma: 5, ids: 0, families: 3, misses: 0 }));
    t.check('behaviour: summary', r.summary === '1 file(s): 7 technique(s), 7 signature(s) (2 YARA, 5 Sigma, 0 IDS), 3 families');
    t.check('behaviour: no self-links', noSelfLinks(graph));
}
// one technique under a retired ID and its current one → ONE node under the current ID
{
    const net = makeNet(behRespond({ behaviour_mitre_trees: { status: 200, body: MITRE_RETIRED } }));
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    const r = await go(BEH, ctx(graph, net, ['f'], { yara: false, sigma: false, classification: false, max_per_kind: 100 }));
    t.check('behaviour retired IDs: run clean, no second create on any pair', hostClean(graph, r));
    const techs = techsOf(graph);
    t.check('behaviour retired IDs: 8 reported IDs → 4 techniques, 4 edges, counted 4', techs.length === 4 && graph.createdEdges.length === 4 && r.counts?.techniques === 4);
    const by = (name) => techs.find((n) => n.data.name === name)?.data;
    t.check('behaviour retired IDs: Registry Run Keys keeps T1547.001 (2 sandboxes over 1), its own tactics', same(by('Registry Run Keys / Startup Folder'), { name: 'Registry Run Keys / Startup Folder', technique_id: 'T1547.001', tactic: 'persistence', vt_tactics: 'Persistence, Privilege Escalation', description: 'Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.', vt_technique_ids: 'T1547.001, T1060' }));
    t.check("behaviour retired IDs: Hidden Files keeps T1564.001 with the current ID's description and tactics", same(by('Hidden Files and Directories'), { name: 'Hidden Files and Directories', technique_id: 'T1564.001', tactic: 'defense-evasion', vt_tactics: 'Stealth', description: HIDDEN_NEW, vt_technique_ids: 'T1564.001, T1158' }));
    t.check('behaviour retired IDs: File Deletion 1–1 tie (retired seen first) → the sub-technique T1070.004', by('File Deletion')?.technique_id === 'T1070.004' && by('File Deletion')?.vt_technique_ids === 'T1070.004, T1107');
    t.check("behaviour retired IDs: 'Credentials in Files' (T1081) folds into 'Credentials In Files' T1552.001 despite the case", by('Credentials In Files')?.technique_id === 'T1552.001' && by('Credentials In Files')?.vt_technique_ids === 'T1552.001, T1081' && !by('Credentials in Files'));
    t.check('behaviour retired IDs: no retired ID left as a technique_id', !techs.some((n) => ['T1060', 'T1158', 'T1107', 'T1081'].includes(n.data.technique_id)));
    t.check('behaviour retired IDs: vt_mitre_sandboxes lists all three', graph.updates[0]?.data.vt_mitre_sandboxes === 'CAPE Sandbox, Yomi Hunter, Zenbox');
}
// across the files of one run: a retired ID never overwrites the current one already written, and a
// second spelling lands on the node the first one made — in either order
for (const order of [['a', 'y'], ['y', 'a']]) {
    const Y = 'd'.repeat(64);
    const net = makeNet((u) => {
        if (relOf(u) !== 'behaviour_mitre_trees') return { status: 404, body: vtErr('NotFoundError') };
        return { status: 200, body: hashOf(u) === Y ? MITRE_YOMI_ONLY : MITRE_RETIRED };
    });
    const graph = hostGraph({ a: fileNode('a', { sha256: SRC }), y: fileNode('y', { sha256: Y }) });
    const r = await go(BEH, ctx(graph, net, order, { yara: false, sigma: false, classification: false }));
    const techs = techsOf(graph);
    const tag = order.join(' then ');
    t.check(`behaviour across files (${tag}): run clean, still 4 technique nodes`, hostClean(graph, r) && techs.length === 4);
    t.check(`behaviour across files (${tag}): every node ends under its current ID`, same(techs.map((n) => n.data.technique_id).sort(), ['T1070.004', 'T1547.001', 'T1552.001', 'T1564.001']));
    t.check(`behaviour across files (${tag}): the Yomi-only file links the same nodes (4 edges)`, graph.createdEdges.filter((e) => e.from === 'y').length === 4 && r.counts?.techniques === 8);
    const cred = techs.find((n) => /^credentials in files$/i.test(n.data.name));
    t.check(`behaviour across files (${tag}): the credentials node keeps the spelling it first landed under`, cred?.data.name === (order[0] === 'a' ? 'Credentials In Files' : 'Credentials in Files') && cred?.data.technique_id === 'T1552.001');
}
// ids on, everything else off: one GET, no MITRE call, no classification
{
    const net = makeNet(behRespond());
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    const r = await go(BEH, ctx(graph, net, ['f'], { mitre: false, yara: false, sigma: false, classification: false, ids: true }));
    t.check('behaviour: mitre off → no behaviour_mitre_trees request', net.calls.length === 1 && new URL(net.calls[0].url).pathname === `/api/v3/files/${SRC}`);
    const ids = graph.createdNodes.filter((n) => n.type === 'threat.signature');
    t.check('behaviour: IDS deduped by message (5 alerts → 4)', ids.length === 4 && r.counts?.ids === 4);
    t.check("behaviour: Snort-sourced IDS rule → signature_type 'snort', rule = rule_id", same(ids.find((n) => n.data.rule === '116:441')?.data, { name: '(icmp4) ICMP destination unreachable communication administratively prohibited', signature_type: 'snort', rule: '116:441', description: 'medium — Snort registered user ruleset' }));
    t.check('behaviour: ET Open IDS rule (engine not named) carries no signature_type', same(ids.find((n) => n.data.rule === '1:2520029')?.data, { name: 'ET TOR Known Tor Exit Node Traffic group 30', rule: '1:2520029', description: 'medium — Proofpoint Emerging Threats Open' }));
    t.check("behaviour: file → IDS rule 'triggers IDS rule'", ids.every((n) => hasEdge(graph, 'f', n.id, 'triggers IDS rule')));
    t.check('behaviour: yara/sigma/classification off → none of those', r.counts.yara === 0 && r.counts.sigma === 0 && r.counts.families === 0 && !graph.createdNodes.some((n) => n.type === 'threat.malware'));
    t.check('behaviour: nothing to write on the file when classification and mitre are off', graph.updates.length === 0);
    t.check('behaviour: IDS nodes pass the host type-pack check', hostClean(graph, r));
}
// mitre only: no report GET
{
    const net = makeNet(behRespond());
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    const r = await go(BEH, ctx(graph, net, ['f'], { yara: false, sigma: false, classification: false }));
    t.check('behaviour: mitre only → only behaviour_mitre_trees requested', net.calls.length === 1 && relOf(new URL(net.calls[0].url)) === 'behaviour_mitre_trees');
    t.check('behaviour: mitre only → techniques + vt_mitre_sandboxes, nothing else', r.counts?.techniques === 7 && r.counts.yara + r.counts.sigma + r.counts.families === 0 && same(graph.updates[0]?.data, { vt_mitre_sandboxes: 'CAPA, Zenbox, CAPE Sandbox' }));
}
// max_per_kind caps techniques and each signature kind
{
    const net = makeNet(behRespond());
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    const r = await go(BEH, ctx(graph, net, ['f'], { ids: true, max_per_kind: 2 }));
    t.check('behaviour: max_per_kind 2 caps techniques to the two most-corroborated', r.counts?.techniques === 2 && same(techsOf(graph).map((n) => n.data.technique_id), ['T1082', 'T1486']));
    t.check('behaviour: max_per_kind 2 caps each signature kind', r.counts.yara === 2 && r.counts.sigma === 2 && r.counts.ids === 2);
    t.check('behaviour: capped Sigma keeps the highest levels', same(sigs(graph, 'sigma').map((n) => n.data.name), ['Add file from suspicious location to autostart registry', 'WannaCry Ransomware Activity']));
    t.check('behaviour: families stay top 3 regardless of the cap', r.counts.families === 3);
}
// 403 on the MITRE trees: only techniques are lost
{
    const net = makeNet(behRespond({ behaviour_mitre_trees: { status: 403, body: vtErr('ForbiddenError') } }));
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    const r = await go(BEH, ctx(graph, net, ['f']));
    t.check('behaviour: 403 on behaviour_mitre_trees → miss, rules + families still written', r.counts?.misses === 1 && r.counts.techniques === 0 && r.counts.yara === 2 && r.counts.sigma === 5 && r.counts.families === 3);
    t.check('behaviour: no vt_mitre_sandboxes after the 403, the rest of the patch kept', graph.updates.length === 1 && !('vt_mitre_sandboxes' in graph.updates[0].data) && graph.updates[0].data.vt_threat_label === 'ransomware.wannacry/wannacryptor');
}
// 403 on the file report: the MITRE tree is still read, nothing from the report is written
{
    const net = makeNet(behRespond({ report: { status: 403, body: vtErr('ForbiddenError') } }));
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    const r = await go(BEH, ctx(graph, net, ['f']));
    t.check('behaviour: 403 on the report → exactly one miss, the MITRE call still made', r.counts?.misses === 1 && same(net.calls.map((c) => new URL(c.url).pathname), [`/api/v3/files/${SRC}`, `/api/v3/files/${SRC}/behaviour_mitre_trees`]));
    t.check('behaviour: 403 on the report → techniques written, no signature or malware nodes', r.counts.techniques === 7 && techsOf(graph).length === 7 && !graph.createdNodes.some((n) => n.type === 'threat.signature' || n.type === 'threat.malware') && r.counts.yara + r.counts.sigma + r.counts.ids + r.counts.families === 0);
    t.check('behaviour: 403 on the report → the file update carries only vt_mitre_sandboxes', graph.updates.length === 1 && same(graph.updates[0].data, { vt_mitre_sandboxes: 'CAPA, Zenbox, CAPE Sandbox' }));
}
// 404 node: the report 404s, the MITRE call is not made, the next file still runs
{
    const UNKNOWN = 'c'.repeat(64);
    const net = makeNet(behRespond({ [UNKNOWN]: { status: 404, body: vtErr('NotFoundError') } }));
    const graph = hostGraph({ u: fileNode('u', { sha256: UNKNOWN }), f: fileNode('f', { sha256: SRC }) });
    const r = await go(BEH, ctx(graph, net, ['u', 'f']));
    t.check('behaviour: 404 file → one request, one miss, no MITRE call for it', net.calls.filter((c) => hashOf(new URL(c.url)) === UNKNOWN).length === 1 && r.counts?.misses === 1);
    t.check('behaviour: next file still processed', r.counts?.checked === 2 && r.counts.techniques === 7 && graph.updates.every((u) => u.id === 'f'));
}
// a report without classification / rule fields writes nothing for them
{
    const bare = { data: { type: 'file', id: SRC, attributes: { sha256: SRC } } };
    const net = makeNet(behRespond({ report: { status: 200, body: bare } }));
    const graph = hostGraph({ f: fileNode('f', { sha256: SRC }) });
    const r = await go(BEH, ctx(graph, net, ['f'], { mitre: false }));
    t.check('behaviour: bare report → no signatures, no families, no file update', r.counts?.yara + r.counts?.sigma + r.counts?.families === 0 && graph.createdNodes.length === 0 && graph.updates.length === 0);
}

t.report();
