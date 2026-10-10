// Mock tests for module B (src/host.ts): vt_host_files, vt_host_urls. No network.
//   Run: node test/host.test.mjs [bundle]
// Response bodies are MEASURED VirusTotal Premium responses (2026-10-10), trimmed to the fields the
// mappers read. meta.cursor is dropped unless a test pages on purpose — vtList would otherwise follow it.
import { loadPlugins, suite, makeGraph, makeNet, RUN, KEY, vtErr, hasEdge } from './harness.mjs';

const P = await loadPlugins();
const FILES = P['run.vineyard.plugins.vt_host_files'];
const URLS = P['run.vineyard.plugins.vt_host_urls'];
const t = suite('host (vt_host_files, vt_host_urls)');

const VT = 'https://www.virustotal.com/api/v3';
const IP = '74.119.239.234';
const DOMAIN = 'avsvmcloud.com';

// ---- trimmed fixtures ------------------------------------------------------------------------
// ip_communicating_files.json — data[0] is the measured report-less entry (no attributes, an error).
const UNREPORTED_COMM = {
    id: '0000000000000000000000000000000010000000000000000000000000000000',
    type: 'file',
    error: { code: 'NotFoundError', message: 'file with id "0000000000000000000000000000000010000000000000000000000000000000" not found' },
};
const COMM_A = {
    type: 'file',
    id: '0002a5ee3980e9bd840088a4a810a5d58d68a3aa797aa42ed20b1a8c25ab35e1',
    attributes: {
        sha256: '0002a5ee3980e9bd840088a4a810a5d58d68a3aa797aa42ed20b1a8c25ab35e1',
        sha1: '2c75b6f89a842f15a89a1562640b26f363573aed',
        md5: '2ddba9156fb6b0a46b5418d82993c339',
        size: 614400,
        type_description: 'Win32 EXE',
        tags: ['suspicious-dns', 'nxdomain', 'peexe', 'malware'],
        last_analysis_stats: { malicious: 67, suspicious: 0, undetected: 6, harmless: 0, timeout: 0, 'confirmed-timeout': 0, failure: 0, 'type-unsupported': 4 },
        times_submitted: 1,
        first_submission_date: 1516562775,
        popular_threat_classification: { suggested_threat_label: 'trojan.simda/shiz' },
    },
};
const COMM_B = {
    type: 'file',
    id: '000354e64e175f3f7712448e6b192a5f674e9276c2cc0d42724b5bb6ba8bd8a2',
    attributes: {
        sha256: '000354e64e175f3f7712448e6b192a5f674e9276c2cc0d42724b5bb6ba8bd8a2',
        sha1: '4398670073785d6569ca16b371cac2cdd9007ab3',
        md5: 'f84da76ddaf196d12a600f6f4ddda2e2',
        size: 223040,
        type_description: 'Win32 EXE',
        tags: ['nxdomain', 'overlay', 'malware'],
        last_analysis_stats: { malicious: 70, suspicious: 0, undetected: 3, harmless: 0 },
        times_submitted: 1,
        first_submission_date: 1525902098,
        meaningful_name: 'f84da76ddaf196d12a600f6f4ddda2e2.virus',
        popular_threat_classification: { suggested_threat_label: 'trojan.carberp/shiz' },
    },
};
const IP_COMM = { data: [UNREPORTED_COMM, COMM_A, COMM_B], meta: { count: 55484 } };

// ip_downloaded_files.json
const DOWN_A = {
    type: 'file',
    id: '4ba1a0fcc6983b539744a6590920fc4596460833c306bb1531095ada391ab21f',
    attributes: {
        sha256: '4ba1a0fcc6983b539744a6590920fc4596460833c306bb1531095ada391ab21f',
        sha1: 'bacf68e98eb1c6b2376382e8bb6b0ea64eb362f2',
        md5: 'e1a3849d9ee13b432bd23dbbac1be083',
        size: 272,
        type_description: 'HTML',
        tags: ['html'],
        last_analysis_stats: { malicious: 0, suspicious: 0, undetected: 64, harmless: 0 },
        times_submitted: 270,
        first_submission_date: 1464249438,
        meaningful_name: 'some-samples-master/e1a3849d9ee13b432bd23dbbac1be083',
    },
};
const DOWN_B = {
    type: 'file',
    id: '8a482f2271a42c5f54c96e816a84340a6f2357a5b81f927d07d00788f5140a41',
    attributes: {
        sha256: '8a482f2271a42c5f54c96e816a84340a6f2357a5b81f927d07d00788f5140a41',
        sha1: 'fb6ff8293fa45e17ba97f84954e7d1d5b0d38f87',
        md5: '4845f01eaa8068384625e302e9a4eb05',
        size: 16,
        type_description: 'Text',
        tags: ['via-tor', 'idle', 'text', 'long-sleeps'],
        last_analysis_stats: { malicious: 0, suspicious: 0, undetected: 62, harmless: 0 },
        times_submitted: 914,
        first_submission_date: 1328282293,
        meaningful_name: 'exit.php',
    },
};
const IP_DOWN = { data: [DOWN_A, DOWN_B], meta: { count: 103 } };

// ip_referrer_files.json — data[1] is again a report-less entry.
const REF_A = {
    type: 'file',
    id: 'd682b807eeaa5a83e6c9d25abe762f0f4433af1cc02cb5356888d23439173222',
    attributes: {
        sha256: 'd682b807eeaa5a83e6c9d25abe762f0f4433af1cc02cb5356888d23439173222',
        sha1: '9a696ad3258f7a87ab60b4d22788595117a4e41c',
        md5: '4dff1241f8db31e130725384da14c1aa',
        size: 12190827,
        type_description: 'Text',
        tags: ['text'],
        last_analysis_stats: { malicious: 3, suspicious: 0, undetected: 58, harmless: 0 },
        times_submitted: 2,
        first_submission_date: 1728708565,
        meaningful_name: 'snort 3.445-2.2896/var/winroute/snort/rules/used.rules',
        popular_threat_classification: { suggested_threat_label: 'trojan.' },
    },
};
const UNREPORTED_REF = {
    id: '43881a008d3776a086ace659c6acc5af43a81d906b8a45d96047a75b7556c60d',
    type: 'file',
    error: { code: 'NotFoundError', message: 'file with id "43881a008d3776a086ace659c6acc5af43a81d906b8a45d96047a75b7556c60d" not found' },
};
const IP_REF = { data: [REF_A, UNREPORTED_REF], meta: { count: 85 } };

// domain_communicating_files.json (measured empty), domain_downloaded_files.json, domain_referrer_files.json
const DOMAIN_COMM = { data: [], meta: { count: 0 } };
const DOMAIN_DOWN = {
    data: [
        {
            type: 'file',
            id: '8ea5fc4bf67d1fc02109c31039d7b4ac9e0391ec36f3ade29cf959bd84486d03',
            attributes: {
                sha256: '8ea5fc4bf67d1fc02109c31039d7b4ac9e0391ec36f3ade29cf959bd84486d03',
                sha1: '6d5afb82575e1acb54889444566f1e910ae21168',
                md5: '7983dae28179de5316b001509702dda4',
                size: 1649,
                type_description: 'HTML',
                tags: ['html', 'contains-embedded-js'],
                last_analysis_stats: { malicious: 0, suspicious: 0, undetected: 65, harmless: 0 },
                times_submitted: 1,
                first_submission_date: 1602041409,
                meaningful_name: 'Orion.Wireless.xml',
            },
        },
    ],
    meta: { count: 1 },
};
const DOMAIN_REF = {
    data: [
        {
            type: 'file',
            id: 'ad587a23b15aacc6a42ce6fcf3dfbd882a88736a0ed5fe6caeda51a990373514',
            attributes: {
                sha256: 'ad587a23b15aacc6a42ce6fcf3dfbd882a88736a0ed5fe6caeda51a990373514',
                sha1: 'ee9d19e07e07ad1e2c331b6883c143d81abdb100',
                md5: 'd02c07a85fefbab1cca30d01c3ad677a',
                size: 335996,
                type_description: 'PDF',
                tags: ['pdf'],
                last_analysis_stats: { malicious: 0, suspicious: 0, undetected: 64, harmless: 0 },
                times_submitted: 1,
                first_submission_date: 1775140874,
                meaningful_name: 'P3230146_P3230175_P3230218.pdf',
            },
        },
    ],
    meta: { count: 6 },
};

// ip_urls.json
const IP_URLS = {
    data: [
        {
            type: 'url',
            id: '4d6572c8a1a091910d1ca9035d970b9a3bd102c7b2609d704ed52e6476f1f268',
            attributes: {
                url: 'https://wulongdakon.com/',
                title: '',
                last_final_url: 'https://wulongdakon.com/',
                last_analysis_stats: { malicious: 11, suspicious: 1, undetected: 34, harmless: 47, timeout: 0 },
            },
            context_attributes: { url: 'https://wulongdakon.com/' },
        },
        {
            type: 'url',
            id: '6e2890da984e0099d9def807ff18cf1a3544d95e4d30feef8d403abcc634e895',
            attributes: {
                url: 'https://veloraio.com/',
                title: 'veloraio.com',
                last_http_response_code: 200,
                last_final_url: 'https://veloraio.com/',
                last_analysis_stats: { malicious: 15, suspicious: 1, undetected: 31, harmless: 46, timeout: 0 },
            },
            context_attributes: { url: 'https://veloraio.com/' },
        },
        {
            type: 'url',
            id: '1d5a6e411e8e8e8219405baec9107766aa2e4b6a7e69ed5d56e5b5a7e5d903bb',
            attributes: {
                url: 'https://pumpsix.xyz/',
                title: '',
                last_final_url: 'https://pumpsix.xyz/',
                last_analysis_stats: { malicious: 4, suspicious: 1, undetected: 32, harmless: 56, timeout: 0 },
            },
            context_attributes: { url: 'https://pumpsix.xyz/' },
        },
    ],
    meta: { count: 200 },
};
// domain_urls.json
const DOMAIN_URLS = {
    data: [
        {
            type: 'url',
            id: '3d609c38ea20b54a6bfd643fe0b4b078efcb49f3e40effc4136a99ce3943c012',
            attributes: {
                url: 'https://avsvmcloud.com/',
                title: '',
                last_http_response_code: 200,
                last_final_url: 'https://avsvmcloud.com/',
                last_analysis_stats: { malicious: 14, suspicious: 0, undetected: 33, harmless: 46, timeout: 0 },
            },
            context_attributes: { url: 'https://avsvmcloud.com/' },
        },
        {
            type: 'url',
            id: '491b33a32dede42c03dea2d710c2294770bfade21288c5b1032e5f386ec3b76e',
            attributes: {
                url: 'https://ihvpgv9psvq02ffo77et.appsync-api.us-east-2.avsvmcloud.com/',
                title: '',
                last_http_response_code: 200,
                last_final_url: 'https://ihvpgv9psvq02ffo77et.appsync-api.us-east-2.avsvmcloud.com/',
                last_analysis_stats: { malicious: 12, suspicious: 1, undetected: 31, harmless: 48, timeout: 0 },
            },
            context_attributes: { url: 'https://ihvpgv9psvq02ffo77et.appsync-api.us-east-2.avsvmcloud.com/' },
        },
    ],
    meta: { count: 100 },
};

// file_itw_domains.json data[0] — a domain object (non-arpa, so nodeFromVt WOULD map it). VT never
// lists one under a host's files/urls (every measured entry is the relationship's own type); it is
// used to prove a foreign-typed object is not minted and linked under the wrong label.
const FOREIGN_DOMAIN = {
    type: 'domain',
    id: '000webhostapp.com',
    attributes: { last_analysis_stats: { malicious: 1, suspicious: 0, undetected: 32, harmless: 59, timeout: 0 } },
};

// Synthetic objects for the paging tests: distinct ids so every object is its own node.
const hex64 = (i) => i.toString(16).padStart(64, '0');
const fileN = (i) => ({ type: 'file', id: hex64(i + 1), attributes: { sha256: hex64(i + 1), type_description: 'Win32 EXE' } });
const urlN = (i) => ({ type: 'url', id: hex64(i + 1), attributes: { url: `https://wulongdakon.com/p${i}` } });

// ---- helpers ---------------------------------------------------------------------------------
const ipNode = (id = 'ip', ip = IP) => ({ id, type: 'infrastructure.ip_address', data: { ip_address: ip } });
const domainNode = (id = 'dom', d = DOMAIN) => ({ id, type: 'infrastructure.domain', data: { domain_name: d } });
const urlNode = (id = 'u', u = 'http://evil.example/x') => ({ id, type: 'web.url', data: { url: u } });
const urlId = (u) => Buffer.from(u, 'utf8').toString('base64url');

/** Route by exact pathname; anything else is a 404 NotFoundError. */
function route(table) {
    return (u) => table[u.pathname] ?? { status: 404, body: vtErr('NotFoundError') };
}
const ok = (body) => ({ status: 200, body });
function ctxFor(nodes, respond, params = {}) {
    const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
    const graph = makeGraph(byId);
    const net = makeNet(respond);
    const logs = [];
    const ctx = {
        ...RUN,
        progress: { log: (l) => logs.push(l), set() {} },
        config: KEY,
        params,
        input: { selection: nodes.map((n) => n.id) },
        net,
        graph,
    };
    return { ctx, graph, net, logs };
}
const nodeBySha = (graph, sha) => graph.createdNodes.find((n) => n.type === 'threat.file_hash' && n.data.sha256 === sha);
const nodeByUrl = (graph, url) => graph.createdNodes.find((n) => n.type === 'web.url' && n.data.url === url);
const paths = (net) => net.calls.map((c) => new URL(c.url).pathname);
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);
async function runCatching(plugin, ctx) {
    try {
        return { r: await plugin.run(ctx), err: null };
    } catch (err) {
        return { r: null, err };
    }
}
/**
 * A list endpoint that never runs dry: every page is as full as asked (VT's cap is 40) and carries a
 * fresh meta.cursor, so only the plugin's own limit can stop the paging. Past 300 calls it answers
 * `data: []` so a runaway limit fails the assertions instead of hanging the suite.
 */
function endless(make) {
    let n = 0;
    let calls = 0;
    return (u) => {
        if (++calls > 300) return ok({ data: [] });
        const size = Math.min(40, Number(u.searchParams.get('limit')) || 40);
        return ok({ data: Array.from({ length: size }, () => make(n++)), meta: { cursor: `C${n}` } });
    };
}
/** Cancel the run the moment the first node is written (as a user pressing Cancel mid-page). */
function cancelOnFirstNode(ctx, graph) {
    const ac = new AbortController();
    ctx.signal = ac.signal;
    const create = graph.createNode;
    graph.createNode = async (d) => {
        const n = await create(d);
        ac.abort();
        return n;
    };
}

const IP_BASE = `/api/v3/ip_addresses/${IP}`;
const DOMAIN_BASE = `/api/v3/domains/${DOMAIN}`;

// =============================================================================================
// vt_host_files — manifest
// =============================================================================================
{
    const m = FILES?.manifest ?? {};
    t.check('files manifest: loaded with identifier/content_type/name/version', !!FILES && m.content_type === 'vineyard:plugin' && m.name === 'VT Host Files' && m.version === '0.2.0');
    t.check('files manifest: icon "files"', m.icon === 'files');
    t.check(
        'files manifest: description quotes every edge label and ends with the key/desktop line',
        /'communicates with'/.test(m.description) && /'served file'/.test(m.description) && /'references'/.test(m.description) && m.description.endsWith('Needs a VirusTotal Premium key. Desktop only.'),
    );
    t.check(
        'files manifest: consumes ip/domain/url, produces file_hash',
        eq(m.io?.consumes?.map((r) => `${r.typepack}|${r.category}.${r.name}`), [
            'run.vineyard.typepacks.infrastructure|infrastructure.ip_address',
            'run.vineyard.typepacks.infrastructure|infrastructure.domain',
            'run.vineyard.typepacks.infrastructure|web.url',
        ]) && eq(m.io?.produces?.map((r) => `${r.typepack}|${r.category}.${r.name}`), ['run.vineyard.typepacks.threat|threat.file_hash']),
    );
    const p = m.params?.properties ?? {};
    t.check(
        'files manifest: one boolean per relationship with the spec defaults',
        p.communicating?.type === 'boolean' && p.communicating.default === true &&
            p.downloaded?.type === 'boolean' && p.downloaded.default === true &&
            p.referrer?.type === 'boolean' && p.referrer.default === false &&
            [p.communicating, p.downloaded, p.referrer].every((x) => typeof x.title === 'string' && typeof x.description === 'string'),
    );
    t.check('files manifest: limit is a 1–200 number defaulting to 20', p.limit?.type === 'number' && p.limit.minimum === 1 && p.limit.maximum === 200 && p.limit.default === 20);
    t.check(
        'files manifest: scopes = graph + VT GET + api_key secret, lifecycle, platforms',
        eq(m.scopes?.graph, ['node:read', 'node:create', 'node:update', 'edge:create']) &&
            m.scopes?.network?.[0]?.endpoint === VT && eq(m.scopes.network[0].methods, ['GET']) && !!m.scopes.network[0].purpose &&
            m.scopes?.config?.[0]?.key === 'api_key' && m.scopes.config[0].secret === true &&
            m.lifecycle?.persistence === 'opt-in' && m.platforms?.primary === 'desktop',
    );
}

// =============================================================================================
// vt_host_files — happy path on an IP with default params (communicating + downloaded)
// =============================================================================================
{
    const { ctx, graph, net, logs } = ctxFor(
        [ipNode()],
        route({
            [`${IP_BASE}/communicating_files`]: ok(IP_COMM),
            [`${IP_BASE}/downloaded_files`]: ok(IP_DOWN),
            [`${IP_BASE}/referrer_files`]: ok(IP_REF),
        }),
    );
    const r = await FILES.run(ctx);
    t.check('files ip: default params read communicating + downloaded only', eq(paths(net), [`${IP_BASE}/communicating_files`, `${IP_BASE}/downloaded_files`]));
    t.check('files ip: default limit=20 on each request', net.calls.every((c) => new URL(c.url).searchParams.get('limit') === '20'));
    t.check('files ip: key only in the x-apikey header', net.calls.every((c) => c.headers['x-apikey'] === 'k' && !/apikey|[?&]k=/.test(c.url)));
    const a = nodeBySha(graph, COMM_A.id);
    t.check(
        'files ip: communicating file node carries the exact mapped properties',
        !!a && eq(a.data, {
            sha256: COMM_A.id,
            sha1: '2c75b6f89a842f15a89a1562640b26f363573aed',
            md5: '2ddba9156fb6b0a46b5418d82993c339',
            size: 614400,
            type_description: 'Win32 EXE',
            tags: 'suspicious-dns, nxdomain, peexe, malware',
            malicious_count: 67,
            suspicious_count: 0,
            undetected_count: 6,
            times_submitted: 1,
            first_seen: new Date(1516562775 * 1000).toISOString(),
            vt_threat_label: 'trojan.simda/shiz',
        }),
    );
    const b = nodeBySha(graph, COMM_B.id);
    t.check('files ip: meaningful_name becomes vt_name', b?.data.vt_name === 'f84da76ddaf196d12a600f6f4ddda2e2.virus' && b?.data.vt_threat_label === 'trojan.carberp/shiz');
    const d = nodeBySha(graph, DOWN_A.id);
    t.check('files ip: downloaded file node mapped (no threat label when VT has none)', d?.data.type_description === 'HTML' && d.data.size === 272 && d.data.malicious_count === 0 && !('vt_threat_label' in d.data));
    t.check('files ip: communicating edges run file → host "communicates with"', hasEdge(graph, a?.id, 'ip', 'communicates with') && hasEdge(graph, b?.id, 'ip', 'communicates with'));
    t.check('files ip: downloaded edges run host → file "served file"', hasEdge(graph, 'ip', d?.id, 'served file') && hasEdge(graph, 'ip', nodeBySha(graph, DOWN_B.id)?.id, 'served file'));
    t.check('files ip: no reversed edges', !hasEdge(graph, 'ip', a?.id, /./) && !hasEdge(graph, d?.id, 'ip', /./));
    t.check('files ip: the report-less placeholder 0000…1000… is not a node', !nodeBySha(graph, UNREPORTED_COMM.id) && graph.createdNodes.length === 4);
    t.check('files ip: only File Hash nodes are created', graph.createdNodes.every((n) => n.type === 'threat.file_hash'));
    t.check(
        'files ip: counts',
        eq(r.counts, { checked: 1, files: 4, communicating: 2, downloaded: 2, referrer: 0, unreported: 1, misses: 0 }),
    );
    t.check('files ip: unreported logged once for the node', logs.filter((l) => /no VirusTotal report/.test(l)).length === 1 && logs.some((l) => l.includes(IP) && /1 listed file/.test(l)));
    t.check('files ip: summary', /1 host\(s\): 4 file\(s\) — 2 communicating, 2 downloaded, 0 referrer; 1 without a VirusTotal report/.test(r.summary));
}

// ---- all three relationships: referrer on (default-false → "=== true") ----------------------
{
    const { ctx, graph, net, logs } = ctxFor(
        [ipNode()],
        route({
            [`${IP_BASE}/communicating_files`]: ok(IP_COMM),
            [`${IP_BASE}/downloaded_files`]: ok(IP_DOWN),
            [`${IP_BASE}/referrer_files`]: ok(IP_REF),
        }),
        { referrer: true },
    );
    const r = await FILES.run(ctx);
    const ref = nodeBySha(graph, REF_A.id);
    t.check('files referrer=true: all three relationships read', eq(paths(net), [`${IP_BASE}/communicating_files`, `${IP_BASE}/downloaded_files`, `${IP_BASE}/referrer_files`]));
    t.check('files referrer=true: referrer edge runs file → host "references"', hasEdge(graph, ref?.id, 'ip', 'references') && !hasEdge(graph, 'ip', ref?.id, /./));
    t.check('files referrer=true: report-less referrer entry skipped too', !nodeBySha(graph, UNREPORTED_REF.id));
    t.check('files referrer=true: counts', eq(r.counts, { checked: 1, files: 5, communicating: 2, downloaded: 2, referrer: 1, unreported: 2, misses: 0 }));
    t.check('files referrer=true: two unreported across relationships → still one log line', logs.filter((l) => /no VirusTotal report/.test(l)).length === 1 && logs.some((l) => /2 listed file/.test(l)));
}
// ---- report-less as an EMPTY attributes object (the spec's wording) ---------------------------
// Synthetic variant of the measured UNREPORTED_REF entry: `attributes: {}` instead of no attributes.
// Its id is still 64 hex, so mapping it would mint a junk File Hash with nothing but the hash.
{
    const emptyAttrs = { type: 'file', id: UNREPORTED_REF.id, attributes: {} };
    const { ctx, graph, logs } = ctxFor(
        [ipNode()],
        route({ [`${IP_BASE}/communicating_files`]: ok({ data: [emptyAttrs, COMM_A] }), [`${IP_BASE}/downloaded_files`]: ok({ data: [] }) }),
    );
    const r = await FILES.run(ctx);
    t.check(
        'files attributes {}: no node and no edge for it, the real file next to it still lands',
        !nodeBySha(graph, emptyAttrs.id) && graph.createdNodes.length === 1 && graph.createdEdges.length === 1 && hasEdge(graph, nodeBySha(graph, COMM_A.id)?.id, 'ip', 'communicates with'),
    );
    t.check('files attributes {}: counted and logged as unreported', r.counts.unreported === 1 && r.counts.communicating === 1 && r.counts.files === 1 && logs.some((l) => l.includes(IP) && /1 listed file/.test(l)));
}

// ---- booleans off: communicating=false, downloaded=false → only referrer -------------------
{
    const { ctx, graph, net } = ctxFor(
        [ipNode()],
        route({ [`${IP_BASE}/referrer_files`]: ok(IP_REF) }),
        { communicating: false, downloaded: false, referrer: true },
    );
    const r = await FILES.run(ctx);
    t.check('files booleans off: only the ticked relationship is requested', eq(paths(net), [`${IP_BASE}/referrer_files`]));
    t.check('files booleans off: counts', r.counts.communicating === 0 && r.counts.downloaded === 0 && r.counts.referrer === 1 && graph.createdEdges.length === 1);
}
// ---- a default-false boolean needs a real true; a default-true one is only off on a real false
{
    const { ctx, net } = ctxFor(
        [ipNode()],
        route({ [`${IP_BASE}/communicating_files`]: ok(IP_COMM), [`${IP_BASE}/downloaded_files`]: ok(IP_DOWN) }),
        { communicating: undefined, downloaded: null, referrer: 'yes' },
    );
    await FILES.run(ctx);
    t.check('files booleans: unset/null keep defaults on, a non-true value leaves referrer off', eq(paths(net), [`${IP_BASE}/communicating_files`, `${IP_BASE}/downloaded_files`]));
}
// ---- nothing ticked: no request at all ----------------------------------------------------
{
    const { ctx, net } = ctxFor([ipNode()], () => ok(IP_COMM), { communicating: false, downloaded: false, referrer: false });
    const r = await FILES.run(ctx);
    t.check('files all off: no network call and the summary says why', net.calls.length === 0 && /No relationship ticked/.test(r.summary) && r.counts.checked === 0);
}

// =============================================================================================
// vt_host_files — domain and URL nodes resolve to their own VT paths
// =============================================================================================
{
    const { ctx, graph, net } = ctxFor(
        [domainNode()],
        route({
            [`${DOMAIN_BASE}/communicating_files`]: ok(DOMAIN_COMM),
            [`${DOMAIN_BASE}/downloaded_files`]: ok(DOMAIN_DOWN),
            [`${DOMAIN_BASE}/referrer_files`]: ok(DOMAIN_REF),
        }),
        { referrer: true },
    );
    const r = await FILES.run(ctx);
    const down = nodeBySha(graph, DOMAIN_DOWN.data[0].id);
    const ref = nodeBySha(graph, DOMAIN_REF.data[0].id);
    t.check('files domain: reads /domains/<name>/<relationship>', eq(paths(net), [`${DOMAIN_BASE}/communicating_files`, `${DOMAIN_BASE}/downloaded_files`, `${DOMAIN_BASE}/referrer_files`]));
    t.check('files domain: measured empty communicating_files adds nothing', r.counts.communicating === 0);
    t.check('files domain: edges host → file "served file", file → host "references"', hasEdge(graph, 'dom', down?.id, 'served file') && hasEdge(graph, ref?.id, 'dom', 'references'));
    t.check('files domain: file node mapped', down?.data.vt_name === 'Orion.Wireless.xml' && down.data.md5 === '7983dae28179de5316b001509702dda4');
    t.check('files domain: counts', eq(r.counts, { checked: 1, files: 2, communicating: 0, downloaded: 1, referrer: 1, unreported: 0, misses: 0 }));
}
{
    const u = 'http://evil.example/x';
    const base = `/api/v3/urls/${urlId(u)}`;
    const { ctx, graph, net } = ctxFor([urlNode('u', u)], route({ [`${base}/communicating_files`]: ok({ data: [COMM_A] }), [`${base}/downloaded_files`]: ok({ data: [DOWN_A] }) }));
    const r = await FILES.run(ctx);
    t.check('files url: reads /urls/<base64url id>/<relationship>', eq(paths(net), [`${base}/communicating_files`, `${base}/downloaded_files`]));
    t.check('files url: edges carry the right direction', hasEdge(graph, nodeBySha(graph, COMM_A.id)?.id, 'u', 'communicates with') && hasEdge(graph, 'u', nodeBySha(graph, DOWN_A.id)?.id, 'served file'));
    t.check('files url: counts', r.counts.checked === 1 && r.counts.files === 2);
}

// ---- the same file under two relationships: two edges, one distinct file -------------------
{
    const { ctx, graph } = ctxFor(
        [ipNode()],
        route({ [`${IP_BASE}/communicating_files`]: ok({ data: [COMM_A] }), [`${IP_BASE}/downloaded_files`]: ok({ data: [COMM_A] }) }),
    );
    const r = await FILES.run(ctx);
    t.check('files dedupe: one file in two relationships → both edges, files counts it once', graph.createdEdges.length === 2 && r.counts.communicating === 1 && r.counts.downloaded === 1 && r.counts.files === 1);
}

// ---- only file objects become nodes: a url/domain in a *_files list is not minted or linked ---
{
    const { ctx, graph } = ctxFor(
        [ipNode()],
        route({
            [`${IP_BASE}/communicating_files`]: ok({ data: [IP_URLS.data[0], FOREIGN_DOMAIN, COMM_A] }),
            [`${IP_BASE}/downloaded_files`]: ok({ data: [DOMAIN_URLS.data[0], DOWN_A] }),
        }),
    );
    const r = await FILES.run(ctx);
    t.check('files foreign types: no URL or Domain node is created', graph.createdNodes.length === 2 && graph.createdNodes.every((n) => n.type === 'threat.file_hash'));
    t.check(
        'files foreign types: only the two files are linked, each under its own label',
        graph.createdEdges.length === 2 &&
            hasEdge(graph, nodeBySha(graph, COMM_A.id)?.id, 'ip', 'communicates with') &&
            hasEdge(graph, 'ip', nodeBySha(graph, DOWN_A.id)?.id, 'served file'),
    );
    t.check('files foreign types: counts only the files', eq(r.counts, { checked: 1, files: 2, communicating: 1, downloaded: 1, referrer: 0, unreported: 0, misses: 0 }));
}

// =============================================================================================
// vt_host_files — failures
// =============================================================================================
// A 403 on one relationship skips only that one; the next still runs.
{
    const { ctx, graph, logs } = ctxFor(
        [ipNode()],
        route({
            [`${IP_BASE}/communicating_files`]: { status: 403, body: vtErr('ForbiddenError') },
            [`${IP_BASE}/downloaded_files`]: ok(IP_DOWN),
        }),
    );
    const { r, err } = await runCatching(FILES, ctx);
    t.check('files 403: does not end the run', err === null);
    t.check('files 403: the other relationship still produces edges', r?.counts.downloaded === 2 && hasEdge(graph, 'ip', nodeBySha(graph, DOWN_A.id)?.id, 'served file'));
    t.check('files 403: counted as a miss and logged as a tier problem', r?.counts.misses === 1 && r.counts.communicating === 0 && logs.some((l) => /communicating_files/.test(l) && /Premium key/.test(l)));
    t.check('files 403: summary names the skipped relationship', /1 relationship\(s\) skipped/.test(r?.summary ?? ''));
}
// A 400 on one relationship is a miss too (not a run-ending error); the next relationship runs.
{
    const { ctx, graph, logs } = ctxFor(
        [ipNode()],
        route({
            [`${IP_BASE}/communicating_files`]: ok({ data: [COMM_A] }),
            [`${IP_BASE}/downloaded_files`]: { status: 400, body: vtErr('InvalidArgumentError') },
            [`${IP_BASE}/referrer_files`]: ok({ data: [REF_A] }),
        }),
        { referrer: true },
    );
    const { r, err } = await runCatching(FILES, ctx);
    t.check('files 400: does not end the run, the relationships around it still produce edges', err === null && r?.counts.communicating === 1 && r.counts.referrer === 1 && hasEdge(graph, nodeBySha(graph, REF_A.id)?.id, 'ip', 'references'));
    t.check('files 400: counted as a miss and logged with the VT error code', r?.counts.misses === 1 && r.counts.downloaded === 0 && logs.some((l) => /downloaded_files/.test(l) && /InvalidArgumentError/.test(l)));
}
// A node VT has no record of: each relationship 404s and is a miss; the next node still runs.
{
    const { ctx, graph } = ctxFor(
        [domainNode('ghost', 'never-seen-before.example'), ipNode()],
        route({ [`${IP_BASE}/communicating_files`]: ok({ data: [COMM_A] }), [`${IP_BASE}/downloaded_files`]: ok({ data: [] }) }),
    );
    const { r, err } = await runCatching(FILES, ctx);
    t.check('files 404 node: no throw, each enabled relationship is a miss', err === null && r.counts.misses === 2);
    t.check('files 404 node: nothing linked to the missing node, the next node still enriched', !graph.createdEdges.some((e) => e.from === 'ghost' || e.to === 'ghost') && r.counts.checked === 2 && r.counts.communicating === 1);
}
// Anything other than 400/403/404 ends the run.
{
    const { ctx } = ctxFor([ipNode()], () => ({ status: 500, body: vtErr('InternalError') }));
    const { err } = await runCatching(FILES, ctx);
    t.check('files 500: rethrown (not swallowed as a miss)', !!err && /InternalError/.test(err.message));
}
{
    const { ctx } = ctxFor([ipNode()], () => ({ status: 401, body: vtErr('WrongCredentialsError') }));
    const { err } = await runCatching(FILES, ctx);
    t.check('files 401: ends the run naming the key', !!err && /rejected this API key/.test(err.message));
}

// ---- nodes VT cannot look up are skipped; other node types are ignored ---------------------
{
    const { ctx, net } = ctxFor(
        [ipNode('bad', 'not-an-ip'), { id: 'h', type: 'threat.file_hash', data: { sha256: COMM_A.id } }],
        () => ok(IP_COMM),
    );
    const r = await FILES.run(ctx);
    t.check('files skip: malformed host and non-consumed types make no request', net.calls.length === 0 && r.counts.checked === 0);
}

// ---- never link a node to itself (host merges a created node onto the selected one) ---------
{
    const { ctx, graph } = ctxFor(
        [ipNode()],
        route({ [`${IP_BASE}/communicating_files`]: ok({ data: [COMM_A] }), [`${IP_BASE}/downloaded_files`]: ok({ data: [DOWN_A] }) }),
    );
    const sel = await graph.get('ip');
    graph.createNode = async () => sel; // simulate an identity merge returning the selected node
    const r = await FILES.run(ctx);
    t.check('files self-link: no edge from a node to itself', graph.createdEdges.every((e) => e.from !== e.to) && graph.createdEdges.length === 0 && r.counts.files === 0);
}

// ---- limit: clamped to 1–200, paged at 40 through meta.cursor -------------------------------
{
    const pages = [];
    const { ctx, net } = ctxFor([ipNode()], (u) => {
        if (u.pathname !== `${IP_BASE}/communicating_files`) return ok({ data: [] });
        pages.push(u.searchParams.get('limit'));
        if (!u.searchParams.get('cursor')) return ok({ data: Array(40).fill(COMM_A), meta: { cursor: 'C1' } });
        return ok({ data: Array(Number(u.searchParams.get('limit'))).fill(COMM_B) });
    }, { limit: 50, downloaded: false });
    const r = await FILES.run(ctx);
    t.check('files limit 50: two pages of 40 + 10, following meta.cursor', eq(pages, ['40', '10']) && new URL(net.calls[1].url).searchParams.get('cursor') === 'C1');
    // The pages repeat the same two files: a file listed 40 times is still one finding and one node.
    t.check('files limit 50: a file repeated across pages is one node, counted once', r.counts.communicating === 2 && r.counts.files === 2);
}
{
    const { ctx, net } = ctxFor([ipNode()], endless(fileN), { limit: 5 });
    const r = await FILES.run(ctx);
    t.check(
        'files limit 5: one request of exactly 5 per relationship, 5 files each',
        net.calls.length === 2 && net.calls.every((c) => new URL(c.url).searchParams.get('limit') === '5') && r.counts.communicating === 5 && r.counts.downloaded === 5,
    );
}
// The upper clamp, against pages that never run dry: 9999 must stop at 200 = five pages of 40.
{
    const { ctx, graph, net } = ctxFor([ipNode()], endless(fileN), { limit: 9999, downloaded: false });
    const r = await FILES.run(ctx);
    t.check(
        'files limit 9999: clamps to 200 — exactly five requests of 40 against endless pages',
        net.calls.length === 5 && net.calls.every((c) => new URL(c.url).searchParams.get('limit') === '40'),
    );
    t.check('files limit 9999: 200 files and 200 edges, not more', r.counts.communicating === 200 && r.counts.files === 200 && graph.createdNodes.length === 200 && graph.createdEdges.length === 200);
}
{
    const seen = [];
    for (const limit of [0, 'abc']) {
        const { ctx, net } = ctxFor([ipNode()], () => ok({ data: [] }), { limit, downloaded: false });
        await FILES.run(ctx);
        seen.push(new URL(net.calls[0].url).searchParams.get('limit'));
    }
    t.check('files limit: 0 and junk fall back to 20', eq(seen, ['20', '20']));
}

// ---- cancel: vt_host_files reads every ticked relationship, THEN writes ----------------------
// Written as they arrived, a file reached two ways would get two edges on one pair and the backend
// would drop the second label at commit — so a host's relationships are all read first. A cancel
// during the write phase therefore stops the writes: no edge for the half-written host, and the
// next host is never requested.
{
    const { ctx, graph, net } = ctxFor(
        [ipNode(), domainNode()],
        route({ [`${IP_BASE}/communicating_files`]: ok({ data: [COMM_A, COMM_B, DOWN_A] }), [`${IP_BASE}/downloaded_files`]: ok(IP_DOWN) }),
    );
    cancelOnFirstNode(ctx, graph);
    const { err } = await runCatching(FILES, ctx);
    t.check('files cancel mid-write: the run rejects with "cancelled"', /cancelled/.test(err?.message ?? ''));
    t.check('files cancel mid-write: the rest is not written (1 node, no half-linked edge)', graph.createdNodes.length === 1 && graph.createdEdges.length === 0);
    t.check('files cancel mid-write: both relationships were read, the next host never requested', net.calls.length === 2 && net.calls.every((c) => c.url.includes(`/ip_addresses/${IP}/`)));
}
// ---- one edge per directed pair: a file that both contacts and names the host ----------------
{
    const { ctx, graph } = ctxFor(
        [ipNode()],
        route({
            [`${IP_BASE}/communicating_files`]: ok({ data: [COMM_A] }),
            [`${IP_BASE}/downloaded_files`]: ok({ data: [] }),
            [`${IP_BASE}/referrer_files`]: ok({ data: [COMM_A] }),
        }),
        { referrer: true },
    );
    const { r } = await runCatching(FILES, ctx);
    const fileNodes = graph.createdNodes.filter((n) => n.type === 'threat.file_hash');
    const fileId = fileNodes[0]?.id;
    t.check('files pair: the shared file gets ONE file → host edge carrying both labels', graph.createdEdges.length === 1 && hasEdge(graph, fileId, 'ip', 'communicates with; references'));
    t.check('files pair: counted once per relationship and once as a file', r?.counts.communicating === 1 && r?.counts.referrer === 1 && r?.counts.files === 1);
}

// =============================================================================================
// vt_host_urls — manifest
// =============================================================================================
{
    const m = URLS?.manifest ?? {};
    t.check('urls manifest: loaded with identifier/content_type/name/version', !!URLS && m.content_type === 'vineyard:plugin' && m.name === 'VT Host URLs' && m.version === '0.2.0');
    t.check('urls manifest: icon "link-2"', m.icon === 'link-2');
    t.check("urls manifest: description quotes 'hosts URL' and ends with the key/desktop line", /'hosts URL'/.test(m.description) && m.description.endsWith('Needs a VirusTotal Premium key. Desktop only.'));
    t.check(
        'urls manifest: consumes ip/domain, produces url',
        eq(m.io?.consumes?.map((r) => `${r.category}.${r.name}`), ['infrastructure.ip_address', 'infrastructure.domain']) &&
            eq(m.io?.produces?.map((r) => `${r.typepack}|${r.category}.${r.name}`), ['run.vineyard.typepacks.infrastructure|web.url']),
    );
    const p = m.params?.properties ?? {};
    t.check('urls manifest: limit is a 1–200 number defaulting to 20', p.limit?.type === 'number' && p.limit.minimum === 1 && p.limit.maximum === 200 && p.limit.default === 20);
    t.check('urls manifest: VT GET scope + api_key', m.scopes?.network?.[0]?.endpoint === VT && m.scopes?.config?.[0]?.key === 'api_key' && m.lifecycle?.controls?.includes('cancel'));
}

// =============================================================================================
// vt_host_urls — happy paths
// =============================================================================================
{
    const { ctx, graph, net } = ctxFor([ipNode()], route({ [`${IP_BASE}/urls`]: ok(IP_URLS) }));
    const r = await URLS.run(ctx);
    t.check('urls ip: reads /ip_addresses/<ip>/urls?limit=20', eq(paths(net), [`${IP_BASE}/urls`]) && new URL(net.calls[0].url).searchParams.get('limit') === '20');
    const w = nodeByUrl(graph, 'https://wulongdakon.com/');
    const v = nodeByUrl(graph, 'https://veloraio.com/');
    t.check(
        'urls ip: empty title / same final URL / no status are left off',
        !!w && eq(w.data, { url: 'https://wulongdakon.com/', vt_malicious: 11, vt_suspicious: 1, vt_harmless: 47, vt_undetected: 34 }),
    );
    t.check(
        'urls ip: page_title and http_status mapped',
        !!v && eq(v.data, { url: 'https://veloraio.com/', page_title: 'veloraio.com', http_status: 200, vt_malicious: 15, vt_suspicious: 1, vt_harmless: 46, vt_undetected: 31 }),
    );
    t.check('urls ip: only URL nodes created', graph.createdNodes.length === 3 && graph.createdNodes.every((n) => n.type === 'web.url'));
    t.check('urls ip: every edge runs host → url "hosts URL"', graph.createdEdges.length === 3 && graph.createdNodes.every((n) => hasEdge(graph, 'ip', n.id, 'hosts URL')));
    t.check('urls ip: counts + summary', eq(r.counts, { checked: 1, urls: 3, misses: 0 }) && r.summary === '1 host(s): 3 URL(s)');
}
{
    const { ctx, graph, net } = ctxFor([domainNode()], route({ [`${DOMAIN_BASE}/urls`]: ok(DOMAIN_URLS) }));
    const r = await URLS.run(ctx);
    const sub = nodeByUrl(graph, 'https://ihvpgv9psvq02ffo77et.appsync-api.us-east-2.avsvmcloud.com/');
    t.check('urls domain: reads /domains/<name>/urls', eq(paths(net), [`${DOMAIN_BASE}/urls`]));
    t.check('urls domain: subdomain URL mapped and linked', sub?.data.http_status === 200 && sub.data.vt_malicious === 12 && hasEdge(graph, 'dom', sub.id, 'hosts URL'));
    t.check('urls domain: counts', eq(r.counts, { checked: 1, urls: 2, misses: 0 }));
}
// A url object without attributes.url has no URL to show (its id is a hash) — skipped. Synthetic
// variant of an ip_urls.json entry with attributes removed.
{
    const bare = { type: 'url', id: '4d6572c8a1a091910d1ca9035d970b9a3bd102c7b2609d704ed52e6476f1f268' };
    const noUrl = { type: 'url', id: '6e2890da984e0099d9def807ff18cf1a3544d95e4d30feef8d403abcc634e895', attributes: { title: 'veloraio.com' } };
    const { ctx, graph } = ctxFor([ipNode()], route({ [`${IP_BASE}/urls`]: ok({ data: [bare, noUrl, IP_URLS.data[2]] }) }));
    const r = await URLS.run(ctx);
    t.check('urls skip: objects without attributes.url make no node', graph.createdNodes.length === 1 && graph.createdNodes[0].data.url === 'https://pumpsix.xyz/' && r.counts.urls === 1);
    t.check('urls skip: no node named after the hash id', !graph.createdNodes.some((n) => String(n.data.url).includes(bare.id)));
}
// Only url objects become nodes: a file or domain in the /urls list is not minted or linked 'hosts URL'.
{
    const { ctx, graph } = ctxFor([ipNode()], route({ [`${IP_BASE}/urls`]: ok({ data: [COMM_A, FOREIGN_DOMAIN, IP_URLS.data[0]] }) }));
    const r = await URLS.run(ctx);
    t.check('urls foreign types: no File Hash or Domain node is created', graph.createdNodes.length === 1 && graph.createdNodes[0].type === 'web.url' && graph.createdNodes[0].data.url === 'https://wulongdakon.com/');
    t.check('urls foreign types: one "hosts URL" edge, counts only the URL', graph.createdEdges.length === 1 && hasEdge(graph, 'ip', graph.createdNodes[0].id, 'hosts URL') && eq(r.counts, { checked: 1, urls: 1, misses: 0 }));
}

// =============================================================================================
// vt_host_urls — failures, skips, self-links, limit
// =============================================================================================
{
    const { ctx, graph, logs } = ctxFor(
        [ipNode(), domainNode()],
        route({ [`${IP_BASE}/urls`]: { status: 403, body: vtErr('ForbiddenError') }, [`${DOMAIN_BASE}/urls`]: ok(DOMAIN_URLS) }),
    );
    const { r, err } = await runCatching(URLS, ctx);
    t.check('urls 403: one node skipped as a miss, the next still runs', err === null && r.counts.misses === 1 && r.counts.urls === 2 && hasEdge(graph, 'dom', graph.createdNodes[0]?.id, 'hosts URL'));
    t.check('urls 403: logged as a tier problem', logs.some((l) => l.includes(IP) && /Premium key/.test(l)) && /1 skipped/.test(r.summary));
}
{
    const { ctx, graph, logs } = ctxFor([domainNode('ghost', 'never-seen-before.example')], route({}));
    const { r, err } = await runCatching(URLS, ctx);
    t.check('urls 404 node: a miss, no throw, nothing created', err === null && r.counts.misses === 1 && r.counts.checked === 1 && graph.createdNodes.length === 0 && logs.some((l) => /no VirusTotal record/.test(l)));
}
{
    const { ctx, graph, logs } = ctxFor(
        [ipNode(), domainNode()],
        route({ [`${IP_BASE}/urls`]: { status: 400, body: vtErr('InvalidArgumentError') }, [`${DOMAIN_BASE}/urls`]: ok(DOMAIN_URLS) }),
    );
    const { r, err } = await runCatching(URLS, ctx);
    t.check('urls 400: a miss, not a run-ending error; the next node still runs', err === null && r?.counts.misses === 1 && r.counts.urls === 2 && graph.createdEdges.every((e) => e.from === 'dom'));
    t.check('urls 400: logged with the VT error code', logs.some((l) => l.includes(IP) && /InvalidArgumentError/.test(l)));
}
{
    const { ctx } = ctxFor([ipNode()], () => ({ status: 500, body: vtErr('InternalError') }));
    const { err } = await runCatching(URLS, ctx);
    t.check('urls 500: rethrown', !!err && /InternalError/.test(err.message));
}
{
    const { ctx, net } = ctxFor([urlNode(), ipNode('bad', '999')], () => ok(IP_URLS));
    const r = await URLS.run(ctx);
    t.check('urls skip: URL nodes are not consumed, malformed IPs make no request', net.calls.length === 0 && r.counts.checked === 0);
}
{
    const { ctx, graph } = ctxFor([ipNode()], route({ [`${IP_BASE}/urls`]: ok(IP_URLS) }));
    const sel = await graph.get('ip');
    graph.createNode = async () => sel;
    const r = await URLS.run(ctx);
    t.check('urls self-link: no edge from a node to itself', graph.createdEdges.length === 0 && r.counts.urls === 0);
}
{
    const seen = [];
    for (const limit of [3, -1]) {
        const { ctx, net } = ctxFor([ipNode()], () => ok({ data: [] }), { limit });
        await URLS.run(ctx);
        seen.push(new URL(net.calls[0].url).searchParams.get('limit'));
    }
    t.check('urls limit: 3 → 3, -1 falls back to 20', eq(seen, ['3', '20']));
}
// The upper clamp, against pages that never run dry: 500 must stop at 200 = five pages of 40.
{
    const { ctx, graph, net } = ctxFor([ipNode()], endless(urlN), { limit: 500 });
    const r = await URLS.run(ctx);
    t.check('urls limit 500: clamps to 200 — exactly five requests of 40 against endless pages', net.calls.length === 5 && net.calls.every((c) => new URL(c.url).searchParams.get('limit') === '40'));
    t.check('urls limit 500: 200 URLs and 200 edges, not more', r.counts.urls === 200 && graph.createdNodes.length === 200 && graph.createdEdges.length === 200);
}
// Cancel mid-page: the rest of the fetched page is not written and the next node is not requested.
{
    const { ctx, graph, net } = ctxFor([ipNode(), domainNode()], route({ [`${IP_BASE}/urls`]: ok(IP_URLS), [`${DOMAIN_BASE}/urls`]: ok(DOMAIN_URLS) }));
    cancelOnFirstNode(ctx, graph);
    const { err } = await runCatching(URLS, ctx);
    t.check('urls cancel mid-page: the run rejects with "cancelled"', /cancelled/.test(err?.message ?? ''));
    t.check('urls cancel mid-page: 1 node and its 1 edge, the next node never requested', graph.createdNodes.length === 1 && graph.createdEdges.length === 1 && net.calls.length === 1);
}
// Cancel on the last URL of a node: the next node must not be read.
{
    const { ctx, graph, net } = ctxFor([ipNode(), domainNode()], route({ [`${IP_BASE}/urls`]: ok({ data: [IP_URLS.data[0]] }), [`${DOMAIN_BASE}/urls`]: ok(DOMAIN_URLS) }));
    cancelOnFirstNode(ctx, graph);
    const { err } = await runCatching(URLS, ctx);
    t.check('urls cancel between nodes: rejects, the domain is never requested', /cancelled/.test(err?.message ?? '') && net.calls.length === 1 && graph.createdNodes.length === 1);
}

// ---- no key: no request -----------------------------------------------------------------------
for (const p of [FILES, URLS]) {
    const { ctx, net } = ctxFor([ipNode()], () => {
        throw new Error('must not reach the network without a key');
    });
    const { err } = await runCatching(p, { ...ctx, config: {} });
    t.check(`${p.manifest.name}: no key → no request, named error`, net.calls.length === 0 && !!err && /is not set/.test(err.message));
}

t.report();
