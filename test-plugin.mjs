// Mock unit tests for the VirusTotal Premium pack — no network, no app.
//   Run: node test-plugin.mjs [bundle]
// Response shapes below are MEASURED (2026-10-10) against a VT Premium key, trimmed to what each
// plugin reads. The net is mocked; a `respond(url)` returns { status, body }.
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
// Optional argv[2]: a bundle to test instead of dist/pack.mjs (e.g. one built to a scratch path).
const pack = (await import(process.argv[2] ? pathToFileURL(resolve(process.argv[2])).href : './dist/pack.mjs')).default;

const ok = [];
const fail = [];
const check = (name, cond) => (cond ? ok : fail).push(name);
const P = Object.fromEntries(pack.plugins.map((p) => [p.manifest.identifier, p]));

function makeGraph(nodeById) {
    const createdNodes = [], createdEdges = [], updates = [];
    const g = {
        createdNodes, createdEdges, updates,
        async get(id) { return nodeById[id] || null; },
        async list(o) { const all = [...Object.values(nodeById), ...createdNodes]; return { nodes: o?.type ? all.filter((n) => n.type === o.type) : all }; },
        async createNode(d) { const n = { id: `n${createdNodes.length + 1}`, type: d.type, data: d.data }; createdNodes.push(n); nodeById[n.id] = n; return n; },
        async updateNode(id, data) { updates.push({ id, data }); },
        async createEdge(e) { createdEdges.push(e); },
    };
    return g;
}
function makeNet(respond) {
    const calls = [];
    return {
        calls,
        async fetch(url, init) {
            calls.push({ url, headers: init?.headers ?? {} });
            const r = respond(new URL(url));
            return { ok: r.status >= 200 && r.status < 300, status: r.status, headers: r.headers ?? {}, async text() { return JSON.stringify(r.body ?? {}); }, async json() { return r.body ?? {}; } };
        },
    };
}
const RUN = { run: { platform: 'desktop' }, signal: new AbortController().signal, progress: { log() {}, set() {} } };
const KEY = { api_key: 'k' };
const vtErr = (code) => ({ error: { code, message: code } });

// ---- key handling: nothing goes out without a key ------------------------------------------
for (const p of pack.plugins) {
    const net = makeNet(() => { throw new Error('must not reach the network without a key'); });
    const graph = makeGraph({ a: { id: 'a', type: 'infrastructure.ip_address', data: { ip_address: '1.2.3.4' } },
                              k: { id: 'k', type: 'infrastructure.ssh_host_key', data: { fingerprint_sha256: 'SHA256:x' } } });
    let threw = null;
    try { await p.run({ ...RUN, config: {}, params: { query: 'entity:ip' }, input: { selection: ['a', 'k'] }, net, graph }); } catch (e) { threw = e; }
    check(`${p.manifest.name}: no network call without a key`, net.calls.length === 0);
    check(`${p.manifest.name}: a missing key is named`, threw === null || /is not set/.test(threw.message));
}

// ---- web platform refuses before any request -----------------------------------------------
{
    const net = makeNet(() => ({ status: 200, body: {} }));
    const graph = makeGraph({ a: { id: 'a', type: 'infrastructure.ip_address', data: { ip_address: '1.2.3.4' } } });
    let threw = null;
    try { await P['run.vineyard.plugins.vt_port_info'].run({ ...RUN, run: { platform: 'web' }, config: KEY, input: { selection: ['a'] }, net, graph }); } catch (e) { threw = e; }
    check('web: refuses with the desktop reason before any request', !!threw && /desktop app/.test(threw.message) && net.calls.length === 0);
}

// ---- vt_port_info: parses port_info, mints the SSH key, carries the key in the header -------
{
    const body = { data: { attributes: {
        jarm: 'JARMVALUE',
        port_info: [
            { port: 22, status: 'PORT_INFO_STATUS_OPEN', last_seen: 1791608973, latest_analysis: { port_service: { product: 'OpenSSH', version: '8.9', ssh: { host_key_fingerprint: 'SHA256:93mvCQWDCdlDbpFrdWGQrQb4BKMSCsjp/x2tUsCTQbg' } } } },
            { port: 80, status: 'PORT_INFO_STATUS_RECENTLY_CLOSED', last_seen: 1791500000, latest_analysis: { port_service: { product: 'Apache' } } },
        ],
    } } };
    let sawHeader = false;
    const net = makeNet((u) => { return { status: 200, body }; });
    const graph = makeGraph({ a: { id: 'a', type: 'infrastructure.ip_address', data: { ip_address: '1.2.3.4' } } });
    // wrap to inspect header
    const net2 = { async fetch(url, init) { sawHeader = init?.headers?.['x-apikey'] === 'k' && !new URL(url).search.includes('apikey'); return net.fetch(url, init); }, get calls() { return net.calls; } };
    const r = await P['run.vineyard.plugins.vt_port_info'].run({ ...RUN, config: KEY, input: { selection: ['a'] }, net: net2, graph });
    const patch = graph.updates[0]?.data ?? {};
    check('port_info: key rides in x-apikey header, not the URL', sawHeader);
    check('port_info: vt_open_ports lists only OPEN ports', patch.vt_open_ports === '22');
    check('port_info: vt_closed_ports records the recently-closed one', /80 \(recently-closed\)/.test(String(patch.vt_closed_ports)));
    check('port_info: vt_services carries product+version', /22:OpenSSH 8.9/.test(String(patch.vt_services)));
    check('port_info: vt_jarm written', patch.vt_jarm === 'JARMVALUE');
    check('port_info: SSH host key minted as hex (type pack) with the OpenSSH spelling kept, + linked', graph.createdNodes.some((n) => n.type === 'infrastructure.ssh_host_key' && n.data.fingerprint_sha256 === 'f779af09058309d9436e916b756190ad06f804a3120ac8e9ff1dad52c09341b8' && n.data.vt_fingerprint === 'SHA256:93mvCQWDCdlDbpFrdWGQrQb4BKMSCsjp/x2tUsCTQbg') && graph.createdEdges.some((e) => e.label === 'presents host key'));
    check('port_info: counts', r.counts.ssh_keys === 1 && r.counts.open_ports === 1);
}

// ---- vt_port_info: a community key (no port_info) is named, not a silent blank --------------
{
    const net = makeNet(() => ({ status: 200, body: { data: { attributes: { /* no port_info */ } } } }));
    const graph = makeGraph({ a: { id: 'a', type: 'infrastructure.ip_address', data: { ip_address: '1.2.3.4' } } });
    const r = await P['run.vineyard.plugins.vt_port_info'].run({ ...RUN, config: KEY, input: { selection: ['a'] }, net, graph });
    check('port_info: missing port_info is reported as needing Premium', /Premium key/.test(r.summary) && r.counts.enriched === 0);
}

// ---- vt_search: creates a node per entity type; a 403 ends the run with a tier message ------
{
    const body = { data: [
        { type: 'ip_address', id: '9.9.9.9' },
        { type: 'domain', id: 'evil.example' },
        { type: 'url', id: 'u', attributes: { url: 'http://evil.example/x' } },
        { type: 'file', id: 'a'.repeat(64) },
    ] };
    const net = makeNet(() => ({ status: 200, body }));
    const graph = makeGraph({});
    const r = await P['run.vineyard.plugins.vt_search'].run({ ...RUN, config: KEY, input: { selection: [] }, params: { query: 'entity:ip', limit: 10 }, net, graph });
    check('search: one node per entity type', r.counts.ips === 1 && r.counts.domains === 1 && r.counts.urls === 1 && r.counts.files === 1);
    check('search: url node uses attributes.url', graph.createdNodes.some((n) => n.type === 'web.url' && n.data.url === 'http://evil.example/x'));
}
{
    const net = makeNet(() => ({ status: 403, body: vtErr('ForbiddenError') }));
    const graph = makeGraph({});
    let threw = null;
    try { await P['run.vineyard.plugins.vt_search'].run({ ...RUN, config: KEY, input: { selection: [] }, params: { query: 'entity:ip' }, net, graph }); } catch (e) { threw = e; }
    check('search: 403 ends the run with a Premium-key message', !!threw && /Premium key/.test(threw.message));
}
{
    const net = makeNet(() => ({ status: 400, body: vtErr('InvalidArgumentError') }));
    const graph = makeGraph({});
    const r = await P['run.vineyard.plugins.vt_search'].run({ ...RUN, config: KEY, input: { selection: [] }, params: { query: 'bad' }, net, graph });
    check('search: 400 is a graceful "rejected the query", not a throw', /rejected the query/.test(r.summary));
}

// ---- vt_search_from_node: builds fingerprint query from an SSH key node, links hits back ----
{
    let askedQuery = '';
    const net = makeNet((u) => { askedQuery = u.searchParams.get('query') ?? ''; return { status: 200, body: { data: [{ type: 'ip_address', id: '5.5.5.5' }] } }; });
    const graph = makeGraph({ k: { id: 'k', type: 'infrastructure.ssh_host_key', data: { fingerprint_sha256: 'f779af09058309d9436e916b756190ad06f804a3120ac8e9ff1dad52c09341b8' } } });
    const r = await P['run.vineyard.plugins.vt_search_from_node'].run({ ...RUN, config: KEY, input: { selection: ['k'] }, params: { limit: 5 }, net, graph });
    check('from_node: a hex SSH key node queries VT in the OpenSSH spelling (the only one VT matches)', askedQuery === 'entity:ip fingerprint:"SHA256:93mvCQWDCdlDbpFrdWGQrQb4BKMSCsjp/x2tUsCTQbg"');
    check('from_node: the hit is created and linked back to the source', graph.createdNodes.some((n) => n.data.ip_address === '5.5.5.5') && graph.createdEdges.some((e) => e.to === 'k' && /SSH host key/.test(e.label)));
    check('from_node: counts', r.counts.hosts === 1 && r.counts.linked === 1);
}

// ---- vt_port_history: reads /port_infos/{ip}:{port} into a timeline --------------------------
{
    const net = makeNet((u) => {
        if (u.pathname.endsWith('/ip_addresses/1.2.3.4')) return { status: 200, body: { data: { attributes: { port_info: [{ port: 22 }, { port: 443 }] } } } };
        if (u.pathname.includes('/port_infos/')) return { status: 200, body: { data: { attributes: { status: 'PORT_INFO_STATUS_RECENTLY_CLOSED', first_seen: 1783330192, open_since: 1791100000, last_seen_open: 1791500000 } } } };
        return { status: 404, body: vtErr('NotFoundError') };
    });
    const graph = makeGraph({ a: { id: 'a', type: 'infrastructure.ip_address', data: { ip_address: '1.2.3.4' } } });
    const r = await P['run.vineyard.plugins.vt_port_history'].run({ ...RUN, config: KEY, input: { selection: ['a'] }, params: {}, net, graph });
    const tl = String(graph.updates[0]?.data?.vt_port_history ?? '');
    check('port_history: writes a per-port timeline with status', /22:.*recently-closed/.test(tl) && /443:/.test(tl));
    check('port_history: counts ports', r.counts.ports === 2);
}

// ---- vt_relationships: historical certs → certificate nodes + edges -------------------------
{
    const net = makeNet((u) => {
        if (u.pathname.includes('/historical_ssl_certificates')) return { status: 200, body: { data: [{ id: 'THUMB1', attributes: { thumbprint_sha256: 'THUMB1', subject: { CN: 'vpn.example' }, validity: { not_before: '2026-01-01' } } }] } };
        return { status: 200, body: { data: [] } };
    });
    const graph = makeGraph({ a: { id: 'a', type: 'infrastructure.ip_address', data: { ip_address: '1.2.3.4' } } });
    const r = await P['run.vineyard.plugins.vt_relationships'].run({ ...RUN, config: KEY, input: { selection: ['a'] }, params: { limit: 5 }, net, graph });
    check('relationships: historical cert becomes a certificate node', graph.createdNodes.some((n) => n.type === 'infrastructure.certificate' && n.data.fingerprint_sha256 === 'THUMB1' && n.data.subject_common_name === 'vpn.example'));
    check('relationships: linked "presented certificate"', graph.createdEdges.some((e) => e.label === 'presented certificate'));
    check('relationships: counts', r.counts.certs === 1);
}

// ---- report --------------------------------------------------------------------------------
for (const n of fail) console.log('FAIL', n);
console.log(`\n${fail.length ? 'FAIL' : 'PASS'} ${ok.length} / ${ok.length + fail.length}`);
if (fail.length && typeof process !== 'undefined') process.exit(1);
