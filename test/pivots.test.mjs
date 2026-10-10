// Mock tests for vt_search_from_node's 0.2 pivots (and the shared searchToNodes) — no network, no app.
//   Run: node test/pivots.test.mjs [bundle]
import { loadPlugins, suite, makeGraph, makeNet, RUN, KEY, vtErr, hasEdge } from './harness.mjs';

const P = await loadPlugins();
const F = P['run.vineyard.plugins.vt_search_from_node'];
const S = P['run.vineyard.plugins.vt_search'];
const t = suite('vt_search_from_node pivots');

// ---- fixtures ------------------------------------------------------------------------------
const WANNACRY = 'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa';
const WANNACRY_MD5 = '84c82835a5d21bbcf75a61706d8ab549';
const HOSTEXE = '0067163b0347e42c03f5d2c88085c773cf1770db695d61068c929f3d29ad225f';
const HOSTSTXT = '15e8556b07cc421f94440a3f544967fb1e037ee19414a1f7840f6ead16189789';
// TRIMMED from fixtures/file_report.json (GET /files/ed01eb…, WannaCry).
const WANNACRY_REPORT = { data: { type: 'file', id: WANNACRY, attributes: { sha256: WANNACRY, sha1: '5ff465afaabcbf0150d1a3ab2c2e74f3a4426467', md5: WANNACRY_MD5, size: 3514368, type_description: 'Win32 EXE', meaningful_name: 'diskpart.exe', vhash: '036046656d1570a8z3631lz1fz', pe_info: { imphash: '68f013d7437aa653a8a98a05807afeb1' } } } };
// Same report with vhash removed — exercises auto's fall-through to imphash.
const WANNACRY_NO_VHASH = { data: { ...WANNACRY_REPORT.data, attributes: { ...WANNACRY_REPORT.data.attributes, vhash: undefined } } };
// TRIMMED from fixtures/file_execution_parents.json (the host.exe object, which carries main_icon).
const HOSTEXE_REPORT = { data: { type: 'file', id: HOSTEXE, attributes: { sha256: HOSTEXE, md5: 'aa5dd8f1d073c1dab3ae4b6191b1778f', size: 13257216, type_description: 'Win32 EXE', meaningful_name: 'host.exe', vhash: '2170367555190212400110', pe_info: { imphash: 'f34d5f2d4577ed6d9ceec516c1f5a744' }, main_icon: { raw_md5: '56bd2fb41fc89b6c72ee4d02f6037b8e', dhash: '00040007ccf8e0cc' } } } };
// …with vhash and pe_info removed — exercises auto's fall-through to the main icon.
const HOSTEXE_ICON_ONLY = { data: { type: 'file', id: HOSTEXE, attributes: { sha256: HOSTEXE, main_icon: HOSTEXE_REPORT.data.attributes.main_icon } } };
// TRIMMED from fixtures/search_content_domain.json (hosts.txt hit): a text file with no vhash/imphash/icon.
const HOSTSTXT_REPORT = { data: { type: 'file', id: HOSTSTXT, attributes: { sha256: HOSTSTXT, md5: 'd17c61815b49bc697fe70b1e863f36b1', size: 393813, type_description: 'Text', meaningful_name: 'hosts.txt' } } };

// TRIMMED from fixtures/search_vhash.json / search_imphash.json (identical first page): the source
// file itself comes back as the first hit.
const SIMILAR_HITS = [
    { type: 'file', id: WANNACRY, attributes: { sha256: WANNACRY, sha1: '5ff465afaabcbf0150d1a3ab2c2e74f3a4426467', md5: WANNACRY_MD5, size: 3514368, type_description: 'Win32 EXE', meaningful_name: 'diskpart.exe', last_analysis_stats: { malicious: 68, suspicious: 0, undetected: 4, harmless: 0 } } },
    { type: 'file', id: '109389eea7f9ed4900ba324b831a8a06e732e999e31331856ad65f1209026b1b', attributes: { sha256: '109389eea7f9ed4900ba324b831a8a06e732e999e31331856ad65f1209026b1b', sha1: 'e9e093e055d55127c900542228d56ad6656b1c8e', md5: '10d37df6dbc4a62f3872a1302e284201', size: 3514368, type_description: 'Win32 EXE', meaningful_name: 'C:\\Windows\\tasksche.exe', last_analysis_stats: { malicious: 63, suspicious: 0, undetected: 9, harmless: 0 } } },
    { type: 'file', id: '2f0e80333daf2c11e76ddd758ef400c465d8b2b037838796f4ef0bd9e6f67be9', attributes: { sha256: '2f0e80333daf2c11e76ddd758ef400c465d8b2b037838796f4ef0bd9e6f67be9', sha1: '88e3628e2fdbcccfe79decdf3657cf2a16376fe2', md5: '48b818f9b7b8244fe5fb5440ba00df6e', size: 3514368, type_description: 'Win32 EXE', last_analysis_stats: { malicious: 63, suspicious: 0, undetected: 9, harmless: 0 } } },
];
// Icon-search hits: no main_icon_dhash search body was captured, so these are file objects TRIMMED
// from fixtures/ip_communicating_files.json (both carry main_icon), plus the source itself.
const ICON_HITS = [
    { type: 'file', id: HOSTEXE, attributes: { sha256: HOSTEXE } },
    { type: 'file', id: '0002a5ee3980e9bd840088a4a810a5d58d68a3aa797aa42ed20b1a8c25ab35e1', attributes: { sha256: '0002a5ee3980e9bd840088a4a810a5d58d68a3aa797aa42ed20b1a8c25ab35e1', type_description: 'Win32 EXE' } },
    { type: 'file', id: '000354e64e175f3f7712448e6b192a5f674e9276c2cc0d42724b5bb6ba8bd8a2', attributes: { sha256: '000354e64e175f3f7712448e6b192a5f674e9276c2cc0d42724b5bb6ba8bd8a2', type_description: 'Win32 EXE', meaningful_name: 'f84da76ddaf196d12a600f6f4ddda2e2.virus' } },
];
// TRIMMED from fixtures/search_content_domain.json (content:"avsvmcloud.com" → 3 files).
const CONTENT_HITS = [
    { type: 'file', id: HOSTSTXT, attributes: { sha256: HOSTSTXT, md5: 'd17c61815b49bc697fe70b1e863f36b1', size: 393813, type_description: 'Text', meaningful_name: 'hosts.txt', last_analysis_stats: { malicious: 0, suspicious: 0, undetected: 62, harmless: 0 } } },
    { type: 'file', id: '8b8d5fd34478e6c072e1977335746f8f38f6f80870839cad902d66d08ce10228', attributes: { sha256: '8b8d5fd34478e6c072e1977335746f8f38f6f80870839cad902d66d08ce10228', size: 25376, type_description: 'Python', last_analysis_stats: { malicious: 17, suspicious: 0, undetected: 38, harmless: 0 } } },
    { type: 'file', id: 'a00c2eb3d952bfa9fcfaa1407d6db6d01f5e6e7252d66f722dafb4c5230b3e9b', attributes: { sha256: 'a00c2eb3d952bfa9fcfaa1407d6db6d01f5e6e7252d66f722dafb4c5230b3e9b', size: 21994, type_description: 'Python', last_analysis_stats: { malicious: 11, suspicious: 0, undetected: 52, harmless: 0 } } },
];
// whois:"…" domain hits: measured 5 hits for the pseudonymised FBI email but the body was not kept,
// so ids are illustrative; the object shape is TRIMMED from fixtures/file_embedded_domains.json.
const WHOIS_DOMAIN_HITS = [
    { type: 'domain', id: 'avsvmcloud.com', attributes: { last_analysis_stats: { malicious: 13, suspicious: 0, undetected: 30, harmless: 49 } } },
    { type: 'domain', id: 'sibling-one.example', attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, undetected: 39, harmless: 53 } } },
    { type: 'domain', id: 'sibling-two.example', attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, undetected: 39, harmless: 53 } } },
];
// fixtures/search_whois_email.json — a whois search with no hits.
const NO_HITS = { data: [], meta: { days_back: 365 } };
const IP_HITS = [{ type: 'ip_address', id: '5.5.5.5' }, { type: 'ip_address', id: '74.119.239.234' }, { type: 'domain', id: 'not-a-target.example' }];
// A SHA-256 certificate thumbprint as a cert viewer shows it (uppercase, colon-separated).
const CERT_HEX = '3c7f5e0b9a2d4c6e8f1a3b5d7c9e0f2a4b6d8c0e1f3a5b7d9c2e4f6a8b0d1c3e';
const CERT_COLON = CERT_HEX.toUpperCase().match(/../g).join(':');

const LABELS = {
    ssh: 'shares SSH host key (VT)',
    certSubject: 'shares certificate subject (VT)',
    certThumb: 'shares certificate thumbprint (VT)',
    jarm: 'shares JARM (VT)',
    domainCert: 'certificate names this domain (VT)',
    content: 'contains this string (VT content search)',
    whoisEmail: 'WHOIS names this email (VT)',
    whoisOrg: 'WHOIS names this organization (VT)',
    whoisDomain: 'WHOIS mentions this domain (VT)',
    vhash: 'shares vhash (VT)',
    imphash: 'shares imphash (VT)',
    icon: 'shares main icon (VT)',
};

/** files: hash → body | {status, body}; search(query) → hits array | body | {status, body}. */
function pivotNet({ files = {}, search = () => [] } = {}) {
    const queries = [];
    const fileGets = [];
    const net = makeNet((u) => {
        if (u.pathname === '/api/v3/intelligence/search') {
            const q = u.searchParams.get('query');
            queries.push(q);
            const r = search(q, u);
            if (Array.isArray(r)) return { status: 200, body: { data: r } };
            return r?.status ? r : { status: 200, body: r };
        }
        const m = u.pathname.match(/^\/api\/v3\/files\/([a-f0-9]+)$/);
        if (m) {
            fileGets.push(m[1]);
            const r = files[m[1]];
            if (!r) return { status: 404, body: vtErr('NotFoundError') };
            return r.status ? r : { status: 200, body: r };
        }
        return { status: 404, body: vtErr('NotFoundError') };
    });
    return Object.assign(net, { queries, fileGets });
}
const run = (graph, net, selection, params = {}, extra = {}) =>
    F.run({ ...RUN, config: KEY, input: { selection }, params, net, graph, ...extra });
const node = (id, type, data) => ({ [id]: { id, type, data } });
const noSelfLinks = (graph) => graph.createdEdges.every((e) => e.from !== e.to);
const shaOf = (graph, id) => graph.createdNodes.find((n) => n.id === id)?.data?.sha256;

// ---- manifest ------------------------------------------------------------------------------
{
    const m = F.manifest;
    t.check('manifest: version 0.2.0', m.version === '0.2.0');
    const pv = m.params?.properties?.pivot ?? {};
    t.check('manifest: pivot param = single-value enum, default auto', pv.type === 'string' && pv.title === 'Pivot' && JSON.stringify(pv.enum) === JSON.stringify(['auto', 'content', 'whois', 'imphash', 'vhash', 'icon']) && pv.default === 'auto' && /content/.test(pv.description) && /whois/.test(pv.description));
    t.check('manifest: limit param kept', m.params?.properties?.limit?.maximum === 300 && m.params?.properties?.limit?.default === 25);
    const refs = (l) => l.map((r) => `${r.category}.${r.name}`).join();
    t.check('manifest: consumes the 0.1 types + email, organization, file_hash, url', refs(m.io.consumes) === 'infrastructure.ssh_host_key,infrastructure.certificate,infrastructure.ip_address,infrastructure.domain,identity.email_address,identity.organization,threat.file_hash,web.url');
    t.check('manifest: consumes TypeRefs carry their type packs', m.io.consumes.find((r) => r.name === 'email_address').typepack === 'run.vineyard.typepacks.identity' && m.io.consumes.find((r) => r.name === 'file_hash').typepack === 'run.vineyard.typepacks.threat');
    t.check('manifest: produces ip_address, domain, file_hash', refs(m.io.produces) === 'infrastructure.ip_address,infrastructure.domain,threat.file_hash');
    t.check('manifest: description quotes every edge label', Object.values(LABELS).every((l) => m.description.includes(`'${l}'`)));
    t.check('manifest: description ends with the key/platform sentence', m.description.endsWith('Needs a VirusTotal Premium key. Desktop only.'));
}

// ---- auto: email → entity:domain whois:"<email>" ---------------------------------------------
{
    const net = pivotNet({ search: () => WHOIS_DOMAIN_HITS });
    const graph = makeGraph(node('e', 'identity.email_address', { email: 'D76E663655D6F79Cs@fbi.gov', vt_pseudonymised: true }));
    const r = await run(graph, net, ['e']);
    t.check('auto email: pseudonymised but complete address is searched, lowercased', net.queries.join() === 'entity:domain whois:"d76e663655d6f79cs@fbi.gov"');
    const doms = graph.createdNodes.filter((n) => n.type === 'infrastructure.domain');
    t.check('auto email: each domain hit becomes a Domain via the shared mapper', doms.length === 3 && doms[1].data.domain_name === 'sibling-one.example' && doms[1].data.vt_harmless === 53);
    t.check('auto email: hit → email "WHOIS names this email (VT)"', doms.every((d) => hasEdge(graph, d.id, 'e', LABELS.whoisEmail)) && graph.createdEdges.length === 3);
    t.check('auto email: counts', r.counts.pivoted === 1 && r.counts.domains === 3 && r.counts.linked === 3 && net.fileGets.length === 0);
}
{
    const net = pivotNet({ search: () => WHOIS_DOMAIN_HITS });
    const graph = makeGraph({
        ...node('t', 'identity.email_address', { email: 'bd343e776d5ffe96s@' }),
        ...node('px', 'identity.email_address', { email: 'contact@whoisguard.com' }),
    });
    const r = await run(graph, net, ['t', 'px']);
    t.check('auto email: truncated (measured 0 hits) and privacy-proxy addresses are skipped, no request', r.counts.skipped === 2 && net.calls.length === 0);
}

// ---- auto: organization → entity:domain whois:"<name>" -----------------------------------------
{
    const net = pivotNet({ search: () => WHOIS_DOMAIN_HITS.slice(1) });
    const graph = makeGraph(node('o', 'identity.organization', { name: 'Federal Bureau of Investigation' }));
    const r = await run(graph, net, ['o']);
    t.check('auto org: whois query on the name', net.queries.join() === 'entity:domain whois:"Federal Bureau of Investigation"');
    t.check('auto org: hit → org "WHOIS names this organization (VT)"', graph.createdEdges.length === 2 && graph.createdEdges.every((e) => e.to === 'o' && e.label === LABELS.whoisOrg) && r.counts.linked === 2);
}
{
    const net = pivotNet({ search: () => WHOIS_DOMAIN_HITS });
    const graph = makeGraph({
        ...node('p1', 'identity.organization', { name: 'da45206aa6bafae3' }),
        ...node('p2', 'identity.organization', { name: 'REDACTED FOR PRIVACY' }),
        ...node('p3', 'identity.organization', { name: 'Acme "Holdings"' }),
        ...node('p4', 'identity.organization', { name: '  ' }),
    });
    const logs = [];
    const r = await run(graph, net, ['p1', 'p2', 'p3', 'p4'], {}, { progress: { set() {}, log: (l) => logs.push(l) } });
    t.check('auto org: 16-hex pseudonym, placeholder, double-quoted and empty names are skipped, no request', r.counts.skipped === 4 && r.counts.pivoted === 0 && net.calls.length === 0);
    t.check('auto org: each skip is logged with the node and the pivot', logs.length === 4 && logs.includes("da45206aa6bafae3: no searchable value for pivot 'auto'"));
}
{
    // The NARROW placeholder test: a hosting / proxy vendor whose name merely contains 'private' or
    // 'proxy' is a legitimate pivot (the 0.2.0 broad substring test refused all three).
    const net = pivotNet({ search: () => WHOIS_DOMAIN_HITS });
    const graph = makeGraph({
        ...node('pl', 'identity.organization', { name: 'Private Layer INC' }),
        ...node('pr', 'identity.organization', { name: 'ProxyRack LLC' }),
        ...node('ps', 'identity.email_address', { email: 'admin@proxy-seller.com' }),
    });
    const r = await run(graph, net, ['pl', 'pr', 'ps']);
    t.check('auto org/email: names merely containing private / proxy are searched', JSON.stringify(net.queries) === JSON.stringify(['entity:domain whois:"Private Layer INC"', 'entity:domain whois:"ProxyRack LLC"', 'entity:domain whois:"admin@proxy-seller.com"']) && r.counts.pivoted === 3 && r.counts.skipped === 0);
}
{
    // Unmistakable privacy-service / redaction values and empty-meaning values are still never searched.
    const net = pivotNet({ search: () => WHOIS_DOMAIN_HITS });
    const graph = makeGraph({
        ...node('q1', 'identity.organization', { name: 'Domains By Proxy, LLC' }),
        ...node('q2', 'identity.organization', { name: 'Privacy service provided by Withheld for Privacy ehf' }),
        ...node('q3', 'identity.organization', { name: 'Data Protected' }),
        ...node('q4', 'identity.email_address', { email: '5be9a8e3b2fd4b0b.protect@withheldforprivacy.com' }),
        ...node('q5', 'identity.email_address', { email: 'actor-example.net@domainsbyproxy.com' }),
        ...node('j1', 'identity.organization', { name: 'N/A' }),
        ...node('j2', 'identity.organization', { name: '-' }),
        ...node('j3', 'identity.organization', { name: 'Not Available From Registry' }),
        ...node('j4', 'identity.email_address', { email: 'none@example.com' }),
    });
    const r = await run(graph, net, ['q1', 'q2', 'q3', 'q4', 'q5', 'j1', 'j2', 'j3', 'j4']);
    t.check('auto org/email: privacy-service, redaction and N/A-style values are skipped, no request', r.counts.skipped === 9 && net.calls.length === 0);
    const net2 = pivotNet({ search: () => WHOIS_DOMAIN_HITS });
    const r2 = await run(makeGraph({ ...node('c', 'identity.organization', { name: '北京某某科技有限公司' }), ...node('qq', 'identity.email_address', { email: '12345678@qq.com' }) }), net2, ['c', 'qq'], { pivot: 'whois' });
    t.check('whois: a CJK organization and an all-digit QQ address are searched', r2.counts.pivoted === 2 && net2.queries.join('|') === 'entity:domain whois:"北京某某科技有限公司"|entity:domain whois:"12345678@qq.com"');
}

// ---- auto: file_hash → vhash, else imphash, else main icon ----------------------------------------
{
    const net = pivotNet({ files: { [WANNACRY]: WANNACRY_REPORT }, search: () => SIMILAR_HITS });
    const graph = makeGraph(node('f', 'threat.file_hash', { sha256: WANNACRY }));
    const r = await run(graph, net, ['f']);
    t.check('auto file: one GET /files/{sha256}, then vhash:"<vhash>"', net.fileGets.join() === WANNACRY && net.queries.join() === 'vhash:"036046656d1570a8z3631lz1fz"');
    t.check('auto file: all 3 hits become File Hashes via the shared mapper', r.counts.files === 3 && graph.createdNodes.some((n) => n.data.vt_name === 'C:\\Windows\\tasksche.exe' && n.data.malicious_count === 63 && n.data.md5 === '10d37df6dbc4a62f3872a1302e284201'));
    t.check('auto file: the source file among the hits is NOT linked (sha256)', !graph.createdEdges.some((e) => shaOf(graph, e.from) === WANNACRY));
    t.check('auto file: the 2 siblings → source "shares vhash (VT)"', graph.createdEdges.length === 2 && graph.createdEdges.every((e) => e.to === 'f' && e.label === LABELS.vhash) && r.counts.linked === 2);
    t.check('auto file: no self-links', noSelfLinks(graph));
}
{
    // Source known only by MD5: the self check uses the SHA-256 the report returns.
    const net = pivotNet({ files: { [WANNACRY_MD5]: WANNACRY_REPORT }, search: () => SIMILAR_HITS });
    const graph = makeGraph(node('fm', 'threat.file_hash', { md5: WANNACRY_MD5 }));
    const r = await run(graph, net, ['fm']);
    t.check('auto file (md5 only): reads /files/{md5}; source hit recognised by the reported sha256', net.fileGets.join() === WANNACRY_MD5 && r.counts.linked === 2 && !graph.createdEdges.some((e) => shaOf(graph, e.from) === WANNACRY));
}
{
    const net = pivotNet({ files: { [WANNACRY]: WANNACRY_NO_VHASH }, search: () => SIMILAR_HITS });
    const graph = makeGraph(node('f', 'threat.file_hash', { sha256: WANNACRY }));
    const r = await run(graph, net, ['f']);
    t.check('auto file: no vhash → imphash:<imphash> (unquoted)', net.queries.join() === 'imphash:68f013d7437aa653a8a98a05807afeb1');
    t.check('auto file: imphash siblings → "shares imphash (VT)", source excluded', r.counts.linked === 2 && graph.createdEdges.every((e) => e.label === LABELS.imphash && e.to === 'f'));
}
{
    const net = pivotNet({ files: { [HOSTEXE]: HOSTEXE_ICON_ONLY }, search: () => ICON_HITS });
    const graph = makeGraph(node('h', 'threat.file_hash', { sha256: HOSTEXE }));
    const r = await run(graph, net, ['h']);
    t.check('auto file: no vhash/imphash → main_icon_dhash:<dhash>', net.queries.join() === 'main_icon_dhash:00040007ccf8e0cc');
    t.check('auto file: icon siblings → "shares main icon (VT)", source excluded', r.counts.linked === 2 && graph.createdEdges.every((e) => e.label === LABELS.icon && e.to === 'h') && !graph.createdEdges.some((e) => shaOf(graph, e.from) === HOSTEXE));
}
{
    const net = pivotNet({ files: { [HOSTSTXT]: HOSTSTXT_REPORT } });
    const graph = makeGraph(node('x', 'threat.file_hash', { sha256: HOSTSTXT }));
    const r = await run(graph, net, ['x']);
    t.check('auto file: a file with none of the three is skipped after its one GET', r.counts.skipped === 1 && net.fileGets.length === 1 && net.queries.length === 0);
}

// ---- explicit imphash / vhash / icon -----------------------------------------------------------
{
    const net = pivotNet({ files: { [WANNACRY]: WANNACRY_REPORT }, search: () => SIMILAR_HITS });
    const graph = makeGraph(node('f', 'threat.file_hash', { sha256: WANNACRY }));
    await run(graph, net, ['f'], { pivot: 'imphash' });
    t.check('mode imphash: forces imphash even when the file has a vhash', net.queries.join() === 'imphash:68f013d7437aa653a8a98a05807afeb1' && graph.createdEdges.every((e) => e.label === LABELS.imphash));
}
{
    const net = pivotNet({ files: { [HOSTEXE]: HOSTEXE_REPORT }, search: () => ICON_HITS });
    const graph = makeGraph(node('h', 'threat.file_hash', { sha256: HOSTEXE }));
    await run(graph, net, ['h'], { pivot: 'icon' });
    t.check('mode icon: forces the main icon even when vhash/imphash exist', net.queries.join() === 'main_icon_dhash:00040007ccf8e0cc');
    const net2 = pivotNet({ files: { [HOSTEXE]: HOSTEXE_REPORT }, search: () => ICON_HITS });
    await run(makeGraph(node('h', 'threat.file_hash', { sha256: HOSTEXE })), net2, ['h'], { pivot: 'vhash' });
    t.check('mode vhash: vhash:"<vhash>"', net2.queries.join() === 'vhash:"2170367555190212400110"');
}
{
    const net = pivotNet({ files: { [WANNACRY]: WANNACRY_REPORT, [HOSTSTXT]: HOSTSTXT_REPORT }, search: () => SIMILAR_HITS });
    const graph = makeGraph({ ...node('f', 'threat.file_hash', { sha256: WANNACRY }), ...node('x', 'threat.file_hash', { sha256: HOSTSTXT }) });
    const r = await run(graph, net, ['f', 'x'], { pivot: 'icon' });
    t.check('mode icon: files without a main icon are skipped after one GET each', r.counts.skipped === 2 && net.fileGets.length === 2 && net.queries.length === 0);
}
{
    const net = pivotNet({ search: () => SIMILAR_HITS });
    const graph = makeGraph({
        ...node('d', 'infrastructure.domain', { domain_name: 'avsvmcloud.com' }),
        ...node('e', 'identity.email_address', { email: 'ops@acme-bp.net' }),
        ...node('k', 'infrastructure.ssh_host_key', { fingerprint_sha256: 'SHA256:93mvCQWDCdlDbpFrdWGQrQb4BKMSCsjp/x2tUsCTQbg' }),
    });
    let total = 0;
    for (const pivot of ['imphash', 'vhash', 'icon']) total += (await run(graph, net, ['d', 'e', 'k'], { pivot })).counts.skipped;
    t.check('mode imphash/vhash/icon: non-file nodes are skipped, no request', total === 9 && net.calls.length === 0);
}

// ---- content ----------------------------------------------------------------------------------
{
    // The mixed entities are added to the measured page to prove only the target (files) is linked.
    const net = pivotNet({ search: () => [...CONTENT_HITS, { type: 'ip_address', id: '74.119.239.234' }, { type: 'domain', id: 'freescanonline.com' }] });
    const graph = makeGraph(node('d', 'infrastructure.domain', { domain_name: 'AVSVMCLOUD.COM' }));
    const r = await run(graph, net, ['d'], { pivot: 'content' });
    t.check('content domain: content:"<domain>" (lowercased)', net.queries.join() === 'content:"avsvmcloud.com"');
    const files = graph.createdNodes.filter((n) => n.type === 'threat.file_hash');
    t.check('content domain: file hit → domain "contains this string (VT content search)"', files.length === 3 && files.every((f) => hasEdge(graph, f.id, 'd', LABELS.content)));
    t.check('content domain: IP / Domain hits are created but NOT linked', r.counts.hosts === 1 && r.counts.domains === 1 && graph.createdEdges.length === 3 && r.counts.linked === 3);
    t.check('content domain: hosts.txt hit mapped by the shared mapper', files[0].data.vt_name === 'hosts.txt' && files[0].data.undetected_count === 62);
}
{
    const net = pivotNet({ search: () => CONTENT_HITS });
    const graph = makeGraph(node('i', 'infrastructure.ip_address', { ip_address: '74.119.239.234' }));
    await run(graph, net, ['i'], { pivot: 'content' });
    t.check('content ip: content:"<ip>"', net.queries.join() === 'content:"74.119.239.234"' && graph.createdEdges.length === 3 && graph.createdEdges.every((e) => e.to === 'i' && e.label === LABELS.content));
}
{
    const net = pivotNet({ search: () => CONTENT_HITS });
    const graph = makeGraph(node('u', 'web.url', { url: 'http://avsvmcloud.com/swip/upd/' }));
    await run(graph, net, ['u']);
    t.check('auto url: content:"<url>", files linked "contains this string (VT content search)"', net.queries.join() === 'content:"http://avsvmcloud.com/swip/upd/"' && graph.createdEdges.length === 3 && graph.createdEdges.every((e) => e.to === 'u' && e.label === LABELS.content));
    const net2 = pivotNet({ search: () => CONTENT_HITS });
    await run(makeGraph(node('u', 'web.url', { url: 'http://x.example/?q="a"' })), net2, ['u'], { pivot: 'content' });
    t.check('content url: a value with a double quote is skipped, no request', net2.calls.length === 0);
}
{
    const net = pivotNet({ search: () => CONTENT_HITS });
    const graph = makeGraph({
        ...node('e', 'identity.email_address', { email: 'ops@acme-bp.net' }),
        ...node('o', 'identity.organization', { name: 'Acme' }),
        ...node('f', 'threat.file_hash', { sha256: WANNACRY }),
        ...node('k', 'infrastructure.ssh_host_key', { fingerprint_sha256: 'SHA256:93mvCQWDCdlDbpFrdWGQrQb4BKMSCsjp/x2tUsCTQbg' }),
    });
    const r = await run(graph, net, ['e', 'o', 'f', 'k'], { pivot: 'content' });
    t.check('content: email / org / file / ssh key are skipped, no request', r.counts.skipped === 4 && net.calls.length === 0);
}

// ---- whois -------------------------------------------------------------------------------------
{
    const net = pivotNet({ search: () => WHOIS_DOMAIN_HITS });
    const graph = makeGraph(node('d', 'infrastructure.domain', { domain_name: 'avsvmcloud.com' }));
    const r = await run(graph, net, ['d'], { pivot: 'whois' });
    t.check('whois domain: entity:domain whois:"<domain>"', net.queries.join() === 'entity:domain whois:"avsvmcloud.com"');
    t.check('whois domain: the domain itself among the hits is not linked', !graph.createdEdges.some((e) => graph.createdNodes.find((n) => n.id === e.from)?.data.domain_name === 'avsvmcloud.com'));
    t.check('whois domain: others → domain "WHOIS mentions this domain (VT)"', r.counts.linked === 2 && graph.createdEdges.every((e) => e.to === 'd' && e.label === LABELS.whoisDomain) && noSelfLinks(graph));
}
{
    const net = pivotNet({ search: () => WHOIS_DOMAIN_HITS });
    const graph = makeGraph({
        ...node('e', 'identity.email_address', { email: 'd76e663655d6f79cs@fbi.gov' }),
        ...node('i', 'infrastructure.ip_address', { ip_address: '74.119.239.234', vt_jarm: 'J' }),
        ...node('f', 'threat.file_hash', { sha256: WANNACRY }),
    });
    const r = await run(graph, net, ['e', 'i', 'f'], { pivot: 'whois' });
    t.check('whois: email pivots with the email label; IP and file are skipped', net.queries.join() === 'entity:domain whois:"d76e663655d6f79cs@fbi.gov"' && r.counts.skipped === 2 && graph.createdEdges.every((e) => e.to === 'e' && e.label === LABELS.whoisEmail));
}
{
    const net = pivotNet({ search: () => NO_HITS });
    const graph = makeGraph(node('e', 'identity.email_address', { email: 'hostmaster@nsone.net' }));
    const r = await run(graph, net, ['e'], { pivot: 'whois' });
    t.check('whois: zero hits is a pivot with nothing linked', r.counts.pivoted === 1 && r.counts.linked === 0 && graph.createdNodes.length === 0);
}

// ---- auto: the 0.1 host pivots are unchanged ------------------------------------------------------
{
    const net = pivotNet({ search: () => IP_HITS });
    const graph = makeGraph({
        ...node('k', 'infrastructure.ssh_host_key', { fingerprint_sha256: 'SHA256:93mvCQWDCdlDbpFrdWGQrQb4BKMSCsjp/x2tUsCTQbg' }),
        ...node('c1', 'infrastructure.certificate', { subject_common_name: 'vpn.example', fingerprint_sha256: 'AB12' }),
        ...node('c2', 'infrastructure.certificate', { fingerprint_sha256: CERT_HEX }),
        ...node('i', 'infrastructure.ip_address', { ip_address: '74.119.239.234', vt_jarm: '2ad2ad16d2ad2ad00042d42d00042ddb04deffa1705e2edc44cae1ed24a4da' }),
        ...node('d', 'infrastructure.domain', { domain_name: 'avsvmcloud.com' }),
        ...node('n', 'infrastructure.ip_address', { ip_address: '1.2.3.4' }),
    });
    const r = await run(graph, net, ['k', 'c1', 'c2', 'i', 'd', 'n']);
    t.check('auto host: queries exactly as 0.1', JSON.stringify(net.queries) === JSON.stringify([
        'entity:ip fingerprint:"SHA256:93mvCQWDCdlDbpFrdWGQrQb4BKMSCsjp/x2tUsCTQbg"',
        'entity:ip ssl_subject:"vpn.example"',
        `entity:ip ssl_thumbprint:${CERT_HEX}`,
        'entity:ip fingerprint:"2ad2ad16d2ad2ad00042d42d00042ddb04deffa1705e2edc44cae1ed24a4da"',
        'entity:ip ssl_subject:"avsvmcloud.com"',
    ]));
    const labelsTo = (id) => [...new Set(graph.createdEdges.filter((e) => e.to === id).map((e) => e.label))].join();
    t.check('auto host: labels as 0.1', labelsTo('k') === LABELS.ssh && labelsTo('c1') === LABELS.certSubject && labelsTo('c2') === LABELS.certThumb && labelsTo('i') === LABELS.jarm && labelsTo('d') === LABELS.domainCert);
    t.check('auto host: IP without a JARM is skipped', r.counts.skipped === 1 && !graph.createdEdges.some((e) => e.to === 'n'));
    t.check('auto host: the JARM source IP among its own hits is not linked to itself', graph.createdEdges.filter((e) => e.to === 'i').length === 1);
    t.check('auto host: only IP hits are linked (the domain hit is not)', !graph.createdEdges.some((e) => graph.createdNodes.find((n) => n.id === e.from)?.type !== 'infrastructure.ip_address'));
    t.check('auto host: counts', r.counts.pivoted === 5 && r.counts.hosts === 10 && r.counts.domains === 5 && r.counts.linked === 9 && noSelfLinks(graph));
}
{
    const net = pivotNet({ search: () => IP_HITS });
    const graph = makeGraph(node('k', 'infrastructure.ssh_host_key', { fingerprint_sha256: 'SHA256:"x' }));
    const r = await run(graph, net, ['k']);
    t.check('auto host: a fingerprint containing a double quote is skipped', r.counts.skipped === 1 && net.calls.length === 0);
}
{
    // ssl_thumbprint goes into the query UNQUOTED: only a SHA-1 / SHA-256 hex value (colons allowed) is used.
    const net = pivotNet({ search: () => IP_HITS });
    const graph = makeGraph({
        ...node('cc', 'infrastructure.certificate', { fingerprint_sha256: CERT_COLON }),
        ...node('cs', 'infrastructure.certificate', { fingerprint_sha256: `${CERT_HEX.slice(0, 32)} OR entity:file` }),
        ...node('ct', 'infrastructure.certificate', { fingerprint_sha256: 'AB12' }),
        ...node('cl', 'infrastructure.certificate', { fingerprint_sha256: CERT_HEX + 'ab' }),
    });
    const logs = [];
    const r = await run(graph, net, ['cc', 'cs', 'ct', 'cl'], {}, { progress: { set() {}, log: (l) => logs.push(l) } });
    t.check('auto cert: a colon-separated uppercase thumbprint becomes bare lowercase hex', net.queries.join() === `entity:ip ssl_thumbprint:${CERT_HEX}`);
    t.check('auto cert: a thumbprint with whitespace / extra terms, a short one and a 66-hex one are skipped', r.counts.skipped === 3 && r.counts.pivoted === 1);
    t.check('auto cert: each skip is logged', logs.filter((l) => /no searchable value for pivot 'auto'/.test(l)).length === 3);
}
{
    // A trailing backslash would escape the closing quote; a control character has no business in a query.
    const net = pivotNet({ search: () => CONTENT_HITS });
    const graph = makeGraph({
        ...node('ob', 'identity.organization', { name: 'Evil Corp\\' }),
        ...node('ub', 'web.url', { url: 'http://x.example/a\\b' }),
        ...node('uc', 'web.url', { url: 'http://x.example/a\nb' }),
        ...node('kb', 'infrastructure.ssh_host_key', { fingerprint_sha256: 'SHA256:93mvCQWDCdlDbpFrdWGQrQb4BKMSCsjp/x2tUsCTQbg\\' }),
    });
    const r = await run(graph, net, ['ob', 'ub', 'uc', 'kb']);
    t.check('quoting: values with a backslash or a control character are skipped, no request', r.counts.skipped === 4 && net.calls.length === 0);
}

// ---- errors: per-node misses vs run-ending 403 -------------------------------------------------
{
    const net = pivotNet({ files: { [HOSTEXE]: { status: 403, body: vtErr('ForbiddenError') } }, search: () => WHOIS_DOMAIN_HITS });
    const graph = makeGraph({
        ...node('gone', 'threat.file_hash', { sha256: 'b'.repeat(64) }),
        ...node('h', 'threat.file_hash', { sha256: HOSTEXE }),
        ...node('e', 'identity.email_address', { email: 'd76e663655d6f79cs@fbi.gov' }),
    });
    const logs = [];
    const r = await run(graph, net, ['gone', 'h', 'e'], {}, { progress: { set() {}, log: (l) => logs.push(l) } });
    t.check('errors: 404 and 403 on GET /files skip just that node (misses)', r.counts.misses === 2 && net.fileGets.length === 2);
    t.check('errors: the rest still runs', r.counts.pivoted === 1 && r.counts.linked === 3 && net.queries.length === 1);
    t.check('errors: misses logged with a reason', logs.some((l) => /no VirusTotal record/.test(l)) && logs.some((l) => /needs a VirusTotal Premium key/.test(l)));
    t.check('errors: summary', r.summary === '1 pivot(s): 0 host(s), 3 domain(s), 0 file(s), 3 link(s), 2 missed (see log)');
}
{
    let n = 0;
    const net = pivotNet({ search: () => (n++ === 0 ? { status: 400, body: vtErr('InvalidArgumentError') } : CONTENT_HITS) });
    const graph = makeGraph({ ...node('d', 'infrastructure.domain', { domain_name: 'avsvmcloud.com' }), ...node('i', 'infrastructure.ip_address', { ip_address: '74.119.239.234' }) });
    const r = await run(graph, net, ['d', 'i'], { pivot: 'content' });
    t.check('errors: a 400 on one search is a miss; the next node still pivots', r.counts.misses === 1 && r.counts.pivoted === 1 && r.counts.linked === 3);
}
{
    const net = pivotNet({ search: () => ({ status: 403, body: vtErr('ForbiddenError') }) });
    const graph = makeGraph(node('e', 'identity.email_address', { email: 'd76e663655d6f79cs@fbi.gov' }));
    let threw = null;
    try { await run(graph, net, ['e']); } catch (e) { threw = e; }
    t.check('errors: a 403 on the only search ends the run with the Premium message', !!threw && /needs a Premium key/.test(threw.message));
}
{
    // Every family 403s: each family is tried once, then the run ends with the Premium message.
    const net = pivotNet({ search: () => ({ status: 403, body: vtErr('ForbiddenError') }) });
    const graph = makeGraph({
        ...node('e', 'identity.email_address', { email: 'd76e663655d6f79cs@fbi.gov' }),
        ...node('k', 'infrastructure.ssh_host_key', { fingerprint_sha256: 'SHA256:93mvCQWDCdlDbpFrdWGQrQb4BKMSCsjp/x2tUsCTQbg' }),
        ...node('k2', 'infrastructure.ssh_host_key', { fingerprint_sha256: 'SHA256:f3M9BMLOu5xHZpDsxzpc4aS7LyxFq/dOgZC2T/MvhJQ' }),
    });
    let threw = null;
    try { await run(graph, net, ['e', 'k', 'k2']); } catch (e) { threw = e; }
    t.check('errors: no search succeeds → Premium message, after one try per family', !!threw && /needs a Premium key/.test(threw.message) && JSON.stringify(net.queries) === JSON.stringify(['entity:domain whois:"d76e663655d6f79cs@fbi.gov"', 'entity:ip fingerprint:"SHA256:93mvCQWDCdlDbpFrdWGQrQb4BKMSCsjp/x2tUsCTQbg"']));
}
{
    // auto mixes families: a 403 on content: alone skips the content pivots, the others still run.
    const search = (q) => (q.startsWith('content:') ? { status: 403, body: vtErr('ForbiddenError') } : IP_HITS);
    const net = pivotNet({ search });
    const graph = makeGraph({
        ...node('k', 'infrastructure.ssh_host_key', { fingerprint_sha256: 'SHA256:93mvCQWDCdlDbpFrdWGQrQb4BKMSCsjp/x2tUsCTQbg' }),
        ...node('u', 'web.url', { url: 'http://avsvmcloud.com/swip/upd/' }),
        ...node('k2', 'infrastructure.ssh_host_key', { fingerprint_sha256: 'SHA256:f3M9BMLOu5xHZpDsxzpc4aS7LyxFq/dOgZC2T/MvhJQ' }),
    });
    const logs = [];
    const r = await run(graph, net, ['k', 'u', 'k2'], {}, { progress: { set() {}, log: (l) => logs.push(l) } });
    t.check('errors: content 403 mid-run is a miss; the next node still pivots', JSON.stringify(net.queries) === JSON.stringify(['entity:ip fingerprint:"SHA256:93mvCQWDCdlDbpFrdWGQrQb4BKMSCsjp/x2tUsCTQbg"', 'content:"http://avsvmcloud.com/swip/upd/"', 'entity:ip fingerprint:"SHA256:f3M9BMLOu5xHZpDsxzpc4aS7LyxFq/dOgZC2T/MvhJQ"']) && r.counts.pivoted === 2 && r.counts.misses === 1);
    t.check('errors: k2 hits linked "shares SSH host key (VT)"', graph.createdEdges.filter((e) => e.to === 'k2' && e.label === LABELS.ssh).length === 2);
    t.check('errors: the 403 family is logged', logs.some((l) => /^content: searches return 403 on this key/.test(l)));
    t.check('errors: summary counts the miss', r.summary === '2 pivot(s): 4 host(s), 2 domain(s), 0 file(s), 4 link(s), 1 missed (see log)');
}
{
    // The 403 comes FIRST: the content family is remembered (no 2nd content request), the run does not end.
    const search = (q) => (q.startsWith('content:') ? { status: 403, body: vtErr('ForbiddenError') } : IP_HITS);
    const net = pivotNet({ search });
    const graph = makeGraph({
        ...node('u', 'web.url', { url: 'http://avsvmcloud.com/swip/upd/' }),
        ...node('u2', 'web.url', { url: 'http://freescanonline.com/' }),
        ...node('k', 'infrastructure.ssh_host_key', { fingerprint_sha256: 'SHA256:93mvCQWDCdlDbpFrdWGQrQb4BKMSCsjp/x2tUsCTQbg' }),
    });
    const logs = [];
    const r = await run(graph, net, ['u', 'u2', 'k'], {}, { progress: { set() {}, log: (l) => logs.push(l) } });
    t.check('errors: first-node 403 does not end the run; the 2nd content pivot makes no request', JSON.stringify(net.queries) === JSON.stringify(['content:"http://avsvmcloud.com/swip/upd/"', 'entity:ip fingerprint:"SHA256:93mvCQWDCdlDbpFrdWGQrQb4BKMSCsjp/x2tUsCTQbg"']) && r.counts.misses === 2 && r.counts.pivoted === 1 && r.counts.linked === 2);
    t.check('errors: the 403 family is logged once', logs.filter((l) => /403/.test(l)).length === 1);
}

// ---- params: limit, unknown pivot ---------------------------------------------------------------
{
    const lim = async (limit) => {
        const net = pivotNet({ search: () => WHOIS_DOMAIN_HITS });
        await run(makeGraph(node('e', 'identity.email_address', { email: 'ops@acme-bp.net' })), net, ['e'], limit === undefined ? {} : { limit });
        return new URL(net.calls[0].url).searchParams.get('limit');
    };
    t.check('limit: passed through, clamped to 300, default 25', (await lim(7)) === '7' && (await lim(9999)) === '300' && (await lim(undefined)) === '25' && (await lim('x')) === '25');
    const net = pivotNet({ search: () => WHOIS_DOMAIN_HITS });
    await run(makeGraph(node('e', 'identity.email_address', { email: 'ops@acme-bp.net' })), net, ['e'], { pivot: 'bogus' });
    t.check('pivot: an unknown value falls back to auto', net.queries.join() === 'entity:domain whois:"ops@acme-bp.net"');
}

// ---- vt_search still works on the generalised searchToNodes ------------------------------------
{
    const net = pivotNet({ search: () => [...CONTENT_HITS.slice(0, 1), { type: 'ip_address', id: '9.9.9.9' }, { type: 'domain', id: 'evil.example' }, { type: 'url', id: 'u', attributes: { url: 'http://evil.example/x' } }, { type: 'domain', id: '129.214.248.87.in-addr.arpa' }, { type: 'collection', id: 'c1' }] });
    const graph = makeGraph({});
    const r = await S.run({ ...RUN, config: KEY, input: { selection: [] }, params: { query: 'content:"avsvmcloud.com"', limit: 10 }, net, graph });
    t.check('vt_search: query run verbatim', net.queries.join() === 'content:"avsvmcloud.com"');
    t.check('vt_search: one node per entity, no edges', r.counts.ips === 1 && r.counts.domains === 1 && r.counts.urls === 1 && r.counts.files === 1 && graph.createdEdges.length === 0);
    t.check('vt_search: arpa name and unknown entity counted as other, no node', r.counts.other === 2 && r.counts.matched === 6 && graph.createdNodes.length === 4);
    t.check('vt_search: summary unchanged', r.summary === '6 match(es): 1 IP(s), 1 domain(s), 1 URL(s), 1 file(s)');
}

// ---- the pack lists vt_whois_history after vt_relationships ----------------------------------------
{
    const ids = Object.keys(P);
    t.check('pack: vt_whois_history wired after vt_relationships', ids.indexOf('run.vineyard.plugins.vt_whois_history') === ids.indexOf('run.vineyard.plugins.vt_relationships') + 1);
}

t.report();
