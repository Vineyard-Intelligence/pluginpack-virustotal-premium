// Mock tests for vt_whois_history — no network, no app.
//   Run: node test/whois.test.mjs [bundle]
import { loadPlugins, suite, makeGraph, makeNet, RUN, KEY, vtErr, hasEdge } from './harness.mjs';

const P = await loadPlugins();
const W = P['run.vineyard.plugins.vt_whois_history'];
const t = suite('vt_whois_history');
const run = (graph, net, selection, params = {}, extra = {}) =>
    W.run({ ...RUN, config: KEY, input: { selection }, params, net, graph, ...extra });

// ---- fixtures ------------------------------------------------------------------------------
// TRIMMED from fixtures/domain_historical_whois.json (GET /domains/avsvmcloud.com/historical_whois,
// measured 2026-10-10): all 10 snapshots in VT's order (newest first), ids shortened, whois_map cut
// to the keys the plugin reads plus the non-registrant contacts it must ignore.
const DOMAIN_SNAPSHOTS = [
    {id:"afd1e812688d",type:"whois",attributes:{first_seen_date:1782423262,last_updated:1782392493,registrar_name:"Stichting Registrar of Last Resort Foundation",whois_map:{"Registrar":"Stichting Registrar of Last Resort Foundation","Name Server":"SUNBURST-NS-A.SINKHOLE.SHADOWSERVER.ORG | SUNBURST-NS-B.SINKHOLE.SHADOWSERVER.ORG","Creation Date":"2018-07-25T11:38:29Z"}}},
    {id:"6d1fa09a9424",type:"whois",attributes:{first_seen_date:1750859154,last_updated:1750856476,registrar_name:"Stichting Registrar of Last Resort Foundation",whois_map:{"Registrar":"Stichting Registrar of Last Resort Foundation","Name Server":"SUNBURST-NS-A.SINKHOLE.SHADOWSERVER.ORG | SUNBURST-NS-B.SINKHOLE.SHADOWSERVER.ORG","Creation Date":"2018-07-25T11:38:29Z"}}},
    {id:"8ac0151177bc",type:"whois",attributes:{first_seen_date:1738315057,last_updated:1737136990,registrar_name:"Stichting Registrar of Last Resort Foundation",registrant_country:"US",whois_map:{"Registrar":"Stichting Registrar of Last Resort Foundation","Name Server":"SUNBURST-NS-A.SINKHOLE.SHADOWSERVER.ORG | SUNBURST-NS-B.SINKHOLE.SHADOWSERVER.ORG","Registrant Email":"d76e663655d6f79cs@fbi.gov","Registrant Organisation":"6fd7c0f890337271","Registrant Name":"a741ddb581c387d9","Creation Date":"2018-07-25T11:38:29Z","Admin Organisation":"Federal Bureau of Investigation","Admin Email":"d76e663655d6f79cs@fbi.gov","Tech Email":"4babf6fcc6f7794as@rolr.eu","Registry Registrant ID":"REDACTED FOR PRIVACY"}}},
    {id:"230681e02bff",type:"whois",attributes:{first_seen_date:1737775622,last_updated:1737136990,registrar_name:"Stichting Registrar of Last Resort Foundation",whois_map:{"Registrar":"Stichting Registrar of Last Resort Foundation","Name Server":"SUNBURST-NS-A.SINKHOLE.SHADOWSERVER.ORG | SUNBURST-NS-B.SINKHOLE.SHADOWSERVER.ORG","Creation Date":"2018-07-25T11:38:29Z"}}},
    {id:"7354e010b8f2",type:"whois",attributes:{first_seen_date:1722899256,last_updated:1721977966,registrar_name:"GoDaddy.com, LLC",registrant_country:"US",whois_map:{"Registrar":"GoDaddy.com, LLC","Name Server":"SUNBURST-NS-A.SINKHOLE.SHADOWSERVER.ORG | SUNBURST-NS-B.SINKHOLE.SHADOWSERVER.ORG","Registrant Email":"bd343e776d5ffe96s@","Registrant Organization":"b46a98a26fe2fd9f","Registrant Name":"80315b2e6ac1a801","Creation Date":"2018-07-25T06:38:29Z | 2018-07-25T11:38:29Z","Admin Organization":"Domains By Proxy, LLC","Registry Registrant ID":"Not Available From Registry"}}},
    {id:"95dda8bea9fb",type:"whois",attributes:{first_seen_date:1721982967,last_updated:1721977966,registrar_name:"GoDaddy.com, LLC",whois_map:{"Registrar":"GoDaddy.com, LLC","Name Server":"SUNBURST-NS-A.SINKHOLE.SHADOWSERVER.ORG | SUNBURST-NS-B.SINKHOLE.SHADOWSERVER.ORG","Creation Date":"2018-07-25T11:38:29Z"}}},
    {id:"c45b796abe2a",type:"whois",attributes:{first_seen_date:1690475025,last_updated:1690355501,registrar_name:"GoDaddy.com, LLC",whois_map:{"Registrar":"GoDaddy.com, LLC","Name Server":"SUNBURST-NS-A.SINKHOLE.SHADOWSERVER.ORG | SUNBURST-NS-B.SINKHOLE.SHADOWSERVER.ORG","Creation Date":"2018-07-25T11:38:29Z"}}},
    {id:"e994a205c4f6",type:"whois",attributes:{first_seen_date:1610663281,last_updated:1608587545,registrar_name:"GoDaddy.com, LLC",whois_map:{"Registrar":"GoDaddy.com, LLC","Name Server":"SUNBURST-NS-A.SINKHOLE.SHADOWSERVER.ORG | SUNBURST-NS-B.SINKHOLE.SHADOWSERVER.ORG","Creation Date":"2018-07-25T11:38:29Z"}}},
    {id:"65a4d36cb737",type:"whois",attributes:{first_seen_date:1608621765,last_updated:1608587545,registrar_name:"GoDaddy.com, LLC",registrant_country:"US",whois_map:{"Registrar":"GoDaddy.com, LLC","Name Server":"NS134A.MICROSOFTINTERNETSAFETY.NET | NS134B.MICROSOFTINTERNETSAFETY.NET | SUNBURST-NS-A.SINKHOLE.SHADOWSERVER.ORG | SUNBURST-NS-B.SINKHOLE.SHADOWSERVER.ORG","Registrant Email":"bd343e776d5ffe96s@","Registrant Organization":"da45206aa6bafae3","Creation Date":"2018-07-25T11:38:29Z"}}},
    {id:"9ce420ed4429",type:"whois",attributes:{first_seen_date:1608342738,last_updated:1608334326,registrar_name:"GoDaddy.com, LLC",registrant_country:"US",whois_map:{"Registrar":"GoDaddy.com, LLC","Name Server":"NS134A.MICROSOFTINTERNETSAFETY.NET | NS134B.MICROSOFTINTERNETSAFETY.NET","Registrant Email":"bd343e776d5ffe96s@","Registrant Organization":"da45206aa6bafae3","Creation Date":"2018-07-25T11:38:29Z"}}},
];
// TRIMMED from fixtures/ip_historical_whois.json (GET /ip_addresses/74.119.239.234/historical_whois):
// a junk snapshot (its only key is 'Socket not responding') and two ARIN records of one holder.
const IP_SNAPSHOTS = [
    {id:"a78578706a5c",type:"whois",attributes:{first_seen_date:1710212199,whois_map:{"Socket not responding":"[Errno 111] Connection refused"}}},
    {id:"9944f1b2ddf1",type:"whois",attributes:{first_seen_date:1581096024,last_updated:1543449600,whois_map:{"Organization":"PDR (PSUL-1)","NetName":"PUBLICDOMAINREGISTRY-NETWORKS","NetRange":"74.119.238.0 - 74.119.239.255","CIDR":"74.119.238.0/23","Name Server":"PDR (PSUL-1)"}}},
    {id:"9001a7f347f9",type:"whois",attributes:{first_seen_date:1573114913,last_updated:1573084800,registrant_country:"US",whois_map:{"Organization":"PDR (PSUL-1)","OrgName":"PDR","OrgId":"PSUL-1","NetName":"PUBLICDOMAINREGISTRY-NETWORKS","NetRange":"74.119.238.0 - 74.119.239.255","CIDR":"74.119.238.0/23","Registrant Country":"US"}}},
];
// SYNTHETIC values in the measured snapshot shape: no measured snapshot carries a plain (non-
// pseudonymised) registrant, so the org / email / placeholder / self-NS rules are exercised here.
const ACTOR_SNAPSHOTS = [
    {id:"s1",type:"whois",attributes:{first_seen_date:1600000000,registrar_name:"NameCheap, Inc.",whois_map:{"Registrar":"NameCheap, Inc.","Registrant Organization":"Acme Bulletproof Hosting Ltd","Registrant Email":"OPS@Acme-BP.net","Name Server":"NS1.ACME-BP.NET | NS2.ACME-BP.NET | ACTOR-EXAMPLE.NET. | 192.0.2.1"}}},
    {id:"s2",type:"whois",attributes:{first_seen_date:1610000000,registrar_name:"NameCheap, Inc.",whois_map:{"Registrant Organization":"acme bulletproof hosting ltd","Registrant Email":"ops@acme-bp.net","Name Server":"ns1.acme-bp.net | ns2.acme-bp.net"}}},
    {id:"s3",type:"whois",attributes:{first_seen_date:1620000000,registrar_name:"NameCheap, Inc.",whois_map:{"Registrant Organization":"Privacy service provided by Withheld for Privacy ehf","Registrant Email":"5be9a8e3b2fd4b0b.protect@withheldforprivacy.com"}}},
    {id:"s4",type:"whois",attributes:{first_seen_date:1630000000,registrar_name:"GoDaddy.com, LLC",whois_map:{"Registrant Organization":"Domains By Proxy, LLC","Registrant Email":"actor-example.net@domainsbyproxy.com"}}},
    {id:"s5",type:"whois",attributes:{first_seen_date:1640000000,registrar_name:"GoDaddy.com, LLC",whois_map:{"Registrant Organization":"REDACTED FOR PRIVACY","Registrant Email":"Please query the RDDS service of the Registrar of Record"}}},
    {id:"s6",type:"whois",attributes:{first_seen_date:1650000000,registrar_name:"GoDaddy.com, LLC",whois_map:{"Registrant Organisation":"Data Protected | Statutory Masking Enabled","Registrant Email":"contact@whoisguard.com"}}},
    {id:"s7",type:"whois",attributes:{first_seen_date:1660000000,registrar_name:"GoDaddy.com, LLC",whois_map:{"Registrant Organisation":"Mr Hex Corp | Acme Holdings S.A.","Registrant Email":"a1@x | b2@acme-holdings.example"}}},
];

const NS_MS = 'ns134a.microsoftinternetsafety.net,ns134b.microsoftinternetsafety.net';
const NS_SB = 'sunburst-ns-a.sinkhole.shadowserver.org,sunburst-ns-b.sinkhole.shadowserver.org';
const GD = 'registrar=GoDaddy.com, LLC';
const RL = 'registrar=Stichting Registrar of Last Resort Foundation';
// 10 snapshots → 6 changes. The THIN registry records (no registrant keys: 2021-01-14, 2023-07-27,
// 2024-07-26, 2025-01-25, 2025-06-25, 2026-06-25) are changes only when a part they carry differs:
// 2021-01-14 (Microsoft NS dropped) and 2025-01-25 (registrar → Last Resort) are; 2023/2024-07 and
// 2025/2026-06 only lack the registrant and collapse.
const AVSVM_TIMELINE = [
    `2020-12-19 ${GD}; org=da45206aa6bafae3; email=bd343e776d5ffe96s@; ns=${NS_MS}`,
    `2020-12-22 ${GD}; org=da45206aa6bafae3; email=bd343e776d5ffe96s@; ns=${NS_MS},${NS_SB}`,
    `2021-01-14 ${GD}; ns=${NS_SB}`,
    `2024-08-05 ${GD}; org=b46a98a26fe2fd9f; email=bd343e776d5ffe96s@; ns=${NS_SB}`,
    `2025-01-25 ${RL}; ns=${NS_SB}`,
    `2025-01-31 ${RL}; org=6fd7c0f890337271; email=d76e663655d6f79cs@fbi.gov; ns=${NS_SB}`,
].join(', ');

/** Routes historical_whois by object; page 1 carries a cursor, page 2 (cursor set) is empty. */
function whoisNet(byPath) {
    return makeNet((u) => {
        const m = u.pathname.match(/^\/api\/v3\/(.+)\/historical_whois$/);
        const r = m && byPath[m[1]];
        if (!r) return { status: 404, body: vtErr('NotFoundError') };
        if (r.status) return r;
        if (u.searchParams.get('cursor')) return { status: 200, body: { data: [], meta: {} } };
        return { status: 200, body: { data: r, meta: { cursor: 'C1' } } };
    });
}
const nodesOf = (graph, type) => graph.createdNodes.filter((n) => n.type === type);
const noSelfLinks = (graph) => graph.createdEdges.every((e) => e.from !== e.to);

// ---- manifest ------------------------------------------------------------------------------
{
    const m = W?.manifest ?? {};
    t.check('manifest: identifier / version / icon', m.identifier === 'run.vineyard.plugins.vt_whois_history' && m.version === '0.2.0' && m.icon === 'scroll-text' && m.name === 'VT WHOIS History');
    const io = JSON.stringify(m.io);
    t.check('manifest: consumes domain + ip_address', m.io?.consumes?.length === 2 && io.includes('"name":"domain"') && io.includes('"name":"ip_address"'));
    t.check('manifest: produces email_address, organization, domain', m.io?.produces?.map((r) => `${r.category}.${r.name}`).join() === 'identity.email_address,identity.organization,infrastructure.domain');
    t.check('manifest: description quotes every edge label', ['registrant email (WHOIS history)', 'registrant organization (WHOIS history)', 'name server (WHOIS history)'].every((l) => m.description.includes(`'${l}'`)));
    t.check('manifest: description ends with the key/platform sentence', m.description.endsWith('Needs a VirusTotal Premium key. Desktop only.'));
    const lim = m.params?.properties?.limit ?? {};
    t.check('manifest: limit param 1–100 default 20', lim.type === 'number' && lim.minimum === 1 && lim.maximum === 100 && lim.default === 20);
    t.check('manifest: API key config + GET-only network scope', m.scopes?.config?.[0]?.key === 'api_key' && m.scopes?.network?.[0]?.methods?.join() === 'GET');
}

// ---- domain happy path: avsvmcloud.com --------------------------------------------------------
{
    const net = whoisNet({ 'domains/avsvmcloud.com': DOMAIN_SNAPSHOTS });
    const graph = makeGraph({ d: { id: 'd', type: 'infrastructure.domain', data: { domain_name: 'avsvmcloud.com' } } });
    const r = await run(graph, net, ['d']);
    const first = new URL(net.calls[0].url);
    t.check('domain: reads /domains/{d}/historical_whois with limit=20 (default)', first.pathname === '/api/v3/domains/avsvmcloud.com/historical_whois' && first.searchParams.get('limit') === '20');
    t.check('domain: pages via meta.cursor (2nd call carries cursor, asks for the remaining 10)', net.calls.length === 2 && new URL(net.calls[1].url).searchParams.get('cursor') === 'C1' && new URL(net.calls[1].url).searchParams.get('limit') === '10');
    t.check('domain: key in x-apikey header, never in the URL', net.calls.every((c) => c.headers['x-apikey'] === 'k' && !/apikey|k=k/i.test(new URL(c.url).search)));
    const patch = graph.updates.find((u) => u.id === 'd')?.data ?? {};
    t.check('domain: vt_whois_history = sorted, collapsed timeline (exact)', patch.vt_whois_history === AVSVM_TIMELINE);
    t.check('domain: a thin record that only lacks the registrant is not a change (no 2025-06-25 / 2023-07-27 entry)', !/2025-06-25|2026-06-25|2023-07-27|2024-07-26/.test(String(patch.vt_whois_history)));
    t.check('domain: vt_whois_snapshots = snapshots read', patch.vt_whois_snapshots === 10);
    t.check('domain: only vt_whois_* written onto the node', Object.keys(patch).sort().join() === 'vt_whois_history,vt_whois_snapshots');
    const emails = nodesOf(graph, 'identity.email_address');
    t.check('domain: pseudonymised complete email kept, flagged vt_pseudonymised', emails.length === 1 && JSON.stringify(emails[0].data) === JSON.stringify({ email: 'd76e663655d6f79cs@fbi.gov', vt_pseudonymised: true }));
    t.check('domain: email linked domain → email "registrant email (WHOIS history)"', hasEdge(graph, 'd', emails[0]?.id, 'registrant email (WHOIS history)'));
    t.check('domain: truncated email (bd343e776d5ffe96s@) and Admin/Tech emails make no node', !graph.createdNodes.some((n) => /bd343e776d5ffe96s|4babf6fcc6f7794as/.test(JSON.stringify(n.data))));
    t.check('domain: 16-hex pseudonymised orgs and the Admin org make no Organization', nodesOf(graph, 'identity.organization').length === 0);
    const ns = nodesOf(graph, 'infrastructure.domain');
    const nsNames = ns.map((n) => n.data.domain_name).sort().join();
    t.check('domain: every distinct name server becomes a lowercased Domain', nsNames === `${NS_MS},${NS_SB}` && ns.every((n) => Object.keys(n.data).join() === 'domain_name'));
    t.check('domain: each NS linked domain → ns "name server (WHOIS history)"', ns.length === 4 && ns.every((n) => hasEdge(graph, 'd', n.id, 'name server (WHOIS history)')));
    t.check('domain: no other edges', graph.createdEdges.length === 5 && noSelfLinks(graph));
    t.check('domain: counts', JSON.stringify(r.counts) === JSON.stringify({ checked: 1, snapshots: 10, changes: 6, emails: 1, orgs: 0, nameservers: 4, misses: 0 }));
    t.check('domain: summary', r.summary === '1 node(s): 10 WHOIS snapshot(s), 6 change(s), 1 registrant email(s), 0 organization(s), 4 name server(s)');
}

// ---- IP: RIR timeline only, junk snapshot skipped, no nodes -----------------------------------
{
    const net = whoisNet({ 'ip_addresses/74.119.239.234': IP_SNAPSHOTS });
    const graph = makeGraph({ i: { id: 'i', type: 'infrastructure.ip_address', data: { ip_address: '74.119.239.234' } } });
    const r = await run(graph, net, ['i']);
    const patch = graph.updates.find((u) => u.id === 'i')?.data ?? {};
    t.check('ip: reads /ip_addresses/{ip}/historical_whois', new URL(net.calls[0].url).pathname === '/api/v3/ip_addresses/74.119.239.234/historical_whois');
    t.check('ip: timeline collapses the two ARIN records; junk snapshot skipped (exact)', patch.vt_whois_history === '2019-11-07 org=PDR (PSUL-1); net=PUBLICDOMAINREGISTRY-NETWORKS; range=74.119.238.0 - 74.119.239.255');
    t.check('ip: vt_whois_snapshots counts the junk one too', patch.vt_whois_snapshots === 3);
    t.check('ip: no nodes or edges (not even from its "Name Server" key)', graph.createdNodes.length === 0 && graph.createdEdges.length === 0);
    t.check('ip: counts', r.counts.checked === 1 && r.counts.snapshots === 3 && r.counts.changes === 1 && r.counts.emails === 0 && r.counts.nameservers === 0);
}

// ---- registrant rules: orgs, emails, placeholders, self NS --------------------------------------
{
    const net = whoisNet({ 'domains/actor-example.net': ACTOR_SNAPSHOTS });
    const graph = makeGraph({ a: { id: 'a', type: 'infrastructure.domain', data: { domain_name: 'actor-example.net' } } });
    const r = await run(graph, net, ['a']);
    const orgs = nodesOf(graph, 'identity.organization');
    const emails = nodesOf(graph, 'identity.email_address');
    t.check('rules: plain orgs become Organizations {name}, deduped case-insensitively, multi-values split', orgs.map((n) => n.data.name).join('|') === 'Acme Bulletproof Hosting Ltd|Mr Hex Corp|Acme Holdings S.A.' && orgs.every((n) => Object.keys(n.data).join() === 'name'));
    t.check('rules: orgs linked "registrant organization (WHOIS history)"', orgs.every((n) => hasEdge(graph, 'a', n.id, 'registrant organization (WHOIS history)')));
    t.check('rules: complete emails lowercased + deduped, no vt_pseudonymised flag', emails.map((n) => JSON.stringify(n.data)).join('|') === '{"email":"ops@acme-bp.net"}|{"email":"b2@acme-holdings.example"}');
    t.check('rules: emails linked "registrant email (WHOIS history)"', emails.every((n) => hasEdge(graph, 'a', n.id, 'registrant email (WHOIS history)')));
    const all = JSON.stringify(graph.createdNodes.map((n) => n.data)).toLowerCase();
    t.check('rules: redaction/privacy-proxy placeholders make no node', !/privacy|proxy|redacted|whoisguard|data protected|statutory|please query/.test(all));
    t.check('rules: an email without a domain.tld (a1@x) makes no node', !all.includes('a1@x'));
    const ns = nodesOf(graph, 'infrastructure.domain').map((n) => n.data.domain_name);
    t.check('rules: NS list drops the domain itself (trailing dot) and a bare IP', ns.join() === 'ns1.acme-bp.net,ns2.acme-bp.net');
    t.check('rules: no self-links', noSelfLinks(graph) && !graph.createdNodes.some((n) => n.data.domain_name === 'actor-example.net'));
    t.check('rules: counts', r.counts.orgs === 3 && r.counts.emails === 2 && r.counts.nameservers === 2 && r.counts.snapshots === 7);
    const tl = String(graph.updates[0]?.data?.vt_whois_history ?? '');
    t.check('rules: timeline keeps what VT showed, placeholders included', tl.startsWith('2020-09-13 registrar=NameCheap, Inc.; org=Acme Bulletproof Hosting Ltd; email=OPS@Acme-BP.net; ns=actor-example.net,ns1.acme-bp.net,ns2.acme-bp.net') && tl.includes('org=REDACTED FOR PRIVACY'));
}

// ---- at most 25 distinct name servers ----------------------------------------------------------
{
    const many = Array.from({ length: 30 }, (_, i) => `NS${i}.DNS-FARM.EXAMPLE`).join(' | ');
    const net = whoisNet({ 'domains/farm.example': [{ id: 'f1', type: 'whois', attributes: { first_seen_date: 1700000000, registrar_name: 'X', whois_map: { 'Name Server': many } } }] });
    const graph = makeGraph({ f: { id: 'f', type: 'infrastructure.domain', data: { domain_name: 'farm.example' } } });
    const r = await run(graph, net, ['f']);
    t.check('ns cap: 30 distinct NS → 25 Domains + 25 edges', r.counts.nameservers === 25 && nodesOf(graph, 'infrastructure.domain').length === 25 && graph.createdEdges.length === 25);
}

// ---- empty-meaning values make no node; real names without Latin letters / all-digit emails do -----
// SYNTHETIC values in the measured shape. 'Not Available From Registry' is MEASURED (avsvmcloud
// 7354e010b8f2, under 'Registry Registrant ID'); here it sits under 'Registrant Organization'.
{
    const snaps = [
        { id: 'j1', type: 'whois', attributes: { first_seen_date: 1600000000, registrar_name: 'R', whois_map: { 'Registrant Organization': 'Not Available From Registry', 'Registrant Email': 'none@example.com' } } },
        { id: 'j2', type: 'whois', attributes: { first_seen_date: 1610000000, registrar_name: 'R', whois_map: { 'Registrant Organization': 'N/A | - | none | . | X', 'Registrant Email': 'n/a@example.com' } } },
        { id: 'j3', type: 'whois', attributes: { first_seen_date: 1620000000, registrar_name: 'R', whois_map: { 'Registrant Organization': '北京某某科技有限公司 | 3M', 'Registrant Email': '12345678@qq.com' } } },
    ];
    const net = whoisNet({ 'domains/junk.example': snaps });
    const graph = makeGraph({ j: { id: 'j', type: 'infrastructure.domain', data: { domain_name: 'junk.example' } } });
    const r = await run(graph, net, ['j']);
    const orgs = nodesOf(graph, 'identity.organization').map((n) => n.data.name);
    const emails = nodesOf(graph, 'identity.email_address').map((n) => n.data.email);
    t.check('junk: N/A, -, none, ., a 1-letter name and "Not Available From Registry" make no Organization', !orgs.some((o) => /^(N\/A|-|none|\.|X|Not Available From Registry)$/.test(o)));
    t.check('junk: a CJK organization and "3M" are kept', orgs.join('|') === '北京某某科技有限公司|3M' && r.counts.orgs === 2);
    t.check('junk: none@ / n/a@ make no Email Address; an all-digit QQ address is kept', emails.join() === '12345678@qq.com' && r.counts.emails === 1);
    t.check('junk: kept nodes are linked from the domain', orgs.length === 2 && graph.createdEdges.filter((e) => e.from === 'j' && e.label === 'registrant organization (WHOIS history)').length === 2);
}

// ---- more than 25 changes: the NEWEST 25 are kept -------------------------------------------------
{
    const day = 86400;
    const snaps = Array.from({ length: 30 }, (_, i) => ({ id: `r${i}`, type: 'whois', attributes: { first_seen_date: 1600000000 + i * 30 * day, registrar_name: `Reg${i}`, whois_map: {} } }));
    const net = whoisNet({ 'domains/hopper.example': snaps.reverse() }); // VT order: newest first
    const graph = makeGraph({ h: { id: 'h', type: 'infrastructure.domain', data: { domain_name: 'hopper.example' } } });
    const r = await run(graph, net, ['h'], { limit: 30 });
    const iso = (i) => new Date((1600000000 + i * 30 * day) * 1000).toISOString().slice(0, 10);
    const expected = '(+5 earlier) ' + Array.from({ length: 25 }, (_, k) => `${iso(k + 5)} registrar=Reg${k + 5}`).join(', ');
    t.check('cap: 30 changes → "(+5 earlier)" then the newest 25, oldest first (exact)', graph.updates[0]?.data?.vt_whois_history === expected);
    t.check('cap: counts.changes still counts all 30', r.counts.changes === 30 && r.counts.snapshots === 30);
}

// ---- a thin record never hides a real change; a switch to a placeholder is recorded ----------------
{
    const snaps = [
        { id: 'p1', type: 'whois', attributes: { first_seen_date: 1600000000, registrar_name: 'NameCheap, Inc.', whois_map: { 'Registrant Organization': 'Acme Ltd', 'Name Server': 'NS1.ACME.EXAMPLE' } } },
        { id: 'p2', type: 'whois', attributes: { first_seen_date: 1610000000, registrar_name: 'NameCheap, Inc.', whois_map: { 'Name Server': 'NS1.ACME.EXAMPLE' } } },
        { id: 'p3', type: 'whois', attributes: { first_seen_date: 1620000000, registrar_name: 'NameCheap, Inc.', whois_map: { 'Registrant Organization': 'Acme Ltd', 'Name Server': 'NS1.ACME.EXAMPLE' } } },
        { id: 'p4', type: 'whois', attributes: { first_seen_date: 1630000000, registrar_name: 'NameCheap, Inc.', whois_map: { 'Registrant Organization': 'Redacted for Privacy', 'Name Server': 'NS1.ACME.EXAMPLE' } } },
    ];
    const net = whoisNet({ 'domains/acme.example': snaps });
    const graph = makeGraph({ a: { id: 'a', type: 'infrastructure.domain', data: { domain_name: 'acme.example' } } });
    const r = await run(graph, net, ['a']);
    t.check('thin: full → thin → same full collapses; the privacy switch is a change (exact)', graph.updates[0]?.data?.vt_whois_history === '2020-09-13 registrar=NameCheap, Inc.; org=Acme Ltd; ns=ns1.acme.example, 2021-08-26 registrar=NameCheap, Inc.; org=Redacted for Privacy; ns=ns1.acme.example' && r.counts.changes === 2);
}

// ---- limit param ---------------------------------------------------------------------------------
{
    const net = whoisNet({ 'domains/avsvmcloud.com': DOMAIN_SNAPSHOTS });
    const graph = makeGraph({ d: { id: 'd', type: 'infrastructure.domain', data: { domain_name: 'avsvmcloud.com' } } });
    const r = await run(graph, net, ['d'], { limit: 3 });
    t.check('limit: 3 → asks for 3, reads the 3 newest snapshots, one request', new URL(net.calls[0].url).searchParams.get('limit') === '3' && net.calls.length === 1 && r.counts.snapshots === 3);
    t.check('limit: 3 newest (1 full + 2 thin) → 1 change, the FBI-era email still found', r.counts.changes === 1 && r.counts.emails === 1 && graph.updates[0].data.vt_whois_snapshots === 3);
    t.check('limit: 3 newest → exact timeline', graph.updates[0].data.vt_whois_history === `2025-01-31 ${RL}; org=6fd7c0f890337271; email=d76e663655d6f79cs@fbi.gov; ns=${NS_SB}`);
}
{
    const net = whoisNet({ 'domains/avsvmcloud.com': DOMAIN_SNAPSHOTS });
    await run(makeGraph({ d: { id: 'd', type: 'infrastructure.domain', data: { domain_name: 'avsvmcloud.com' } } }), net, ['d'], { limit: 1000 });
    t.check('limit: 1000 is clamped (first page capped at 40)', new URL(net.calls[0].url).searchParams.get('limit') === '40');
    const net2 = whoisNet({ 'domains/avsvmcloud.com': DOMAIN_SNAPSHOTS });
    await run(makeGraph({ d: { id: 'd', type: 'infrastructure.domain', data: { domain_name: 'avsvmcloud.com' } } }), net2, ['d'], { limit: 'abc' });
    t.check('limit: garbage → default 20', new URL(net2.calls[0].url).searchParams.get('limit') === '20');
}

// ---- 404 / 403 skip just that node; invalid and unsupported nodes are ignored --------------------
{
    const net = whoisNet({
        'domains/nx.example': { status: 404, body: vtErr('NotFoundError') },
        'ip_addresses/9.9.9.9': { status: 403, body: vtErr('ForbiddenError') },
        'domains/avsvmcloud.com': DOMAIN_SNAPSHOTS,
    });
    const graph = makeGraph({
        nx: { id: 'nx', type: 'infrastructure.domain', data: { domain_name: 'nx.example' } },
        fb: { id: 'fb', type: 'infrastructure.ip_address', data: { ip_address: '9.9.9.9' } },
        bad: { id: 'bad', type: 'infrastructure.domain', data: { domain_name: 'not a domain' } },
        k: { id: 'k', type: 'infrastructure.ssh_host_key', data: { fingerprint_sha256: 'SHA256:x' } },
        d: { id: 'd', type: 'infrastructure.domain', data: { domain_name: 'avsvmcloud.com' } },
    });
    const logs = [];
    const r = await run(graph, net, ['nx', 'fb', 'bad', 'k', 'd'], {}, { progress: { set() {}, log: (l) => logs.push(l) } });
    t.check('errors: 404 node and 403 node counted as misses', r.counts.misses === 2);
    t.check('errors: the rest still runs (avsvmcloud fully processed)', r.counts.snapshots === 10 && r.counts.nameservers === 4 && graph.updates.some((u) => u.id === 'd'));
    t.check('errors: misses are logged with a reason', logs.some((l) => /nx\.example: no VirusTotal record/.test(l)) && logs.some((l) => /9\.9\.9\.9: needs a VirusTotal Premium key/.test(l)));
    t.check('errors: invalid domain and unsupported type make no request and are not checked', r.counts.checked === 3 && !net.calls.some((c) => /not%20a%20domain|ssh/.test(c.url)));
    t.check('errors: nothing written for the missed nodes', !graph.updates.some((u) => u.id === 'nx' || u.id === 'fb'));
    t.check('errors: summary names the skipped nodes', / 2 skipped$/.test(r.summary));
}

// ---- a 5xx is not a per-item miss: it ends the run ---------------------------------------------
{
    const net = whoisNet({ 'domains/avsvmcloud.com': { status: 500, body: vtErr('InternalError') } });
    let threw = null;
    try { await run(makeGraph({ d: { id: 'd', type: 'infrastructure.domain', data: { domain_name: 'avsvmcloud.com' } } }), net, ['d']); } catch (e) { threw = e; }
    t.check('errors: HTTP 500 rethrows instead of being skipped', !!threw && /HTTP 500/.test(threw.message));
}

// ---- cancel before the first request ---------------------------------------------------------
{
    const ac = new AbortController();
    ac.abort();
    const net = whoisNet({ 'domains/avsvmcloud.com': DOMAIN_SNAPSHOTS });
    let threw = null;
    try { await run(makeGraph({ d: { id: 'd', type: 'infrastructure.domain', data: { domain_name: 'avsvmcloud.com' } } }), net, ['d'], {}, { signal: ac.signal }); } catch (e) { threw = e; }
    t.check('cancel: an aborted run throws "cancelled" with no request', !!threw && /cancelled/.test(threw.message) && net.calls.length === 0);
}

t.report();
