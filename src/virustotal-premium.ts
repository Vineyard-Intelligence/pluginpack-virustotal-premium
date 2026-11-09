// VirusTotal Premium — Premium-API-tier v3 pivots for VINEYARD.
//
// WHY A SEPARATE PACK (not folded into VirusTotal Community): every plugin here calls a surface a
// free/community key cannot read. MEASURED 2026-10-10 with two keys side by side:
//   - `/ip_addresses/{ip}` returns `data.attributes.port_info` ONLY on a Premium key; a community
//     key gets the same object with that field simply absent (not an error).
//   - `/intelligence/search`, `/port_infos/...`, `/port_analyses/...` answer 403 ForbiddenError on a
//     community key (`GET /users/{key}` reports zero granted privileges there).
// VirusTotal's docs call the paid API tier the "Premium API" (vs the free "Public API"); the product
// granting it is branded VirusTotal Enterprise / Google Threat Intelligence, and the search/hunting
// module is "Intelligence" (hence the `/intelligence/*` paths). A community key would 403 or come
// back empty on every call this pack makes, so the free-tier reports stay in the Community pack and
// only the Premium-only capabilities live here.
//
// KEY MODEL: the analyst's own VirusTotal Premium API key, declared as a `secret: true` config value
// (`api_key`) and sent only as the `x-apikey` header — never in a URL.
//
// PLATFORM: desktop-only. VirusTotal sends no `access-control-allow-*` header, so a browser blocks
// every response; the desktop shell writes them for declared origins.
//
// Graph writes are STAGED: nothing reaches the graph until the analyst reviews and commits.
import { definePlugin, definePluginPack } from './sdk';
import type { GraphNode, HostContext, PluginManifest, RunResult, VineyardPluginPack } from './sdk';
import {
    API_KEY_CONFIG,
    DOMAIN_RE,
    GRAPH_SCOPES,
    LIFECYCLE,
    PLATFORMS,
    SHA256_RE,
    VtError,
    abortErr,
    certSpecFromVt,
    clampParam,
    dateFromUnix,
    datetimeFromUnix,
    ensureEdge,
    ensureNode,
    identityType,
    infra,
    isIp,
    itemMiss,
    joinCapped,
    netScope,
    nodeFromVt,
    selectedNodesOfTypes,
    sshFpHex,
    sshFpOpenSsh,
    threatType,
    updateNode,
    vtGet,
    vtPathFor,
    webType,
} from './vt-core';
import { completeEmail, isJunkValue, isPlaceholder, isPseudonym, vtWhoisHistory } from './whois';
import { vtHostFiles, vtHostUrls } from './host';
import { vtFileBehaviour, vtFileNetwork, vtFileRelatives } from './file';

// ---- shared: VT Intelligence search → nodes -------------------------------------------------
// One place both vt_search (free-form) and vt_search_from_node (query built from a node) go through.
// Runs the query VERBATIM, pages via meta.cursor up to `limit`, and adds a node per matched entity
// through the shared VT-object mapping. Returns the created nodes per entity so a caller can link
// the ones its pivot targets back to the pivot source.
const SEARCH_MAX = 300;
type HitEntity = 'ip' | 'domain' | 'url' | 'file';
const HIT_ENTITY: Record<string, HitEntity> = { ip_address: 'ip', domain: 'domain', url: 'url', file: 'file' };
const HIT_COUNT = { ip: 'ips', domain: 'domains', url: 'urls', file: 'files' } as const;
interface SearchOut {
    counts: { matched: number; ips: number; domains: number; urls: number; files: number; other: number };
    hits: Record<HitEntity, GraphNode[]>;
}
async function searchToNodes(ctx: HostContext, query: string, limit: number): Promise<SearchOut> {
    const counts = { matched: 0, ips: 0, domains: 0, urls: 0, files: 0, other: 0 };
    const hits: Record<HitEntity, GraphNode[]> = { ip: [], domain: [], url: [], file: [] };
    const results: Array<{ type?: string; id?: string; attributes?: any }> = [];
    let cursor: string | undefined;
    const want = Math.min(SEARCH_MAX, Math.max(1, limit || 25));
    while (results.length < want && !ctx.signal?.aborted) {
        const page = Math.min(300, want - results.length);
        const q =
            `/intelligence/search?query=${encodeURIComponent(query)}&limit=${page}` +
            (cursor ? `&cursor=${encodeURIComponent(cursor)}` : '');
        const body = (await vtGet(ctx, q)) as { data?: any[]; meta?: { cursor?: string } };
        const batch = Array.isArray(body?.data) ? body.data : [];
        results.push(...batch);
        if (!batch.length) break;
        cursor = body?.meta?.cursor;
        if (!cursor) break;
    }
    for (const r of results.slice(0, want)) {
        if (ctx.signal?.aborted) throw abortErr();
        if (!String(r?.id ?? '').trim()) continue;
        counts.matched++;
        const entity = HIT_ENTITY[String(r?.type)];
        const n = entity ? await nodeFromVt(ctx, r) : null;
        if (!entity || !n) {
            counts.other++; // an entity the graph does not hold, or one that maps to nothing (an arpa name)
            continue;
        }
        hits[entity].push(n);
        counts[HIT_COUNT[entity]]++;
    }
    return { counts, hits };
}

const PARAM_QUERY = {
    type: 'string',
    title: 'VT Intelligence query',
    description:
        "A VirusTotal Intelligence search query, run verbatim. Start with the entity: 'entity:ip' (also entity:domain, entity:url, entity:file). Premium internet-scanning modifiers: port / open_port / closed_port / port_status / port_protocol / port_service_product / port_service_version / port_service_cpe / port_banner / os_type / device_type / fingerprint (matches the SSH host-key fingerprint and JARM) / ssl_subject / ssl_thumbprint. Pin a condition to one port with brackets, e.g. port_service_product[80]:nginx. Full syntax: VT Intelligence search documentation.",
} as const;
const PARAM_LIMIT = {
    type: 'number',
    title: 'Max results',
    description: 'Maximum entities to add (1–300, default 25).',
    minimum: 1,
    maximum: SEARCH_MAX,
    default: 25,
} as const;

// =============================================================================================
// 1. vt_port_info — the Premium internet-scanning surface of an IP
// =============================================================================================
const PORT_STATUS: Record<string, string> = {
    PORT_INFO_STATUS_OPEN: 'open',
    PORT_INFO_STATUS_CLOSED: 'closed',
    PORT_INFO_STATUS_RECENTLY_CLOSED: 'recently-closed',
};

export const vtPortInfo = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.vt_port_info',
        content_type: 'vineyard:plugin',
        name: 'VT Port Info',
        version: '0.2.0',
        description:
            "Reads VirusTotal's internet-scanning port data for each selected IP Address (Premium key only) and writes its observable surface: vt_open_ports, vt_services (product per port), vt_closed_ports (VT keeps closed/recently-closed ports — a timestamped record of a port going down), vt_jarm and vt_ports_scanned (freshness). Materialises each SSH host key as an SSH Host Key node linked 'presents host key' (SHA-256 as hex, VirusTotal's OpenSSH spelling kept as vt_fingerprint), so it can be pivoted with VT Search from Node. A community key returns no port data and the run says so. Desktop only.",
        icon: 'ethernet-port',
        platforms: PLATFORMS,
        io: { consumes: [infra('ip_address')], produces: [infra('ssh_host_key')] },
        scopes: { graph: GRAPH_SCOPES, network: netScope('Read VirusTotal port_info for an IP'), config: [API_KEY_CONFIG] },
        lifecycle: LIFECYCLE,
    },
    async run(ctx: HostContext): Promise<RunResult> {
        const ips = await selectedNodesOfTypes(ctx, ['infrastructure.ip_address']);
        const counts = { checked: 0, enriched: 0, ssh_keys: 0, open_ports: 0, misses: 0 };
        let sawPortInfo = false;
        let noPortInfo = 0;
        for (const node of ips) {
            if (ctx.signal?.aborted) throw abortErr();
            const ip = String(node.data.ip_address ?? '').trim();
            if (!ip || !isIp(ip)) continue;
            counts.checked++;
            ctx.progress?.set?.({ message: `port_info ${ip}`, percent: counts.checked / ips.length });
            let body: any;
            try {
                body = await vtGet(ctx, `/ip_addresses/${encodeURIComponent(ip)}`);
            } catch (e) {
                const miss = itemMiss(e);
                if (miss) {
                    counts.misses++;
                    ctx.progress?.log?.(`${ip}: ${miss}`);
                    continue;
                }
                throw e;
            }
            const attrs = body?.data?.attributes ?? {};
            const portInfo = attrs.port_info;
            if (!Array.isArray(portInfo)) {
                noPortInfo++;
                counts.misses++;
                continue;
            }
            sawPortInfo = true;
            const open: number[] = [];
            const closed: string[] = [];
            const services: string[] = [];
            const sshKeys = new Map<string, string>(); // hex (the type pack's form) → VT's OpenSSH spelling
            let lastSeenMax = 0;
            for (const p of portInfo) {
                const port = Number(p?.port);
                if (!Number.isFinite(port)) continue;
                const status = PORT_STATUS[String(p?.status)] ?? 'open';
                if (status === 'open') open.push(port);
                else closed.push(`${port} (${status})`);
                if (typeof p?.last_seen === 'number' && p.last_seen > lastSeenMax) lastSeenMax = p.last_seen;
                const svc = p?.latest_analysis?.port_service ?? {};
                const product = typeof svc.product === 'string' ? svc.product : '';
                if (product && status === 'open') {
                    const version = typeof svc.version === 'string' && svc.version ? ` ${svc.version}` : '';
                    services.push(`${port}:${product}${version}`);
                }
                const fp = svc?.ssh?.host_key_fingerprint;
                const hex = sshFpHex(fp);
                if (hex) sshKeys.set(hex, sshFpOpenSsh(hex)!);
                else if (typeof fp === 'string' && fp.trim()) ctx.progress?.log?.(`${ip}:${port}: unreadable SSH host-key fingerprint ${fp.trim()} — skipped`);
            }
            open.sort((a, b) => a - b);
            const patch: Record<string, unknown> = {};
            if (open.length) patch.vt_open_ports = open.join(', ');
            const svcJoined = joinCapped(services);
            if (svcJoined) patch.vt_services = svcJoined;
            const closedJoined = joinCapped(closed);
            if (closedJoined) patch.vt_closed_ports = closedJoined;
            if (typeof attrs.jarm === 'string' && attrs.jarm) patch.vt_jarm = attrs.jarm;
            const scanned = datetimeFromUnix(lastSeenMax);
            if (scanned) patch.vt_ports_scanned = scanned;
            if (Object.keys(patch).length) {
                await updateNode(ctx, node, patch);
                counts.enriched++;
            }
            counts.open_ports += open.length;
            for (const [hex, openssh] of sshKeys) {
                const keyNode = await ensureNode(ctx, 'infrastructure.ssh_host_key', { fingerprint_sha256: hex, vt_fingerprint: openssh });
                await ensureEdge(ctx, node.id, keyNode.id, 'presents host key');
                counts.ssh_keys++;
            }
        }
        let summary = `${counts.checked} IP(s): ${counts.enriched} enriched, ${counts.open_ports} open port(s), ${counts.ssh_keys} SSH host key(s)`;
        if (!sawPortInfo && noPortInfo) summary += ` — no port_info on ${noPortInfo} IP(s): needs a VirusTotal Premium key`;
        return { summary, counts };
    },
});

// =============================================================================================
// 2. vt_search — VT Intelligence search, the reverse pivot
// =============================================================================================
export const vtSearch = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.vt_search',
        content_type: 'vineyard:plugin',
        name: 'VT Search',
        version: '0.2.0',
        description:
            "Runs a VirusTotal Intelligence search query (as typed, like a Censys/Shodan search) and adds what it matches: hosts as IP Addresses, domains as Domains, URLs as URLs, files as File Hashes. The query decides the entity and the pivot — e.g. 'entity:ip fingerprint:\"<ssh host key or JARM>\"', 'entity:ip port_service_product[443]:nginx open_port:22', 'entity:ip ssl_subject:example.com'. Needs a VirusTotal Premium key; each search costs intelligence quota. Desktop only.",
        icon: 'search',
        platforms: PLATFORMS,
        params: { type: 'object', properties: { query: PARAM_QUERY, limit: PARAM_LIMIT }, required: ['query'] },
        io: { consumes: [], produces: [infra('ip_address'), infra('domain'), webType('url'), threatType('file_hash')] },
        scopes: { graph: GRAPH_SCOPES, network: netScope('Run a VirusTotal Intelligence search'), config: [API_KEY_CONFIG] },
        lifecycle: LIFECYCLE,
    },
    async run(ctx: HostContext): Promise<RunResult> {
        const query = typeof ctx.params?.query === 'string' ? ctx.params.query.trim() : '';
        if (!query) return { summary: 'No query — type a VT Intelligence query in the Run dialog.', counts: {} };
        const limit = Number(ctx.params?.limit) || 25;
        let out: SearchOut;
        try {
            out = await searchToNodes(ctx, query, limit);
        } catch (e) {
            if (e instanceof VtError && e.status === 403) throw new Error('VT Intelligence search needs a Premium key (this key returned 403).');
            if (e instanceof VtError && e.status === 400) return { summary: `VirusTotal rejected the query (${e.code}). Check the entity: and modifiers.`, counts: {} };
            throw e;
        }
        const c = out.counts;
        return { summary: `${c.matched} match(es): ${c.ips} IP(s), ${c.domains} domain(s), ${c.urls} URL(s), ${c.files} file(s)`, counts: c };
    },
});

// =============================================================================================
// 3. vt_search_from_node — build the pivot query from a selected node
// =============================================================================================
// The ergonomic wrapper around vt_search: take what you already have and find its siblings, without
// writing the query by hand. Only the hits of the pivot's TARGET entity are linked back to the
// source (hit → source), so the pivot is visible in the graph and nothing incidental is.
// 'auto' — the natural pivot per type:
//   ssh_host_key (fingerprint_sha256)  -> entity:ip fingerprint:"SHA256:<b64>"            (validated: finds K_A/K_B siblings)
//   certificate (fingerprint_sha256)   -> entity:ip ssl_subject:"<name>" when the node names a domain, else ssl_thumbprint:<fp>
//   ip_address (vt_jarm)               -> entity:ip fingerprint:"<jarm>"          (JARM family)
//   domain (domain_name)               -> entity:ip ssl_subject:"<domain>"        (hosts whose cert names it)
//   email_address / organization       -> entity:domain whois:"<value>"           (domains the registrant also holds)
//   file_hash                          -> vhash:"<vhash>", else imphash:<imphash>, else main_icon_dhash:<dhash>
//                                         (read with one GET /files/{hash}: siblings built from the same code / imports / icon)
//   url                                -> content:"<url>"                         (files that embed the URL)
// Explicit modes: 'content' (files containing a Domain/IP/URL string — MEASURED: content:"avsvmcloud.com"
// and content:"74.119.239.234" return files), 'whois' (domains whose WHOIS names a Domain/Email/Organization),
// 'imphash' / 'vhash' / 'icon' (one File Hash similarity pivot). MEASURED: an imphash/vhash search returns
// the source file itself among its hits, so a hit is compared to the source by node id AND by SHA-256.
// VirusTotal's 16-hex pseudonymised names and truncated 'xxxxs@' emails match nothing (measured 0 hits)
// and privacy-proxy placeholders / 'N/A'-style values match everything, so none of them is searched —
// with the narrow placeholder test, since 'Private Layer INC' or a proxy vendor is a real pivot.
// A 403 may cover one query family (say content:) rather than the whole key, and 'auto' mixes four
// families in one run, so a 403 skips that family for the rest of the run; the run ends with the
// Premium message only when no search succeeded at all (nothing was staged, so nothing is lost).
type PivotMode = 'auto' | 'content' | 'whois' | 'imphash' | 'vhash' | 'icon';
const PIVOT_MODES: PivotMode[] = ['auto', 'content', 'whois', 'imphash', 'vhash', 'icon'];
interface Pivot {
    query: string;
    label: string;
    /** Only hits of this entity are linked back to the source. */
    target: HitEntity;
    /** The source file's SHA-256 as VirusTotal reports it — the file a similarity search finds first. */
    selfSha?: string;
}

/** The value trimmed, or '' when it is empty or could break out of the query's double quotes (a quote, a backslash escaping the closing one, a control character). */
function quotable(v: unknown): string {
    const s = String(v ?? '').trim();
    return s && !/["\\\x00-\x1f\x7f]/.test(s) ? s : '';
}
/** A certificate thumbprint (SHA-1 or SHA-256 hex, colons allowed) as bare lowercase hex — it goes into the query unquoted. */
function thumbprint(v: unknown): string {
    const s = String(v ?? '').trim();
    if (!/^[A-Fa-f0-9:]{40,95}$/.test(s)) return '';
    const hex = s.replace(/:/g, '').toLowerCase();
    return hex.length === 40 || hex.length === 64 ? hex : '';
}
/** A short handle for a node in a log line. */
function nodeKey(node: GraphNode): string {
    const d = node.data || {};
    return String(d.domain_name ?? d.ip_address ?? d.url ?? d.email ?? d.name ?? d.sha256 ?? d.md5 ?? d.fingerprint_sha256 ?? node.id);
}
function domainValue(node: GraphNode): string {
    const dom = String(node.data?.domain_name ?? node.data?.name ?? '').trim().toLowerCase();
    return DOMAIN_RE.test(dom) ? dom : '';
}

// The 0.1 pivots: a host-side value → the IPs that share it.
function hostPivot(node: GraphNode): Pivot | null {
    const d = node.data || {};
    if (node.type === 'infrastructure.ssh_host_key') {
        // The node holds hex (type pack) or OpenSSH; VT search matches only the OpenSSH spelling.
        const fp = sshFpOpenSsh(d.fingerprint_sha256 ?? d.vt_fingerprint ?? d.fingerprint);
        if (fp) return { query: `entity:ip fingerprint:"${fp}"`, label: 'shares SSH host key (VT)', target: 'ip' };
    } else if (node.type === 'infrastructure.certificate') {
        // subject_common_name is the type pack's property; subject_cn is what 0.1.x wrote — still read.
        const name = quotable(d.subject_common_name ?? d.subject_cn ?? d.common_name ?? d.cn);
        if (name && DOMAIN_RE.test(name)) return { query: `entity:ip ssl_subject:"${name}"`, label: 'shares certificate subject (VT)', target: 'ip' };
        const fp = thumbprint(d.fingerprint_sha256);
        if (fp) return { query: `entity:ip ssl_thumbprint:${fp}`, label: 'shares certificate thumbprint (VT)', target: 'ip' };
    } else if (node.type === 'infrastructure.ip_address') {
        const jarm = quotable(d.vt_jarm ?? d.jarm ?? d.shodan_jarm);
        if (jarm) return { query: `entity:ip fingerprint:"${jarm}"`, label: 'shares JARM (VT)', target: 'ip' };
    } else if (node.type === 'infrastructure.domain') {
        const dom = domainValue(node);
        if (dom) return { query: `entity:ip ssl_subject:"${dom}"`, label: 'certificate names this domain (VT)', target: 'ip' };
    }
    return null;
}

function contentPivot(node: GraphNode): Pivot | null {
    let value = '';
    if (node.type === 'infrastructure.domain') {
        value = domainValue(node);
    } else if (node.type === 'infrastructure.ip_address') {
        const ip = String(node.data?.ip_address ?? '').trim();
        value = isIp(ip) ? ip : '';
    } else if (node.type === 'web.url') {
        value = String(node.data?.url ?? '');
    }
    value = quotable(value);
    return value ? { query: `content:"${value}"`, label: 'contains this string (VT content search)', target: 'file' } : null;
}

function whoisPivot(node: GraphNode): Pivot | null {
    let value = '';
    let label = '';
    if (node.type === 'identity.email_address') {
        // A pseudonymised but complete address IS searchable (measured: 5 hits); a truncated one is not.
        const email = completeEmail(node.data?.email);
        value = email && !isPlaceholder(email) ? email : '';
        label = 'WHOIS names this email (VT)';
    } else if (node.type === 'identity.organization') {
        const name = String(node.data?.name ?? '').trim();
        value = name && !isPseudonym(name) && !isPlaceholder(name) && !isJunkValue(name) ? name : '';
        label = 'WHOIS names this organization (VT)';
    } else if (node.type === 'infrastructure.domain') {
        value = domainValue(node);
        label = 'WHOIS mentions this domain (VT)';
    }
    value = quotable(value);
    return value ? { query: `entity:domain whois:"${value}"`, label, target: 'domain' } : null;
}

// One GET /files/{hash} reads the similarity values; 'auto' takes the first the file has.
async function filePivot(ctx: HostContext, node: GraphNode, mode: 'auto' | 'imphash' | 'vhash' | 'icon'): Promise<Pivot | null> {
    const path = vtPathFor(node);
    if (!path) return null;
    const body = (await vtGet(ctx, path)) as any;
    const a = body?.data?.attributes ?? {};
    const sha = String(a.sha256 ?? node.data?.sha256 ?? '').toLowerCase();
    const selfSha = SHA256_RE.test(sha) ? sha : undefined;
    const vhash = quotable(a.vhash);
    const imphash = String(a.pe_info?.imphash ?? '').trim().toLowerCase();
    const dhash = String(a.main_icon?.dhash ?? '').trim().toLowerCase();
    const options: Record<'vhash' | 'imphash' | 'icon', { query: string; label: string } | null> = {
        vhash: vhash ? { query: `vhash:"${vhash}"`, label: 'shares vhash (VT)' } : null,
        imphash: /^[a-f0-9]{32}$/.test(imphash) ? { query: `imphash:${imphash}`, label: 'shares imphash (VT)' } : null,
        icon: /^[a-f0-9]{16}$/.test(dhash) ? { query: `main_icon_dhash:${dhash}`, label: 'shares main icon (VT)' } : null,
    };
    for (const k of mode === 'auto' ? (['vhash', 'imphash', 'icon'] as const) : [mode]) {
        const o = options[k];
        if (o) return { ...o, target: 'file', selfSha };
    }
    return null;
}

async function buildPivot(ctx: HostContext, node: GraphNode, mode: PivotMode): Promise<Pivot | null> {
    if (mode === 'content') return contentPivot(node);
    if (mode === 'whois') return whoisPivot(node);
    if (mode !== 'auto') return node.type === 'threat.file_hash' ? filePivot(ctx, node, mode) : null;
    switch (node.type) {
        case 'identity.email_address':
        case 'identity.organization':
            return whoisPivot(node);
        case 'threat.file_hash':
            return filePivot(ctx, node, 'auto');
        case 'web.url':
            return contentPivot(node);
        default:
            return hostPivot(node);
    }
}

/** Is this search hit the pivot source itself? By node id, and by identity value (SHA-256 for a file). */
function isSource(hit: GraphNode, src: GraphNode, selfSha?: string): boolean {
    if (hit.id === src.id) return true;
    if (hit.type !== src.type) return false;
    const h = hit.data || {};
    const s = src.data || {};
    switch (hit.type) {
        case 'threat.file_hash': {
            const sha = String(h.sha256 ?? '').toLowerCase();
            return !!sha && (sha === selfSha || sha === String(s.sha256 ?? '').trim().toLowerCase());
        }
        case 'infrastructure.domain':
            return String(h.domain_name ?? '') === domainValue(src);
        case 'infrastructure.ip_address':
            return String(h.ip_address ?? '') === String(s.ip_address ?? '').trim();
        case 'web.url':
            return String(h.url ?? '') === String(s.url ?? '').trim();
        default:
            return false;
    }
}

const FROM_NODE_TYPES = [
    'infrastructure.ssh_host_key',
    'infrastructure.certificate',
    'infrastructure.ip_address',
    'infrastructure.domain',
    'identity.email_address',
    'identity.organization',
    'threat.file_hash',
    'web.url',
];

export const vtSearchFromNode = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.vt_search_from_node',
        content_type: 'vineyard:plugin',
        name: 'VT Search from Node',
        version: '0.2.0',
        description:
            "Pivots from each selected node by building a VirusTotal Intelligence query from it and adding what matches, the matches of the pivot's target linked back to the source. Pivot 'auto' picks the natural query per type: an SSH Host Key or an IP Address's JARM on fingerprint: (hosts linked 'shares SSH host key (VT)' / 'shares JARM (VT)'), a TLS Certificate on its subject or thumbprint ('shares certificate subject (VT)' / 'shares certificate thumbprint (VT)'), a Domain on ssl_subject: ('certificate names this domain (VT)'), an Email Address or Organization on whois: (domains linked 'WHOIS names this email (VT)' / 'WHOIS names this organization (VT)'), a File Hash on its vhash, else imphash, else main icon (files linked 'shares vhash (VT)' / 'shares imphash (VT)' / 'shares main icon (VT)'), a URL on content: (files linked 'contains this string (VT content search)'). Pivot 'content' finds the files containing a Domain, IP Address or URL string ('contains this string (VT content search)'); 'whois' finds the domains whose WHOIS names a Domain ('WHOIS mentions this domain (VT)'), Email Address or Organization; 'imphash', 'vhash' and 'icon' pick that File Hash pivot. VirusTotal's pseudonymised organization names, truncated emails and privacy-proxy placeholders are skipped. Each pivot costs intelligence quota. Needs a VirusTotal Premium key. Desktop only.",
        icon: 'git-fork',
        platforms: PLATFORMS,
        params: {
            type: 'object',
            properties: {
                pivot: {
                    type: 'string',
                    title: 'Pivot',
                    enum: PIVOT_MODES,
                    default: 'auto',
                    description:
                        "auto: the natural pivot per node type (SSH key/JARM → fingerprint, cert → subject/thumbprint, domain → ssl_subject, email/org → whois, file → vhash, URL → content). content: files containing the value. whois: domains whose WHOIS names it. imphash/vhash/icon: similar files; others are skipped.",
                },
                limit: PARAM_LIMIT,
            },
        },
        io: {
            consumes: [
                infra('ssh_host_key'),
                infra('certificate'),
                infra('ip_address'),
                infra('domain'),
                identityType('email_address'),
                identityType('organization'),
                threatType('file_hash'),
                webType('url'),
            ],
            produces: [infra('ip_address'), infra('domain'), threatType('file_hash')],
        },
        scopes: { graph: GRAPH_SCOPES, network: netScope('Pivot a node through VirusTotal Intelligence search'), config: [API_KEY_CONFIG] },
        lifecycle: LIFECYCLE,
    },
    async run(ctx: HostContext): Promise<RunResult> {
        const nodes = await selectedNodesOfTypes(ctx, FROM_NODE_TYPES);
        const mode = PIVOT_MODES.find((m) => m === ctx.params?.pivot) ?? 'auto';
        const limit = clampParam(ctx.params?.limit, 25, 1, SEARCH_MAX);
        const counts = { pivoted: 0, skipped: 0, misses: 0, hosts: 0, domains: 0, urls: 0, files: 0, linked: 0 };
        const forbidden = new Set<string>(); // query families ('fingerprint', 'whois', 'content', …) this key got a 403 on
        for (let i = 0; i < nodes.length; i++) {
            const node = nodes[i];
            if (ctx.signal?.aborted) throw abortErr();
            ctx.progress?.set?.({ message: `pivot ${node.type}`, percent: i / nodes.length });
            let pivot: Pivot | null;
            try {
                pivot = await buildPivot(ctx, node, mode); // a File Hash pivot reads /files/{hash} first
            } catch (e) {
                const miss = itemMiss(e);
                if (miss) {
                    counts.misses++;
                    ctx.progress?.log?.(`${vtPathFor(node) ?? node.id}: ${miss}`);
                    continue;
                }
                throw e;
            }
            if (!pivot) {
                counts.skipped++;
                ctx.progress?.log?.(`${nodeKey(node)}: no searchable value for pivot '${mode}'`);
                continue;
            }
            const family = pivot.query.replace(/^entity:\w+\s+/, '').split(':')[0];
            if (forbidden.has(family)) {
                counts.misses++; // already logged on the first 403
                continue;
            }
            ctx.progress?.set?.({ message: pivot.query, percent: i / nodes.length });
            let out: SearchOut;
            try {
                out = await searchToNodes(ctx, pivot.query, limit);
            } catch (e) {
                const miss = itemMiss(e);
                if (miss) {
                    counts.misses++;
                    if (e instanceof VtError && e.status === 403) {
                        forbidden.add(family);
                        ctx.progress?.log?.(`${family}: searches return 403 on this key — skipping the remaining ${family}: pivots`);
                    } else {
                        ctx.progress?.log?.(`${pivot.query}: ${miss}`);
                    }
                    continue;
                }
                throw e;
            }
            counts.pivoted++;
            counts.hosts += out.counts.ips;
            counts.domains += out.counts.domains;
            counts.urls += out.counts.urls;
            counts.files += out.counts.files;
            for (const hit of out.hits[pivot.target]) {
                if (isSource(hit, node, pivot.selfSha)) continue; // never link a node to itself
                await ensureEdge(ctx, hit.id, node.id, pivot.label);
                counts.linked++;
            }
        }
        if (!counts.pivoted && forbidden.size) throw new Error('VT Intelligence search needs a Premium key (this key returned 403).');
        return {
            summary:
                `${counts.pivoted} pivot(s): ${counts.hosts} host(s), ${counts.domains} domain(s), ${counts.files} file(s), ${counts.linked} link(s)` +
                (counts.skipped ? `, ${counts.skipped} skipped` : '') +
                (counts.misses ? `, ${counts.misses} missed (see log)` : ''),
            counts,
        };
    },
});

// =============================================================================================
// 4. vt_port_history — a port's open/closed timeline
// =============================================================================================
// `/port_infos/{ip}:{port}` carries first_seen, open_since, last_seen_open and the current status —
// VT's timestamped record of when a port went up and when it last answered. This reads it for each of
// an IP's known ports and writes a compact per-IP timeline, which (unlike Censys/Shodan) survives a
// port going down: the stall that took a cluster offline shows up here as a RECENTLY-CLOSED with the
// last_open date it went dark.
function fmtPort(port: number, a: any): string {
    const status = PORT_STATUS[String(a?.status)] ?? 'open';
    const first = dateFromUnix(a?.first_seen);
    const open = dateFromUnix(a?.open_since);
    const lastOpen = dateFromUnix(a?.last_seen_open);
    const bits: string[] = [];
    if (open) bits.push(`open since ${open}`);
    else if (first) bits.push(`first ${first}`);
    if (lastOpen) bits.push(`last open ${lastOpen}`);
    return `${port}: ${bits.join(', ')} (${status})`;
}

export const vtPortHistory = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.vt_port_history',
        content_type: 'vineyard:plugin',
        name: 'VT Port History',
        version: '0.1.0',
        description:
            "For each selected IP Address, reads VirusTotal's per-port state (first seen, open since, last seen open, current status) for its ports and writes a compact vt_port_history timeline onto the IP. VirusTotal keeps closed ports, so a port that went down shows as RECENTLY-CLOSED with the date it was last open — a forensic timeline the other scanners do not expose. Needs a VirusTotal Premium key. Desktop only.",
        icon: 'history',
        platforms: PLATFORMS,
        params: {
            type: 'object',
            properties: {
                port: { type: 'number', title: 'Port (optional)', description: 'A single port to read; leave empty to read all ports VirusTotal has seen on the IP.', minimum: 1, maximum: 65535 },
            },
        },
        io: { consumes: [infra('ip_address')], produces: [] },
        scopes: { graph: ['node:read', 'node:update'], network: netScope('Read VirusTotal per-port history for an IP'), config: [API_KEY_CONFIG] },
        lifecycle: LIFECYCLE,
    },
    async run(ctx: HostContext): Promise<RunResult> {
        const ips = await selectedNodesOfTypes(ctx, ['infrastructure.ip_address']);
        const onlyPort = Number(ctx.params?.port) || 0;
        const counts = { checked: 0, enriched: 0, ports: 0, misses: 0 };
        for (const node of ips) {
            if (ctx.signal?.aborted) throw abortErr();
            const ip = String(node.data.ip_address ?? '').trim();
            if (!ip || !isIp(ip)) continue;
            counts.checked++;
            // Which ports? The one asked for, else the ports VT lists on the IP's port_info.
            let ports: number[] = [];
            if (onlyPort) ports = [onlyPort];
            else {
                try {
                    const ipBody = (await vtGet(ctx, `/ip_addresses/${encodeURIComponent(ip)}`)) as any;
                    const pi = ipBody?.data?.attributes?.port_info;
                    if (Array.isArray(pi)) ports = pi.map((p: any) => Number(p?.port)).filter((n: number) => Number.isFinite(n));
                } catch (e) {
                    const miss = itemMiss(e);
                    if (miss) { counts.misses++; continue; }
                    throw e;
                }
            }
            ports = [...new Set(ports)].sort((a, b) => a - b).slice(0, 25);
            if (!ports.length) { counts.misses++; continue; }
            const lines: string[] = [];
            for (const port of ports) {
                if (ctx.signal?.aborted) throw abortErr();
                ctx.progress?.set?.({ message: `${ip}:${port}`, percent: counts.checked / ips.length });
                try {
                    const body = (await vtGet(ctx, `/port_infos/${encodeURIComponent(ip)}:${port}`)) as any;
                    const a = body?.data?.attributes ?? body?.data ?? {};
                    if (a && (a.status || a.first_seen)) lines.push(fmtPort(port, a));
                } catch (e) {
                    if (!itemMiss(e)) throw e;
                }
            }
            if (lines.length) {
                await updateNode(ctx, node, { vt_port_history: joinCapped(lines) });
                counts.enriched++;
                counts.ports += lines.length;
            }
        }
        return { summary: `${counts.checked} IP(s): ${counts.enriched} with a timeline, ${counts.ports} port(s)`, counts };
    },
});

// =============================================================================================
// 5. vt_relationships — historical certificates (the premium time-depth pivot)
// =============================================================================================
// A community key sees only the LAST cert an IP/domain presented; a Premium key can walk the
// historical_ssl_certificates relationship — the certificates it presented over time, which is how a
// rotated or expired cert (that cert_fp pivots miss today) is still recoverable.
export const vtRelationships = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.vt_relationships',
        content_type: 'vineyard:plugin',
        name: 'VT Historical Certificates',
        version: '0.2.0',
        description:
            "Walks VirusTotal's historical SSL/TLS certificates for each selected IP Address or Domain (Premium relationship) and adds each certificate it presented over time as a TLS Certificate linked 'presented certificate' — SHA-256 thumbprint, subject CN, issuer, serial, validity (ISO-8601) and SAN count, the same fields the VirusTotal Community pack writes. This recovers rotated or expired certificates that a current-cert pivot misses. Needs a VirusTotal Premium key. Desktop only.",
        icon: 'file-clock',
        platforms: PLATFORMS,
        params: { type: 'object', properties: { limit: { type: 'number', title: 'Max certificates per node', minimum: 1, maximum: 100, default: 40 } } },
        io: { consumes: [infra('ip_address'), infra('domain')], produces: [infra('certificate')] },
        scopes: { graph: GRAPH_SCOPES, network: netScope('Read VirusTotal historical certificates'), config: [API_KEY_CONFIG] },
        lifecycle: LIFECYCLE,
    },
    async run(ctx: HostContext): Promise<RunResult> {
        const nodes = await selectedNodesOfTypes(ctx, ['infrastructure.ip_address', 'infrastructure.domain']);
        const limit = Math.min(100, Math.max(1, Number(ctx.params?.limit) || 40));
        const counts = { checked: 0, certs: 0, misses: 0 };
        for (const node of nodes) {
            if (ctx.signal?.aborted) throw abortErr();
            const isIpNode = node.type === 'infrastructure.ip_address';
            const key = isIpNode ? String(node.data.ip_address ?? '').trim() : String(node.data.domain_name ?? '').trim();
            if (!key) continue;
            counts.checked++;
            const base = isIpNode ? `/ip_addresses/${encodeURIComponent(key)}` : `/domains/${encodeURIComponent(key)}`;
            let seen = 0;
            let cursor: string | undefined;
            try {
                while (seen < limit && !ctx.signal?.aborted) {
                    const page = Math.min(40, limit - seen);
                    const q = `${base}/historical_ssl_certificates?limit=${page}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`;
                    const body = (await vtGet(ctx, q)) as { data?: any[]; meta?: { cursor?: string } };
                    const batch = Array.isArray(body?.data) ? body.data : [];
                    for (const cert of batch) {
                        const data = certSpecFromVt(cert?.attributes, cert?.id); // same fields as the Community pack
                        if (!data) continue;
                        const certNode = await ensureNode(ctx, 'infrastructure.certificate', data);
                        await ensureEdge(ctx, node.id, certNode.id, 'presented certificate');
                        counts.certs++;
                        seen++;
                        if (seen >= limit) break;
                    }
                    if (!batch.length) break;
                    cursor = body?.meta?.cursor;
                    if (!cursor) break;
                }
            } catch (e) {
                const miss = itemMiss(e);
                if (miss) { counts.misses++; ctx.progress?.log?.(`${key}: ${miss}`); continue; }
                throw e;
            }
        }
        return { summary: `${counts.checked} node(s): ${counts.certs} historical certificate(s)`, counts };
    },
});

// ---- pack --------------------------------------------------------------------------------------
// The pack's page in the marketplace drawer, in Markdown. Lines in an array rather than one template
// literal, because the Markdown is full of backticks.
const PAGE = [
    "Pivots that need VirusTotal's Premium API, the paid tier sold as VirusTotal Enterprise / Google Threat Intelligence. Every plugin here calls something a free community key cannot read: internet-scanning port data and its history, historical certificates and WHOIS, the files and URLs VirusTotal ties to a host, a sample's network indicators, relatives and sandbox behaviour, and Intelligence searches, typed or built from a node. The free-tier reports (IP, domain, URL and file reports, passive DNS, subdomains) are in the separate VirusTotal Community pack.",
    '',
    '## Plugins',
    '',
    '### Hosts',
    '',
    '**VT Port Info** (`vt_port_info`)',
    '',
    '- **Runs on:** IP Address.',
    '- **Writes** `vt_open_ports`, `vt_services` (product per port), `vt_closed_ports` (closed and recently closed ports, which VirusTotal keeps), `vt_jarm` and `vt_ports_scanned` (scan freshness).',
    "- **Adds** each SSH host key as an SSH Host Key linked `presents host key`: the SHA-256 as hex, with VirusTotal's OpenSSH spelling kept as `vt_fingerprint`, so it can be pivoted with VT Search from Node.",
    '- A community key gets no port data, and the run says so.',
    '',
    '**VT Port History** (`vt_port_history`)',
    '',
    '- **Runs on:** IP Address, optionally for one port.',
    '- **Writes** a `vt_port_history` timeline onto the IP: first seen, open since, last seen open and current status per port, for up to 25 ports. A port that went down shows as recently closed, with the date it was last open.',
    '',
    '**VT Historical Certificates** (`vt_relationships`)',
    '',
    '- **Runs on:** IP Address or Domain.',
    '- **Adds** each certificate VirusTotal saw it present over time as a TLS Certificate linked `presented certificate`: SHA-256 thumbprint, subject CN, issuer, serial, validity and SAN count, the same fields VirusTotal Community writes. This recovers rotated or expired certificates that a current-certificate lookup misses.',
    '- Up to 100 certificates per node, default 40.',
    '',
    '**VT WHOIS History** (`vt_whois_history`)',
    '',
    '- **Runs on:** Domain or IP Address.',
    '- **Writes** `vt_whois_history`, one line per change (registrar, registrant organization and email, name servers; for an IP, the RIR holder, net name and range), and `vt_whois_snapshots`. Reads up to 100 of the most recent snapshots, default 20.',
    '- **For a Domain, adds** each registrant email as an Email Address (`registrant email (WHOIS history)`), each registrant organization as an Organization (`registrant organization (WHOIS history)`) and each name server ever used as a Domain (`name server (WHOIS history)`).',
    "- Privacy-proxy placeholders, empty values such as N/A, truncated emails and 16-hex pseudonymised names are skipped. VirusTotal's pseudonymised emails are kept and marked `vt_pseudonymised`, because VirusTotal search still matches them.",
    '',
    '**VT Host Files** (`vt_host_files`)',
    '',
    '- **Runs on:** IP Address, Domain or URL.',
    '- **Adds** File Hashes (hashes, file type, detection counts, threat label) for files that contact the host (file → host `communicates with`, malware using it as C2) and files it served (host → file `served file`). Files whose content names the host (file → host `references`) are off by default.',
    '- Up to 200 files per relationship, default 20. Listed hashes VirusTotal holds no report for are skipped and counted as unreported.',
    '',
    '**VT Host URLs** (`vt_host_urls`)',
    '',
    '- **Runs on:** IP Address or Domain.',
    '- **Adds** the URLs VirusTotal has seen on it as URLs (page title, HTTP status, final URL, detection counts), linked host → URL `hosts URL`. Up to 200 per node, default 20.',
    '',
    '### Files',
    '',
    '**VT File Network** (`vt_file_network`)',
    '',
    '- **Runs on:** File Hash.',
    "- **Adds** the IP Addresses, Domains and URLs around a sample: what it contacted when detonated in VirusTotal's sandboxes (`contacts (sandbox)`), what is embedded in it as strings (`embeds`), and where it was seen distributed in the wild (`distributed from (in the wild)`). Each can be switched off; up to 100 per relationship, default 20.",
    '- Reverse-DNS (`in-addr.arpa`) lookups are dropped.',
    '',
    '**VT File Relatives** (`vt_file_relatives`)',
    '',
    '- **Runs on:** File Hash.',
    '- **Adds** related files as File Hashes: files VirusTotal finds similar (`similar to (VT)`), files that launched it (`executed`) and files it dropped when detonated (`dropped`). Archives that contain it and files bundled inside it (`contains`) are off by default; a popular sample can have hundreds of compressed parents.',
    '- Up to 100 per relationship, default 20. The file itself is never linked as its own relative.',
    '',
    '**VT File Behaviour** (`vt_file_behaviour`)',
    '',
    '- **Runs on:** File Hash.',
    '- **Adds** MITRE ATT&CK techniques the sandboxes observed as Attack Patterns (`exhibits (sandbox)`), crowdsourced YARA, Sigma and IDS hits as Detection Signatures (`matches YARA rule`, `matches Sigma rule`, `triggers IDS rule`), and the top AV family names as Malware (`classified as`).',
    '- **Writes** `vt_threat_label`, `vt_threat_category`, `vt_sandbox_verdicts` and `vt_mitre_sandboxes` onto the file.',
    '- A technique reported under both a retired ID and its current one becomes one Attack Pattern, under the current ID. IDS alerts are off by default because they are noisy (ICMP, Tor exit lists). Up to 100 entries per kind, default 25.',
    '',
    '### Intelligence search',
    '',
    '**VT Search** (`vt_search`)',
    '',
    '- **Runs on:** a VirusTotal Intelligence query typed in the Run dialog, run verbatim. It reads nothing from the canvas.',
    '- **Adds** what matches: hosts as IP Addresses, domains as Domains, URLs as URLs, files as File Hashes. Up to 300 results, default 25.',
    '- The query starts with the entity (`entity:ip`, `entity:domain`, `entity:url`, `entity:file`). Internet-scanning modifiers include `port`, `open_port`, `closed_port`, `port_service_product`, `port_banner`, `fingerprint` (SSH host-key fingerprint and JARM), `ssl_subject` and `ssl_thumbprint`; brackets pin a condition to one port, as in `port_service_product[80]:nginx`.',
    '',
    '**VT Search from Node** (`vt_search_from_node`)',
    '',
    '- **Runs on:** SSH Host Key, TLS Certificate, IP Address, Domain, Email Address, Organization, File Hash or URL.',
    '- Builds the query from the node, adds the matches, and links them back to it. Up to 300 results per node, default 25. With the pivot set to `auto`:',
    '',
    '| Selected node | Query | Matches linked by |',
    '|---|---|---|',
    '| SSH Host Key | `fingerprint:` | `shares SSH host key (VT)` |',
    '| IP Address with `vt_jarm` | `fingerprint:` on the JARM | `shares JARM (VT)` |',
    '| TLS Certificate | subject or thumbprint | `shares certificate subject (VT)`, `shares certificate thumbprint (VT)` |',
    '| Domain | `ssl_subject:` | `certificate names this domain (VT)` |',
    '| Email Address, Organization | `whois:` | `WHOIS names this email (VT)`, `WHOIS names this organization (VT)` |',
    '| File Hash | `vhash:`, else `imphash:`, else main icon | `shares vhash (VT)`, `shares imphash (VT)`, `shares main icon (VT)` |',
    '| URL | `content:` | `contains this string (VT content search)` |',
    '',
    '- Other pivots: `content` finds the files containing a Domain, IP Address or URL string; `whois` finds the domains whose WHOIS names a Domain (`WHOIS mentions this domain (VT)`), Email Address or Organization; `imphash`, `vhash` and `icon` choose one File Hash pivot. Nodes the chosen pivot does not apply to are skipped.',
    '- VirusTotal search matches only the OpenSSH spelling of an SSH key fingerprint, so a key stored as hex is converted before the query. Pseudonymised organization names, truncated emails and privacy-proxy placeholders are not searched.',
    '',
    '## Requirements',
    '',
    "- **The analyst's own VirusTotal Premium API key**, stored as a secret plugin setting and sent only in the `x-apikey` header, never in a URL. A community key cannot read what this pack asks for: measured on 2026-10-10, `/intelligence/search`, `/port_infos/…` and the historical relationships answer 403 on a community key, and an IP report comes back without its port data.",
    '- **Desktop app only.** VirusTotal sends no CORS headers, so a browser cannot read its replies; on the web the plugins refuse with that reason.',
    '- Uses types from the Infrastructure, Threat and Identity type packs.',
    '',
    '## Cost and limits',
    '',
    "- Each VT Search and each pivot VT Search from Node runs costs Intelligence quota. A File Hash pivot first reads the file's report for its vhash, imphash or icon, one more request.",
    "- Relationship and history lists are read 40 entries per request, so a limit of 100 costs three requests per relationship per node. VT Port History makes one request per port, plus one to list the IP's ports when no port is given.",
    '- HTTP 429 is retried three times, after 15, 30 and 60 seconds (or the `Retry-After` the server sends, capped at 60 seconds); after that the run stops with "quota exhausted".',
    '- A rejected key (HTTP 401) ends the run. Per item, a 404 (no record), a 400 (rejected value) or a 403 (not readable with this key) is logged and skipped. VT Search ends on a 403; VT Search from Node, on a 403 for one query family (such as `content:`), skips that family for the rest of the run.',
    '',
    '## What it contacts',
    '',
    "- Only `https://www.virustotal.com/api/v3`, with GET requests. VirusTotal sees every value looked up or searched, under the analyst's key.",
    '- **Passive.** Nothing is submitted, and the hosts and files under investigation are never contacted: port data, certificates, WHOIS and sandbox results are what VirusTotal already holds.',
    '- Graph writes are staged: nothing reaches the project until the analyst reviews and applies them.',
    '- One edge per direction between two nodes: a target reached two ways gets one edge carrying both labels, joined by `; ` (for example `communicates with; references`).',
    '',
    '## Data and licences',
    '',
    "Everything the pack adds is VirusTotal's data, read with the analyst's own key. The `vt_` properties record VirusTotal's view at the time of the run. The pack bundles no data of its own.",
    '',
    '## Source',
    '',
    'https://github.com/Vineyard-Intelligence/pluginpack-virustotal-premium (Apache-2.0). `dist/pack.mjs` is built from `src/` with `node build.mjs`: `src/vt-core.ts` holds the shared request and mapping code, `src/whois.ts`, `src/host.ts` and `src/file.ts` the WHOIS, host and file plugins, and `src/virustotal-premium.ts` the rest and the pack.',
].join('\n');

// The pack-level author/license/icon/platforms are not optional decoration: the registry's
// verify_pinned check compares the catalog entry's claims (icon, platforms) against THIS document
// at the pinned ref, and a missing field fails the pin — which is what kept 0.1.0 out of the
// approved list.
const pack: VineyardPluginPack & {
    author: { name: string; url: string };
    license: string;
    icon: string;
    platforms: PluginManifest['platforms'];
} = {
    identifier: 'run.vineyard.pluginpacks.virustotal_premium',
    content_type: 'vineyard:pluginpack',
    name: 'VirusTotal Premium',
    version: '0.3.0',
    summary:
        'VirusTotal Premium pivots: port data/history, historical certs, WHOIS history, host files/URLs, file IOCs, relatives and sandbox behaviour, and Intelligence search from keys, certs, WHOIS, strings or similar files. Needs a Premium key. Desktop only.',
    description: PAGE,
    author: { name: 'VINEYARD', url: 'https://vineyard.run' },
    license: 'Apache-2.0',
    icon: 'scan-search',
    platforms: PLATFORMS,
    plugins: [
        vtPortInfo,
        vtSearch,
        vtSearchFromNode,
        vtPortHistory,
        vtRelationships,
        vtWhoisHistory,
        vtHostFiles,
        vtHostUrls,
        vtFileNetwork,
        vtFileRelatives,
        vtFileBehaviour,
    ],
};

export const virustotalPremiumPack = definePluginPack(pack);
export default virustotalPremiumPack;
