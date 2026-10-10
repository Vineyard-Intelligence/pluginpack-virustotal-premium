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
import type {
    ConfigValue,
    GraphScope,
    GraphNode,
    HostContext,
    NetworkScope,
    PluginManifest,
    RunResult,
    TypeRef,
    VineyardPluginPack,
} from './sdk';

const VT_BASE = 'https://www.virustotal.com/api/v3';
const API_KEY_LABEL = 'VirusTotal Premium API Key';

// ---- shared manifest fragments ---------------------------------------------------------------
const PLATFORMS: PluginManifest['platforms'] = {
    primary: 'desktop',
    web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
    desktop: { runtime: 'sandbox-js', entry: 'dist/pack.mjs', min_app_version: '0.1.0' },
};
const netScope = (purpose: string): NetworkScope[] => [{ endpoint: VT_BASE, methods: ['GET'], purpose }];
const API_KEY_CONFIG: ConfigValue = { key: 'api_key', label: API_KEY_LABEL, type: 'string', secret: true, optional: false };
const GRAPH_SCOPES: GraphScope[] = ['node:read', 'node:create', 'node:update', 'edge:create'];
const LIFECYCLE: NonNullable<PluginManifest['lifecycle']> = {
    persistence: 'opt-in',
    controls: ['progress', 'cancel'],
    progress: 'determinate',
};
const infra = (name: string): TypeRef => ({ typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name });
const webType = (name: string): TypeRef => ({ typepack: 'run.vineyard.typepacks.infrastructure', category: 'web', name });
const threatType = (name: string): TypeRef => ({ typepack: 'run.vineyard.typepacks.threat', category: 'threat', name });

// ---- tiny utilities -------------------------------------------------------------------------
const abortErr = () => new Error('cancelled');
const sleep = (ms: number, signal?: AbortSignal): Promise<void> =>
    new Promise((resolve, reject) => {
        const timer = setTimeout(finish, ms);
        function finish() {
            signal?.removeEventListener('abort', onAbort);
            resolve();
        }
        function onAbort() {
            clearTimeout(timer);
            reject(abortErr());
        }
        signal?.addEventListener('abort', onAbort, { once: true });
    });

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const isIp = (v: string): boolean => IPV4_RE.test(v) || (v.includes(':') && /^[0-9a-fA-F:]+$/.test(v));
const DOMAIN_RE = /^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$/;

function vtKey(ctx: HostContext): string {
    const k = ctx.config?.api_key;
    if (typeof k !== 'string' || !k.trim()) {
        throw new Error(`${API_KEY_LABEL} is not set — configure it in the plugin settings first`);
    }
    return String(k).trim();
}

class VtError extends Error {
    constructor(readonly status: number, readonly code: string, msg: string) {
        super(`${code}: ${msg} (HTTP ${status})`);
    }
}

const backoffMs = (attempt: number, retryAfterSec: number): number =>
    Math.min(60_000, Number.isFinite(retryAfterSec) && retryAfterSec > 0 ? retryAfterSec * 1000 : 15_000 * 2 ** attempt);

/** One GET against v3 with `x-apikey`. 429 retried; 401 ends the run; 403 is named as a tier problem. */
async function vtGet(ctx: HostContext, path: string): Promise<unknown> {
    if (ctx.signal?.aborted) throw abortErr();
    if (ctx.run?.platform && ctx.run.platform !== 'desktop') {
        throw new Error('VirusTotal sends no CORS headers — this pack only works in the VINEYARD desktop app');
    }
    const key = vtKey(ctx);
    for (let attempt = 0; ; attempt++) {
        if (ctx.signal?.aborted) throw abortErr();
        const res = await ctx.net!.fetch!(VT_BASE + path, { method: 'GET', headers: { 'x-apikey': key } });
        if (res.status === 429) {
            if (attempt < 3) {
                const waitMs = backoffMs(attempt, Number(res.headers?.['retry-after'] ?? NaN));
                ctx.progress?.log?.(`quota throttle — waiting ${Math.round(waitMs / 1000)}s before retrying`);
                await sleep(waitMs, ctx.signal);
                continue;
            }
            throw new Error('VirusTotal quota exhausted — retry later or narrow the request.');
        }
        if (res.status >= 200 && res.status < 300) return res.json();
        let code = `HTTP ${res.status}`;
        let msg = '';
        try {
            const j = (await res.json()) as { error?: { code?: string; message?: string } };
            if (j?.error?.code) code = j.error.code;
            if (j?.error?.message) msg = j.error.message;
        } catch {
            /* non-JSON body */
        }
        if (res.status === 401) throw new Error(`VirusTotal rejected this API key (${code})`);
        throw new VtError(res.status, code, msg);
    }
}

/** Why THIS one item was skipped, or null when the error must end the whole run. */
function itemMiss(e: unknown): string | null {
    if (!(e instanceof VtError)) return null;
    if (e.status === 404) return 'no VirusTotal record';
    if (e.status === 400) return `rejected by VirusTotal (${e.code})`;
    if (e.status === 403) return 'needs a VirusTotal Premium key';
    return null;
}

const datetimeFromUnix = (sec: unknown): string | undefined =>
    typeof sec === 'number' && Number.isFinite(sec) && sec > 0 ? new Date(sec * 1000).toISOString() : undefined;
const dateFromUnix = (sec: unknown): string | undefined => datetimeFromUnix(sec)?.slice(0, 10);

const MAX_LISTED = 25;
function joinCapped(parts: string[], max = MAX_LISTED): string | undefined {
    if (!parts.length) return undefined;
    return parts.length <= max ? parts.join(', ') : `${parts.slice(0, max).join(', ')} (+${parts.length - max} more)`;
}

// ---- graph helpers --------------------------------------------------------------------------
async function selectedNodesOfTypes(ctx: HostContext, types: string[]): Promise<GraphNode[]> {
    const out: GraphNode[] = [];
    for (const id of ctx.input.selection ?? []) {
        if (ctx.signal?.aborted) throw abortErr();
        const n = await ctx.graph?.get?.(id);
        if (n && types.includes(n.type)) out.push(n);
    }
    return out;
}
async function updateNode(ctx: HostContext, node: GraphNode, patch: Record<string, unknown>): Promise<void> {
    const delta: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(patch)) {
        if (v != null && v !== '' && node.data?.[k] !== v) delta[k] = v;
    }
    if (Object.keys(delta).length) await ctx.graph!.updateNode!(node.id, delta);
}
async function ensureNode(ctx: HostContext, type: string, data: Record<string, unknown>): Promise<GraphNode> {
    return ctx.graph!.createNode!({ type, data });
}
async function ensureEdge(ctx: HostContext, from: string, to: string, label: string): Promise<void> {
    await ctx.graph!.createEdge!({ from, to, label });
}

// ---- shared: VT Intelligence search → nodes -------------------------------------------------
// One place both vt_search (free-form) and vt_search_from_node (query built from a node) go through.
// Runs the query VERBATIM, pages via meta.cursor up to `limit`, and adds a node per matched entity.
// Returns the created IP node ids so a caller can link them back to the pivot source.
const SEARCH_MAX = 300;
interface SearchOut {
    counts: { matched: number; ips: number; domains: number; urls: number; files: number; other: number };
    ipNodeIds: string[];
}
async function searchToNodes(ctx: HostContext, query: string, limit: number): Promise<SearchOut> {
    const counts = { matched: 0, ips: 0, domains: 0, urls: 0, files: 0, other: 0 };
    const ipNodeIds: string[] = [];
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
        const id = String(r?.id ?? '').trim();
        if (!id) continue;
        counts.matched++;
        switch (r?.type) {
            case 'ip_address':
                if (isIp(id)) {
                    const n = await ensureNode(ctx, 'infrastructure.ip_address', { ip_address: id });
                    ipNodeIds.push(n.id);
                    counts.ips++;
                }
                break;
            case 'domain':
                if (DOMAIN_RE.test(id)) {
                    await ensureNode(ctx, 'infrastructure.domain', { domain_name: id });
                    counts.domains++;
                }
                break;
            case 'url': {
                const url = typeof r?.attributes?.url === 'string' ? r.attributes.url : id;
                await ensureNode(ctx, 'web.url', { url });
                counts.urls++;
                break;
            }
            case 'file':
                await ensureNode(ctx, 'threat.file_hash', { sha256: id });
                counts.files++;
                break;
            default:
                counts.other++;
        }
    }
    return { counts, ipNodeIds };
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
        version: '0.1.0',
        description:
            "Reads VirusTotal's internet-scanning port data for each selected IP Address (Premium key only) and writes its observable surface: vt_open_ports, vt_services (product per port), vt_closed_ports (VT keeps closed/recently-closed ports — a timestamped record of a port going down), vt_jarm and vt_ports_scanned (freshness). Materialises each SSH host key as an SSH Host Key node linked 'presents host key', so it can be pivoted with VT Search. A community key returns no port data and the run says so. Desktop only.",
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
            const sshKeys = new Set<string>();
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
                if (typeof fp === 'string' && fp.trim()) sshKeys.add(fp.trim());
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
            for (const fp of sshKeys) {
                const keyNode = await ensureNode(ctx, 'infrastructure.ssh_host_key', { fingerprint_sha256: fp });
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
        version: '0.1.0',
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
// 3. vt_search_from_node — build the pivot query from a selected certificate / SSH key / IP / domain
// =============================================================================================
// The ergonomic wrapper around vt_search: take what you already have and find its siblings, without
// writing the query by hand. Each created IP is linked back to the source node so the pivot is
// visible in the graph.
//   ssh_host_key (fingerprint_sha256)  -> entity:ip fingerprint:"<fp>"       (validated: finds K_A/K_B siblings)
//   certificate (fingerprint_sha256)   -> entity:ip ssl_thumbprint:<fp>, or ssl_subject:<name> when the node names one
//   ip_address (vt_jarm)               -> entity:ip fingerprint:"<jarm>"     (JARM family)
//   domain (domain_name)               -> entity:ip ssl_subject:"<domain>"   (hosts whose cert names it)
function buildPivot(node: GraphNode): { query: string; label: string } | null {
    const d = node.data || {};
    if (node.type === 'infrastructure.ssh_host_key') {
        const fp = String(d.fingerprint_sha256 ?? d.fingerprint ?? '').trim();
        if (fp) return { query: `entity:ip fingerprint:"${fp}"`, label: 'shares SSH host key (VT)' };
    } else if (node.type === 'infrastructure.certificate') {
        const name = String(d.subject_cn ?? d.common_name ?? d.cn ?? '').trim();
        if (name && DOMAIN_RE.test(name)) return { query: `entity:ip ssl_subject:"${name}"`, label: 'shares certificate subject (VT)' };
        const fp = String(d.fingerprint_sha256 ?? '').trim();
        if (fp) return { query: `entity:ip ssl_thumbprint:${fp}`, label: 'shares certificate thumbprint (VT)' };
    } else if (node.type === 'infrastructure.ip_address') {
        const jarm = String(d.vt_jarm ?? d.jarm ?? d.shodan_jarm ?? '').trim();
        if (jarm) return { query: `entity:ip fingerprint:"${jarm}"`, label: 'shares JARM (VT)' };
    } else if (node.type === 'infrastructure.domain') {
        const dom = String(d.domain_name ?? d.name ?? '').trim();
        if (dom && DOMAIN_RE.test(dom)) return { query: `entity:ip ssl_subject:"${dom}"`, label: 'certificate names this domain (VT)' };
    }
    return null;
}

export const vtSearchFromNode = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.vt_search_from_node',
        content_type: 'vineyard:plugin',
        name: 'VT Search from Node',
        version: '0.1.0',
        description:
            "Pivots from each selected SSH Host Key, TLS Certificate, IP Address or Domain by building a VirusTotal Intelligence query from it and adding the hosts that match, linked back to the source node. SSH host key and JARM pivot on 'fingerprint:', a certificate on its subject or thumbprint, a domain on 'ssl_subject:'. Use it to find the other hosts carrying a shared key or certificate without writing the query by hand. Needs a VirusTotal Premium key; each pivot costs intelligence quota. Desktop only.",
        icon: 'git-fork',
        platforms: PLATFORMS,
        params: { type: 'object', properties: { limit: PARAM_LIMIT } },
        io: {
            consumes: [infra('ssh_host_key'), infra('certificate'), infra('ip_address'), infra('domain')],
            produces: [infra('ip_address')],
        },
        scopes: { graph: GRAPH_SCOPES, network: netScope('Pivot a node through VirusTotal Intelligence search'), config: [API_KEY_CONFIG] },
        lifecycle: LIFECYCLE,
    },
    async run(ctx: HostContext): Promise<RunResult> {
        const nodes = await selectedNodesOfTypes(ctx, [
            'infrastructure.ssh_host_key',
            'infrastructure.certificate',
            'infrastructure.ip_address',
            'infrastructure.domain',
        ]);
        const limit = Number(ctx.params?.limit) || 25;
        const counts = { pivoted: 0, skipped: 0, hosts: 0, linked: 0 };
        for (const node of nodes) {
            if (ctx.signal?.aborted) throw abortErr();
            const pivot = buildPivot(node);
            if (!pivot) {
                counts.skipped++;
                continue;
            }
            ctx.progress?.set?.({ message: pivot.query, percent: (counts.pivoted + counts.skipped) / nodes.length });
            let out: SearchOut;
            try {
                out = await searchToNodes(ctx, pivot.query, limit);
            } catch (e) {
                if (e instanceof VtError && e.status === 403) throw new Error('VT Intelligence search needs a Premium key (this key returned 403).');
                const miss = itemMiss(e);
                if (miss) {
                    counts.skipped++;
                    ctx.progress?.log?.(`${pivot.query}: ${miss}`);
                    continue;
                }
                throw e;
            }
            counts.pivoted++;
            counts.hosts += out.counts.ips;
            for (const ipId of out.ipNodeIds) {
                if (ipId === node.id) continue; // don't link a node to itself
                await ensureEdge(ctx, ipId, node.id, pivot.label);
                counts.linked++;
            }
        }
        return {
            summary: `${counts.pivoted} pivot(s): ${counts.hosts} host(s), ${counts.linked} link(s)${counts.skipped ? `, ${counts.skipped} skipped` : ''}`,
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
        version: '0.1.0',
        description:
            "Walks VirusTotal's historical SSL/TLS certificates for each selected IP Address or Domain (Premium relationship) and adds each certificate it presented over time as a TLS Certificate linked 'presented certificate', with its SHA-256 thumbprint. This recovers rotated or expired certificates that a current-cert pivot misses. Needs a VirusTotal Premium key. Desktop only.",
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
                        const a = cert?.attributes ?? {};
                        const thumb = a?.thumbprint_sha256 ?? cert?.id;
                        if (!thumb) continue;
                        const data: Record<string, unknown> = { fingerprint_sha256: String(thumb) };
                        const cn = a?.subject?.CN;
                        if (typeof cn === 'string' && cn) data.subject_cn = cn;
                        const nb = a?.validity?.not_before;
                        if (typeof nb === 'string' && nb) data.not_before = nb;
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
const pack: VineyardPluginPack = definePluginPack({
    identifier: 'run.vineyard.pluginpacks.virustotal_premium',
    content_type: 'vineyard:pluginpack',
    name: 'VirusTotal Premium',
    version: '0.1.0',
    description:
        "VirusTotal Premium-API pivots: internet-scanning port data (vt_port_info, vt_port_history), Intelligence search (vt_search, vt_search_from_node) for pivoting a shared SSH host key / certificate / JARM back to its siblings, and historical certificates (vt_relationships). Needs the analyst's own VirusTotal Premium API key (VirusTotal Enterprise / Google Threat Intelligence); a community key cannot read these. Desktop only.",
    plugins: [vtPortInfo, vtSearch, vtSearchFromNode, vtPortHistory, vtRelationships],
});

export default pack;
