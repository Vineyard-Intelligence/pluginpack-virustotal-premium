// Shared plumbing for every VirusTotal Premium plugin: the manifest fragments, the one GET helper,
// cursor paging, graph helpers, and the VT-object → node mappers.
//
// The mappers live HERE, not in each plugin, because four plugins create the same four node types
// from the same VT objects (a file from a host relationship, a file from a file relationship, a file
// from a search hit…). One mapping means one set of property names on the graph: a file node minted
// by VT Host Files and one minted by VT File Relatives carry identical fields, so neither shadows
// the other when the host merges them on their identity.
import type { ConfigValue, GraphNode, GraphScope, HostContext, NetworkScope, PluginManifest, TypeRef } from './sdk';

export const VT_BASE = 'https://www.virustotal.com/api/v3';
export const API_KEY_LABEL = 'VirusTotal Premium API Key';

// ---- shared manifest fragments ---------------------------------------------------------------
export const PLATFORMS: PluginManifest['platforms'] = {
    primary: 'desktop',
    web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
    desktop: { runtime: 'sandbox-js', entry: 'dist/pack.mjs', min_app_version: '0.1.0' },
};
export const netScope = (purpose: string): NetworkScope[] => [{ endpoint: VT_BASE, methods: ['GET'], purpose }];
export const API_KEY_CONFIG: ConfigValue = { key: 'api_key', label: API_KEY_LABEL, type: 'string', secret: true, optional: false };
export const GRAPH_SCOPES: GraphScope[] = ['node:read', 'node:create', 'node:update', 'edge:create'];
export const LIFECYCLE: NonNullable<PluginManifest['lifecycle']> = {
    persistence: 'opt-in',
    controls: ['progress', 'cancel'],
    progress: 'determinate',
};
export const infra = (name: string): TypeRef => ({ typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name });
export const webType = (name: string): TypeRef => ({ typepack: 'run.vineyard.typepacks.infrastructure', category: 'web', name });
export const threatType = (name: string): TypeRef => ({ typepack: 'run.vineyard.typepacks.threat', category: 'threat', name });
export const identityType = (name: string): TypeRef => ({ typepack: 'run.vineyard.typepacks.identity', category: 'identity', name });

// ---- tiny utilities -------------------------------------------------------------------------
export const abortErr = () => new Error('cancelled');
export const sleep = (ms: number, signal?: AbortSignal): Promise<void> =>
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
export const isIp = (v: string): boolean => IPV4_RE.test(v) || (v.includes(':') && /^[0-9a-fA-F:]+$/.test(v));
export const DOMAIN_RE = /^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$/;
export const SHA256_RE = /^[a-f0-9]{64}$/i;
/** Reverse-DNS names VT lists as "contacted domains" — a PTR lookup, not a destination. */
export const isArpa = (d: string): boolean => /\.(in-addr|ip6)\.arpa\.?$/i.test(d);

function vtKey(ctx: HostContext): string {
    const k = ctx.config?.api_key;
    if (typeof k !== 'string' || !k.trim()) {
        throw new Error(`${API_KEY_LABEL} is not set — configure it in the plugin settings first`);
    }
    return String(k).trim();
}

export class VtError extends Error {
    constructor(readonly status: number, readonly code: string, msg: string) {
        super(`${code}: ${msg} (HTTP ${status})`);
    }
}

const backoffMs = (attempt: number, retryAfterSec: number): number =>
    Math.min(60_000, Number.isFinite(retryAfterSec) && retryAfterSec > 0 ? retryAfterSec * 1000 : 15_000 * 2 ** attempt);

/** One GET against v3 with `x-apikey`. 429 retried; 401 ends the run; 403 is named as a tier problem. */
export async function vtGet(ctx: HostContext, path: string): Promise<unknown> {
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

/**
 * A relationship (or any list endpoint) read through meta.cursor up to `limit` objects.
 * `path` may already carry a query string. Pages are capped at 40 — the relationship endpoints'
 * own maximum — so a larger `limit` costs ceil(limit/40) requests, never one oversized one.
 */
export async function vtList(ctx: HostContext, path: string, limit: number): Promise<any[]> {
    const out: any[] = [];
    let cursor: string | undefined;
    const sep = path.includes('?') ? '&' : '?';
    while (out.length < limit && !ctx.signal?.aborted) {
        const page = Math.min(40, limit - out.length);
        const q = `${path}${sep}limit=${page}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`;
        const body = (await vtGet(ctx, q)) as { data?: any[]; meta?: { cursor?: string } };
        const batch = Array.isArray(body?.data) ? body.data : [];
        out.push(...batch);
        if (!batch.length) break;
        cursor = body?.meta?.cursor;
        if (!cursor) break;
    }
    if (ctx.signal?.aborted) throw abortErr();
    return out.slice(0, limit);
}

/** Why THIS one item was skipped, or null when the error must end the whole run. */
export function itemMiss(e: unknown): string | null {
    if (!(e instanceof VtError)) return null;
    if (e.status === 404) return 'no VirusTotal record';
    if (e.status === 400) return `rejected by VirusTotal (${e.code})`;
    if (e.status === 403) return 'needs a VirusTotal Premium key';
    return null;
}

export const datetimeFromUnix = (sec: unknown): string | undefined =>
    typeof sec === 'number' && Number.isFinite(sec) && sec > 0 ? new Date(sec * 1000).toISOString() : undefined;
export const dateFromUnix = (sec: unknown): string | undefined => datetimeFromUnix(sec)?.slice(0, 10);

export const MAX_LISTED = 25;
export function joinCapped(parts: string[], max = MAX_LISTED): string | undefined {
    if (!parts.length) return undefined;
    return parts.length <= max ? parts.join(', ') : `${parts.slice(0, max).join(', ')} (+${parts.length - max} more)`;
}

/** Clamp a numeric param to [min, max], falling back to `def` when unset or not a number. */
export function clampParam(v: unknown, def: number, min: number, max: number): number {
    const n = Number(v);
    return Math.min(max, Math.max(min, Number.isFinite(n) && n > 0 ? Math.floor(n) : def));
}

// ASN has two spellings across the type packs: infrastructure 2.7 declares ip_address.asn and
// netblock.asn STRINGS ('AS13335'), and autonomous_system.autonomous_system_number an INTEGER.
// Every pack converts at its own boundary — Shodan parses 'AS…' with a regex for the AS node, Cymru
// and the Community VT pack format VT's number as `AS${n}` for the IP — because the host converts
// nothing: validateNodeData refuses a number where a string is declared and a string where an
// integer is. These two are that boundary for this pack. Whatever comes in (14956, '14956',
// 'AS14956', 'as 14956'), one canonical form goes out. AS0 is "not routed": as a value it would
// make every unrouted IP share an ASN (shared-attribute clustering groups by it), so it is null.
export function asnNumber(v: unknown): number | null {
    let n: number;
    if (typeof v === 'number') n = v;
    else {
        const m = /^\s*(?:AS)?\s*(\d{1,10})\s*$/i.exec(String(v ?? ''));
        if (!m) return null;
        n = Number(m[1]);
    }
    return Number.isInteger(n) && n > 0 && n <= 4294967295 ? n : null;
}
/** For ip_address.asn / netblock.asn: 'AS<n>'. */
export function asnLabel(v: unknown): string | null {
    const n = asnNumber(v);
    return n == null ? null : `AS${n}`;
}

// A VirusTotal certificate object → certificate node data, IDENTICAL to the VirusTotal Community
// pack's vtCert mapping. Both packs fill the same certificate node (its identity is the SHA-256
// thumbprint) and mergeNodeData overwrites with any non-blank value, so two spellings of one field
// would flip on every run. Community: issuer 'O — CN', serial as VT gives it (a hex string),
// validity as ISO-8601 UTC (VT sends 'YYYY-MM-DD HH:MM:SS'), san_count over the public names.
const INTERNAL_SUFFIX = /\.(local|localdomain|localhost|internal|lan|home\.arpa)$/;
export function certTime(v: unknown): string | undefined {
    return typeof v === 'string' && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(v) ? `${v.replace(' ', 'T')}Z` : undefined;
}
export function sanDomains(raw: unknown): string[] {
    const out = new Set<string>();
    for (const v of Array.isArray(raw) ? raw : []) {
        if (typeof v !== 'string') continue;
        const name = v.trim().toLowerCase().replace(/\.$/, '').replace(/^\*\./, '');
        if (DOMAIN_RE.test(name) && !INTERNAL_SUFFIX.test(name)) out.add(name);
    }
    return [...out];
}
/** `cert` is the attributes object (last_https_certificate, or an ssl_cert object's attributes). */
export function certSpecFromVt(cert: any, fallbackThumb?: unknown): Record<string, unknown> | null {
    const thumb = typeof cert?.thumbprint_sha256 === 'string' ? cert.thumbprint_sha256 : fallbackThumb;
    if (typeof thumb !== 'string' || !SHA256_RE.test(thumb)) return null;
    const data: Record<string, unknown> = { fingerprint_sha256: thumb };
    if (typeof cert?.subject?.CN === 'string') data.subject_common_name = cert.subject.CN;
    const issuer = [cert?.issuer?.O, cert?.issuer?.CN].filter((x: unknown) => typeof x === 'string' && x);
    if (issuer.length) data.issuer = issuer.join(' — ');
    if (typeof cert?.serial_number === 'string') data.serial_number = cert.serial_number;
    const nb = certTime(cert?.validity?.not_before);
    const na = certTime(cert?.validity?.not_after);
    if (nb) data.not_before = nb;
    if (na) data.not_after = na;
    const names = sanDomains(cert?.extensions?.subject_alternative_name);
    if (names.length) data.san_count = names.length;
    return data;
}

// SSH host-key fingerprints come in two spellings of the same 32-byte SHA-256: OpenSSH's
// 'SHA256:<43 base64 chars>' (what VirusTotal port_info reports) and 64 hex (what the type pack's
// ssh_host_key.fingerprint_sha256 requires — the host refuses anything else). MEASURED 2026-10-10:
// VT's `fingerprint:` search matches ONLY the OpenSSH spelling — 'SHA256:93mv…' found the two
// testbed hosts sharing K_A, the same key as hex 'f779af09…' found none.
const SSH_B64_RE = /^(?:SHA256:)?([A-Za-z0-9+/]{43})=?$/i;

/** Either spelling → 64 lowercase hex, or null. */
export function sshFpHex(v: unknown): string | null {
    const s = String(v ?? '').trim();
    if (SHA256_RE.test(s)) return s.toLowerCase();
    const m = SSH_B64_RE.exec(s);
    if (!m) return null;
    let bin: string;
    try {
        bin = atob(`${m[1]}=`);
    } catch {
        return null;
    }
    if (bin.length !== 32) return null;
    let hex = '';
    for (let i = 0; i < bin.length; i++) hex += bin.charCodeAt(i).toString(16).padStart(2, '0');
    return hex;
}

/** Either spelling → 'SHA256:<base64, unpadded>' (the form VT search matches), or null. */
export function sshFpOpenSsh(v: unknown): string | null {
    const hex = sshFpHex(v);
    if (!hex) return null;
    let bin = '';
    for (let i = 0; i < 64; i += 2) bin += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
    return `SHA256:${btoa(bin).replace(/=+$/, '')}`;
}

/** The v3 URL object id: base64url of the URL with padding stripped. */
export function urlId(u: string): string {
    const bytes = new TextEncoder().encode(u);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ---- graph helpers --------------------------------------------------------------------------
export async function selectedNodesOfTypes(ctx: HostContext, types: string[]): Promise<GraphNode[]> {
    const out: GraphNode[] = [];
    for (const id of ctx.input.selection ?? []) {
        if (ctx.signal?.aborted) throw abortErr();
        const n = await ctx.graph?.get?.(id);
        if (n && types.includes(n.type)) out.push(n);
    }
    return out;
}
export async function updateNode(ctx: HostContext, node: GraphNode, patch: Record<string, unknown>): Promise<void> {
    const delta: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(patch)) {
        if (v != null && v !== '' && node.data?.[k] !== v) delta[k] = v;
    }
    if (Object.keys(delta).length) await ctx.graph!.updateNode!(node.id, delta);
}
export async function ensureNode(ctx: HostContext, type: string, data: Record<string, unknown>): Promise<GraphNode> {
    return ctx.graph!.createNode!({ type, data });
}
export async function ensureEdge(ctx: HostContext, from: string, to: string, label: string): Promise<void> {
    await ctx.graph!.createEdge!({ from, to, label });
}

/**
 * Edges for one subject, ONE per directed pair. The backend allows a single edge per
 * (project, from, to): a second create on the same pair in the same run is dropped at commit as a
 * duplicate, so its label would be lost. A writer that can reach one target two ways (a file that
 * both contacts and embeds a host) collects the labels here and writes one edge carrying both.
 */
export type EdgePairs = Map<string, { from: string; to: string; labels: string[] }>;

/** Propose `label` on from → to. Returns 'pair' for a new pair, 'label' for a new label on a known pair, null for a repeat. */
export function addPair(pairs: EdgePairs, from: string, to: string, label: string): 'pair' | 'label' | null {
    const key = `${from}\u0000${to}`;
    const p = pairs.get(key);
    if (!p) {
        pairs.set(key, { from, to, labels: [label] });
        return 'pair';
    }
    if (p.labels.includes(label)) return null;
    p.labels.push(label);
    return 'label';
}

/** Write every collected pair as one edge, its labels joined by '; '. */
export async function linkPairs(ctx: HostContext, pairs: EdgePairs): Promise<void> {
    for (const p of pairs.values()) await ensureEdge(ctx, p.from, p.to, p.labels.join('; '));
}

/** The VirusTotal object path for a graph node, or null when the node carries nothing VT can look up. */
export function vtPathFor(node: GraphNode): string | null {
    const d = node.data || {};
    switch (node.type) {
        case 'infrastructure.ip_address': {
            const ip = String(d.ip_address ?? '').trim();
            return ip && isIp(ip) ? `/ip_addresses/${encodeURIComponent(ip)}` : null;
        }
        case 'infrastructure.domain': {
            const dom = String(d.domain_name ?? '').trim().toLowerCase();
            return dom && DOMAIN_RE.test(dom) ? `/domains/${encodeURIComponent(dom)}` : null;
        }
        case 'web.url': {
            const u = String(d.url ?? '').trim();
            return u ? `/urls/${urlId(u)}` : null;
        }
        case 'threat.file_hash': {
            const h = String(d.sha256 ?? d.sha1 ?? d.md5 ?? '').trim().toLowerCase();
            return /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(h) ? `/files/${h}` : null;
        }
        default:
            return null;
    }
}

// ---- VT object → node data --------------------------------------------------------------------
// Property names are the type pack's own (infrastructure 2.7 / threat 1.4) plus the vt_* verdict
// counts the VirusTotal Community pack writes, so the two packs agree on a shared node.
function verdictCounts(attrs: any): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    const stats = attrs?.last_analysis_stats ?? {};
    for (const [k, field] of [
        ['malicious', 'vt_malicious'],
        ['suspicious', 'vt_suspicious'],
        ['harmless', 'vt_harmless'],
        ['undetected', 'vt_undetected'],
    ] as const) {
        if (typeof stats[k] === 'number') out[field] = stats[k];
    }
    return out;
}

export interface NodeSpec {
    type: string;
    data: Record<string, unknown>;
}

/**
 * Map one VT API object ({type, id, attributes}) to the node it should become, or null when it is
 * not something the graph holds (an arpa PTR name, a file without a SHA-256, an unknown type).
 * Attributes are optional: a relationship read with `relationships/` returns descriptors only, and
 * the mapping still yields a valid identity-only node.
 */
export function nodeSpecFromVt(obj: any): NodeSpec | null {
    const id = String(obj?.id ?? '').trim();
    const a = obj?.attributes ?? {};
    switch (obj?.type) {
        case 'ip_address': {
            if (!id || !isIp(id)) return null;
            const data: Record<string, unknown> = { ip_address: id };
            if (typeof a.country === 'string' && a.country) data.country_code = a.country;
            const asn = asnLabel(a.asn); // declared string 'AS<n>'; VT sends a number — see asnNumber
            if (asn) data.asn = asn;
            if (typeof a.as_owner === 'string' && a.as_owner) data.organization = a.as_owner;
            return { type: 'infrastructure.ip_address', data: { ...data, ...verdictCounts(a) } };
        }
        case 'domain': {
            const dom = id.toLowerCase().replace(/\.$/, '');
            if (!dom || !DOMAIN_RE.test(dom) || isArpa(dom)) return null;
            return { type: 'infrastructure.domain', data: { domain_name: dom, ...verdictCounts(a) } };
        }
        case 'url': {
            const url = typeof a.url === 'string' && a.url ? a.url : '';
            if (!url) return null; // a url object's id is a hash; without attributes.url there is no URL to show
            const data: Record<string, unknown> = { url };
            if (typeof a.title === 'string' && a.title) data.page_title = a.title;
            if (typeof a.last_http_response_code === 'number') data.http_status = a.last_http_response_code;
            if (typeof a.last_final_url === 'string' && a.last_final_url && a.last_final_url !== url) data.final_url = a.last_final_url;
            return { type: 'web.url', data: { ...data, ...verdictCounts(a) } };
        }
        case 'file': {
            const sha256 = typeof a.sha256 === 'string' ? a.sha256 : id;
            if (!SHA256_RE.test(sha256)) return null;
            const data: Record<string, unknown> = { sha256: sha256.toLowerCase() };
            if (typeof a.sha1 === 'string') data.sha1 = a.sha1;
            if (typeof a.md5 === 'string') data.md5 = a.md5;
            if (typeof a.size === 'number') data.size = a.size;
            if (typeof a.type_description === 'string' && a.type_description) data.type_description = a.type_description;
            if (Array.isArray(a.tags) && a.tags.length) data.tags = a.tags.join(', ');
            const stats = a.last_analysis_stats ?? {};
            if (typeof stats.malicious === 'number') data.malicious_count = stats.malicious;
            if (typeof stats.suspicious === 'number') data.suspicious_count = stats.suspicious;
            if (typeof stats.undetected === 'number') data.undetected_count = stats.undetected;
            if (typeof a.times_submitted === 'number') data.times_submitted = a.times_submitted;
            const firstSeen = datetimeFromUnix(a.first_submission_date);
            if (firstSeen) data.first_seen = firstSeen;
            if (typeof a.meaningful_name === 'string' && a.meaningful_name) data.vt_name = a.meaningful_name;
            const label = a.popular_threat_classification?.suggested_threat_label;
            if (typeof label === 'string' && label) data.vt_threat_label = label;
            return { type: 'threat.file_hash', data };
        }
        default:
            return null;
    }
}

/** nodeSpecFromVt + create. Returns the node, or null when the object maps to nothing. */
export async function nodeFromVt(ctx: HostContext, obj: any): Promise<GraphNode | null> {
    const spec = nodeSpecFromVt(obj);
    return spec ? ensureNode(ctx, spec.type, spec.data) : null;
}
