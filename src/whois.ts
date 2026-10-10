// VT WHOIS History — the registrant / registrar / name-server timeline of a domain or an IP.
//
// Graph writes are STAGED like every plugin in this pack: nothing reaches the graph until the
// analyst reviews and commits.
import { definePlugin } from './sdk';
import type { HostContext, RunResult } from './sdk';
import {
    API_KEY_CONFIG,
    DOMAIN_RE,
    GRAPH_SCOPES,
    LIFECYCLE,
    MAX_LISTED,
    PLATFORMS,
    abortErr,
    clampParam,
    dateFromUnix,
    ensureEdge,
    ensureNode,
    identityType,
    infra,
    itemMiss,
    joinCapped,
    netScope,
    nodeFromVt,
    selectedNodesOfTypes,
    updateNode,
    vtList,
    vtPathFor,
} from './vt-core';

// ---- VirusTotal's pseudonyms and the privacy-proxy placeholders --------------------------------
// MEASURED 2026-10-10: VirusTotal PSEUDONYMISES registrant PII inside historical WHOIS.
//   email 'd76e663655d6f79cs@fbi.gov'  16 hex + 's' local part, real domain — STILL SEARCHABLE:
//                                       whois:"d76e663655d6f79cs@fbi.gov" → 5 hits
//   email 'bd343e776d5ffe96s@'          truncated, no domain             → 0 hits
//   org   'da45206aa6bafae3'            16 hex                           → 0 hits
// So a complete pseudonymised email is still a pivot (kept, flagged vt_pseudonymised), while a
// truncated email or a 16-hex name matches nothing and is skipped. A privacy-proxy placeholder
// ('REDACTED FOR PRIVACY', 'Domains By Proxy, LLC', …) names the proxy service, not the
// registrant, and an empty-meaning value ('N/A', '-', 'Not Available From Registry' — the last
// measured in avsvmcloud's 2024-08 snapshot) names nobody: as a node either would link every such
// domain on earth together, so both are skipped. vt_search_from_node's whois pivot reuses these
// helpers — hence the exports — but with the NARROW placeholder test (isPlaceholder): there the
// value is one the analyst picked, and 'Private Layer INC' / 'ProxyRack LLC' are real pivots.
const PSEUDONYM_RE = /^[a-f0-9]{16}$/i;
const PSEUDONYM_EMAIL_RE = /^[a-f0-9]{16}s@/i;
const REDACTION_MARKERS = [
    'redacted',
    'privacy',
    'private',
    'proxy',
    'withheld',
    'not disclosed',
    'data protected',
    'gdpr',
    'whoisguard',
    'contact privacy',
    'domains by proxy',
    'please query',
    'statutory masking',
    'identity protect',
    'perfect privacy',
    'see privacypolicy',
];

// The narrow list: phrases only a privacy service or a redaction notice uses, matched with spaces
// and punctuation squeezed out so 'Withheld for Privacy ehf' and '…@withheldforprivacy.com' both hit.
const PLACEHOLDER_MARKERS = [
    'redacted',
    'withheldforprivacy',
    'domainsbyproxy',
    'contactprivacy',
    'whoisguard',
    'perfectprivacy',
    'privacyprotect',
    'whoisprivacy',
    'privacyservice',
    'domainprivacy',
    'privateregistration',
    'registrationprivate',
    'identityprotect',
    'privacyguardian',
    'dataprotected',
    'notdisclosed',
    'pleasequery',
    'statutorymasking',
    'seeprivacypolicy',
    'gdprmasked',
];
const JUNK_RE = /^(n\/?a|none|null|nil|unknown|not available.*|not applicable|no data|empty|-+|\.+)$/i;

/** VirusTotal's 16-hex stand-in for a registrant name or organization. */
export const isPseudonym = (v: string): boolean => PSEUDONYM_RE.test(v.trim());
/** A privacy-proxy / redaction placeholder — it names the proxy, never the registrant. BROAD: WHOIS-history node creation. */
export function isRedacted(v: string): boolean {
    const l = v.toLowerCase();
    return REDACTION_MARKERS.some((m) => l.includes(m));
}
/** The NARROW placeholder test for a value the analyst selected: only unmistakable privacy-service / redaction phrases. */
export function isPlaceholder(v: string): boolean {
    const l = v.toLowerCase().replace(/[^a-z0-9]+/g, '');
    return PLACEHOLDER_MARKERS.some((m) => l.includes(m));
}
/** An empty-meaning name: 'N/A', '-', 'Not Available From Registry', or one with no letter / under 2 letters or digits (Unicode-aware, so a CJK name counts). */
export function isJunkValue(v: string): boolean {
    const s = v.trim();
    return JUNK_RE.test(s) || !/\p{L}/u.test(s) || (s.match(/[\p{L}\p{N}]/gu)?.length ?? 0) < 2;
}
/**
 * The address lowercased when it is complete (local@domain.tld), else null — VT's truncated 'xxxxs@'
 * included, and so is a placeholder local part ('none@…', 'n/a@…'). Only the pattern applies to the
 * local part, not the letter rule: QQ addresses are all digits.
 */
export function completeEmail(v: unknown): string | null {
    const e = String(v ?? '').trim().toLowerCase();
    const at = e.indexOf('@');
    if (at < 1 || at !== e.lastIndexOf('@') || /[\s"\\]/.test(e) || JUNK_RE.test(e.slice(0, at))) return null;
    return DOMAIN_RE.test(e.slice(at + 1)) ? e : null;
}

// ---- one snapshot → one timeline state ---------------------------------------------------------
// whois_map keys vary by registrar and by RIR (measured: 'Registrant Organization' on GoDaddy,
// 'Registrant Organisation' on the Registrar of Last Resort; ARIN's OrgName/NetName/NetRange on an
// IP), so keys are matched case-insensitively against a list of spellings.
function lowerKeys(m: unknown): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries((m as Record<string, unknown>) ?? {})) {
        if (typeof v === 'string') out[k.trim().toLowerCase()] = v;
    }
    return out;
}
function field(m: Record<string, string>, names: string[]): string {
    for (const n of names) {
        const v = (m[n] ?? '').replace(/\s+/g, ' ').trim();
        if (v) return v;
    }
    return '';
}
/** A whois_map value may hold several values joined with ' | '. */
const multi = (v: string): string[] => v.split('|').map((s) => s.trim()).filter(Boolean);
/** 'NS1.X.COM | NS2.X.COM' (or ccTLD 'nserver' lines with glue IPs) → sorted, lowercased host names. */
function nameServers(raw: string): string[] {
    const out = new Set<string>();
    for (const tok of raw.split(/[|,\s]+/)) {
        const ns = tok.trim().toLowerCase().replace(/\.$/, '');
        if (ns && DOMAIN_RE.test(ns)) out.add(ns);
    }
    return [...out].sort();
}

interface WhoisState {
    /** The parts this snapshot actually carries, in timeline order — [['registrar', …], ['ns', 'a,b']]. */
    parts: Array<[string, string]>;
    emails: string[];
    orgs: string[];
    ns: string[];
}
/** The [key, value] pairs whose value is non-empty. */
const present = (pairs: Array<[string, string]>): Array<[string, string]> => pairs.filter(([, v]) => v);
function domainState(a: any): WhoisState | null {
    const m = lowerKeys(a?.whois_map);
    const registrar = String(a?.registrar_name ?? '').trim() || field(m, ['registrar', 'sponsoring registrar', 'registrar name']);
    const org = field(m, ['registrant organization', 'registrant organisation']);
    const email = field(m, ['registrant email', 'registrant e-mail']);
    const ns = nameServers(field(m, ['name server', 'name servers', 'nameservers', 'nameserver', 'nserver']));
    const parts = present([['registrar', registrar], ['org', org], ['email', email], ['ns', ns.join(',')]]);
    return parts.length ? { parts, emails: multi(email), orgs: multi(org), ns } : null;
}
// An IP's record is the RIR allocation: who holds the block and which block. Organization is read
// before OrgName because ARIN snapshots carry one or both ('PDR (PSUL-1)' vs 'PDR') for the same holder.
function ipState(a: any): WhoisState | null {
    const m = lowerKeys(a?.whois_map);
    const org = field(m, ['organization', 'orgname', 'org-name', 'owner', 'descr']);
    const net = field(m, ['netname', 'net-name']);
    const range = field(m, ['netrange', 'inetnum', 'inet6num', 'cidr']);
    const parts = present([['org', org], ['net', net], ['range', range]]);
    return parts.length ? { parts, emails: [], orgs: [], ns: [] } : null;
}
/** At most MAX_LISTED entries, the NEWEST kept: the oldest are the ones folded into '(+N earlier)'. */
function joinNewest(entries: string[]): string | undefined {
    if (entries.length <= MAX_LISTED) return joinCapped(entries);
    return `(+${entries.length - MAX_LISTED} earlier) ${entries.slice(-MAX_LISTED).join(', ')}`;
}

// =============================================================================================
// vt_whois_history — a domain's / IP's WHOIS over time (Premium relationship)
// =============================================================================================
// `/{domains|ip_addresses}/{id}/historical_whois` keeps every WHOIS snapshot VirusTotal parsed.
// Today's record of a seized or sinkholed domain names the sinkhole, not the actor; the snapshots
// from BEFORE the takedown still carry the actor's registrar, registrant email and name servers —
// and a registrant email or an NS pair reused across domains is the pivot to the rest of the
// infrastructure. Measured on avsvmcloud.com: GoDaddy with Microsoft's NS in 2020-12, then the
// Shadowserver sinkhole NS, then the Registrar of Last Resort in 2025-01. The response comes newest
// first and repeats unchanged snapshots, so it is sorted oldest first and collapsed to its changes.
// It also interleaves THIN registry records (registrar + NS, no registrant keys at all — measured:
// 6 of avsvmcloud's 10) with the registrar's full ones, so a part a snapshot lacks is "not shown",
// not "removed": a snapshot is a change only when a part it DOES carry differs from the last known
// value. A switch to a privacy placeholder is a carried value, so it is still recorded. The timeline
// keeps the newest MAX_LISTED changes when there are more.
const MAX_NS = 25;

export const vtWhoisHistory = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.vt_whois_history',
        content_type: 'vineyard:plugin',
        name: 'VT WHOIS History',
        version: '0.2.0',
        description:
            "Reads VirusTotal's WHOIS history for each selected Domain or IP Address and writes the changes as a timeline onto it: vt_whois_history (registrar, registrant organization and email, name servers per change — the RIR holder, net name and range for an IP) and vt_whois_snapshots. For a Domain it also adds each registrant email as an Email Address linked 'registrant email (WHOIS history)' (VirusTotal's pseudonymised addresses are kept with vt_pseudonymised — they are still searchable), each registrant organization as an Organization linked 'registrant organization (WHOIS history)', and each name server as a Domain linked 'name server (WHOIS history)'. Privacy-proxy placeholders, empty values such as N/A, truncated emails and 16-hex pseudonymised names are skipped. Needs a VirusTotal Premium key. Desktop only.",
        icon: 'scroll-text',
        platforms: PLATFORMS,
        params: {
            type: 'object',
            properties: {
                limit: {
                    type: 'number',
                    title: 'Snapshots per node',
                    description: 'How many of the most recent WHOIS snapshots to read per node (1–100, default 20).',
                    minimum: 1,
                    maximum: 100,
                    default: 20,
                },
            },
        },
        io: {
            consumes: [infra('domain'), infra('ip_address')],
            produces: [identityType('email_address'), identityType('organization'), infra('domain')],
        },
        scopes: { graph: GRAPH_SCOPES, network: netScope('Read VirusTotal historical WHOIS'), config: [API_KEY_CONFIG] },
        lifecycle: LIFECYCLE,
    },
    async run(ctx: HostContext): Promise<RunResult> {
        const nodes = await selectedNodesOfTypes(ctx, ['infrastructure.domain', 'infrastructure.ip_address']);
        const limit = clampParam(ctx.params?.limit, 20, 1, 100);
        const counts = { checked: 0, snapshots: 0, changes: 0, emails: 0, orgs: 0, nameservers: 0, misses: 0 };
        for (let i = 0; i < nodes.length; i++) {
            const node = nodes[i];
            if (ctx.signal?.aborted) throw abortErr();
            const path = vtPathFor(node);
            if (!path) continue;
            const isIpNode = node.type === 'infrastructure.ip_address';
            const key = String(isIpNode ? node.data.ip_address : node.data.domain_name).trim().toLowerCase();
            counts.checked++;
            ctx.progress?.set?.({ message: `WHOIS history ${key}`, percent: i / nodes.length });
            let objs: any[];
            try {
                objs = await vtList(ctx, `${path}/historical_whois`, limit);
            } catch (e) {
                const miss = itemMiss(e);
                if (miss) {
                    counts.misses++;
                    ctx.progress?.log?.(`${key}: ${miss}`);
                    continue;
                }
                throw e;
            }
            counts.snapshots += objs.length;

            // Oldest first; a junk snapshot ('Socket not responding' as its only key) yields no state
            // and is passed over without breaking the collapse of the states around it.
            const snaps = objs
                .map((o) => ({ a: o?.attributes ?? {}, seen: Number(o?.attributes?.first_seen_date ?? o?.attributes?.last_updated) || 0 }))
                .sort((x, y) => x.seen - y.seen);
            const entries: string[] = [];
            const emails = new Set<string>();
            const orgs = new Map<string, string>();
            const ns = new Set<string>();
            const known: Record<string, string> = {}; // last value seen per part
            for (const s of snaps) {
                const st = isIpNode ? ipState(s.a) : domainState(s.a);
                if (!st) continue;
                for (const v of st.emails) {
                    const e = completeEmail(v);
                    if (e && !isRedacted(e)) emails.add(e);
                }
                for (const v of st.orgs) {
                    if (!isPseudonym(v) && !isRedacted(v) && !isJunkValue(v) && !orgs.has(v.toLowerCase())) orgs.set(v.toLowerCase(), v);
                }
                for (const n of st.ns) if (n !== key) ns.add(n);
                if (st.parts.every(([k, v]) => known[k] === v)) continue;
                for (const [k, v] of st.parts) known[k] = v;
                const text = st.parts.map(([k, v]) => `${k}=${v}`).join('; ');
                const date = dateFromUnix(s.seen);
                entries.push(date ? `${date} ${text}` : text);
            }
            counts.changes += entries.length;
            if (objs.length) await updateNode(ctx, node, { vt_whois_history: joinNewest(entries), vt_whois_snapshots: objs.length });
            if (isIpNode) continue; // an IP's WHOIS names the RIR holder, already the IP's organization

            for (const email of emails) {
                const data: Record<string, unknown> = { email };
                if (PSEUDONYM_EMAIL_RE.test(email)) data.vt_pseudonymised = true;
                const n = await ensureNode(ctx, 'identity.email_address', data);
                await ensureEdge(ctx, node.id, n.id, 'registrant email (WHOIS history)');
                counts.emails++;
            }
            for (const name of orgs.values()) {
                const n = await ensureNode(ctx, 'identity.organization', { name });
                await ensureEdge(ctx, node.id, n.id, 'registrant organization (WHOIS history)');
                counts.orgs++;
            }
            for (const host of [...ns].slice(0, MAX_NS)) {
                const n = await nodeFromVt(ctx, { type: 'domain', id: host });
                if (!n || n.id === node.id) continue;
                await ensureEdge(ctx, node.id, n.id, 'name server (WHOIS history)');
                counts.nameservers++;
            }
        }
        return {
            summary:
                `${counts.checked} node(s): ${counts.snapshots} WHOIS snapshot(s), ${counts.changes} change(s), ` +
                `${counts.emails} registrant email(s), ${counts.orgs} organization(s), ${counts.nameservers} name server(s)` +
                (counts.misses ? `, ${counts.misses} skipped` : ''),
            counts,
        };
    },
});

export default { plugins: [vtWhoisHistory] };
