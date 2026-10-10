// VirusTotal Premium — file pivots: from a File Hash to the network it touches, the files around
// it, and what the sandboxes saw it do. Everything here reads under `/files/{hash}` (a SHA-256,
// SHA-1 or MD5 all resolve), relationships as full objects so each IP / domain / URL / file lands
// with its verdicts.
//
// MEASURED 2026-10-10 (Premium key, WannaCry ed01ebfb…41aa):
//   - contacted_domains lists the sandbox's own PTR lookups ('129.214.248.87.in-addr.arpa') — the
//     shared mapper drops those; itw_domains lists path-carrying pseudo-domains
//     ('000webhostapp.com/asacubebotnetcontrolpanel') — the mapper drops those too.
//   - similar_files returns the SOURCE FILE ITSELF as its first hit.
//   - behaviour_mitre_trees already uses ATT&CK's newer tactic names (TA0005 is "Stealth", and a
//     TA0112 "Defense Impairment" appears), which the type pack's tactic enum predates.
//   - an empty relationship is 200 with `data: []` (embedded_ips, bundled_files), not an error.
//   - every ip_address object carries `asn` as a number — the type pack's form (infrastructure 3.0).
// A 404 on a file's FIRST answered read means VirusTotal has no such file, so it ends that file
// instead of spending a request per remaining relationship. Any other refusal — a 403, a 400, a 404
// after an earlier read proved the file exists — skips only the one read it answered.
//
// THE HOST KEEPS ONE EDGE PER DIRECTED (from, to) PAIR: a second create on the pair is dropped at
// commit as a duplicate, label and all. So every edge here goes through `Pairs`, and a target reached
// more than one way (an IP the file both embeds and contacts, an archive that is both an execution
// parent and a compressed parent) gets one edge whose label names each way, joined with '; '.
import { definePlugin } from './sdk';
import type { GraphNode, HostContext, RunResult } from './sdk';
import {
    API_KEY_CONFIG,
    GRAPH_SCOPES,
    LIFECYCLE,
    PLATFORMS,
    VtError,
    abortErr,
    addPair,
    clampParam,
    ensureNode,
    infra,
    itemMiss,
    joinCapped,
    linkPairs,
    netScope,
    nodeSpecFromVt,
    selectedNodesOfTypes,
    threatType,
    updateNode,
    vtGet,
    vtList,
    vtPathFor,
    webType,
} from './vt-core';
import type { EdgePairs } from './vt-core';

const FILE_TYPE = 'threat.file_hash';

/** What to call a file node in progress lines and logs: its hash, shortened. */
function fileLabel(node: GraphNode): string {
    const d = node.data || {};
    return String(d.sha256 ?? d.sha1 ?? d.md5 ?? node.id).slice(0, 12);
}

/**
 * One VT read for one file. Returns the body, or — when VirusTotal refused — 'stop' (a 404 before
 * any read of this file succeeded: VT has no such file, so its other reads would miss too) or 'skip'
 * (anything else itemMiss names: only this read is lost). `file.found` records that a read of this
 * file succeeded. The miss is counted and logged here; anything else (401, quota, cancel) rethrows.
 */
async function readOrMiss<T>(
    ctx: HostContext,
    read: () => Promise<T>,
    what: string,
    counts: { misses: number },
    file: { found: boolean },
): Promise<T | 'skip' | 'stop'> {
    try {
        const body = await read();
        file.found = true;
        return body;
    } catch (e) {
        const miss = itemMiss(e);
        if (!miss) throw e;
        counts.misses++;
        ctx.progress?.log?.(`${what}: ${miss}`);
        return e instanceof VtError && e.status === 404 && !file.found ? 'stop' : 'skip';
    }
}

type Pairs = EdgePairs;

const LIMIT_PARAM = { type: 'number', title: 'Max per relationship', description: 'Objects read per relationship (1–100, default 20).', minimum: 1, maximum: 100, default: 20 } as const;

// =============================================================================================
// 1. vt_file_network — the IPs, domains and URLs a file touches
// =============================================================================================
// The pivot from a sample to infrastructure, three ways that mean different things: what it
// CONTACTED when detonated (its C2 and staging hosts — the strongest lead), what is EMBEDDED in it as
// strings (configured but maybe never reached in the sandbox), and where it was seen DISTRIBUTED in
// the wild (the hosts that served it). Each is its own edge label so the analyst can tell a beacon
// from a download site at a glance. Edges run file → entity; an entity in two groups gets one edge
// naming both ('contacts (sandbox); embeds').
const NET_GROUPS = [
    { param: 'contacted', label: 'contacts (sandbox)', rels: ['contacted_ips', 'contacted_domains', 'contacted_urls'] },
    { param: 'embedded', label: 'embeds', rels: ['embedded_ips', 'embedded_domains', 'embedded_urls'] },
    { param: 'itw', label: 'distributed from (in the wild)', rels: ['itw_ips', 'itw_domains', 'itw_urls'] },
] as const;
const NET_ENTITY: Record<string, 'ips' | 'domains' | 'urls'> = {
    'infrastructure.ip_address': 'ips',
    'infrastructure.domain': 'domains',
    'web.url': 'urls',
};

export const vtFileNetwork = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.vt_file_network',
        content_type: 'vineyard:plugin',
        name: 'VT File Network',
        version: '0.2.0',
        description:
            "For each selected File Hash, reads VirusTotal's network relationships and adds the IP Addresses, Domains and URLs around it: what the file contacted when detonated in VirusTotal's sandboxes (linked 'contacts (sandbox)'), what is embedded in it as strings (linked 'embeds'), and where it was seen distributed in the wild (linked 'distributed from (in the wild)'). An entity found more than one way gets one edge naming each, e.g. 'contacts (sandbox); embeds'. Reverse-DNS (in-addr.arpa) lookups are dropped. Needs a VirusTotal Premium key. Desktop only.",
        icon: 'network',
        platforms: PLATFORMS,
        params: {
            type: 'object',
            properties: {
                contacted: { type: 'boolean', title: 'Contacted (sandbox)', default: true, description: "IPs/domains/URLs the file contacted when detonated in VirusTotal's sandboxes." },
                embedded: { type: 'boolean', title: 'Embedded', default: true, description: 'IPs/domains/URLs found as strings inside the file.' },
                itw: { type: 'boolean', title: 'In the wild', default: true, description: 'Where the file was seen distributed in the wild.' },
                limit: LIMIT_PARAM,
            },
        },
        io: { consumes: [threatType('file_hash')], produces: [infra('ip_address'), infra('domain'), webType('url')] },
        scopes: { graph: GRAPH_SCOPES, network: netScope("Read a file's network relationships from VirusTotal"), config: [API_KEY_CONFIG] },
        lifecycle: LIFECYCLE,
    },
    async run(ctx: HostContext): Promise<RunResult> {
        const files = await selectedNodesOfTypes(ctx, [FILE_TYPE]);
        const limit = clampParam(ctx.params?.limit, 20, 1, 100);
        const rels = NET_GROUPS.filter((g) => ctx.params?.[g.param] !== false).flatMap((g) => g.rels.map((rel) => ({ ...g, rel })));
        const counts = { checked: 0, contacted: 0, embedded: 0, itw: 0, ips: 0, domains: 0, urls: 0, misses: 0 };
        for (const [i, node] of files.entries()) {
            if (ctx.signal?.aborted) throw abortErr();
            const path = vtPathFor(node);
            if (!path) continue;
            counts.checked++;
            const who = fileLabel(node);
            const file = { found: false };
            const hits: Array<{ obj: any; group: (typeof rels)[number] }> = [];
            for (const [j, r] of rels.entries()) {
                if (ctx.signal?.aborted) throw abortErr();
                ctx.progress?.set?.({ message: `${who} ${r.rel}`, percent: (i + j / rels.length) / files.length });
                const objs = await readOrMiss(ctx, () => vtList(ctx, `${path}/${r.rel}`, limit), `${who} ${r.rel}`, counts, file);
                if (objs === 'stop') break;
                if (objs === 'skip') continue;
                for (const obj of objs) hits.push({ obj, group: r });
            }
            // Written once every read for this file is in, so each entity's edge carries all its
            // labels — and a run stopped mid-file leaves no half-linked entities behind.
            const pairs: Pairs = new Map();
            for (const { obj, group } of hits) {
                const spec = nodeSpecFromVt(obj);
                const kind = spec && NET_ENTITY[spec.type];
                if (!spec || !kind) continue;
                const n = await ensureNode(ctx, spec.type, spec.data);
                if (n.id === node.id) continue;
                const added = addPair(pairs, node.id, n.id, group.label);
                if (added) counts[group.param]++;
                if (added === 'pair') counts[kind]++;
            }
            await linkPairs(ctx, pairs);
        }
        return {
            summary: `${counts.checked} file(s): ${counts.contacted} contacted, ${counts.embedded} embedded, ${counts.itw} in-the-wild link(s) — ${counts.ips} IP(s), ${counts.domains} domain(s), ${counts.urls} URL(s)${counts.misses ? `, ${counts.misses} miss(es)` : ''}`,
            counts,
        };
    },
});

// =============================================================================================
// 2. vt_file_relatives — the files around a file
// =============================================================================================
// The sample-to-sample pivot that clusters a campaign: VT's similar files (same family, rebuilt or
// repacked), the execution parents that launched it (droppers, installers, archives), the files it
// dropped (payload stages, ransom notes), and — off by default because popular samples have hundreds
// — the archives it was compressed into and the files bundled inside it. The edge direction carries
// the meaning: parents point at the source, children hang off it, and a file related two ways in
// the same direction gets one edge naming both ('executed; contains'). similar_files lists the
// source itself as its first hit (measured), so a hit sharing any hash with the source is never linked.
const RELATIVES = [
    { param: 'similar', byDefault: true, rel: 'similar_files', label: 'similar to (VT)', hitIsSource: true, count: 'similar', title: 'Similar files', hint: 'Files VirusTotal clusters as similar to this one (same family, rebuilt or repacked).' },
    { param: 'execution_parents', byDefault: true, rel: 'execution_parents', label: 'executed', hitIsSource: true, count: 'parents', title: 'Execution parents', hint: 'Files that launched this file when detonated — droppers, installers, archives.' },
    { param: 'dropped', byDefault: true, rel: 'dropped_files', label: 'dropped', hitIsSource: false, count: 'dropped', title: 'Dropped files', hint: 'Files this file wrote to disk when detonated.' },
    { param: 'compressed_parents', byDefault: false, rel: 'compressed_parents', label: 'contains', hitIsSource: true, count: 'compressed_parents', title: 'Compressed parents', hint: 'Archives that contain this file — often hundreds for a popular sample.' },
    { param: 'bundled', byDefault: false, rel: 'bundled_files', label: 'contains', hitIsSource: false, count: 'bundled', title: 'Bundled files', hint: 'Files packed inside this file when it is an archive or installer.' },
] as const;

/** Two file records are the same file when any hash they both carry matches (case-insensitive). */
function sameFile(a: Record<string, unknown>, b: Record<string, unknown>): boolean {
    return (['sha256', 'sha1', 'md5'] as const).some(
        (k) => typeof a[k] === 'string' && typeof b[k] === 'string' && (a[k] as string).toLowerCase() === (b[k] as string).toLowerCase(),
    );
}

export const vtFileRelatives = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.vt_file_relatives',
        content_type: 'vineyard:plugin',
        name: 'VT File Relatives',
        version: '0.2.0',
        description:
            "For each selected File Hash, reads VirusTotal's file relationships and adds the related files as File Hashes: files VirusTotal finds similar (linked 'similar to (VT)'; the file itself is never linked), files that launched it (linked 'executed'), files it dropped when detonated (linked 'dropped'), and — when switched on — archives that contain it and files bundled inside it (linked 'contains'). A file related more than one way in the same direction gets one edge naming each, e.g. 'executed; contains'. Needs a VirusTotal Premium key. Desktop only.",
        icon: 'git-compare',
        platforms: PLATFORMS,
        params: {
            type: 'object',
            properties: {
                ...Object.fromEntries(RELATIVES.map((r) => [r.param, { type: 'boolean', title: r.title, default: r.byDefault, description: r.hint }])),
                limit: LIMIT_PARAM,
            },
        },
        io: { consumes: [threatType('file_hash')], produces: [threatType('file_hash')] },
        scopes: { graph: GRAPH_SCOPES, network: netScope("Read a file's related files from VirusTotal"), config: [API_KEY_CONFIG] },
        lifecycle: LIFECYCLE,
    },
    async run(ctx: HostContext): Promise<RunResult> {
        const files = await selectedNodesOfTypes(ctx, [FILE_TYPE]);
        const limit = clampParam(ctx.params?.limit, 20, 1, 100);
        const rels = RELATIVES.filter((r) => (r.byDefault ? ctx.params?.[r.param] !== false : ctx.params?.[r.param] === true));
        const counts = { checked: 0, similar: 0, parents: 0, dropped: 0, compressed_parents: 0, bundled: 0, misses: 0 };
        for (const [i, node] of files.entries()) {
            if (ctx.signal?.aborted) throw abortErr();
            const path = vtPathFor(node);
            if (!path) continue;
            counts.checked++;
            const who = fileLabel(node);
            const file = { found: false };
            const hits: Array<{ obj: any; r: (typeof rels)[number] }> = [];
            for (const [j, r] of rels.entries()) {
                if (ctx.signal?.aborted) throw abortErr();
                ctx.progress?.set?.({ message: `${who} ${r.rel}`, percent: (i + j / rels.length) / files.length });
                const objs = await readOrMiss(ctx, () => vtList(ctx, `${path}/${r.rel}`, limit), `${who} ${r.rel}`, counts, file);
                if (objs === 'stop') break;
                if (objs === 'skip') continue;
                for (const obj of objs) hits.push({ obj, r });
            }
            // Written once every read is in, as in vt_file_network: one edge per pair, all its labels.
            const pairs: Pairs = new Map();
            for (const { obj, r } of hits) {
                if (!obj?.attributes) continue; // an unreported hash: an id and an error, nothing to show
                const spec = nodeSpecFromVt(obj);
                if (!spec || spec.type !== FILE_TYPE || sameFile(node.data || {}, spec.data)) continue;
                const n = await ensureNode(ctx, spec.type, spec.data);
                if (n.id === node.id) continue;
                const [from, to] = r.hitIsSource ? [n.id, node.id] : [node.id, n.id];
                if (addPair(pairs, from, to, r.label)) counts[r.count]++;
            }
            await linkPairs(ctx, pairs);
        }
        const parts = [`${counts.similar} similar`, `${counts.parents} execution parent(s)`, `${counts.dropped} dropped`];
        if (counts.compressed_parents) parts.push(`${counts.compressed_parents} compressed parent(s)`);
        if (counts.bundled) parts.push(`${counts.bundled} bundled`);
        return { summary: `${counts.checked} file(s): ${parts.join(', ')}${counts.misses ? `, ${counts.misses} miss(es)` : ''}`, counts };
    },
});

// =============================================================================================
// 3. vt_file_behaviour — what the sandboxes and rule sets say a file does
// =============================================================================================
// Turns a sample into the things analysts pivot and report on: the ATT&CK techniques VirusTotal's
// sandboxes observed (behaviour_mitre_trees — the same technique across many unrelated samples is how
// a TTP overlap shows up in the graph), the crowdsourced YARA / Sigma / IDS rules it trips (a shared
// rule is a cheap cluster key), and the AV consensus family name. One file-report GET feeds rules and
// classification; the MITRE tree is a second GET, made only when that box is ticked.
//
// Type pack fit (validated by the host on every create, so these are not optional):
//   - attack_pattern.tactic is a single-value enum of the 14 classic tactics, so it takes the first
//     tactic the technique appeared under, mapped by tactic ID; every tactic name goes to vt_tactics.
//   - signature.signature_type has no 'ids'; an IDS rule gets 'snort' / 'suricata' only when its
//     rule_source names the engine (the measured 'Proofpoint Emerging Threats Open' does not).
//   - malware.malware_type is required; it takes VT's top threat category when the enum has it.
//   - attack_pattern has no identity but its NAME, and a later write overwrites technique_id. The
//     measured trees name one technique under two IDs four times — Yomi Hunter still reports the IDs
//     ATT&CK retired into sub-techniques (T1060 → T1547.001 'Registry Run Keys / Startup Folder',
//     T1158 → T1564.001, T1107 → T1070.004, T1081 → T1552.001 'Credentials In Files'/'in Files'). So
//     techniques are folded by ID and by case-folded name into one node that keeps the current ID,
//     with every ID VT used listed in vt_technique_ids.
const TACTIC_ENUM: Record<string, string> = {
    TA0043: 'reconnaissance',
    TA0042: 'resource-development',
    TA0001: 'initial-access',
    TA0002: 'execution',
    TA0003: 'persistence',
    TA0004: 'privilege-escalation',
    TA0005: 'defense-evasion', // "Stealth" in the measured trees — same ID
    TA0112: 'defense-evasion', // "Defense Impairment", split out of Defense Evasion
    TA0006: 'credential-access',
    TA0007: 'discovery',
    TA0008: 'lateral-movement',
    TA0009: 'collection',
    TA0011: 'command-and-control',
    TA0010: 'exfiltration',
    TA0040: 'impact',
};
const TECHNIQUE_ID_RE = /^T\d{4}(\.\d{3})?$/;
const MALWARE_TYPES = new Set(['trojan', 'ransomware', 'worm', 'loader', 'backdoor', 'rat', 'stealer', 'rootkit', 'botnet', 'downloader', 'wiper', 'spyware', 'adware']);
const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, informational: 4 };
const bySeverity = (level: (x: any) => unknown) => (a: any, b: any) =>
    (SEVERITY_RANK[String(level(a)).toLowerCase()] ?? 5) - (SEVERITY_RANK[String(level(b)).toLowerCase()] ?? 5);
const str = (v: unknown): string => (typeof v === 'string' ? v.trim() : '');
const list = (v: unknown): any[] => (Array.isArray(v) ? v : []);
const joinDash = (...parts: unknown[]): string | undefined => parts.map(str).filter(Boolean).join(' — ') || undefined;
const isSubTechnique = (id: string): boolean => id.includes('.');

/** One technique ID as the sandboxes reported it. */
interface Reported {
    name: string;
    description: string;
    tactics: Array<{ id: string; name: string }>;
    sandboxes: Set<string>;
}

interface Technique extends Reported {
    /** The current ID: see techniquesFrom. */
    id: string;
    /** Every ID folded into this technique, the current one first. */
    ids: string[];
    order: number;
}

/**
 * Techniques across every sandbox's tree, one per technique however many IDs and spellings VT used
 * for it, most-corroborated first. Of the IDs folded together the one kept is a sub-technique over a
 * bare technique (the retired form, whatever its vote — measured, each retired ID here is reported by
 * a single sandbox, and 'File Deletion' is a 1–1 tie), then the one more sandboxes reported; its own
 * name, description and tactics describe the node.
 */
function techniquesFrom(trees: any): { techniques: Technique[]; sandboxes: string[] } {
    const groups: Array<Map<string, Reported>> = [];
    const byKey = new Map<string, Map<string, Reported>>(); // 'id:T1129' and 'name:shared modules' → its group
    const sandboxes: string[] = [];
    for (const [sandbox, tree] of Object.entries<any>(trees ?? {})) {
        let reported = false;
        for (const tactic of list(tree?.tactics)) {
            const tac = { id: str(tactic?.id), name: str(tactic?.name) };
            for (const t of list(tactic?.techniques)) {
                const id = str(t?.id);
                const name = str(t?.name);
                if (!TECHNIQUE_ID_RE.test(id) || !name) continue;
                reported = true;
                const nameKey = `name:${name.toLowerCase()}`;
                let group = byKey.get(`id:${id}`) ?? byKey.get(nameKey);
                if (!group) groups.push((group = new Map()));
                byKey.set(`id:${id}`, group);
                byKey.set(nameKey, group);
                let r = group.get(id);
                if (!r) group.set(id, (r = { name, description: str(t?.description).slice(0, 300), tactics: [], sandboxes: new Set() }));
                r.sandboxes.add(sandbox);
                if (tac.name && !r.tactics.some((x) => x.name === tac.name)) r.tactics.push(tac);
            }
        }
        if (reported) sandboxes.push(sandbox);
    }
    const techniques = groups.map((group, order): Technique => {
        const ids = [...group.keys()].sort(
            (a, b) => Number(isSubTechnique(b)) - Number(isSubTechnique(a)) || group.get(b)!.sandboxes.size - group.get(a)!.sandboxes.size,
        );
        const current = group.get(ids[0])!;
        const all = new Set([...group.values()].flatMap((r) => [...r.sandboxes]));
        return { ...current, id: ids[0], ids, sandboxes: all, order };
    });
    techniques.sort((a, b) => b.sandboxes.size - a.sandboxes.size || a.order - b.order);
    return { techniques, sandboxes };
}

function techniqueData(t: Technique): Record<string, unknown> {
    const data: Record<string, unknown> = { name: t.name, technique_id: t.id };
    const tactic = t.tactics.map((x) => TACTIC_ENUM[x.id] ?? x.name.toLowerCase().replace(/\s+/g, '-')).find((v) => Object.values(TACTIC_ENUM).includes(v));
    if (tactic) data.tactic = tactic;
    if (t.tactics.length) data.vt_tactics = t.tactics.map((x) => x.name).join(', ');
    if (t.description) data.description = t.description;
    return data;
}

/**
 * techniqueData, settled against what this run already wrote for the same case-folded name — the
 * same node to the host. Across the selected files a name keeps the spelling it first landed under
 * (so it stays one node), a retired bare ID never overwrites a sub-technique already written for it,
 * and vt_technique_ids gathers every ID seen for it this run.
 */
function settleTechnique(written: Map<string, { data: Record<string, unknown>; ids: string[] }>, t: Technique): Record<string, unknown> {
    const key = t.name.toLowerCase();
    const prev = written.get(key);
    const keepPrev = !!prev && isSubTechnique(String(prev.data.technique_id)) && !isSubTechnique(t.id);
    const data: Record<string, unknown> = keepPrev ? { ...prev!.data } : { ...techniqueData(t), ...(prev ? { name: prev.data.name } : {}) };
    const ids = [...new Set([String(data.technique_id), ...(prev?.ids ?? []), ...t.ids])];
    delete data.vt_technique_ids;
    if (ids.length > 1) data.vt_technique_ids = ids.join(', ');
    written.set(key, { data, ids });
    return data;
}

interface SigSpec {
    kind: 'yara' | 'sigma' | 'ids';
    label: string;
    data: Record<string, unknown>;
}

/** The report's YARA / Sigma / IDS hits as signature drafts, deduped by (kind, name), each kind capped. */
function signaturesFrom(attrs: any, kinds: { yara: boolean; sigma: boolean; ids: boolean }, cap: number): SigSpec[] {
    const raw: SigSpec[] = [];
    if (kinds.yara) {
        for (const y of list(attrs?.crowdsourced_yara_results)) {
            raw.push({ kind: 'yara', label: 'matches YARA rule', data: { name: str(y?.rule_name), signature_type: 'yara', rule: str(y?.ruleset_name) || undefined, description: joinDash(y?.description, y?.author) } });
        }
    }
    if (kinds.sigma) {
        for (const s of [...list(attrs?.sigma_analysis_results)].sort(bySeverity((x) => x?.rule_level))) {
            raw.push({ kind: 'sigma', label: 'matches Sigma rule', data: { name: str(s?.rule_title), signature_type: 'sigma', description: joinDash(s?.rule_level, s?.rule_source) } });
        }
    }
    if (kinds.ids) {
        for (const a of [...list(attrs?.crowdsourced_ids_results)].sort(bySeverity((x) => x?.alert_severity))) {
            const source = str(a?.rule_source);
            const engine = /snort/i.test(source) ? 'snort' : /suricata/i.test(source) ? 'suricata' : undefined;
            raw.push({ kind: 'ids', label: 'triggers IDS rule', data: { name: str(a?.rule_msg), signature_type: engine, rule: str(a?.rule_id) || undefined, description: joinDash(a?.alert_severity, source) } });
        }
    }
    const seen = new Set<string>();
    const perKind: Record<string, number> = {};
    const out: SigSpec[] = [];
    for (const s of raw) {
        const name = String(s.data.name);
        const key = `${s.kind}\u0000${name}`;
        if (!name || seen.has(key) || (perKind[s.kind] ?? 0) >= cap) continue;
        seen.add(key);
        perKind[s.kind] = (perKind[s.kind] ?? 0) + 1;
        // Drop unset fields so a blank never reaches the host's enum/required checks.
        out.push({ ...s, data: Object.fromEntries(Object.entries(s.data).filter(([, v]) => v != null && v !== '')) });
    }
    return out;
}

/** VT's top threat category in the type pack's malware_type vocabulary. */
function malwareType(categories: any[]): string {
    const top = str(categories[0]?.value).toLowerCase();
    if (!top) return 'unknown';
    return MALWARE_TYPES.has(top) ? top : 'other';
}

const byCount = (a: any, b: any) => (Number(b?.count) || 0) - (Number(a?.count) || 0);

export const vtFileBehaviour = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.vt_file_behaviour',
        content_type: 'vineyard:plugin',
        name: 'VT File Behaviour',
        version: '0.2.0',
        description:
            "For each selected File Hash, reads VirusTotal's file report and its sandboxes' MITRE ATT&CK trees and adds what they found: ATT&CK techniques as Attack Patterns linked 'exhibits (sandbox)' (a technique VirusTotal reports under a retired ID and its current one is one Attack Pattern, kept under the current ID), crowdsourced YARA, Sigma and IDS hits as Detection Signatures linked 'matches YARA rule', 'matches Sigma rule' and 'triggers IDS rule', and the top AV family names as Malware linked 'classified as'. Writes vt_threat_label, vt_threat_category, vt_sandbox_verdicts and vt_mitre_sandboxes onto the file. Needs a VirusTotal Premium key. Desktop only.",
        icon: 'activity',
        platforms: PLATFORMS,
        params: {
            type: 'object',
            properties: {
                mitre: { type: 'boolean', title: 'MITRE ATT&CK techniques', default: true, description: "Techniques VirusTotal's sandboxes observed when detonating the file." },
                yara: { type: 'boolean', title: 'YARA rules', default: true, description: 'Crowdsourced YARA rules that match the file.' },
                sigma: { type: 'boolean', title: 'Sigma rules', default: true, description: "Sigma rules that matched the sandboxes' event logs." },
                ids: { type: 'boolean', title: 'IDS alerts', default: false, description: "IDS (Snort/Suricata) alerts on the sandboxes' network capture — noisy (ICMP, Tor exit lists)." },
                classification: { type: 'boolean', title: 'Threat classification', default: true, description: 'Top AV family names as Malware, plus the threat label, category and sandbox verdicts on the file.' },
                max_per_kind: { type: 'number', title: 'Max per kind', description: 'Techniques / YARA / Sigma / IDS entries kept per file, each (1–100, default 25).', minimum: 1, maximum: 100, default: 25 },
            },
        },
        io: { consumes: [threatType('file_hash')], produces: [threatType('attack_pattern'), threatType('signature'), threatType('malware')] },
        scopes: { graph: GRAPH_SCOPES, network: netScope("Read a file's report and sandbox ATT&CK trees from VirusTotal"), config: [API_KEY_CONFIG] },
        lifecycle: LIFECYCLE,
    },
    async run(ctx: HostContext): Promise<RunResult> {
        const files = await selectedNodesOfTypes(ctx, [FILE_TYPE]);
        const p = ctx.params ?? {};
        const want = { mitre: p.mitre !== false, yara: p.yara !== false, sigma: p.sigma !== false, ids: p.ids === true, classification: p.classification !== false };
        const cap = clampParam(p.max_per_kind, 25, 1, 100);
        const needReport = want.yara || want.sigma || want.ids || want.classification;
        const counts = { checked: 0, techniques: 0, yara: 0, sigma: 0, ids: 0, families: 0, misses: 0 };
        const written = new Map<string, { data: Record<string, unknown>; ids: string[] }>();
        for (const node of files) {
            if (ctx.signal?.aborted) throw abortErr();
            const path = vtPathFor(node);
            if (!path) continue;
            counts.checked++;
            const who = fileLabel(node);
            ctx.progress?.set?.({ message: `${who} behaviour`, percent: counts.checked / files.length });
            const file = { found: false };
            const patch: Record<string, unknown> = {};
            // Signatures and families key on their name too, so two rules sharing one name are one
            // node — and one edge, through the pairs, never a second create the host would drop.
            const pairs: Pairs = new Map();

            let attrs: any = null;
            if (needReport) {
                const body = await readOrMiss(ctx, () => vtGet(ctx, path), `${who} report`, counts, file);
                if (body === 'stop') continue;
                if (body !== 'skip') attrs = (body as any)?.data?.attributes ?? {};
            }

            if (want.mitre) {
                if (ctx.signal?.aborted) throw abortErr();
                const body = await readOrMiss(ctx, () => vtGet(ctx, `${path}/behaviour_mitre_trees`), `${who} behaviour_mitre_trees`, counts, file);
                // A miss here costs only the techniques: a report already read still feeds the rest.
                if (body !== 'skip' && body !== 'stop') {
                    const { techniques, sandboxes } = techniquesFrom((body as any)?.data);
                    for (const t of techniques.slice(0, cap)) {
                        const n = await ensureNode(ctx, 'threat.attack_pattern', settleTechnique(written, t));
                        if (addPair(pairs, node.id, n.id, 'exhibits (sandbox)')) counts.techniques++;
                    }
                    const sb = joinCapped(sandboxes);
                    if (sb) patch.vt_mitre_sandboxes = sb;
                }
            }

            if (attrs) {
                for (const s of signaturesFrom(attrs, want, cap)) {
                    if (ctx.signal?.aborted) throw abortErr();
                    const n = await ensureNode(ctx, 'threat.signature', s.data);
                    if (addPair(pairs, node.id, n.id, s.label)) counts[s.kind]++;
                }
                if (want.classification) {
                    const ptc = attrs.popular_threat_classification ?? {};
                    const categories = (Array.isArray(ptc.popular_threat_category) ? [...ptc.popular_threat_category] : []).sort(byCount);
                    const names = (Array.isArray(ptc.popular_threat_name) ? [...ptc.popular_threat_name] : []).sort(byCount);
                    const malware_type = malwareType(categories);
                    for (const f of names.filter((x) => str(x?.value)).slice(0, 3)) {
                        const n = await ensureNode(ctx, 'threat.malware', { name: str(f.value), is_family: true, malware_type });
                        if (addPair(pairs, node.id, n.id, 'classified as')) counts.families++;
                    }
                    if (str(ptc.suggested_threat_label)) patch.vt_threat_label = str(ptc.suggested_threat_label);
                    const cat = categories.map((c) => str(c?.value)).filter(Boolean).join(', ');
                    if (cat) patch.vt_threat_category = cat;
                    const verdicts = Object.entries<any>(attrs.sandbox_verdicts ?? {}).map(([key, v]) => {
                        const classes = Array.isArray(v?.malware_classification) ? v.malware_classification.filter(Boolean) : [];
                        return `${str(v?.sandbox_name) || key}: ${str(v?.category) || 'unknown'}${classes.length ? ` (${classes.join(', ')})` : ''}`;
                    });
                    const joined = joinCapped(verdicts);
                    if (joined) patch.vt_sandbox_verdicts = joined;
                }
            }
            await linkPairs(ctx, pairs);
            await updateNode(ctx, node, patch);
        }
        const sigs = counts.yara + counts.sigma + counts.ids;
        return {
            summary: `${counts.checked} file(s): ${counts.techniques} technique(s), ${sigs} signature(s) (${counts.yara} YARA, ${counts.sigma} Sigma, ${counts.ids} IDS), ${counts.families} famil${counts.families === 1 ? 'y' : 'ies'}${counts.misses ? `, ${counts.misses} miss(es)` : ''}`,
            counts,
        };
    },
});

export default { plugins: [vtFileNetwork, vtFileRelatives, vtFileBehaviour] };
