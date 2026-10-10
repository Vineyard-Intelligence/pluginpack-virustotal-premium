// VirusTotal Premium — host pivots: from an IP / domain / URL to the files and URLs VirusTotal ties
// to it. These are the relationship endpoints under `/ip_addresses/{ip}`, `/domains/{domain}` and
// `/urls/{id}`, read as full objects so every file or URL lands with its hashes, type and verdicts.
//
// MEASURED 2026-10-10 (Premium key, 74.119.239.234 and avsvmcloud.com):
//   - the file relationships list a hash VirusTotal holds no report for as
//     `{id, type: 'file', error: {code: 'NotFoundError'}}` with no `attributes` at all, one of them
//     with the placeholder id 0000…1000…. The id is still 64 hex characters, so mapping it would mint a
//     junk File Hash; those are skipped and counted as `unreported`.
//   - a host with nothing in a relationship answers 200 with `data: []` (avsvmcloud.com
//     communicating_files), not 404.
import { definePlugin } from './sdk';
import type { GraphNode, HostContext, RunResult } from './sdk';
import {
    API_KEY_CONFIG,
    GRAPH_SCOPES,
    LIFECYCLE,
    PLATFORMS,
    abortErr,
    addPair,
    clampParam,
    ensureEdge,
    infra,
    itemMiss,
    linkPairs,
    netScope,
    nodeFromVt,
    selectedNodesOfTypes,
    threatType,
    vtList,
    vtPathFor,
    webType,
} from './vt-core';
import type { EdgePairs } from './vt-core';

const HOST_TYPES = ['infrastructure.ip_address', 'infrastructure.domain'];
const LIMIT_MAX = 200;
const LIMIT_DEFAULT = 20;

/** What to call a host node in progress lines and logs. */
function hostLabel(node: GraphNode): string {
    const d = node.data || {};
    return String(d.ip_address ?? d.domain_name ?? d.url ?? node.id);
}

// =============================================================================================
// 1. vt_host_files — the files that talk to, came from, or name a host
// =============================================================================================
// The pivot from infrastructure to tooling. communicating_files is the malware that contacts the
// host (it is somebody's C2, and these are the samples to cluster), downloaded_files is what the
// host served (it is a distribution point), referrer_files is content that names the host (configs,
// scripts, documents — noisy, so off by default). Each relationship is its own request: a 403 or 404
// on one skips only that one and the others still run.
//
// The edge direction carries the meaning: the sample contacts the host (file → host), the host
// serves the download (host → file), the document names the host (file → host).
const FILE_RELS = [
    {
        param: 'communicating',
        rel: 'communicating_files',
        label: 'communicates with',
        fileIsSource: true,
        byDefault: true,
        title: 'Communicating files',
        hint: 'Files that contact this host — malware using it as C2.',
    },
    {
        param: 'downloaded',
        rel: 'downloaded_files',
        label: 'served file',
        fileIsSource: false,
        byDefault: true,
        title: 'Downloaded files',
        hint: 'Files VirusTotal saw served from this host.',
    },
    {
        param: 'referrer',
        rel: 'referrer_files',
        label: 'references',
        fileIsSource: true,
        byDefault: false,
        title: 'Referrer files',
        hint: 'Files whose content references this host.',
    },
] as const;

export const vtHostFiles = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.vt_host_files',
        content_type: 'vineyard:plugin',
        name: 'VT Host Files',
        version: '0.2.0',
        description:
            "For each selected IP Address, Domain or URL, reads the files VirusTotal ties to it and adds each as a File Hash (hashes, file type, detection counts, threat label): files that contact it, linked file → host 'communicates with' (malware using it as C2); files it served, linked host → file 'served file'; and, when ticked, files whose content names it, linked file → host 'references'. A file that both contacts and names the host gets one file → host edge carrying both labels ('communicates with; references'). Listed hashes VirusTotal holds no report for are skipped and counted as unreported. Needs a VirusTotal Premium key. Desktop only.",
        icon: 'files',
        platforms: PLATFORMS,
        params: {
            type: 'object',
            properties: {
                ...Object.fromEntries(
                    FILE_RELS.map((r) => [r.param, { type: 'boolean', title: r.title, default: r.byDefault, description: r.hint }]),
                ),
                limit: {
                    type: 'number',
                    title: 'Max files per relationship',
                    description: 'Files to read per relationship for each node (1–200, default 20). Every 40 costs one request.',
                    minimum: 1,
                    maximum: LIMIT_MAX,
                    default: LIMIT_DEFAULT,
                },
            },
        },
        io: { consumes: [infra('ip_address'), infra('domain'), webType('url')], produces: [threatType('file_hash')] },
        scopes: { graph: GRAPH_SCOPES, network: netScope('Read the files VirusTotal relates to a host'), config: [API_KEY_CONFIG] },
        lifecycle: LIFECYCLE,
    },
    async run(ctx: HostContext): Promise<RunResult> {
        const nodes = await selectedNodesOfTypes(ctx, [...HOST_TYPES, 'web.url']);
        const limit = clampParam(ctx.params?.limit, LIMIT_DEFAULT, 1, LIMIT_MAX);
        const rels = FILE_RELS.filter((r) => (r.byDefault ? ctx.params?.[r.param] !== false : ctx.params?.[r.param] === true));
        const counts = { checked: 0, files: 0, communicating: 0, downloaded: 0, referrer: 0, unreported: 0, misses: 0 };
        if (!rels.length) return { summary: 'No relationship ticked — pick at least one in the Run dialog.', counts };
        const seen = new Set<string>();
        for (const node of nodes) {
            if (ctx.signal?.aborted) throw abortErr();
            const path = vtPathFor(node);
            if (!path) continue;
            counts.checked++;
            const host = hostLabel(node);
            // Read every ticked relationship first, then write. The backend keeps ONE edge per
            // directed pair, and a sample that both contacts the host and names it is file → host
            // twice ('communicates with' + 'references'): written as it arrives, the second label
            // would be dropped at commit. Collected first, it lands as one edge carrying both.
            const found: Array<{ r: (typeof FILE_RELS)[number]; obj: any }> = [];
            let unreported = 0;
            for (const r of rels) {
                if (ctx.signal?.aborted) throw abortErr();
                ctx.progress?.set?.({ message: `${r.rel} ${host}`, percent: counts.checked / nodes.length });
                let objs: any[];
                try {
                    objs = await vtList(ctx, `${path}/${r.rel}`, limit);
                } catch (e) {
                    const miss = itemMiss(e);
                    if (miss) {
                        counts.misses++;
                        ctx.progress?.log?.(`${host} ${r.rel}: ${miss}`);
                        continue;
                    }
                    throw e;
                }
                for (const obj of objs) {
                    if (obj?.type !== 'file') continue;
                    if (!obj.attributes || !Object.keys(obj.attributes).length) {
                        unreported++;
                        continue;
                    }
                    found.push({ r, obj });
                }
            }
            const pairs: EdgePairs = new Map();
            const minted = new Map<string, GraphNode | null>(); // one createNode per file, however many relationships list it
            for (const { r, obj } of found) {
                if (ctx.signal?.aborted) throw abortErr();
                const key = String(obj.attributes?.sha256 ?? obj.id).toLowerCase();
                let file = minted.get(key);
                if (file === undefined) {
                    file = await nodeFromVt(ctx, obj);
                    minted.set(key, file);
                }
                if (!file || file.id === node.id) continue;
                const added = r.fileIsSource ? addPair(pairs, file.id, node.id, r.label) : addPair(pairs, node.id, file.id, r.label);
                if (added) counts[r.param]++;
                seen.add(String(file.data?.sha256 ?? file.id));
            }
            await linkPairs(ctx, pairs);
            if (unreported) {
                counts.unreported += unreported;
                ctx.progress?.log?.(`${host}: ${unreported} listed file(s) have no VirusTotal report — skipped`);
            }
        }
        counts.files = seen.size;
        let summary =
            `${counts.checked} host(s): ${counts.files} file(s) — ${counts.communicating} communicating, ` +
            `${counts.downloaded} downloaded, ${counts.referrer} referrer`;
        if (counts.unreported) summary += `; ${counts.unreported} without a VirusTotal report`;
        if (counts.misses) summary += `; ${counts.misses} relationship(s) skipped`;
        return { summary, counts };
    },
});

// =============================================================================================
// 2. vt_host_urls — the URLs VirusTotal has seen on a host
// =============================================================================================
// What a host actually serves, path by path: the phishing kit, the payload drop, the panel login.
// For an IP this is also the cheapest way to see which hostnames point at it (the URLs carry them),
// and every URL keeps its own verdicts, title and final URL for the next pivot.
export const vtHostUrls = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.vt_host_urls',
        content_type: 'vineyard:plugin',
        name: 'VT Host URLs',
        version: '0.2.0',
        description:
            "For each selected IP Address or Domain, reads the URLs VirusTotal has seen on it and adds each as a URL (page title, HTTP status, final URL, detection counts) linked host → URL 'hosts URL'. Needs a VirusTotal Premium key. Desktop only.",
        icon: 'link-2',
        platforms: PLATFORMS,
        params: {
            type: 'object',
            properties: {
                limit: {
                    type: 'number',
                    title: 'Max URLs per node',
                    description: 'URLs to read for each node (1–200, default 20). Every 40 costs one request.',
                    minimum: 1,
                    maximum: LIMIT_MAX,
                    default: LIMIT_DEFAULT,
                },
            },
        },
        io: { consumes: [infra('ip_address'), infra('domain')], produces: [webType('url')] },
        scopes: { graph: GRAPH_SCOPES, network: netScope('Read the URLs VirusTotal has seen on a host'), config: [API_KEY_CONFIG] },
        lifecycle: LIFECYCLE,
    },
    async run(ctx: HostContext): Promise<RunResult> {
        const nodes = await selectedNodesOfTypes(ctx, HOST_TYPES);
        const limit = clampParam(ctx.params?.limit, LIMIT_DEFAULT, 1, LIMIT_MAX);
        const counts = { checked: 0, urls: 0, misses: 0 };
        for (const node of nodes) {
            if (ctx.signal?.aborted) throw abortErr();
            const path = vtPathFor(node);
            if (!path) continue;
            counts.checked++;
            const host = hostLabel(node);
            ctx.progress?.set?.({ message: `urls ${host}`, percent: counts.checked / nodes.length });
            let objs: any[];
            try {
                objs = await vtList(ctx, `${path}/urls`, limit);
            } catch (e) {
                const miss = itemMiss(e);
                if (miss) {
                    counts.misses++;
                    ctx.progress?.log?.(`${host}: ${miss}`);
                    continue;
                }
                throw e;
            }
            for (const obj of objs) {
                if (ctx.signal?.aborted) throw abortErr();
                if (obj?.type !== 'url') continue;
                const url = await nodeFromVt(ctx, obj); // null without attributes.url — the id alone is a hash
                if (!url || url.id === node.id) continue;
                await ensureEdge(ctx, node.id, url.id, 'hosts URL');
                counts.urls++;
            }
        }
        return {
            summary: `${counts.checked} host(s): ${counts.urls} URL(s)${counts.misses ? `; ${counts.misses} skipped` : ''}`,
            counts,
        };
    },
});

export default { plugins: [vtHostFiles, vtHostUrls] };
