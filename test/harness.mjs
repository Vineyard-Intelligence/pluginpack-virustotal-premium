// Shared mock harness for the per-module tests under test/. No network, no app.
//   Run one module:  node test/<module>.test.mjs [bundle]
// `bundle` is any ESM module whose default export has `plugins` — the full pack (dist/pack.mjs, the
// default) or a single module bundled on its own while it is being built
// (npx esbuild src/<module>.ts --bundle --format=esm --platform=browser --outfile=/tmp/<module>.mjs).
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

export async function loadPlugins(defaultRel = '../dist/pack.mjs') {
    const arg = process.argv[2];
    const url = arg ? pathToFileURL(resolve(arg)).href : new URL(defaultRel, import.meta.url).href;
    const mod = await import(url);
    const list = mod.default?.plugins ?? [];
    return Object.fromEntries(list.map((p) => [p.manifest.identifier, p]));
}

export function suite(title) {
    const ok = [];
    const fail = [];
    return {
        check(name, cond) {
            (cond ? ok : fail).push(name);
        },
        report() {
            for (const n of fail) console.log('FAIL', n);
            console.log(`${fail.length ? 'FAIL' : 'PASS'} ${title}: ${ok.length} / ${ok.length + fail.length}`);
            if (fail.length) process.exitCode = 1;
            return fail.length === 0;
        },
    };
}

export function makeGraph(nodeById) {
    const createdNodes = [];
    const createdEdges = [];
    const updates = [];
    return {
        createdNodes,
        createdEdges,
        updates,
        async get(id) {
            return nodeById[id] || null;
        },
        async list(o) {
            const all = [...Object.values(nodeById), ...createdNodes];
            return { nodes: o?.type ? all.filter((n) => n.type === o.type) : all };
        },
        async createNode(d) {
            const n = { id: `n${createdNodes.length + 1}`, type: d.type, data: d.data };
            createdNodes.push(n);
            nodeById[n.id] = n;
            return n;
        },
        async updateNode(id, data) {
            updates.push({ id, data });
        },
        async createEdge(e) {
            createdEdges.push(e);
        },
    };
}

/** `respond(url: URL)` returns { status, body, headers? }. Every call is recorded in `calls`. */
export function makeNet(respond) {
    const calls = [];
    return {
        calls,
        async fetch(url, init) {
            calls.push({ url, headers: init?.headers ?? {} });
            const r = respond(new URL(url));
            return {
                ok: r.status >= 200 && r.status < 300,
                status: r.status,
                headers: r.headers ?? {},
                async text() {
                    return JSON.stringify(r.body ?? {});
                },
                async json() {
                    return r.body ?? {};
                },
            };
        },
    };
}

export const RUN = { run: { platform: 'desktop' }, signal: new AbortController().signal, progress: { log() {}, set() {} } };
export const KEY = { api_key: 'k' };
export const vtErr = (code) => ({ error: { code, message: code } });
/** Find the edge from→to with this label (label may be a RegExp). */
export const hasEdge = (graph, from, to, label) =>
    graph.createdEdges.some((e) => e.from === from && e.to === to && (label instanceof RegExp ? label.test(e.label) : e.label === label));
