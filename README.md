# VirusTotal Premium — VINEYARD plugin pack

Premium-API-tier VirusTotal v3 pivots. Separate from **VirusTotal Community** on purpose: every
plugin here calls a surface a free/community key cannot read, so folding them into the Community pack
would mean a 403 or an empty response on every call. The free-tier reports stay in the Community
pack; only the Premium-only capabilities live here.

VirusTotal's docs call the paid API tier the **Premium API** (vs the free *Public API*). The product
that grants it is branded **VirusTotal Enterprise / Google Threat Intelligence (GTI)**, and the
search/hunting module is **Intelligence** (hence the `/intelligence/*` paths). Needs the analyst's own
**VirusTotal Premium API key** (`api_key`, a secret config value, sent only as the `x-apikey` header).
Desktop-only (VirusTotal sends no CORS headers).

## Tier difference (measured 2026-10-10, two keys side by side)

| | `/ip_addresses/{ip}` `port_info` | `/intelligence/search`, `/port_infos/…`, historical relationships |
|---|---|---|
| Community key | field **absent** (same object otherwise) | **403 ForbiddenError** |
| Premium key | present | works |

## Plugins

| Plugin | Consumes | What it does |
|---|---|---|
| **VT Port Info** (`vt_port_info`) | IP | Open ports + service per port, JARM, scan freshness; closed/recently-closed ports (VT keeps them); mints each **SSH host key** as a node (SHA-256 hex, VT's OpenSSH spelling kept as `vt_fingerprint`). |
| **VT Port History** (`vt_port_history`) | IP | Per-port `first_seen` / `open_since` / `last_seen_open` / status → a forensic timeline that survives a port going down. |
| **VT Historical Certificates** (`vt_relationships`) | IP / domain | Walks `historical_ssl_certificates` → every cert presented over time, so a rotated/expired cert is still recoverable. |
| **VT WHOIS History** (`vt_whois_history`) | domain / IP | `historical_whois` → a change timeline on the node (`vt_whois_history`), registrant **email** and **organization** nodes, and every **name server** ever used. Privacy-service placeholders are kept out; VT's pseudonymised emails become nodes because VT search still matches them. |
| **VT Host Files** (`vt_host_files`) | IP / domain / URL | Files that **contact** the host (its malware), files it **served**, and (opt-in) files that **name** it. |
| **VT Host URLs** (`vt_host_urls`) | IP / domain | The URLs VT has seen on the host, with title, status and verdicts. |
| **VT Search** (`vt_search`) | — (query) | Runs a VT Intelligence query **verbatim** (like Censys/Shodan search); adds matched IPs/domains/URLs/files. |
| **VT Search from Node** (`vt_search_from_node`) | SSH key / cert / IP / domain / email / organization / file / URL | Builds the query from the node and links the hits back. `auto`: SSH key & JARM on `fingerprint:`, cert on subject/thumbprint, domain on `ssl_subject:`, email/org on `whois:`, file on `vhash:` (else `imphash:` / icon), URL on `content:`. Explicit modes: `content` (files containing the string), `whois`, `imphash`, `vhash`, `icon`. |
| **VT File Network** (`vt_file_network`) | file | The IPs/domains/URLs a sample **contacted** in the sandbox, **embeds** as strings, and was **distributed from** in the wild. |
| **VT File Relatives** (`vt_file_relatives`) | file | Similar files, execution parents, dropped files (and, opt-in, compressed parents / bundled files). |
| **VT File Behaviour** (`vt_file_behaviour`) | file | Sandbox MITRE ATT&CK techniques, crowdsourced YARA / Sigma (/ IDS, opt-in) matches, malware family, sandbox verdicts. |

One edge per directed pair: the backend keeps a single edge per (from, to), so a target reached two
ways (a file that both contacts and names a host) gets one edge carrying both labels, joined by `; `.

## Validated against the controlled testbed (2026-10-10, Premium key)
- `vt_port_info` on the seed: 4 open ports + the cluster-A SSH host key materialised as a node.
- `vt_search_from_node` on that SSH host key: `fingerprint:"SHA256:…"` recovered the cluster-A members
  carrying it — the **SSH-key reverse pivot the paywalled Shodan Search (403) could not do**. On the
  bridge key K_B it recovered three cluster-B hosts **and** the cluster-A bridge host — the A→B bridge
  from VirusTotal alone. VT search matches only the OpenSSH spelling (hex finds nothing), so the
  pivot converts a hex node before querying.
- `vt_port_history`: the seed's per-port timeline, with the stall window visible as an earlier
  `last open` on the ports that went down.
- `vt_relationships`: recovered the planted cluster-A certificate as a historical cert; a certificate
  pivot on its CN recovered the seed and a cluster-A sibling.
- `vt_search "entity:ip ssl_subject:goldtrade-fx.com"`: recovered the cluster-A members.

Live checks of the 0.2 plugins (public samples, every created node validated against the type packs —
0 refusals): `vt_whois_history` on `avsvmcloud.com` (19 snapshots → 10 changes, 17 name servers, the
pseudonymised registrant email); `whois:` on that email → 5 sibling domains; `content:"avsvmcloud.com"` →
5 files; WannaCry → 47 network IOCs, 14 related samples, 10 ATT&CK techniques, 22 signatures, 3 family
names; a parking IP → 28 files and 10 URLs.

## Why it matters for the pivoting system
A third fresh scanner alongside Censys and Shodan, and the one place a **shared SSH host key** or
**certificate** can be searched back to its siblings on a key that actually has the privilege — so the
single-source (Censys) dependence that lost a cluster when Censys was stale can be cross-checked.

## Build / test
```
node build.mjs                 # esbuild → dist/pack.mjs
node gen-manifest.mjs          # dist/pack.mjs → plugins/virustotal-premium.manifest.json
node test-plugin.mjs           # mock unit tests, original plugins (no network)
for f in test/*.test.mjs; do node $f; done   # per-module mock tests (core converters, whois, pivots, host, file)
```

## Notes
Source layout: `src/vt-core.ts` holds the shared plumbing (vtGet, cursor paging, graph helpers, the one
VT-object → node mapper); `src/whois.ts`, `src/host.ts`, `src/file.ts` hold the 0.2 plugins;
`src/virustotal-premium.ts` the original ones and the pack. The VirusTotal Community pack keeps its
own copy of the request plumbing on purpose — the two packs are maintained separately. LiveHunt
(`vt.net.ip`) does not expose port data yet, so no port-based hunting plugin here.
