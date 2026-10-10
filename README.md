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
| **VT Port Info** (`vt_port_info`) | IP | Open ports + service per port, JARM, scan freshness; closed/recently-closed ports (VT keeps them); mints each **SSH host key** as a node to pivot. |
| **VT Search** (`vt_search`) | — (query) | Runs a VT Intelligence query **verbatim** (like Censys/Shodan search); adds matched IPs/domains/URLs/files. |
| **VT Search from Node** (`vt_search_from_node`) | SSH key / cert / IP / domain | Builds the pivot query from the node and links the hits back: SSH key & JARM on `fingerprint:`, cert on subject/thumbprint, domain on `ssl_subject:`. |
| **VT Port History** (`vt_port_history`) | IP | Per-port `first_seen` / `open_since` / `last_seen_open` / status → a forensic timeline that survives a port going down. |
| **VT Historical Certificates** (`vt_relationships`) | IP / domain | Walks `historical_ssl_certificates` → every cert presented over time, so a rotated/expired cert is still recoverable. |

## Validated against the controlled testbed (2026-10-10, Premium key)
- `vt_port_info` on the seed: 4 open ports + the cluster-A SSH host key materialised as a node.
- `vt_search_from_node` on that SSH host key: `fingerprint:"<key>"` recovered the cluster-A members
  carrying it — the **SSH-key reverse pivot the paywalled Shodan Search (403) could not do**.
- `vt_port_history`: the seed's per-port timeline, with the stall window visible as an earlier
  `last open` on the ports that went down.
- `vt_relationships`: recovered the planted cluster-A certificate as a historical cert.
- `vt_search "entity:ip ssl_subject:goldtrade-fx.com"`: recovered the cluster-A members.

## Why it matters for the pivoting system
A third fresh scanner alongside Censys and Shodan, and the one place a **shared SSH host key** or
**certificate** can be searched back to its siblings on a key that actually has the privilege — so the
single-source (Censys) dependence that lost a cluster when Censys was stale can be cross-checked.

## Build / test
```
node build.mjs          # esbuild → dist/pack.mjs
node gen-manifest.mjs    # dist/pack.mjs → plugins/virustotal-premium.manifest.json
node test-plugin.mjs    # mock unit tests (no network)
```

## Notes
The shared VT request plumbing (vtGet, backoff, graph helpers) is copied from the Community pack for
now; a later refactor lifts it into a shared `vt-core` module both packs import. LiveHunt
(`vt.net.ip`) does not expose port data yet, so no port-based hunting plugin here.
