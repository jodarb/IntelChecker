# CTI sources

Notes on each integration: how it is queried, what it needs and anything that affects how its result is read. The coverage table (which indicator types each source supports) and the API key list are in the [README](../README.md#-sources). Scoring rules per source are in [admin.md § 6](admin.md#6-reference-defaults-and-scoring-rules-per-source).

---

## Sources without an API key

**Tor Exit Nodes, MITRE ATT&CK, RIPEstat, PhishTank and TweetFeed** are free public datasets/APIs: always on, toggleable like any other source.

- **MITRE ATT&CK** — the backend downloads the ~50 MB STIX dataset from GitHub and caches it in memory for 24 h (the first lookup after a cold start takes a few seconds). Besides actor lookups, it feeds the Summary's actor detection and malware alias merging (`GET /mitre/aliases`). Without internet those fall back to the built-in family table.
- **RIPEstat** — routing (ASN / prefix) and abuse-contact data from the RIPE NCC registry.
- **PhishTank** — the `checkurl` API works anonymously; an optional `PHISHTANK_API_KEY` only gives higher request priority.
- **TweetFeed** — a free (CC0) feed of IOCs shared by the infosec community on X/Twitter, queried by exact match over the last 365 days. Reports are unvetted (a legitimate service hosting abused content can show up), so its risk subscore is capped at 7 and it never issues a clean verdict. For reported IPs/domains it also feeds GeoIP / ASN / ISP into the Summary.

## Passive lookups (nothing is submitted)

- **urlscan.io** queries the public index of scans already submitted by others — it never submits your indicator, so nothing you look up becomes visible to third parties.
- **ANY.RUN** uses the **TI Lookup** API: a search over existing sandbox intelligence (~180-day window), not a live detonation.
- **Hybrid Analysis** uses `/search/terms` and `/search/hash` over existing Falcon Sandbox reports, not a live submission.

## Shared credentials and limits

- **ThreatFox, URLhaus and MalwareBazaar** share the unified abuse.ch key (`ABUSECH_AUTH_KEY`), but are independent, individually toggleable sources.
- **AlienVault OTX** threat-actor lookups use the [pulse search API](https://otx.alienvault.com/api/v1/search/pulses) with the same `ALIENVAULT_API_KEY`. It is a full-text search over community reports, not a curated actor database: results can take up to ~20 s, and MITRE ATT&CK remains the more authoritative actor profile.
- **GreyNoise** uses the free Community API: it classifies an IP as an internet-wide scanner (noise) and/or a known-good business service (RIOT). Capped at 50 lookups/week per key.
- **Google Safe Browsing** only supports URLs. It is a real-time check against Google's threat lists, so — unlike most sources — a clean result is a genuine verdict, not just "no data".

## MISP (any number of instances)

MISP is the only source you can add several times: your own instance, a partner's, an ISAC feed… Each one shows up as its own named source with its own status and toggle. The backend discovers them from `backend/.env` at startup (the `MISP_<N>_*` block in `backend/.env.example`) and the UI renders each with a shared card — adding an instance is just more env lines and a restart.

- **Search** — by indicator value only (not MISP's `ip-src` / `ip-dst` / … attribute types), so it works the same for IP, domain, URL and hash regardless of how a community tags its attributes.
- **Scoring** — only attributes flagged for detection (`to_ids`, shown as an **IDS** chip) count as a risk hit (subscore 9). A match whose attributes all have `to_ids` off — typically benign infrastructure referenced inside an event, like a public DNS resolver — adds to Knowledge but issues no risk verdict (and is never treated as clean).
- **Weights** — `MISP_<N>_WEIGHT` / `MISP_<N>_KNOWLEDGE_WEIGHT` (0–10, defaults 0 / 9) only set the instance's initial weights; a value saved in Admin wins.
- **Mutual TLS** — some instances (common on government / CERT deployments) reject requests without a client certificate. Drop the cert (and key, if separate) into `backend/certs/` (gitignored, mounted at `/app/certs`) and set `MISP_<N>_CLIENT_CERT` / `MISP_<N>_CLIENT_KEY` to the filenames. A combined cert+key PEM only needs `CLIENT_CERT`.

## Roadmap

Criminal IP · OpenCTI
