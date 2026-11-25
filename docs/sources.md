# CTI sources

Notes on each integration: how it is queried, what it needs and anything that affects how its result is read. The coverage table (which indicator types each source supports) and the API key list are in the [README](../README.md#-sources). Scoring rules per source are in [admin.md § 6](admin.md#6-reference-defaults-and-scoring-rules-per-source).

---

## Sources without an API key

**Tor Exit Nodes, MITRE ATT&CK, RIPEstat, PhishTank, TweetFeed, CIRCL hashlookup, RDAP, Tranco and Malpedia** are free public datasets/APIs: always on, toggleable like any other source.

- **MITRE ATT&CK** — the backend downloads the ~50 MB STIX dataset from GitHub and caches it in memory for 24 h (the first lookup after a cold start takes a few seconds). Besides actor lookups, it feeds the Summary's actor detection and malware alias merging (`GET /mitre/aliases`). Without internet those fall back to the built-in family table.
- **RIPEstat** — routing (ASN / prefix) and abuse-contact data from the RIPE NCC registry.
- **PhishTank** — the `checkurl` API works anonymously; an optional `PHISHTANK_API_KEY` only gives higher request priority.
- **TweetFeed** — a free (CC0) feed of IOCs shared by the infosec community on X/Twitter, queried by exact match over the last 365 days. Reports are unvetted (a legitimate service hosting abused content can show up), so its risk subscore is capped at 7 and it never issues a clean verdict. For reported IPs/domains it also feeds GeoIP / ASN / ISP into the Summary.

- **CIRCL hashlookup** — known-good file hashes (MD5 / SHA-1 / SHA-256 / SHA-512) from NIST's NSRL, Linux distribution packages, app stores… A hit is an explicit **clean** verdict for a hash, the only hash source that gives one — except when the record carries `KnownMalicious` (the file is also in a malware repository: EICAR, dual-use tools such as Metasploit), which turns it into context only. Not found is no data: most files are simply not catalogued.
- **RDAP** — registration data of the domain (of the URL's host for URLs), straight from the TLD registry found through IANA's bootstrap file (cached 24 h). Subdomains are reduced to the registered domain with the Public Suffix List bundled in `tldextract` (no network fetch). Its point is **domain age**, computed at lookup time and frozen in the history: < 7 days → 7, < 30 days → 5; an older domain issues no verdict (compromised sites are old too). Some ccTLDs (.es, .de…) publish no RDAP service: the card says so (`NoRdapService`).
- **Tranco** — research-grade ranking of the top 1M domains (aggregated over 30 days, hard to manipulate). A registered domain in the top 100 000 is an explicit **clean** verdict; outside it, context only. A **subdomain never inherits** its parent's rank (`evil.duckdns.org` → `duckdns.org` is #134): it shows as context with a warning. Popular ≠ safe content, so the risk weight is low (2). The API allows about one request per second; the backend spaces requests.
- **Malpedia** (Fraunhofer FKIE) — threat actor profiles with synonyms, suspected sponsor, targeted sectors, references and the **malware families attributed to the actor**, which feed the Summary's families and actor relations. Name search matches synonyms ("Fancy Bear" → APT28). Works without a key; an optional `MALPEDIA_API_KEY` raises the rate limit.

## Passive lookups (nothing is submitted)

- **urlscan.io** queries the public index of scans already submitted by others — it never submits your indicator, so nothing you look up becomes visible to third parties.
- **ANY.RUN** uses the **TI Lookup** API: a search over existing sandbox intelligence (~180-day window), not a live detonation.
- **Hybrid Analysis** uses `/search/terms` and `/search/hash` over existing Falcon Sandbox reports, not a live submission.

## Shared credentials and limits

- **ThreatFox, URLhaus and MalwareBazaar** share the unified abuse.ch key (`ABUSECH_AUTH_KEY`), but are independent, individually toggleable sources.
- **AlienVault OTX** threat-actor lookups use the [pulse search API](https://otx.alienvault.com/api/v1/search/pulses) with the same `ALIENVAULT_API_KEY`. It is a full-text search over community reports, not a curated actor database: results can take up to ~20 s, and MITRE ATT&CK remains the more authoritative actor profile.
- **GreyNoise** uses the free Community API: it classifies an IP as an internet-wide scanner (noise) and/or a known-good business service (RIOT). Capped at 50 lookups/week per key.
- **CrowdSec CTI** (`CROWDSEC_API_KEY`) — IP reputation built from attacks seen by the CrowdSec network: reputation (malicious / suspicious / known / safe / benign), behaviours, attack scenarios, MITRE techniques and CVEs. A known false positive (public resolver, known scanner…) or a *safe* / *benign* reputation is a clean verdict. **The free Community key has a small monthly quota** (around 120 lookups/month): consider disabling it on the home page for bulk work, and mind it when using **Test**.
- **Google Safe Browsing** only supports URLs. It is a real-time check against Google's threat lists, so — unlike most sources — a clean result is a genuine verdict, not just "no data".

## MISP (any number of instances)

MISP is the only source you can add several times: your own instance, a partner's, an ISAC feed… Each one shows up as its own named source with its own status and toggle. Admins add, edit and delete them on the **Connectors** page (name, URL, API key, TLS verification, mTLS certificate) and the change applies to the next lookup, no restart. The UI renders each with a shared card.

Instances defined in `backend/.env` (the `MISP_<N>_*` block in `backend/.env.example`) keep working: they are used until the first MISP change on Connectors, which copies them into `backend/data/connectors.json` — from then on `MISP_<N>_*` is ignored. Instance ids (`misp_<N>`) are never reused after a delete, so a new instance doesn't inherit an old one's weights.

- **Search** — by indicator value only (not MISP's `ip-src` / `ip-dst` / … attribute types), so it works the same for IP, domain, URL and hash regardless of how a community tags its attributes.
- **Scoring** — only attributes flagged for detection (`to_ids`, shown as an **IDS** chip) count as a risk hit (subscore 9). A match whose attributes all have `to_ids` off — typically benign infrastructure referenced inside an event, like a public DNS resolver — adds to Knowledge but issues no risk verdict (and is never treated as clean).
- **Weights** — set on the Admin page. New instances start at 0 / 9; instances imported from `.env` start at `MISP_<N>_WEIGHT` / `MISP_<N>_KNOWLEDGE_WEIGHT`. A value saved in Admin wins.
- **Mutual TLS** — some instances (common on government / CERT deployments) reject requests without a client certificate. Drop the cert (and key, if separate) into `backend/certs/` (gitignored, mounted read-only at `/app/certs`) and pick them in the instance's **Client certificate** / **Client key** on Connectors (or `MISP_<N>_CLIENT_CERT` / `_CLIENT_KEY` in `.env`). A combined cert+key PEM only needs the certificate.

## Roadmap

Criminal IP · OpenCTI
