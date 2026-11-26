# CTI sources

Notes on each integration: how it is queried, what it needs and anything that affects how its result is read. The coverage table (which indicator types each source supports) and the API key list are in the [README](../README.md#-sources). Scoring rules per source are in [admin.md § 6](admin.md#6-reference-defaults-and-scoring-rules-per-source).

---

## Sources without an API key

**Tor Exit Nodes, MITRE ATT&CK, RIPEstat, PhishTank, TweetFeed, CIRCL hashlookup, RDAP, Tranco, Malpedia, Spamhaus, OpenPhish, SSLBL, NVD, CISA KEV and EPSS** are free public datasets/APIs: always on, toggleable like any other source.

- **MITRE ATT&CK** — the backend downloads the ~50 MB STIX dataset from GitHub and caches it in memory for 24 h (the first lookup after a cold start takes a few seconds). Besides actor lookups, it feeds the Summary's actor detection and malware alias merging (`GET /mitre/aliases`). Without internet those fall back to the built-in family table.
- **RIPEstat** — routing (ASN / prefix) and abuse-contact data from the RIPE NCC registry.
- **PhishTank** — the `checkurl` API works anonymously; an optional `PHISHTANK_API_KEY` only gives higher request priority.
- **TweetFeed** — a free (CC0) feed of IOCs shared by the infosec community on X/Twitter, queried by exact match over the last 365 days. Reports are unvetted (a legitimate service hosting abused content can show up), so its risk subscore is capped at 7 and it never issues a clean verdict. For reported IPs/domains it also feeds GeoIP / ASN / ISP into the Summary.

- **CIRCL hashlookup** — known-good file hashes (MD5 / SHA-1 / SHA-256 / SHA-512) from NIST's NSRL, Linux distribution packages, app stores… A hit is an explicit **clean** verdict for a hash, the only hash source that gives one — except when the record carries `KnownMalicious` (the file is also in a malware repository: EICAR, dual-use tools such as Metasploit), which turns it into context only. Not found is no data: most files are simply not catalogued.
- **RDAP** — registration data of the domain (of the URL's host for URLs), straight from the TLD registry found through IANA's bootstrap file (cached 24 h). Subdomains are reduced to the registered domain with the Public Suffix List bundled in `tldextract` (no network fetch). Its point is **domain age**, computed at lookup time and frozen in the history: < 7 days → 7, < 30 days → 5; an older domain issues no verdict (compromised sites are old too). Some ccTLDs (.es, .de…) publish no RDAP service: the card says so (`NoRdapService`).
- **Tranco** — research-grade ranking of the top 1M domains (aggregated over 30 days, hard to manipulate). A registered domain in the top 100 000 is an explicit **clean** verdict; outside it, context only. A **subdomain never inherits** its parent's rank (`evil.duckdns.org` → `duckdns.org` is #134): it shows as context with a warning. Popular ≠ safe content, so the risk weight is low (2). The API allows about one request per second; the backend spaces requests.
- **Malpedia** (Fraunhofer FKIE) — threat actor profiles with synonyms, suspected sponsor, targeted sectors, references and the **malware families attributed to the actor**, which feed the Summary's families and actor relations. Name search matches synonyms ("Fancy Bear" → APT28). Works without a key; an optional `MALPEDIA_API_KEY` raises the rate limit.

- **Spamhaus** — DNS queries to **ZEN** for IPs (SBL, CSS, XBL, DROP, PBL) and to the **DBL** for domains and URL hosts (the registered domain and, if different, the full host), plus the **ASN-DROP** list for ASNs (downloaded, cached 12 h) — the only source that gives ASNs a risk verdict. Scored by return code: DROP / ASN-DROP and DBL phishing / malware / C&C → 9, SBL → 8, XBL and DBL spam → 7, CSS → 6, abused legitimate domains → 5–6; the PBL (dynamic / end-user ranges) is context only. **Spamhaus refuses queries arriving through public resolvers** (8.8.8.8, 1.1.1.1…): the backend uses the container's resolver, i.e. the host's; set `SPAMHAUS_DNS_SERVER` in `backend/.env` to choose one, or add a free **DQS key** (`SPAMHAUS_DQS_KEY`, Connectors), which works from any resolver. A refused query shows as `ResolverBlocked`. Free for low-volume, non-commercial use — check [the terms](https://www.spamhaus.org/organization/dnsblusage/).
- **OpenPhish** — the community feed (a few hundred currently active phishing URLs), downloaded and kept for an hour. URL: listed itself → 9, another listed URL on the same host → 6. Domain / IP: phishing URLs whose host *is* that domain (or `www.`) or IP → 7; subdomains' URLs never count for the parent. Not listed is no data — the feed is small.
- **SSLBL (abuse.ch)** — the SSL certificate blacklist (SHA-1 fingerprints of certificates used by botnet C&C / malware servers), downloaded and kept for an hour. It only answers for 40-character hashes; any other hash is reported as not applicable. Its IP and JA3 blacklists are no longer maintained (deprecated in 2025 / 2021) and are not used. The listing reason ("Vidar C&C") feeds the Summary's malware families.
- **Vulnerabilities (CVE)** — three sources for the `cve` type. The identifier is normalised (`cve-2021-44228`, `CVE_2021_44228` → `CVE-2021-44228`); anything else is rejected with `BadRequest` without querying.
  - **NVD (NIST)** — the CVE record: description, CVSS (newest version, NVD's own score first), CWE weaknesses, CISA's SSVC decision points (exploitation none / PoC / active, automatable), affected products (from the CPE configuration, trimmed to 25) and references (exploit and vendor-advisory ones first). Works without a key at ~5 requests per 30 s; a free `NVD_API_KEY` (Connectors) raises it to 50. The NVD answers a rate-limited client with HTTP 403, shown as `RateLimitExceeded`; recently published CVEs may still be *Awaiting Analysis* without a CVSS (no verdict until scored).
  - **CISA KEV** — the Known Exploited Vulnerabilities catalog (~1 800 CVEs with confirmed exploitation in the wild), downloaded and kept for 3 hours. Listed → 9, or 10 when CISA knows it's used in ransomware campaigns. Not listed is no data: KEV only holds exploitation CISA has confirmed.
  - **EPSS (FIRST)** — the daily probability that the CVE is exploited in the next 30 days, with its percentile and the last 30 days of history (sparkline on the card). Under 1 % is an explicit low-risk (clean) verdict.
- **Feodo Tracker** is deliberately not integrated: after the Emotet / QakBot takedowns its list holds a handful of entries, so it would almost never match while still diluting Knowledge for every IP.

## Passive lookups (nothing is submitted)

- **urlscan.io** queries the public index of scans already submitted by others — it never submits your indicator, so nothing you look up becomes visible to third parties.
- **ANY.RUN** uses the **TI Lookup** API: a search over existing sandbox intelligence (~180-day window), not a live detonation.
- **Hybrid Analysis** uses `/search/terms` and `/search/hash` over existing Falcon Sandbox reports, not a live submission.

## Shared credentials and limits

- **ThreatFox, URLhaus, MalwareBazaar and YARAify** share the unified abuse.ch key (`ABUSECH_AUTH_KEY`), but are independent, individually toggleable sources.
- **AlienVault OTX** threat-actor lookups use the [pulse search API](https://otx.alienvault.com/api/v1/search/pulses) with the same `ALIENVAULT_API_KEY`. It is a full-text search over community reports, not a curated actor database: results can take up to ~20 s, and MITRE ATT&CK remains the more authoritative actor profile.
- **GreyNoise** uses the free Community API: it classifies an IP as an internet-wide scanner (noise) and/or a known-good business service (RIOT). Capped at 50 lookups/week per key.
- **CrowdSec CTI** (`CROWDSEC_API_KEY`) — IP reputation built from attacks seen by the CrowdSec network: reputation (malicious / suspicious / known / safe / benign), behaviours, attack scenarios, MITRE techniques and CVEs. A known false positive (public resolver, known scanner…) or a *safe* / *benign* reputation is a clean verdict. **The free Community key has a small monthly quota** (around 120 lookups/month): consider disabling it on the home page for bulk work, and mind it when using **Test**.
- **YARAify (abuse.ch)** uses the unified `ABUSECH_AUTH_KEY`: YARA rule and ClamAV matches across every submission of a file (merged; only the latest tasks are kept). Community YARA rules are often generic (Go binary, packer…), so they only feed Knowledge; a ClamAV signature → 7.
- **CIRCL Passive DNS** (`CIRCL_PDNS_CREDENTIALS` as `user:password`, free for security teams on request) — DNS resolution history: what a domain resolved to, or which names pointed to an IP, with first / last seen. Context only (Knowledge), never a risk verdict.
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
