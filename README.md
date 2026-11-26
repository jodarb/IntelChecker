<div align="center">

<img src="docs/logo.png" alt="IntelChecker logo" width="240" />

# IntelChecker

### One indicator in. One explainable verdict out.

**IntelChecker queries 30+ threat intelligence sources in parallel and turns their answers into a single, traceable verdict, in seconds.**
Built for SOC analysts and CTI teams who triage IPs, domains, URLs, hashes, ASNs, threat actors and CVEs all day.

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-4-06B6D4?style=flat-square&logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![Vite](https://img.shields.io/badge/Vite-8-646CFF?style=flat-square&logo=vite&logoColor=white)](https://vitejs.dev/)

</div>

<img src="docs/screenshot.png" alt="IntelChecker results view" width="100%" />

## Why IntelChecker

Triage a suspicious IP the usual way and you end up with ten browser tabs, ten different scoring scales and a gut feeling. Worse, "not found" quietly reads as "clean".

IntelChecker replaces that routine with **one search**:

- **Every source at once.** VirusTotal, AbuseIPDB, OTX, abuse.ch, Shodan, GreyNoise, Recorded Future, your own **MISP** and **OpenCTI** servers, and more, all queried in parallel. Each result card appears the moment its source answers.
- **A verdict you can defend.** Two independent scores tell apart *"we know a lot and it's bad"* and *"one feed says it's bad, and nobody else has heard of it"*. Every number can be traced back to the source and the field it came from.
- **Absence of data is never a clean bill of health.** A source with no record lowers confidence. It never lowers risk.
- **Yours to run.** Self-hosted with Docker Compose, built for internal networks and VPNs. API keys and history stay on your server. Lookups only go to the sources you leave enabled.

## How it works

```
  ┌──────────────┐     ┌────────────────────────────────┐     ┌─────────────────────────────┐
  │  Indicator   │ ──▶ │  30+ sources queried in        │ ──▶ │  Knowledge 0–10             │
  │  IP · domain │     │  parallel, each normalised to  │     │  Risk      0–10             │
  │  URL · hash  │     │  hit / clean / context /       │     │  ─────────────────────────  │
  │  ASN · actor │     │  no data, plus a depth of      │     │  Quadrant: Confirmed ·      │
  │  CVE         │     │  record                        │     │  Isolated signal · Benign … │
  └──────────────┘     └────────────────────────────────┘     └─────────────────────────────┘
```

| Score | Question it answers | How |
|---|---|---|
| 🧠 **Knowledge** | *How much does the intel world know about this?* | Weighted share of the sources that have a record, rich or basic |
| 🔥 **Risk** | *Of the sources that issued a verdict, how bad is it?* | Weighted average of their 0–10 subscores, ignoring "no data" |

Together they place the indicator in a **quadrant**:
- *Malicious · Confirmed*: act on it.
- *Isolated signal · Verify*: high risk, but few sources know it.
- *Known · Benign*.
- *Unknown*.

For CVEs the quadrants are worded as exploitation risk. Weights and thresholds are tunable per source from the Admin page. The full formulas are in the [user guide](docs/user-guide.md).

## ✨ Features

| | |
|---|---|
| ⚡ **Real-time, parallel** | One request per source, fired at once; a slow or failing source never blocks the others, and its card says *why* it failed (bad key, rate limit, timeout…) |
| 🎯 **Two-score verdict** | Knowledge × Risk → quadrant, computed identically in the browser and in the API |
| 📊 **Cross-source Summary** | Who flagged it, malware families (aliases merged), threat actor relations, campaigns, first / last seen, GeoIP · ASN · ISP, CVSS · KEV · EPSS, each value traceable to its source |
| 🗺️ **Explainable** | The matrix view replays, source by source, how each answer moved both scores; *How is this calculated?* lists every contribution |
| 🏢 **Your own intel** | Any number of **MISP** and **OpenCTI** instances (partners, ISACs, internal), with TLS / mTLS, added at runtime from the UI |
| 🐞 **Vulnerabilities** | CVE lookups across NVD, CISA KEV, EPSS, OTX and OpenCTI: severity, exploitation probability, known exploitation, public exploits |
| 🔌 **API** | `POST /lookup` with per-user tokens: every source plus the same verdict in one call, logged in History, ready for SOAR / scripts |
| 🔐 **Access control** | Sign-in required; Admin · Analyst · Reader roles; server-side sessions; keys managed and tested from the **Connectors** page |
| 🕓 **History** | Every lookup is stored with a frozen snapshot of every source's answer; recurring indicators are flagged |
| 🌐 **EN / ES** | Full interface and in-app docs in English and Spanish |

## 🔎 Sources

**34 integrations across 7 indicator types.** 15 of them work with no API key at all, and most others have a free tier.

| Category | Sources |
|---|---|
| **Reputation & detections** | VirusTotal · AbuseIPDB · AlienVault OTX · Recorded Future · CrowdSec CTI · GreyNoise · Spamhaus · Google Safe Browsing |
| **Malware & IOC feeds** | ThreatFox · URLhaus · MalwareBazaar · YARAify · SSLBL · OpenPhish · PhishTank · TweetFeed |
| **Sandboxes** | ANY.RUN · Hybrid Analysis · urlscan.io |
| **Infrastructure context** | Shodan · IPinfo · RIPEstat · Tor exit nodes · RDAP · Tranco · CIRCL Passive DNS · CIRCL hashlookup |
| **Threat actors** | MITRE ATT&CK · Malpedia · OTX · OpenCTI |
| **Vulnerabilities** | NVD · CISA KEV · EPSS · OTX · OpenCTI |
| **Your platforms** | MISP (N instances) · OpenCTI (N instances, 6.0+) |

<details>
<summary><b>Full coverage table (which types each source supports)</b></summary>

| Source | IP | Domain | URL | Hash | ASN | Threat Actor | CVE |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| [AbuseIPDB](https://www.abuseipdb.com) | ✅ | | | | | | |
| [VirusTotal](https://www.virustotal.com) | ✅ | ✅ | ✅ | ✅ | | | |
| [ThreatFox · abuse.ch](https://threatfox.abuse.ch) | ✅ | | | ✅ | | | |
| [AlienVault OTX](https://otx.alienvault.com) | ✅ | ✅ | ✅ | ✅ | | ✅ | ✅ |
| [IPinfo](https://ipinfo.io) | ✅ | | | | | | |
| [Shodan](https://www.shodan.io) | ✅ | | | | ✅ | | |
| [Tor Exit Nodes (dan.me.uk)](https://www.dan.me.uk/tornodes) | ✅ | | | | | | |
| [URLhaus · abuse.ch](https://urlhaus.abuse.ch) | ✅ | ✅ | ✅ | ✅ | | | |
| [MITRE ATT&CK](https://attack.mitre.org) | | | | | | ✅ | |
| [RIPEstat](https://stat.ripe.net) | ✅ | | | | ✅ | | |
| [urlscan.io](https://urlscan.io) | | ✅ | ✅ | | | | |
| [MalwareBazaar · abuse.ch](https://bazaar.abuse.ch) | | | | ✅ | | | |
| [PhishTank](https://phishtank.org) | | | ✅ | | | | |
| [MISP](https://www.misp-project.org) *(any number of instances)* | ✅ | ✅ | ✅ | ✅ | | | |
| [OpenCTI](https://filigran.io/platforms/opencti/) *(any number of instances, 6.0+)* | ✅ | ✅ | ✅ | ✅ | | ✅ | ✅ |
| [Recorded Future](https://www.recordedfuture.com) | ✅ | ✅ | ✅ | ✅ | | | |
| [ANY.RUN](https://any.run) *(TI Lookup)* | ✅ | ✅ | ✅ | ✅ | | | |
| [GreyNoise](https://greynoise.io) *(Community)* | ✅ | | | | | | |
| [Hybrid Analysis](https://hybrid-analysis.com) *(Falcon Sandbox)* | ✅ | ✅ | ✅ | ✅ | | | |
| [Google Safe Browsing](https://safebrowsing.google.com) | | | ✅ | | | | |
| [TweetFeed](https://tweetfeed.live) | ✅ | ✅ | ✅ | ✅ | | | |
| [CrowdSec CTI](https://www.crowdsec.net/cti) | ✅ | | | | | | |
| [CIRCL hashlookup](https://hashlookup.circl.lu) *(known-good files)* | | | | ✅ | | | |
| RDAP *(domain registration / age)* | | ✅ | ✅ | | | | |
| [Tranco](https://tranco-list.eu) *(top 1M domains)* | | ✅ | | | | | |
| [Malpedia](https://malpedia.caad.fkie.fraunhofer.de) | | | | | | ✅ | |
| [Spamhaus](https://www.spamhaus.org) *(ZEN, DBL, ASN-DROP)* | ✅ | ✅ | ✅ | | ✅ | | |
| [OpenPhish](https://openphish.com) *(community feed)* | ✅ | ✅ | ✅ | | | | |
| [YARAify · abuse.ch](https://yaraify.abuse.ch) | | | | ✅ | | | |
| [SSLBL · abuse.ch](https://sslbl.abuse.ch) *(certificate SHA-1)* | | | | ✅ | | | |
| [CIRCL Passive DNS](https://www.circl.lu/services/passive-dns/) | ✅ | ✅ | | | | | |
| [NVD (NIST)](https://nvd.nist.gov) *(CVSS, CWE, affected products)* | | | | | | | ✅ |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) *(known exploited)* | | | | | | | ✅ |
| [EPSS · FIRST](https://www.first.org/epss) *(exploitation probability)* | | | | | | | ✅ |

</details>

Per-source notes (passive lookups, shared keys, limits, MISP / OpenCTI multi-instance and mTLS) are in [docs/sources.md](docs/sources.md).

## 🚀 Getting started

All you need is Docker + Docker Compose. No API key is mandatory: sources without one show as *Not configured*, and the keyless ones work out of the box.

```bash
git clone <repo-url>
cd IntelChecker

cp backend/.env.example backend/.env     # optional: initial admin, session settings
cp .env.example .env                     # optional: change FRONTEND_PORT / BACKEND_PORT

docker compose up --build -d
```

1. Open `http://<host>:8080` (or your `FRONTEND_PORT`) and sign in. On first start the backend creates the admin **`admin` / `admin`**, and a warning stays visible until you change that password. Do it before going to production, or set `ADMIN_USERNAME` / `ADMIN_PASSWORD` in `backend/.env` beforehand.
2. Go to **Connectors**: paste your API keys, add your MISP / OpenCTI instances and press **Test** on each one.
3. Search your first indicator from the home page.

Users, connectors, weights and thresholds are all managed from the UI. History, users, connectors and weights persist in the `backend/data/` volume.

**Update to a new version**

```bash
docker compose down
git pull
docker compose up --build -d      # add `build --no-cache` if a container serves stale code
```

`backend/.env` and `backend/data/` (history, users, connectors and saved weights) are not touched by an update.

## 🔑 API keys

Admins manage every key from the **Connectors** page: set, replace, remove and **Test** a key, and add or edit MISP and OpenCTI instances, with no restart. Keys are stored in `backend/data/connectors.json`, with permissions 0600 and in clear like `.env`, so protect the volume and its backups. Each key is listed by its last four characters; an admin can reveal one on demand, and every reveal is logged.

The variables below still work in `backend/.env` as a fallback; a key saved on Connectors wins. `MISP_<N>_*` / `OPENCTI_<N>_*` instances in `.env` are used until the first MISP / OpenCTI change on Connectors, which copies them over.

<details>
<summary><b>Environment variables and where to get each key</b></summary>

| Variable | Service | Free tier |
|---|---|:---:|
| `ABUSEIPDB_API_KEY` | [AbuseIPDB](https://www.abuseipdb.com/api) | ✅ |
| `VIRUSTOTAL_API_KEY` | [VirusTotal](https://www.virustotal.com/gui/join-us) | ✅ |
| `ABUSECH_AUTH_KEY` | [ThreatFox, URLhaus, MalwareBazaar & YARAify](https://auth.abuse.ch/register) | ✅ |
| `ALIENVAULT_API_KEY` | [AlienVault OTX](https://otx.alienvault.com) | ✅ |
| `IPINFO_API_KEY` | [IPinfo](https://ipinfo.io/signup) | ✅ |
| `SHODAN_API_KEY` | [Shodan](https://account.shodan.io/register) | ✅ |
| `URLSCAN_API_KEY` | [urlscan.io](https://urlscan.io/user/signup) | ✅ |
| `PHISHTANK_API_KEY` *(optional)* | [PhishTank](https://phishtank.org/api_register.php) | ✅ |
| `RECORDED_FUTURE_API_KEY` | [Recorded Future](https://www.recordedfuture.com) | ❌ |
| `ANYRUN_API_KEY` | [ANY.RUN](https://any.run) (TI Lookup) | ❌ |
| `GREYNOISE_API_KEY` | [GreyNoise](https://viz.greynoise.io/account/) (Community) | ✅ 50/week |
| `HYBRID_ANALYSIS_API_KEY` | [Hybrid Analysis](https://hybrid-analysis.com/my-account?tab=%23api-key-tab) | ✅ |
| `GOOGLE_SAFE_BROWSING_API_KEY` | [Google Safe Browsing](https://developers.google.com/safe-browsing/v4/get-started) | ✅ |
| `CROWDSEC_API_KEY` | [CrowdSec CTI](https://app.crowdsec.net/settings/cti-api-keys) | ✅ small monthly quota |
| `MALPEDIA_API_KEY` *(optional)* | [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/user/register) | ✅ |
| `CIRCL_PDNS_CREDENTIALS` (`user:password`) | [CIRCL Passive DNS](https://www.circl.lu/services/passive-dns/) | ✅ on request |
| `NVD_API_KEY` *(optional)* | [NVD](https://nvd.nist.gov/developers/request-an-api-key) — raises the limit from 5 to 50 requests / 30 s | ✅ |
| `SPAMHAUS_DQS_KEY` *(optional)* | [Spamhaus DQS](https://www.spamhaus.com/free-trial/sign-up-for-a-free-data-query-service-account/) — only if your DNS resolver is a public one | ✅ |
| `MISP_<N>_NAME` / `_URL` / `_KEY` / … | [MISP](https://www.misp-project.org) — any number of instances (better: add them on Connectors) | n/a |
| `OPENCTI_<N>_NAME` / `_URL` / `_KEY` / … | [OpenCTI](https://filigran.io/platforms/opencti/) — any number of instances; `KEY` is a user's API token (better: add them on Connectors) | n/a |

</details>

Tor Exit Nodes, MITRE ATT&CK, RIPEstat, PhishTank, TweetFeed, CIRCL hashlookup, RDAP, Tranco, Malpedia, Spamhaus, OpenPhish, SSLBL, NVD, CISA KEV and EPSS need no key.

## 🧱 Under the hood

| Layer | Stack |
|---|---|
| Backend | Python 3.11+ · FastAPI · `asyncio` + `httpx` (one non-blocking client per source) · SQLite |
| Frontend | React 19 · TypeScript · Vite · Tailwind CSS v4 · shadcn/ui |
| Delivery | Docker Compose: nginx serves the SPA and proxies `/api` to the backend; works on networks without internet access to CDNs (fonts and assets bundled) |
| Verdict | One engine in TypeScript (UI) and a line-by-line Python mirror (API), kept identical by a randomised parity test |

## 📚 Documentation

| Document | Contents |
|---|---|
| [docs/user-guide.md](docs/user-guide.md) | Reading a lookup: Knowledge / Risk formulas, quadrants, Summary, matrix, history and search frequency |
| [docs/admin.md](docs/admin.md) | Users and roles, Connectors, every Admin setting and its effect, default weights, per-source scoring rules |
| [docs/api.md](docs/api.md) | API tokens, `POST /lookup` and the other endpoints, with curl / Python examples |
| [docs/sources.md](docs/sources.md) | Notes on each integration, MISP / OpenCTI multi-instance and mutual TLS |
| [docs/development.md](docs/development.md) | Running without Docker, configuration files, project structure, architecture, tests |

The same user and admin guidance is built into the app (header → **Docs**) and shows the live weights of your deployment.

---

<div align="center">
<sub>Built for internal SOC and CTI operations · Self-hosted · Admin / Analyst / Reader roles</sub>
</div>
