<div align="center">

<img src="docs/logo.png" alt="IntelChecker logo" width="260" />

# IntelChecker

**Real-time Threat Intelligence triage for SOC analysts and CTI teams**

*Submit an indicator — get consolidated results from multiple sources in seconds.*

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-4-06B6D4?style=flat-square&logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![Vite](https://img.shields.io/badge/Vite-8-646CFF?style=flat-square&logo=vite&logoColor=white)](https://vitejs.dev/)

</div>

<img src="docs/screenshot.png" alt="IntelChecker results view" width="100%" />

## ✨ Features

| | |
|---|---|
| ⚡ **Parallel lookups** | Every source is queried at once; each card renders as soon as its source answers |
| 🎯 **Two-score verdict** | **Knowledge** (how much is known) + **Risk** (how risky, per sources with a verdict) → a quadrant: Confirmed malicious · Isolated signal · Known benign · Unknown… |
| 📊 **Summary** | Who flagged it, malware families, threat actor relations, first/last seen, GeoIP / ASN / ISP — each value traceable to its source |
| 🗺️ **Explainable** | Matrix view replays how each source moved both scores; *How is this calculated?* shows every contribution |
| 🔐 **Role-based access** | Sign-in required; Admin · Analyst · Reader roles, users managed from the **Users** page |
| 🔌 **API** | `POST /lookup` with per-user API tokens: every source + the same verdict as the UI in one call, logged in History |
| 🧮 **Tunable** | Per-source risk/knowledge weights, thresholds and knowledge saturation from the **Admin** page |
| 🕓 **History** | Every lookup is saved with a frozen snapshot; a frequency card flags indicators that keep coming back |
| 🌐 **EN / ES** | Whole interface and in-app docs in English and Spanish |

## 🔎 Sources

| Source | IP | Domain | URL | Hash | ASN | Threat Actor |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| [AbuseIPDB](https://www.abuseipdb.com) | ✅ | | | | | |
| [VirusTotal](https://www.virustotal.com) | ✅ | ✅ | ✅ | ✅ | | |
| [ThreatFox · abuse.ch](https://threatfox.abuse.ch) | ✅ | | | ✅ | | |
| [AlienVault OTX](https://otx.alienvault.com) | ✅ | ✅ | ✅ | ✅ | | ✅ |
| [IPinfo](https://ipinfo.io) | ✅ | | | | | |
| [Shodan](https://www.shodan.io) | ✅ | | | | ✅ | |
| [Tor Exit Nodes (dan.me.uk)](https://www.dan.me.uk/tornodes) | ✅ | | | | | |
| [URLhaus · abuse.ch](https://urlhaus.abuse.ch) | ✅ | ✅ | ✅ | ✅ | | |
| [MITRE ATT&CK](https://attack.mitre.org) | | | | | | ✅ |
| [RIPEstat](https://stat.ripe.net) | ✅ | | | | ✅ | |
| [urlscan.io](https://urlscan.io) | | ✅ | ✅ | | | |
| [MalwareBazaar · abuse.ch](https://bazaar.abuse.ch) | | | | ✅ | | |
| [PhishTank](https://phishtank.org) | | | ✅ | | | |
| [MISP](https://www.misp-project.org) *(any number of instances)* | ✅ | ✅ | ✅ | ✅ | | |
| [Recorded Future](https://www.recordedfuture.com) | ✅ | ✅ | ✅ | ✅ | | |
| [ANY.RUN](https://any.run) *(TI Lookup)* | ✅ | ✅ | ✅ | ✅ | | |
| [GreyNoise](https://greynoise.io) *(Community)* | ✅ | | | | | |
| [Hybrid Analysis](https://hybrid-analysis.com) *(Falcon Sandbox)* | ✅ | ✅ | ✅ | ✅ | | |
| [Google Safe Browsing](https://safebrowsing.google.com) | | | ✅ | | | |
| [TweetFeed](https://tweetfeed.live) | ✅ | ✅ | ✅ | ✅ | | |
| [CrowdSec CTI](https://www.crowdsec.net/cti) | ✅ | | | | | |
| [CIRCL hashlookup](https://hashlookup.circl.lu) *(known-good files)* | | | | ✅ | | |
| RDAP *(domain registration / age)* | | ✅ | ✅ | | | |
| [Tranco](https://tranco-list.eu) *(top 1M domains)* | | ✅ | | | | |
| [Malpedia](https://malpedia.caad.fkie.fraunhofer.de) | | | | | | ✅ |
| [Spamhaus](https://www.spamhaus.org) *(ZEN, DBL, ASN-DROP)* | ✅ | ✅ | ✅ | | ✅ | |
| [OpenPhish](https://openphish.com) *(community feed)* | ✅ | ✅ | ✅ | | | |
| [YARAify · abuse.ch](https://yaraify.abuse.ch) | | | | ✅ | | |
| [SSLBL · abuse.ch](https://sslbl.abuse.ch) *(certificate SHA-1)* | | | | ✅ | | |
| [CIRCL Passive DNS](https://www.circl.lu/services/passive-dns/) | ✅ | ✅ | | | | |

Per-source notes (passive lookups, shared keys, limits, MISP multi-instance and mTLS) are in [docs/sources.md](docs/sources.md).

## 🚀 Getting started

Requires Docker + Docker Compose. No API key is mandatory: sources without one show as *Not configured* and everything else keeps working.

```bash
git clone <repo-url>
cd IntelChecker

cp backend/.env.example backend/.env     # optional: initial admin, session settings
cp .env.example .env                     # optional: change FRONTEND_PORT / BACKEND_PORT

docker compose up --build -d
```

Open `http://<host>:8080` (or your `FRONTEND_PORT`) and sign in. On the first start the backend creates the admin **`admin` / `admin`** (a warning is shown until you change that password — do it before going to production); set `ADMIN_USERNAME` / `ADMIN_PASSWORD` in `backend/.env` to start with your own instead. Then add your API keys on the **Connectors** page (header → **Connectors**). Users, connectors, weights and thresholds are managed from the UI; query history, users, connectors and weights persist in the `backend/data/` volume.

**Update to a new version**

```bash
docker compose down
git pull
docker compose up --build -d      # add `build --no-cache` if a container serves stale code
```

`backend/.env` and `backend/data/` (history, users, connectors and saved weights) are not touched by an update.

## 🔑 API keys

Admins manage every key from the **Connectors** page (header → **Connectors**): set / replace / remove a key, **Test** it, and add or edit MISP instances — no restart needed. Keys are stored in `backend/data/connectors.json` (permissions 0600, in clear like `.env`: protect the volume and its backups) and listed by their last four characters (an admin can reveal one on demand; it's logged).

The variables below still work in `backend/.env` as a fallback (a key saved on Connectors wins). `MISP_<N>_*` instances in `.env` are used until the first MISP change on Connectors, which copies them over.

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
| `SPAMHAUS_DQS_KEY` *(optional)* | [Spamhaus DQS](https://www.spamhaus.com/free-trial/sign-up-for-a-free-data-query-service-account/) — only if your DNS resolver is a public one | ✅ |
| `MISP_<N>_NAME` / `_URL` / `_KEY` / … | [MISP](https://www.misp-project.org) — any number of instances (better: add them on Connectors) | n/a |

Tor Exit Nodes, MITRE ATT&CK, RIPEstat, PhishTank, TweetFeed, CIRCL hashlookup, RDAP, Tranco, Malpedia, Spamhaus, OpenPhish and SSLBL need no key.

## 📚 Documentation

| Document | Contents |
|---|---|
| [docs/user-guide.md](docs/user-guide.md) | Reading a lookup: Knowledge / Risk formulas, quadrants, Summary, matrix, history and search frequency |
| [docs/admin.md](docs/admin.md) | Users and roles, every Admin setting and its effect, default weights, per-source scoring rules |
| [docs/api.md](docs/api.md) | API tokens, `POST /lookup` and the other endpoints, with curl / Python examples |
| [docs/sources.md](docs/sources.md) | Notes on each integration, MISP multi-instance and mutual TLS |
| [docs/development.md](docs/development.md) | Running without Docker, configuration files, project structure, architecture |

The same user and admin guidance is available in the app (header → **Docs**) with this deployment's live weights.

---

<div align="center">
<sub>Built for internal SOC and CTI operations · Sign-in with Admin / Analyst / Reader roles</sub>
</div>
