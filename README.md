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

Per-source notes (passive lookups, shared keys, limits, MISP multi-instance and mTLS) are in [docs/sources.md](docs/sources.md).

## 🚀 Getting started

Requires Docker + Docker Compose. No API key is mandatory: sources without one show as *Not configured* and everything else keeps working.

```bash
git clone <repo-url>
cd IntelChecker

cp backend/.env.example backend/.env     # fill in the keys you have (see below)
cp .env.example .env                     # optional: change FRONTEND_PORT / BACKEND_PORT

docker compose up --build -d
```

Open `http://<host>:8080` (or your `FRONTEND_PORT`) and sign in. On the first start the backend creates the admin **`admin` / `admin`** (a warning is shown until you change that password — do it before going to production); set `ADMIN_USERNAME` / `ADMIN_PASSWORD` in `backend/.env` to start with your own instead. Users, weights and thresholds are managed from the **Admin** page; query history, users and weights persist in the `backend/data/` volume.

**Update to a new version**

```bash
docker compose down
git pull
docker compose up --build -d      # add `build --no-cache` if a container serves stale code
```

`backend/.env` and `backend/data/` (history, users and saved weights) are not touched by an update.

## 🔑 API keys

All keys go in `backend/.env` (gitignored).

| Variable | Service | Free tier |
|---|---|:---:|
| `ABUSEIPDB_API_KEY` | [AbuseIPDB](https://www.abuseipdb.com/api) | ✅ |
| `VIRUSTOTAL_API_KEY` | [VirusTotal](https://www.virustotal.com/gui/join-us) | ✅ |
| `ABUSECH_AUTH_KEY` | [ThreatFox, URLhaus & MalwareBazaar](https://auth.abuse.ch/register) | ✅ |
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
| `MISP_<N>_NAME` / `_URL` / `_KEY` / … | [MISP](https://www.misp-project.org) — any number of instances | n/a |

Tor Exit Nodes, MITRE ATT&CK, RIPEstat, PhishTank and TweetFeed need no key.

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
