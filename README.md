<div align="center">

# 🛡️ IntelChecker

**Real-time Threat Intelligence triage for SOC analysts and CTI teams**

*Submit an indicator — get consolidated results from multiple sources in seconds.*

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-3-06B6D4?style=flat-square&logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![Vite](https://img.shields.io/badge/Vite-6-646CFF?style=flat-square&logo=vite&logoColor=white)](https://vitejs.dev/)

</div>

---

## 🚀 Deployment

How to get IntelChecker running in your own environment.

### Prerequisites

- Docker + Docker Compose
- API keys for the CTI sources you want to use (see [🔑 API Keys](#-api-keys)) — none are required to run the app, sources without a key just render as "not configured" in the UI and everything else keeps working

### Steps

1. Clone the repo onto the host that will run it:
   ```bash
   git clone <repo-url>
   cd IntelChecker
   ```
2. Configure your credentials:
   ```bash
   cp backend/.env.example backend/.env
   ```
   Uncomment and fill in the keys for the sources you have access to. Anything left commented out just shows as "not configured" in the UI — it doesn't break the rest of the app.
3. *(Optional)* Drop your organization's logos at `logo/light.png` and `logo/dark.png` (repo root — one per theme, shown/hidden automatically as the analyst switches theme) and tune `weights.json` (repo root) to adjust how much each engine contributes to the verdict score. Both are optional — the app works fine without either.
4. Build and start the stack:
   ```bash
   docker compose up --build -d
   ```
5. Open `http://<host>:8080`.

That's the whole stack — one container for the backend, one for the frontend/nginx reverse proxy. `backend/data/` (query history) and `backend/certs/` (MISP mTLS client certs, if you need them) are Docker volumes, so they persist across restarts and rebuilds.

### Updating to a new version

When a new version is released:

```bash
docker compose down
git pull
docker compose up --build -d
```

Stop the running containers first, then pull, then rebuild and relaunch — this avoids updating source files out from under a container that's still running against them. `docker compose down` doesn't touch anything outside the containers themselves, so your `backend/.env`, `weights.json`, `logo/`, and the `backend/data/history.db` volume are all untouched by an update.

If you ever suspect a container is still serving stale code after an update (rare, but Docker's build cache can occasionally miss a change), force a clean rebuild instead:

```bash
docker compose down
docker compose build --no-cache
docker compose up -d
```

---

## ✨ Features

| | |
|---|---|
| ⚡ **Parallel queries** | All CTI sources are queried simultaneously — no waiting in line |
| 🎴 **Per-engine cards** | Each source renders its result independently as soon as it responds |
| 📊 **Summary section** | GeoIP, ASN, ISP and Tor-exit status aggregated across all engines with consensus count |
| 🎯 **Threat score gauge** | Visual semicircle gauge (0 – 10) driven by the VerdictEngine |
| 🧮 **Weighted verdict** | Configurable per-engine weights (`weights.json`, plus per-instance for MISP) drive the score, with a full contribution breakdown |
| 🏷️ **Per-engine score badges** | Every card shows its own 0–10 score, keeping "checked & clean" visually distinct from "no signal" and from "error" |
| ⬆️ **Weight-sorted results** | Both the home page's source list and the results page sort engines by weight, highest first |
| 🕓 **Query history** | Every lookup is logged to a local database — browse past queries and reopen the exact result they returned at the time |
| 🌡️ **Search frequency** | Flags indicators that keep coming back, color-scaled from grey (new) to red (hot) across 24h/72h/30d windows |
| 🔗 **Deep links** | Every card links straight to the indicator's page on the original tool |
| 🔍 **Raw JSON viewer** | Per-card `{ RAW }` button opens a syntax-highlighted modal with copy & download |
| 🛠️ **Actionable errors** | Failed sources show the exact reason (invalid key, rate limit, timeout…) |
| 🌗 **Dark / Light mode** | Full theme support — syntax highlighter adapts automatically |

---

## 🔎 CTI Engine Coverage

| Engine | IP | Domain | URL | Hash | ASN | Threat Actor |
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

> No API key required for Tor Exit Nodes, MITRE ATT&CK, RIPEstat, or PhishTank — all four are free public datasets/APIs, always on, toggleable like any other source. MITRE ATT&CK caches its ~50 MB STIX dataset in memory for 24h (the first lookup after a cold start takes a few seconds). RIPEstat returns routing (ASN/prefix) and abuse-contact data from the RIPE NCC registry. PhishTank's `checkurl` API works anonymously — an optional `PHISHTANK_API_KEY` gets you higher request priority but isn't required.
> urlscan.io queries the public search index of scans already submitted by others (passive lookup) — it does not submit your indicator for an active scan, so nothing you look up becomes visible to third parties.
> MalwareBazaar shares its credential with ThreatFox and URLhaus (`ABUSECH_AUTH_KEY`) — same unified abuse.ch key, no new registration needed if you already have one configured.
> AlienVault OTX's Threat Actor support queries the [pulse search API](https://otx.alienvault.com/api/v1/search/pulses) (same `ALIENVAULT_API_KEY` as its other lookups) — it's a full-text search over community threat reports, not a curated actor database, so results can take up to ~20s and MITRE ATT&CK remains the more authoritative source for actor profiles.
> URLhaus shares its credential with ThreatFox (`ABUSECH_AUTH_KEY`) — both are abuse.ch platforms under the same unified auth key, but are independent, individually toggleable sources.

> **Roadmap:** Criminal IP · Any.run · OpenCTI

### MISP is multi-instance

Every other source above is one fixed integration. MISP is different: you can point IntelChecker at **any number of MISP servers** — your own instance, a partner's, an ISAC feed — and each one shows up as its own named source in Connected Sources, with its own connect/disconnect status and its own toggle. There's no MISP-specific frontend code to write per instance; the backend discovers them from `.env` at startup (see the `MISP_<N>_*` block in `backend/.env.example`) and reports their names to the UI, which renders each with a shared generic card. Add a fourth instance by adding four more env lines and restarting — no code changes.

Each instance searches by indicator value only (not MISP's `ip-src`/`ip-dst`/etc. attribute-type distinctions), so it works the same way across IP, domain, URL, and hash lookups regardless of how a given MISP community tags its attributes.

**Mutual TLS**: some MISP instances (common on government/CERT deployments) reject every request with a TLS-layer "certificate required" alert unless the client presents its own certificate — the API key alone isn't enough. If yours does this, drop the cert (and key, if it's a separate file) into `backend/certs/` (gitignored, mounted into the backend container at `/app/certs`) and point `MISP_<N>_CLIENT_CERT` / `MISP_<N>_CLIENT_KEY` at the filenames. A combined cert+key PEM only needs `CLIENT_CERT`.

---

## 🧮 Verdict Scoring & Weights

The Threat Score gauge is a weighted average of every engine's own 0–10 subscore. Weights live in `weights.json` (repo root) — a flat `{ "engineId": weight }` map, same optional-file pattern as the `logo/` folder: edit the numbers to retune the verdict, no code changes, no rebuild logic to touch. **Every** engine has an entry, including ones that don't affect the score — a weight of `0` is how you explicitly say "show this source, but don't let it move the needle" (that's the default for purely contextual sources like Shodan, IPinfo, RIPEstat and MITRE ATT&CK, none of which carry a maliciousness signal to score).

Each engine's own card shows its individual score too, using a badge deliberately styled to avoid two different kinds of ambiguity:

- **Solid, high-contrast pill** (green → red) — an actual 0–10 score. `0` is a real "checked and found clean" result (e.g. VirusTotal scanned it with dozens of engines and none flagged it) — that's a meaningfully different, stronger claim than "no data."
- **Soft pill, yellow** — `No results`: the engine has no record of this indicator at all (not the same as clean — absence of evidence isn't evidence of absence), or `No score`: the engine returned real data but has nothing to score (a Shodan host profile, an IPinfo geolocation).
- **Soft pill, red** — `Error`: the lookup itself failed (timeout, rate limit, bad credentials…).

Both the home page's Connected Sources list and the results page's per-engine cards sort by weight, highest first (ties keep their original order) — on the home page, sources matching the currently-selected indicator type float to the top of that ordering first. A small weight badge next to each result shows the exact number in play.

MISP is the one exception to `weights.json`: since instances are only known at deploy time (see above), their weight is set alongside their name — `MISP_<N>_WEIGHT` in `backend/.env`, defaulting to `0` if omitted — and merged into the same scoring pipeline at runtime. A MISP instance contributes its high-confidence score whenever it returns a matching attribute; no match is treated as "no results," same as everywhere else.

---

## 🕓 Query History & Search Frequency

Every completed lookup is logged to a small local database (`backend/data/history.db`, SQLite — gitignored, and mounted as a Docker volume so it survives container rebuilds) — one entry per indicator+type per visit to the results page, not per engine toggle. The **History** button in the header opens a chronological list (indicator, type, timestamp, score); opening an entry reconstructs the results page exactly as it looked at that moment — the score, the per-engine weight contributions, and every engine's raw response are all frozen at save time, so a later change to `weights.json` or a MISP instance's config won't rewrite history.

Each result also shows a **Search Frequency** card — how many times that exact indicator has been looked up in the last 24h, 72h, and 30d — color-scaled so a spike is obvious at a glance without reading the numbers:

| Level | 24h | 72h | 30d |
|---|:---:|:---:|:---:|
| ⬜ Grey — never seen | 0 | 0 | 0 |
| 🟩 Green — stale only | 0 | 0 | 1–3 |
| 🟨 Yellow | 1–2 | 1–4 | 4–8 |
| 🟧 Orange | 3–4 | 5–7 | 9–15 |
| 🟥 Red | 5+ | 8+ | 16+ |

Grey is reserved for genuinely zero activity everywhere, and green only shows up for stale hits — something seen in the last 30 days but nothing in the last 72h. The moment there's *any* hit within 72h (which includes any hit within 24h), the card is at least yellow — recent activity is never shown "cooler" than that, no matter how small the count. From that yellow floor, higher counts in the tighter windows escalate to orange/red, since a burst in the last 24h is far more significant than the same count spread across 30 days. The card's color is whichever window reads most severe.

---

## 🖥️ Screenshot

<img src="docs/screenshot.png" alt="IntelChecker results view" width="100%" />

---

## 🚀 Quick Start

Three steps: set your keys, drop in your logo (optional), run one command.

```bash
git clone <repo-url>
cd IntelChecker

cp backend/.env.example backend/.env
# Edit backend/.env and fill in your API keys

# Optional: replace logo/light.png and logo/dark.png (repo root) with your own —
# if you leave them out or delete them, the UI just renders without a logo, no
# broken image. The right one is shown automatically based on the active theme.

docker compose up --build -d
```

| Service | URL |
|---|---|
| App | http://localhost:8080 |

The frontend container serves the built SPA via nginx and reverse-proxies `/api/*` to the backend container — there's nothing else to configure, and no ports to expose beyond `8080`.

```bash
# Stop
docker compose down
```

> Re-run `docker compose up --build -d` any time you change `.env`, the logo, `weights.json`, or the code — it rebuilds only what changed.
> `logo/light.png` and `logo/dark.png` live at the repo root so they're the first thing a deployer sees — `frontend/public/logo` is just a symlink to that folder, kept for local (non-Docker) dev. Missing either file? The build doesn't fail and the UI silently renders without it, per theme.
> `weights.json` (repo root) sets each engine's contribution to the unified verdict score — edit the numbers to tune it, no code changes needed. Same symlink/optional-copy pattern as the logo folder: missing file just means no verdict score is computed.
> Query history needs no setup — `docker compose up` creates `backend/data/history.db` on first run and it persists across restarts/rebuilds via the volume mount in `docker-compose.yml`.

<details>
<summary>Development (without Docker)</summary>

**Backend**

```bash
python -m venv .venv
source .venv/bin/activate      # Linux / macOS
# .venv\Scripts\activate       # Windows

pip install -r backend/requirements.txt
cd backend && uvicorn app.main:app --reload
```

**Frontend**

```bash
cd frontend
npm install
npm run dev
```

| Service | URL |
|---|---|
| Frontend | http://localhost:5173 |
| Backend API | http://localhost:8000 |

The Vite dev server proxies `/api/*` to `http://localhost:8000` (see `frontend/vite.config.ts`); override the target with the `BACKEND_URL` env var if your backend runs elsewhere.

</details>

---

## 🔑 API Keys

All credentials live in `backend/.env`. This file is **gitignored and never committed**.

```
backend/.env          ← your real keys  (gitignored)
backend/.env.example  ← empty template  (committed)
```

| Variable | Service | Free tier |
|---|---|:---:|
| `ABUSEIPDB_API_KEY` | [AbuseIPDB](https://www.abuseipdb.com/api) | ✅ |
| `VIRUSTOTAL_API_KEY` | [VirusTotal](https://www.virustotal.com/gui/join-us) | ✅ |
| `ABUSECH_AUTH_KEY` | [ThreatFox, URLhaus & MalwareBazaar · abuse.ch](https://auth.abuse.ch/register) | ✅ |
| `ALIENVAULT_API_KEY` | [AlienVault OTX](https://otx.alienvault.com) | ✅ |
| `IPINFO_API_KEY` | [IPinfo](https://ipinfo.io/signup) | ✅ |
| `SHODAN_API_KEY` | [Shodan](https://account.shodan.io/register) | ✅ |
| `URLSCAN_API_KEY` | [urlscan.io](https://urlscan.io/user/signup) | ✅ |
| `PHISHTANK_API_KEY` *(optional)* | [PhishTank](https://phishtank.org/api_register.php) | ✅ |
| `RECORDED_FUTURE_API_KEY` | [Recorded Future](https://www.recordedfuture.com) — API token from your org's admin panel | ❌ (commercial) |
| `MISP_<N>_NAME` / `_URL` / `_KEY` / `_VERIFY_SSL` / `_WEIGHT` | [MISP](https://www.misp-project.org) — as many instances as you want, see below | n/a |

> Sources with an empty key render an error card in the UI; all other sources continue working normally.

---

## 🗂️ Project Structure

```
IntelChecker/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI entrypoint & routes
│   │   ├── core/
│   │   │   ├── config.py        # API key loader (.env)
│   │   │   ├── registry.py      # Engine capabilities (which types each supports)
│   │   │   └── db.py            # SQLite query-history store (save/list/get/frequency)
│   │   └── services/            # Async CTI client modules
│   │       ├── abuseipdb.py
│   │       ├── virustotal.py
│   │       ├── abusech.py
│   │       ├── alienvault.py
│   │       ├── ipinfo.py
│   │       ├── shodan.py
│   │       ├── torexitlist.py
│   │       ├── urlhaus.py
│   │       ├── mitreattack.py
│   │       ├── ripestat.py
│   │       ├── urlscan.py
│   │       ├── malwarebazaar.py
│   │       ├── phishtank.py
│   │       ├── recordedfuture.py
│   │       └── misp.py          # One class, N instances — see registry.py's MISP_INSTANCES loop
│   ├── .env                     # Your keys — gitignored
│   ├── .env.example             # Empty template
│   ├── certs/                    # MISP mTLS client certs — gitignored, mounted into the container
│   ├── data/                      # SQLite history.db lives here — gitignored, mounted into the container
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── public/
│   │   ├── logo/                 # Symlink → ../../logo/ (for local `npm run dev`)
│   │   └── weights.json          # Symlink → ../../weights.json (for local `npm run dev`)
│   ├── src/
│   │   ├── components/results/  # Per-engine cards, ScoreBadge, WeightBadge, SearchFrequencyCard, RawJsonModal, shared MISPCard
│   │   ├── pages/                # HomePage · ResultsPage · HistoryPage · HistoryDetailPage
│   │   ├── registry.tsx          # Static (build-time) engine registry
│   │   ├── verdictEngine.ts      # Per-engine + aggregate 0-10 scoring logic
│   │   ├── EnginesContext.tsx    # Merges static engines with backend-discovered MISP instances
│   │   └── summaryRegistry.ts    # Summary field extractors per engine+type
│   ├── Dockerfile               # Multi-stage build → nginx serving the SPA
│   └── nginx.conf                # Serves the SPA + proxies /api/* to the backend
├── logo/
│   ├── light.png                 # ← Replace with your org's logo, light theme (optional, PNG)
│   └── dark.png                  # ← Replace with your org's logo, dark theme (optional, PNG)
├── weights.json                  # ← Per-engine weights for the verdict score (optional)
├── docker-compose.yml
└── README.md
```

---

## 🏗️ Architecture

```
Analyst input
     │
     ▼
┌─────────────────────────────────────────┐
│  FastAPI  POST /analyze/{engine}        │
│  AnalyzeRequest { indicator, type }     │
└──────────────┬──────────────────────────┘
               │ dispatch(indicator, type)
       ┌───────┴──────────────────────┐
       │  Async parallel workers      │
       │  (one per engine)            │
       └──┬───┬───┬───┬───┬──────────┘
          │   │   │   │   │
         VT  AB  CH  OTX  IPi   ← external CTI APIs
          │   │   │   │   │
       ┌──┴───┴───┴───┴───┴──────────┐
       │  React frontend             │
       │  Per-engine cards           │
       │  Summary + Verdict gauge    │
       └──────────────┬──────────────┘
                       │ once every engine settles
                       ▼
       ┌─────────────────────────────┐
       │  POST /history               │
       │  → SQLite (backend/data/)    │
       │  score + per-engine snapshot │
       └─────────────────────────────┘
```

---

<div align="center">
<sub>Built for internal SOC and CTI operations · Not intended for public deployment</sub>
</div>
