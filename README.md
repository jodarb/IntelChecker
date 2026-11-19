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
3. *(Optional)* Drop your organization's logos at `logo/light.png` and `logo/dark.png` (repo root — one per theme, shown/hidden automatically as the analyst switches theme). Optional — the app works fine without them. Verdict weights are tuned from the **Admin** page once the stack is running (no files to edit).
4. *(Optional)* If `8080` and/or `8000` are already taken by something else on this host:
   ```bash
   cp .env.example .env
   ```
   and change `FRONTEND_PORT` / `BACKEND_PORT` in the new root `.env` — don't confuse it with `backend/.env` (API keys), it only controls ports and Docker Compose reads it directly, nothing else needs editing.
5. Build and start the stack:
   ```bash
   docker compose up --build -d
   ```
6. Open `http://<host>:<FRONTEND_PORT>` (`8080` unless you changed it in step 4).

That's the whole stack — one container for the backend, one for the frontend/nginx reverse proxy. `backend/data/` (query history) and `backend/certs/` (MISP mTLS client certs, if you need them) are Docker volumes, so they persist across restarts and rebuilds.

### Updating to a new version

When a new version is released:

```bash
docker compose down
git pull
docker compose up --build -d
```

Stop the running containers first, then pull, then rebuild and relaunch — this avoids updating source files out from under a container that's still running against them. `docker compose down` doesn't touch anything outside the containers themselves, so your `backend/.env`, `logo/`, and the `backend/data/` volume (`history.db` and the admin-edited `weights.json`) are all untouched by an update.

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
| 🎯 **Knowledge + Risk scores** | Two gauges (0 – 10): how much is known about the indicator, and how risky it is according to the sources that issued a verdict — plus a quadrant reading (Confirmed malicious · Isolated signal · Known benign · Known, low-level signals · Known, no verdict · Unknown) |
| 🗺️ **Verdict matrix** | *View matrix* plots Knowledge (X) × Risk (Y) and replays, step by step from (0, 0), how each source moved both scores — knowledge only ever climbs, risk can rise or fall |
| 🧮 **Weighted verdict** | Per-engine risk and knowledge weights, editable from the **Admin** page, with a full contribution breakdown for each score (*How is this calculated?*) |
| 🏷️ **Per-engine score badges** | Every card shows its own 0–10 score, keeping "checked & clean" visually distinct from "no signal" and from "error" |
| ⬆️ **Weight-sorted results** | Both the home page's source list and the results page sort engines by weight, highest first — every source always shows its R (risk) and K (knowledge) weight |
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
| [ANY.RUN](https://any.run) *(TI Lookup)* | ✅ | ✅ | ✅ | ✅ | | |
| [GreyNoise](https://greynoise.io) *(Community)* | ✅ | | | | | |
| [Hybrid Analysis](https://hybrid-analysis.com) *(Falcon Sandbox)* | ✅ | ✅ | ✅ | ✅ | | |
| [Google Safe Browsing](https://safebrowsing.google.com) | | | ✅ | | | |
| [TweetFeed](https://tweetfeed.live) | ✅ | ✅ | ✅ | ✅ | | |

> No API key required for Tor Exit Nodes, MITRE ATT&CK, RIPEstat, PhishTank, or TweetFeed — all five are free public datasets/APIs, always on, toggleable like any other source. MITRE ATT&CK caches its ~50 MB STIX dataset in memory for 24h (the first lookup after a cold start takes a few seconds). RIPEstat returns routing (ASN/prefix) and abuse-contact data from the RIPE NCC registry. PhishTank's `checkurl` API works anonymously — an optional `PHISHTANK_API_KEY` gets you higher request priority but isn't required.
> urlscan.io queries the public search index of scans already submitted by others (passive lookup) — it does not submit your indicator for an active scan, so nothing you look up becomes visible to third parties.
> MalwareBazaar shares its credential with ThreatFox and URLhaus (`ABUSECH_AUTH_KEY`) — same unified abuse.ch key, no new registration needed if you already have one configured.
> AlienVault OTX's Threat Actor support queries the [pulse search API](https://otx.alienvault.com/api/v1/search/pulses) (same `ALIENVAULT_API_KEY` as its other lookups) — it's a full-text search over community threat reports, not a curated actor database, so results can take up to ~20s and MITRE ATT&CK remains the more authoritative source for actor profiles.
> URLhaus shares its credential with ThreatFox (`ABUSECH_AUTH_KEY`) — both are abuse.ch platforms under the same unified auth key, but are independent, individually toggleable sources.
> ANY.RUN integrates via its **TI Lookup** API — a passive search over ANY.RUN's existing sandbox intelligence database (~180-day window). Like urlscan.io, it does not submit your indicator for a live detonation; it only returns what's already on record from prior analyses.
> GreyNoise's free **Community API** classifies an IP as an internet-wide scanner (noise) and/or a known-good business service (RIOT — search engines, CDNs, etc.); it's capped at 50 lookups/week per key.
> Hybrid Analysis integrates via `/search/terms` and `/search/hash` — also a passive search over existing Falcon Sandbox detonation reports, not a live submission.
> Google Safe Browsing only supports URL lookups (it's a real-time check against Google's threat lists, not a database of domains/IPs) — unlike most sources here, a clean result is a genuine active verdict, not just "no data".
> TweetFeed needs no API key — it's a free (CC0) feed of IOCs shared by the infosec community on X/Twitter, queried via its exact-match lookup over the last 365 days. Reports are unvetted (a legitimate service hosting abused content can show up), so its risk subscore is capped at 7 and it never issues a clean verdict: not being reported is just "no data". For reported IPs/domains it also feeds GeoIP/ASN/ISP into the summary.

> **Roadmap:** Criminal IP · OpenCTI

### MISP is multi-instance

Every other source above is one fixed integration. MISP is different: you can point IntelChecker at **any number of MISP servers** — your own instance, a partner's, an ISAC feed — and each one shows up as its own named source in Connected Sources, with its own connect/disconnect status and its own toggle. There's no MISP-specific frontend code to write per instance; the backend discovers them from `.env` at startup (see the `MISP_<N>_*` block in `backend/.env.example`) and reports their names to the UI, which renders each with a shared generic card. Add a fourth instance by adding four more env lines and restarting — no code changes.

Each instance searches by indicator value only (not MISP's `ip-src`/`ip-dst`/etc. attribute-type distinctions), so it works the same way across IP, domain, URL, and hash lookups regardless of how a given MISP community tags its attributes.

**Mutual TLS**: some MISP instances (common on government/CERT deployments) reject every request with a TLS-layer "certificate required" alert unless the client presents its own certificate — the API key alone isn't enough. If yours does this, drop the cert (and key, if it's a separate file) into `backend/certs/` (gitignored, mounted into the backend container at `/app/certs`) and point `MISP_<N>_CLIENT_CERT` / `MISP_<N>_CLIENT_KEY` at the filenames. A combined cert+key PEM only needs `CLIENT_CERT`.

---

## 🧮 Verdict Scoring & Weights

Every lookup produces **two independent scores** and a reading of both together.

### Knowledge Score (0–10) — how much is known about the indicator
Good or bad doesn't matter here — it measures how much of the available intel coverage has information on the indicator. Every **configured and enabled** source that supports the indicator type counts in the total; sources without an API key or disabled by the analyst are left out.

Knowledge **only grows**: each source *adds* its share, and a source with no record — or one that failed to answer (timeout, rate limit…) — simply adds nothing. No single source can reach 10 on its own; 10 means every source has a rich record. A failing source does lower the ceiling of what's knowable for that lookup, which is the honest reading: with a source down, we know less.

Each source rates its own **depth of record**: `None` (0, no record), `Basic` (0.5, a generic profile, a single pulse/scan) or `Rich` (1, multiple reports, samples, verdicts, vulns…). Sources that answer for almost anything (IPinfo, RIPEstat) or only say yes/no (Tor exit list, Safe Browsing) carry low knowledge weights, so they can't inflate the score on their own.

```
knowledge = round(10 × Σ(knowledge_weight × depth) / Σ(knowledge_weight of every configured, enabled source for that type))
```

### Risk Score (0–10) — how risky it is, according to sources that issued a verdict
Weighted average of the 0–10 maliciousness subscores, using **only** sources that returned an actual verdict: a risk signal, or an explicit clean evaluation (e.g. a VirusTotal file scan with 0/70 detections, a GreyNoise RIOT match, an AbuseIPDB whitelist). Having no record — or having only context, like Shodan ports or IPinfo geolocation — is **not** a benign verdict, so those sources stay out. If nothing issued a verdict, the Risk Score shows **No data**, never a clean `0`.

```
risk = round(Σ(risk_weight × subscore) / Σ(risk_weight))
```

### Quadrant
| | Risk < threshold | Risk ≥ threshold |
|---|---|---|
| **Knowledge ≥ threshold** | Known · Benign · Known · Low-level signals · Known · No risk verdict *(see below)* | Malicious · Confirmed |
| **Knowledge < threshold** | Unknown | Isolated signal · Verify |

In the "known, low risk" cell, the label depends on *why* the risk is low — a low average alone is never called benign:
- **Known · Benign** — at least one source explicitly evaluated it as clean, and no single source raised a signal at or above the risk threshold.
- **Known · Low-level signals** — the average is below the threshold, but it's made of risk signals (or a strong signal was diluted by others). Not a benign confirmation.
- **Known · No risk verdict** — sources have context on it, but none issued a risk verdict at all.

Default thresholds: knowledge ≥ 4, risk ≥ 5.

### Verdict matrix
The **View matrix** button in the summary opens a Knowledge (X) × Risk (Y) chart with the quadrant regions and threshold lines. Starting from (0, 0), it adds one source at a time — in the same order as the result cards — and draws the staircase of how each one moved the two scores: knowledge only climbs (a source with no record or an error adds nothing), while risk is the running weighted average and can go up or down. The side list shows each step's Δ; hovering a step highlights it on the chart. It is rebuilt from the saved contributions, so it works the same for archived history entries.

Every weight and threshold is explained in detail in [docs/admin.md](docs/admin.md).

### Weights & the Admin page
Each engine has a **risk weight** and a **knowledge weight** (plus optional per-indicator-type knowledge overrides — e.g. RIPEstat counts 1 for IPs but 6 for ASNs). Both are always visible: as `R`/`K` chips on the home page's source list and on every result card (the `K` chip also shows that source's depth for the current result). The **Admin** page (header → Admin) edits every weight — MISP instances included — and the quadrant thresholds; changes are saved to `backend/data/weights.json` and apply to the next lookup. *Reset to defaults* restores the built-in values. The Admin page has no authentication, consistent with the rest of the app being an internal tool.

`MISP_<N>_WEIGHT` / `MISP_<N>_KNOWLEDGE_WEIGHT` in `backend/.env` only set an instance's *initial* weights (defaults `0` / `9`); a value saved in Admin takes precedence.

Each engine's card also shows its own risk subscore, using a badge deliberately styled to avoid ambiguity:

- **Solid, high-contrast pill** (green → red) — an actual 0–10 risk verdict. `0` is an explicit "evaluated and found clean" result — a stronger claim than "no data".
- **Soft pill, yellow** — `No results`: the engine has no record of this indicator (absence of evidence isn't evidence of absence), or `No score`: real data, but nothing to score (a Shodan host profile, an IPinfo geolocation).
- **Soft pill, red** — `Error`: the lookup itself failed (timeout, rate limit, bad credentials…). "Not found" is never shown as an error.

Both the home page's Connected Sources list and the results page sort engines by risk weight, then knowledge weight (ties keep their original order).

---

## 🕓 Query History & Search Frequency

Every completed lookup is logged to a small local database (`backend/data/history.db`, SQLite — gitignored, and mounted as a Docker volume so it survives container rebuilds) — one entry per indicator+type per visit to the results page, not per engine toggle. The **History** button in the header opens a chronological list (indicator, type, timestamp, quadrant, Knowledge / Risk scores), optionally filtered to one indicator via `?indicator=` (that's what the Search Frequency card's **View all** link uses — an unlimited, all-time count, not just the 24h/72h/30d windows). Opening an entry reconstructs the results page exactly as it looked at that moment — both scores, the quadrant, the per-engine weight contributions (so the matrix view replays too), and every engine's raw response are all frozen at save time, so a later change to the weights or a MISP instance's config won't rewrite history. Entries saved before the two-score model only have a Risk Score; their Knowledge Score shows as `—`.

Each result also shows a **Search Frequency** card — how many *other* times that exact indicator has been looked up in the last 24h, 72h, and 30d — color-scaled so a spike is obvious at a glance without reading the numbers, with a **View all** link that jumps to the History page pre-filtered to that indicator (see below):

| Level | 24h | 72h | 30d |
|---|:---:|:---:|:---:|
| ⬜ Grey — no other activity | 0 | 0 | 0 |
| 🟩 Green — stale only | — | — | 1–3 |
| 🟨 Yellow | 1 | 1–4 | 4–8 |
| 🟧 Orange | 2–4 | 5–7 | 9–15 |
| 🟥 Red | 5+ | 8+ | 16+ |

The lookup currently on screen never counts itself — on a live results page it hasn't been saved yet at the moment this card fetches its numbers, so the raw count from the backend already excludes it; when reopening an *already-saved* entry from History, that entry is subtracted back out for the same reason, so both views mean the same thing: "how many other times has this been searched." Grey means genuinely no other activity at all. Green only shows up for stale hits — nothing in the last 72h besides older activity within 30 days. The moment there's any hit within 72h (which includes any hit within 24h), it's at least yellow — recent activity is never shown "cooler" than that, no matter how small the count. From that yellow floor, higher counts in the tighter windows escalate to orange/red, since a burst in the last 24h is far more significant than the same count spread across 30 days. The card's color is whichever window reads most severe.

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

# Optional: 8080 or 8000 already taken by something else? cp .env.example .env
# and change FRONTEND_PORT / BACKEND_PORT there — nothing else to edit.

docker compose up --build -d
```

| Service | URL |
|---|---|
| App | http://localhost:8080 *(or your `FRONTEND_PORT`)* |

The frontend container serves the built SPA via nginx and reverse-proxies `/api/*` to the backend container, so `FRONTEND_PORT` alone is enough for normal use. `BACKEND_PORT` (also in the root `.env`, `8000` by default) additionally exposes the API directly on the host — handy for debugging or hitting it from another tool, not required otherwise.

```bash
# Stop
docker compose down
```

> Re-run `docker compose up --build -d` any time you change `.env`, the logo, or the code — it rebuilds only what changed.
> `logo/light.png` and `logo/dark.png` live at the repo root so they're the first thing a deployer sees — `frontend/public/logo` is just a symlink to that folder, kept for local (non-Docker) dev. Missing either file? The build doesn't fail and the UI silently renders without it, per theme.
> Verdict weights are edited from the **Admin** page and saved to `backend/data/weights.json` (same volume as the history DB) — no rebuild needed, changes apply to the next lookup.
> Query history needs no setup — `docker compose up` creates `backend/data/history.db` on first run and it persists across restarts/rebuilds via the volume mount in `docker-compose.yml`.
> `.env` (repo root) sets `FRONTEND_PORT` / `BACKEND_PORT` — Docker Compose loads it automatically for variable substitution in `docker-compose.yml`. It's a different file from `backend/.env` (API keys) and doesn't get passed into any container. No file present? Compose falls back to `8080` / `8000`.

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
| `ANYRUN_API_KEY` | [ANY.RUN](https://any.run) — TI Lookup, from your account's API tab | ❌ (commercial) |
| `GREYNOISE_API_KEY` | [GreyNoise](https://viz.greynoise.io/account/) — Community API | ✅ (50/week) |
| `HYBRID_ANALYSIS_API_KEY` | [Hybrid Analysis](https://hybrid-analysis.com/my-account?tab=%23api-key-tab) | ✅ |
| `GOOGLE_SAFE_BROWSING_API_KEY` | [Google Safe Browsing](https://developers.google.com/safe-browsing/v4/get-started) — Google Cloud API key with the Safe Browsing API enabled | ✅ |
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
│   │   │   ├── weights.py       # Default verdict weights/thresholds + Admin persistence (data/weights.json)
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
│   │       ├── anyrun.py
│   │       ├── greynoise.py
│   │       ├── hybridanalysis.py
│   │       ├── safebrowsing.py
│   │       ├── tweetfeed.py
│   │       └── misp.py          # One class, N instances — see registry.py's MISP_INSTANCES loop
│   ├── .env                     # Your keys — gitignored
│   ├── .env.example             # Empty template
│   ├── certs/                    # MISP mTLS client certs — gitignored, mounted into the container
│   ├── data/                      # SQLite history.db lives here — gitignored, mounted into the container
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── public/
│   │   ├── app-logo.png          # IntelChecker logo (header) · favicon.png · apple-touch-icon.png
│   │   └── logo/                 # Symlink → ../../logo/ (for local `npm run dev`)
│   ├── src/
│   │   ├── components/results/  # Per-engine cards, ScoreBadge, WeightBadge, SearchFrequencyCard, RawJsonModal, VerdictExplainerModal, MatrixModal, shared MISPCard
│   │   ├── pages/                # HomePage · ResultsPage · HistoryPage · HistoryDetailPage · AdminPage
│   │   ├── registry.tsx          # Static (build-time) engine registry
│   │   ├── verdictEngine.ts      # Per-engine subscores + depth, Knowledge/Risk scores, quadrant
│   │   ├── trajectory.ts         # Step-by-step replay of the verdict for the matrix view
│   │   ├── quadrants.ts          # Quadrant / outcome labels and styles
│   │   ├── EnginesContext.tsx    # Merges static engines with backend-discovered MISP instances
│   │   └── summaryRegistry.ts    # Summary field extractors per engine+type
│   ├── Dockerfile               # Multi-stage build → nginx serving the SPA
│   └── nginx.conf                # Serves the SPA + proxies /api/* to the backend
├── docs/
│   ├── admin.md                  # Admin page guide: every weight/threshold and its effect
│   └── logo.png
├── logo/
│   ├── light.png                 # ← Replace with your org's logo, light theme (optional, PNG)
│   └── dark.png                  # ← Replace with your org's logo, dark theme (optional, PNG)
├── .env                          # ← FRONTEND_PORT / BACKEND_PORT — gitignored, default 8080 / 8000
├── .env.example                  # Template for the above
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
       │  Knowledge + Risk · matrix  │
       └──────────────┬──────────────┘
                       │ once every engine settles
                       ▼
       ┌─────────────────────────────┐
       │  POST /history               │
       │  → SQLite (backend/data/)    │
       │  scores + engine snapshot    │
       └─────────────────────────────┘
```

---

<div align="center">
<sub>Built for internal SOC and CTI operations · Not intended for public deployment</sub>
</div>
