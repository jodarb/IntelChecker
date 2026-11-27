# Claude.md - INTELCHECKER

## 1. Project Overview
**INTELCHECKER** is an internal web application designed for the rapid triage and classification of Indicators of Compromise (IoCs) and Cyber Threat Intelligence (CTI) data. Analysts can input an indicator, select its type (or let the system automatically detect it), and receive a unified verdict alongside detailed technical context streamed in parallel from multiple external CTI sources.

### Key Features
* **Decoupled & Internal Architecture:** SPA design deployed within a local network/VPN environment.
* **Authentication & roles:** every page and API call requires a session. Three roles: `admin` (everything + edit weights + manage users), `analyst` (run lookups + read history), `reader` (read history only). See §7.
* **Asynchronous Processing:** Multi-threaded/asynchronous API requests that prevent thread blocking and resource starvation.
* **Real-Time Data Streaming:** Dynamic frontend components that render individual API responses immediately as they are streamed from the backend.
* **Near-stateless Operation:** Lookups are always executed in real time (no result caching). The only persisted state lives in `backend/data/` (Docker volume): `history.db` (SQLite query history with frozen snapshots of every lookup, plus who ran it), `users.db` (users, roles, sessions), `weights.json` (verdict weights/thresholds edited from the Admin page), `connectors.json` (API keys + MISP / OpenCTI instances edited from the Connectors page) and `feeds/` (last good download of the ransomware.live lists and the Tor exit list, `CachedFeed(persist=…)`, so a restart doesn't wait out its download limit).

---

## 2. Tech Stack

### Backend
* **Language/Framework:** Python 3.11+ using **FastAPI**.
* **Concurrency:** `asyncio` and `httpx` for non-blocking, asynchronous HTTP client requests.
* **Data Transmission:** One `POST /analyze/{engine}` request per source, fired in parallel by the frontend, so each card renders as soon as its own response arrives (per-source streaming without SSE/WebSockets).

### Frontend
* **Framework:** Component-driven modern SPA built with **React 19** and **TypeScript**, bundled via **Vite**.
* **Styling:** **Tailwind CSS v4** (`@tailwindcss/vite`, no `tailwind.config.js`) configured with a clean, high-contrast dark theme optimized for SOC and Threat Intel operations.
* **UI Components:** **shadcn/ui** as the component library, providing accessible and composable primitives that integrate natively with Tailwind.
* **i18n (EN / ES):** every user-facing string goes through `useI18n()` (`frontend/src/i18n/`): `t('key')` / `tn('key', n)` for plurals, with inline markup (`**bold**`, `` `code` ``, `[link](/route)`) rendered by `rich()`. Dictionaries live in `i18n/messages/<area>.ts`, each exporting `{ en, es }` with `es` typed against `en`, so a missing translation is a compile error. The Docs page content is in `i18n/docs/{en,es}.ts`. Source data (raw JSON, tags, report titles) is never translated; backend error messages are translated by error code (`i18n/errors.ts`). The language selector lives in the header and is stored per browser (`localStorage`), defaulting to the browser language.
* **Branding:** Detective logo at `frontend/public/app-logo.png` (also `favicon.png`, `apple-touch-icon.png`, `docs/logo.png`). Header wordmark uses **Bebas Neue**, bundled locally via `@fontsource/bebas-neue` (no external font requests — the app must work on networks without internet); colors are the `.brand-*` classes in `index.css`.

### Infrastructure
* **Containerisation:** The entire application is orchestrated via **Docker Compose**. Each service (backend, frontend) runs in its own container. The single entry point to spin up the full stack is `docker compose up`.

---

## 3. Architecture & Data Flow

1.  **User Input:** The analyst inputs an indicator via the UI and either explicitly selects its type (IP, URL, Domain, File Hash, ASN, Threat Actor, Vulnerability/CVE, Company) or chooses the **"Free Text"** option.
2.  **Ingestion & Validation (Backend):**
    * Typed inputs are routed directly to their respective API endpoint managers.
    * "Free Text" inputs trigger an internal parser/regex evaluation pipeline to dynamically classify the IoC type before routing.
3.  **Query Orchestration:** The backend initializes concurrent asynchronous workers to query the relevant endpoints of all configured threat intelligence providers simultaneously.
4.  **Response Streaming:** As soon as an individual API worker receives a payload, the backend serializes the JSON data and streams it to the frontend via the open connection. The frontend intercepts the specific event and updates the corresponding data card dynamically without affecting the rest of the view.
5.  **Error Handling:** If an individual API worker fails (timeout, HTTP error, missing credentials, rate limit, etc.), the backend must stream an error event for that specific source. The frontend renders the corresponding card in an error state, displaying the human-readable reason for the failure. Other cards are not affected. The error message must be actionable — it should indicate *why* it failed (e.g., "Invalid API key", "Rate limit exceeded", "Service unavailable") rather than a generic error.

---

## 4. Threat Intel Integrations (CTI Sources)
The backend manages API authentication using server-side credentials managed by admins on the **Connectors** page (`backend/app/core/connectors.py` → `backend/data/connectors.json`, mode 0600, in clear; `backend/.env` is a fallback — a key saved on Connectors wins). Services must read keys at call time with `connectors.secret("<ENV_NAME>")`, never as module constants, and a new key needs an entry in `CONNECTORS`. MISP and OpenCTI instances also live there, in one store keyed by kind (`connectors.instances(kind)`, `INSTANCE_KINDS`; `MISP_<N>_*` / `OPENCTI_<N>_*` in `.env` only until the first change of that kind from the UI), so the engine list is dynamic: use `registry.engines()` / `registry.is_connected()`, not a static dict. Instance engines are `misp_<N>` / `opencti_<N>` (prefix-matched in both verdict engines and `intelAggregates.ts`; `kind` in `/engines/status` picks the card). OpenCTI GraphQL documents live in `services/opencti_queries.py` (full + compat variants); validate them with `backend/tests/opencti_schema_check.py`. Engine capabilities (supported indicator types, required key) are declared in `backend/app/core/registry.py`; each source is a module in `backend/app/services/` and a card in `frontend/src/components/results/`, wired through `frontend/src/registry.tsx`, `summaryRegistry.ts` and `intelAggregates.ts` (tags, actors, first/last seen for the Summary). A source without its API key is reported as `MissingApiKey` and excluded from both scores.

Implemented sources: VirusTotal, AlienVault OTX, AbuseIPDB, abuse.ch (ThreatFox), URLhaus, MalwareBazaar, Shodan, IPinfo, RIPEstat, Tor Exit List, MITRE ATT&CK, URLScan, PhishTank, Recorded Future, Any.run, GreyNoise, Hybrid Analysis, Google Safe Browsing, TweetFeed, CrowdSec CTI, CIRCL hashlookup, RDAP, Tranco, Malpedia, Spamhaus, OpenPhish, YARAify, SSLBL, CIRCL Passive DNS, Kaspersky OpenTIP, NVD, CISA KEV, VulnCheck KEV, EPSS (the `cve` sources with OTX and OpenCTI; CVE ids normalised by `backend/app/core/cve.py`), Wikidata, GLEIF, ransomware.live, Hudson Rock, Have I Been Pwned, GDELT, plus Recorded Future (the `company` sources: indicator `Name (domain, Q-id, LEI)` parsed by `backend/app/core/company.py`, searched from its own tab (`/companies` → `CompanySearchPage`, report `/companies/report` → `components/company/CompanyReport.tsx`, also used by `HistoryDetailPage`; tabs under the header via `Layout tab=…`; live lookups shared through `hooks/useLookup.ts`), entity picked from `GET /company/resolve`; domain-only sources return `NeedsDomain`, left out of Knowledge via `NOT_APPLICABLE_ERROR_CODES`), and N MISP and N OpenCTI instances (`MISP_<N>_*` env vars). The README's coverage table is the source of truth for which types each one supports.

---

## 5. Verdict Engine
Implemented in `frontend/src/verdictEngine.ts` (`computeVerdict`) and mirrored line by line in `backend/app/core/verdict.py` (used by `POST /lookup`). **Any change to the logic must be made in both**, and `backend/tests/verdict_parity.py` (random fuzz comparing both engines; needs Node ≥ 23) must report 0 mismatches. Engine order/labels in `backend/app/core/registry.py` must match `frontend/src/registry.tsx`. It produces **two independent scores** plus a quadrant. Full user-facing explanation: `docs/user-guide.md`, `docs/admin.md` and the in-app Docs page (`/docs`, text in `frontend/src/i18n/docs/{en,es}.ts`) — keep all of them (both languages) in sync with any change to the logic.

* **Per-engine assessment:** each engine's result is normalized to an outcome — `hit` / `clean` / `context` / `no_data` / `excluded` — with a risk **subscore** (0–10, only for hit/clean) and a **depth of record** (0 / 0.5 / 1). "Not found" is `no_data`, never `clean`: absence of data is not a benign confirmation.
* **Knowledge (0–10):** `coverage = Σ(kw × depth) / Σ(kw of every counted source for the type)`, `knowledge = round(10 × min(1, coverage ÷ full_at))` with `full_at` = `scoring.knowledge_full_at` % (Admin, default 70, 10–100; 100 = no saturation). Sources still loading or with a persistent error (bad key…) count in the denominator with depth 0; sources that failed for a **transient** reason (`TRANSIENT_ERROR_CODES`: rate limit, timeout, network, HTTP/5xx, or the frontend couldn't reach the backend) are left out (`inTotal: false` in the contribution), and so are sources that can't evaluate the input (`NOT_APPLICABLE_ERROR_CODES`: `NeedsDomain`). Contributions store `knowledgeFullAt` so the matrix replays history with the value in force then (missing = 100).
* **Risk (0–10):** `round(Σ(rw × subscore) / Σ(rw))` over hit/clean sources only; `null` ("No data") if no source issued a verdict.
* **Quadrants** (`frontend/src/quadrants.ts`; CVE lookups use their own wording, `quadrant.cve.*`, via `quadrantLabel(q, t, type)`): confirmed_malicious, isolated_signal, known_benign (requires ≥1 explicit clean verdict and no single source ≥ risk threshold), known_low_signals, known_no_verdict, unknown. Default thresholds: knowledge 4, risk 5.
* **Weights:** defaults in `backend/app/core/weights.py`, editable from the Admin page (`GET/PUT /weights`, `POST /weights/reset`), persisted to `backend/data/weights.json`. Supports per-type knowledge overrides. MISP initial weights come from `MISP_<N>_WEIGHT` / `MISP_<N>_KNOWLEDGE_WEIGHT`.
* **Matrix view:** `frontend/src/trajectory.ts` replays the verdict source by source from (0, 0) for `MatrixModal.tsx`, using only the saved contributions so it works for history entries too.
* **Threat actors:** no Risk/quadrant shown. `components/actor/ActorReport.tsx` (live in `ResultsPage`, history in `HistoryDetailPage`) renders a Summary (name, alias tags + per-source alias table, the description of the highest Knowledge-weight source (others behind a button), an Activity + Knowledge box on the right, field: value rows — type, MITRE code, country, sites (leak sites, one per address with its sources), active since, lineage, victims (+ full victims table from ransomware.live `victims`), identified by — each value with its sources, most targeted sectors / countries, and TTPs / Arsenal / CVEs / IOCs / Reports buttons opening filterable tables exported to CSV / JSON) above the per-source cards, from `frontend/src/actorProfile.ts` (`types` normalises each source's wording; `descriptions` merges identical texts), which first identifies the actor each source matched (`identify`, grouped by shared names: status confirmed / single / persona / conflict / none; only the main group feeds the report; suggestions from `/actor/resolve`), and **Activity** from `frontend/src/actorActivity.ts` (active ≤ 90 d / recent ≤ 365 d / dormant; ransomware.live victims, OpenCTI last_seen + reports, OTX pulses filtered by `relevantPulses`, RF Threat Map log). Display only, not part of the verdict (no parity needed); history replays activity from the entry timestamp. OpenCTI actors use `ACTOR_CONTEXT` (300 relationships).
* **Companies are not scored**: `computeVerdict` / `compute_verdict` return an empty verdict for `company` (no Risk, Knowledge or quadrant); `POST /history` and `POST /lookup` store / return nulls; Admin hides company-only sources. Per-source assessments still order the company report's cards.
* History entries store `score`, `knowledge_score`, `quadrant` and contributions at save time; they are never recomputed.

---

## 6. Development Instructions for the AI Assistant

### Directory Structure
```text
intelchecker/
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI app: /auth/*, /users (+tokens), /connectors (keys, misp, opencti), /lookup, /analyze/{engine}, /company/resolve, /actor/resolve, /engines/status, /history, /weights, /mitre/aliases
│   │   ├── core/
│   │   │   ├── config.py      # Environment variables (.env), MISP instances from .env
│   │   │   ├── connectors.py  # API keys + MISP instances store (Connectors page, admin)
│   │   │   ├── registry.py    # Engine capabilities (types supported, required key)
│   │   │   ├── weights.py     # Default verdict weights/thresholds + persistence
│   │   │   ├── auth.py        # Users, roles, sessions, API tokens, FastAPI permission dependencies
│   │   │   ├── verdict.py     # Python mirror of verdictEngine.ts (POST /lookup)
│   │   │   ├── domains.py     # Hostname → registered domain (bundled Public Suffix List, offline)
│   │   │   ├── feeds.py       # Downloaded lists cached in memory (SSLBL, OpenPhish, ASN-DROP, CISA KEV, ransomware.live)
│   │   │   ├── cve.py         # CVE identifier normalisation (NVD, CISA KEV, EPSS)
│   │   │   ├── company.py     # Company indicator format, name matching, Wikidata helpers, /company/resolve
│   │   │   ├── actor.py       # Threat actor candidates (fuzzy over MITRE + ransomware.live, Malpedia + RF search), /actor/resolve
│   │   │   └── db.py          # SQLite query history
│   │   └── services/          # One async httpx client module per CTI source
│   ├── data/                  # history.db, users.db, weights.json, connectors.json (Docker volume, gitignored)
│   ├── Dockerfile
│   ├── .env.example
│   └── requirements.txt
├── frontend/
│   ├── public/                # app-logo.png, favicons, logos/ (source logos)
│   ├── src/
│   │   ├── components/        # Layout, EngineStatusPanel, results/ (per-source cards, Summary, modals)
│   │   ├── auth/              # AuthProvider, AuthGate, useAuth (role/permission checks)
│   │   ├── lib/api.ts         # apiFetch/apiJson: every backend call (detects expired sessions)
│   │   ├── pages/             # Home + Results (artifacts), CompanySearch + CompanyReport (companies), History, HistoryDetail, Admin (weights), Users + Connectors (admin only), Account, Login, Docs
│   │   ├── hooks/             # useEngines (engines context), useVerdictWeights, useEngineToggles, useTheme, useFetchJson, useMitreAliases, useLookup
│   │   ├── i18n/              # EN/ES: provider, useI18n, rich(), messages/<area>.ts, docs/{en,es}.ts
│   │   ├── verdictEngine.ts   # Two-score verdict
│   │   ├── trajectory.ts      # Matrix view replay
│   │   ├── quadrants.ts       # Quadrant/outcome labels
│   │   ├── registry.tsx       # Frontend engine registry
│   │   ├── intelAggregates.ts # Summary aggregates (tags/families, actors, first/last seen, flagged-by)
│   │   └── summaryRegistry.ts # Summary field extractors
│   ├── Dockerfile             # Build → nginx (proxies /api to backend)
│   └── package.json
├── docs/                      # user-guide.md, admin.md, api.md, sources.md, development.md, logo.png, screenshot.png
├── docker-compose.yml
└── .env.example               # FRONTEND_PORT / BACKEND_PORT
```

---

## 7. Authentication & Roles
* **Backend** (`backend/app/core/auth.py`): users + sessions in `backend/data/users.db`, scrypt password hashes (stdlib), opaque session token in an HttpOnly `SameSite=Strict` cookie (`intelchecker_session`), only its SHA-256 stored. Server-side sessions, so disabling a user or resetting a password revokes them at once.
* **Permissions:** `PERMISSIONS` maps role → `history:read` / `analyze` / `admin`. Endpoints declare them via `auth.require(...)` in `main.py`: `/analyze/*`, `/company/resolve`, `/actor/resolve` and `POST /history` need `analyze`; `GET /history*` needs `history:read`; `PUT /weights`, `POST /weights/reset`, `/users*` and `/connectors*` need `admin` (the `…/reveal` endpoints that return a stored key additionally require a browser session, never an API token, and log every reveal); `/engines/status`, `GET /weights`, `/mitre/aliases` need any signed-in user. **Every new endpoint must declare one.**
* **Bootstrap:** on first start with no users, an admin is created from `ADMIN_USERNAME` / `ADMIN_PASSWORD`, defaulting to `admin` / `admin` (not forced to change; `/auth/me` returns `default_password: true` and the header shows a warning until it is changed). Admin-set passwords are temporary (`must_change_password`): `current_user` rejects them with `PasswordChangeRequired` until `/auth/password` is called.
* **Safeguards:** at least one active admin always remains; admins can't change their own role, disable or delete themselves. Login is throttled per username (5 failures / 15 min).
* **API tokens:** `api_tokens` table in `users.db`, created/revoked by admins (`/users/{id}/tokens`), sent as `Authorization: Bearer ick_…`, stored as SHA-256. `session_user` accepts a token or the cookie (`user["auth"]` = `token`/`session`); a token acts as its user with the current role, ignores `must_change_password`, and can't change the password (`browser_session_user`). `POST /lookup` (analyze) runs every source + the Python verdict and saves to history with `via='api'`. Usage doc: `docs/api.md`.
* **Frontend:** `AuthGate` (in `main.tsx`) shows Login / forced password change before anything else mounts; routes are wrapped with `<Allowed permission=…>` in `App.tsx`; use `useAuth().can(...)` to hide actions. All backend calls go through `lib/api.ts` (`apiFetch`/`apiJson`) so a 401 signs the UI out. Auth error codes are translated via `authError.<code>` keys (`i18n/messages/auth.ts`).

