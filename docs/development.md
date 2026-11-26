# Development

Running IntelChecker without Docker, where configuration lives, and how the code is organised.

---

## Running without Docker

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

## Configuration files

| File | Purpose |
|---|---|
| `backend/.env` | Initial admin / session settings, plus fallback API keys and MISP / OpenCTI instances (the Connectors page wins). Gitignored; template in `backend/.env.example`. Rebuild after changes. |
| `backend/data/connectors.json` | API keys and MISP / OpenCTI instances saved from the Connectors page (`app/core/connectors.py`), mode 0600. Re-read when it changes; no restart needed. |
| `.env` (repo root) | `FRONTEND_PORT` / `BACKEND_PORT` for Docker Compose (defaults `8080` / `8000`). Not passed into any container. Template in `.env.example`. |
| `backend/data/weights.json` | Verdict weights, thresholds and Knowledge saturation, written by the Admin page. No rebuild needed. |
| `backend/data/history.db` | SQLite query history, created on first run. |
| `backend/data/users.db` | Users, roles and sessions (see [admin.md § 0](admin.md#0-users-and-roles)). Created on first run with the initial admin. |
| `backend/certs/` | MISP / OpenCTI mutual-TLS client certificates (see [sources.md](sources.md#misp-any-number-of-instances)). |

`backend/data/` and `backend/certs/` are Docker volumes, so they survive restarts, rebuilds and updates.

In Docker, the frontend container serves the built SPA through nginx and proxies `/api/*` to the backend, so `FRONTEND_PORT` is enough for normal use. `BACKEND_PORT` also exposes the API directly on the host, which is handy for debugging. nginx serves `index.html` with `no-cache` and the hashed `/assets/*` as immutable, so a redeploy is picked up on the next reload.

## Project structure

```
IntelChecker/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI: /auth/*, /users, /connectors (keys, misp, opencti), /lookup,
│   │   │                        #          /analyze/{engine}, /engines/status, /history, /weights, /mitre/aliases
│   │   ├── core/
│   │   │   ├── auth.py          # Users, roles, sessions, API tokens, permission dependencies
│   │   │   ├── config.py        # .env loader; MISP_<N>_* / OPENCTI_<N>_* instances from .env
│   │   │   ├── connectors.py    # API keys + MISP / OpenCTI instances store (Connectors page)
│   │   │   ├── registry.py      # Engine capabilities (types supported, required key), dynamic instances
│   │   │   ├── verdict.py       # Python mirror of verdictEngine.ts (POST /lookup)
│   │   │   ├── weights.py       # Default weights/thresholds/saturation + Admin persistence
│   │   │   ├── feeds.py         # Downloaded lists cached in memory (SSLBL, OpenPhish, ASN-DROP, CISA KEV)
│   │   │   ├── domains.py       # Hostname → registered domain (bundled Public Suffix List)
│   │   │   ├── cve.py           # CVE id normalisation
│   │   │   └── db.py            # SQLite query history
│   │   └── services/            # One async httpx client per CTI source; misp.py and opencti.py
│   │                            # serve N instances; opencti_queries.py holds the GraphQL documents
│   ├── tests/
│   │   ├── verdict_parity.py    # TypeScript ↔ Python verdict fuzz (Node ≥ 23)
│   │   └── opencti_schema_check.py  # Validates the OpenCTI queries against any release's schema
│   ├── certs/                   # mTLS client certs — gitignored, mounted
│   ├── data/                    # history.db, users.db, weights.json, connectors.json — gitignored, mounted
│   ├── Dockerfile
│   ├── .env.example
│   └── requirements.txt
├── frontend/
│   ├── public/                  # app-logo.png, favicons, logos/ (source logos)
│   ├── src/
│   │   ├── auth/                # AuthProvider, AuthGate, useAuth (role / permission checks)
│   │   ├── components/results/  # Per-source cards, Summary, ScoreBadge, WeightBadge, modals
│   │   ├── components/admin/    # Connectors panel, connector tests
│   │   ├── lib/api.ts           # apiFetch / apiJson: every backend call (detects expired sessions)
│   │   ├── pages/               # Home · Results · History · HistoryDetail · Admin · Users · Connectors · Account · Docs
│   │   ├── hooks/               # useVerdictWeights, useEngineToggles, useTheme, useFetchJson, useMitreAliases
│   │   ├── i18n/                # EN/ES: provider, useI18n, rich(), messages/<area>.ts, docs/{en,es}.ts
│   │   ├── verdictEngine.ts     # Subscores, depth, Knowledge/Risk scores, quadrant
│   │   ├── trajectory.ts        # Step-by-step replay for the matrix view
│   │   ├── quadrants.ts         # Quadrant / outcome styles and labels (CVE wording included)
│   │   ├── intelAggregates.ts   # Summary: families, actor relations, first/last seen, flagged-by
│   │   ├── summaryRegistry.ts   # Summary field extractors (GeoIP/ASN/ISP/Tor/ports, CVSS/KEV/EPSS)
│   │   ├── registry.tsx         # Static engine registry (same order, labels and types as the backend)
│   │   └── EnginesContext.tsx   # Merges static engines with backend-discovered MISP / OpenCTI instances
│   ├── Dockerfile               # Multi-stage build → nginx
│   └── nginx.conf               # SPA + /api proxy + cache headers
├── docs/                        # user-guide.md, admin.md, api.md, sources.md, development.md, logo, screenshot
├── docker-compose.yml
└── .env.example                 # FRONTEND_PORT / BACKEND_PORT
```

## Architecture

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
       │  (one request per engine)    │
       └──┬───┬───┬───┬───┬──────────┘
          │   │   │   │   │
         VT  AB  CH  OTX  …   ← external CTI APIs
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

The frontend fires one `POST /analyze/{engine}` per source in parallel, so each card renders as soon as its own response arrives. The verdict is computed in the browser (`verdictEngine.ts`) from the weights served by `GET /weights`; history entries store the scores and contributions at save time and are never recomputed.

## Conventions

- Every user-facing string goes through `useI18n()`; dictionaries are in `frontend/src/i18n/messages/<area>.ts` with `es` typed against `en`, so a missing translation fails the build. The Docs page text is in `frontend/src/i18n/docs/{en,es}.ts`.
- Changes to the verdict logic must be reflected in [user-guide.md](user-guide.md), [admin.md](admin.md) and the in-app Docs page (both languages).
- The verdict engine exists twice: `frontend/src/verdictEngine.ts` (results page) and its Python mirror `backend/app/core/verdict.py` (`POST /lookup`). Change both, then run the parity test, which feeds thousands of random results to both engines and requires identical output (needs Node ≥ 23):

  ```bash
  cd backend && .venv/bin/python tests/verdict_parity.py            # add --history data/history.db to replay real lookups
  ```
- New source: also add it to `backend/app/core/registry.py` with the same order, label and supported types as `frontend/src/registry.tsx` (the results page queries what the frontend registry declares).
- OpenCTI: after touching `backend/app/services/opencti_queries.py`, validate the GraphQL documents against old and new releases (dev-only dependency, no instance needed):

  ```bash
  cd backend && .venv/bin/pip install graphql-core && .venv/bin/python tests/opencti_schema_check.py   # 6.0.0 and master
  ```
