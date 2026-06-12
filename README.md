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

## ✨ Features

| | |
|---|---|
| ⚡ **Parallel queries** | All CTI sources are queried simultaneously — no waiting in line |
| 🎴 **Per-engine cards** | Each source renders its result independently as soon as it responds |
| 📊 **Summary section** | GeoIP and ASN aggregated across all engines with consensus count |
| 🎯 **Threat score gauge** | Visual semicircle gauge (0 – 10) driven by the VerdictEngine |
| 🔍 **Raw JSON viewer** | Per-card `{ RAW }` button opens a syntax-highlighted modal with copy & download |
| 🛠️ **Actionable errors** | Failed sources show the exact reason (invalid key, rate limit, timeout…) |
| 🌗 **Dark / Light mode** | Full theme support — syntax highlighter adapts automatically |

---

## 🔎 CTI Engine Coverage

| Engine | IP | Domain | URL | Hash | ASN |
|---|:---:|:---:|:---:|:---:|:---:|
| [AbuseIPDB](https://www.abuseipdb.com) | ✅ | | | | |
| [VirusTotal](https://www.virustotal.com) | ✅ | ✅ | ✅ | ✅ | |
| [ThreatFox · abuse.ch](https://threatfox.abuse.ch) | ✅ | | | ✅ | |
| [AlienVault OTX](https://otx.alienvault.com) | ✅ | ✅ | ✅ | ✅ | |
| [IPinfo](https://ipinfo.io) | ✅ | | | | |

> **Roadmap:** Shodan · Criminal IP · Recorded Future · Any.run · OpenCTI

---

## 🖥️ Screenshot

<!-- Add a screenshot: commit an image to docs/screenshot.png and uncomment the line below -->
<!-- <img src="docs/screenshot.png" alt="IntelChecker results view" width="100%" /> -->

> *Add `docs/screenshot.png` to the repo and uncomment the line above.*

---

## 🚀 Quick Start

### With Docker *(recommended)*

```bash
git clone <repo-url>
cd IntelChecker

cp backend/.env.example backend/.env
# Edit backend/.env and fill in your API keys

docker compose up
```

| Service | URL |
|---|---|
| Frontend | http://localhost:5173 |
| Backend API | http://localhost:8000 |

```bash
# Stop
docker compose down
```

### Without Docker *(development)*

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
| `ABUSECH_API_KEY` | [ThreatFox · abuse.ch](https://auth.abuse.ch/register) | ✅ |
| `ALIENVAULT_API_KEY` | [AlienVault OTX](https://otx.alienvault.com) | ✅ |
| `IPINFO_API_KEY` | [IPinfo](https://ipinfo.io/signup) | ✅ |

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
│   │   │   └── registry.py      # Engine capabilities (which types each supports)
│   │   └── services/            # Async CTI client modules
│   │       ├── base.py
│   │       ├── abuseipdb.py
│   │       ├── virustotal.py
│   │       ├── abusech.py
│   │       ├── alienvault.py
│   │       └── ipinfo.py
│   ├── .env                     # Your keys — gitignored
│   ├── .env.example             # Empty template
│   └── requirements.txt
├── frontend/
│   ├── public/
│   │   └── logo.svg             # Replace with your own logo
│   └── src/
│       ├── components/results/  # Per-engine cards + RawJsonModal
│       ├── pages/               # HomePage · ResultsPage
│       ├── registry.tsx         # Frontend engine registry
│       └── summaryRegistry.ts   # Summary field extractors per engine+type
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
       └─────────────────────────────┘
```

---

<div align="center">
<sub>Built for internal SOC and CTI operations · Not intended for public deployment</sub>
</div>
