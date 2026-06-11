# IntelChecker

Internal web application for rapid triage and classification of Indicators of Compromise (IoCs). Analysts can submit an IP, domain, URL, ASN or threat actor and receive consolidated threat intelligence from multiple CTI sources in real time.

## Requirements

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) with Docker Compose

That's it. No Python, Node or any other runtime needed on the host.

---

## Installation

```bash
git clone <repo-url>
cd IntelChecker
cp backend/.env.example backend/.env
```

Then open `backend/.env` and fill in your API keys (see [API Keys](#api-keys) section below).

---

## Running the application

```bash
docker compose up
```

The first run will build the images — subsequent starts are fast.

| Service  | URL                    |
|----------|------------------------|
| Frontend | http://localhost:5173  |
| Backend  | http://localhost:8000  |

### Stop

```bash
docker compose down
```

---

## API Keys

All credentials are stored in `backend/.env`. This file is **never committed to git**.

```
backend/.env       ← your real keys (gitignored)
backend/.env.example ← empty template (committed)
```

Edit `backend/.env` and set the keys for the services you want to use:

| Variable | Service |
|---|---|
| `VIRUSTOTAL_API_KEY` | [VirusTotal](https://www.virustotal.com) |
| `ABUSEIPDB_API_KEY` | [AbuseIPDB](https://www.abuseipdb.com) |
| `SHODAN_API_KEY` | [Shodan](https://shodan.io) |
| `CRIMINALIP_API_KEY` | [Criminal IP](https://www.criminalip.io) |
| `IPINFO_API_KEY` | [IPinfo](https://ipinfo.io) |
| `RECORDED_FUTURE_API_KEY` | [Recorded Future](https://www.recordedfuture.com) |
| `ANYRUN_API_KEY` | [Any.run](https://any.run) |
| `OPENCTI_URL` | OpenCTI instance URL |
| `OPENCTI_API_KEY` | OpenCTI API key |

Services with an empty key will show an error card in the UI instead of results. The rest of the sources continue working normally.

---

## Custom logo

The logo shown above the search bar is fully customizable per installation.

**To use your own logo:**

Replace `frontend/public/logo.svg` with your own file. Any browser-renderable image format works (SVG recommended). The image is displayed at `48px` height and centered.

**To hide the logo entirely:**

Edit `frontend/public/config.json` and set `showLogo` to `false`:

```json
{ "showLogo": false }
```

---

## Development (without Docker)

If you need to run services locally for development:

**Backend**

```bash
# Create and activate the virtual environment (first time only)
python -m venv .venv
.venv/Scripts/activate        # Windows
# source .venv/bin/activate   # Linux / macOS

pip install -r backend/requirements.txt

# Run from the backend directory
cd backend
uvicorn app.main:app --reload
```

**Frontend**

```bash
cd frontend
npm install
npm run dev
```

---

## Project structure

```
IntelChecker/
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI entrypoint & routes
│   │   ├── core/config.py   # Loads API keys from .env
│   │   └── services/        # Async CTI client modules
│   ├── .env                 # Your keys (gitignored)
│   ├── .env.example         # Empty template
│   └── requirements.txt
├── frontend/
│   ├── public/
│   │   ├── logo.svg         # Replace with your logo
│   │   └── config.json      # showLogo toggle
│   └── src/
├── pocs/                    # Standalone API test scripts
├── docker-compose.yml
└── README.md
```
