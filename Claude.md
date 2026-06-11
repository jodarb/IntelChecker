# Claude.md - INTELCHECKER

## 1. Project Overview
**INTELCHECKER** is an internal web application designed for the rapid triage and classification of Indicators of Compromise (IoCs) and Cyber Threat Intelligence (CTI) data. Analysts can input an indicator, select its type (or let the system automatically detect it), and receive a unified verdict alongside detailed technical context streamed in parallel from multiple external CTI sources.

### Key Features
* **Decoupled & Internal Architecture:** SPA design deployed within a local network/VPN environment, omitting initial user authentication mechanisms.
* **Asynchronous Processing:** Multi-threaded/asynchronous API requests that prevent thread blocking and resource starvation.
* **Real-Time Data Streaming:** Dynamic frontend components that render individual API responses immediately as they are streamed from the backend.
* **Stateless Operation:** No database persistence layer required; all queries are executed and processed strictly in real time.

---

## 2. Tech Stack

### Backend
* **Language/Framework:** Python 3.11+ using **FastAPI**.
* **Concurrency:** `asyncio` and `httpx` for non-blocking, asynchronous HTTP client requests.
* **Data Transmission:** Server-Sent Events (SSE) or WebSockets to handle real-time streaming to the frontend client.

### Frontend
* **Framework:** Component-driven modern SPA built with **React 18** and **TypeScript**, bundled via **Vite**.
* **Styling:** **Tailwind CSS** configured with a clean, high-contrast dark theme optimized for SOC and Threat Intel operations.
* **UI Components:** **shadcn/ui** as the component library, providing accessible and composable primitives that integrate natively with Tailwind.

---

## 3. Architecture & Data Flow

1.  **User Input:** The analyst inputs an indicator via the UI and either explicitly selects its type (IP, URL, Domain, ASN, Threat Actor) or chooses the **"Free Text"** option.
2.  **Ingestion & Validation (Backend):**
    * Typed inputs are routed directly to their respective API endpoint managers.
    * "Free Text" inputs trigger an internal parser/regex evaluation pipeline to dynamically classify the IoC type before routing.
3.  **Query Orchestration:** The backend initializes concurrent asynchronous workers to query the relevant endpoints of all configured threat intelligence providers simultaneously.
4.  **Response Streaming:** As soon as an individual API worker receives a payload, the backend serializes the JSON data and streams it to the frontend via the open connection. The frontend intercepts the specific event and updates the corresponding data card dynamically without affecting the rest of the view.
5.  **Error Handling:** If an individual API worker fails (timeout, HTTP error, missing credentials, rate limit, etc.), the backend must stream an error event for that specific source. The frontend renders the corresponding card in an error state, displaying the human-readable reason for the failure. Other cards are not affected. The error message must be actionable — it should indicate *why* it failed (e.g., "Invalid API key", "Rate limit exceeded", "Service unavailable") rather than a generic error.

---

## 4. Threat Intel Integrations (CTI Sources)
The backend manages API authentication using server-side credentials defined in an environment file (`.env`). The following integrations will be available:

* **VirusTotal** (IPs, Domains, URLs)
* **AlienVault OTX** (IPs, Domains, URLs, Threat Actors)
* **AbuseIPDB** (IPs)
* **Shodan** (IPs, ASNs)
* **Criminal IP** (IPs, Domains)
* **IPinfo** (IPs, ASNs)
* **Recorded Future** (Multi-IoC, Threat Context)
* **Any.run** (URLs, Domains)
* **OpenCTI** (Internal/External instance connection - Global Context & Threat Actors)

---

## 5. Verdict Engine (Pending Definition)
* The system will calculate a unified scoring metric ranging from **0 to 10**.
* *Development Note:* The architecture must abstract this logic into a dedicated component/class (`VerdictEngine`). This engine will ingest the normalized results from all responsive APIs and output a structured integer score. The mathematical distribution, weights, and thresholds will be defined and implemented at a later stage.

---

## 6. Development Instructions for the AI Assistant

### Target Directory Structure
```text
intelchecker/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py            # FastAPI application entrypoint & streaming routes
│   │   ├── core/
│   │   │   └── config.py      # Environment variables and app configuration (.env)
│   │   ├── services/          # Asynchronous CTI client modules
│   │   │   ├── __init__.py
│   │   │   ├── base.py        # Abstract base class for CTI API clients
│   │   │   ├── virustotal.py
│   │   │   ├── abuseipdb.py
│   │   │   └── ...
│   │   └── utils/
│   │       └── parser.py      # Regex and logical parsing for "Free Text" detection
│   ├── .env.example
│   └── requirements.txt
└── frontend/
    ├── src/
    │   ├── components/        # UI Cards for individual API source tracking
    │   ├── App.tsx
    │   └── main.tsx
    ├── package.json
    ├── tsconfig.json
    └── tailwind.config.js
```
