import os
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from app.core import db as history_db
from app.core.config import MISP_INSTANCES
from app.core.registry import ENGINES
from app.services import (
    abuseipdb, virustotal, abusech, alienvault, ipinfo, shodan,
    torexitlist, urlhaus, mitreattack, ripestat, urlscan, malwarebazaar, phishtank,
    recordedfuture, anyrun, greynoise, hybridanalysis, safebrowsing, misp,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    history_db.init_db()
    task = asyncio.create_task(torexitlist.start_background_refresh())
    yield
    task.cancel()


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_SERVICES = {
    "abuseipdb": abuseipdb,
    "virustotal": virustotal,
    "abusech": abusech,
    "alienvault": alienvault,
    "ipinfo": ipinfo,
    "shodan": shodan,
    "torexitlist": torexitlist,
    "urlhaus": urlhaus,
    "mitreattack": mitreattack,
    "ripestat": ripestat,
    "urlscan": urlscan,
    "malwarebazaar": malwarebazaar,
    "phishtank": phishtank,
    "recordedfuture": recordedfuture,
    "anyrun": anyrun,
    "greynoise": greynoise,
    "hybridanalysis": hybridanalysis,
    "safebrowsing": safebrowsing,
    **misp.build_engines(MISP_INSTANCES),
}


class AnalyzeRequest(BaseModel):
    indicator: str
    type: str


class HistoryEntryRequest(BaseModel):
    indicator: str
    type: str
    score: int | None = None
    results: dict
    contributions: list = []


@app.get("/engines/status")
def engines_status():
    result = {}
    for name, meta in ENGINES.items():
        if "connected" in meta:
            connected = meta["connected"]
        else:
            connected = True if meta["key"] is None else bool(os.environ.get(meta["key"], ""))
        entry = {"connected": connected, "supports": meta["supports"]}
        if "name" in meta:
            entry["label"] = meta["name"]
        if "weight" in meta:
            entry["weight"] = meta["weight"]
        result[name] = entry
    return result


@app.post("/analyze/{engine}")
async def analyze(engine: str, req: AnalyzeRequest):
    if engine not in ENGINES:
        raise HTTPException(
            status_code=404, detail=f"Unknown engine: {engine}"
        )
    return await _SERVICES[engine].dispatch(req.indicator, req.type)


@app.post("/history")
def create_history_entry(entry: HistoryEntryRequest):
    entry_id = history_db.save_query(
        entry.indicator, entry.type, entry.score, entry.results, entry.contributions
    )
    return {"id": entry_id}


@app.get("/history")
def list_history_entries(indicator: str | None = None):
    # No cap when filtering to one indicator — the point is an accurate global
    # count, not just what fits in the default recent-activity page size.
    return history_db.list_history(limit=100000 if indicator else 200, indicator=indicator)


# Must be registered before /history/{entry_id} — otherwise "frequency" would be
# swallowed by that route and rejected as an invalid int id.
@app.get("/history/frequency")
def get_history_frequency(indicator: str):
    return history_db.get_frequency(indicator)


@app.get("/history/{entry_id}")
def get_history_entry(entry_id: int):
    entry = history_db.get_entry(entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="History entry not found")
    return entry
