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
    recordedfuture, misp,
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
def list_history_entries():
    return history_db.list_history()


@app.get("/history/{entry_id}")
def get_history_entry(entry_id: int):
    entry = history_db.get_entry(entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="History entry not found")
    return entry
