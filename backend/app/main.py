import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from app.core.config import MISP_INSTANCES
from app.core.registry import ENGINES
from app.services import (
    abuseipdb, virustotal, abusech, alienvault, ipinfo, shodan,
    torexitlist, urlhaus, mitreattack, ripestat, urlscan, malwarebazaar, phishtank,
    recordedfuture, misp,
)

app = FastAPI()

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
        result[name] = entry
    return result


@app.post("/analyze/{engine}")
async def analyze(engine: str, req: AnalyzeRequest):
    if engine not in ENGINES:
        raise HTTPException(
            status_code=404, detail=f"Unknown engine: {engine}"
        )
    return await _SERVICES[engine].dispatch(req.indicator, req.type)
