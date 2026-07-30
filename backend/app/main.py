import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from app.core.registry import ENGINES
from app.services import abuseipdb, virustotal, abusech, alienvault, ipinfo, shodan, torexitlist, urlhaus, mitreattack

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
}


class AnalyzeRequest(BaseModel):
    indicator: str
    type: str


@app.get("/engines/status")
def engines_status():
    return {
        name: {
            "connected": True if meta["key"] is None else bool(os.environ.get(meta["key"], "")),
            "supports": meta["supports"],
        }
        for name, meta in ENGINES.items()
    }


@app.post("/analyze/{engine}")
async def analyze(engine: str, req: AnalyzeRequest):
    if engine not in ENGINES:
        raise HTTPException(
            status_code=404, detail=f"Unknown engine: {engine}"
        )
    return await _SERVICES[engine].dispatch(req.indicator, req.type)
