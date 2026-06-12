import os
from pathlib import Path
from dotenv import dotenv_values
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from app.core.registry import ENGINES
from app.services import abuseipdb, virustotal, abusech, alienvault, ipinfo

_ENV_PATH = Path(__file__).parent.parent / ".env"

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_SERVICES = {
    "abuseipdb": abuseipdb,
    "virustotal": virustotal,
    "abusech": abusech,
    "alienvault": alienvault,
    "ipinfo": ipinfo,
}


class AnalyzeRequest(BaseModel):
    indicator: str
    type: str


@app.get("/engines/status")
def engines_status():
    live = dotenv_values(_ENV_PATH)
    return {
        name: {
            "connected": bool(live.get(meta["key"], "")),
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
