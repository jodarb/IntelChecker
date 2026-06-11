from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from app.services.abuseipdb import check_ip

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["POST"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    indicator: str
    type: str = "auto"


@app.post("/analyze")
async def analyze(req: AnalyzeRequest):
    return await check_ip(req.indicator)
