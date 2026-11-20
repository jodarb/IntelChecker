import os
import asyncio
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel
from app.core import auth
from app.core import db as history_db
from app.core import weights as weights_store
from app.core.config import MISP_INSTANCES
from app.core.registry import ENGINES
from app.services import (
    abuseipdb, virustotal, abusech, alienvault, ipinfo, shodan,
    torexitlist, urlhaus, mitreattack, ripestat, urlscan, malwarebazaar, phishtank,
    recordedfuture, anyrun, greynoise, hybridanalysis, safebrowsing, tweetfeed, misp,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    history_db.init_db()
    auth.init_db()
    task = asyncio.create_task(torexitlist.start_background_refresh())
    yield
    task.cancel()


app = FastAPI(lifespan=lifespan)

# No CORS middleware: the SPA reaches the API same-origin through the nginx (or Vite)
# /api proxy, and the session cookie is SameSite=Strict, so cross-site requests are
# neither needed nor allowed.

# Role checks (see app/core/auth.py): any signed-in user, reader+, analyst+, admin.
SignedIn = Depends(auth.current_user)
CanReadHistory = Depends(auth.require("history:read"))
CanAnalyze = Depends(auth.require("analyze"))
IsAdmin = Depends(auth.require("admin"))

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
    "tweetfeed": tweetfeed,
    **misp.build_engines(MISP_INSTANCES),
}


class AnalyzeRequest(BaseModel):
    indicator: str
    type: str


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: str


class UserUpdateRequest(BaseModel):
    role: str | None = None
    active: bool | None = None
    password: str | None = None


class HistoryEntryRequest(BaseModel):
    indicator: str
    type: str
    score: int | None = None              # Risk Score
    knowledge_score: int | None = None
    quadrant: str | None = None
    results: dict
    # {"risk": [...], "knowledge": [...]} — older clients sent a flat list (risk only).
    contributions: dict | list = []


# ── Authentication ────────────────────────────────────────────────────────────

def _me(user: dict) -> dict:
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "must_change_password": user["must_change_password"],
        "permissions": sorted(auth.PERMISSIONS.get(user["role"], set())),
    }


@app.post("/auth/login")
def login(req: LoginRequest, response: Response):
    token, user = auth.login(req.username, req.password)
    response.set_cookie(
        auth.COOKIE_NAME, token,
        max_age=auth.SESSION_TTL_SECONDS, httponly=True, samesite="strict",
        secure=auth.COOKIE_SECURE, path="/",
    )
    return _me(user)


@app.post("/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(auth.COOKIE_NAME)
    if token:
        auth.logout(token)
    response.delete_cookie(auth.COOKIE_NAME, path="/")
    return {"ok": True}


# session_user (not current_user): a user with a temporary password must still be
# able to see who they are and change it.
@app.get("/auth/me")
def me(user: dict = Depends(auth.session_user)):
    return _me(user)


@app.put("/auth/password")
def change_password(req: PasswordChangeRequest, user: dict = Depends(auth.session_user)):
    auth.change_own_password(user["id"], req.current_password, req.new_password, user["token_hash"])
    return _me({**user, "must_change_password": False})


# ── User management (admin) ───────────────────────────────────────────────────

@app.get("/users", dependencies=[IsAdmin])
def list_users():
    return auth.list_users()


@app.post("/users", dependencies=[IsAdmin], status_code=201)
def create_user(req: UserCreateRequest):
    return auth.create_user(req.username, req.password, req.role)


@app.patch("/users/{user_id}")
def update_user(user_id: int, req: UserUpdateRequest, admin: dict = IsAdmin):
    return auth.update_user(user_id, admin["id"], role=req.role, active=req.active, password=req.password)


@app.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: int, admin: dict = IsAdmin):
    auth.delete_user(user_id, admin["id"])
    return Response(status_code=204)


# ── Lookups ───────────────────────────────────────────────────────────────────

@app.get("/engines/status", dependencies=[SignedIn])
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


@app.post("/analyze/{engine}", dependencies=[CanAnalyze])
async def analyze(engine: str, req: AnalyzeRequest):
    if engine not in ENGINES:
        raise HTTPException(
            status_code=404, detail=f"Unknown engine: {engine}"
        )
    return await _SERVICES[engine].dispatch(req.indicator, req.type)


@app.get("/mitre/aliases", dependencies=[SignedIn])
async def mitre_aliases():
    return await mitreattack.alias_lists()


# Every signed-in user reads the weights (the verdict is computed in the browser);
# only admins change them.
@app.get("/weights", dependencies=[SignedIn])
def get_weights():
    return weights_store.get_weights()


@app.put("/weights", dependencies=[IsAdmin])
def put_weights(payload: dict):
    try:
        return weights_store.save_weights(payload)
    except weights_store.WeightsValidationError as e:
        raise HTTPException(status_code=422, detail=str(e))


@app.post("/weights/reset", dependencies=[IsAdmin])
def reset_weights():
    return weights_store.reset_weights()


# Saving is part of running a lookup, so it needs the "analyze" permission. The
# username comes from the session, never from the request body.
@app.post("/history")
def create_history_entry(entry: HistoryEntryRequest, user: dict = CanAnalyze):
    entry_id = history_db.save_query(
        entry.indicator, entry.type, entry.score, entry.knowledge_score, entry.quadrant,
        entry.results, entry.contributions, user["username"],
    )
    return {"id": entry_id}


@app.get("/history", dependencies=[CanReadHistory])
def list_history_entries(indicator: str | None = None):
    # No cap when filtering to one indicator — the point is an accurate global
    # count, not just what fits in the default recent-activity page size.
    return history_db.list_history(limit=100000 if indicator else 200, indicator=indicator)


# Must be registered before /history/{entry_id} — otherwise "frequency" would be
# swallowed by that route and rejected as an invalid int id.
@app.get("/history/frequency", dependencies=[CanReadHistory])
def get_history_frequency(indicator: str):
    return history_db.get_frequency(indicator)


@app.get("/history/{entry_id}", dependencies=[CanReadHistory])
def get_history_entry(entry_id: int):
    entry = history_db.get_entry(entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="History entry not found")
    return entry
