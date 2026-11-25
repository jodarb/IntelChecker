import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel
from app.core import auth
from app.core import db as history_db
from app.core import weights as weights_store
from app.core import connectors
from app.core.registry import INDICATOR_TYPES, engines as current_engines, is_connected
from app.core.verdict import compute_verdict, get_engine_assessment
from app.services import (
    abuseipdb, virustotal, abusech, alienvault, ipinfo, shodan,
    torexitlist, urlhaus, mitreattack, ripestat, urlscan, malwarebazaar, phishtank,
    recordedfuture, anyrun, greynoise, hybridanalysis, safebrowsing, tweetfeed, misp,
)


log = logging.getLogger("intelchecker")


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
}


def _service(engine_id: str):
    """Static source module, or a MISP engine bound to the instance's current settings."""
    return _SERVICES.get(engine_id) or misp.engine_for(engine_id)


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


class TokenCreateRequest(BaseModel):
    name: str
    expires_in_days: int | None = None   # None = never expires


class LookupRequest(BaseModel):
    indicator: str
    type: str
    engines: list[str] | None = None     # only these sources (default: every configured one for the type)
    exclude: list[str] = []              # skip these sources
    save: bool = True                    # store in the history, like a lookup from the UI
    include_raw: bool = False            # add each source's raw response to the answer


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
        "default_password": auth.uses_default_password(user["id"]),
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
def change_password(req: PasswordChangeRequest, user: dict = Depends(auth.browser_session_user)):
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


# ── API tokens (admin) ────────────────────────────────────────────────────────

@app.get("/users/{user_id}/tokens", dependencies=[IsAdmin])
def list_tokens(user_id: int):
    return auth.list_tokens(user_id)


@app.post("/users/{user_id}/tokens", dependencies=[IsAdmin], status_code=201)
def create_token(user_id: int, req: TokenCreateRequest):
    raw, token = auth.create_token(user_id, req.name, req.expires_in_days)
    return {**token, "token": raw}


@app.delete("/users/{user_id}/tokens/{token_id}", dependencies=[IsAdmin], status_code=204)
def delete_token(user_id: int, token_id: int):
    auth.delete_token(user_id, token_id)
    return Response(status_code=204)


# ── Connectors (admin) ────────────────────────────────────────────────────────
# API keys and MISP instances (app/core/connectors.py). Stored keys are never
# returned, only their last four characters.

class SecretRequest(BaseModel):
    value: str


class MispRequest(BaseModel):
    name: str | None = None
    url: str | None = None
    key: str | None = None          # omitted on edit = keep the current key
    verify_ssl: bool | None = None
    client_cert: str | None = None  # filename in backend/certs/, "" = none
    client_key: str | None = None


# A harmless, well-known indicator per type, to check that a source accepts its key.
_TEST_INDICATORS = {
    "ip": "8.8.8.8",
    "domain": "example.com",
    "url": "https://example.com/",
    # EICAR test file
    "hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "asn": "AS15169",
    "threat-actor": "APT28",
}


@app.get("/connectors", dependencies=[IsAdmin])
def list_connectors():
    return {
        "keys": connectors.list_keys(),
        "misp": connectors.list_misp(),
        "misp_from_env": not connectors.misp_managed_in_ui(),
        "cert_files": connectors.list_cert_files(),
    }


@app.put("/connectors/keys/{env_name}", dependencies=[IsAdmin], status_code=204)
def set_connector_key(env_name: str, req: SecretRequest):
    connectors.set_key(env_name, req.value)
    return Response(status_code=204)


@app.delete("/connectors/keys/{env_name}", dependencies=[IsAdmin], status_code=204)
def delete_connector_key(env_name: str):
    connectors.delete_key(env_name)
    return Response(status_code=204)


@app.post("/connectors/misp", dependencies=[IsAdmin], status_code=201)
def create_misp_instance(req: MispRequest):
    return connectors.create_misp(req.model_dump(exclude_unset=True))


@app.patch("/connectors/misp/{instance_id}", dependencies=[IsAdmin])
def update_misp_instance(instance_id: str, req: MispRequest):
    return connectors.update_misp(instance_id, req.model_dump(exclude_unset=True))


@app.delete("/connectors/misp/{instance_id}", dependencies=[IsAdmin], status_code=204)
def delete_misp_instance(instance_id: str):
    connectors.delete_misp(instance_id)
    return Response(status_code=204)


@app.post("/connectors/test/{engine}", dependencies=[IsAdmin])
async def test_connector(engine: str):
    """Runs a real lookup of a harmless indicator against one source. "Not found"
    counts as success: the source answered and accepted the credentials. Uses one
    request of the source's quota."""
    meta = current_engines().get(engine)
    service = _service(engine)
    if meta is None or service is None:
        raise auth.api_error(404, "ConnectorNotFound", f"Unknown source: {engine}.")
    type_ = next(t for t in ("ip", "domain", "url", "hash", "asn", "threat-actor") if t in meta["supports"])
    try:
        data = await service.dispatch(_TEST_INDICATORS[type_], type_)
    except Exception:
        log.exception("Connector test of %s failed", engine)
        return {"ok": False, "error": {"code": "InternalError", "message": f"{meta['label']} test failed unexpectedly."}}
    err = data.get("error") if isinstance(data, dict) else None
    if isinstance(err, dict) and err.get("code") != "NotFound":
        return {"ok": False, "error": err}
    return {"ok": True, "error": None}


# ── Lookups ───────────────────────────────────────────────────────────────────

@app.get("/engines/status", dependencies=[SignedIn])
def engines_status():
    result = {}
    for name, meta in current_engines().items():
        entry = {"connected": is_connected(meta), "supports": meta["supports"]}
        if "name" in meta:
            entry["label"] = meta["name"]
        result[name] = entry
    return result


@app.post("/analyze/{engine}", dependencies=[CanAnalyze])
async def analyze(engine: str, req: AnalyzeRequest):
    service = _service(engine)
    if service is None:
        raise HTTPException(
            status_code=404, detail=f"Unknown engine: {engine}"
        )
    return await service.dispatch(req.indicator, req.type)


@app.post("/lookup")
async def lookup(req: LookupRequest, user: dict = CanAnalyze):
    """Full lookup in one call, for API clients: queries every configured source for
    the type in parallel, computes the verdict with the current weights (the same
    engine as the UI — app/core/verdict.py) and stores it in the history under the
    caller's username, like a lookup run from the results page."""
    indicator = req.indicator.strip()
    if not indicator:
        raise auth.api_error(422, "InvalidIndicator", "The indicator is empty.")
    if req.type not in INDICATOR_TYPES:
        raise auth.api_error(422, "InvalidType", f"Type must be one of: {', '.join(INDICATOR_TYPES)}.")
    all_engines = current_engines()
    unknown = sorted({e for e in (req.engines or []) + req.exclude if e not in all_engines})
    if unknown:
        raise auth.api_error(422, "UnknownEngine", f"Unknown source(s): {', '.join(unknown)}.")

    # Same selection as the results page: sources supporting the type that have their
    # API key (unconfigured ones aren't queried nor counted), in display order.
    selected = [
        eid for eid, meta in all_engines.items()
        if req.type in meta["supports"] and is_connected(meta)
        and (req.engines is None or eid in req.engines) and eid not in req.exclude
    ]

    async def run(eid: str) -> dict:
        try:
            return {"data": await _service(eid).dispatch(indicator, req.type), "error": None}
        except Exception:
            # The UI sees this as "couldn't reach the backend": a transient failure.
            log.exception("Lookup of %s on %s failed", indicator, eid)
            return {"data": None, "error": f"{all_engines[eid]['label']} lookup failed unexpectedly."}

    results = dict(zip(selected, await asyncio.gather(*(run(e) for e in selected))))
    config = weights_store.get_weights()
    engines = [{"id": e, "label": all_engines[e]["label"]} for e in selected]
    verdict = compute_verdict(config, engines, results, req.type)

    history_id = None
    if req.save and selected:
        snapshot = {
            e: {"label": all_engines[e]["label"], "data": results[e]["data"], "error": results[e]["error"]}
            for e in selected
        }
        history_id = history_db.save_query(
            indicator, req.type, verdict["risk"], verdict["knowledge"], verdict["quadrant"],
            snapshot, verdict["contributions"], user["username"], via="api",
        )

    sources = {}
    for e in selected:
        data, error = results[e]["data"], results[e]["error"]
        api_err = data.get("error") if isinstance(data, dict) else None
        a = get_engine_assessment(e, req.type, results[e])
        entry = {
            "label": all_engines[e]["label"],
            "outcome": a["outcome"],
            "subscore": a["subscore"],
            "depth": a["depth"],
            "error": api_err if isinstance(api_err, dict) else ({"code": "InternalError", "message": error}
                                                                 if error else None),
        }
        if req.include_raw:
            entry["data"] = data
        sources[e] = entry

    return {
        "history_id": history_id,
        "indicator": indicator,
        "type": req.type,
        "risk": verdict["risk"],
        "knowledge": verdict["knowledge"],
        "quadrant": verdict["quadrant"],
        "thresholds": config["thresholds"],
        "responded": verdict["responded"],
        "queried": verdict["queried"],
        "sources": sources,
        "contributions": verdict["contributions"],
    }


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
