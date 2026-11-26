"""Recorded Future — Connect API (IOC risk), Links API (validated relationships) and
Threat API (threat actors, threat map). Header X-RFToken.

  * IP / domain / URL / hash: `GET /v2/<type>/<value>` with risk, timestamps, intel
    card, the AI summary (`aiInsights`) and the threat lists it is on; then
    `POST /links/search` for the relationships Insikt Group / RF's technical analysis
    validated (threat actors, malware, ATT&CK techniques…), which feed the Summary.
    `relatedEntities` is deliberately not requested: it is co-mention noise (the
    EICAR test hash comes out "related" to the GRU) and weighs ~90 KB.
  * Threat actor: `POST /threat/actor/search` (matches any alias: "APT28" →
    BlueDelta), then the actor's links (malware, techniques, organisations, its
    infrastructure) and, if the actor is on this organisation's Threat Map, the
    intent / opportunity RF estimates towards it. The map (~700 KB, every actor
    relevant to the organisation) is cached for a few hours.

A failing links or threat map call never fails the lookup: the main answer is kept
and the missing part is reported in `links_error` / `threat_map_error`.
The Vulnerability module is a separate licence: CVEs are not queried here.
"""
import asyncio
import time
from urllib.parse import quote

import httpx

from app.core.connectors import secret

_BASE = "https://api.recordedfuture.com"
_FIELDS = "risk,timestamps,entity,intelCard,aiInsights,threatLists"
_PORTAL = "https://app.recordedfuture.com/live/sc/entity/{}"
_LINKS_PER_TYPE = 10
_MAX_ALIASES = 40
_MAP_TTL = 6 * 3600

# Links API entity type → our group name.
_LINK_GROUPS = {
    "type:Malware": "malware",
    "type:MitreAttackIdentifier": "mitre",
    "type:AttackVector": "attack_vectors",
    "type:IpAddress": "ips",
    "type:InternetDomainName": "domains",
    "type:URL": "urls",
    "type:Hash": "hashes",
    "type:CyberVulnerability": "vulnerabilities",
}
_IOC_GROUPS = ("ips", "domains", "urls", "hashes")

_map_lock = asyncio.Lock()
_map_cache: dict = {"at": 0.0, "by_id": None, "date": None}


class _RFError(Exception):
    def __init__(self, error: dict):
        super().__init__(error.get("message"))
        self.error = error


def _headers() -> dict:
    return {"X-RFToken": secret("RECORDED_FUTURE_API_KEY"), "Accept": "application/json",
            "Content-Type": "application/json"}


def _raise_for(r: httpx.Response, what: str) -> None:
    if r.status_code == 401:
        raise _RFError({"code": "Unauthorized", "message": "Invalid Recorded Future API token."})
    if r.status_code == 403:
        raise _RFError({"code": "Forbidden",
                        "message": f"The Recorded Future token has no access to {what} (missing API privileges)."})
    if r.status_code == 404:
        raise _RFError({"code": "NotFound", "message": "Indicator not found in Recorded Future."})
    if r.status_code == 429:
        raise _RFError({"code": "RateLimitExceeded", "message": "Recorded Future API rate limit exceeded."})
    if r.status_code >= 500:
        raise _RFError({"code": "ServiceUnavailable", "message": f"Recorded Future is unavailable (HTTP {r.status_code})."})
    if not r.is_success:
        # Error bodies aren't always JSON (e.g. 401 returns a plain text message).
        try:
            detail = r.json().get("error", {}).get("message", "")
        except (ValueError, AttributeError):
            detail = r.text[:200]
        raise _RFError({"code": "HttpError", "message": f"Recorded Future returned HTTP {r.status_code}." + (f" {detail}" if detail else "")})


async def _call(client: httpx.AsyncClient, method: str, path: str, what: str, **kw):
    try:
        r = await client.request(method, f"{_BASE}{path}", **kw)
    except httpx.TimeoutException:
        raise _RFError({"code": "Timeout", "message": f"Recorded Future {what} request timed out."})
    except httpx.RequestError:
        raise _RFError({"code": "NetworkError", "message": "Could not reach Recorded Future."})
    _raise_for(r, what)
    try:
        return r.json()
    except ValueError:
        raise _RFError({"code": "InvalidResponse", "message": "Recorded Future returned a non-JSON response."})


def _attrs(link: dict) -> dict:
    return {a.get("id"): a.get("value") for a in link.get("attributes") or [] if isinstance(a, dict)}


def _group_links(raw_links: list, own_id: str | None) -> dict:
    """Links grouped by kind. Organisations split into threat actors and the rest
    (targets, sponsors, victims… the API doesn't say which)."""
    out: dict[str, list] = {g: [] for g in (*_LINK_GROUPS.values(), "actors", "organizations")}
    for link in raw_links:
        if not isinstance(link, dict) or link.get("id") == own_id or not link.get("name"):
            continue
        attrs = _attrs(link)
        if link.get("type") == "type:Organization":
            group = "actors" if attrs.get("threat_actor") is True else "organizations"
        else:
            group = _LINK_GROUPS.get(link.get("type"))
        if not group or len(out[group]) >= _LINKS_PER_TYPE:
            continue
        item = {"id": link.get("id"), "name": link["name"], "source": link.get("source")}
        if attrs.get("risk_score") is not None:
            item["risk_score"] = attrs["risk_score"]
            item["criticality"] = attrs.get("criticality")
        if attrs.get("display_name"):
            item["label"] = attrs["display_name"]
        out[group].append(item)
    return {k: v for k, v in out.items() if v}


async def _links(client: httpx.AsyncClient, entity_id: str) -> tuple[dict, dict | None]:
    try:
        body = await _call(client, "POST", "/links/search", "the Links API", json={
            "entities": [entity_id], "limits": {"search_scope": "medium", "per_entity_type": _LINKS_PER_TYPE},
        })
    except _RFError as e:
        return {}, e.error
    rows = body.get("data") if isinstance(body, dict) else None
    row = rows[0] if isinstance(rows, list) and rows and isinstance(rows[0], dict) else {}
    return _group_links(row.get("links") or [], entity_id), None


async def _threat_map(client: httpx.AsyncClient) -> tuple[dict | None, str | None, dict | None]:
    """This organisation's threat map, cached: (actor id → entry, map date, error)."""
    async with _map_lock:
        if _map_cache["by_id"] is not None and time.time() - _map_cache["at"] < _MAP_TTL:
            return _map_cache["by_id"], _map_cache["date"], None
        try:
            body = await _call(client, "POST", "/threat/map/actors", "the Threat Map", json={})
        except _RFError as e:
            return None, None, e.error
        data = body.get("data") if isinstance(body, dict) else {}
        entries = [x for x in (data or {}).get("threat_map") or [] if isinstance(x, dict) and x.get("id")]
        _map_cache.update(at=time.time(), by_id={x["id"]: x for x in entries}, date=(data or {}).get("date"))
        return _map_cache["by_id"], _map_cache["date"], None


# ── Lookups ───────────────────────────────────────────────────────────────────

async def _ioc(client: httpx.AsyncClient, entity_type: str, indicator: str) -> dict:
    body = await _call(client, "GET", f"/v2/{entity_type}/{quote(indicator, safe='')}", "this lookup",
                       params={"fields": _FIELDS})
    data = body.get("data", body) if isinstance(body, dict) else {}
    ai = data.get("aiInsights") if isinstance(data.get("aiInsights"), dict) else {}
    data["aiInsights"] = {"text": ai.get("text"), "numberOfReferences": ai.get("numberOfReferences")} if ai.get("text") else None
    data["threatLists"] = [{"id": t.get("id"), "name": t.get("name"), "type": t.get("type")}
                           for t in data.get("threatLists") or [] if isinstance(t, dict) and t.get("name")]
    entity_id = (data.get("entity") or {}).get("id")
    if entity_id:
        data["insikt_links"], links_error = await _links(client, entity_id)
        if links_error:
            data["links_error"] = links_error
    return data


def _best_actor(needle: str, candidates: list) -> tuple[dict | None, bool]:
    n = needle.casefold()
    for c in candidates:
        a = c.get("attributes") or {}
        names = [a.get("name"), *(a.get("common_names") or []), *(a.get("alias") or [])]
        if any(isinstance(x, str) and x.casefold() == n for x in names):
            return c, True
    return (candidates[0], False) if candidates else (None, False)


async def _actor(client: httpx.AsyncClient, name: str) -> dict:
    needle = name.strip()
    body = await _call(client, "POST", "/threat/actor/search", "the Threat API", json={"name": needle, "limit": 10})
    rows = body.get("data") if isinstance(body, dict) else None
    match, exact = _best_actor(needle, [r for r in rows or [] if isinstance(r, dict) and r.get("id")])
    if not match:
        return {"kind": "actor", "found": False, "query": needle}
    a = match.get("attributes") or {}
    aliases = sorted({x for x in [*(a.get("common_names") or []), *(a.get("alias") or [])] if isinstance(x, str)},
                     key=str.casefold)
    (links, links_error), (tmap, map_date, map_error) = await asyncio.gather(
        _links(client, match["id"]), _threat_map(client))
    entry = (tmap or {}).get(match["id"])
    out = {
        "kind": "actor",
        "found": True,
        "exact": exact,
        "query": needle,
        "id": match["id"],
        "name": a.get("name") or needle,
        "common_names": [x for x in a.get("common_names") or [] if isinstance(x, str)],
        "aliases": aliases[:_MAX_ALIASES],
        "aliases_total": len(aliases),
        "categories": [c.get("name") for c in a.get("categories") or [] if isinstance(c, dict) and c.get("name")],
        "insikt_links": links,
        # On this organisation's threat map: intent / opportunity towards it (0-100).
        "threat_map": {
            "intent": entry.get("intent"),
            "opportunity": entry.get("opportunity"),
            "date": map_date,
            # Latest changes first: what moved the actor's intent / capability.
            "log": sorted(({"date": e.get("date"), "axis": e.get("axis"), "severity": e.get("severity")}
                           for e in entry.get("log_entries") or [] if isinstance(e, dict)),
                          key=lambda e: str(e["date"]), reverse=True)[:5],
        } if entry else None,
        "on_threat_map": bool(entry) if tmap is not None else None,
        "link": _PORTAL.format(match["id"]),
    }
    if links_error:
        out["links_error"] = links_error
    if map_error:
        out["threat_map_error"] = map_error
    return out


async def dispatch(indicator: str, type: str) -> dict:
    entity_types = {"ip": "ip", "domain": "domain", "url": "url", "hash": "hash"}
    if type not in (*entity_types, "threat-actor"):
        return {"error": {"code": "UnsupportedType", "message": f"Recorded Future does not support type '{type}'."}}
    if not secret("RECORDED_FUTURE_API_KEY"):
        return {"error": {"code": "MissingApiKey", "message": "Recorded Future API token is not configured."}}
    async with httpx.AsyncClient(timeout=20, headers=_headers()) as client:
        try:
            if type == "threat-actor":
                return await _actor(client, indicator)
            return await _ioc(client, entity_types[type], indicator)
        except _RFError as e:
            return {"error": e.error}
