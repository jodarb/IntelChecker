"""Malpedia (Fraunhofer FKIE) — threat actors and the malware families attributed to
them (https://malpedia.caad.fkie.fraunhofer.de).

Actor search and details are public; an API token (optional) raises the rate
limit. The search matches names and synonyms, so "Fancy Bear" finds APT28. The
families list is trimmed to what the card and the Summary use (no reference URLs
per family), to keep history snapshots small.
"""
import re
from urllib.parse import quote

import httpx

from app.core.connectors import secret

_BASE = "https://malpedia.caad.fkie.fraunhofer.de"
_MAX_REFS = 15


def _norm(v: str) -> str:
    return re.sub(r"[^a-z0-9]", "", v.lower())


def _headers() -> dict:
    h = {"User-Agent": "IntelChecker/1.0", "Accept": "application/json"}
    key = secret("MALPEDIA_API_KEY")
    if key:
        h["Authorization"] = f"apitoken {key}"
    return h


def _error(r: httpx.Response) -> dict | None:
    if r.status_code in (401, 403):
        return {"error": {"code": "Unauthorized", "message": "Invalid Malpedia API token."}}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "Malpedia rate limit exceeded (an API token raises it)."}}
    if r.status_code >= 500:
        return {"error": {"code": "ServiceUnavailable", "message": f"Malpedia is unavailable (HTTP {r.status_code})."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"Malpedia returned HTTP {r.status_code}."}}
    return None


def _best(needle: str, candidates: list) -> tuple[dict | None, bool]:
    """Exact name/synonym match first, then Malpedia's own first hit (exact = False)."""
    n = _norm(needle)
    actors = [c for c in candidates if isinstance(c, dict) and c.get("name")]
    for c in actors:
        names = [c.get("name"), c.get("common_name"), *(c.get("synonyms") or [])]
        if any(isinstance(x, str) and _norm(x) == n for x in names):
            return c, True
    return (actors[0], False) if actors else (None, False)


async def lookup(actor: str) -> dict:
    needle = actor.strip()
    if not needle:
        return {"error": {"code": "BadRequest", "message": "Empty threat actor name."}}

    async with httpx.AsyncClient(timeout=20, headers=_headers()) as client:
        try:
            r = await client.get(f"{_BASE}/api/find/actor/{quote(needle, safe='')}")
            if err := _error(r):
                return err
            match, exact = _best(needle, r.json() if isinstance(r.json(), list) else [])
            if not match:
                return {"found": False, "query": needle}
            r = await client.get(f"{_BASE}/api/get/actor/{quote(match['name'], safe='')}")
            if r.status_code == 404:
                return {"found": False, "query": needle}
            if err := _error(r):
                return err
            data = r.json()
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "Malpedia request timed out after 20 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach Malpedia."}}
        except ValueError:
            return {"error": {"code": "InvalidResponse", "message": "Malpedia returned a non-JSON response."}}

    if not isinstance(data, dict):
        return {"error": {"code": "InvalidResponse", "message": "Malpedia returned an unexpected response."}}
    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    families = [
        {
            "id": fid,
            "common_name": f.get("common_name") or fid,
            "alt_names": [a for a in f.get("alt_names") or [] if isinstance(a, str)],
            "updated": f.get("updated"),
            "link": f"{_BASE}/details/{fid}",
        }
        for fid, f in (data.get("families") or {}).items() if isinstance(f, dict)
    ]
    families.sort(key=lambda f: str(f["common_name"]).lower())
    refs = [x for x in meta.get("refs") or [] if isinstance(x, str)]
    return {
        "found": True,
        # False: Malpedia's closest hit, no name or synonym equals the query.
        "exact": exact,
        "query": needle,
        "id": match["name"],
        "name": data.get("value") or match.get("common_name") or match["name"],
        "description": data.get("description") or "",
        "synonyms": [s for s in meta.get("synonyms") or match.get("synonyms") or [] if isinstance(s, str)],
        "country": meta.get("country"),
        "state_sponsor": meta.get("cfr-suspected-state-sponsor"),
        "victims": meta.get("cfr-suspected-victims") or [],
        "target_category": meta.get("cfr-target-category") or [],
        "incident_type": meta.get("cfr-type-of-incident"),
        "attribution_confidence": meta.get("attribution-confidence"),
        "families": families,
        "refs": refs[:_MAX_REFS],
        "refs_total": len(refs),
        "link": f"{_BASE}/actor/{match['name']}",
    }


async def dispatch(indicator: str, type: str) -> dict:
    if type != "threat-actor":
        return {"error": {"code": "UnsupportedType", "message": f"Malpedia does not support type '{type}'."}}
    return await lookup(indicator)
