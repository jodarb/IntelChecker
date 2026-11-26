from urllib.parse import quote
import httpx
from app.core.connectors import secret
from app.core.cve import bad_cve, normalize_cve

_BASE = "https://otx.alienvault.com/api/v1/indicators"
_SEARCH_PULSES_URL = "https://otx.alienvault.com/api/v1/search/pulses"


async def _request(path: str) -> dict:
    if not secret("ALIENVAULT_API_KEY"):
        return {"error": {"code": "MissingApiKey", "message": "AlienVault OTX API key is not configured."}}

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(
                f"{_BASE}/{path}",
                headers={"X-OTX-API-KEY": secret("ALIENVAULT_API_KEY")},
            )
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "AlienVault OTX request timed out after 15 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach AlienVault OTX."}}

    if r.status_code == 401:
        return {"error": {"code": "Unauthorized", "message": "Invalid AlienVault OTX API key."}}
    if r.status_code == 404:
        return {"error": {"code": "NotFound", "message": "Indicator not found in AlienVault OTX."}}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "AlienVault OTX rate limit exceeded."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"AlienVault OTX returned HTTP {r.status_code}."}}

    return r.json()


async def check_ip(ip: str) -> dict:
    return await _request(f"IPv4/{ip}/general")


async def check_domain(domain: str) -> dict:
    return await _request(f"domain/{domain}/general")


async def check_url(url: str) -> dict:
    return await _request(f"URL/{quote(url, safe='')}/general")


async def check_hash(hash_value: str) -> dict:
    return await _request(f"file/{hash_value}/general")


_MAX_CVE_PULSES = 20
_MAX_CVE_EXPLOITS = 10


def _trim_pulse(p: dict) -> dict:
    """The pulse fields the card and the Summary read (tags, families, adversary, dates, size)."""
    author = p.get("author") if isinstance(p.get("author"), dict) else {}
    return {
        "id": p.get("id"),
        "name": p.get("name"),
        "description": (p.get("description") or "")[:400],
        "tags": p.get("tags") or [],
        "created": p.get("created"),
        "modified": p.get("modified"),
        "author_name": p.get("author_name") or author.get("username"),
        "adversary": p.get("adversary"),
        "malware_families": [
            {"display_name": m.get("display_name") or m.get("id")} if isinstance(m, dict) else m
            for m in p.get("malware_families") or []
        ],
        "indicator_count": p.get("indicator_count"),
    }


async def check_cve(value: str) -> dict:
    """CVE indicator: OTX's own record (seen in the wild, public exploits) plus the
    pulses that reference it. The raw answer is ~300 KB (every product and
    reference), so it is trimmed to what the card, Summary and verdict use."""
    cve_id = normalize_cve(value)
    if not cve_id:
        return bad_cve(value, "AlienVault OTX")
    if not secret("ALIENVAULT_API_KEY"):
        return {"error": {"code": "MissingApiKey", "message": "AlienVault OTX API key is not configured."}}

    # OTX takes ~60 s and then answers 504 for a CVE it has no record of, so don't wait for that.
    async with httpx.AsyncClient(timeout=25) as client:
        try:
            r = await client.get(f"{_BASE}/cve/{cve_id}/general", headers={"X-OTX-API-KEY": secret("ALIENVAULT_API_KEY")})
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "AlienVault OTX did not answer within 25 s (it is very slow for CVEs it has no record of)."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach AlienVault OTX."}}

    if r.status_code == 401:
        return {"error": {"code": "Unauthorized", "message": "Invalid AlienVault OTX API key."}}
    if r.status_code == 404:
        return {"error": {"code": "NotFound", "message": "CVE not found in AlienVault OTX."}}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "AlienVault OTX rate limit exceeded."}}
    if r.status_code >= 500:
        return {"error": {"code": "ServiceUnavailable", "message": f"AlienVault OTX is unavailable (HTTP {r.status_code})."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"AlienVault OTX returned HTTP {r.status_code}."}}
    try:
        d = r.json()
    except ValueError:
        return {"error": {"code": "InvalidResponse", "message": "AlienVault OTX returned a non-JSON response."}}

    info = d.get("pulse_info") if isinstance(d.get("pulse_info"), dict) else {}
    pulses = [p for p in info.get("pulses") or [] if isinstance(p, dict)]
    exploits = [e for e in d.get("exploits") or [] if isinstance(e, dict)]
    return {
        "indicator": cve_id,
        "type_title": "CVE",
        "description": d.get("description"),
        "seen_wild": d.get("seen_wild") is True,
        "exploits_total": len(exploits),
        "exploits": [
            {k: e.get(k) for k in ("name", "source", "type", "platform", "date", "url")}
            for e in exploits[:_MAX_CVE_EXPLOITS]
        ],
        "products_total": len(d.get("products") or []),
        "date_created": d.get("date_created"),
        "pulse_info": {
            "count": info.get("count", len(pulses)),
            "pulses": [_trim_pulse(p) for p in pulses[:_MAX_CVE_PULSES]],
            "related": info.get("related") or {},
        },
    }


async def check_threat_actor(actor: str) -> dict:
    if not secret("ALIENVAULT_API_KEY"):
        return {"error": {"code": "MissingApiKey", "message": "AlienVault OTX API key is not configured."}}

    async with httpx.AsyncClient(timeout=25) as client:
        try:
            r = await client.get(
                _SEARCH_PULSES_URL,
                params={"q": actor, "limit": 10},
                headers={"X-OTX-API-KEY": secret("ALIENVAULT_API_KEY")},
            )
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "AlienVault OTX pulse search timed out after 25 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach AlienVault OTX."}}

    if r.status_code == 401:
        return {"error": {"code": "Unauthorized", "message": "Invalid AlienVault OTX API key."}}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "AlienVault OTX rate limit exceeded."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"AlienVault OTX returned HTTP {r.status_code}."}}

    return r.json()


async def dispatch(indicator: str, type: str) -> dict:
    handlers = {
        "ip": check_ip,
        "domain": check_domain,
        "url": check_url,
        "hash": check_hash,
        "threat-actor": check_threat_actor,
        "cve": check_cve,
    }
    handler = handlers.get(type)
    if not handler:
        return {"error": {"code": "UnsupportedType", "message": f"AlienVault OTX does not support type '{type}'."}}
    return await handler(indicator)
