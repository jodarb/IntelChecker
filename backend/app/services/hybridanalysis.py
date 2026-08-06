import httpx
from app.core.config import HYBRID_ANALYSIS_API_KEY

_BASE = "https://hybrid-analysis.com/api/v2"


def _headers() -> dict:
    # Hybrid Analysis rejects requests without a recognized User-Agent, regardless
    # of API key validity.
    return {"api-key": HYBRID_ANALYSIS_API_KEY, "User-Agent": "Falcon Sandbox"}


def _error_for_status(status_code: int) -> dict | None:
    if status_code in (401, 403):
        return {"error": {"code": "Unauthorized", "message": "Invalid Hybrid Analysis API key."}}
    if status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "Hybrid Analysis rate limit exceeded."}}
    if status_code >= 400:
        return {"error": {"code": "HttpError", "message": f"Hybrid Analysis returned HTTP {status_code}."}}
    return None


async def _search_terms(field: str, value: str) -> dict:
    if not HYBRID_ANALYSIS_API_KEY:
        return {"error": {"code": "MissingApiKey", "message": "Hybrid Analysis API key is not configured."}}

    async with httpx.AsyncClient(timeout=20) as client:
        try:
            r = await client.post(
                f"{_BASE}/search/terms",
                data={field: value},
                headers={**_headers(), "Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "Hybrid Analysis request timed out after 20 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach Hybrid Analysis."}}

    error = _error_for_status(r.status_code)
    if error:
        return error

    payload = r.json()
    results = payload.get("result", []) if isinstance(payload, dict) else (payload or [])
    return {"count": len(results), "result": results}


async def check_ip(ip: str) -> dict:
    return await _search_terms("host", ip)


async def check_domain(domain: str) -> dict:
    return await _search_terms("domain", domain)


async def check_url(url: str) -> dict:
    return await _search_terms("url", url)


async def check_hash(hash_value: str) -> dict:
    if not HYBRID_ANALYSIS_API_KEY:
        return {"error": {"code": "MissingApiKey", "message": "Hybrid Analysis API key is not configured."}}

    async with httpx.AsyncClient(timeout=20) as client:
        try:
            r = await client.get(f"{_BASE}/search/hash", params={"hash": hash_value}, headers=_headers())
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "Hybrid Analysis request timed out after 20 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach Hybrid Analysis."}}

    error = _error_for_status(r.status_code)
    if error:
        return error

    payload = r.json()
    results = payload if isinstance(payload, list) else payload.get("result", [])
    return {"count": len(results), "result": results}


async def dispatch(indicator: str, type: str) -> dict:
    handlers = {
        "ip": check_ip,
        "domain": check_domain,
        "url": check_url,
        "hash": check_hash,
    }
    handler = handlers.get(type)
    if not handler:
        return {"error": {"code": "UnsupportedType", "message": f"Hybrid Analysis does not support type '{type}'."}}
    return await handler(indicator)
