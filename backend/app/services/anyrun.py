import httpx
from datetime import datetime, timedelta
from app.core.connectors import secret

_BASE = "https://api.any.run/v1"
_LOOKBACK_DAYS = 180  # matches the ANY.RUN SDK's own default lookup window

_QUERY_FIELD = {
    "ip": "destinationIP",
    "domain": "domainName",
    "url": "url",
}


def _hash_field(value: str) -> str:
    if len(value) == 64:
        return "sha256"
    if len(value) == 40:
        return "sha1"
    return "md5"


async def _search(field: str, value: str) -> dict:
    if not secret("ANYRUN_API_KEY"):
        return {"error": {"code": "MissingApiKey", "message": "ANY.RUN API key is not configured."}}

    today = datetime.utcnow().date()
    body = {
        "query": f'{field}:"{value}"',
        "startDate": (today - timedelta(days=_LOOKBACK_DAYS)).isoformat(),
        "endDate": today.isoformat(),
    }
    # ANY.RUN expects the raw key prefixed with "API-KEY " in the Authorization header.
    headers = {"Authorization": f"API-KEY {secret('ANYRUN_API_KEY')}"}

    async with httpx.AsyncClient(timeout=20) as client:
        try:
            r = await client.post(f"{_BASE}/intelligence/api/search", json=body, headers=headers)
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "ANY.RUN request timed out after 20 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach ANY.RUN."}}

    if r.status_code == 401:
        return {"error": {"code": "Unauthorized", "message": "Invalid ANY.RUN API key."}}
    if r.status_code == 403:
        return {"error": {"code": "Forbidden", "message": "ANY.RUN API key does not have TI Lookup access."}}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "ANY.RUN rate limit exceeded."}}
    if not r.is_success:
        try:
            detail = r.json().get("message") or r.json().get("description")
        except ValueError:
            detail = None
        return {"error": {"code": "HttpError", "message": detail or f"ANY.RUN returned HTTP {r.status_code}."}}

    return r.json()


async def check_ip(ip: str) -> dict:
    return await _search(_QUERY_FIELD["ip"], ip)


async def check_domain(domain: str) -> dict:
    return await _search(_QUERY_FIELD["domain"], domain)


async def check_url(url: str) -> dict:
    return await _search(_QUERY_FIELD["url"], url)


async def check_hash(hash_value: str) -> dict:
    return await _search(_hash_field(hash_value), hash_value)


async def dispatch(indicator: str, type: str) -> dict:
    handlers = {
        "ip": check_ip,
        "domain": check_domain,
        "url": check_url,
        "hash": check_hash,
    }
    handler = handlers.get(type)
    if not handler:
        return {"error": {"code": "UnsupportedType", "message": f"ANY.RUN does not support type '{type}'."}}
    return await handler(indicator)
