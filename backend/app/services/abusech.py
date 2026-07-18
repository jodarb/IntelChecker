import httpx
from app.core.config import ABUSECH_AUTH_KEY

_URL = "https://threatfox-api.abuse.ch/api/v1/"


async def _query(search_term: str) -> dict:
    if not ABUSECH_AUTH_KEY:
        return {"error": {"code": "MissingApiKey", "message": "abuse.ch API key is not configured."}}

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.post(
                _URL,
                json={"query": "search_ioc", "search_term": search_term},
                headers={"Auth-Key": ABUSECH_AUTH_KEY},
            )
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "ThreatFox request timed out after 15 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach ThreatFox."}}

    if r.status_code == 401:
        return {"error": {"code": "Unauthorized", "message": "Invalid abuse.ch API key."}}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "ThreatFox rate limit exceeded."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"ThreatFox returned HTTP {r.status_code}."}}

    data = r.json()
    query_status = data.get("query_status", "")

    if query_status == "no_result":
        return {"query_status": "no_result", "data": []}
    if query_status != "ok":
        return {"error": {"code": "ApiError", "message": f"ThreatFox error: {query_status}"}}

    return data


async def check_ip(ip: str) -> dict:
    return await _query(ip)


async def check_hash(hash_value: str) -> dict:
    return await _query(hash_value)


async def dispatch(indicator: str, type: str) -> dict:
    handlers = {"ip": check_ip, "hash": check_hash}
    handler = handlers.get(type)
    if not handler:
        return {"error": {"code": "UnsupportedType", "message": f"ThreatFox does not support type '{type}'."}}
    return await handler(indicator)
