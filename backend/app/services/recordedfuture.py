from urllib.parse import quote
import httpx
from app.core.connectors import secret

_BASE = "https://api.recordedfuture.com/v2"
_FIELDS = "risk,timestamps,entity,intelCard"


async def _request(entity_type: str, indicator: str) -> dict:
    if not secret("RECORDED_FUTURE_API_KEY"):
        return {"error": {"code": "MissingApiKey", "message": "Recorded Future API token is not configured."}}

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(
                f"{_BASE}/{entity_type}/{quote(indicator, safe='')}",
                params={"fields": _FIELDS},
                headers={"X-RFToken": secret("RECORDED_FUTURE_API_KEY"), "Accept": "application/json"},
            )
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "Recorded Future request timed out after 15 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach Recorded Future."}}

    if r.status_code == 401:
        return {"error": {"code": "Unauthorized", "message": "Invalid Recorded Future API token."}}
    if r.status_code == 404:
        return {"error": {"code": "NotFound", "message": "Indicator not found in Recorded Future."}}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "Recorded Future API rate limit exceeded."}}
    if not r.is_success:
        # Error bodies aren't always JSON (e.g. 401 returns a plain text message).
        try:
            detail = r.json().get("error", {}).get("message", "")
        except ValueError:
            detail = r.text[:200]
        return {"error": {"code": "HttpError", "message": f"Recorded Future returned HTTP {r.status_code}." + (f" {detail}" if detail else "")}}

    payload = r.json()
    return payload.get("data", payload)


async def dispatch(indicator: str, type: str) -> dict:
    handlers = {
        "ip": "ip",
        "domain": "domain",
        "url": "url",
        "hash": "hash",
    }
    entity_type = handlers.get(type)
    if not entity_type:
        return {"error": {"code": "UnsupportedType", "message": f"Recorded Future does not support type '{type}'."}}
    return await _request(entity_type, indicator)
