import httpx
from app.core.config import IPINFO_API_KEY

_BASE = "https://ipinfo.io"


async def check_ip(ip: str) -> dict:
    if not IPINFO_API_KEY:
        return {"error": {"code": "MissingApiKey", "message": "IPinfo API key is not configured."}}

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(
                f"{_BASE}/{ip}",
                headers={
                    "Authorization": f"Bearer {IPINFO_API_KEY}",
                    "Accept": "application/json",
                },
            )
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "IPinfo request timed out after 15 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach IPinfo."}}

    if r.status_code == 401:
        return {"error": {"code": "Unauthorized", "message": "Invalid IPinfo API token."}}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "IPinfo rate limit exceeded."}}
    if r.status_code == 404:
        return {"error": {"code": "NotFound", "message": "IP not found in IPinfo."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"IPinfo returned HTTP {r.status_code}."}}

    return r.json()


async def dispatch(indicator: str, type: str) -> dict:
    if type == "ip":
        return await check_ip(indicator)
    return {"error": {"code": "UnsupportedType", "message": f"IPinfo does not support type '{type}'."}}
