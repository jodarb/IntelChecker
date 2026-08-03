import httpx
from app.core.config import PHISHTANK_API_KEY

_URL = "https://checkurl.phishtank.com/checkurl/"
# PhishTank's Cloudflare front-end 403s any User-Agent that doesn't contain "phishtank" —
# confirmed empirically: generic/browser UAs get blocked, "phishtank/<app>" passes.
_HEADERS = {"User-Agent": "phishtank/intelchecker"}


async def check_url(url: str) -> dict:
    data = {"url": url, "format": "json"}
    if PHISHTANK_API_KEY:
        data["app_key"] = PHISHTANK_API_KEY

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.post(_URL, data=data, headers=_HEADERS)
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "PhishTank request timed out after 15 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach PhishTank."}}

    if r.status_code == 403:
        return {"error": {"code": "Blocked", "message": "PhishTank blocked this request (Cloudflare)."}}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "PhishTank rate limit exceeded."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"PhishTank returned HTTP {r.status_code}."}}

    payload = r.json()
    if payload.get("meta", {}).get("status") == "error":
        message = payload.get("errortext", "PhishTank query failed.")
        return {"error": {"code": "ApiError", "message": message}}

    return payload.get("results", {})


async def dispatch(indicator: str, type: str) -> dict:
    if type != "url":
        return {"error": {"code": "UnsupportedType", "message": f"PhishTank does not support type '{type}'."}}
    return await check_url(indicator)
