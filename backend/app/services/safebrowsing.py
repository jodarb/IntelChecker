import httpx
from app.core.connectors import secret

_BASE = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]


async def check_url(url: str) -> dict:
    if not secret("GOOGLE_SAFE_BROWSING_API_KEY"):
        return {"error": {"code": "MissingApiKey", "message": "Google Safe Browsing API key is not configured."}}

    body = {
        "client": {"clientId": "intelchecker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": _THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.post(_BASE, params={"key": secret("GOOGLE_SAFE_BROWSING_API_KEY")}, json=body)
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "Google Safe Browsing request timed out after 15 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach Google Safe Browsing."}}

    if r.status_code in (400, 403):
        try:
            detail = r.json().get("error", {}).get("message")
        except ValueError:
            detail = None
        return {"error": {"code": "Unauthorized", "message": detail or "Invalid Google Safe Browsing API key."}}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "Google Safe Browsing rate limit exceeded."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"Google Safe Browsing returned HTTP {r.status_code}."}}

    return r.json()


async def dispatch(indicator: str, type: str) -> dict:
    if type != "url":
        return {"error": {"code": "UnsupportedType", "message": f"Google Safe Browsing does not support type '{type}'."}}
    return await check_url(indicator)
