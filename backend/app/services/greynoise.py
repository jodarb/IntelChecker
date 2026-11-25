import httpx
from app.core.connectors import secret

_BASE = "https://api.greynoise.io/v3/community"


async def check_ip(ip: str) -> dict:
    if not secret("GREYNOISE_API_KEY"):
        return {"error": {"code": "MissingApiKey", "message": "GreyNoise API key is not configured."}}

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(f"{_BASE}/{ip}", headers={"key": secret("GREYNOISE_API_KEY")})
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "GreyNoise request timed out after 15 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach GreyNoise."}}

    if r.status_code == 401:
        return {"error": {"code": "Unauthorized", "message": "Invalid GreyNoise API key."}}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "GreyNoise Community API weekly quota exceeded (50 lookups/week)."}}
    # 404 is how the Community API can represent "not observed" for some accounts —
    # the body is still the normal shaped JSON, not an error payload, so fall through.
    if not r.is_success and r.status_code != 404:
        return {"error": {"code": "HttpError", "message": f"GreyNoise returned HTTP {r.status_code}."}}

    return r.json()


async def dispatch(indicator: str, type: str) -> dict:
    if type != "ip":
        return {"error": {"code": "UnsupportedType", "message": f"GreyNoise does not support type '{type}'."}}
    return await check_ip(indicator)
