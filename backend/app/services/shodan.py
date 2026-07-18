import re
import httpx
from app.core.config import SHODAN_API_KEY

_BASE = "https://api.shodan.io"


def _normalize_asn(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    return f"AS{digits}" if digits else value.upper()


async def _get(path: str, params: dict) -> dict:
    if not SHODAN_API_KEY:
        return {"error": {"code": "MissingApiKey", "message": "Shodan API key is not configured."}}

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(f"{_BASE}{path}", params={**params, "key": SHODAN_API_KEY})
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "Shodan request timed out after 15 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach Shodan."}}

    if r.status_code == 401:
        return {"error": {"code": "Unauthorized", "message": "Invalid Shodan API key."}}
    if r.status_code == 404:
        return {"error": {"code": "NotFound", "message": "Indicator not found in Shodan."}}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "Shodan API rate limit exceeded."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"Shodan returned HTTP {r.status_code}."}}

    return r.json()


async def check_ip(ip: str) -> dict:
    return await _get(f"/shodan/host/{ip}", {"minify": "false"})


async def check_asn(asn: str) -> dict:
    query = f"asn:{_normalize_asn(asn)}"
    return await _get("/shodan/host/count", {"query": query, "facets": "port,org,country"})


async def dispatch(indicator: str, type: str) -> dict:
    if type == "ip":
        return await check_ip(indicator)
    if type == "asn":
        return await check_asn(indicator)
    return {"error": {"code": "UnsupportedType", "message": f"Shodan does not support type '{type}'."}}
