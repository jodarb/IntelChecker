from urllib.parse import quote
import httpx
from app.core.config import ALIENVAULT_API_KEY

_BASE = "https://otx.alienvault.com/api/v1/indicators"
_SEARCH_PULSES_URL = "https://otx.alienvault.com/api/v1/search/pulses"


async def _request(path: str) -> dict:
    if not ALIENVAULT_API_KEY:
        return {"error": {"code": "MissingApiKey", "message": "AlienVault OTX API key is not configured."}}

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(
                f"{_BASE}/{path}",
                headers={"X-OTX-API-KEY": ALIENVAULT_API_KEY},
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


async def check_threat_actor(actor: str) -> dict:
    if not ALIENVAULT_API_KEY:
        return {"error": {"code": "MissingApiKey", "message": "AlienVault OTX API key is not configured."}}

    async with httpx.AsyncClient(timeout=25) as client:
        try:
            r = await client.get(
                _SEARCH_PULSES_URL,
                params={"q": actor, "limit": 10},
                headers={"X-OTX-API-KEY": ALIENVAULT_API_KEY},
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
    }
    handler = handlers.get(type)
    if not handler:
        return {"error": {"code": "UnsupportedType", "message": f"AlienVault OTX does not support type '{type}'."}}
    return await handler(indicator)
