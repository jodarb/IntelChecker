import base64
import httpx
from app.core.config import VIRUSTOTAL_API_KEY

_BASE = "https://www.virustotal.com/api/v3"


async def _request(path: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {"error": {"code": "MissingApiKey", "message": "VirusTotal API key is not configured."}}

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(f"{_BASE}/{path}", headers={"x-apikey": VIRUSTOTAL_API_KEY})
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "VirusTotal request timed out after 15 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach VirusTotal."}}

    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "VirusTotal API rate limit exceeded. Free tier allows 4 requests/min — wait a moment and retry."}}
    if r.status_code == 401:
        return {"error": {"code": "Unauthorized", "message": "Invalid VirusTotal API key."}}
    if r.status_code == 404:
        return {"error": {"code": "NotFound", "message": "Indicator not found in VirusTotal."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"VirusTotal returned HTTP {r.status_code}."}}

    payload = r.json()
    if "error" in payload:
        code = payload["error"].get("code", "ApiError")
        msg = payload["error"].get("message", "Unknown VirusTotal API error.")
        if code == "QuotaExceededError":
            msg = "VirusTotal API rate limit exceeded. Free tier allows 4 requests/min — wait a moment and retry."
        return {"error": {"code": code, "message": msg}}

    return payload


async def check_ip(ip: str) -> dict:
    return await _request(f"ip_addresses/{ip}")


async def check_domain(domain: str) -> dict:
    return await _request(f"domains/{domain}")


async def check_url(url: str) -> dict:
    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    return await _request(f"urls/{url_id}")


async def check_hash(hash_value: str) -> dict:
    return await _request(f"files/{hash_value}")


async def dispatch(indicator: str, type: str) -> dict:
    handlers = {
        "ip": check_ip,
        "domain": check_domain,
        "url": check_url,
        "hash": check_hash,
    }
    handler = handlers.get(type)
    if not handler:
        return {"error": {"code": "UnsupportedType", "message": f"VirusTotal does not support type '{type}'."}}
    return await handler(indicator)
