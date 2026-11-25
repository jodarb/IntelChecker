"""CrowdSec CTI — IP reputation from the CrowdSec network's real attack signals
(https://www.crowdsec.net/cti). Needs a CTI API key (free Community key: small
monthly quota — see docs/sources.md).

`reputation` is malicious / suspicious / known / safe / benign / unknown. An IP the
network has never reported is HTTP 404: returned as `{"found": false}`.
"""
import httpx

from app.core.connectors import secret

_BASE = "https://cti.api.crowdsec.net/v2/smoke"


async def check_ip(ip: str) -> dict:
    key = secret("CROWDSEC_API_KEY")
    if not key:
        return {"error": {"code": "MissingApiKey", "message": "CrowdSec CTI API key is not configured."}}

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(f"{_BASE}/{ip}", headers={"x-api-key": key, "User-Agent": "IntelChecker/1.0"})
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "CrowdSec CTI request timed out after 15 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach CrowdSec CTI."}}

    if r.status_code == 404:
        return {"found": False, "ip": ip}
    if r.status_code in (401, 403):
        return {"error": {"code": "Unauthorized", "message": "Invalid CrowdSec CTI API key."}}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "CrowdSec CTI quota exceeded for this API key."}}
    if r.status_code == 400:
        return {"error": {"code": "BadRequest", "message": "CrowdSec CTI rejected the IP address as malformed."}}
    if r.status_code >= 500:
        return {"error": {"code": "ServiceUnavailable", "message": f"CrowdSec CTI is unavailable (HTTP {r.status_code})."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"CrowdSec CTI returned HTTP {r.status_code}."}}
    try:
        data = r.json()
    except ValueError:
        return {"error": {"code": "InvalidResponse", "message": "CrowdSec CTI returned a non-JSON response."}}
    if not isinstance(data, dict):
        return {"error": {"code": "InvalidResponse", "message": "CrowdSec CTI returned an unexpected response."}}
    return {"found": True, **data}


async def dispatch(indicator: str, type: str) -> dict:
    if type != "ip":
        return {"error": {"code": "UnsupportedType", "message": f"CrowdSec CTI does not support type '{type}'."}}
    return await check_ip(indicator.strip())
