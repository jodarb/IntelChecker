import httpx
from app.core.connectors import secret


async def check_ip(ip: str) -> dict:
    if not secret("ABUSEIPDB_API_KEY"):
        return {"error": {"code": "MissingApiKey", "message": "AbuseIPDB API key is not configured."}}

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": secret("ABUSEIPDB_API_KEY"), "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            )
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "AbuseIPDB request timed out after 15 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach AbuseIPDB."}}

    if r.status_code == 401:
        return {"error": {"code": "Unauthorized", "message": "Invalid AbuseIPDB API key."}}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "AbuseIPDB rate limit exceeded."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"AbuseIPDB returned HTTP {r.status_code}."}}

    return r.json()


async def dispatch(indicator: str, type: str) -> dict:
    if type == "ip":
        return await check_ip(indicator)
    return {"error": {"code": "UnsupportedType", "message": f"AbuseIPDB does not support type '{type}'."}}
