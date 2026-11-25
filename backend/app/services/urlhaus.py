import httpx
from app.core.connectors import secret

_BASE = "https://urlhaus-api.abuse.ch/v1"


async def _post(path: str, data: dict) -> dict:
    if not secret("ABUSECH_AUTH_KEY"):
        return {"error": {"code": "MissingApiKey", "message": "abuse.ch API key is not configured."}}

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.post(f"{_BASE}{path}", data=data, headers={"Auth-Key": secret("ABUSECH_AUTH_KEY")})
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "URLhaus request timed out after 15 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach URLhaus."}}

    if r.status_code == 401:
        return {"error": {"code": "Unauthorized", "message": "Invalid abuse.ch API key."}}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "URLhaus rate limit exceeded."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"URLhaus returned HTTP {r.status_code}."}}

    payload = r.json()
    query_status = payload.get("query_status", "")

    if query_status == "no_results":
        return {"query_status": "no_results"}
    if query_status != "ok":
        return {"error": {"code": "ApiError", "message": f"URLhaus error: {query_status}"}}

    return payload


async def check_url(url: str) -> dict:
    return await _post("/url/", {"url": url})


async def check_host(host: str) -> dict:
    return await _post("/host/", {"host": host})


async def check_hash(hash_value: str) -> dict:
    key = "sha256_hash" if len(hash_value) == 64 else "md5_hash"
    return await _post("/payload/", {key: hash_value})


async def dispatch(indicator: str, type: str) -> dict:
    handlers = {
        "url": check_url,
        "ip": check_host,
        "domain": check_host,
        "hash": check_hash,
    }
    handler = handlers.get(type)
    if not handler:
        return {"error": {"code": "UnsupportedType", "message": f"URLhaus does not support type '{type}'."}}
    return await handler(indicator)
