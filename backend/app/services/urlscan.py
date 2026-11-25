import httpx
from app.core.connectors import secret

_BASE = "https://urlscan.io/api/v1"


async def _search(query: str) -> dict:
    if not secret("URLSCAN_API_KEY"):
        return {"error": {"code": "MissingApiKey", "message": "urlscan.io API key is not configured."}}

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(
                f"{_BASE}/search/",
                params={"q": query, "size": 10},
                headers={"API-Key": secret("URLSCAN_API_KEY")},
            )
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "urlscan.io request timed out after 15 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach urlscan.io."}}

    if r.status_code == 401:
        return {"error": {"code": "Unauthorized", "message": "Invalid urlscan.io API key."}}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "urlscan.io rate limit exceeded."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"urlscan.io returned HTTP {r.status_code}."}}

    return r.json()


async def check_url(url: str) -> dict:
    return await _search(f'page.url:"{url}"')


async def check_domain(domain: str) -> dict:
    return await _search(f'page.domain:"{domain}"')


async def dispatch(indicator: str, type: str) -> dict:
    handlers = {
        "url": check_url,
        "domain": check_domain,
    }
    handler = handlers.get(type)
    if not handler:
        return {"error": {"code": "UnsupportedType", "message": f"urlscan.io does not support type '{type}'."}}
    return await handler(indicator)
