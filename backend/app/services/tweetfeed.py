"""TweetFeed — IOCs shared by the infosec community on X/Twitter (https://tweetfeed.live).

Free, keyless, CC0. Uses the exact-match lookup endpoint, which covers the last
365 days. Unknown indicators come back as HTTP 200 with `found: false`.
"""
import httpx

_LOOKUP_URL = "https://api.tweetfeed.live/v1/ioc"
# Cloudflare bot protection rejects some default client User-Agents with a 403.
_HEADERS = {"User-Agent": "IntelChecker/1.0", "Accept": "application/json"}

_SUPPORTED = {"ip", "domain", "url", "hash"}


async def lookup(value: str) -> dict:
    async with httpx.AsyncClient(timeout=15, headers=_HEADERS) as client:
        try:
            r = await client.get(_LOOKUP_URL, params={"value": value})
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "TweetFeed request timed out after 15 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach TweetFeed."}}

    if r.status_code == 400:
        return {"error": {"code": "BadRequest", "message": "TweetFeed rejected the indicator as malformed."}}
    if r.status_code == 403:
        return {"error": {
            "code": "Forbidden",
            "message": "TweetFeed blocked the request (Cloudflare bot protection). Try again later.",
        }}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "TweetFeed rate limit exceeded."}}
    if r.status_code >= 500:
        return {"error": {"code": "ServiceUnavailable", "message": f"TweetFeed is unavailable (HTTP {r.status_code})."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"TweetFeed returned HTTP {r.status_code}."}}

    try:
        return r.json()
    except ValueError:
        return {"error": {"code": "InvalidResponse", "message": "TweetFeed returned a non-JSON response."}}


async def dispatch(indicator: str, type: str) -> dict:
    if type not in _SUPPORTED:
        return {"error": {"code": "UnsupportedType", "message": f"TweetFeed does not support type '{type}'."}}
    return await lookup(indicator.strip())
