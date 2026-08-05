import time
import asyncio
import logging
import httpx

_URL = "https://www.dan.me.uk/torlist/?exit"
_TTL_SECONDS = 1800  # dan.me.uk's usage policy asks for no more than one fetch every 30 minutes
_HEADERS = {"User-Agent": "IntelChecker/1.0 (internal CTI triage tool)"}

_cache: set[str] = set()
_cache_fetched_at: float = 0.0
_last_error: dict | None = None

_log = logging.getLogger(__name__)


def _parse(text: str) -> set[str]:
    return {
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    }


async def _refresh() -> None:
    global _cache, _cache_fetched_at, _last_error

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(_URL, headers=_HEADERS)
        except httpx.TimeoutException:
            _last_error = {"code": "Timeout", "message": "Tor exit node list request timed out after 15 s."}
            return
        except httpx.RequestError:
            _last_error = {"code": "NetworkError", "message": "Could not reach dan.me.uk."}
            return

    if r.status_code == 403:
        _last_error = {
            "code": "RateLimitExceeded",
            "message": "dan.me.uk rate limit: this list can only be fetched once every 30 minutes. Try again later.",
        }
        return
    if not r.is_success:
        _last_error = {"code": "HttpError", "message": f"dan.me.uk returned HTTP {r.status_code}."}
        return

    _cache = _parse(r.text)
    _cache_fetched_at = time.time()
    _last_error = None


async def start_background_refresh() -> None:
    """Keeps the exit-node list warm in the background so per-request lookups never
    trigger a live fetch (and dan.me.uk's 30-minute rate limit) themselves — fetched
    once at startup, then re-fetched on the same cadence as the list's own TTL."""
    while True:
        await _refresh()
        if _last_error and not _cache:
            _log.warning("Tor exit node list refresh failed: %s", _last_error["message"])
        await asyncio.sleep(_TTL_SECONDS)


async def check_ip(ip: str) -> dict:
    if not _cache:
        if _last_error:
            return {"error": _last_error}
        return {"error": {
            "code": "ServiceUnavailable",
            "message": "Tor exit node list is still loading, try again in a few seconds.",
        }}

    return {
        "ip": ip,
        "is_tor_exit": ip in _cache,
        "list_size": len(_cache),
        "list_updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(_cache_fetched_at)),
        "source": _URL,
    }


async def dispatch(indicator: str, type: str) -> dict:
    if type == "ip":
        return await check_ip(indicator)
    return {"error": {"code": "UnsupportedType", "message": f"Tor Exit Node List does not support type '{type}'."}}
