import asyncio
import logging
import time

from app.core.feeds import CachedFeed

_URL = "https://www.dan.me.uk/torlist/?exit"
_TTL_SECONDS = 1800  # dan.me.uk's usage policy asks for no more than one fetch every 30 minutes

_log = logging.getLogger(__name__)


def _parse(text: str) -> set[str]:
    ips = {
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    }
    if not ips:
        raise ValueError("empty Tor exit node list")
    return ips


# The last good list is also kept in backend/data/feeds/, so a restart starts from it
# instead of waiting out dan.me.uk's 30-minute limit (it answers 403 when exceeded).
_feed = CachedFeed("Tor exit node list (dan.me.uk)", _URL, _TTL_SECONDS, _parse, timeout=15,
                   retry_after=_TTL_SECONDS, persist="tor-exit-nodes", rate_limit_status=(403, 429))


async def start_background_refresh() -> None:
    """Keeps the exit-node list warm in the background so per-request lookups never
    trigger a live fetch (and dan.me.uk's 30-minute rate limit) themselves — loaded at
    startup (from the saved copy when it is recent), then re-fetched as it expires."""
    while True:
        await _feed.get()
        if _feed.last_error and _feed.data is None:
            _log.warning("Tor exit node list refresh failed: %s", _feed.last_error["message"])
        await asyncio.sleep(max(60.0, _feed.retrying_in + 5))


async def check_ip(ip: str) -> dict:
    if _feed.data is None:
        if _feed.last_error:
            return {"error": _feed.last_error}
        return {"error": {
            "code": "ServiceUnavailable",
            "message": "Tor exit node list is still loading, try again in a few seconds.",
        }}

    return {
        "ip": ip,
        "is_tor_exit": ip in _feed.data,
        "list_size": _feed.size,
        "list_updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(_feed.fetched_at)),
        "source": _URL,
    }


async def dispatch(indicator: str, type: str) -> dict:
    if type == "ip":
        return await check_ip(indicator)
    return {"error": {"code": "UnsupportedType", "message": f"Tor Exit Node List does not support type '{type}'."}}
