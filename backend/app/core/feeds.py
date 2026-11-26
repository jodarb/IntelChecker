"""Downloaded blocklists kept in memory (SSLBL, OpenPhish, Spamhaus ASN-DROP, CISA KEV).

A feed is fetched on the first lookup that needs it and re-fetched once its TTL has
passed, under a lock so concurrent lookups share one download. If a refresh fails
the previous copy keeps being used; only a feed that was never loaded reports the
error. Lookups are still real time — this only avoids re-downloading a whole list
per indicator.
"""
import asyncio
import time
from typing import Any, Callable

import httpx

_HEADERS = {"User-Agent": "IntelChecker/1.0 (internal CTI triage tool)"}


class CachedFeed:
    def __init__(self, name: str, url: str, ttl: int, parse: Callable[[str], Any],
                 count: Callable[[Any], int] = len):
        self.name, self.url, self.ttl, self._parse, self._count = name, url, ttl, parse, count
        self.data: Any = None
        self.size = 0
        self.fetched_at = 0.0
        self._lock = asyncio.Lock()

    @property
    def updated(self) -> str | None:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.fetched_at)) if self.fetched_at else None

    async def get(self) -> dict | None:
        """None when the feed is ready (read `.data`), or {"error": …}."""
        async with self._lock:
            if self.data is not None and time.time() - self.fetched_at < self.ttl:
                return None
            err = await self._refresh()
            if err and self.data is None:
                return {"error": err}
            return None

    async def _refresh(self) -> dict | None:
        try:
            async with httpx.AsyncClient(timeout=30, headers=_HEADERS, follow_redirects=True) as client:
                r = await client.get(self.url)
        except httpx.TimeoutException:
            return {"code": "Timeout", "message": f"Downloading the {self.name} list timed out."}
        except httpx.RequestError:
            return {"code": "NetworkError", "message": f"Could not download the {self.name} list."}
        if r.status_code == 429:
            return {"code": "RateLimitExceeded", "message": f"{self.name} rate limit exceeded while downloading the list."}
        if not r.is_success:
            return {"code": "HttpError", "message": f"{self.name} list download returned HTTP {r.status_code}."}
        try:
            data = self._parse(r.text)
        except (ValueError, KeyError, TypeError):
            return {"code": "InvalidResponse", "message": f"The {self.name} list could not be parsed."}
        self.data, self.size, self.fetched_at = data, self._count(data), time.time()
        return None
