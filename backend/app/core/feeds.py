"""Downloaded lists kept in memory (SSLBL, OpenPhish, Spamhaus ASN-DROP, CISA KEV,
ransomware.live victims).

A feed is fetched on the first lookup that needs it and re-fetched once its TTL has
passed, under a lock so concurrent lookups share one download. If a refresh fails
the previous copy keeps being used; only a feed that was never loaded reports the
error. Lookups are still real time — this only avoids re-downloading a whole list
per indicator. `retry_after` spaces out failed downloads for sources that throttle
them (ransomware.live: once every 30 min per IP); the last error is returned meanwhile.

`persist` also keeps the last good download on disk (backend/data/feeds/, a Docker
volume), so a restart starts from it instead of an empty cache: no re-download while
it is within its TTL, and a stale copy is still served if the refresh fails (a
restarted backend would otherwise wait out ransomware.live's 30-minute limit).
"""
import asyncio
import gzip
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable

import httpx

_HEADERS = {"User-Agent": "IntelChecker/1.0 (internal CTI triage tool)"}
_DIR = Path(__file__).parent.parent.parent / "data" / "feeds"
_log = logging.getLogger(__name__)


class CachedFeed:
    def __init__(self, name: str, url: str, ttl: int, parse: Callable[[str], Any],
                 count: Callable[[Any], int] = len, timeout: float = 30, retry_after: float = 0,
                 persist: str | None = None, rate_limit_status: tuple[int, ...] = (429,)):
        self.name, self.url, self.ttl, self._parse, self._count = name, url, ttl, parse, count
        self.timeout, self.retry_after = timeout, retry_after
        self._path = _DIR / f"{persist}.gz" if persist else None
        self._disk_checked = False
        # HTTP statuses that mean "too many downloads" (dan.me.uk answers 403).
        self._rate_limit_status = rate_limit_status
        self._failed_at, self._last_error = 0.0, None
        self.data: Any = None
        self.size = 0
        self.fetched_at = 0.0
        self._lock = asyncio.Lock()

    @property
    def last_error(self) -> dict | None:
        """Why the last download failed (None after a good one)."""
        return self._last_error

    @property
    def retrying_in(self) -> float:
        """Seconds until a download may be tried again (0: now)."""
        if self._last_error is None:
            return max(0.0, self.fetched_at + self.ttl - time.time())
        return max(0.0, self._failed_at + self.retry_after - time.time())

    @property
    def updated(self) -> str | None:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.fetched_at)) if self.fetched_at else None

    async def get(self) -> dict | None:
        """None when the feed is ready (read `.data`), or {"error": …}."""
        async with self._lock:
            if self.data is None and self._path and not self._disk_checked:
                self._disk_checked = True
                await asyncio.to_thread(self._load)
            now = time.time()
            if self.data is not None and now - self.fetched_at < self.ttl:
                return None
            if self._last_error and now - self._failed_at < self.retry_after:
                return {"error": self._last_error} if self.data is None else None
            err = await self._refresh()
            self._failed_at, self._last_error = (now, err) if err else (0.0, None)
            if err and self.data is None:
                return {"error": err}
            return None

    async def _refresh(self) -> dict | None:
        try:
            async with httpx.AsyncClient(timeout=self.timeout, headers=_HEADERS, follow_redirects=True) as client:
                r = await client.get(self.url)
        except httpx.TimeoutException:
            return {"code": "Timeout", "message": f"Downloading the {self.name} list timed out."}
        except httpx.RequestError:
            return {"code": "NetworkError", "message": f"Could not download the {self.name} list."}
        if r.status_code in self._rate_limit_status:
            return {"code": "RateLimitExceeded", "message": f"{self.name} rate limit exceeded while downloading the list."}
        if not r.is_success:
            return {"code": "HttpError", "message": f"{self.name} list download returned HTTP {r.status_code}."}
        try:
            data = self._parse(r.text)
        except (ValueError, KeyError, TypeError):
            return {"code": "InvalidResponse", "message": f"The {self.name} list could not be parsed."}
        self.data, self.size, self.fetched_at = data, self._count(data), time.time()
        if self._path:
            await asyncio.to_thread(self._save, r.text)
        return None

    # ── Disk copy ───────────────────────────────────────────────────────────

    def _load(self) -> None:
        """The last good download, with the time it was fetched (the file's mtime)."""
        try:
            fetched_at = self._path.stat().st_mtime
            data = self._parse(gzip.decompress(self._path.read_bytes()).decode("utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError, KeyError, TypeError, EOFError) as e:
            _log.warning("Ignoring the saved %s list (%s): %s", self.name, self._path, e)
            return
        self.data, self.size, self.fetched_at = data, self._count(data), fetched_at

    def _save(self, text: str) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            tmp.write_bytes(gzip.compress(text.encode("utf-8"), compresslevel=6))
            os.replace(tmp, self._path)   # atomic: a crash never leaves half a file
            os.utime(self._path, (self.fetched_at, self.fetched_at))
        except OSError as e:
            _log.warning("Could not save the %s list to %s: %s", self.name, self._path, e)
