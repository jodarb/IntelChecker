"""Tranco — research-grade ranking of the top 1M most popular domains
(https://tranco-list.eu). Free and keyless.

A domain that has been in the top 100k for the last 30 days is very unlikely to be
attacker infrastructure, so it's the domain source that can give an explicit
*clean* verdict. Two caveats, both handled in the verdict engine and the card:

  * Only the registered domain is ranked. A subdomain ("evil.duckdns.org",
    "phish.blogspot.com") inherits nothing: free hosting and dynamic DNS parents
    are very popular. Those lookups are returned with `exact: false` and only
    count as context.
  * Popular ≠ safe content: legitimate services host abuse. That's why the risk
    weight is low.

The API allows about one request per second per client, so requests are spaced.
"""
import asyncio
import time

import httpx

from app.core.domains import host_of, registered_domain

_API = "https://tranco-list.eu/api/ranks/domain/{}"
_HEADERS = {"User-Agent": "IntelChecker/1.0", "Accept": "application/json"}
_MIN_INTERVAL = 1.1

_lock = asyncio.Lock()
_last_request = 0.0


async def _get(client: httpx.AsyncClient, domain: str) -> httpx.Response:
    global _last_request
    async with _lock:
        wait = _MIN_INTERVAL - (time.monotonic() - _last_request)
        if wait > 0:
            await asyncio.sleep(wait)
        try:
            return await client.get(_API.format(domain))
        finally:
            _last_request = time.monotonic()


async def lookup(indicator: str) -> dict:
    host = host_of(indicator, "domain")
    domain = registered_domain(host)
    if not domain:
        return {"error": {"code": "BadRequest", "message": f"'{host or indicator}' has no registrable domain."}}

    async with httpx.AsyncClient(timeout=20, headers=_HEADERS) as client:
        try:
            r = await _get(client, domain)
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "Tranco request timed out."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach Tranco."}}

    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "Tranco rate limit exceeded (about one lookup per second)."}}
    if r.status_code >= 500:
        return {"error": {"code": "ServiceUnavailable", "message": f"Tranco is unavailable (HTTP {r.status_code})."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"Tranco returned HTTP {r.status_code}."}}
    try:
        data = r.json()
    except ValueError:
        return {"error": {"code": "InvalidResponse", "message": "Tranco returned a non-JSON response."}}

    ranks = [
        {"date": x.get("date"), "rank": x.get("rank")}
        for x in (data.get("ranks") if isinstance(data, dict) else None) or []
        if isinstance(x, dict) and isinstance(x.get("rank"), int)
    ]
    ranks.sort(key=lambda x: str(x["date"]), reverse=True)
    return {
        "host": host,
        "domain": domain,
        # The ranking applies to what was asked only if it *is* the registered domain.
        "exact": host in (domain, f"www.{domain}"),
        "found": bool(ranks),
        "rank": ranks[0]["rank"] if ranks else None,
        "date": ranks[0]["date"] if ranks else None,
        "best_rank": min(x["rank"] for x in ranks) if ranks else None,
        "days_listed": len(ranks),
        "ranks": ranks,
        "link": f"https://tranco-list.eu/query#{domain}",
    }


async def dispatch(indicator: str, type: str) -> dict:
    if type != "domain":
        return {"error": {"code": "UnsupportedType", "message": f"Tranco does not support type '{type}'."}}
    return await lookup(indicator)
