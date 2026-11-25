"""CIRCL Passive DNS — historical DNS resolutions (https://www.circl.lu/services/passive-dns/).

Free for security teams on request: CIRCL issues a username and password. They are
stored as one connector value, `CIRCL_PDNS_CREDENTIALS` = "user:password".

A domain query returns what it resolved to over time; an IP query returns the
names that pointed to it. Answers are NDJSON in the Passive DNS Common Output
Format (rrname, rrtype, rdata, count, time_first, time_last as Unix time). Only the
most recent records are kept, to keep history snapshots small. Context only: DNS
history says how established an indicator is, not whether it is malicious.
"""
import json
from collections import Counter
from urllib.parse import quote

import httpx

from app.core.connectors import secret

_BASE = "https://www.circl.lu/pdns/query/"
_MAX_RECORDS = 100


def _credentials() -> tuple[str, str] | None:
    raw = secret("CIRCL_PDNS_CREDENTIALS")
    if not raw or ":" not in raw:
        return None
    user, password = raw.split(":", 1)
    return (user, password) if user and password else None


def _summarize(query: str, text: str) -> dict:
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("rrname"):
            records.append({k: rec.get(k) for k in ("rrname", "rrtype", "rdata", "count", "time_first", "time_last")})
    records.sort(key=lambda r: r.get("time_last") or 0, reverse=True)
    firsts = [r["time_first"] for r in records if isinstance(r.get("time_first"), (int, float))]
    lasts = [r["time_last"] for r in records if isinstance(r.get("time_last"), (int, float))]
    return {
        "found": bool(records),
        "query": query,
        "total": len(records),
        "distinct_rdata": len({str(r.get("rdata")) for r in records}),
        "rrtypes": dict(Counter(str(r.get("rrtype")) for r in records)),
        "first_seen": min(firsts) if firsts else None,
        "last_seen": max(lasts) if lasts else None,
        "records": records[:_MAX_RECORDS],
    }


async def lookup(query: str) -> dict:
    creds = _credentials()
    if not creds:
        return {"error": {"code": "MissingApiKey", "message": "CIRCL Passive DNS credentials (user:password) are not configured."}}

    async with httpx.AsyncClient(timeout=30, auth=creds, headers={"User-Agent": "IntelChecker/1.0"}) as client:
        try:
            r = await client.get(_BASE + quote(query, safe=""))
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "CIRCL Passive DNS request timed out after 30 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach CIRCL Passive DNS."}}

    if r.status_code in (401, 403):
        return {"error": {"code": "Unauthorized", "message": "Invalid CIRCL Passive DNS credentials."}}
    if r.status_code == 404:
        return _summarize(query, "")
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "CIRCL Passive DNS rate limit exceeded."}}
    if r.status_code >= 500:
        return {"error": {"code": "ServiceUnavailable", "message": f"CIRCL Passive DNS is unavailable (HTTP {r.status_code})."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"CIRCL Passive DNS returned HTTP {r.status_code}."}}
    return _summarize(query, r.text)


async def dispatch(indicator: str, type: str) -> dict:
    if type not in ("domain", "ip"):
        return {"error": {"code": "UnsupportedType", "message": f"CIRCL Passive DNS does not support type '{type}'."}}
    return await lookup(indicator.strip().rstrip(".").lower())
