"""Have I Been Pwned — public data breaches of a company's own services, by domain
(https://haveibeenpwned.com/API/v3#BreachesForDomain). Free, no key: this endpoint
lists breaches *of the site* (e.g. adobe.com's 2013 breach), not the company's
employees found in other breaches, which needs domain verification.

Breach descriptions come as HTML; tags are stripped. Spam lists and fabricated
breaches are flagged by HIBP and kept with their flags so the card can show them.
"""
import asyncio
import html
import re
import time
from datetime import datetime, timezone

import httpx

from app.core import company

_API = "https://haveibeenpwned.com/api/v3/breaches"
_SOURCE = "Have I Been Pwned"
_TAG = re.compile(r"<[^>]+>")


def _days_since(date: str | None, now: float) -> int | None:
    try:
        t = datetime.strptime(str(date)[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None
    return max(0, int((now - t) // 86400))


def _breach(b: dict) -> dict:
    desc = b.get("Description")
    return {
        "name": b.get("Name"),
        "title": b.get("Title"),
        "domain": b.get("Domain"),
        "breach_date": b.get("BreachDate"),
        "added_date": str(b.get("AddedDate") or "")[:10] or None,
        "pwn_count": b.get("PwnCount") if isinstance(b.get("PwnCount"), int) else None,
        "data_classes": [c for c in b.get("DataClasses") or [] if isinstance(c, str)][:12],
        "verified": b.get("IsVerified") is True,
        "fabricated": b.get("IsFabricated") is True,
        "sensitive": b.get("IsSensitive") is True,
        "spam_list": b.get("IsSpamList") is True,
        "description": html.unescape(_TAG.sub("", desc))[:700] if isinstance(desc, str) else None,
        "link": f"https://haveibeenpwned.com/PwnedWebsites#{b.get('Name')}",
    }


async def _one(client: httpx.AsyncClient, domain: str) -> list | dict:
    try:
        r = await client.get(_API, params={"domain": domain})
    except httpx.RequestError as e:
        return company.request_error(e, _SOURCE)
    if r.status_code == 404:
        return []
    if err := company.http_error(r, _SOURCE):
        return err
    try:
        rows = r.json()
    except ValueError:
        return {"error": {"code": "InvalidResponse", "message": f"{_SOURCE} returned a non-JSON response."}}
    return [_breach(b) for b in rows if isinstance(b, dict)] if isinstance(rows, list) else []


async def lookup(indicator: str) -> dict:
    parsed = company.parse(indicator)
    if not parsed["domains"]:
        return company.needs_domain(_SOURCE)
    async with httpx.AsyncClient(timeout=20, headers={"User-Agent": company.UA, "Accept": "application/json"}) as client:
        per = await asyncio.gather(*(_one(client, d) for d in parsed["domains"][:3]))
    if all(isinstance(p, dict) for p in per):
        return per[0]
    breaches = {b["name"]: b for p in per if isinstance(p, list) for b in p}
    # Fabricated breaches and spam lists aren't incidents of the company.
    real = sorted((b for b in breaches.values() if not b["fabricated"] and not b["spam_list"]),
                  key=lambda b: str(b["breach_date"] or ""), reverse=True)
    other = [b for b in breaches.values() if b["fabricated"] or b["spam_list"]]
    latest = real[0]["breach_date"] if real else None
    return {
        "domains": parsed["domains"][:3],
        "count": len(real),
        "breaches": real[:20],
        "flagged": other[:5],
        "latest_breach": latest,
        "days_since_latest": _days_since(latest, time.time()) if latest else None,
        "accounts": sum(b["pwn_count"] or 0 for b in real),
        "link": "https://haveibeenpwned.com/PwnedWebsites",
    }


async def dispatch(indicator: str, type: str) -> dict:
    if type != "company":
        return {"error": {"code": "UnsupportedType", "message": f"{_SOURCE} does not support type '{type}'."}}
    return await lookup(indicator)
