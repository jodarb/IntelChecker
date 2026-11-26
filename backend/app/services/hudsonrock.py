"""Hudson Rock Cavalier (free OSINT API) — infostealer infections linked to a company's
domain: employees whose machines leaked corporate credentials, users (customers)
whose credentials for the company's sites were stolen, and third parties
(https://www.hudsonrock.com/free-tools). Free, no key. Searches by domain only.

Only counts, dates, malware families and the affected login URLs are kept — never
credentials or personal data: the API itself doesn't return them, and nothing like
that should land in the history.

Hudson Rock evaluates every domain against its whole database, so 0 infections is
an explicit "clean" answer, not missing data.
"""
import asyncio
import time
from datetime import datetime

import httpx

from app.core import company

_API = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
_SOURCE = "Hudson Rock"
_EPOCH = "1970-01-01"


def _date(v) -> str | None:
    s = str(v or "")[:10]
    return None if not s or s.startswith(_EPOCH) else s


def _days_since(date: str | None, now: float) -> int | None:
    if not date:
        return None
    try:
        return max(0, int((now - datetime.fromisoformat(date).timestamp()) // 86400))
    except ValueError:
        return None


def _int(v) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) and v > 0 else 0


def _urls(rows, n: int = 10) -> list[dict]:
    out = [{"url": r.get("url"), "occurrence": _int(r.get("occurrence"))}
           for r in rows or [] if isinstance(r, dict) and isinstance(r.get("url"), str)]
    return sorted(out, key=lambda r: -r["occurrence"])[:n]


def _top(d, n: int = 8) -> list[dict]:
    if not isinstance(d, dict):
        return []
    items = [(k, _int(v)) for k, v in d.items() if k not in ("total", "others")]
    return [{"name": k, "count": c} for k, c in sorted(items, key=lambda kv: -kv[1])[:n] if c]


async def _one(client: httpx.AsyncClient, domain: str) -> dict:
    try:
        r = await client.get(_API, params={"domain": domain})
    except httpx.RequestError as e:
        return company.request_error(e, _SOURCE)
    if err := company.http_error(r, _SOURCE):
        return err
    try:
        d = r.json()
    except ValueError:
        return {"error": {"code": "InvalidResponse", "message": f"{_SOURCE} returned a non-JSON response."}}
    if not isinstance(d, dict):
        return {"error": {"code": "InvalidResponse", "message": f"{_SOURCE} returned an unexpected response."}}
    data = d.get("data") if isinstance(d.get("data"), dict) else {}
    return {
        "domain": domain,
        "total": _int(d.get("total")),
        "employees": _int(d.get("employees")),
        "users": _int(d.get("users")),
        "third_parties": _int(d.get("third_parties")),
        "last_employee_compromised": _date(d.get("last_employee_compromised")),
        "last_user_compromised": _date(d.get("last_user_compromised")),
        "stealer_families": _top(d.get("stealerFamilies")),
        "employee_urls": _urls(data.get("employees_urls")),
        "user_urls": _urls(data.get("clients_urls")),
        "third_party_domains": [x.get("domain") for x in d.get("thirdPartyDomains") or []
                                if isinstance(x, dict) and isinstance(x.get("domain"), str)][:10],
        "database_size": _int(d.get("totalStealers")) or None,
    }


async def lookup(indicator: str) -> dict:
    parsed = company.parse(indicator)
    if not parsed["domains"]:
        return company.needs_domain(_SOURCE)
    async with httpx.AsyncClient(timeout=25, headers={"User-Agent": company.UA, "Accept": "application/json"}) as client:
        per = await asyncio.gather(*(_one(client, d) for d in parsed["domains"][:3]))
    ok = [p for p in per if "error" not in p]
    if not ok:
        return per[0]

    families: dict[str, int] = {}
    for p in ok:
        for f in p["stealer_families"]:
            families[f["name"]] = families.get(f["name"], 0) + f["count"]
    now = time.time()
    last_emp = max((p["last_employee_compromised"] for p in ok if p["last_employee_compromised"]), default=None)
    last_user = max((p["last_user_compromised"] for p in ok if p["last_user_compromised"]), default=None)
    return {
        "domains": [p["domain"] for p in ok],
        "total": sum(p["total"] for p in ok),
        "employees": sum(p["employees"] for p in ok),
        "users": sum(p["users"] for p in ok),
        "third_parties": sum(p["third_parties"] for p in ok),
        "last_employee_compromised": last_emp,
        "last_user_compromised": last_user,
        "days_since_employee": _days_since(last_emp, now),
        "days_since_user": _days_since(last_user, now),
        "stealer_families": [{"name": k, "count": v} for k, v in sorted(families.items(), key=lambda kv: -kv[1])[:8]],
        "per_domain": ok,
        "database_size": next((p["database_size"] for p in ok if p["database_size"]), None),
        "link": "https://www.hudsonrock.com/free-tools",
    }


async def dispatch(indicator: str, type: str) -> dict:
    if type != "company":
        return {"error": {"code": "UnsupportedType", "message": f"{_SOURCE} does not support type '{type}'."}}
    return await lookup(indicator)
