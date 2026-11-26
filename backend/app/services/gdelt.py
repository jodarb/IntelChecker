"""GDELT DOC 2.0 — recent news coverage (last 90 days, worldwide, 65 languages) that
mentions the company together with security-incident words: cyberattack, ransomware,
data breach, hackers… (https://blog.gdeltproject.org/gdelt-doc-2-0-api-debuts/).
Free, no key.

News is noisy: an article can name the company only in passing. Articles whose
*title* mentions the company are flagged `in_title` and are the ones that count as a
record; the rest are listed below them. Context only, no risk verdict: a headline is
not a confirmed incident.

GDELT allows one request every 5 seconds per IP and answers faster ones with a plain
text notice, so requests are spaced like Tranco's.
"""
import asyncio
import time
from datetime import datetime, timezone

import httpx

from app.core import company

_API = "https://api.gdeltproject.org/api/v2/doc/doc"
_SOURCE = "GDELT"
_MIN_INTERVAL = 5.5
_WORDS = ('cyberattack', '"cyber attack"', 'ransomware', '"data breach"', 'hackers', 'hacked',
          'ciberataque', 'hackeo', '"fuga de datos"', '"brecha de seguridad"')

_lock = asyncio.Lock()
_last_request = 0.0


async def _get(client: httpx.AsyncClient, params: dict) -> httpx.Response:
    global _last_request
    async with _lock:
        wait = _MIN_INTERVAL - (time.monotonic() - _last_request)
        if wait > 0:
            await asyncio.sleep(wait)
        try:
            return await client.get(_API, params=params)
        finally:
            _last_request = time.monotonic()


def _seen(v) -> str | None:
    """'20261120T101500Z' → '2026-11-20T10:15:00Z'."""
    try:
        return datetime.strptime(str(v), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


async def lookup(indicator: str) -> dict:
    parsed = company.parse(indicator)
    name = parsed["name"] or parsed["label"]
    if len(name) < 3:
        return {"error": {"code": "BadRequest", "message": f"{_SOURCE} needs a company name of at least 3 characters."}}
    phrase = name.replace('"', "")
    query = f'"{phrase}" ({" OR ".join(_WORDS)})'
    params = {"query": query, "mode": "artlist", "format": "json", "maxrecords": 50,
              "timespan": "3months", "sort": "datedesc"}
    async with httpx.AsyncClient(timeout=30, headers={"User-Agent": company.UA}) as client:
        try:
            r = await _get(client, params)
        except httpx.RequestError as e:
            return company.request_error(e, _SOURCE)
    if err := company.http_error(r, _SOURCE):
        return err
    try:
        body = r.json()
    except ValueError:
        text = r.text.strip()
        if "limit requests" in text.lower():
            return {"error": {"code": "RateLimitExceeded",
                              "message": f"{_SOURCE} rate limit exceeded (one request every 5 seconds per IP)."}}
        return {"error": {"code": "BadRequest", "message": f"{_SOURCE} rejected the query: {text[:200]}"}}

    key = company.normalize_name(name)
    articles = []
    for a in (body.get("articles") if isinstance(body, dict) else None) or []:
        if not isinstance(a, dict) or not isinstance(a.get("url"), str):
            continue
        title = a.get("title") if isinstance(a.get("title"), str) else ""
        articles.append({
            "title": title.strip(),
            "url": a["url"],
            "source": a.get("domain"),
            "language": a.get("language"),
            "source_country": a.get("sourcecountry"),
            "seen": _seen(a.get("seendate")),
            "in_title": bool(key) and f" {key} " in f" {company.normalize_name(title)} ",
        })
    # GDELT often returns the same story syndicated under several URLs.
    unique = list({(x["title"].lower() or x["url"]): x for x in articles}.values())
    unique.sort(key=lambda x: (not x["in_title"], -(datetime.fromisoformat(x["seen"].replace("Z", "+00:00")).timestamp()
                                                    if x["seen"] else 0)))
    in_title = [x for x in unique if x["in_title"]]
    return {
        "query": name,
        "count": len(unique),
        "in_title": len(in_title),
        "latest": max((x["seen"] for x in in_title if x["seen"]), default=None),
        "articles": unique[:30],
        "link": "https://api.gdeltproject.org/api/v2/doc/doc?" + str(httpx.QueryParams({**params, "format": "html"})),
    }


async def dispatch(indicator: str, type: str) -> dict:
    if type != "company":
        return {"error": {"code": "UnsupportedType", "message": f"{_SOURCE} does not support type '{type}'."}}
    return await lookup(indicator)
