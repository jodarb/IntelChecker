"""ransomware.live — victims claimed on ransomware groups' leak sites (dark web), with
group, dates, sector and country (https://www.ransomware.live). Free, no key.

The free API allows one request per minute per endpoint, which a few lookups in a
row would exhaust. So, like the other feeds, the full victims dump
(data.ransomware.live/victims.json, ~25 MB, downloadable once every 30 min per IP) is
kept in memory and refreshed every 6 hours; the search API is only used while the
dump has never been loaded.

A victim matches the company when its domain is one of the company's domains, or
its name equals the company name once case, accents and legal forms are ignored.
Victims that only *contain* the name ("Iberia Compositech" for "Iberia") are listed
as `similar`, never counted: they are usually other companies.

Threat actors: the group profiles (data.ransomware.live/groups.json, ~2 MB, same
6 h cache) matched on name or alternative name ("LockBit" → lockbit, lockbit2,
lockbit3…; "Akira Ransomware Group" → akira), plus the group's victims from the
same dump: total, last claim, claims in the last 30 / 90 / 365 days, top sectors
and countries. That last claim is the actor's operational activity.
"""
import json
import re
import time
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from app.core import company
from app.core.domains import host_of, registered_domain
from app.core.feeds import CachedFeed

_SOURCE = "ransomware.live"
_DUMP = "https://data.ransomware.live/victims.json"
_SEARCH = "https://api.ransomware.live/v2/searchvictims/{}"
_GROUPS = "https://data.ransomware.live/groups.json"


def _first(d: dict, *keys: str):
    for k in keys:
        v = d.get(k)
        if v not in (None, "", "N/A"):
            return v
    return None


def _victim(d: dict) -> dict | None:
    """Both the dump and the API, whose field names have changed over time."""
    name = _first(d, "victim", "post_title", "name")
    if not isinstance(name, str):
        return None
    site = _first(d, "domain", "website")
    host = host_of(site, "url") if isinstance(site, str) else ""
    desc = _first(d, "description")
    return {
        "victim": name.strip(),
        "group": _first(d, "group", "group_name"),
        "domain": registered_domain(host) or None,
        "country": _first(d, "country"),
        "sector": _first(d, "activity", "sector"),
        "attack_date": str(_first(d, "attackdate", "published") or "")[:10] or None,
        "discovered": str(_first(d, "discovered") or "")[:10] or None,
        "description": desc[:600] if isinstance(desc, str) else None,
        "data_size": _first(d, "data_size"),
        "ransom": _first(d, "ransom"),
        "link": _first(d, "url"),
        # .onion leak-site page: shown as text, never as a link.
        "claim_url": _first(d, "claim_url", "post_url"),
    }


def _rows(raw) -> list:
    if isinstance(raw, dict):
        raw = next((v for v in raw.values() if isinstance(v, list)), None)
    if not isinstance(raw, list):
        raise ValueError("unexpected ransomware.live payload")
    return raw


def _parse(text: str) -> list[dict]:
    victims = [v for v in (_victim(x) for x in _rows(json.loads(text)) if isinstance(x, dict)) if v]
    if not victims:
        raise ValueError("empty dump")
    for v in victims:
        v["_key"] = company.normalize_name(v["victim"])
    return victims


_feed = CachedFeed(_SOURCE, _DUMP, 6 * 3600, _parse, timeout=90, retry_after=1800)


def _days_since(date: str | None, now: float) -> int | None:
    try:
        t = datetime.strptime(date[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None
    return max(0, int((now - t) // 86400))


async def _search_api(keyword: str) -> list[dict] | dict:
    async with httpx.AsyncClient(timeout=25, headers={"User-Agent": company.UA, "Accept": "application/json"}) as client:
        try:
            r = await client.get(_SEARCH.format(quote(keyword, safe="")))
        except httpx.RequestError as e:
            return company.request_error(e, _SOURCE)
    if r.status_code == 404:
        return []
    if err := company.http_error(r, _SOURCE):
        return err
    try:
        body = r.json()
    except ValueError:
        return {"error": {"code": "InvalidResponse", "message": f"{_SOURCE} returned a non-JSON response."}}
    if isinstance(body, dict) and "per" in str(body.get("message", "")):
        return {"error": {"code": "RateLimitExceeded",
                          "message": f"{_SOURCE} free API allows one search per minute; the victims list is still loading."}}
    try:
        return [v for v in (_victim(x) for x in _rows(body) if isinstance(x, dict)) if v]
    except ValueError:
        return []


async def lookup(indicator: str) -> dict:
    parsed = company.parse(indicator)
    name, domains = parsed["name"], set(parsed["domains"])
    key = company.normalize_name(name)
    label_key = company.normalize_name(parsed["label"])
    if not key and not domains:
        return {"error": {"code": "BadRequest", "message": "Enter a company name or domain."}}

    via = "dump"
    if await _feed.get():
        victims = await _search_api(name or parsed["domains"][0])
        if isinstance(victims, dict):
            return victims
        via = "api"
        for v in victims:
            v["_key"] = company.normalize_name(v["victim"])
    else:
        victims = _feed.data

    matches, similar = [], []
    for v in victims:
        if (v["domain"] and v["domain"] in domains) or (key and v["_key"] == key):
            matches.append(v)
        elif (key and key in v["_key"]) or (not key and label_key and label_key in v["_key"]):
            similar.append(v)
    clean = lambda v: {k: x for k, x in v.items() if k != "_key"}  # noqa: E731
    order = lambda v: v.get("discovered") or v.get("attack_date") or ""  # noqa: E731
    matches.sort(key=order, reverse=True)
    similar.sort(key=order, reverse=True)

    now = time.time()
    last = order(matches[0]) if matches else None
    since = _days_since(last, now)
    return {
        "query": name or parsed["label"],
        "domains": sorted(domains),
        "listed": bool(matches),
        "matches": [clean(v) for v in matches[:25]],
        "match_count": len(matches),
        "groups": sorted({v["group"] for v in matches if v.get("group")}),
        "last_claim": last,
        "days_since_last": since,
        "claims_365d": sum(1 for v in matches if (d := _days_since(order(v), now)) is not None and d <= 365),
        "similar": [clean(v) for v in similar[:10]],
        "similar_count": len(similar),
        "via": via,
        "list_size": _feed.size if via == "dump" else None,
        "list_updated": _feed.updated if via == "dump" else None,
        "link": f"https://www.ransomware.live/search?q={quote(name or parsed['label'])}",
    }


# ── Threat actors (ransomware groups) ─────────────────────────────────────────

# Words that name the kind of actor, not the actor: "Akira Ransomware Group" → akira.
_ACTOR_NOISE = re.compile(r"\b(ransomware|ransom ware|group|gang|team|operators?|cartel|raas)\b", re.I)


def group_key(name: str | None) -> str:
    """Lower-case alphanumerics: "INC RANSOM" → incransom, "The Gentlemen" → thegentlemen."""
    return re.sub(r"[^a-z0-9]+", "", (name or "").lower())


def _needle_keys(name: str) -> set[str]:
    keys = {group_key(name), group_key(_ACTOR_NOISE.sub(" ", name))}
    return {k for k in keys if len(k) >= 3}


def _group_matches(group: dict, needles: set[str]) -> bool:
    names = [group.get("name"), *re.split(r"[/,;|]", group.get("altname") or "")]
    for n in names:
        k = group_key(n)
        if not k:
            continue
        for needle in needles:
            # Versions of the same brand: lockbit → lockbit2, lockbit3, lockbit3fs.
            if k == needle or re.fullmatch(re.escape(needle) + r"\d+[a-z]{0,3}", k):
                return True
    return False


def _parse_groups(text: str) -> list[dict]:
    groups = [g for g in _rows(json.loads(text)) if isinstance(g, dict) and g.get("name")]
    if not groups:
        raise ValueError("empty groups list")
    return groups


_groups = CachedFeed(f"{_SOURCE} groups", _GROUPS, 6 * 3600, _parse_groups, timeout=60, retry_after=1800)


_MAX_LOCATIONS = 20


def _location(x: dict) -> dict | None:
    """A leak site / chat / file server of the group. The address is attacker
    infrastructure (.onion mostly): shown as text, never linked."""
    addr = x.get("slug") or x.get("fqdn")
    if not isinstance(addr, str) or not addr.strip():
        return None
    title = x.get("title")
    return {
        "address": addr.strip()[:300],
        "type": x.get("type") if isinstance(x.get("type"), str) else None,
        "title": title.strip()[:120] if isinstance(title, str) and title.strip() else None,
        "available": x.get("available") if isinstance(x.get("available"), bool) else None,
        "enabled": x.get("enabled") if isinstance(x.get("enabled"), bool) else None,
        "updated": x.get("updated") if isinstance(x.get("updated"), str) else None,
        "last_scrape": x.get("lastscrape") if isinstance(x.get("lastscrape"), str) else None,
    }


def _profile(g: dict) -> dict:
    locs = [x for x in g.get("locations") or [] if isinstance(x, dict)]
    desc = g.get("description")
    types = g.get("type") if isinstance(g.get("type"), dict) else {}
    return {
        "name": g.get("name"),
        "altname": g.get("altname") or None,
        "lineage": g.get("lineage") or None,
        "first_seen": str(g.get("date") or "")[:10] or None,
        "raas": types.get("raas") if isinstance(types.get("raas"), bool) else None,
        "description": desc[:800] if isinstance(desc, str) and desc.strip() else None,
        "leak_sites": len(locs),
        "leak_sites_up": sum(1 for x in locs if x.get("available") is True),
        "locations": [loc for loc in (_location(x) for x in locs) if loc][:_MAX_LOCATIONS],
        "link": f"https://www.ransomware.live/group/{quote(str(g.get('name')))}",
    }


async def lookup_group(indicator: str) -> dict:
    name = (indicator or "").strip()
    needles = _needle_keys(name)
    if not needles:
        return {"error": {"code": "BadRequest", "message": "Enter a ransomware group name."}}
    if err := await _groups.get():
        return err
    groups = [g for g in _groups.data if _group_matches(g, needles)]
    if not groups:
        return {"kind": "group", "found": False, "query": name}
    keys = {group_key(g["name"]) for g in groups}

    victims, victims_error = [], None
    if err := await _feed.get():
        victims_error = err.get("error")
    else:
        victims = [v for v in _feed.data if group_key(v.get("group")) in keys]
    order = lambda v: v.get("discovered") or v.get("attack_date") or ""  # noqa: E731
    victims.sort(key=order, reverse=True)
    now = time.time()
    ages = [_days_since(order(v), now) for v in victims]
    within = lambda days: sum(1 for a in ages if a is not None and a <= days)  # noqa: E731
    top = lambda field: [{"name": k, "count": n} for k, n in Counter(  # noqa: E731
        v[field] for v in victims if v.get(field)).most_common(6)]
    clean = lambda v: {k: x for k, x in v.items() if k not in ("_key", "description")}  # noqa: E731
    # The main brand first: the most victims, then the oldest.
    groups.sort(key=lambda g: (-(g.get("_victim_count") or 0), str(g.get("date") or "")))
    out = {
        "kind": "group",
        "found": True,
        "query": name,
        "groups": [_profile(g) for g in groups[:6]],
        "victim_count": len(victims),
        "last_claim": order(victims[0]) if victims else None,
        "days_since_last": ages[0] if ages else None,
        "first_claim": order(victims[-1]) if victims else None,
        "claims_30d": within(30),
        "claims_90d": within(90),
        "claims_365d": within(365),
        "top_sectors": top("sector"),
        "top_countries": top("country"),
        "recent": [clean(v) for v in victims[:15]],
        "list_updated": _feed.updated,
        "link": _profile(groups[0])["link"],
    }
    if victims_error:
        out["victims_error"] = victims_error
    return out


async def dispatch(indicator: str, type: str) -> dict:
    if type == "threat-actor":
        return await lookup_group(indicator)
    if type != "company":
        return {"error": {"code": "UnsupportedType", "message": f"{_SOURCE} does not support type '{type}'."}}
    return await lookup(indicator)
