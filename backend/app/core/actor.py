"""Threat actor name resolution for the Actors search box (GET /actor/resolve).

Actor names are spelled many ways ("Gentleman" for The Gentlemen, "Fancy Bear" for
APT28), and every source matches its own names and aliases. So, like companies,
the analyst first picks the actor among candidates, and the lookup then runs on the
name most sources know it by.

Candidates come from:
  * MITRE ATT&CK groups and ransomware.live groups — already cached in memory,
    matched here with an approximate substring search (a letter or two off counts:
    "gentleman" ~ "thegentlemen");
  * Malpedia's and Recorded Future's own actor search (sent the query as typed).
Candidates that share a name or alias are merged into one actor.
"""
import asyncio
import re
from urllib.parse import quote

import httpx

from app.core.connectors import secret

_MAX = 10
_MAX_ALIASES = 12


def key(v: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", "", (v or "").lower())


def _max_distance(n: int) -> int:
    return 0 if n <= 3 else 1 if n <= 7 else 2


def _substring_distance(needle: str, text: str, anchored: bool = False) -> int:
    """Edit distance between `needle` and its closest substring of `text` (Sellers),
    counting two swapped letters as one edit ("akria" ~ "akira")."""
    before = None
    prev = [0] * (len(text) + 1)
    for i, c in enumerate(needle, 1):
        cur = [i] + [0] * len(text)
        for j, t in enumerate(text, 1):
            cur[j] = min(prev[j - 1] + (c != t), prev[j] + 1, cur[j - 1] + 1)
            if before is not None and j > 1 and c == text[j - 2] and needle[i - 2] == t:
                cur[j] = min(cur[j], before[j - 2] + 1)
        before, prev = prev, cur
    return prev[-1] if anchored else min(prev)


def score(needle: str, names: list[str]) -> int:
    """How well the query matches any of the names: 100 exact, 80 contained, lower
    with each letter off; 0 = no match."""
    nk = key(needle)
    if not nk:
        return 0
    best = 0
    for name in names:
        k = key(name)
        if not k:
            continue
        if k == nk:
            return 100
        if len(nk) >= 3 and nk in k:
            best = max(best, 80 - min(10, len(k) - len(nk)))
            continue
        limit = _max_distance(len(nk))
        if not limit:
            continue
        # Long queries: a letter or two off anywhere inside a name ("gentleman" in
        # "thegentlemen"). Short ones: only against a whole word of the name, or any
        # five-letter query would match half the catalogue.
        if len(nk) >= 6:
            d = _substring_distance(nk, k)
        else:
            d = min(_substring_distance(nk, w, anchored=True) for w in [k, *map(key, re.split(r"[^A-Za-z0-9]+", name))] if w)
        if d <= limit:
            best = max(best, 60 - 10 * d)
    return best


# ── Sources ─────────────────────────────────────────────────────────────────

async def _mitre(q: str) -> list[dict]:
    from app.services import mitreattack
    if await mitreattack._ensure_fresh():
        return []
    groups = {id(g): g for g in mitreattack._index.values()}.values()
    out = []
    for g in groups:
        names = list(dict.fromkeys([g.get("name"), *(g.get("aliases") or [])]))
        if (s := score(q, names)):
            out.append({"source": "MITRE ATT&CK", "name": g.get("name"), "names": names, "score": s,
                        "description": g.get("description"), "mitre_id": g.get("attack_id")})
    return out


async def _ransomwarelive(q: str) -> list[dict]:
    from app.services import ransomwarelive
    if await ransomwarelive._groups.get():
        return []
    out = []
    for g in ransomwarelive._groups.data:
        names = [g.get("name"), *re.split(r"[/,;|]", g.get("altname") or "")]
        names = [n.strip() for n in names if n and n.strip()]
        if (s := score(q, names)):
            desc = g.get("description")
            out.append({"source": "ransomware.live", "name": g.get("name"), "names": names, "score": s,
                        "description": desc if isinstance(desc, str) else None, "ransomware": True,
                        "victims": g.get("_victim_count")})
    return out


async def _malpedia(client: httpx.AsyncClient, q: str) -> list[dict]:
    try:
        r = await client.get(f"https://malpedia.caad.fkie.fraunhofer.de/api/find/actor/{quote(q, safe='')}",
                             headers={"User-Agent": "IntelChecker/1.0", "Accept": "application/json"})
        rows = r.json() if r.is_success else []
    except (httpx.HTTPError, ValueError):
        return []
    out = []
    for a in rows if isinstance(rows, list) else []:
        if not isinstance(a, dict) or not a.get("common_name"):
            continue
        names = [a["common_name"], *(x for x in a.get("synonyms") or [] if isinstance(x, str))]
        # Malpedia already matched it: keep it even when our score says no.
        out.append({"source": "Malpedia", "name": a["common_name"], "names": names, "score": max(score(q, names), 50)})
    return out


async def _recordedfuture(client: httpx.AsyncClient, q: str) -> list[dict]:
    token = secret("RECORDED_FUTURE_API_KEY")
    if not token:
        return []
    try:
        r = await client.post("https://api.recordedfuture.com/threat/actor/search", json={"name": q, "limit": 10},
                              headers={"X-RFToken": token, "Accept": "application/json", "Content-Type": "application/json"})
        rows = (r.json() or {}).get("data") if r.is_success else []
    except (httpx.HTTPError, ValueError, AttributeError):
        return []
    out = []
    for row in rows or []:
        a = (row or {}).get("attributes") or {}
        if not a.get("name"):
            continue
        cats = [c.get("name") for c in a.get("categories") or [] if isinstance(c, dict) and c.get("name")]
        names = [a["name"], *(x for x in [*(a.get("common_names") or []), *(a.get("alias") or [])] if isinstance(x, str))]
        out.append({"source": "Recorded Future", "name": a["name"], "names": names, "score": max(score(q, names), 50),
                    "categories": cats,
                    # Forum handles ("gentleman07"): people, listed apart and never merged with a group.
                    "persona": any("Forum Member" in c or "Community Member" in c for c in cats)})
    return out


# ── Merge ───────────────────────────────────────────────────────────────────

# Which source's name to show first when they disagree.
_NAME_PRIORITY = ["MITRE ATT&CK", "Malpedia", "Recorded Future", "ransomware.live"]


def _search_name(cluster: list[dict]) -> str:
    """The name to look the actor up by: the one most sources list (as name or alias),
    then the most authoritative source's name. Spelled as the most authoritative
    source spells it ("APT28", not RF's alias "APT 28"), else with capitals
    ("TheGentlemen" over "thegentlemen")."""
    counts: dict[str, int] = {}
    spelling: dict[str, str] = {}
    ranked = sorted(cluster, key=lambda c: _NAME_PRIORITY.index(c["source"]))
    for c in ranked:
        for n in {key(x): x for x in c["names"]}.values():
            k = key(n)
            counts[k] = counts.get(k, 0) + 1
            cur = spelling.get(k)
            if cur is None or (cur.islower() and not n.islower()):
                spelling[k] = n
    primary = [key(c["name"]) for c in ranked]
    best = max(counts, key=lambda k: (counts[k], -(primary.index(k) if k in primary else 99), -len(k)))
    return spelling[best]


def merge(found: list[dict], limit: int = _MAX) -> list[dict]:
    clusters: list[dict] = []   # {"keys": set, "items": [...]}
    for item in sorted(found, key=lambda c: -c["score"]):
        keys = {key(n) for n in item["names"] if len(key(n)) >= 3}
        persona = bool(item.get("persona"))
        hit = [c for c in clusters if c["persona"] == persona and c["keys"] & keys]
        if hit:
            target = hit[0]
            for other in hit[1:]:   # the item bridges two clusters: join them
                target["keys"] |= other["keys"]
                target["items"] += other["items"]
                clusters.remove(other)
            target["keys"] |= keys
            target["items"].append(item)
        else:
            clusters.append({"keys": keys, "items": [item], "persona": persona})

    out = []
    for c in clusters:
        items = c["items"]
        name = _search_name(items)
        aliases = list(dict.fromkeys(n for i in items for n in i["names"] if key(n) != key(name)))
        desc = next((i["description"] for i in items if i.get("description")), None)
        out.append({
            "name": name,
            "aliases": aliases[:_MAX_ALIASES],
            "aliases_total": len(aliases),
            "sources": sorted({i["source"] for i in items}, key=_NAME_PRIORITY.index),
            "score": max(i["score"] for i in items),
            "description": re.sub(r"\s+", " ", desc)[:240] if desc else None,
            "mitre_id": next((i["mitre_id"] for i in items if i.get("mitre_id")), None),
            "ransomware": any(i.get("ransomware") for i in items),
            "victims": next((i["victims"] for i in items if isinstance(i.get("victims"), int)), None),
            "categories": sorted({x for i in items for x in i.get("categories") or []}),
            "persona": c["persona"],
        })
    for c in out:
        # Curated catalogues (MITRE, Malpedia, ransomware.live) or an RF group category:
        # an established actor. RF-only names without one (handles like "gentleman07",
        # forum members) are listed apart, after the actors.
        groupish = any(re.search(r"group|nation state|apt|ransomware|hacktivist|espionage", x, re.I)
                       for x in c["categories"])
        c["minor"] = c["persona"] or (c["sources"] == ["Recorded Future"] and not groupish)
    out.sort(key=lambda c: (c["minor"], -c["score"], -len(c["sources"]), c["name"].lower()))
    return out[:limit]


async def resolve(q: str) -> dict:
    local = await asyncio.gather(_mitre(q), _ransomwarelive(q), return_exceptions=True)
    found = [c for p in local if isinstance(p, list) for c in p if c.get("name")]
    # Malpedia and RF only match their own spellings ("Gentleman" finds nothing, "The
    # Gentlemen" does): also ask them for the best names the local catalogues matched.
    terms = [q]
    for c in sorted(found, key=lambda c: -c["score"]):
        if len(terms) >= 3:
            break
        if key(c["name"]) not in {key(t) for t in terms}:
            terms.append(c["name"])
    async with httpx.AsyncClient(timeout=12) as client:
        remote = await asyncio.gather(*(f(client, t) for t in terms for f in (_malpedia, _recordedfuture)),
                                      return_exceptions=True)
    for part in remote:
        if isinstance(part, list):
            # Scored against the query, not the term it was found with.
            found += [{**c, "score": max(score(q, c["names"]), 50)} for c in part if c.get("name")]
    return {"query": q, "candidates": merge(found)}
