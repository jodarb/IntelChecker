"""GLEIF — Global Legal Entity Identifier Foundation (https://www.gleif.org): the legal
entity behind a company, its jurisdiction, registered and headquarters addresses,
parent and subsidiaries (with the country of each). Free, no key.

The LEI comes from the indicator ("Acme (…, <LEI>)"), else from the Wikidata item
(P1278) when the indicator has a QID, else from a search by legal name (the item's
official names and country first), keeping only a legal name equal to the searched
one once legal forms are ignored ("Apple Inc." == "APPLE INC"). Anything looser is
returned as `candidates` (no record): GLEIF has ~2.9 million entities and a fuzzy
pick would often be another company. A match on the name alone is flagged
`exact: false` (basic record): several entities often share a short name.

Context only: no risk verdict.
"""
import asyncio

import httpx

from app.core import company

_API = "https://api.gleif.org/api/v1"
_SOURCE = "GLEIF"
_HEADERS = {"User-Agent": company.UA, "Accept": "application/vnd.api+json"}


def _addr(a: dict | None) -> dict | None:
    if not isinstance(a, dict):
        return None
    return {"city": a.get("city"), "region": a.get("region"), "country": a.get("country"),
            "lines": [x for x in a.get("addressLines") or [] if isinstance(x, str)]}


def _record(x: dict) -> dict:
    a = x.get("attributes") or {}
    e = a.get("entity") or {}
    reg = a.get("registration") or {}
    return {
        "lei": x.get("id"),
        "legal_name": (e.get("legalName") or {}).get("name"),
        "other_names": [n.get("name") for n in e.get("otherNames") or [] if isinstance(n, dict)][:5],
        "jurisdiction": e.get("jurisdiction"),
        "legal_address": _addr(e.get("legalAddress")),
        "hq_address": _addr(e.get("headquartersAddress")),
        "entity_status": e.get("status"),
        "category": e.get("category"),
        "legal_form": (e.get("legalForm") or {}).get("id"),
        "registered_as": e.get("registeredAs"),
        "creation_date": (e.get("creationDate") or "")[:10] or None,
        "registration_status": reg.get("status"),
        "initial_registration": (reg.get("initialRegistrationDate") or "")[:10] or None,
        "last_update": (reg.get("lastUpdateDate") or "")[:10] or None,
        "next_renewal": (reg.get("nextRenewalDate") or "")[:10] or None,
    }


def _brief(x: dict) -> dict:
    r = _record(x)
    return {"lei": r["lei"], "legal_name": r["legal_name"],
            "country": (r["legal_address"] or {}).get("country"), "status": r["entity_status"]}


class _WikidataDown(Exception):
    pass


async def _get(client: httpx.AsyncClient, path: str, **params) -> dict | None:
    """JSON body, None on 404 (no parent, unknown LEI); raises on other failures."""
    r = await client.get(f"{_API}{path}", params=params or None)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


async def _search(client: httpx.AsyncClient, name: str, country: str | None,
                  unique: bool) -> tuple[str | None, list[dict]]:
    """Best record whose legal name equals `name` (legal forms ignored), and the rest.
    `unique`: several equal names make it ambiguous — no record, only candidates."""
    params = {"filter[entity.legalName]": name, "page[size]": 25}
    if country:
        params["filter[entity.legalAddress.country]"] = country
    body = await _get(client, "/lei-records", **params) or {}
    rows = [x for x in body.get("data") or [] if isinstance(x, dict)]
    legal = lambda x: (((x.get("attributes") or {}).get("entity") or {}).get("legalName") or {}).get("name")  # noqa: E731
    exact = [x for x in rows if company.same_company(legal(x), name)]
    # Several entities can share a name across countries: prefer an active one.
    exact.sort(key=lambda x: ((x.get("attributes") or {}).get("entity") or {}).get("status") != "ACTIVE")
    if exact and not (unique and len(exact) > 1):
        return exact[0].get("id"), [_brief(x) for x in exact[1:5]]
    return None, [_brief(x) for x in (exact or rows)[:5]]


async def _find_lei(client: httpx.AsyncClient, parsed: dict) -> tuple[str | None, list[dict], bool]:
    """(lei, other candidates, exact). exact = the LEI was given or comes from the
    Wikidata item; a name match alone is a guess (many funds are called "Iberia")."""
    if parsed["lei"]:
        return parsed["lei"], [], True
    names = [parsed["name"] or parsed["label"]]
    country = None
    if parsed["qid"]:
        async with httpx.AsyncClient(timeout=20) as wd:
            try:
                info = await company.wikidata_legal(wd, parsed["qid"])
            except (httpx.HTTPError, ValueError):
                # Without the item's LEI / country a name match would be a guess.
                raise _WikidataDown() from None
        if info.get("lei"):
            return info["lei"], [], True
        names = [*info.get("official_names", []), *names]
        country = info.get("country")
    others: list[dict] = []
    for name in dict.fromkeys(n for n in names if n):
        lei, rest = await _search(client, name, country, unique=not country)
        if lei:
            # Official name + the Wikidata item's country: as good as a given LEI.
            return lei, rest, bool(country) and name != names[-1]
        others = others or rest
    return None, others, False


async def lookup(indicator: str) -> dict:
    parsed = company.parse(indicator)
    async with httpx.AsyncClient(timeout=25, headers=_HEADERS) as client:
        try:
            lei, others, exact = await _find_lei(client, parsed)
            if not lei:
                return {"found": False, "query": parsed["name"] or parsed["label"], "candidates": others}
            rec, parent, ultimate, children = await asyncio.gather(
                _get(client, f"/lei-records/{lei}"),
                _get(client, f"/lei-records/{lei}/direct-parent"),
                _get(client, f"/lei-records/{lei}/ultimate-parent"),
                _get(client, f"/lei-records/{lei}/direct-children", **{"page[size]": 100}),
            )
        except _WikidataDown:
            return {"error": {"code": "ServiceUnavailable",
                              "message": "Wikidata is unavailable to identify the entity's LEI and country; GLEIF was not searched by name."}}
        except httpx.HTTPStatusError as e:
            return company.http_error(e.response, _SOURCE) or {
                "error": {"code": "HttpError", "message": f"{_SOURCE} returned HTTP {e.response.status_code}."}}
        except httpx.RequestError as e:
            return company.request_error(e, _SOURCE)
        except ValueError:
            return {"error": {"code": "InvalidResponse", "message": f"{_SOURCE} returned an invalid response."}}

    data = (rec or {}).get("data")
    if not isinstance(data, dict):
        return {"found": False, "query": parsed["name"] or parsed["label"], "lei": lei, "candidates": others}
    kids = [x for x in (children or {}).get("data") or [] if isinstance(x, dict)]
    kids_total = (((children or {}).get("meta") or {}).get("pagination") or {}).get("total", len(kids))
    by_country: dict[str, int] = {}
    for k in kids:
        c = _brief(k)["country"]
        if c:
            by_country[c] = by_country.get(c, 0) + 1
    out = {
        "found": True,
        "exact": exact,
        **_record(data),
        "direct_parent": _brief(parent["data"]) if isinstance((parent or {}).get("data"), dict) else None,
        "ultimate_parent": _brief(ultimate["data"]) if isinstance((ultimate or {}).get("data"), dict) else None,
        "children_total": kids_total,
        "children": [_brief(k) for k in kids[:25]],
        "children_countries": dict(sorted(by_country.items(), key=lambda kv: -kv[1])),
        "same_name": others,
        "link": f"https://search.gleif.org/#/record/{lei}",
    }
    if out["ultimate_parent"] and out["direct_parent"] and out["ultimate_parent"]["lei"] == out["direct_parent"]["lei"]:
        out["ultimate_parent"] = None
    return out


async def dispatch(indicator: str, type: str) -> dict:
    if type != "company":
        return {"error": {"code": "UnsupportedType", "message": f"{_SOURCE} does not support type '{type}'."}}
    return await lookup(indicator)
