"""Wikidata — company profile: sector, countries, headquarters, parent and subsidiaries
(https://www.wikidata.org). Free, no key. Uses the entity API (wbsearchentities /
wbgetentities), not the SPARQL endpoint, which throttles hard per client.

The item comes from the indicator's QID when the search box resolved one; otherwise
the name (or the domain's first label) is searched and the first organisation whose
official website matches the domain is used, or the first organisation if there is
no domain — that guess is returned with `exact: false` so the card says so.

"Countries" is the union of the company's own country, its headquarters' country
and its subsidiaries' countries: where it has a presence, not where it sells.
Context only: no risk verdict.
"""
import httpx

from app.core import company
from app.core.company import wb_claims, wb_entities, wb_text, wb_values

_SOURCE = "Wikidata"
_MAX_SUBSIDIARIES = 50

# property → field (item-valued). Labels as Wikidata has them, English first.
_ITEM_PROPS = {
    "P31": "types", "P452": "industries", "P17": "countries", "P159": "headquarters",
    "P749": "parents", "P127": "owners", "P355": "subsidiaries", "P414": "exchanges",
}


async def _pick(client: httpx.AsyncClient, parsed: dict) -> tuple[str | None, bool]:
    """(qid, exact). exact = the indicator named it, or the domain matched the website."""
    if parsed["qid"]:
        return parsed["qid"], True
    text = parsed["name"] or parsed["label"]
    if not text:
        return None, False
    cands = [c for c in await company.wikidata_candidates(client, await company.wikidata_search(client, text))
             if c["organization"]]
    if parsed["domains"]:
        for c in cands:
            if c["domain"] in parsed["domains"]:
                return c["qid"], True
        # A domain was given and no organisation has it as website: don't guess.
        return None, False
    for c in cands:
        if company.same_company(c["name"], text):
            return c["qid"], False
    return (cands[0]["qid"], False) if cands else (None, False)


def _tickers(e: dict) -> list[str]:
    out = []
    for c in wb_claims(e, "P414"):
        for q in (c.get("qualifiers") or {}).get("P249") or []:
            v = (q.get("datavalue") or {}).get("value")
            if isinstance(v, str) and v not in out:
                out.append(v)
    return out[:5]


async def lookup(indicator: str) -> dict:
    parsed = company.parse(indicator)
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            qid, exact = await _pick(client, parsed)
            if not qid:
                return {"found": False, "query": parsed["name"] or parsed["label"], "domains": parsed["domains"]}
            e = (await wb_entities(client, [qid])).get(qid)
            if not e:
                return {"found": False, "query": parsed["name"] or parsed["label"], "qid": qid}
            ids = {f: [v for v in wb_values(e, p) if isinstance(v, str)] for p, f in _ITEM_PROPS.items()}
            ids["subsidiaries"] = ids["subsidiaries"][:_MAX_SUBSIDIARIES]
            # Labels of everything referenced + the country of the HQ and subsidiaries.
            refs = await wb_entities(client, [i for v in ids.values() for i in v], props="labels|claims", reference=True)
            located = ids["headquarters"] + ids["subsidiaries"]
            place_country = {i: (wb_values(refs.get(i), "P17") or [None])[0] for i in located}
            wanted = [c for c in [*ids["countries"], *place_country.values()] if c and c not in refs]
            countries = await wb_entities(client, wanted, props="labels|claims", reference=True)
            countries.update(refs)
        except httpx.HTTPStatusError as err:
            return company.http_error(err.response, _SOURCE) or {
                "error": {"code": "HttpError", "message": f"{_SOURCE} returned HTTP {err.response.status_code}."}}
        except httpx.RequestError as err:
            return company.request_error(err, _SOURCE)
        except ValueError:
            return {"error": {"code": "InvalidResponse", "message": f"{_SOURCE} returned an invalid response."}}

    def label(i: str | None) -> str | None:
        return wb_text(countries.get(i) or refs.get(i)) if i else None

    def code(i: str | None) -> str | None:
        v = wb_values(countries.get(i), "P297") if i else []
        return v[0] if v and isinstance(v[0], str) else None

    def ref(i: str, with_country: bool = False) -> dict:
        out = {"name": label(i) or i, "qid": i}
        if with_country and (c := label(place_country.get(i))):
            out["country"] = c
        return out

    lists = {f: [ref(i, f in ("headquarters", "subsidiaries")) for i in v] for f, v in ids.items()}
    presence: dict[str, dict] = {}

    def add(country_id: str | None, via: str):
        if not country_id or not (name := label(country_id)):
            return
        p = presence.setdefault(name, {"code": code(country_id), "via": set()})
        p["via"].add(via)

    for c in ids["countries"]:
        add(c, "company")
    for h in ids["headquarters"]:
        add(place_country.get(h), "headquarters")
    for s in ids["subsidiaries"]:
        add(place_country.get(s), "subsidiary")

    employees = [v for v in wb_values(e, "P1128") if isinstance(v, float)]
    inception = [v for v in wb_values(e, "P571") if isinstance(v, str)]
    lei = [v for v in wb_values(e, "P1278") if isinstance(v, str)]
    websites = [v for v in wb_values(e, "P856") if isinstance(v, str)]
    return {
        "found": True,
        "exact": exact,
        "qid": qid,
        "name": wb_text(e),
        "description": wb_text(e, "descriptions"),
        "official_names": [v for v in wb_values(e, "P1448") if isinstance(v, str)][:3],
        **lists,
        "sectors": [x["name"] for x in (lists["industries"] or lists["types"])],
        "countries": [x["name"] for x in lists["countries"]],
        "presence": sorted(
            ({"country": c, "code": p["code"], "via": sorted(p["via"])} for c, p in presence.items()),
            key=lambda x: ("company" not in x["via"], "headquarters" not in x["via"], x["country"]),
        ),
        "subsidiaries_total": len(wb_values(e, "P355")),
        "tickers": _tickers(e),
        "websites": websites[:5],
        "domain": company._best_domain(websites),
        "inception": min(inception) if inception else None,
        "employees": int(employees[0]) if employees else None,
        "lei": lei[0] if lei else None,
        "link": f"https://www.wikidata.org/wiki/{qid}",
    }


async def dispatch(indicator: str, type: str) -> dict:
    if type != "company":
        return {"error": {"code": "UnsupportedType", "message": f"{_SOURCE} does not support type '{type}'."}}
    return await lookup(indicator)
