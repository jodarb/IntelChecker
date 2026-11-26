"""Company (organisation) lookups: indicator format, name matching and Wikidata access,
shared by the company sources (Wikidata, GLEIF, ransomware.live, Hudson Rock, HIBP,
GDELT) and by GET /company/resolve.

A company name is ambiguous ("Iberia" is an airline, a piano suite and a peninsula),
so the indicator can carry identifiers in a trailing parenthesis that every source
reads the same way:

    Iberia                               name only
    iberia.com                           domain only
    Iberia (iberia.com)                  name + domain
    Iberia (iberia.com, Q187972)         + Wikidata item
    Iberia (iberia.com, 549300GEL7LRGKK0DG70)   + LEI

The search box builds the last forms from the candidate the analyst picks, so the
history keeps the exact entity and a re-run hits the same one. Name-based sources
use the name, domain-based ones (Hudson Rock, HIBP) need a domain.
"""
import asyncio
import re
import time
import unicodedata

import httpx

from app.core import config
from app.core.domains import host_of, registered_domain

_QID = re.compile(r"^Q[1-9]\d*$")
_LEI = re.compile(r"^[A-Z0-9]{18}\d{2}$")
_PAREN = re.compile(r"^(.*?)\s*\(([^()]*)\)\s*$")
_DOMAINISH = re.compile(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$", re.IGNORECASE)

# Legal-form words dropped when comparing names ("Iberia, S.A." == "IBERIA SA").
_LEGAL_SUFFIXES = {
    "sa", "sau", "sl", "slu", "sociedad", "anonima", "limitada", "inc", "incorporated", "ltd", "limited",
    "llc", "llp", "lp", "plc", "corp", "corporation", "co", "company", "gmbh", "ag", "kg", "se", "nv", "bv",
    "spa", "srl", "sas", "sarl", "oy", "oyj", "ab", "asa", "as", "aps", "kk", "pte", "pty", "bhd", "sdn",
    "group", "grupo", "holding", "holdings", "the", "de", "cv",
}

UA = "IntelChecker/1.0 (self-hosted CTI triage tool)"


def wikimedia_headers() -> dict:
    """User-Agent for Wikidata, with the operator's contact (WIKIMEDIA_CONTACT) when
    set: Wikimedia throttles anonymous clients hard. Read at call time."""
    contact = config.get("WIKIMEDIA_CONTACT").strip()
    ua = f"IntelChecker/1.0 ({contact}; self-hosted CTI triage tool)" if contact else UA
    return {"User-Agent": ua, "Accept": "application/json"}
WIKIDATA_API = "https://www.wikidata.org/w/api.php"


def parse(indicator: str) -> dict:
    """{"name", "domains", "qid", "lei", "label"} from a company indicator."""
    s = (indicator or "").strip()
    name, domains, qid, lei = s, [], None, None
    m = _PAREN.match(s)
    if m:
        tokens = [t for t in re.split(r"[,;·\s]+", m.group(2)) if t]
        ok, d_list, q, lei_tok = True, [], None, None
        for tok in tokens:
            if _QID.match(tok.upper()):
                q = tok.upper()
            elif _LEI.match(tok.upper()):
                lei_tok = tok.upper()
            elif (d := _domain_of(tok)):
                if d not in d_list:
                    d_list.append(d)
            else:
                ok = False   # "Acme (Spain)": a plain parenthesis, part of the name
                break
        if ok and tokens:
            name, domains, qid, lei = m.group(1).strip(), d_list, q, lei_tok
    if name and not domains and (d := _domain_of(name)):
        # A bare domain (or URL) is the company's domain, not its name.
        name, domains = "", [d]
    label = name or (domains[0].split(".")[0] if domains else "")
    return {"name": name, "domains": domains, "qid": qid, "lei": lei, "label": label}


def _domain_of(token: str) -> str:
    t = token.strip().lower()
    if "://" in t or "/" in t:
        t = host_of(t, "url")
    if t.startswith("www."):
        t = t[4:]
    if not _DOMAINISH.match(t):
        return ""
    return registered_domain(t)


def build(name: str, domains: list[str] | None = None, qid: str | None = None, lei: str | None = None) -> str:
    ids = [*(domains or []), *([qid] if qid else []), *([lei] if lei else [])]
    return f"{name} ({', '.join(ids)})" if ids else name


def normalize_name(value: str | None) -> str:
    """Accent-, case-, punctuation- and legal-form-insensitive key for a company name."""
    if not value:
        return ""
    s = unicodedata.normalize("NFKD", value)
    s = "".join(c for c in s if not unicodedata.combining(c)).lower().replace("&", " and ")
    s = re.sub(r"\b([a-z])\.(?=[a-z]\.)", r"\1", s)      # s.a. → sa.
    s = re.sub(r"[^a-z0-9]+", " ", s).split()
    while len(s) > 1 and s[-1] in _LEGAL_SUFFIXES:
        s.pop()
    while len(s) > 1 and s[0] == "the":
        s.pop(0)
    return " ".join(s)


def same_company(a: str | None, b: str | None) -> bool:
    na, nb = normalize_name(a), normalize_name(b)
    return bool(na) and na == nb


def needs_domain(source: str) -> dict:
    """The source only answers by domain and the indicator has none: not applicable,
    left out of the knowledge total (NOT_APPLICABLE_ERROR_CODES in both verdict engines)."""
    return {"error": {"code": "NeedsDomain",
                      "message": f"{source} searches by domain: add the company's domain, e.g. \"Acme (acme.com)\"."}}


def http_error(r: httpx.Response, source: str) -> dict | None:
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": f"{source} rate limit exceeded."}}
    if r.status_code >= 500:
        return {"error": {"code": "ServiceUnavailable", "message": f"{source} is unavailable (HTTP {r.status_code})."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"{source} returned HTTP {r.status_code}."}}
    return None


def request_error(e: Exception, source: str) -> dict:
    if isinstance(e, httpx.TimeoutException):
        return {"error": {"code": "Timeout", "message": f"{source} request timed out."}}
    return {"error": {"code": "NetworkError", "message": f"Could not reach {source}."}}


# ── Wikidata ─────────────────────────────────────────────────────────────────
# The Action API (wbsearchentities / wbgetentities), not the SPARQL endpoint: WDQS
# throttles hard per client (down to 1 query/min during its frequent incidents),
# while entity lookups are cheap, cached and far more reliable.

_LANGS = ("en", "es", "mul")

# An item is treated as an organisation when it has any property only organisations
# carry (industry, HQ, employees, LEI, stock exchange, parent, subsidiary, founder,
# CEO, legal form, revenue…) or is an instance of a common business class.
ORG_PROPS = {"P452", "P159", "P1128", "P1278", "P414", "P749", "P355", "P112", "P169", "P1454", "P2139", "P1056"}
ORG_CLASSES = {
    "Q43229", "Q4830453", "Q783794", "Q891723", "Q6881511", "Q167037", "Q1589009", "Q219577", "Q161726",
    "Q22687", "Q46970", "Q2085381", "Q1058914", "Q210167", "Q18388277", "Q15911314", "Q163740", "Q658255",
}


# Referenced items (countries, cities, item types, parent companies) change rarely
# and every company lookup needs them: their labels / claims are kept for an hour so
# a lookup costs Wikidata 1–3 requests, not 5–6. The company's own item is always
# fetched live (`reference=False`).
_REF_TTL = 3600
_ref_cache: dict[tuple[str, str], tuple[float, dict]] = {}


async def wikidata_get(client: httpx.AsyncClient, params: dict) -> httpx.Response:
    """GET the Wikidata API, waiting once (≤ 5 s) if it answers 429 with Retry-After."""
    r = await client.get(WIKIDATA_API, params=params, headers=wikimedia_headers())
    if r.status_code == 429:
        try:
            wait = float(r.headers.get("retry-after", "0"))
        except ValueError:
            wait = 0
        if 0 < wait <= 5:
            await asyncio.sleep(wait)
            r = await client.get(WIKIDATA_API, params=params, headers=wikimedia_headers())
    r.raise_for_status()
    return r


async def wb_entities(client: httpx.AsyncClient, ids: list[str], props: str = "labels|descriptions|claims",
                      reference: bool = False) -> dict:
    """wbgetentities for any number of ids (batches of 50): id → entity."""
    out: dict = {}
    ids = list(dict.fromkeys(i for i in ids if i and _QID.match(i)))
    now = time.time()
    if reference:
        for i in ids:
            hit = _ref_cache.get((i, props))
            if hit and now - hit[0] < _REF_TTL:
                out[i] = hit[1]
        ids = [i for i in ids if i not in out]
    for i in range(0, len(ids), 50):
        r = await wikidata_get(client, {
            "action": "wbgetentities", "ids": "|".join(ids[i:i + 50]), "props": props,
            "languages": "|".join(_LANGS), "languagefallback": 1, "format": "json",
        })
        ents = r.json().get("entities") or {}
        found = {k: v for k, v in ents.items() if isinstance(v, dict) and "missing" not in v}
        out.update(found)
        if reference:
            _ref_cache.update({(k, props): (now, v) for k, v in found.items()})
    if len(_ref_cache) > 5000:
        _ref_cache.clear()
    return out


def wb_text(entity: dict | None, field: str = "labels") -> str | None:
    vals = (entity or {}).get(field) or {}
    for lang in _LANGS:
        if isinstance(vals.get(lang), dict) and vals[lang].get("value"):
            return vals[lang]["value"]
    first = next(iter(vals.values()), None)
    return first.get("value") if isinstance(first, dict) else None


def wb_claims(entity: dict | None, prop: str) -> list[dict]:
    """Statements of a property, best rank first (preferred → normal; deprecated dropped)."""
    claims = [c for c in ((entity or {}).get("claims") or {}).get(prop) or []
              if isinstance(c, dict) and c.get("rank") != "deprecated"]
    return sorted(claims, key=lambda c: c.get("rank") != "preferred")


def wb_values(entity: dict | None, prop: str) -> list:
    """Plain values: item ids, strings, monolingual text, ISO dates, quantities."""
    out = []
    for c in wb_claims(entity, prop):
        v = ((c.get("mainsnak") or {}).get("datavalue") or {}).get("value")
        if isinstance(v, dict):
            if "id" in v:
                v = v["id"]
            elif "text" in v:
                v = v["text"]
            elif "time" in v:
                t = str(v["time"]).lstrip("+")
                v = t[:4] if v.get("precision", 11) <= 9 else t[:7] if v.get("precision") == 10 else t[:10]
            elif "amount" in v:
                try:
                    v = float(str(v["amount"]))
                except ValueError:
                    continue
            else:
                continue
        if v is not None and v not in out:
            out.append(v)
    return out


def is_organization(entity: dict | None) -> bool:
    claims = (entity or {}).get("claims") or {}
    return bool(ORG_PROPS & set(claims)) or bool(ORG_CLASSES & set(wb_values(entity, "P31")))


async def wikidata_search(client: httpx.AsyncClient, text: str, limit: int = 8) -> list[str]:
    """Item ids whose label or alias matches `text` (English, then Spanish), best first."""
    seen: list[str] = []
    for lang in ("en", "es"):
        r = await wikidata_get(client, {
            "action": "wbsearchentities", "search": text, "language": lang, "uselang": lang,
            "type": "item", "limit": limit, "format": "json",
        })
        for hit in r.json().get("search") or []:
            if isinstance(hit, dict) and isinstance(hit.get("id"), str) and hit["id"] not in seen:
                seen.append(hit["id"])
        if len(seen) >= limit:
            break
    return seen[:limit]


def _best_domain(websites: list[str]) -> str | None:
    """Registered domain of the official website: the one most websites share."""
    counts: dict[str, int] = {}
    for w in websites:
        if isinstance(w, str) and (d := _domain_of(w)):
            counts[d] = counts.get(d, 0) + 1
    return max(counts, key=lambda d: (counts[d], -len(d))) if counts else None


async def wikidata_candidates(client: httpx.AsyncClient, qids: list[str]) -> list[dict]:
    """Summary of each item (label, description, countries, domain, LEI, is it an
    organisation), in the order given."""
    ents = await wb_entities(client, qids)
    refs = [v for e in ents.values() for p in ("P17", "P31") for v in wb_values(e, p)[:4]]
    labels = await wb_entities(client, refs, props="labels", reference=True) if refs else {}
    out = []
    for q in qids:
        e = ents.get(q)
        if not e:
            continue
        lbl = lambda ids: [x for x in (wb_text(labels.get(i)) for i in ids) if x]  # noqa: E731
        lei = wb_values(e, "P1278")
        out.append({
            "qid": q,
            "name": wb_text(e),
            "description": wb_text(e, "descriptions"),
            "countries": lbl(wb_values(e, "P17")[:4]),
            "types": lbl(wb_values(e, "P31")[:3]),
            "domain": _best_domain(wb_values(e, "P856")),
            "lei": lei[0] if lei and isinstance(lei[0], str) else None,
            "organization": is_organization(e),
        })
    return out


async def wikidata_legal(client: httpx.AsyncClient, qid: str) -> dict:
    """LEI (P1278), official names (P1448) and country ISO code of an item, for GLEIF."""
    e = (await wb_entities(client, [qid], props="claims")).get(qid)
    if not e:
        return {}
    countries = wb_values(e, "P17")[:1]
    ref = await wb_entities(client, countries, props="labels|claims", reference=True) if countries else {}
    codes = wb_values(ref.get(countries[0]), "P297") if countries else []
    lei = [x for x in wb_values(e, "P1278") if isinstance(x, str)]
    return {
        "lei": lei[0] if lei else None,
        "official_names": [x for x in wb_values(e, "P1448") if isinstance(x, str)][:3],
        "country": codes[0] if codes and isinstance(codes[0], str) else None,
    }


async def resolve(query: str) -> dict:
    """Candidates for the search box: organisations first, then the rest."""
    parsed = parse(query)
    text = parsed["name"] or parsed["label"]
    if not text and not parsed["qid"]:
        return {"query": query, "candidates": []}
    async with httpx.AsyncClient(timeout=25) as client:
        try:
            qids = [parsed["qid"]] if parsed["qid"] else await wikidata_search(client, text)
            cands = await wikidata_candidates(client, qids)
        except (httpx.HTTPError, ValueError) as e:
            err = request_error(e, "Wikidata") if isinstance(e, httpx.RequestError) else \
                {"error": {"code": "ServiceUnavailable", "message": "Wikidata search failed."}}
            return {"query": query, "candidates": [], **err}
    want = set(parsed["domains"])
    for c in cands:
        c["domain_match"] = bool(want) and c["domain"] in want
        domains = parsed["domains"] or ([c["domain"]] if c["domain"] else [])
        c["indicator"] = build(c["name"] or text, domains, c["qid"], c["lei"])
    cands.sort(key=lambda c: (not c["domain_match"], not c["organization"]))
    return {"query": query, "candidates": cands}
