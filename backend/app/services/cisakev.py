"""CISA Known Exploited Vulnerabilities (KEV) catalog — CVEs with reliable evidence of
exploitation in the wild (https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

Free, no key. The whole catalog (~1,800 entries, a JSON file of a couple of MB) is
downloaded and kept in memory for a few hours, like the other feeds. A CVE that is
not in the catalog is "no data", never a benign verdict: KEV only lists exploitation
CISA could confirm.
"""
import json

from app.core.cve import bad_cve, normalize_cve
from app.core.feeds import CachedFeed

_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _parse(text: str) -> dict:
    raw = json.loads(text)
    items = {
        v["cveID"].upper(): v
        for v in raw.get("vulnerabilities") or []
        if isinstance(v, dict) and isinstance(v.get("cveID"), str)
    }
    if not items:
        raise ValueError("empty catalog")
    return {"version": raw.get("catalogVersion"), "released": raw.get("dateReleased"), "items": items}


_feed = CachedFeed("CISA KEV", _URL, 3 * 3600, _parse, count=lambda d: len(d["items"]))


async def lookup(value: str) -> dict:
    cve_id = normalize_cve(value)
    if not cve_id:
        return bad_cve(value, "CISA KEV")
    if err := await _feed.get():
        return err
    hit = _feed.data["items"].get(cve_id)
    base = {
        "cve": cve_id,
        "listed": hit is not None,
        "catalog_version": _feed.data["version"],
        "catalog_size": _feed.size,
        "list_updated": _feed.updated,
    }
    if not hit:
        return base
    return {
        **base,
        "vendor": hit.get("vendorProject"),
        "product": hit.get("product"),
        "name": hit.get("vulnerabilityName"),
        "description": hit.get("shortDescription"),
        "date_added": hit.get("dateAdded"),
        "due_date": hit.get("dueDate"),
        "required_action": hit.get("requiredAction"),
        # "Known" or "Unknown"
        "ransomware": hit.get("knownRansomwareCampaignUse"),
        "cwes": [c for c in hit.get("cwes") or [] if isinstance(c, str)],
        "notes": hit.get("notes"),
        "link": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}",
    }


async def dispatch(indicator: str, type: str) -> dict:
    if type != "cve":
        return {"error": {"code": "UnsupportedType", "message": f"CISA KEV does not support type '{type}'."}}
    return await lookup(indicator)
