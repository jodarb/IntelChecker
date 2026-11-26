"""VulnCheck KEV — VulnCheck's catalog of known exploited vulnerabilities
(https://docs.vulncheck.com/community/vulncheck-kev/introduction). Free Community key
(https://vulncheck.com/settings/tokens; a token unused for 30 days expires).

A superset of CISA KEV: it lists exploitation reported publicly (with the source
URLs), seen by VulnCheck's own canaries, and links public exploit code (VulnCheck
XDB), usually days or weeks before CISA adds a CVE — or for CVEs CISA never adds.

    GET https://api.vulncheck.com/v3/index/vulncheck-kev?cve=<CVE>
    Authorization: Bearer <token>

Not in the catalog is "no data", never a benign verdict.
"""
import httpx

from app.core.connectors import secret
from app.core.cve import bad_cve, normalize_cve

_API = "https://api.vulncheck.com/v3/index/vulncheck-kev"
_MAX_LINKS = 15


def _date(v) -> str | None:
    return v[:10] if isinstance(v, str) and v else None


async def lookup(value: str) -> dict:
    cve_id = normalize_cve(value)
    if not cve_id:
        return bad_cve(value, "VulnCheck KEV")
    key = secret("VULNCHECK_API_KEY")
    if not key:
        return {"error": {"code": "MissingApiKey", "message": "VulnCheck API token is not configured."}}

    headers = {"Authorization": f"Bearer {key}", "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=20, headers=headers) as client:
        try:
            r = await client.get(_API, params={"cve": cve_id})
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "VulnCheck request timed out after 20 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach the VulnCheck API."}}

    if r.status_code == 401:
        return {"error": {"code": "Unauthorized", "message": "Invalid or expired VulnCheck API token (tokens unused for 30 days expire)."}}
    if r.status_code in (402, 403):
        return {"error": {"code": "Forbidden", "message": "This VulnCheck token has no access to the KEV index."}}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "VulnCheck rate limit exceeded."}}
    if r.status_code == 404:
        return {"cve": cve_id, "listed": False}
    if r.status_code >= 500:
        return {"error": {"code": "ServiceUnavailable", "message": f"VulnCheck is unavailable (HTTP {r.status_code})."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"VulnCheck returned HTTP {r.status_code}."}}
    try:
        body = r.json()
    except ValueError:
        return {"error": {"code": "InvalidResponse", "message": "VulnCheck returned a non-JSON response."}}

    rows = body.get("data") if isinstance(body, dict) else None
    rec = next((x for x in rows or [] if isinstance(x, dict)), None)
    if rec is None:
        return {"cve": cve_id, "listed": False}

    exploits = [
        {"id": x.get("xdb_id"), "url": x.get("xdb_url"), "type": x.get("exploit_type"), "date": _date(x.get("date_added"))}
        for x in rec.get("vulncheck_xdb") or [] if isinstance(x, dict)
    ]
    reports = [
        {"url": x.get("url"), "date": _date(x.get("date_added"))}
        for x in rec.get("vulncheck_reported_exploitation") or [] if isinstance(x, dict) and x.get("url")
    ]
    reports.sort(key=lambda x: x["date"] or "")
    return {
        "cve": cve_id,
        "listed": True,
        "vendor": rec.get("vendorProject"),
        "product": rec.get("product"),
        "name": rec.get("vulnerabilityName"),
        "description": rec.get("shortDescription"),
        "required_action": rec.get("required_action"),
        # "Known" or "Unknown"
        "ransomware": rec.get("knownRansomwareCampaignUse"),
        "cwes": [c for c in rec.get("cwes") or [] if isinstance(c, str)],
        "date_added": _date(rec.get("date_added")),
        "cisa_date_added": _date(rec.get("cisa_date_added")),
        "due_date": _date(rec.get("dueDate")),
        "canaries": rec.get("reported_exploited_by_vulncheck_canaries") is True,
        "exploits_total": len(exploits),
        "exploits": exploits[:_MAX_LINKS],
        "reports_total": len(reports),
        # Earliest first: when exploitation was first reported publicly.
        "reports": reports[:_MAX_LINKS],
    }


async def dispatch(indicator: str, type: str) -> dict:
    if type != "cve":
        return {"error": {"code": "UnsupportedType", "message": f"VulnCheck KEV does not support type '{type}'."}}
    return await lookup(indicator)
