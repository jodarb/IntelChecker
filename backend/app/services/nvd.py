"""NVD (NIST National Vulnerability Database) — CVE records with CVSS scores, CWE
weaknesses, affected products (CPE) and references (https://nvd.nist.gov).

Free. Without an API key the API allows about 5 requests per 30 s; an optional
NVD_API_KEY (free, Connectors page) raises that to 50. The payload is trimmed to what
the card, the Summary and the verdict use, to keep history snapshots small: the
full CPE configuration tree of a popular CVE can be hundreds of KB.

The CVSS used for the verdict is the newest version available (4.0 → 3.1 → 3.0 →
2.0), preferring NVD's own ("Primary") assessment over the CNA's ("Secondary").
"""
import httpx

from app.core.connectors import secret
from app.core.cve import bad_cve, normalize_cve

_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_MAX_REFS = 15
_MAX_PRODUCTS = 25
_CVSS_KEYS = (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0"))


def _headers() -> dict:
    h = {"User-Agent": "IntelChecker/1.0", "Accept": "application/json"}
    key = secret("NVD_API_KEY")
    if key:
        h["apiKey"] = key
    return h


def _cvss_entry(metric: dict, version: str) -> dict | None:
    data = metric.get("cvssData") if isinstance(metric.get("cvssData"), dict) else {}
    score = data.get("baseScore")
    if not isinstance(score, (int, float)) or isinstance(score, bool):
        return None
    return {
        "version": data.get("version") or version,
        "score": score,
        # CVSS 2.0 keeps the severity next to cvssData, the others inside it.
        "severity": data.get("baseSeverity") or metric.get("baseSeverity"),
        "vector": data.get("vectorString"),
        "source": metric.get("source"),
        "type": metric.get("type"),
    }


def _cvss(metrics: dict) -> tuple[dict | None, list[dict]]:
    """(the score used for the verdict, every CVSS assessment present)."""
    all_entries: list[dict] = []
    best = None
    for key, version in _CVSS_KEYS:
        entries = [e for m in metrics.get(key) or [] if isinstance(m, dict) and (e := _cvss_entry(m, version))]
        all_entries += entries
        if best is None and entries:
            best = next((e for e in entries if e["type"] == "Primary"), entries[0])
    return best, all_entries


def _ssvc(metrics: dict) -> dict | None:
    """CISA's SSVC decision points (Vulnrichment): exploitation none/poc/active…"""
    for m in metrics.get("ssvcV203") or metrics.get("ssvcV2") or []:
        options = (m.get("ssvcData") or {}).get("options") if isinstance(m, dict) else None
        if isinstance(options, list):
            merged = {k: v for o in options if isinstance(o, dict) for k, v in o.items()}
            return {
                "exploitation": merged.get("exploitation"),
                "automatable": merged.get("automatable"),
                "technical_impact": merged.get("technicalImpact"),
            }
    return None


def _products(cve: dict) -> list[str]:
    """'vendor product' pairs from the vulnerable CPEs (or the CNA's affected list)."""
    out: list[str] = []

    def add(name: str) -> None:
        if name and name not in out:
            out.append(name)

    for conf in cve.get("configurations") or []:
        for node in (conf or {}).get("nodes") or []:
            for match in (node or {}).get("cpeMatch") or []:
                parts = str((match or {}).get("criteria", "")).split(":")
                if (match or {}).get("vulnerable") and len(parts) > 4:
                    add(f"{parts[3]} {parts[4]}".replace("_", " "))
    if not out:
        for a in cve.get("affected") or []:
            for d in (a or {}).get("affectedData") or []:
                add(" ".join(x for x in ((d or {}).get("vendor"), (d or {}).get("product")) if x))
    return out


def _summarise(cve: dict) -> dict:
    metrics = cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {}
    best, all_cvss = _cvss(metrics)
    description = next(
        (d.get("value") for d in cve.get("descriptions") or [] if isinstance(d, dict) and d.get("lang") == "en"), ""
    )
    cwes: list[str] = []
    for w in cve.get("weaknesses") or []:
        for d in (w or {}).get("description") or []:
            v = (d or {}).get("value")
            if isinstance(v, str) and v.startswith("CWE-") and v not in cwes:
                cwes.append(v)
    refs = [
        {"url": r.get("url"), "tags": [t for t in r.get("tags") or [] if isinstance(t, str)]}
        for r in cve.get("references") or [] if isinstance(r, dict) and r.get("url")
    ]
    # Exploit and advisory references first: what an analyst opens.
    refs.sort(key=lambda r: (0 if "Exploit" in r["tags"] else 1 if "Vendor Advisory" in r["tags"] else 2))
    products = _products(cve)
    return {
        "found": True,
        "id": cve.get("id"),
        "status": cve.get("vulnStatus"),
        "rejected": cve.get("vulnStatus") == "Rejected",
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": description,
        "cvss": best,
        "cvss_all": all_cvss,
        "cwes": cwes,
        "ssvc": _ssvc(metrics),
        "kev": {
            "date_added": cve.get("cisaExploitAdd"),
            "due_date": cve.get("cisaActionDue"),
            "name": cve.get("cisaVulnerabilityName"),
        } if cve.get("cisaExploitAdd") else None,
        "products": products[:_MAX_PRODUCTS],
        "products_total": len(products),
        "references": refs[:_MAX_REFS],
        "references_total": len(refs),
        "exploit_refs": sum(1 for r in refs if "Exploit" in r["tags"]),
        "link": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
    }


async def lookup(value: str) -> dict:
    cve_id = normalize_cve(value)
    if not cve_id:
        return bad_cve(value, "NVD")
    has_key = bool(secret("NVD_API_KEY"))
    async with httpx.AsyncClient(timeout=30, headers=_headers()) as client:
        try:
            r = await client.get(_API, params={"cveId": cve_id})
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "NVD request timed out after 30 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach the NVD API."}}

    # NVD answers an invalid key with 404 and a rate-limited client with 403.
    if r.status_code == 404 and has_key:
        return {"error": {"code": "Unauthorized", "message": "Invalid NVD API key."}}
    if r.status_code in (403, 429):
        hint = "" if has_key else " (an API key raises it from 5 to 50 requests per 30 s)"
        return {"error": {"code": "RateLimitExceeded", "message": f"NVD rate limit exceeded{hint}."}}
    if r.status_code >= 500:
        return {"error": {"code": "ServiceUnavailable", "message": f"NVD is unavailable (HTTP {r.status_code})."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"NVD returned HTTP {r.status_code}."}}
    try:
        data = r.json()
    except ValueError:
        return {"error": {"code": "InvalidResponse", "message": "NVD returned a non-JSON response."}}

    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    cve = vulns[0].get("cve") if isinstance(vulns, list) and vulns and isinstance(vulns[0], dict) else None
    if not isinstance(cve, dict):
        return {"found": False, "id": cve_id, "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}
    return _summarise(cve)


async def dispatch(indicator: str, type: str) -> dict:
    if type != "cve":
        return {"error": {"code": "UnsupportedType", "message": f"NVD does not support type '{type}'."}}
    return await lookup(indicator)
