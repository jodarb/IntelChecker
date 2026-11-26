"""EPSS (FIRST Exploit Prediction Scoring System) — daily estimate of the probability
that a CVE will be exploited in the wild in the next 30 days
(https://www.first.org/epss). Free, no key.

Returns today's score and percentile plus the last 30 days (`scope=time-series`), so
the card can show whether the probability is rising. FIRST serves the scores as
strings; they're converted to numbers here.
"""
import httpx

from app.core.cve import bad_cve, normalize_cve

_API = "https://api.first.org/data/v1/epss"
_HEADERS = {"User-Agent": "IntelChecker/1.0", "Accept": "application/json"}


def _num(v) -> float | None:
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return x if 0 <= x <= 1 else None


async def lookup(value: str) -> dict:
    cve_id = normalize_cve(value)
    if not cve_id:
        return bad_cve(value, "EPSS")
    async with httpx.AsyncClient(timeout=20, headers=_HEADERS) as client:
        try:
            r = await client.get(_API, params={"cve": cve_id, "scope": "time-series"})
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "EPSS request timed out."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach the EPSS API (api.first.org)."}}

    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "EPSS rate limit exceeded."}}
    if r.status_code >= 500:
        return {"error": {"code": "ServiceUnavailable", "message": f"EPSS is unavailable (HTTP {r.status_code})."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"EPSS returned HTTP {r.status_code}."}}
    try:
        data = r.json()
    except ValueError:
        return {"error": {"code": "InvalidResponse", "message": "EPSS returned a non-JSON response."}}

    rows = data.get("data") if isinstance(data, dict) else None
    row = rows[0] if isinstance(rows, list) and rows and isinstance(rows[0], dict) else None
    link = f"https://www.first.org/epss/data_stats?cve={cve_id}"
    epss = _num(row.get("epss")) if row else None
    if row is None or epss is None:
        # New, reserved or rejected CVEs have no score yet.
        return {"found": False, "cve": cve_id, "link": link}

    series = [
        {"date": p.get("date"), "epss": e, "percentile": _num(p.get("percentile"))}
        for p in row.get("time-series") or []
        if isinstance(p, dict) and (e := _num(p.get("epss"))) is not None
    ]
    series.append({"date": row.get("date"), "epss": epss, "percentile": _num(row.get("percentile"))})
    series = sorted({p["date"]: p for p in series}.values(), key=lambda p: str(p["date"]))
    oldest = series[0]["epss"] if len(series) > 1 else None
    return {
        "found": True,
        "cve": cve_id,
        "epss": epss,
        "percentile": _num(row.get("percentile")),
        "date": row.get("date"),
        "change_30d": round(epss - oldest, 6) if oldest is not None else None,
        "series": series,
        "link": link,
    }


async def dispatch(indicator: str, type: str) -> dict:
    if type != "cve":
        return {"error": {"code": "UnsupportedType", "message": f"EPSS does not support type '{type}'."}}
    return await lookup(indicator)
