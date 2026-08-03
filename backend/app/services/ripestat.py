import asyncio
import re
import httpx

_BASE = "https://stat.ripe.net/data"


def _normalize_asn(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    return f"AS{digits}" if digits else value.upper()


async def _request(endpoint: str, resource: str) -> dict:
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            r = await client.get(f"{_BASE}/{endpoint}/data.json", params={"resource": resource})
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "RIPEstat request timed out after 15 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach RIPEstat."}}

    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "RIPEstat rate limit exceeded."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"RIPEstat returned HTTP {r.status_code}."}}

    payload = r.json()
    if payload.get("status") != "ok":
        messages = payload.get("messages") or []
        msg = "; ".join(m[1] for m in messages if len(m) > 1) or "RIPEstat could not process this query."
        return {"error": {"code": "ApiError", "message": msg}}

    return payload.get("data", {})


async def check_ip(ip: str) -> dict:
    info, abuse = await asyncio.gather(
        _request("network-info", ip),
        _request("abuse-contact-finder", ip),
    )
    if "error" in info:
        return info
    return {
        "network_info": info,
        "abuse_contacts": None if "error" in abuse else abuse,
    }


async def check_asn(asn: str) -> dict:
    resource = _normalize_asn(asn)
    overview, abuse = await asyncio.gather(
        _request("as-overview", resource),
        _request("abuse-contact-finder", resource),
    )
    if "error" in overview:
        return overview
    return {
        "as_overview": overview,
        "abuse_contacts": None if "error" in abuse else abuse,
    }


async def dispatch(indicator: str, type: str) -> dict:
    if type == "ip":
        return await check_ip(indicator)
    if type == "asn":
        return await check_asn(indicator)
    return {"error": {"code": "UnsupportedType", "message": f"RIPEstat does not support type '{type}'."}}
