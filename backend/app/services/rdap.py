"""RDAP — domain registration data (registrar, creation date, status).

Free and keyless. The RDAP server of each TLD comes from IANA's bootstrap file
(https://data.iana.org/rdap/dns.json, cached for a day); the query goes straight to
the registry. Subdomains are reduced to their registered domain first.

The point is **domain age**: a domain registered days ago is a classic phishing /
malware signal. `age_days` is computed here, at lookup time, so history snapshots
keep the age the domain had when it was checked and the verdict replays the same.

Some ccTLDs (e.g. .es, .de) publish no RDAP service: reported as `NoRdapService`.
"""
import asyncio
import time
from datetime import datetime, timezone

import httpx

from app.core.domains import host_of, is_ip, registered_domain

_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_BOOTSTRAP_TTL = 86400
_HEADERS = {"User-Agent": "IntelChecker/1.0", "Accept": "application/rdap+json, application/json"}

_bootstrap: dict[str, str] = {}
_bootstrap_at = 0.0
_bootstrap_lock = asyncio.Lock()


async def _servers(client: httpx.AsyncClient) -> dict[str, str] | dict:
    """TLD → RDAP base URL, or {"error": …} if the bootstrap file can't be fetched."""
    global _bootstrap, _bootstrap_at
    async with _bootstrap_lock:
        if _bootstrap and time.time() - _bootstrap_at < _BOOTSTRAP_TTL:
            return _bootstrap
        try:
            r = await client.get(_BOOTSTRAP_URL)
            r.raise_for_status()
            services = r.json()["services"]
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            if _bootstrap:   # stale is better than nothing
                return _bootstrap
            return {"error": {"code": "ServiceUnavailable", "message": "Could not load the IANA RDAP bootstrap file."}}
        table = {}
        for tlds, urls in services:
            base = next((u for u in urls if u.startswith("https://")), urls[0] if urls else None)
            if base:
                for tld in tlds:
                    table[tld.lower()] = base if base.endswith("/") else f"{base}/"
        _bootstrap, _bootstrap_at = table, time.time()
        return table


def _parse_date(v) -> datetime | None:
    if not isinstance(v, str) or not v:
        return None
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _vcard_name(entity: dict) -> str | None:
    card = entity.get("vcardArray")
    if not (isinstance(card, list) and len(card) > 1 and isinstance(card[1], list)):
        return None
    for prop in card[1]:
        if isinstance(prop, list) and len(prop) > 3 and prop[0] == "fn" and prop[3]:
            return str(prop[3])
    return None


def _summarize(domain: str, server: str, raw: dict) -> dict:
    events = {
        e.get("eventAction"): e.get("eventDate")
        for e in raw.get("events") or [] if isinstance(e, dict)
    }
    registrar = None
    registrar_iana_id = None
    abuse_email = None
    for ent in raw.get("entities") or []:
        if not isinstance(ent, dict) or "registrar" not in (ent.get("roles") or []):
            continue
        registrar = _vcard_name(ent) or ent.get("handle")
        for pid in ent.get("publicIds") or []:
            if isinstance(pid, dict) and pid.get("type") == "IANA Registrar ID":
                registrar_iana_id = pid.get("identifier")
        for sub in ent.get("entities") or []:
            if isinstance(sub, dict) and "abuse" in (sub.get("roles") or []):
                for prop in ((sub.get("vcardArray") or [None, []])[1] or []):
                    if isinstance(prop, list) and len(prop) > 3 and prop[0] == "email" and prop[3]:
                        abuse_email = prop[3]
    registered = _parse_date(events.get("registration"))
    now = datetime.now(timezone.utc)
    return {
        "found": True,
        "domain": (raw.get("ldhName") or domain).lower(),
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "age_days": max(0, (now - registered).days) if registered else None,
        "checked_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "registrar": registrar,
        "registrar_iana_id": registrar_iana_id,
        "abuse_email": abuse_email,
        "status": [s for s in raw.get("status") or [] if isinstance(s, str)],
        "nameservers": [
            str(n.get("ldhName")).lower() for n in raw.get("nameservers") or []
            if isinstance(n, dict) and n.get("ldhName")
        ],
        "dnssec": bool((raw.get("secureDNS") or {}).get("delegationSigned")),
        "rdap_url": f"{server}domain/{domain}",
    }


async def lookup(indicator: str, type: str) -> dict:
    host = host_of(indicator, type)
    if is_ip(host):
        return {"error": {"code": "UnsupportedType", "message": "RDAP domain lookup does not apply to an IP address host."}}
    domain = registered_domain(host)
    if not domain:
        return {"error": {"code": "BadRequest", "message": f"'{host or indicator}' has no registrable domain."}}
    tld = domain.rsplit(".", 1)[-1]

    async with httpx.AsyncClient(timeout=15, headers=_HEADERS, follow_redirects=True) as client:
        servers = await _servers(client)
        if "error" in servers:
            return servers
        server = servers.get(tld)
        if not server:
            return {"error": {"code": "NoRdapService", "message": f"The .{tld} registry does not publish an RDAP service."}}
        try:
            r = await client.get(f"{server}domain/{domain}")
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": f"RDAP request to the .{tld} registry timed out after 15 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": f"Could not reach the .{tld} RDAP server."}}

    if r.status_code == 404:
        return {"found": False, "domain": domain, "rdap_url": f"{server}domain/{domain}"}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": f"The .{tld} RDAP server rate limit was exceeded."}}
    if r.status_code >= 500:
        return {"error": {"code": "ServiceUnavailable", "message": f"The .{tld} RDAP server is unavailable (HTTP {r.status_code})."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"The .{tld} RDAP server returned HTTP {r.status_code}."}}
    try:
        raw = r.json()
    except ValueError:
        return {"error": {"code": "InvalidResponse", "message": "The RDAP server returned a non-JSON response."}}
    if not isinstance(raw, dict):
        return {"error": {"code": "InvalidResponse", "message": "The RDAP server returned an unexpected response."}}
    return _summarize(domain, server, raw)


async def dispatch(indicator: str, type: str) -> dict:
    if type not in ("domain", "url"):
        return {"error": {"code": "UnsupportedType", "message": f"RDAP does not support type '{type}'."}}
    return await lookup(indicator, type)
