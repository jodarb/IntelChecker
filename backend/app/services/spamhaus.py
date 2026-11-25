"""Spamhaus — IP, domain and ASN reputation (https://www.spamhaus.org).

  * IPs (and URLs whose host is an IP): DNS query to ZEN (SBL, CSS, XBL, DROP, PBL).
  * Domains / URL hosts: DNS query to the DBL, for the registered domain and, when
    different, the full host (the DBL also lists abused subdomains).
  * ASNs: the ASN-DROP list (JSON download, cached), "bulletproof" / hijacked networks.

Spamhaus refuses DNSBL queries that arrive through public resolvers (8.8.8.8,
1.1.1.1…): use your own resolver (`SPAMHAUS_DNS_SERVER` in backend/.env to pick one)
or a free Data Query Service key (`SPAMHAUS_DQS_KEY`, Connectors page), which uses
the dq.spamhaus.net zones and works from any resolver. Free for low-volume,
non-commercial use — see https://www.spamhaus.org/organization/dnsblusage/.

Each listing is returned with its return code; the verdict engines score by code.
"""
import ipaddress
import json
import os

import dns.asyncresolver
import dns.exception
import dns.resolver

from app.core.connectors import secret
from app.core.domains import host_of, is_ip, registered_domain
from app.core.feeds import CachedFeed

# Return code → (list, category). Categories are translated in the UI.
CODES = {
    "127.0.0.2": ("SBL", "spam"),
    "127.0.0.3": ("SBL CSS", "css"),
    "127.0.0.4": ("XBL", "exploited"),
    "127.0.0.5": ("XBL", "exploited"),
    "127.0.0.6": ("XBL", "exploited"),
    "127.0.0.7": ("XBL", "exploited"),
    "127.0.0.9": ("DROP", "drop"),
    "127.0.0.10": ("PBL", "policy"),
    "127.0.0.11": ("PBL", "policy"),
    "127.0.1.2": ("DBL", "spam-domain"),
    "127.0.1.4": ("DBL", "phish"),
    "127.0.1.5": ("DBL", "malware"),
    "127.0.1.6": ("DBL", "botnet"),
    "127.0.1.102": ("DBL", "abused-spam"),
    "127.0.1.103": ("DBL", "abused-redirector"),
    "127.0.1.104": ("DBL", "abused-phish"),
    "127.0.1.105": ("DBL", "abused-malware"),
    "127.0.1.106": ("DBL", "abused-botnet"),
}
# Answers that mean "your query was refused", not "listed".
_REFUSED = {
    "127.255.255.252": ("BadRequest", "Spamhaus rejected the query as malformed."),
    "127.0.1.255": ("BadRequest", "Spamhaus DBL does not accept IP addresses."),
    "127.255.255.254": ("ResolverBlocked",
                        "Spamhaus refuses queries from public DNS resolvers: set SPAMHAUS_DNS_SERVER to your own "
                        "resolver or add a free Spamhaus DQS key on Connectors."),
    "127.255.255.255": ("RateLimitExceeded", "Spamhaus query limit exceeded for this resolver."),
}

_ASNDROP_URL = "https://www.spamhaus.org/drop/asndrop.json"


def _parse_asndrop(text: str) -> dict[int, dict]:
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if isinstance(rec, dict) and isinstance(rec.get("asn"), int):
            out[rec["asn"]] = rec
    if not out:
        raise ValueError("empty list")
    return out


_asndrop = CachedFeed("Spamhaus ASN-DROP", _ASNDROP_URL, 12 * 3600, _parse_asndrop)


def _zones() -> tuple[str, str, bool]:
    key = secret("SPAMHAUS_DQS_KEY")
    if key:
        return f"{key}.zen.dq.spamhaus.net", f"{key}.dbl.dq.spamhaus.net", True
    return "zen.spamhaus.org", "dbl.spamhaus.org", False


def _resolver() -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver()
    server = os.environ.get("SPAMHAUS_DNS_SERVER", "").strip()
    if server:
        r.nameservers = [s.strip() for s in server.split(",") if s.strip()]
    r.lifetime = 6
    return r


async def _query(res, name: str) -> list[str] | dict:
    """A records of `name` ([] = not listed), or {"error": …}."""
    try:
        answer = await res.resolve(name, "A")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.Timeout:
        return {"error": {"code": "Timeout", "message": "Spamhaus DNS query timed out."}}
    except (dns.resolver.NoNameservers, dns.exception.DNSException):
        return {"error": {"code": "NetworkError", "message": "Could not reach a DNS resolver for the Spamhaus query."}}
    return sorted({rr.address for rr in answer})


def _reverse(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(ip.split(".")))
    return ".".join(reversed(addr.exploded.replace(":", "")))


async def _dnsbl(queries: list[tuple[str, str, str]], dqs: bool) -> dict:
    """queries: (label shown, name to resolve, zone kind). Never puts the DQS key in the result."""
    res = _resolver()
    checks, listings = [], []
    for shown, name, zone in queries:
        codes = await _query(res, name)
        if isinstance(codes, dict):
            return codes
        for code in codes:
            if code in _REFUSED:
                err_code, msg = _REFUSED[code]
                return {"error": {"code": err_code, "message": msg}}
        checks.append({"zone": zone, "query": shown, "codes": codes})
        for code in codes:
            lst, cat = CODES.get(code, ("Spamhaus", "other"))
            listings.append({"code": code, "list": lst, "category": cat, "query": shown, "zone": zone})
    return {"checks": checks, "listings": listings, "listed": bool(listings), "dqs": dqs}


async def check_ip(ip: str) -> dict:
    zen, _, dqs = _zones()
    try:
        name = f"{_reverse(ip)}.{zen}"
    except ValueError:
        return {"error": {"code": "BadRequest", "message": f"'{ip}' is not a valid IP address."}}
    out = await _dnsbl([(ip, name, "zen")], dqs)
    return out if "error" in out else {"indicator": ip, **out, "link": f"https://check.spamhaus.org/results/?query={ip}"}


async def check_domain(host: str) -> dict:
    _, dbl, dqs = _zones()
    domain = registered_domain(host)
    if not domain:
        return {"error": {"code": "BadRequest", "message": f"'{host}' has no registrable domain."}}
    names = [domain] + ([host] if host != domain else [])
    out = await _dnsbl([(n, f"{n}.{dbl}", "dbl") for n in names], dqs)
    return out if "error" in out else {"indicator": host, **out, "link": f"https://check.spamhaus.org/results/?query={domain}"}


async def check_asn(value: str) -> dict:
    raw = value.strip().upper().removeprefix("AS")
    if not raw.isdigit():
        return {"error": {"code": "BadRequest", "message": f"'{value}' is not a valid ASN."}}
    if err := await _asndrop.get():
        return err
    rec = _asndrop.data.get(int(raw))
    listings = [{"code": "asndrop", "list": "ASN-DROP", "category": "asn-drop", "query": f"AS{raw}", "zone": "asndrop"}] if rec else []
    return {
        "indicator": f"AS{raw}",
        "checks": [{"zone": "asndrop", "query": f"AS{raw}", "codes": ["asndrop"] if rec else []}],
        "listings": listings,
        "listed": bool(rec),
        "asn_record": rec,
        "list_size": _asndrop.size,
        "list_updated": _asndrop.updated,
        "link": "https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
    }


async def dispatch(indicator: str, type: str) -> dict:
    if type == "ip":
        return await check_ip(indicator.strip())
    if type == "asn":
        return await check_asn(indicator)
    if type in ("domain", "url"):
        host = host_of(indicator, type)
        if is_ip(host):
            return await check_ip(host.strip("[]"))
        return await check_domain(host)
    return {"error": {"code": "UnsupportedType", "message": f"Spamhaus does not support type '{type}'."}}
