"""Hostname helpers shared by the domain-level sources (RDAP, Tranco).

The registered domain ("mail.google.com" → "google.com", "a.b.co.uk" → "b.co.uk")
comes from the Public Suffix List snapshot bundled with tldextract — no network
fetch, so it works on networks without internet access. Only the ICANN section of
the list is used: "evil.duckdns.org" → "duckdns.org", which is what registries
(RDAP) and popularity lists (Tranco) know about.
"""
import ipaddress
from urllib.parse import urlsplit

import tldextract

_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def host_of(indicator: str, type: str) -> str:
    """Lower-case hostname of a domain or URL indicator ("" if there is none)."""
    value = indicator.strip()
    if type == "url":
        if "://" not in value:
            value = f"http://{value}"
        try:
            value = urlsplit(value).hostname or ""
        except ValueError:
            return ""
    return value.strip().rstrip(".").lower()


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registered_domain(host: str) -> str:
    """Domain under its public suffix, or "" (IP, single label, unknown suffix)."""
    if not host or is_ip(host):
        return ""
    r = _extract(host)
    return getattr(r, "top_domain_under_public_suffix", None) or r.registered_domain or ""
