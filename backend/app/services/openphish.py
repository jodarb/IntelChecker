"""OpenPhish — community phishing feed (https://openphish.com). Free, no key.

The community feed is a plain list of currently active phishing URLs (a few
hundred, refreshed every few hours upstream), downloaded and kept for an hour.

  * URL lookups: listed itself → `exact`; other phishing URLs on the same host are
    returned as `matches` (the host is serving phishing).
  * Domain / IP lookups: phishing URLs whose host *is* that domain (or www.) or IP.
    A parent domain is never matched by its subdomains' URLs (sites.google.com
    phishing says nothing about google.com).
"""
from urllib.parse import urlsplit

from app.core.domains import host_of
from app.core.feeds import CachedFeed

_URL = "https://openphish.com/feed.txt"
_MAX_MATCHES = 25


def _norm_url(u: str) -> str:
    u = u.strip()
    if "://" not in u:
        u = f"http://{u}"
    try:
        p = urlsplit(u)
    except ValueError:
        return u.lower()
    host = (p.hostname or "").lower()
    port = f":{p.port}" if p.port else ""
    path = p.path.rstrip("/")
    query = f"?{p.query}" if p.query else ""
    return f"{p.scheme.lower()}://{host}{port}{path}{query}"


def _parse(text: str) -> dict:
    urls = [line.strip() for line in text.splitlines() if line.strip().startswith(("http://", "https://"))]
    if not urls:
        raise ValueError("empty feed")
    by_host: dict[str, list[str]] = {}
    for u in urls:
        by_host.setdefault(host_of(u, "url"), []).append(u)
    return {"urls": {_norm_url(u) for u in urls}, "by_host": by_host, "count": len(urls)}


_feed = CachedFeed("OpenPhish", _URL, 3600, _parse, count=lambda d: d["count"])


async def lookup(indicator: str, type: str) -> dict:
    host = host_of(indicator, type)
    if not host:
        return {"error": {"code": "BadRequest", "message": "The indicator has no host to look up."}}
    if err := await _feed.get():
        return err
    by_host = _feed.data["by_host"]
    hosts = [host] if type == "ip" else [host, f"www.{host}"] if type == "domain" else [host]
    matches = [u for h in hosts for u in by_host.get(h, [])]
    exact = _norm_url(indicator) in _feed.data["urls"] if type == "url" else bool(matches)
    return {
        "kind": "url" if type == "url" else "host",
        "host": host,
        "exact": exact,
        "listed": exact or bool(matches),
        "matches": matches[:_MAX_MATCHES],
        "matches_total": len(matches),
        "feed_size": _feed.size,
        "feed_updated": _feed.updated,
    }


async def dispatch(indicator: str, type: str) -> dict:
    if type not in ("url", "domain", "ip"):
        return {"error": {"code": "UnsupportedType", "message": f"OpenPhish does not support type '{type}'."}}
    return await lookup(indicator, type)
