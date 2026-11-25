"""abuse.ch SSLBL — SSL/TLS certificates used by botnet C&C servers and malware
(https://sslbl.abuse.ch). Free download, no key.

Only the certificate blacklist (SHA-1 fingerprints) is still maintained: the IP
blacklist was deprecated on 2025-01-03 and the JA3 list stopped in 2021. So this
source answers for SHA-1 hashes only; any other hash length is "not applicable"
(no record), so the card can say so.
"""
import re

from app.core.feeds import CachedFeed

_URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
_SHA1 = re.compile(r"^[0-9a-fA-F]{40}$")


def _parse(text: str) -> dict[str, dict]:
    out = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(",", 2)
        if len(parts) == 3 and _SHA1.match(parts[1]):
            out[parts[1].lower()] = {"listing_date": parts[0], "reason": parts[2].strip()}
    if not out:
        raise ValueError("empty list")
    return out


_feed = CachedFeed("SSLBL", _URL, 3600, _parse)


async def lookup(value: str) -> dict:
    if not _SHA1.match(value):
        return {"applicable": False, "listed": False, "hash": value}
    if err := await _feed.get():
        return err
    hit = _feed.data.get(value.lower())
    return {
        "applicable": True,
        "listed": hit is not None,
        "sha1": value.lower(),
        "listing_date": hit["listing_date"] if hit else None,
        "reason": hit["reason"] if hit else None,
        "list_size": _feed.size,
        "list_updated": _feed.updated,
        "link": f"https://sslbl.abuse.ch/ssl-certificates/sha1/{value.lower()}/" if hit else None,
    }


async def dispatch(indicator: str, type: str) -> dict:
    if type != "hash":
        return {"error": {"code": "UnsupportedType", "message": f"SSLBL does not support type '{type}'."}}
    return await lookup(indicator.strip())
