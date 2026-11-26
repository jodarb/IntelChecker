"""Kaspersky OpenTIP (Threat Intelligence Portal) — reputation of IPs, domains, URLs and
file hashes (https://opentip.kaspersky.com). Free API key (https://opentip.kaspersky.com/token)
with a daily request quota.

    GET https://opentip.kaspersky.com/api/v1/search/{ip|domain|url|hash}?request=<value>
    header x-api-key: <token>

Every answer carries a `Zone`, Kaspersky's verdict for the object: Red (dangerous),
Orange (not trusted), Yellow (adware / other potentially unwanted), Green (good),
Grey (not categorised). The verdict uses only `Zone`; the rest of the answer
(`IpGeneralInfo`, `DomainGeneralInfo`, `UrlGeneralInfo`, `FileGeneralInfo`, WHOIS,
detections…) is passed through, with long lists trimmed, and rendered generically by
the card — so a field Kaspersky adds or renames never breaks the lookup.

Status codes: 400 malformed request (URLs need a path: `example.com/` not
`example.com`), 401 bad key, 403 quota or request limit exceeded, 404 no results
for the object.
"""
import re
from urllib.parse import quote, urlsplit

import httpx

from app.core.connectors import secret

_API = "https://opentip.kaspersky.com/api/v1/search/{}"
_PORTAL = "https://opentip.kaspersky.com/{}/results?tab=lookup"
_MAX_LIST = 20
_HASH = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")


def _trim(value, depth: int = 0):
    """Lists capped at _MAX_LIST items (detections, categories, IPs…), recursively."""
    if isinstance(value, list):
        return [_trim(v, depth + 1) for v in value[:_MAX_LIST]]
    if isinstance(value, dict) and depth < 6:
        return {k: _trim(v, depth + 1) for k, v in value.items()}
    return value


def _url_with_path(url: str) -> str:
    """OpenTIP rejects a bare host as a URL: give it at least the root path."""
    raw = url.strip()
    parts = urlsplit(raw if "://" in raw else f"http://{raw}")
    if parts.netloc and not parts.path:
        return raw + "/"
    return raw


async def lookup(value: str, type: str) -> dict:
    key = secret("KASPERSKY_OPENTIP_API_KEY")
    if not key:
        return {"error": {"code": "MissingApiKey", "message": "Kaspersky OpenTIP API key is not configured."}}
    value = value.strip()
    if type == "hash" and not _HASH.match(value):
        # OpenTIP knows MD5, SHA-1 and SHA-256 only.
        return {"applicable": False, "hash": value}
    request = _url_with_path(value) if type == "url" else value

    async with httpx.AsyncClient(timeout=20, headers={"x-api-key": key, "Accept": "application/json"}) as client:
        try:
            r = await client.get(_API.format(type), params={"request": request})
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "Kaspersky OpenTIP request timed out after 20 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach Kaspersky OpenTIP."}}

    if r.status_code == 401:
        return {"error": {"code": "Unauthorized", "message": "Invalid Kaspersky OpenTIP API key."}}
    if r.status_code in (403, 429):
        return {"error": {"code": "RateLimitExceeded", "message": "Kaspersky OpenTIP quota or request limit exceeded (the free key has a daily quota)."}}
    if r.status_code == 404:
        return {"error": {"code": "NotFound", "message": "No Kaspersky OpenTIP results for this indicator."}}
    if r.status_code == 400:
        hint = " A URL needs a path; look up the bare host as a domain." if type == "url" else ""
        return {"error": {"code": "BadRequest", "message": f"Kaspersky OpenTIP rejected the request as malformed.{hint}"}}
    if r.status_code >= 500:
        return {"error": {"code": "ServiceUnavailable", "message": f"Kaspersky OpenTIP is unavailable (HTTP {r.status_code})."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"Kaspersky OpenTIP returned HTTP {r.status_code}."}}
    try:
        data = r.json()
    except ValueError:
        return {"error": {"code": "InvalidResponse", "message": "Kaspersky OpenTIP returned a non-JSON response."}}
    if not isinstance(data, dict):
        return {"error": {"code": "InvalidResponse", "message": "Kaspersky OpenTIP returned an unexpected response."}}

    out = _trim(data)
    out["applicable"] = True
    out["link"] = _PORTAL.format(quote(request.lower() if type in ("hash", "domain") else request, safe=""))
    return out


async def dispatch(indicator: str, type: str) -> dict:
    if type not in ("ip", "domain", "url", "hash"):
        return {"error": {"code": "UnsupportedType", "message": f"Kaspersky OpenTIP does not support type '{type}'."}}
    return await lookup(indicator, type)
