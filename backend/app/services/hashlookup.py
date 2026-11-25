"""CIRCL hashlookup — known-good file hashes (https://hashlookup.circl.lu).

Free and keyless. Aggregates NSRL (NIST's National Software Reference Library) and
the packages of the main Linux distributions, app stores, etc., so a hit means the
file ships with known, legitimate software. It is the hash source that can give an
explicit *clean* verdict — except when the record carries `KnownMalicious` (the
same file is also in a malware repository, e.g. EICAR or dual-use tools).

An unknown hash is HTTP 404: returned as `{"found": false}` (no record, not clean).
"""
import re

import httpx

_BASE = "https://hashlookup.circl.lu/lookup"
_HEADERS = {"User-Agent": "IntelChecker/1.0", "Accept": "application/json"}
_ALGOS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
_HEX = re.compile(r"^[0-9a-fA-F]+$")
# Popular files list thousands of parent packages: keep the snapshot small.
_MAX_PARENTS = 20


async def lookup(value: str) -> dict:
    algo = _ALGOS.get(len(value)) if _HEX.match(value) else None
    if not algo:
        return {"error": {"code": "BadRequest", "message": "CIRCL hashlookup accepts MD5, SHA-1, SHA-256 or SHA-512 hashes."}}

    async with httpx.AsyncClient(timeout=15, headers=_HEADERS) as client:
        try:
            r = await client.get(f"{_BASE}/{algo}/{value}")
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "CIRCL hashlookup request timed out after 15 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach CIRCL hashlookup."}}

    if r.status_code == 404:
        return {"found": False, "hash": value, "algorithm": algo}
    if r.status_code == 400:
        return {"error": {"code": "BadRequest", "message": "CIRCL hashlookup rejected the hash as malformed."}}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "CIRCL hashlookup rate limit exceeded."}}
    if r.status_code >= 500:
        return {"error": {"code": "ServiceUnavailable", "message": f"CIRCL hashlookup is unavailable (HTTP {r.status_code})."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"CIRCL hashlookup returned HTTP {r.status_code}."}}

    try:
        data = r.json()
    except ValueError:
        return {"error": {"code": "InvalidResponse", "message": "CIRCL hashlookup returned a non-JSON response."}}
    if not isinstance(data, dict):
        return {"error": {"code": "InvalidResponse", "message": "CIRCL hashlookup returned an unexpected response."}}

    parents = data.get("parents")
    if isinstance(parents, list) and len(parents) > _MAX_PARENTS:
        data["parents"] = parents[:_MAX_PARENTS]
        data["parents_truncated"] = True
    return {"found": True, "algorithm": algo, **data}


async def dispatch(indicator: str, type: str) -> dict:
    if type != "hash":
        return {"error": {"code": "UnsupportedType", "message": f"CIRCL hashlookup does not support type '{type}'."}}
    return await lookup(indicator.strip())
