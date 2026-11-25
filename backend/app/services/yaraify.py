"""abuse.ch YARAify — YARA rule and ClamAV matches on submitted files
(https://yaraify.abuse.ch). Uses the unified abuse.ch key (ABUSECH_AUTH_KEY).

A file is scanned every time someone submits it, so popular samples have hundreds
of tasks: the rules and ClamAV signatures are merged across all of them and only
the latest tasks are kept, to keep history snapshots small. Many community rules
are generic ("Detect_Golang_Binary"), so rule matches are context; ClamAV
signatures are the maliciousness signal.
"""
import httpx

from app.core.connectors import secret

_URL = "https://yaraify-api.abuse.ch/api/v1/"
_MAX_TASKS = 10


def _summarize(data: dict) -> dict:
    tasks = [t for t in data.get("tasks") or [] if isinstance(t, dict)]
    tasks.sort(key=lambda t: str(t.get("time_stamp") or ""), reverse=True)
    rules: dict[str, dict] = {}
    clamav: list[str] = []
    file_names: list[str] = []
    for t in tasks:
        for r in t.get("static_results") or []:
            if isinstance(r, dict) and r.get("rule_name") and r["rule_name"] not in rules:
                rules[r["rule_name"]] = {k: r.get(k) for k in ("rule_name", "author", "description", "reference", "tlp")}
        for sig in t.get("clamav_results") or []:
            if isinstance(sig, str) and sig not in clamav:
                clamav.append(sig)
        name = t.get("file_name")
        if isinstance(name, str) and name not in file_names:
            file_names.append(name)
    return {
        "found": True,
        "metadata": data.get("metadata") or {},
        "rules": list(rules.values()),
        "clamav": clamav,
        "file_names": file_names[:20],
        "tasks_total": len(tasks),
        "tasks": [
            {k: t.get(k) for k in ("task_id", "time_stamp", "file_name")}
            for t in tasks[:_MAX_TASKS]
        ],
    }


async def lookup(value: str) -> dict:
    key = secret("ABUSECH_AUTH_KEY")
    if not key:
        return {"error": {"code": "MissingApiKey", "message": "abuse.ch API key is not configured."}}

    async with httpx.AsyncClient(timeout=20) as client:
        try:
            r = await client.post(_URL, json={"query": "lookup_hash", "search_term": value}, headers={"Auth-Key": key})
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "YARAify request timed out after 20 s."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach YARAify."}}

    if r.status_code in (401, 403):
        return {"error": {"code": "Unauthorized", "message": "Invalid abuse.ch API key."}}
    if r.status_code == 429:
        return {"error": {"code": "RateLimitExceeded", "message": "YARAify rate limit exceeded."}}
    if r.status_code >= 500:
        return {"error": {"code": "ServiceUnavailable", "message": f"YARAify is unavailable (HTTP {r.status_code})."}}
    if not r.is_success:
        return {"error": {"code": "HttpError", "message": f"YARAify returned HTTP {r.status_code}."}}
    try:
        data = r.json()
    except ValueError:
        return {"error": {"code": "InvalidResponse", "message": "YARAify returned a non-JSON response."}}

    status = data.get("query_status") if isinstance(data, dict) else None
    if status in ("no_results", "not_found", "hash_not_found"):
        return {"found": False}
    if status in ("illegal_search_term", "illegal_hash"):
        return {"error": {"code": "BadRequest", "message": "YARAify rejected the hash as malformed."}}
    if status != "ok" or not isinstance(data.get("data"), dict):
        return {"error": {"code": "ApiError", "message": f"YARAify error: {status}"}}
    return _summarize(data["data"])


async def dispatch(indicator: str, type: str) -> dict:
    if type != "hash":
        return {"error": {"code": "UnsupportedType", "message": f"YARAify does not support type '{type}'."}}
    return await lookup(indicator.strip())
