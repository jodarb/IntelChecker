import re
import time
import asyncio
import httpx

_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
_TTL_SECONDS = 86400  # ATT&CK data changes infrequently; refresh once a day
_TIMEOUT_SECONDS = 60  # the STIX bundle is ~50 MB

_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_CITATION_RE = re.compile(r"\(Citation:[^)]+\)")

# Alias/name (lowercased) -> group record
_index: dict[str, dict] = {}
# Name + aliases of every group and every malware/tool, used by the frontend
# Summary to recognise actor names hidden in free-text tags and to merge malware
# family spellings (e.g. "Qbot" / "QakBot" / "Pinkslipbot").
_aliases: dict[str, list[list[str]]] = {"groups": [], "software": []}
_fetched_at: float = 0.0
_lock = asyncio.Lock()


def _clean_description(text: str) -> str:
    text = _MD_LINK_RE.sub(r"\1", text)
    text = _CITATION_RE.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


def _external_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _build_index(bundle: dict) -> tuple[dict[str, dict], dict[str, list[list[str]]]]:
    objects = bundle.get("objects", [])
    software_aliases: list[list[str]] = []

    groups: dict[str, dict] = {}
    techniques: dict[str, dict] = {}
    software: dict[str, dict] = {}
    uses: list[tuple[str, str]] = []

    for obj in objects:
        obj_type = obj.get("type")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        if obj_type == "intrusion-set":
            groups[obj["id"]] = {
                "attack_id": _external_id(obj),
                "name": obj.get("name", ""),
                "aliases": obj.get("aliases") or [obj.get("name", "")],
                "description": _clean_description(obj.get("description", "")),
                "techniques": [],
                "software": [],
            }
        elif obj_type == "attack-pattern":
            techniques[obj["id"]] = {"attack_id": _external_id(obj), "name": obj.get("name", "")}
        elif obj_type in ("malware", "tool"):
            software[obj["id"]] = {"attack_id": _external_id(obj), "name": obj.get("name", "")}
            names = [obj.get("name", ""), *(obj.get("x_mitre_aliases") or [])]
            software_aliases.append(list(dict.fromkeys(n for n in names if n)))
        elif obj_type == "relationship" and obj.get("relationship_type") == "uses":
            uses.append((obj.get("source_ref"), obj.get("target_ref")))

    for source_ref, target_ref in uses:
        group = groups.get(source_ref)
        if not group:
            continue
        if target_ref in techniques:
            group["techniques"].append(techniques[target_ref])
        elif target_ref in software:
            group["software"].append(software[target_ref])

    for group in groups.values():
        group["url"] = f"https://attack.mitre.org/groups/{group['attack_id']}" if group["attack_id"] else None

    name_index: dict[str, dict] = {}
    for group in groups.values():
        for alias in group["aliases"]:
            key = alias.strip().lower()
            if key and key not in name_index:
                name_index[key] = group

    group_aliases = [
        list(dict.fromkeys(n for n in [g["name"], *g["aliases"]] if n)) for g in groups.values()
    ]
    return name_index, {"groups": group_aliases, "software": software_aliases}


async def _refresh() -> dict | None:
    global _index, _aliases, _fetched_at

    async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
        try:
            r = await client.get(_URL)
        except httpx.TimeoutException:
            return {"error": {"code": "Timeout", "message": "MITRE ATT&CK dataset request timed out."}}
        except httpx.RequestError:
            return {"error": {"code": "NetworkError", "message": "Could not reach the MITRE ATT&CK dataset."}}

    if not r.is_success:
        return {"error": {
            "code": "HttpError",
            "message": f"MITRE ATT&CK dataset request returned HTTP {r.status_code}.",
        }}

    _index, _aliases = _build_index(r.json())
    _fetched_at = time.time()
    return None


async def _ensure_fresh() -> dict | None:
    if _index and (time.time() - _fetched_at) < _TTL_SECONDS:
        return None

    async with _lock:
        if _index and (time.time() - _fetched_at) < _TTL_SECONDS:
            return None
        error = await _refresh()
        # If the refresh failed but we still have a (stale) index, keep serving it
        # instead of failing the whole request.
        if error and not _index:
            return error

    return None


async def check_actor(name: str) -> dict:
    error = await _ensure_fresh()
    if error:
        return error

    group = _index.get(name.strip().lower())
    if not group:
        return {"error": {"code": "NotFound", "message": f"'{name}' was not found in the MITRE ATT&CK dataset."}}

    return group


async def alias_lists() -> dict:
    """Group and software names with their aliases. Empty lists if the dataset
    can't be fetched (e.g. no internet) — callers treat it as best-effort."""
    error = await _ensure_fresh()
    if error:
        return {"groups": [], "software": [], **error}
    return _aliases


async def dispatch(indicator: str, type: str) -> dict:
    if type == "threat-actor":
        return await check_actor(indicator)
    return {"error": {"code": "UnsupportedType", "message": f"MITRE ATT&CK does not support type '{type}'."}}
