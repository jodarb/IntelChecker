"""Connector credentials store: API keys and MISP instances, managed from the
Connectors page (admin only).

Persisted to backend/data/connectors.json (Docker volume, gitignored), written with
0600 permissions. Keys are stored in clear, like backend/.env — protect the volume
and its backups the same way. The API never returns a stored key, only its last
four characters.

  * API keys: a key saved here wins over the same variable in backend/.env; removing
    it from here falls back to the .env value (if any). So existing deployments keep
    working untouched, and the .env can be emptied once every key is in the UI.
  * MISP: while "misp" is absent from the file, the instances defined in .env
    (MISP_<N>_*) are used. The first add/edit/delete from the Connectors page copies
    them into the file and, from then on, MISP_<N>_* in .env is ignored.

The file is re-read whenever its mtime changes, so every worker sees a change at once.
"""
import json
import os
import re
import threading
from pathlib import Path

from app.core import config
from app.core.auth import api_error

_PATH = Path(__file__).parent.parent.parent / "data" / "connectors.json"
_lock = threading.Lock()
_cache: dict = {"mtime": None, "data": {}}

# Order of the Connectors page. `engines` are the sources each key powers; `optional`
# means the source works without it (PhishTank: lower priority without a key).
CONNECTORS: list[dict] = [
    {"key": "VIRUSTOTAL_API_KEY", "label": "VirusTotal", "engines": ["virustotal"],
     "signup": "https://www.virustotal.com/gui/my-apikey"},
    {"key": "ABUSEIPDB_API_KEY", "label": "AbuseIPDB", "engines": ["abuseipdb"],
     "signup": "https://www.abuseipdb.com/account/api"},
    {"key": "ABUSECH_AUTH_KEY", "label": "abuse.ch", "engines": ["abusech", "urlhaus", "malwarebazaar"],
     "signup": "https://auth.abuse.ch/"},
    {"key": "ALIENVAULT_API_KEY", "label": "AlienVault OTX", "engines": ["alienvault"],
     "signup": "https://otx.alienvault.com/api"},
    {"key": "SHODAN_API_KEY", "label": "Shodan", "engines": ["shodan"],
     "signup": "https://account.shodan.io/"},
    {"key": "URLSCAN_API_KEY", "label": "urlscan.io", "engines": ["urlscan"],
     "signup": "https://urlscan.io/user/profile/"},
    {"key": "IPINFO_API_KEY", "label": "IPinfo", "engines": ["ipinfo"],
     "signup": "https://ipinfo.io/account/token"},
    {"key": "RECORDED_FUTURE_API_KEY", "label": "Recorded Future", "engines": ["recordedfuture"],
     "signup": "https://api.recordedfuture.com/"},
    {"key": "ANYRUN_API_KEY", "label": "ANY.RUN", "engines": ["anyrun"],
     "signup": "https://app.any.run/"},
    {"key": "GREYNOISE_API_KEY", "label": "GreyNoise", "engines": ["greynoise"],
     "signup": "https://viz.greynoise.io/account/"},
    {"key": "HYBRID_ANALYSIS_API_KEY", "label": "Hybrid Analysis", "engines": ["hybridanalysis"],
     "signup": "https://hybrid-analysis.com/my-account?tab=%23api-key-tab"},
    {"key": "GOOGLE_SAFE_BROWSING_API_KEY", "label": "Google Safe Browsing", "engines": ["safebrowsing"],
     "signup": "https://developers.google.com/safe-browsing/v4/get-started"},
    {"key": "PHISHTANK_API_KEY", "label": "PhishTank", "engines": ["phishtank"], "optional": True,
     "signup": "https://www.phishtank.com/api_register.php"},
]
_CONNECTOR_KEYS = {c["key"] for c in CONNECTORS}
KEYED_ENGINES = {e for c in CONNECTORS for e in c["engines"]}

DEFAULT_MISP_WEIGHT = 0
DEFAULT_MISP_KNOWLEDGE_WEIGHT = 9

_MISP_ID_RE = re.compile(r"^misp_(\d+)$")
_MAX_SECRET = 1024


# ── Persistence ───────────────────────────────────────────────────────────────

def _load() -> dict:
    try:
        mtime = _PATH.stat().st_mtime_ns
    except FileNotFoundError:
        _cache.update(mtime=None, data={})
        return {}
    if mtime != _cache["mtime"]:
        try:
            data = json.loads(_PATH.read_text())
        except (OSError, json.JSONDecodeError):
            data = {}
        _cache.update(mtime=mtime, data=data if isinstance(data, dict) else {})
    return _cache["data"]


def _write(data: dict) -> None:
    """Atomic write with 0600 permissions (the tmp file is created 0600, so the
    keys are never readable by others, not even for an instant)."""
    _PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = _PATH.with_suffix(".json.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, _PATH)
    _cache["mtime"] = None  # force a re-read


def _copy() -> dict:
    return json.loads(json.dumps(_load()))


# ── API keys ──────────────────────────────────────────────────────────────────

def secret(env_name: str) -> str:
    """The key in force for an env-style name: Connectors page first, then .env."""
    stored = (_load().get("keys") or {}).get(env_name)
    if isinstance(stored, str) and stored:
        return stored
    return os.environ.get(env_name, "").strip()


def _hint(value: str) -> str:
    return value[-4:] if len(value) >= 12 else ""


def _validate_secret(value, field: str = "key") -> str:
    if not isinstance(value, str):
        raise api_error(422, "InvalidSecret", f"The {field} must be a string.")
    value = value.strip()
    # Keys end up in HTTP headers: no whitespace or control characters.
    if not value or len(value) > _MAX_SECRET or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise api_error(422, "InvalidSecret",
                        f"The {field} must be 1–{_MAX_SECRET} characters with no spaces or control characters.")
    return value


def _check_connector(env_name: str) -> None:
    if env_name not in _CONNECTOR_KEYS:
        raise api_error(404, "ConnectorNotFound", f"Unknown connector: {env_name}.")


def set_key(env_name: str, value) -> None:
    _check_connector(env_name)
    value = _validate_secret(value)
    with _lock:
        data = _copy()
        data.setdefault("keys", {})[env_name] = value
        _write(data)


def delete_key(env_name: str) -> None:
    _check_connector(env_name)
    with _lock:
        data = _copy()
        (data.get("keys") or {}).pop(env_name, None)
        _write(data)


def list_keys() -> list[dict]:
    stored = _load().get("keys") or {}
    out = []
    for c in CONNECTORS:
        ui_value = stored.get(c["key"]) or ""
        env_value = os.environ.get(c["key"], "").strip()
        value = ui_value or env_value
        out.append({
            "key": c["key"],
            "label": c["label"],
            "engines": c["engines"],
            "optional": c.get("optional", False),
            "signup": c["signup"],
            "configured": bool(value),
            "source": "ui" if ui_value else ("env" if env_value else None),
            "env_available": bool(env_value),   # removing the UI key would fall back to it
            "hint": _hint(value),
        })
    return out


# ── MISP instances ────────────────────────────────────────────────────────────

def misp_managed_in_ui() -> bool:
    return isinstance(_load().get("misp"), list)


def _stored_misp() -> list[dict]:
    """Instances as stored (cert/key are filenames in backend/certs/)."""
    misp = _load().get("misp")
    if isinstance(misp, list):
        return [m for m in misp if isinstance(m, dict) and _MISP_ID_RE.match(str(m.get("id", "")))]
    return [dict(m) for m in config.MISP_INSTANCES]


def misp_instances() -> list[dict]:
    """Current MISP instances, ordered by number: the runtime list the registry,
    the weights defaults and the MISP engine use."""
    return sorted(
        ({
            "id": m["id"],
            "name": str(m.get("name") or m["id"]),
            "url": str(m.get("url") or ""),
            "key": str(m.get("key") or ""),
            "verify_ssl": m.get("verify_ssl", True) is not False,
            "client_cert": str(m.get("client_cert") or ""),
            "client_key": str(m.get("client_key") or ""),
            "weight": m.get("weight", DEFAULT_MISP_WEIGHT),
            "knowledge_weight": m.get("knowledge_weight", DEFAULT_MISP_KNOWLEDGE_WEIGHT),
        } for m in _stored_misp()),
        key=lambda m: int(_MISP_ID_RE.match(m["id"]).group(1)),
    )


def get_misp(instance_id: str) -> dict | None:
    return next((m for m in misp_instances() if m["id"] == instance_id), None)


def list_misp() -> list[dict]:
    return [{
        "id": m["id"],
        "name": m["name"],
        "url": m["url"],
        "verify_ssl": m["verify_ssl"],
        "client_cert": m["client_cert"],
        "client_key": m["client_key"],
        "has_key": bool(m["key"]),
        "hint": _hint(m["key"]),
        "connected": bool(m["url"]) and bool(m["key"]),
    } for m in misp_instances()]


def list_cert_files() -> list[str]:
    try:
        return sorted(p.name for p in config.CERTS_DIR.iterdir()
                      if p.is_file() and not p.name.startswith("."))
    except FileNotFoundError:
        return []


def _validate_misp(fields: dict, current: dict | None, others: list[dict]) -> dict:
    """Validated copy of the editable fields. `current` is None when creating."""
    out = {}
    if "name" in fields or current is None:
        name = fields.get("name")
        name = name.strip() if isinstance(name, str) else ""
        if not 1 <= len(name) <= 64:
            raise api_error(422, "InvalidMispName", "The name must be 1–64 characters.")
        if any(o["name"].casefold() == name.casefold() for o in others):
            raise api_error(409, "MispNameExists", f"A MISP instance named {name} already exists.")
        out["name"] = name
    if "url" in fields or current is None:
        url = fields.get("url")
        url = url.strip().rstrip("/") if isinstance(url, str) else ""
        if not re.match(r"^https?://[^\s/]+", url) or len(url) > 512 or any(c.isspace() for c in url):
            raise api_error(422, "InvalidMispUrl", "The URL must start with http:// or https://.")
        out["url"] = url
    if fields.get("key") is not None:   # omitted / null = keep the current key
        out["key"] = _validate_secret(fields["key"], "API key")
    elif current is None:
        raise api_error(422, "InvalidSecret", "The API key is required.")
    if "verify_ssl" in fields:
        if not isinstance(fields["verify_ssl"], bool):
            raise api_error(422, "InvalidMispUrl", "verify_ssl must be true or false.")
        out["verify_ssl"] = fields["verify_ssl"]
    certs = set(list_cert_files())
    for field in ("client_cert", "client_key"):
        if field in fields:
            value = fields[field] or ""
            if not isinstance(value, str) or (value and value not in certs):
                raise api_error(422, "InvalidCertFile",
                                f"{value} is not a file in backend/certs/.")
            out[field] = value
    if out.get("client_key", current and current.get("client_key")) and \
            not out.get("client_cert", current and current.get("client_cert")):
        raise api_error(422, "InvalidCertFile", "A client key needs a client certificate.")
    return out


def _misp_for_write(data: dict) -> list[dict]:
    """The stored list, importing the .env instances the first time MISP is edited."""
    if not isinstance(data.get("misp"), list):
        data["misp"] = [{k: v for k, v in m.items()} for m in config.MISP_INSTANCES]
        data["misp_next"] = max((int(_MISP_ID_RE.match(m["id"]).group(1)) for m in data["misp"]), default=0) + 1
    return data["misp"]


def create_misp(fields: dict) -> dict:
    with _lock:
        data = _copy()
        misp = _misp_for_write(data)
        values = _validate_misp(fields, None, misp_instances())
        n = max(int(data.get("misp_next") or 1),
                max((int(_MISP_ID_RE.match(m["id"]).group(1)) for m in misp), default=0) + 1)
        # Ids are never reused: weights.json may still hold a deleted instance's weights.
        data["misp_next"] = n + 1
        inst = {
            "id": f"misp_{n}", "verify_ssl": True, "client_cert": "", "client_key": "",
            "weight": DEFAULT_MISP_WEIGHT, "knowledge_weight": DEFAULT_MISP_KNOWLEDGE_WEIGHT,
            **values,
        }
        misp.append(inst)
        _write(data)
    return next(m for m in list_misp() if m["id"] == inst["id"])


def update_misp(instance_id: str, fields: dict) -> dict:
    with _lock:
        data = _copy()
        misp = _misp_for_write(data)
        inst = next((m for m in misp if m.get("id") == instance_id), None)
        if inst is None:
            raise api_error(404, "MispNotFound", "That MISP instance no longer exists.")
        others = [m for m in misp_instances() if m["id"] != instance_id]
        inst.update(_validate_misp(fields, inst, others))
        _write(data)
    return next(m for m in list_misp() if m["id"] == instance_id)


def delete_misp(instance_id: str) -> None:
    with _lock:
        data = _copy()
        misp = _misp_for_write(data)
        if not any(m.get("id") == instance_id for m in misp):
            raise api_error(404, "MispNotFound", "That MISP instance no longer exists.")
        data["misp"] = [m for m in misp if m.get("id") != instance_id]
        _write(data)
