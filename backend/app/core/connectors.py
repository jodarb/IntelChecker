"""Connector credentials store: API keys and MISP / OpenCTI instances, managed from the
Connectors page (admin only).

Persisted to backend/data/connectors.json (Docker volume, gitignored), written with
0600 permissions. Keys are stored in clear, like backend/.env — protect the volume
and its backups the same way. The list endpoints never return a stored key, only
its last four characters; an admin can reveal one on demand (GET …/reveal, browser
session only, logged).

  * API keys: a key saved here wins over the same variable in backend/.env; removing
    it from here falls back to the .env value (if any). So existing deployments keep
    working untouched, and the .env can be emptied once every key is in the UI.
  * MISP / OpenCTI: while "misp" (or "opencti") is absent from the file, the
    instances defined in .env (MISP_<N>_*, OPENCTI_<N>_*) are used. The first
    add/edit/delete from the Connectors page copies them into the file and, from
    then on, those variables in .env are ignored.

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
    {"key": "ABUSECH_AUTH_KEY", "label": "abuse.ch", "engines": ["abusech", "urlhaus", "malwarebazaar", "yaraify"],
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
    {"key": "CROWDSEC_API_KEY", "label": "CrowdSec CTI", "engines": ["crowdsec"],
     "signup": "https://app.crowdsec.net/settings/cti-api-keys"},
    {"key": "MALPEDIA_API_KEY", "label": "Malpedia", "engines": ["malpedia"], "optional": True,
     "signup": "https://malpedia.caad.fkie.fraunhofer.de/user/register"},
    {"key": "CIRCL_PDNS_CREDENTIALS", "label": "CIRCL Passive DNS (user:password)", "engines": ["circlpdns"],
     "signup": "https://www.circl.lu/services/passive-dns/"},
    {"key": "SPAMHAUS_DQS_KEY", "label": "Spamhaus DQS", "engines": ["spamhaus"], "optional": True,
     "signup": "https://www.spamhaus.com/free-trial/sign-up-for-a-free-data-query-service-account/"},
    {"key": "NVD_API_KEY", "label": "NVD (NIST)", "engines": ["nvd"], "optional": True,
     "signup": "https://nvd.nist.gov/developers/request-an-api-key"},
]
_CONNECTOR_KEYS = {c["key"] for c in CONNECTORS}
KEYED_ENGINES = {e for c in CONNECTORS for e in c["engines"]}

DEFAULT_MISP_WEIGHT = 0
DEFAULT_MISP_KNOWLEDGE_WEIGHT = 9
DEFAULT_OPENCTI_WEIGHT = 0
DEFAULT_OPENCTI_KNOWLEDGE_WEIGHT = 9

_MISP_ID_RE = re.compile(r"^misp_(\d+)$")
_OPENCTI_ID_RE = re.compile(r"^opencti_(\d+)$")
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


def reveal_key(env_name: str) -> dict:
    """The key in force (Connectors first, then .env) and where it comes from."""
    _check_connector(env_name)
    stored = (_load().get("keys") or {}).get(env_name) or ""
    env_value = os.environ.get(env_name, "").strip()
    return {"value": stored or env_value, "source": "ui" if stored else ("env" if env_value else None)}


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


# ── Platform instances (MISP, OpenCTI) ────────────────────────────────────────
#
# Both are multi-instance: any number of servers, each its own source with its own
# weights. They share one store, keyed by kind: `data[kind]` (list) and
# `data[kind + "_next"]` (next id number, ids are never reused). While `data[kind]`
# is absent the .env definition (MISP_<N>_*, OPENCTI_<N>_*) is used; the first add /
# edit / delete from the Connectors page copies it into the file.

_KINDS: dict[str, dict] = {
    "misp": {
        "label": "MISP", "id_re": _MISP_ID_RE, "env": lambda: config.MISP_INSTANCES,
        "weight": DEFAULT_MISP_WEIGHT, "knowledge_weight": DEFAULT_MISP_KNOWLEDGE_WEIGHT,
        "not_found": "MispNotFound", "name_exists": "MispNameExists",
    },
    "opencti": {
        "label": "OpenCTI", "id_re": _OPENCTI_ID_RE, "env": lambda: config.OPENCTI_INSTANCES,
        "weight": DEFAULT_OPENCTI_WEIGHT, "knowledge_weight": DEFAULT_OPENCTI_KNOWLEDGE_WEIGHT,
        "not_found": "OpenctiNotFound", "name_exists": "OpenctiNameExists",
    },
}
INSTANCE_KINDS = tuple(_KINDS)


def _kind(kind: str) -> dict:
    return _KINDS[kind]


def managed_in_ui(kind: str) -> bool:
    return isinstance(_load().get(kind), list)


def _stored(kind: str) -> list[dict]:
    """Instances as stored (cert/key are filenames in backend/certs/)."""
    k = _kind(kind)
    items = _load().get(kind)
    if isinstance(items, list):
        return [m for m in items if isinstance(m, dict) and k["id_re"].match(str(m.get("id", "")))]
    return [dict(m) for m in k["env"]()]


def instances(kind: str) -> list[dict]:
    """Current instances of a kind, ordered by number: the runtime list the registry,
    the weights defaults and the engines use."""
    k = _kind(kind)
    return sorted(
        ({
            "id": m["id"],
            "kind": kind,
            "name": str(m.get("name") or m["id"]),
            "url": str(m.get("url") or ""),
            "key": str(m.get("key") or ""),
            "verify_ssl": m.get("verify_ssl", True) is not False,
            "client_cert": str(m.get("client_cert") or ""),
            "client_key": str(m.get("client_key") or ""),
            "weight": m.get("weight", k["weight"]),
            "knowledge_weight": m.get("knowledge_weight", k["knowledge_weight"]),
        } for m in _stored(kind)),
        key=lambda m: int(k["id_re"].match(m["id"]).group(1)),
    )


def get_instance(kind: str, instance_id: str) -> dict | None:
    return next((m for m in instances(kind) if m["id"] == instance_id), None)


def list_instances(kind: str) -> list[dict]:
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
    } for m in instances(kind)]


def reveal_instance_key(kind: str, instance_id: str) -> dict:
    inst = get_instance(kind, instance_id)
    if inst is None:
        raise api_error(404, _kind(kind)["not_found"], f"That {_kind(kind)['label']} instance no longer exists.")
    return {"value": inst["key"], "source": "ui" if managed_in_ui(kind) else "env"}


def list_cert_files() -> list[str]:
    try:
        return sorted(p.name for p in config.CERTS_DIR.iterdir()
                      if p.is_file() and not p.name.startswith("."))
    except FileNotFoundError:
        return []


def _validate(kind: str, fields: dict, current: dict | None, others: list[dict]) -> dict:
    """Validated copy of the editable fields. `current` is None when creating."""
    k = _kind(kind)
    out = {}
    if "name" in fields or current is None:
        name = fields.get("name")
        name = name.strip() if isinstance(name, str) else ""
        if not 1 <= len(name) <= 64:
            raise api_error(422, "InvalidMispName", "The name must be 1–64 characters.")
        if any(o["name"].casefold() == name.casefold() for o in others):
            raise api_error(409, k["name_exists"], f"A {k['label']} instance named {name} already exists.")
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


def _for_write(kind: str, data: dict) -> list[dict]:
    """The stored list, importing the .env instances the first time the kind is edited."""
    k = _kind(kind)
    if not isinstance(data.get(kind), list):
        data[kind] = [{key: v for key, v in m.items()} for m in k["env"]()]
        data[f"{kind}_next"] = max((int(k["id_re"].match(m["id"]).group(1)) for m in data[kind]), default=0) + 1
    return data[kind]


def create_instance(kind: str, fields: dict) -> dict:
    k = _kind(kind)
    with _lock:
        data = _copy()
        items = _for_write(kind, data)
        values = _validate(kind, fields, None, instances(kind))
        n = max(int(data.get(f"{kind}_next") or 1),
                max((int(k["id_re"].match(m["id"]).group(1)) for m in items), default=0) + 1)
        # Ids are never reused: weights.json may still hold a deleted instance's weights.
        data[f"{kind}_next"] = n + 1
        inst = {
            "id": f"{kind}_{n}", "verify_ssl": True, "client_cert": "", "client_key": "",
            "weight": k["weight"], "knowledge_weight": k["knowledge_weight"],
            **values,
        }
        items.append(inst)
        _write(data)
    return next(m for m in list_instances(kind) if m["id"] == inst["id"])


def update_instance(kind: str, instance_id: str, fields: dict) -> dict:
    k = _kind(kind)
    with _lock:
        data = _copy()
        items = _for_write(kind, data)
        inst = next((m for m in items if m.get("id") == instance_id), None)
        if inst is None:
            raise api_error(404, k["not_found"], f"That {k['label']} instance no longer exists.")
        others = [m for m in instances(kind) if m["id"] != instance_id]
        inst.update(_validate(kind, fields, inst, others))
        _write(data)
    return next(m for m in list_instances(kind) if m["id"] == instance_id)


def delete_instance(kind: str, instance_id: str) -> None:
    k = _kind(kind)
    with _lock:
        data = _copy()
        items = _for_write(kind, data)
        if not any(m.get("id") == instance_id for m in items):
            raise api_error(404, k["not_found"], f"That {k['label']} instance no longer exists.")
        data[kind] = [m for m in items if m.get("id") != instance_id]
        _write(data)


# MISP names kept for the existing callers.
def misp_managed_in_ui() -> bool:
    return managed_in_ui("misp")


def misp_instances() -> list[dict]:
    return instances("misp")


def get_misp(instance_id: str) -> dict | None:
    return get_instance("misp", instance_id)


def list_misp() -> list[dict]:
    return list_instances("misp")


def reveal_misp_key(instance_id: str) -> dict:
    return reveal_instance_key("misp", instance_id)


def opencti_instances() -> list[dict]:
    return instances("opencti")
