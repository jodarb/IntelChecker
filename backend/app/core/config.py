import os
import re
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent.parent / ".env", override=True)


def get(key: str) -> str:
    return os.environ.get(key, "")


_MISP_INDEX_RE = re.compile(r"^MISP_(\d+)_NAME$")

# Client certs for mTLS-only MISP instances live here (gitignored, like .env).
# Resolves to backend/certs/ locally and /app/certs/ in the container — the same
# relative computation as _ENV_PATH below, kept in sync with where docker-compose
# bind-mounts the directory.
_CERTS_DIR = Path(__file__).parent.parent.parent / "certs"


def _resolve_cert(idx: int, suffix: str) -> str:
    """MISP_<idx>_CLIENT_CERT / _CLIENT_KEY hold a filename, not a path — the file
    must live in backend/certs/. Returns an absolute path, or "" if unset."""
    filename = os.environ.get(f"MISP_{idx}_{suffix}", "").strip()
    return str(_CERTS_DIR / filename) if filename else ""


def _load_misp_instances() -> list[dict]:
    """Discover MISP_<N>_NAME / _URL / _KEY / _VERIFY_SSL groups from the environment.

    Any number of instances can be defined this way, each becoming its own source
    in the UI. An instance is registered as soon as its NAME is set, even if URL or
    KEY are missing — that surfaces as a clear "not configured" error on the card
    instead of the instance silently not appearing at all.
    """
    indices = sorted(
        int(match.group(1))
        for key in os.environ
        if (match := _MISP_INDEX_RE.match(key))
    )

    instances = []
    for idx in indices:
        name = os.environ.get(f"MISP_{idx}_NAME", "").strip()
        if not name:
            continue
        verify_raw = os.environ.get(f"MISP_{idx}_VERIFY_SSL", "true").strip().lower()
        weight_raw = os.environ.get(f"MISP_{idx}_WEIGHT", "0").strip()
        try:
            weight = int(weight_raw) if weight_raw else 0
        except ValueError:
            weight = 0
        kweight_raw = os.environ.get(f"MISP_{idx}_KNOWLEDGE_WEIGHT", "9").strip()
        try:
            knowledge_weight = int(kweight_raw) if kweight_raw else 9
        except ValueError:
            knowledge_weight = 9
        instances.append({
            "id": f"misp_{idx}",
            "name": name,
            "url": os.environ.get(f"MISP_{idx}_URL", "").strip().rstrip("/"),
            "key": os.environ.get(f"MISP_{idx}_KEY", "").strip(),
            "verify_ssl": verify_raw not in ("false", "0", "no"),
            "client_cert": _resolve_cert(idx, "CLIENT_CERT"),
            "client_key": _resolve_cert(idx, "CLIENT_KEY"),
            "weight": weight,
            "knowledge_weight": knowledge_weight,
        })
    return instances


ABUSEIPDB_API_KEY: str = get("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY: str = get("VIRUSTOTAL_API_KEY")
ABUSECH_AUTH_KEY: str = get("ABUSECH_AUTH_KEY")  # unified auth.abuse.ch key, shared by ThreatFox and URLhaus
ALIENVAULT_API_KEY: str = get("ALIENVAULT_API_KEY")
IPINFO_API_KEY: str = get("IPINFO_API_KEY")
SHODAN_API_KEY: str = get("SHODAN_API_KEY")
URLSCAN_API_KEY: str = get("URLSCAN_API_KEY")
PHISHTANK_API_KEY: str = get("PHISHTANK_API_KEY")  # optional — checkurl works without a key, just at lower priority
RECORDED_FUTURE_API_KEY: str = get("RECORDED_FUTURE_API_KEY")
ANYRUN_API_KEY: str = get("ANYRUN_API_KEY")
GREYNOISE_API_KEY: str = get("GREYNOISE_API_KEY")
HYBRID_ANALYSIS_API_KEY: str = get("HYBRID_ANALYSIS_API_KEY")
GOOGLE_SAFE_BROWSING_API_KEY: str = get("GOOGLE_SAFE_BROWSING_API_KEY")
MISP_INSTANCES: list[dict] = _load_misp_instances()
