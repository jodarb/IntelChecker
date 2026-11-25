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
# relative computation as the .env path above, kept in sync with where docker-compose
# bind-mounts the directory.
CERTS_DIR = Path(__file__).parent.parent.parent / "certs"


def cert_path(filename: str) -> str:
    """MISP client cert/key settings hold a filename, not a path — the file must
    live in backend/certs/. Returns an absolute path, or "" if unset."""
    return str(CERTS_DIR / filename) if filename else ""


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
            "client_cert": os.environ.get(f"MISP_{idx}_CLIENT_CERT", "").strip(),
            "client_key": os.environ.get(f"MISP_{idx}_CLIENT_KEY", "").strip(),
            "weight": weight,
            "knowledge_weight": knowledge_weight,
        })
    return instances


# API keys are no longer module constants: they are read on every call through
# app.core.connectors.secret(), so a key saved from the Connectors page takes effect
# at once. The .env value is the fallback. MISP_INSTANCES is the .env definition,
# used until MISP is first edited from the Connectors page (see connectors.py).
MISP_INSTANCES: list[dict] = _load_misp_instances()
