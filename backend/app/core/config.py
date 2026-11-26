import os
import re
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent.parent / ".env", override=True)


def get(key: str) -> str:
    return os.environ.get(key, "")


# Client certs for mTLS-only MISP / OpenCTI instances live here (gitignored, like .env).
# Resolves to backend/certs/ locally and /app/certs/ in the container — the same
# relative computation as the .env path above, kept in sync with where docker-compose
# bind-mounts the directory.
CERTS_DIR = Path(__file__).parent.parent.parent / "certs"


def cert_path(filename: str) -> str:
    """MISP client cert/key settings hold a filename, not a path — the file must
    live in backend/certs/. Returns an absolute path, or "" if unset."""
    return str(CERTS_DIR / filename) if filename else ""


def _load_instances(prefix: str, id_prefix: str, default_knowledge: int) -> list[dict]:
    """Discover <PREFIX>_<N>_NAME / _URL / _KEY / _VERIFY_SSL groups from the environment
    (MISP_<N>_*, OPENCTI_<N>_*).

    Any number of instances can be defined this way, each becoming its own source
    in the UI. An instance is registered as soon as its NAME is set, even if URL or
    KEY are missing — that surfaces as a clear "not configured" error on the card
    instead of the instance silently not appearing at all.
    """
    index_re = re.compile(rf"^{prefix}_(\d+)_NAME$")
    indices = sorted(int(m.group(1)) for key in os.environ if (m := index_re.match(key)))

    def num(name: str, default: int) -> int:
        raw = os.environ.get(name, "").strip()
        try:
            return int(raw) if raw else default
        except ValueError:
            return default

    instances = []
    for idx in indices:
        env = lambda field: os.environ.get(f"{prefix}_{idx}_{field}", "").strip()  # noqa: E731
        name = env("NAME")
        if not name:
            continue
        instances.append({
            "id": f"{id_prefix}_{idx}",
            "name": name,
            "url": env("URL").rstrip("/"),
            "key": env("KEY"),
            "verify_ssl": (env("VERIFY_SSL") or "true").lower() not in ("false", "0", "no"),
            "client_cert": env("CLIENT_CERT"),
            "client_key": env("CLIENT_KEY"),
            "weight": num(f"{prefix}_{idx}_WEIGHT", 0),
            "knowledge_weight": num(f"{prefix}_{idx}_KNOWLEDGE_WEIGHT", default_knowledge),
        })
    return instances


# API keys are no longer module constants: they are read on every call through
# app.core.connectors.secret(), so a key saved from the Connectors page takes effect
# at once. The .env value is the fallback. MISP_INSTANCES is the .env definition,
# used until MISP is first edited from the Connectors page (see connectors.py); the
# same goes for OPENCTI_<N>_* and OpenCTI.
MISP_INSTANCES: list[dict] = _load_instances("MISP", "misp", 9)
OPENCTI_INSTANCES: list[dict] = _load_instances("OPENCTI", "opencti", 9)
