"""Validate the GraphQL documents sent to OpenCTI (app/services/opencti_queries.py)
against the platform schema of one or more OpenCTI releases, without a running
instance. Downloads the schema files from GitHub (cached under tests/.opencti-schema/).

    cd backend && .venv/bin/pip install graphql-core          # dev-only dependency
    .venv/bin/python tests/opencti_schema_check.py             # 6.0.0 and master
    .venv/bin/python tests/opencti_schema_check.py 6.8.0 7.261124.0

Expected: every document validates on the newest release; on old ones the "full"
variants may fail (the service then falls back to "compat"), but "compat",
"observables", "indicators" and "context" must validate everywhere.
Exit code 0 = OK, 1 = a document that has no fallback fails somewhere.
"""
import re
import sys
from pathlib import Path

import httpx

try:
    from graphql import build_schema, parse, validate
except ImportError:
    sys.exit("graphql-core is required: .venv/bin/pip install graphql-core")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.services import opencti_queries as Q  # noqa: E402

CACHE = Path(__file__).with_name(".opencti-schema")
REPO = "OpenCTI-Platform/opencti"


def schema_files(tag: str) -> list[Path]:
    folder = CACHE / tag
    if folder.exists() and any(folder.iterdir()):
        return sorted(folder.iterdir())
    folder.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        tree = client.get(f"https://api.github.com/repos/{REPO}/git/trees/{tag}?recursive=1").json()
        paths = [x["path"] for x in tree.get("tree", [])
                 if x["path"].endswith(".graphql") and "opencti-graphql/" in x["path"] and "/tests/" not in x["path"]]
        if not paths:
            sys.exit(f"No schema files found for {tag} (GitHub API limit or unknown tag).")
        for i, path in enumerate(paths):
            text = client.get(f"https://raw.githubusercontent.com/{REPO}/{tag}/{path}").text
            (folder / f"{i:03d}.graphql").write_text(text)
    return sorted(folder.iterdir())


def load_schema(tag: str):
    parts = []
    for f in schema_files(tag):
        text = f.read_text()
        # Modules declare their own `type Query`; OpenCTI merges them (graphql-tools).
        is_main = re.search(r"(?m)^type Query \{", text) and "type StixCyberObservable" in text
        if not is_main:
            text = re.sub(r"(?m)^type (Query|Mutation|Subscription) ", r"extend type \1 ", text)
        parts.append(text)
    return build_schema("\n".join(parts), assume_valid_sdl=True)


def main() -> int:
    tags = sys.argv[1:] or ["6.0.0", "master"]
    failed = False
    for tag in tags:
        schema = load_schema(tag)
        print(f"OpenCTI {tag}")
        for name, doc in Q.ALL.items():
            errors = validate(schema, parse(doc))
            has_fallback = name.endswith(".full")
            status = "OK" if not errors else ("falls back to compat" if has_fallback else "FAIL")
            print(f"  {name:24} {status}")
            for e in errors[:3] if not has_fallback else []:
                print(f"      {e.message}")
            failed |= bool(errors) and not has_fallback
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
