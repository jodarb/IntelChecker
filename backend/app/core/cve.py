"""CVE identifier normalisation, shared by the vulnerability sources (NVD, CISA KEV, EPSS).

Accepts what analysts paste: any case, surrounding spaces, an en dash or an
underscore instead of a hyphen ("cve–2021–44228", "CVE_2021_44228"). The sequence
part has at least four digits and no upper bound (CVE-2026-103406 exists).
"""
import re

_CVE = re.compile(r"^CVE[-_‐-―](\d{4})[-_‐-―](\d{4,})$", re.IGNORECASE)


def normalize_cve(value: str) -> str | None:
    """'cve-2021-44228 ' → 'CVE-2021-44228'; None if it isn't a CVE identifier."""
    m = _CVE.match((value or "").strip())
    return f"CVE-{m.group(1)}-{m.group(2)}" if m else None


def bad_cve(value: str, source: str) -> dict:
    return {"error": {"code": "BadRequest",
                      "message": f"'{value.strip()}' is not a CVE identifier (expected CVE-YYYY-NNNN). {source} was not queried."}}
