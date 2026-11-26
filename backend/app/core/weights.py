"""Verdict weights store — the single source of truth for both scores.

Each engine has two independent weights:
  * risk       — how much its 0-10 maliciousness subscore moves the Risk Score.
  * knowledge  — how much its "depth of record" (0 / 0.5 / 1) moves the Knowledge Score.
Optionally `knowledge_by_type` overrides the knowledge weight for a given indicator
type (e.g. RIPEstat is a minor source for IPs but one of the few ones for ASNs).

Defaults live in code (below). Admin edits are persisted to backend/data/weights.json,
which is a Docker volume, so they survive restarts and rebuilds. The file only needs
to hold what the admin changed: anything missing falls back to the defaults, so new
engines added in a future release get sensible weights without touching the file.
"""
import json
import os
import threading
from pathlib import Path

from app.core import connectors

_WEIGHTS_PATH = Path(__file__).parent.parent.parent / "data" / "weights.json"
_lock = threading.Lock()

DEFAULT_ENGINE_WEIGHTS: dict[str, dict] = {
    "recordedfuture": {"risk": 10, "knowledge": 9},
    "mitreattack":    {"risk": 0,  "knowledge": 9},
    "virustotal":     {"risk": 8,  "knowledge": 8},
    "alienvault":     {"risk": 6,  "knowledge": 7},
    "malwarebazaar":  {"risk": 8,  "knowledge": 7},
    "abuseipdb":      {"risk": 7,  "knowledge": 6},
    "abusech":        {"risk": 7,  "knowledge": 6},
    "urlhaus":        {"risk": 7,  "knowledge": 6},
    "anyrun":         {"risk": 0,  "knowledge": 6},
    "shodan":         {"risk": 0,  "knowledge": 5},
    "hybridanalysis": {"risk": 0,  "knowledge": 5},
    "urlscan":        {"risk": 5,  "knowledge": 5},
    "greynoise":      {"risk": 0,  "knowledge": 5},
    "phishtank":      {"risk": 7,  "knowledge": 4},
    "tweetfeed":      {"risk": 4,  "knowledge": 4},
    "safebrowsing":   {"risk": 0,  "knowledge": 3},
    "torexitlist":    {"risk": 5,  "knowledge": 2},
    "ipinfo":         {"risk": 0,  "knowledge": 1},
    "ripestat":       {"risk": 0,  "knowledge": 1, "knowledge_by_type": {"asn": 6}},
    "crowdsec":       {"risk": 7,  "knowledge": 6},
    "malpedia":       {"risk": 0,  "knowledge": 7},
    "hashlookup":     {"risk": 4,  "knowledge": 5},
    "rdap":           {"risk": 4,  "knowledge": 3},
    "tranco":         {"risk": 2,  "knowledge": 3},
    "spamhaus":       {"risk": 8,  "knowledge": 5, "knowledge_by_type": {"asn": 6}},
    "openphish":      {"risk": 7,  "knowledge": 3},
    "yaraify":        {"risk": 5,  "knowledge": 4},
    "sslbl":          {"risk": 8,  "knowledge": 1},
    "circlpdns":      {"risk": 0,  "knowledge": 4},
    "nvd":            {"risk": 6,  "knowledge": 9},
    "epss":           {"risk": 8,  "knowledge": 6},
    "cisakev":        {"risk": 10, "knowledge": 3},
    "opentip":        {"risk": 8,  "knowledge": 6},
    "vulncheckkev":   {"risk": 10, "knowledge": 4},
}

DEFAULT_THRESHOLDS = {"knowledge": 4, "risk": 5}

# Knowledge saturates: once this % of the available knowledge weight has a record
# (weighted by depth), the Knowledge Score is already 10. An indicator doesn't need
# *every* source to know it to be well known.
DEFAULT_SCORING = {"knowledge_full_at": 70}
_FULL_AT_MIN, _FULL_AT_MAX = 10, 100

# Every weight (risk, knowledge and per-type knowledge overrides) lives on a 0-10 scale.
_MAX_WEIGHT = 10


def _clamp_weight(value):
    """Coerce a stored/env weight into [0, _MAX_WEIGHT]; non-numbers become 0."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    return max(0, min(_MAX_WEIGHT, value))


def _clamp_entry(w: dict) -> dict:
    out = dict(w)
    for k in ("risk", "knowledge"):
        if k in out:
            out[k] = _clamp_weight(out[k])
    if isinstance(out.get("knowledge_by_type"), dict):
        out["knowledge_by_type"] = {t: _clamp_weight(v) for t, v in out["knowledge_by_type"].items()}
    return out


def _defaults() -> dict:
    engines = {k: json.loads(json.dumps(v)) for k, v in DEFAULT_ENGINE_WEIGHTS.items()}
    # MISP / OpenCTI instances come from the Connectors page (or .env); their initial weights act as defaults.
    for inst in (i for kind in connectors.INSTANCE_KINDS for i in connectors.instances(kind)):
        engines[inst["id"]] = {
            "risk": _clamp_weight(inst["weight"]),
            "knowledge": _clamp_weight(inst["knowledge_weight"]),
        }
    return {"engines": engines, "thresholds": dict(DEFAULT_THRESHOLDS), "scoring": dict(DEFAULT_SCORING)}


def _read_overrides() -> dict:
    try:
        return json.loads(_WEIGHTS_PATH.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def get_weights() -> dict:
    """Defaults merged with persisted admin overrides."""
    merged = _defaults()
    overrides = _read_overrides()
    for engine_id, w in (overrides.get("engines") or {}).items():
        if engine_id in merged["engines"] and isinstance(w, dict):
            # Clamp so a weights.json saved under the old 0-100 scale still loads in range.
            merged["engines"][engine_id].update(_clamp_entry(w))
    merged["thresholds"].update(overrides.get("thresholds") or {})
    full_at = (overrides.get("scoring") or {}).get("knowledge_full_at")
    if isinstance(full_at, (int, float)) and not isinstance(full_at, bool):
        merged["scoring"]["knowledge_full_at"] = max(_FULL_AT_MIN, min(_FULL_AT_MAX, full_at))
    return merged


class WeightsValidationError(ValueError):
    pass


def _check_number(value, field: str, lo: float, hi: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise WeightsValidationError(f"{field} must be a number.")
    if not lo <= value <= hi:
        raise WeightsValidationError(f"{field} must be between {lo} and {hi}.")
    return value


def save_weights(payload: dict) -> dict:
    known = _defaults()["engines"]
    engines_in = payload.get("engines")
    thresholds_in = payload.get("thresholds")
    if not isinstance(engines_in, dict) or not isinstance(thresholds_in, dict):
        raise WeightsValidationError("Payload must contain 'engines' and 'thresholds' objects.")

    engines: dict[str, dict] = {}
    for engine_id, w in engines_in.items():
        if engine_id not in known:
            raise WeightsValidationError(f"Unknown engine: {engine_id}")
        if not isinstance(w, dict):
            raise WeightsValidationError(f"{engine_id}: weights must be an object.")
        entry = {
            "risk": _check_number(w.get("risk"), f"{engine_id}.risk", 0, _MAX_WEIGHT),
            "knowledge": _check_number(w.get("knowledge"), f"{engine_id}.knowledge", 0, _MAX_WEIGHT),
        }
        by_type = w.get("knowledge_by_type")
        if by_type:
            if not isinstance(by_type, dict):
                raise WeightsValidationError(f"{engine_id}.knowledge_by_type must be an object.")
            entry["knowledge_by_type"] = {
                t: _check_number(v, f"{engine_id}.knowledge_by_type.{t}", 0, _MAX_WEIGHT)
                for t, v in by_type.items()
            }
        else:
            # Explicitly cleared — store an empty map so the default override doesn't come back.
            entry["knowledge_by_type"] = {}
        engines[engine_id] = entry

    thresholds = {
        "knowledge": _check_number(thresholds_in.get("knowledge"), "thresholds.knowledge", 0, 10),
        "risk": _check_number(thresholds_in.get("risk"), "thresholds.risk", 0, 10),
    }

    # Optional for older clients: missing → keep the current value.
    scoring_in = payload.get("scoring") or {}
    if not isinstance(scoring_in, dict):
        raise WeightsValidationError("'scoring' must be an object.")
    full_at = scoring_in.get("knowledge_full_at", get_weights()["scoring"]["knowledge_full_at"])
    scoring = {
        "knowledge_full_at": _check_number(full_at, "scoring.knowledge_full_at", _FULL_AT_MIN, _FULL_AT_MAX),
    }

    data = {"engines": engines, "thresholds": thresholds, "scoring": scoring}
    with _lock:
        _WEIGHTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = _WEIGHTS_PATH.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2))
        os.replace(tmp, _WEIGHTS_PATH)
    return get_weights()


def reset_weights() -> dict:
    with _lock:
        _WEIGHTS_PATH.unlink(missing_ok=True)
    return get_weights()
