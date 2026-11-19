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

from app.core.config import MISP_INSTANCES

_WEIGHTS_PATH = Path(__file__).parent.parent.parent / "data" / "weights.json"
_lock = threading.Lock()

DEFAULT_ENGINE_WEIGHTS: dict[str, dict] = {
    "recordedfuture": {"risk": 25, "knowledge": 9},
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
}

DEFAULT_THRESHOLDS = {"knowledge": 4, "risk": 5}

_MAX_WEIGHT = 100


def _defaults() -> dict:
    engines = {k: json.loads(json.dumps(v)) for k, v in DEFAULT_ENGINE_WEIGHTS.items()}
    # MISP instances are discovered at deploy time; their .env weights act as defaults.
    for inst in MISP_INSTANCES:
        engines[inst["id"]] = {"risk": inst["weight"], "knowledge": inst["knowledge_weight"]}
    return {"engines": engines, "thresholds": dict(DEFAULT_THRESHOLDS)}


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
            merged["engines"][engine_id].update(w)
    merged["thresholds"].update(overrides.get("thresholds") or {})
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

    data = {"engines": engines, "thresholds": thresholds}
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
