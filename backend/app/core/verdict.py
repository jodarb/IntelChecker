"""Two-score verdict — Python port of frontend/src/verdictEngine.ts.

Used by POST /lookup so API clients get the same Knowledge Score, Risk Score,
quadrant and contributions the UI computes in the browser. **This is a line-by-line
mirror of the TypeScript engine: any change there must be made here too**, and
`backend/tests/verdict_parity.py` (runs both engines on thousands of random
results) must keep passing. See verdictEngine.ts for the reasoning behind every
rule; comments here only note where JavaScript semantics had to be reproduced.

A "result" has the frontend QueryResult shape: {"data": <service payload> | None,
"error": <str> | None}. `error` is set when the service call itself blew up — the
equivalent of the frontend not reaching the backend — and counts as transient.
"""
import json
import math
from typing import Any

# ── JavaScript semantics helpers ─────────────────────────────────────────────


def _truthy(v: Any) -> bool:
    """JS truthiness: {} and [] are truthy, unlike in Python."""
    if v is None or v is False:
        return False
    if isinstance(v, bool):
        return True
    if isinstance(v, (int, float)):
        return v != 0 and not math.isnan(v)
    if isinstance(v, str):
        return v != ""
    return True


def _get(obj: Any, *keys: str) -> Any:
    """Optional chaining: obj?.a?.b — None as soon as a level isn't an object."""
    for k in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(k)
    return obj


def _nz(v: Any, default: Any) -> Any:
    """Nullish coalescing: v ?? default."""
    return default if v is None else v


def _arr(v: Any) -> list:
    return v if isinstance(v, list) else []


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _js_round(x: float) -> int:
    """Math.round: halves round up (towards +∞), unlike Python's banker's rounding."""
    return math.floor(x + 0.5)


def _key(v: Any) -> Any:
    """Hashable stand-in for a JS Set member (objects compared by content here; the
    payloads only put strings and numbers in these sets)."""
    try:
        hash(v)
        return v
    except TypeError:
        return json.dumps(v, sort_keys=True)


def _js_string(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


# ── Constants ────────────────────────────────────────────────────────────────

DEFAULT_SCORING = {"knowledge_full_at": 70}

TRANSIENT_ERROR_CODES = {"RateLimitExceeded", "Timeout", "NetworkError", "ServiceUnavailable", "HttpError"}

NO_DATA_ERROR_CODES = {"NotFound"}

TRANCO_CLEAN_MAX_RANK = 100000

# EPSS probability floor → subscore; below the last floor is an explicit clean (0).
EPSS_TIERS = ((0.5, 10), (0.2, 8), (0.05, 6), (0.01, 3))


def knowledge_from_sums(num: float, total: float, full_at_pct: float) -> float:
    if total <= 0:
        return 0
    ratio = num / total
    return min(10, (10 * ratio) / (full_at_pct / 100))


def risk_weight_of(config: dict | None, engine_id: str) -> float:
    return _nz(_get(config, "engines", engine_id, "risk"), 0)


def knowledge_weight_of(config: dict | None, engine_id: str, type: str) -> float:
    w = _get(config, "engines", engine_id)
    if not _truthy(w):
        return 0
    return _nz(_get(w, "knowledge_by_type", type), w.get("knowledge"))


# ── Per-engine normalizers: raw API response → 0-10 subscore, or None ────────

def _vt_subscore(d: Any) -> float | None:
    stats = _get(d, "data", "attributes", "last_analysis_stats")
    if not _truthy(stats):
        return None
    flagged = _nz(_get(stats, "malicious"), 0) + _nz(_get(stats, "suspicious"), 0)
    if flagged == 0:
        return 0
    if flagged <= 2:
        return 3
    if flagged <= 5:
        return 6
    return 10


def _vt_host_subscore(d: Any) -> float | None:
    score = _vt_subscore(d)
    if score != 0 or score is None:
        return score
    a = _get(d, "data", "attributes")
    votes = _nz(_get(a, "total_votes", "harmless"), 0) + _nz(_get(a, "total_votes", "malicious"), 0)
    tags = len(a["tags"]) if isinstance(_get(a, "tags"), list) else 0
    return 0 if votes > 0 or tags > 0 else None


def _abuseipdb_subscore(d: Any) -> float | None:
    data = _get(d, "data")
    score = _get(data, "abuseConfidenceScore")
    if score is None:
        return None
    if score == 0 and not _truthy(data.get("totalReports")) and not _truthy(data.get("isWhitelisted")):
        return None
    return min(10, score / 10)


def _alienvault_subscore(d: Any) -> float | None:
    count = _get(d, "pulse_info", "count")
    if count is None:
        return None
    if count == 0:
        return None
    if count <= 2:
        return 4
    if count <= 5:
        return 7
    return 10


def _alienvault_cve_subscore(d: Any) -> float | None:
    if _get(d, "seen_wild") is True:
        return 9
    n = _get(d, "exploits_total")
    return 7 if _is_num(n) and n > 0 else None


def _abusech_subscore(d: Any) -> float | None:
    iocs = _get(d, "data")
    if not isinstance(iocs, list):
        return None
    if len(iocs) == 0:
        return None
    top_confidence = max(_nz(_get(i, "confidence_level"), 0) for i in iocs)
    return min(10, 7 + (top_confidence / 100) * 3)


def _recorded_future_subscore(d: Any) -> float | None:
    risk = _get(d, "risk")
    score = _get(risk, "score")
    if score is None:
        return None
    evidence = len(risk["evidenceDetails"]) if isinstance(_get(risk, "evidenceDetails"), list) else 0
    if evidence == 0 and score == 0:
        return None
    return min(10, score / 9.9)


def _tor_exit_list_subscore(d: Any) -> float | None:
    if not _truthy(_get(d, "is_tor_exit")):
        return None
    return 7


def _urlhaus_subscore(d: Any) -> float | None:
    if _get(d, "query_status") == "no_results":
        return None
    if isinstance(_get(d, "url_status"), str):
        return 9 if d["url_status"] == "online" else 6
    urls = _get(d, "urls")
    if isinstance(urls, list):
        if len(urls) == 0:
            return None
        any_online = any(_get(u, "url_status") == "online" for u in urls)
        return 9 if any_online else 6
    return None


def _urlscan_subscore(d: Any) -> float | None:
    total = _get(d, "total")
    if total is None:
        return None
    if total == 0:
        return None
    if total <= 2:
        return 3
    if total <= 5:
        return 5
    return 6


def _malware_bazaar_subscore(d: Any) -> float | None:
    if _get(d, "query_status") == "no_results":
        return None
    data = _get(d, "data")
    if isinstance(data, list):
        if len(data) == 0:
            return None
        return 10
    return None


def _phishtank_subscore(d: Any) -> float | None:
    if _get(d, "in_database") is None:
        return None
    if not _truthy(d["in_database"]):
        return None
    if d.get("valid") is False:
        return 0
    if d.get("verified") is False:
        return 5
    return 10


def _anyrun_subscore(d: Any) -> float | None:
    threat_level = _get(d, "summary", "threatLevel")
    if threat_level is None:
        return None
    if threat_level == 0:
        return 0
    if threat_level == 1:
        return 5
    return 9


def _greynoise_subscore(d: Any) -> float | None:
    if not _truthy(_get(d, "noise")) and not _truthy(_get(d, "riot")):
        return None
    if d.get("classification") == "malicious":
        return 9
    if _truthy(d.get("riot")) or d.get("classification") == "benign":
        return 0
    return 4


def _hybrid_analysis_subscore(d: Any) -> float | None:
    results = _get(d, "result")
    if not isinstance(results, list) or len(results) == 0:
        return None
    verdicts = [_js_string(_nz(_get(r, "verdict"), "")).lower() for r in results]
    if "malicious" in verdicts:
        return 9
    if "suspicious" in verdicts:
        return 5
    if any(v in ("whitelisted", "no specific threat") for v in verdicts):
        return 0
    return None


def _safe_browsing_subscore(d: Any) -> float | None:
    matches = _get(d, "matches")
    return 9 if isinstance(matches, list) and len(matches) > 0 else 0


_TWEETFEED_GENERIC_TAGS = {"#phishing", "#malware", "#scam", "#spam", "#opendir", "#ioc", "#iocs", "#threatintel"}


def _tweetfeed_signals(d: Any) -> dict:
    records = d["records"] if _truthy(_get(d, "found")) and isinstance(_get(d, "records"), list) else []
    users = {_key(u) for r in records for u in _arr(_get(r, "users"))}
    tweets = {_key(t) for r in records for t in _arr(_get(r, "tweets"))}
    tags = [t for r in records for t in _arr(_get(r, "tags"))]
    in_campaign = isinstance(_get(d, "campaigns"), list) and len(d["campaigns"]) > 0
    has_family = (in_campaign or _truthy(_get(d, "ai", "family"))
                  or any(_js_string(t).lower() not in _TWEETFEED_GENERIC_TAGS for t in tags))
    return {"found": len(records) > 0, "users": len(users), "tweets": len(tweets),
            "in_campaign": in_campaign, "has_family": has_family}


def _tweetfeed_subscore(d: Any) -> float | None:
    s = _tweetfeed_signals(d)
    if not s["found"]:
        return None
    if s["users"] >= 3 or s["has_family"]:
        return 7
    if s["users"] == 2:
        return 6
    return 5


_CROWDSEC_SCORES = {"malicious": 9, "suspicious": 6, "known": 4}


def _crowdsec_subscore(d: Any) -> float | None:
    if not _truthy(_get(d, "found")):
        return None
    rep = _get(d, "reputation")
    if len(_arr(_get(d, "classifications", "false_positives"))) > 0 or rep in ("safe", "benign"):
        return 0
    return _CROWDSEC_SCORES.get(rep) if isinstance(rep, str) else None


def _hashlookup_subscore(d: Any) -> float | None:
    if not _truthy(_get(d, "found")) or _truthy(_get(d, "KnownMalicious")):
        return None
    return 0


def _rdap_subscore(d: Any) -> float | None:
    age = _get(d, "age_days")
    if not _truthy(_get(d, "found")) or not _is_num(age):
        return None
    if age < 7:
        return 7
    if age < 30:
        return 5
    return None


def _tranco_subscore(d: Any) -> float | None:
    rank = _get(d, "rank")
    if not _truthy(_get(d, "found")) or _get(d, "exact") is not True or not _is_num(rank):
        return None
    return 0 if rank <= TRANCO_CLEAN_MAX_RANK else None


SPAMHAUS_SCORES = {
    "127.0.0.2": 8, "127.0.0.3": 6, "127.0.0.4": 7, "127.0.0.5": 7, "127.0.0.6": 7, "127.0.0.7": 7,
    "127.0.0.9": 9,
    "127.0.1.2": 7, "127.0.1.4": 9, "127.0.1.5": 9, "127.0.1.6": 9,
    "127.0.1.102": 5, "127.0.1.103": 5, "127.0.1.104": 6, "127.0.1.105": 6, "127.0.1.106": 6,
    "asndrop": 9,
}


def _spamhaus_scores(d: Any) -> list:
    out = []
    for item in _arr(_get(d, "listings")):
        code = _get(item, "code")
        if isinstance(code, str) and code in SPAMHAUS_SCORES:
            out.append(SPAMHAUS_SCORES[code])
    return out


def _spamhaus_subscore(d: Any) -> float | None:
    scores = _spamhaus_scores(d)
    if len(scores) == 0:
        return None
    best = 0
    for x in scores:
        if x > best:
            best = x
    return best


def _openphish_subscore(d: Any) -> float | None:
    if _get(d, "exact") is True:
        return 9 if _get(d, "kind") == "url" else 7
    return 6 if len(_arr(_get(d, "matches"))) > 0 else None


def _sslbl_subscore(d: Any) -> float | None:
    return 9 if _get(d, "listed") is True else None


def _yaraify_subscore(d: Any) -> float | None:
    if not _truthy(_get(d, "found")) or len(_arr(_get(d, "clamav"))) == 0:
        return None
    return 7


def _nvd_subscore(d: Any) -> float | None:
    score = _get(d, "cvss", "score")
    if not _truthy(_get(d, "found")) or _truthy(_get(d, "rejected")) or not _is_num(score):
        return None
    return max(0, min(10, score))


def _kev_subscore(d: Any) -> float | None:
    if _get(d, "listed") is not True:
        return None
    return 10 if _get(d, "ransomware") == "Known" else 9


def _epss_subscore(d: Any) -> float | None:
    p = _get(d, "epss")
    if not _truthy(_get(d, "found")) or not _is_num(p):
        return None
    for floor, score in EPSS_TIERS:
        if p >= floor:
            return score
    return 0


OPENTIP_ZONE_SCORES = {"Red": 9, "Orange": 7, "Yellow": 5, "Green": 0}


def _opentip_subscore(d: Any) -> float | None:
    zone = _get(d, "Zone")
    if _get(d, "applicable") is False or not isinstance(zone, str):
        return None
    return OPENTIP_ZONE_SCORES.get(zone)


def _vulncheck_kev_subscore(d: Any) -> float | None:
    if _get(d, "listed") is not True:
        return None
    return 10 if _get(d, "ransomware") == "Known" else 9


def _misp_subscore(d: Any) -> float | None:
    attrs = _get(d, "Attribute")
    if not isinstance(attrs, list):
        return None
    if len(attrs) == 0:
        return None
    ids_hit = any(
        (lambda t: (t is True) or (_is_num(t) and t == 1) or t == "1")(_get(a, "to_ids")) for a in attrs
    )
    return 9 if ids_hit else None


def _opencti_subscore(d: Any) -> float | None:
    if not _truthy(_get(d, "found")):
        return None
    if _get(d, "kind") == "actor":
        return None
    if _get(d, "kind") == "vulnerability":
        if _get(d, "vulnerability", "kev") is True:
            return 9
        n = _get(d, "threat_links")
        return 8 if _is_num(n) and n > 0 else None
    active = [i for i in _arr(_get(d, "indicators")) if _get(i, "active") is True]
    if len(active) == 0:
        return None
    scores = [s for s in (_get(i, "score") for i in active) if _is_num(s)]
    if len(scores) == 0:
        return 7
    best = scores[0]
    for s in scores:
        if s > best:
            best = s
    return min(10, best / 10) if best > 0 else None


_ALL4 = ("ip", "domain", "url", "hash")


def _for(types, fn) -> dict:
    return {t: fn for t in types}


_VERDICT_NORMALIZERS: dict[str, dict] = {
    "virustotal": {"ip": _vt_host_subscore, "domain": _vt_host_subscore, "url": _vt_subscore, "hash": _vt_subscore},
    "abuseipdb": {"ip": _abuseipdb_subscore},
    "alienvault": {**_for(_ALL4, _alienvault_subscore), "cve": _alienvault_cve_subscore},
    "abusech": _for(("ip", "hash"), _abusech_subscore),
    "recordedfuture": _for(_ALL4, _recorded_future_subscore),
    "torexitlist": {"ip": _tor_exit_list_subscore},
    "urlhaus": _for(_ALL4, _urlhaus_subscore),
    "urlscan": _for(("url", "domain"), _urlscan_subscore),
    "malwarebazaar": {"hash": _malware_bazaar_subscore},
    "phishtank": {"url": _phishtank_subscore},
    "anyrun": _for(_ALL4, _anyrun_subscore),
    "greynoise": {"ip": _greynoise_subscore},
    "hybridanalysis": _for(_ALL4, _hybrid_analysis_subscore),
    "safebrowsing": {"url": _safe_browsing_subscore},
    "tweetfeed": _for(_ALL4, _tweetfeed_subscore),
    "crowdsec": {"ip": _crowdsec_subscore},
    "hashlookup": {"hash": _hashlookup_subscore},
    "rdap": _for(("domain", "url"), _rdap_subscore),
    "tranco": {"domain": _tranco_subscore},
    "spamhaus": _for(("ip", "domain", "url", "asn"), _spamhaus_subscore),
    "openphish": _for(("ip", "domain", "url"), _openphish_subscore),
    "sslbl": {"hash": _sslbl_subscore},
    "yaraify": {"hash": _yaraify_subscore},
    "nvd": {"cve": _nvd_subscore},
    "cisakev": {"cve": _kev_subscore},
    "epss": {"cve": _epss_subscore},
    "opentip": _for(_ALL4, _opentip_subscore),
    "vulncheckkev": {"cve": _vulncheck_kev_subscore},
}


def get_engine_subscore(engine_id: str, type: str, data: Any) -> float | None:
    if not _truthy(data) or _truthy(_get(data, "error")):
        return None
    if engine_id.startswith("misp_"):
        return _misp_subscore(data)
    if engine_id.startswith("opencti_"):
        return _opencti_subscore(data)
    normalizer = _VERDICT_NORMALIZERS.get(engine_id, {}).get(type)
    if normalizer is None:
        return None
    return normalizer(data)


# ── Per-engine depth: raw API response → 0 / 0.5 / 1 ─────────────────────────

def _by_count(n: Any, basic_max: int) -> float:
    return 0 if n <= 0 else 0.5 if n <= basic_max else 1


def _vt_depth(d: Any) -> float:
    a = _get(d, "data", "attributes")
    if not _truthy(a):
        return 0
    s = _nz(a.get("last_analysis_stats"), {})
    detections = _nz(_get(s, "malicious"), 0) + _nz(_get(s, "suspicious"), 0)
    votes = _nz(_get(a, "total_votes", "harmless"), 0) + _nz(_get(a, "total_votes", "malicious"), 0)
    if detections > 0 or votes > 0 or len(_arr(a.get("tags"))) > 0:
        return 1
    return 0.5


def _alienvault_depth(d: Any) -> float:
    if _get(d, "type_title") == "CVE" and (_get(d, "seen_wild") is True or (
            _is_num(_get(d, "exploits_total")) and d["exploits_total"] > 0)):
        return 1
    count = _nz(_get(d, "pulse_info", "count"), _nz(_get(d, "count"), len(_arr(_get(d, "results")))))
    return _by_count(_nz(count, 0), 2)


def _recorded_future_depth(d: Any) -> float:
    if _get(d, "kind") == "actor":
        if not _truthy(_get(d, "found")):
            return 0
        links = _get(d, "insikt_links")
        return 1 if isinstance(links, dict) and len(links) > 0 else 0.5
    if not _truthy(_get(d, "risk")) and not _truthy(_get(d, "entity")):
        return 0
    return 1 if len(_arr(_get(d, "risk", "evidenceDetails"))) > 0 else 0.5


def _misp_depth(d: Any) -> float:
    attrs = _arr(_get(d, "Attribute"))
    if len(attrs) == 0:
        return 0
    events = {_key(e) for e in (_nz(_get(a, "event_id"), _get(a, "Event", "id")) for a in attrs) if _truthy(e)}
    return 1 if len(attrs) >= 3 or len(events) >= 2 else 0.5


def _mitre_depth(d: Any) -> float:
    if not _truthy(_get(d, "name")):
        return 0
    return 1 if len(_arr(d.get("techniques"))) > 0 or len(_arr(d.get("software"))) > 0 else 0.5


def _abuseipdb_depth(d: Any) -> float:
    data = _get(d, "data")
    if not _truthy(data):
        return 0
    if _truthy(_get(data, "isWhitelisted")):
        return 1
    return _by_count(_nz(_get(data, "totalReports"), 0), 9)


def _list_hit_depth(d: Any) -> float:
    return 1 if len(_arr(_get(d, "data"))) > 0 else 0


def _urlhaus_depth(d: Any) -> float:
    if _get(d, "query_status") == "no_results":
        return 0
    if isinstance(_get(d, "url_status"), str):
        return 1 if len(_arr(d.get("payloads"))) > 0 else 0.5
    return _by_count(len(_arr(_get(d, "urls"))), 1)


def _anyrun_depth(d: Any) -> float:
    level = _get(d, "summary", "threatLevel")
    if level is None:
        return 0
    return 1 if level >= 1 else 0.5


def _shodan_depth(d: Any) -> float:
    if _truthy(_get(d, "ip_str")):
        if len(_arr(d.get("ports"))) >= 3 or len(_arr(d.get("vulns"))) > 0 or len(_arr(d.get("tags"))) > 0:
            return 1
        return 0.5
    total = _get(d, "total")
    if _is_num(total):
        return 1 if total > 0 else 0
    return 0


def _hybrid_analysis_depth(d: Any) -> float:
    results = _arr(_get(d, "result"))
    if len(results) == 0:
        return 0
    has_verdict = any(
        (lambda v: v != "" and v != "no verdict")(_js_string(_nz(_get(r, "verdict"), "")).lower()) for r in results
    )
    return 1 if has_verdict else 0.5


def _urlscan_depth(d: Any) -> float:
    return _by_count(_nz(_get(d, "total"), 0), 2)


def _greynoise_depth(d: Any) -> float:
    if not _truthy(_get(d, "noise")) and not _truthy(_get(d, "riot")):
        return 0
    if _truthy(d.get("riot")) or d.get("classification") in ("malicious", "benign"):
        return 1
    return 0.5


def _phishtank_depth(d: Any) -> float:
    if not _truthy(_get(d, "in_database")):
        return 0
    return 1 if _truthy(d.get("verified")) else 0.5


def _safe_browsing_depth(d: Any) -> float:
    return 1 if len(_arr(_get(d, "matches"))) > 0 else 0


def _tor_depth(d: Any) -> float:
    return 1 if _truthy(_get(d, "is_tor_exit")) else 0


def _ipinfo_depth(d: Any) -> float:
    if not _truthy(d) or _truthy(_get(d, "bogon")):
        return 0
    return 0.5


def _ripestat_depth(d: Any) -> float:
    if _truthy(_get(d, "as_overview")):
        return 1 if _truthy(_get(d, "as_overview", "holder")) else 0
    return 0.5 if len(_arr(_get(d, "network_info", "asns"))) > 0 else 0


def _tweetfeed_depth(d: Any) -> float:
    s = _tweetfeed_signals(d)
    if not s["found"]:
        return 0
    return 1 if s["users"] >= 2 or s["tweets"] >= 2 or s["in_campaign"] else 0.5


def _crowdsec_depth(d: Any) -> float:
    if not _truthy(_get(d, "found")):
        return 0
    if (len(_arr(_get(d, "behaviors"))) > 0 or len(_arr(_get(d, "classifications", "false_positives"))) > 0
            or _get(d, "reputation") in ("malicious", "suspicious", "safe", "benign")):
        return 1
    return 0.5


def _hashlookup_depth(d: Any) -> float:
    if not _truthy(_get(d, "found")):
        return 0
    trust = _get(d, "hashlookup:trust")
    parents = _get(d, "hashlookup:parent-total")
    return 1 if (_is_num(trust) and trust > 50) or (_is_num(parents) and parents > 0) else 0.5


def _rdap_depth(d: Any) -> float:
    return 0.5 if _truthy(_get(d, "found")) else 0


def _tranco_depth(d: Any) -> float:
    rank = _get(d, "rank")
    if not _truthy(_get(d, "found")) or _get(d, "exact") is not True or not _is_num(rank):
        return 0
    return 1 if rank <= TRANCO_CLEAN_MAX_RANK else 0.5


def _malpedia_depth(d: Any) -> float:
    if not _truthy(_get(d, "found")):
        return 0
    return 1 if len(_arr(_get(d, "families"))) > 0 or _truthy(_get(d, "description")) else 0.5


def _spamhaus_depth(d: Any) -> float:
    if len(_spamhaus_scores(d)) > 0:
        return 1
    return 0.5 if len(_arr(_get(d, "listings"))) > 0 else 0


def _openphish_depth(d: Any) -> float:
    if _get(d, "exact") is True:
        return 1
    return 0.5 if len(_arr(_get(d, "matches"))) > 0 else 0


def _sslbl_depth(d: Any) -> float:
    return 1 if _get(d, "listed") is True else 0


def _yaraify_depth(d: Any) -> float:
    if not _truthy(_get(d, "found")):
        return 0
    return 1 if len(_arr(_get(d, "rules"))) > 0 or len(_arr(_get(d, "clamav"))) > 0 else 0.5


def _circlpdns_depth(d: Any) -> float:
    total = _get(d, "total")
    if not _is_num(total) or total <= 0:
        return 0
    return 0.5 if total <= 4 else 1


def _nvd_depth(d: Any) -> float:
    if not _truthy(_get(d, "found")):
        return 0
    if _truthy(_get(d, "rejected")):
        return 0.5
    return 1 if _is_num(_get(d, "cvss", "score")) else 0.5


def _kev_depth(d: Any) -> float:
    return 1 if _get(d, "listed") is True else 0


def _epss_depth(d: Any) -> float:
    return 1 if _truthy(_get(d, "found")) and _is_num(_get(d, "epss")) else 0


def _opencti_depth(d: Any) -> float:
    if not _truthy(_get(d, "found")):
        return 0
    reports = _get(d, "reports_total")
    if len(_arr(_get(d, "indicators"))) > 0 or len(_arr(_get(d, "relations"))) > 0 or (_is_num(reports) and reports > 0):
        return 1
    return 0.5


def _opentip_depth(d: Any) -> float:
    zone = _get(d, "Zone")
    if _get(d, "applicable") is False or not isinstance(zone, str):
        return 0
    return 1 if zone in OPENTIP_ZONE_SCORES else 0.5


def _vulncheck_kev_depth(d: Any) -> float:
    return 1 if _get(d, "listed") is True else 0


_DEPTH_FNS = {
    "tweetfeed": _tweetfeed_depth,
    "virustotal": _vt_depth,
    "alienvault": _alienvault_depth,
    "recordedfuture": _recorded_future_depth,
    "mitreattack": _mitre_depth,
    "abuseipdb": _abuseipdb_depth,
    "abusech": _list_hit_depth,
    "malwarebazaar": _list_hit_depth,
    "urlhaus": _urlhaus_depth,
    "anyrun": _anyrun_depth,
    "shodan": _shodan_depth,
    "hybridanalysis": _hybrid_analysis_depth,
    "urlscan": _urlscan_depth,
    "greynoise": _greynoise_depth,
    "phishtank": _phishtank_depth,
    "safebrowsing": _safe_browsing_depth,
    "torexitlist": _tor_depth,
    "ipinfo": _ipinfo_depth,
    "ripestat": _ripestat_depth,
    "crowdsec": _crowdsec_depth,
    "hashlookup": _hashlookup_depth,
    "rdap": _rdap_depth,
    "tranco": _tranco_depth,
    "malpedia": _malpedia_depth,
    "spamhaus": _spamhaus_depth,
    "openphish": _openphish_depth,
    "sslbl": _sslbl_depth,
    "yaraify": _yaraify_depth,
    "circlpdns": _circlpdns_depth,
    "nvd": _nvd_depth,
    "cisakev": _kev_depth,
    "epss": _epss_depth,
    "opentip": _opentip_depth,
    "vulncheckkev": _vulncheck_kev_depth,
}


# ── Assessment & aggregation ─────────────────────────────────────────────────

_EXCLUDED = {"outcome": "excluded", "subscore": None, "depth": None}


def _error_code(data: Any) -> Any:
    return _get(data, "error", "code")


def get_engine_assessment(engine_id: str, type: str, result: dict | None) -> dict:
    if not result or _truthy(result.get("error")) or not _truthy(result.get("data")):
        return dict(_EXCLUDED)
    data = result["data"]
    code = _error_code(data)
    if _truthy(code):
        if code in NO_DATA_ERROR_CODES:
            return {"outcome": "no_data", "subscore": None, "depth": 0}
        return dict(_EXCLUDED)

    subscore = get_engine_subscore(engine_id, type, data)
    depth_fn = (_misp_depth if engine_id.startswith("misp_")
                else _opencti_depth if engine_id.startswith("opencti_") else _DEPTH_FNS.get(engine_id))
    depth = depth_fn(data) if depth_fn else 0

    if subscore is not None:
        outcome = "hit" if subscore > 0 else "clean"
    else:
        outcome = "context" if depth > 0 else "no_data"
    return {"outcome": outcome, "subscore": subscore, "depth": depth}


def _classify(knowledge: float, risk: float | None, risk_rows: list[dict], t: dict) -> str:
    known_well = knowledge >= t["knowledge"]
    if risk is not None and risk >= t["risk"]:
        return "confirmed_malicious" if known_well else "isolated_signal"
    if not known_well:
        return "unknown"
    if risk is None:
        return "known_no_verdict"
    any_clean = any(c["subscore"] == 0 for c in risk_rows)
    any_relevant_hit = any(c["subscore"] >= t["risk"] for c in risk_rows)
    return "known_benign" if any_clean and not any_relevant_hit else "known_low_signals"


def _is_transient_failure(result: dict | None) -> bool:
    if not result:
        return False
    if _truthy(result.get("error")):
        return True
    code = _error_code(result.get("data"))
    return _truthy(code) and code in TRANSIENT_ERROR_CODES


def compute_verdict(config: dict, engines: list[dict], results: dict[str, dict], type: str) -> dict:
    """engines: [{"id", "label"}] in display order; results: engine id → result."""
    risk: list[dict] = []
    knowledge: list[dict] = []
    responded = 0
    knowledge_denominator = 0
    knowledge_numerator = 0
    queried = 0

    for engine in engines:
        eid = engine["id"]
        result = results.get(eid)
        if _error_code(_get(result, "data")) == "MissingApiKey":
            continue
        queried += 1
        a = get_engine_assessment(eid, type, result)

        kw = knowledge_weight_of(config, eid, type)
        if _is_num(kw) and kw > 0:  # JS: undefined > 0 is false
            depth = 0 if a["outcome"] == "excluded" else _nz(a["depth"], 0)
            in_total = not _is_transient_failure(result)
            row = {"engineId": eid, "label": engine["label"], "weight": kw, "depth": depth, "outcome": a["outcome"]}
            if not in_total:
                row["inTotal"] = False
            knowledge.append(row)
            if in_total:
                knowledge_denominator += kw
                knowledge_numerator += kw * depth

        if a["outcome"] == "excluded":
            continue
        responded += 1

        rw = risk_weight_of(config, eid)
        if _is_num(rw) and rw > 0 and a["subscore"] is not None:
            risk.append({"engineId": eid, "label": engine["label"], "weight": rw, "subscore": a["subscore"]})

    full_at = _nz(_get(config, "scoring", "knowledge_full_at"), DEFAULT_SCORING["knowledge_full_at"])
    knowledge_score = (
        _js_round(knowledge_from_sums(knowledge_numerator, knowledge_denominator, full_at))
        if knowledge_denominator > 0 and responded > 0 else None
    )

    risk_score = None
    if len(risk) > 0 and knowledge_numerator > 0:
        tw = 0
        for c in risk:
            tw = tw + c["weight"]
        ws = 0
        for c in risk:
            ws = ws + c["weight"] * c["subscore"]
        risk_score = max(0, min(10, _js_round(ws / tw)))

    quadrant = None if knowledge_score is None else _classify(knowledge_score, risk_score, risk, config["thresholds"])

    return {
        "risk": risk_score,
        "knowledge": knowledge_score,
        "quadrant": quadrant,
        "contributions": {"risk": risk, "knowledge": knowledge, "knowledgeFullAt": full_at},
        "responded": responded,
        "queried": queried,
    }
