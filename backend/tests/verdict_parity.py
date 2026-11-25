"""Parity test: backend/app/core/verdict.py must give exactly what
frontend/src/verdictEngine.ts gives.

Generates random source results (realistic payload shapes with random values,
error codes, missing fields…) plus random weights, runs both engines and compares
every per-source assessment and the whole verdict (scores, quadrant,
contributions). Needs Node ≥ 23 (runs the TypeScript engine directly).

    cd backend && .venv/bin/python tests/verdict_parity.py            # 3000 cases
    cd backend && .venv/bin/python tests/verdict_parity.py 20000 --seed 7

Optionally replay real lookups from a history database (their stored results):

    .venv/bin/python tests/verdict_parity.py --history data/history.db

Exit code 0 = identical, 1 = mismatch (the first differences are printed).
"""
import argparse
import json
import math
import random
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.core.verdict import compute_verdict, get_engine_assessment  # noqa: E402

CLI = ROOT / "frontend" / "scripts" / "verdict-cli.ts"
TYPES = ["ip", "domain", "url", "hash", "asn", "threat-actor"]
ENGINE_IDS = [
    "abuseipdb", "virustotal", "abusech", "alienvault", "ipinfo", "shodan", "torexitlist", "urlhaus",
    "mitreattack", "ripestat", "urlscan", "malwarebazaar", "phishtank", "recordedfuture", "anyrun",
    "greynoise", "hybridanalysis", "safebrowsing", "tweetfeed", "crowdsec", "hashlookup", "rdap", "tranco",
    "malpedia", "spamhaus", "openphish", "sslbl", "yaraify", "circlpdns", "misp_1", "misp_2",
]
ERROR_CODES = ["NotFound", "MissingApiKey", "RateLimitExceeded", "Timeout", "NetworkError",
               "ServiceUnavailable", "HttpError", "Unauthorized", "UnsupportedType", "ApiError"]


def maybe(r: random.Random, value, p_missing=0.15):
    """Return the value, None or a sentinel meaning "leave the key out"."""
    x = r.random()
    if x < p_missing:
        return _MISSING
    if x < p_missing + 0.08:
        return None
    return value


_MISSING = object()


def obj(**fields) -> dict:
    return {k: v for k, v in fields.items() if v is not _MISSING}


def num(r: random.Random, choices=(0, 1, 2, 3, 5, 6, 9, 10, 50, 100)):
    return r.choice(choices) if r.random() < 0.85 else round(r.uniform(0, 100), 3)


def payload(r: random.Random, engine: str):
    m = lambda v: maybe(r, v)  # noqa: E731
    if engine == "virustotal":
        return obj(data=m(obj(attributes=m(obj(
            last_analysis_stats=m(obj(malicious=m(num(r, (0, 1, 2, 4, 5, 8))), suspicious=m(num(r, (0, 1, 3))))),
            total_votes=m(obj(harmless=m(num(r, (0, 1, 3))), malicious=m(num(r, (0, 2))))),
            tags=m(r.choice([[], ["cdn"], ["a", "b"]])),
        )))))
    if engine == "abuseipdb":
        return obj(data=m(obj(abuseConfidenceScore=m(num(r)), totalReports=m(num(r, (0, 1, 9, 10, 40))),
                              isWhitelisted=m(r.choice([True, False, None])))))
    if engine == "alienvault":
        return obj(pulse_info=m(obj(count=m(num(r, (0, 1, 2, 3, 5, 6, 30))))), count=m(num(r, (0, 2, 4))),
                   results=m(r.choice([[], [{}], [{}, {}, {}]])))
    if engine in ("abusech", "malwarebazaar"):
        return obj(query_status=m(r.choice(["ok", "no_results"])),
                   data=m(r.choice([[], [obj(confidence_level=m(num(r, (0, 50, 75, 100))))],
                                    [obj(confidence_level=m(25)), obj(confidence_level=m(100))]])))
    if engine == "recordedfuture":
        return obj(risk=m(obj(score=m(num(r, (0, 5, 25, 65, 89, 99))),
                              evidenceDetails=m(r.choice([[], [{}], [{}, {}]])))), entity=m(r.choice([{}, {"id": "x"}])))
    if engine == "torexitlist":
        return obj(is_tor_exit=m(r.choice([True, False])))
    if engine == "urlhaus":
        if r.random() < 0.5:
            return obj(query_status=m(r.choice(["ok", "no_results"])), url_status=m(r.choice(["online", "offline"])),
                       payloads=m(r.choice([[], [{}]])))
        return obj(query_status=m(r.choice(["ok", "no_results"])),
                   urls=m(r.choice([[], [{"url_status": "offline"}], [{"url_status": "online"}, {}]])))
    if engine == "urlscan":
        return obj(total=m(num(r, (0, 1, 2, 3, 5, 6, 100))))
    if engine == "phishtank":
        return obj(in_database=m(r.choice([True, False])), valid=m(r.choice([True, False])),
                   verified=m(r.choice([True, False])))
    if engine == "anyrun":
        return obj(summary=m(obj(threatLevel=m(r.choice([0, 1, 2, 3])))))
    if engine == "greynoise":
        return obj(noise=m(r.choice([True, False])), riot=m(r.choice([True, False])),
                   classification=m(r.choice(["malicious", "benign", "unknown", ""])))
    if engine == "hybridanalysis":
        verdicts = ["malicious", "suspicious", "whitelisted", "no specific threat", "no verdict", "", None, "Malicious"]
        return obj(result=m([obj(verdict=m(r.choice(verdicts))) for _ in range(r.choice([0, 1, 2, 3]))]))
    if engine == "safebrowsing":
        return obj(matches=m(r.choice([[], [{}], [{}, {}]])))
    if engine == "tweetfeed":
        tags = ["#phishing", "#malware", "#IOC", "#emotet", "#cobaltstrike", 3]
        records = [obj(users=m(r.sample(["a", "b", "c", "d"], r.choice([0, 1, 2, 3]))),
                       tweets=m(r.sample(["t1", "t2", "t3"], r.choice([0, 1, 2]))),
                       tags=m(r.sample(tags, r.choice([0, 1, 2]))))
                   for _ in range(r.choice([0, 1, 2]))]
        return obj(found=m(r.choice([True, False])), records=m(records),
                   campaigns=m(r.choice([[], [{}]])), ai=m(obj(family=m(r.choice(["", "Emotet"])))))
    if engine == "crowdsec":
        return obj(found=m(r.choice([True, False])),
                   reputation=m(r.choice(["malicious", "suspicious", "known", "safe", "benign", "unknown", "", 3])),
                   behaviors=m(r.choice([[], [{"name": "ssh:bruteforce"}]])),
                   classifications=m(obj(false_positives=m(r.choice([[], [{"name": "public_dns"}]])))))
    if engine == "hashlookup":
        return obj(found=m(r.choice([True, False])), KnownMalicious=m(r.choice(["", "malshare.com", None])),
                   **{"hashlookup:trust": m(r.choice([50, 51, 100, 0, "60"])),
                      "hashlookup:parent-total": m(r.choice([0, 1, 15]))})
    if engine == "rdap":
        return obj(found=m(r.choice([True, False])), age_days=m(r.choice([0, 6, 7, 29, 30, 365, 0.5, "3"])))
    if engine == "tranco":
        return obj(found=m(r.choice([True, False])), exact=m(r.choice([True, False, 1])),
                   rank=m(r.choice([1, 99999, 100000, 100001, 999999, "5"])))
    if engine == "malpedia":
        return obj(found=m(r.choice([True, False])), families=m(r.choice([[], [{}]])),
                   description=m(r.choice(["", "APT group"])))
    if engine == "spamhaus":
        codes = ["127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.9", "127.0.0.10", "127.0.0.11", "127.0.1.2",
                 "127.0.1.6", "127.0.1.104", "asndrop", "127.0.0.99", "constructor", 2, None]
        return obj(listings=m([obj(code=m(r.choice(codes))) for _ in range(r.choice([0, 1, 2, 3]))]))
    if engine == "openphish":
        return obj(kind=m(r.choice(["url", "host", ""])), exact=m(r.choice([True, False, 1])),
                   matches=m(r.choice([[], ["https://a/"], ["https://a/", "https://a/b"]])))
    if engine == "sslbl":
        return obj(listed=m(r.choice([True, False, 1])), applicable=m(r.choice([True, False])))
    if engine == "yaraify":
        return obj(found=m(r.choice([True, False])), rules=m(r.choice([[], [{}]])),
                   clamav=m(r.choice([[], ["Win.Trojan.X"]])))
    if engine == "circlpdns":
        return obj(total=m(r.choice([0, 1, 4, 5, 100, "7", -1])))
    if engine.startswith("misp_"):
        to_ids = [True, False, 1, 0, "1", "0", None]
        return obj(Attribute=m([obj(to_ids=m(r.choice(to_ids)), event_id=m(r.choice(["1", "2", "3", None])),
                                    Event=m(obj(id=m(r.choice(["7", "8"])))))
                                for _ in range(r.choice([0, 1, 2, 3, 4]))]))
    if engine == "mitreattack":
        return obj(name=m(r.choice(["APT28", ""])), techniques=m(r.choice([[], [{}]])), software=m(r.choice([[], [{}]])))
    if engine == "shodan":
        if r.random() < 0.5:
            return obj(ip_str=m(r.choice(["1.2.3.4", ""])), ports=m(r.choice([[], [80], [22, 80, 443]])),
                       vulns=m(r.choice([[], ["CVE"]])), tags=m(r.choice([[], ["vpn"]])))
        return obj(total=m(r.choice([0, 3, "5"])))
    if engine == "ipinfo":
        return obj(bogon=m(r.choice([True, False])), ip=m("1.2.3.4"))
    if engine == "ripestat":
        if r.random() < 0.5:
            return obj(as_overview=m(obj(holder=m(r.choice(["CLOUDFLARENET", ""])))))
        return obj(network_info=m(obj(asns=m(r.choice([[], ["13335"]])))))
    return {}


def random_result(r: random.Random, engine: str) -> dict:
    x = r.random()
    if x < 0.05:
        return {"data": None, "error": "Could not reach the backend. Is it running?"}
    if x < 0.20:
        return {"data": {"error": {"code": r.choice(ERROR_CODES), "message": "x"}}, "error": None}
    if x < 0.23:
        return {"data": r.choice([{}, None]), "error": None}
    return {"data": payload(r, engine), "error": None}


def random_config(r: random.Random, engines: list[str]) -> dict:
    cfg = {"engines": {}, "thresholds": {"knowledge": r.randint(0, 10), "risk": r.randint(0, 10)}}
    if r.random() < 0.8:
        cfg["scoring"] = {"knowledge_full_at": r.choice([10, 35, 50, 70, 85, 100])}
    for e in engines:
        if r.random() < 0.05:
            continue  # engine missing from the config → weight 0
        w = {"risk": r.randint(0, 10), "knowledge": r.randint(0, 10)}
        if r.random() < 0.2:
            w["knowledge_by_type"] = {r.choice(TYPES): r.randint(0, 10)}
        cfg["engines"][e] = w
    return cfg


def random_case(r: random.Random) -> dict:
    type_ = r.choice(TYPES)
    ids = r.sample(ENGINE_IDS, r.randint(0, 9))
    return {
        "config": random_config(r, ids),
        "engines": [{"id": e, "label": e.upper()} for e in ids],
        "results": {e: random_result(r, e) for e in ids if r.random() > 0.03},  # some never answered
        "type": type_,
    }


def history_cases(db_path: str) -> list[dict]:
    weights_path = Path(db_path).with_name("weights.json")
    sys.path.insert(0, str(ROOT / "backend"))
    from app.core import weights as weights_store  # noqa: E402
    if weights_path.exists():
        weights_store._WEIGHTS_PATH = weights_path
    config = weights_store.get_weights()
    conn = sqlite3.connect(db_path)
    cases = []
    for type_, results_json in conn.execute("SELECT type, results_json FROM history"):
        stored = json.loads(results_json)
        cases.append({
            "config": config,
            "engines": [{"id": k, "label": v.get("label", k)} for k, v in stored.items()],
            "results": {k: {"data": v.get("data"), "error": v.get("error")} for k, v in stored.items()},
            "type": type_,
        })
    return cases


def same(a, b, path="") -> list[str]:
    if isinstance(a, dict) and isinstance(b, dict):
        diffs = []
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                diffs.append(f"{path}.{k}: missing on {'python' if k not in a else 'typescript'} side")
            else:
                diffs += same(a[k], b[k], f"{path}.{k}")
        return diffs
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return [f"{path}: length {len(a)} (py) != {len(b)} (ts)"]
        return [d for i, (x, y) in enumerate(zip(a, b)) for d in same(x, y, f"{path}[{i}]")]
    numeric = (int, float)
    if isinstance(a, numeric) and isinstance(b, numeric) and not isinstance(a, bool) and not isinstance(b, bool):
        return [] if math.isclose(a, b, rel_tol=0, abs_tol=1e-12) else [f"{path}: {a!r} (py) != {b!r} (ts)"]
    return [] if a == b and type(a) is type(b) else [f"{path}: {a!r} (py) != {b!r} (ts)"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("n", nargs="?", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--history", help="also replay the results stored in this history.db")
    args = ap.parse_args()

    r = random.Random(args.seed)
    cases = [random_case(r) for _ in range(args.n)]
    if args.history:
        cases += history_cases(args.history)

    proc = subprocess.run(["node", str(CLI)], input=json.dumps(cases), capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        return 2
    ts_out = json.loads(proc.stdout)

    failures = 0
    for i, (case, ts) in enumerate(zip(cases, ts_out)):
        py = {
            "verdict": compute_verdict(case["config"], case["engines"], case["results"], case["type"]),
            "assessments": {e["id"]: get_engine_assessment(e["id"], case["type"], case["results"].get(e["id"]))
                            for e in case["engines"]},
        }
        diffs = same(py, ts)
        if diffs:
            failures += 1
            if failures <= 5:
                print(f"case {i} ({case['type']}):\n  " + "\n  ".join(diffs[:8]))
    print(f"{len(cases)} cases, {failures} mismatches")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
