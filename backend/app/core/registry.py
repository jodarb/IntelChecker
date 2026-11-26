from app.core import connectors

# Order and labels mirror STATIC_ENGINES in frontend/src/registry.tsx: the backend
# verdict (POST /lookup) lists contributions in this order and stores these labels
# in history snapshots, exactly like a lookup run from the UI.
_ALL = ["ip", "domain", "url", "hash"]


def _engine(label: str, supports: list[str], key: str | None) -> dict:
    return {"label": label, "supports": supports, "key": key}


STATIC_ENGINES: dict[str, dict] = {
    "abuseipdb":      _engine("AbuseIPDB", ["ip"], "ABUSEIPDB_API_KEY"),
    "virustotal":     _engine("VirusTotal", _ALL, "VIRUSTOTAL_API_KEY"),
    "abusech":        _engine("ThreatFox · abuse.ch", ["ip", "hash"], "ABUSECH_AUTH_KEY"),
    "alienvault":     _engine("AlienVault OTX", [*_ALL, "threat-actor", "cve"], "ALIENVAULT_API_KEY"),
    "ipinfo":         _engine("IPinfo", ["ip"], "IPINFO_API_KEY"),
    "shodan":         _engine("Shodan", ["ip", "asn"], "SHODAN_API_KEY"),
    "torexitlist":    _engine("Tor Exit Nodes (dan.me.uk)", ["ip"], None),
    "urlhaus":        _engine("URLhaus · abuse.ch", _ALL, "ABUSECH_AUTH_KEY"),
    "mitreattack":    _engine("MITRE ATT&CK", ["threat-actor"], None),
    "ripestat":       _engine("RIPEstat", ["ip", "asn"], None),
    "urlscan":        _engine("urlscan.io", ["url", "domain"], "URLSCAN_API_KEY"),
    "malwarebazaar":  _engine("MalwareBazaar · abuse.ch", ["hash"], "ABUSECH_AUTH_KEY"),
    "phishtank":      _engine("PhishTank", ["url"], None),
    "recordedfuture": _engine("Recorded Future", _ALL, "RECORDED_FUTURE_API_KEY"),
    "anyrun":         _engine("ANY.RUN", _ALL, "ANYRUN_API_KEY"),
    "greynoise":      _engine("GreyNoise", ["ip"], "GREYNOISE_API_KEY"),
    "hybridanalysis": _engine("Hybrid Analysis", _ALL, "HYBRID_ANALYSIS_API_KEY"),
    "safebrowsing":   _engine("Google Safe Browsing", ["url"], "GOOGLE_SAFE_BROWSING_API_KEY"),
    "tweetfeed":      _engine("TweetFeed", _ALL, None),
    "crowdsec":       _engine("CrowdSec CTI", ["ip"], "CROWDSEC_API_KEY"),
    "hashlookup":     _engine("CIRCL hashlookup", ["hash"], None),
    "rdap":           _engine("RDAP (domain registration)", ["domain", "url"], None),
    "tranco":         _engine("Tranco (top domains)", ["domain"], None),
    # The API token is optional (higher rate limit): connected without it.
    "malpedia":       _engine("Malpedia", ["threat-actor"], None),
    # Works without the DQS key (own DNS resolver); the key is optional.
    "spamhaus":       _engine("Spamhaus", ["ip", "domain", "url", "asn"], None),
    "openphish":      _engine("OpenPhish", ["ip", "domain", "url"], None),
    "yaraify":        _engine("YARAify · abuse.ch", ["hash"], "ABUSECH_AUTH_KEY"),
    "sslbl":          _engine("SSLBL · abuse.ch", ["hash"], None),
    "circlpdns":      _engine("CIRCL Passive DNS", ["ip", "domain"], "CIRCL_PDNS_CREDENTIALS"),
    # Vulnerabilities. The NVD key is optional (higher rate limit): connected without it.
    "nvd":            _engine("NVD (NIST)", ["cve"], None),
    "cisakev":        _engine("CISA KEV", ["cve"], None),
    "epss":           _engine("EPSS · FIRST", ["cve"], None),
}

# MISP and OpenCTI are multi-instance: any number of servers, managed from the Connectors page
# (or MISP_<N>_* in .env until then — see connectors.py), each becoming its own
# entry with its own display name and connected status. Instances can be added or
# removed at runtime, so the full list is built on every call.
# OpenCTI works the same way (OPENCTI_<N>_* in .env), and also answers CVEs and
# threat actors. `kind` tells the frontend which card renders the instance.
INSTANCE_SUPPORTS = {
    "misp": ["ip", "domain", "url", "hash"],
    "opencti": ["ip", "domain", "url", "hash", "threat-actor", "cve"],
}


def engines() -> dict[str, dict]:
    out = dict(STATIC_ENGINES)
    for kind in connectors.INSTANCE_KINDS:
        for inst in connectors.instances(kind):
            out[inst["id"]] = {
                "label": inst["name"],
                "supports": INSTANCE_SUPPORTS[kind],
                "key": None,
                "name": inst["name"],
                "kind": kind,
                "connected": bool(inst["url"]) and bool(inst["key"]),
            }
    return out


def is_connected(meta: dict) -> bool:
    if "connected" in meta:
        return meta["connected"]
    return True if meta["key"] is None else bool(connectors.secret(meta["key"]))


INDICATOR_TYPES = ("ip", "domain", "url", "hash", "asn", "threat-actor", "cve")
