from app.core.config import MISP_INSTANCES

# Order and labels mirror STATIC_ENGINES in frontend/src/registry.tsx: the backend
# verdict (POST /lookup) lists contributions in this order and stores these labels
# in history snapshots, exactly like a lookup run from the UI.
_ALL = ["ip", "domain", "url", "hash"]


def _engine(label: str, supports: list[str], key: str | None) -> dict:
    return {"label": label, "supports": supports, "key": key}


ENGINES: dict[str, dict] = {
    "abuseipdb":      _engine("AbuseIPDB", ["ip"], "ABUSEIPDB_API_KEY"),
    "virustotal":     _engine("VirusTotal", _ALL, "VIRUSTOTAL_API_KEY"),
    "abusech":        _engine("ThreatFox · abuse.ch", ["ip", "hash"], "ABUSECH_AUTH_KEY"),
    "alienvault":     _engine("AlienVault OTX", [*_ALL, "threat-actor"], "ALIENVAULT_API_KEY"),
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
}

# MISP is multi-instance: any number of servers can be defined via MISP_<N>_*
# env vars (see config.py), each becoming its own entry here at startup, with
# its own display name and its own connected status.
for _inst in MISP_INSTANCES:
    ENGINES[_inst["id"]] = {
        "label": _inst["name"],
        "supports": ["ip", "domain", "url", "hash"],
        "key": None,
        "name": _inst["name"],
        "connected": bool(_inst["url"]) and bool(_inst["key"]),
    }

INDICATOR_TYPES = ("ip", "domain", "url", "hash", "asn", "threat-actor")
