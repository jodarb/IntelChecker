from app.core.config import MISP_INSTANCES

ENGINES: dict[str, dict] = {
    "abuseipdb":  {"supports": ["ip"],                          "key": "ABUSEIPDB_API_KEY"},
    "virustotal": {"supports": ["ip", "domain", "url", "hash"], "key": "VIRUSTOTAL_API_KEY"},
    "abusech":    {"supports": ["ip", "hash"],                  "key": "ABUSECH_AUTH_KEY"},
    "urlhaus":    {"supports": ["ip", "domain", "url", "hash"], "key": "ABUSECH_AUTH_KEY"},
    "alienvault": {"supports": ["ip", "domain", "url", "hash", "threat-actor"], "key": "ALIENVAULT_API_KEY"},
    "ipinfo":     {"supports": ["ip"],                          "key": "IPINFO_API_KEY"},
    "shodan":     {"supports": ["ip", "asn"],                   "key": "SHODAN_API_KEY"},
    "torexitlist": {"supports": ["ip"],                         "key": None},
    "mitreattack": {"supports": ["threat-actor"],                "key": None},
    "ripestat":    {"supports": ["ip", "asn"],                   "key": None},
    "urlscan":     {"supports": ["url", "domain"],                "key": "URLSCAN_API_KEY"},
    "malwarebazaar": {"supports": ["hash"],                       "key": "ABUSECH_AUTH_KEY"},
    "phishtank":   {"supports": ["url"],                          "key": None},
    "recordedfuture": {"supports": ["ip", "domain", "url", "hash"], "key": "RECORDED_FUTURE_API_KEY"},
    "anyrun":      {"supports": ["ip", "domain", "url", "hash"],   "key": "ANYRUN_API_KEY"},
    "greynoise":   {"supports": ["ip"],                            "key": "GREYNOISE_API_KEY"},
    "hybridanalysis": {"supports": ["ip", "domain", "url", "hash"], "key": "HYBRID_ANALYSIS_API_KEY"},
    "safebrowsing": {"supports": ["url"],                          "key": "GOOGLE_SAFE_BROWSING_API_KEY"},
    "tweetfeed":   {"supports": ["ip", "domain", "url", "hash"],   "key": None},
}

# MISP is multi-instance: any number of servers can be defined via MISP_<N>_*
# env vars (see config.py), each becoming its own entry here at startup, with
# its own display name and its own connected status.
for _inst in MISP_INSTANCES:
    ENGINES[_inst["id"]] = {
        "supports": ["ip", "domain", "url", "hash"],
        "key": None,
        "name": _inst["name"],
        "connected": bool(_inst["url"]) and bool(_inst["key"]),
    }
