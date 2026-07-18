ENGINES: dict[str, dict] = {
    "abuseipdb":  {"supports": ["ip"],                          "key": "ABUSEIPDB_API_KEY"},
    "virustotal": {"supports": ["ip", "domain", "url", "hash"], "key": "VIRUSTOTAL_API_KEY"},
    "abusech":    {"supports": ["ip", "hash"],                  "key": "ABUSECH_AUTH_KEY"},
    "urlhaus":    {"supports": ["ip", "domain", "url", "hash"], "key": "ABUSECH_AUTH_KEY"},
    "alienvault": {"supports": ["ip", "domain", "url", "hash"], "key": "ALIENVAULT_API_KEY"},
    "ipinfo":     {"supports": ["ip"],                          "key": "IPINFO_API_KEY"},
    "shodan":     {"supports": ["ip", "asn"],                   "key": "SHODAN_API_KEY"},
    "torexitlist": {"supports": ["ip"],                         "key": None},
    "mitreattack": {"supports": ["threat-actor"],                "key": None},
}
