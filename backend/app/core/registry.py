ENGINES: dict[str, dict] = {
    "abuseipdb":  {"supports": ["ip"],                          "key": "ABUSEIPDB_API_KEY"},
    "virustotal": {"supports": ["ip", "domain", "url", "hash"], "key": "VIRUSTOTAL_API_KEY"},
    "abusech":    {"supports": ["ip", "hash"],                  "key": "ABUSECH_API_KEY"},
    "alienvault": {"supports": ["ip", "domain", "url", "hash"], "key": "ALIENVAULT_API_KEY"},
    "ipinfo":     {"supports": ["ip"],                          "key": "IPINFO_API_KEY"},
}
