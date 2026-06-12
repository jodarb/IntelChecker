ENGINES: dict[str, dict] = {
    "abuseipdb":  {"supports": ["ip"]},
    "virustotal": {"supports": ["ip", "domain", "url", "hash"]},
    "abusech":    {"supports": ["ip", "hash"]},
    "alienvault": {"supports": ["ip", "domain", "url", "hash"]},
    "ipinfo":     {"supports": ["ip"]},
}
