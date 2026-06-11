import sys
import json
import httpx
from pathlib import Path
from dotenv import dotenv_values

KEYS = dotenv_values(Path(__file__).parent / "keys.env")
API_KEY = KEYS.get("ABUSEIPDB_API_KEY", "")

if len(sys.argv) != 2:
    print("Usage: python abuseipdb_ip_poc1.py <ip>")
    sys.exit(1)

ip = sys.argv[1]
r = httpx.get(
    "https://api.abuseipdb.com/api/v2/check",
    headers={"Key": API_KEY, "Accept": "application/json"},
    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
    timeout=15,
)

print(json.dumps(r.json(), indent=2))
