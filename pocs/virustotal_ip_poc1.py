import sys
import json
import httpx
from pathlib import Path
from dotenv import dotenv_values

KEYS = dotenv_values(Path(__file__).parent / "keys.env")
API_KEY = KEYS.get("VIRUSTOTAL_API_KEY", "")

if len(sys.argv) != 2:
    print("Usage: python virustotal_ip_poc1.py <ip>")
    sys.exit(1)

ip = sys.argv[1]
r = httpx.get(
    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
    headers={"x-apikey": API_KEY},
    timeout=15,
)

print(json.dumps(r.json(), indent=2))
