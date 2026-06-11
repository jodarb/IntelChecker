import httpx
from app.core.config import ABUSEIPDB_API_KEY


async def check_ip(ip: str) -> dict:
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
        )
        return r.json()
