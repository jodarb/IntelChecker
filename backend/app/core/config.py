from pathlib import Path
from dotenv import dotenv_values

_env = dotenv_values(Path(__file__).parent.parent.parent / ".env")

ABUSEIPDB_API_KEY: str = _env.get("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY: str = _env.get("VIRUSTOTAL_API_KEY", "")
ABUSECH_API_KEY: str = _env.get("ABUSECH_API_KEY", "")
ALIENVAULT_API_KEY: str = _env.get("ALIENVAULT_API_KEY", "")
IPINFO_API_KEY: str = _env.get("IPINFO_API_KEY", "")
