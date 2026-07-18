import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent.parent / ".env", override=True)


def get(key: str) -> str:
    return os.environ.get(key, "")


ABUSEIPDB_API_KEY: str = get("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY: str = get("VIRUSTOTAL_API_KEY")
ABUSECH_API_KEY: str = get("ABUSECH_API_KEY")
ALIENVAULT_API_KEY: str = get("ALIENVAULT_API_KEY")
IPINFO_API_KEY: str = get("IPINFO_API_KEY")
SHODAN_API_KEY: str = get("SHODAN_API_KEY")
