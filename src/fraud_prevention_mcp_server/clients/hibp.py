"""
HaveIBeenPwned API-Client.

Prueft ob E-Mail-Adressen in bekannten Datenpannen aufgetaucht sind.
Kostenloser API-Key: https://haveibeenpwned.com/API/Key
"""

import os
import httpx

# API-Key aus Umgebungsvariable (optional fuer Breach-Details)
HIBP_KEY = os.getenv("HIBP_API_KEY", "")
BASE_URL = "https://haveibeenpwned.com/api/v3"


async def check_email_breaches(email: str) -> dict:
    """Prueft ob eine E-Mail-Adresse in Datenpannen aufgetaucht ist."""
    headers = {
        "User-Agent": "fraud-prevention-mcp-server/0.1.0",
        "hibp-api-key": HIBP_KEY,
    }

    if not HIBP_KEY:
        # Ohne Key nur Pruefung ob Breach-Daten existieren (eingeschraenkt)
        return {
            "warning": "HIBP_API_KEY not set. Get a free key at haveibeenpwned.com/API/Key",
            "email": email,
        }

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{BASE_URL}/breachedaccount/{email}",
            headers=headers,
            params={"truncateResponse": "false"},
        )

        if resp.status_code == 404:
            # 404 = keine Breaches gefunden (gut!)
            return {
                "email": email,
                "found_in_breaches": False,
                "breach_count": 0,
                "breaches": [],
            }

        resp.raise_for_status()
        breaches = resp.json()

        # Relevante Felder extrahieren
        breach_summary = [
            {
                "name": b.get("Name"),
                "domain": b.get("Domain"),
                "breach_date": b.get("BreachDate"),
                "pwn_count": b.get("PwnCount"),
                "data_classes": b.get("DataClasses", []),
                "is_verified": b.get("IsVerified"),
                "is_sensitive": b.get("IsSensitive"),
            }
            for b in breaches
        ]

        return {
            "email": email,
            "found_in_breaches": True,
            "breach_count": len(breach_summary),
            "breaches": breach_summary,
        }
