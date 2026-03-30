"""
IPQualityScore API-Client.

Bietet IP-Reputation, E-Mail-Validierung, URL-Sicherheit und Telefon-Checks.
Kostenloser Tier: 5.000 Anfragen/Monat (API-Key erforderlich).
Registrierung: https://www.ipqualityscore.com/create-account
"""

import os
import httpx

# API-Key aus Umgebungsvariable
IPQS_KEY = os.getenv("IPQS_API_KEY", "")
BASE_URL = "https://ipqualityscore.com/api/json"


async def check_ip(ip_address: str, strictness: int = 1) -> dict:
    """Prueft IP-Adresse auf Fraud, Proxy, VPN, Tor."""
    if not IPQS_KEY:
        return {"error": "IPQS_API_KEY not set. Get a free key at ipqualityscore.com"}

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{BASE_URL}/ip/{IPQS_KEY}/{ip_address}",
            params={"strictness": strictness, "allow_public_access_points": "true"},
        )
        resp.raise_for_status()
        return resp.json()


async def check_email(email: str, strictness: int = 1) -> dict:
    """Prueft E-Mail auf Fraud, Disposable, Typos, Aktivitaet."""
    if not IPQS_KEY:
        return {"error": "IPQS_API_KEY not set. Get a free key at ipqualityscore.com"}

    import urllib.parse
    encoded_email = urllib.parse.quote(email, safe="")

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{BASE_URL}/email/{IPQS_KEY}/{encoded_email}",
            params={"strictness": strictness},
        )
        resp.raise_for_status()
        return resp.json()


async def check_url(url: str, strictness: int = 1) -> dict:
    """Prueft URL auf Phishing, Malware, Spam."""
    if not IPQS_KEY:
        return {"error": "IPQS_API_KEY not set. Get a free key at ipqualityscore.com"}

    import urllib.parse
    encoded_url = urllib.parse.quote(url, safe="")

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{BASE_URL}/url/{IPQS_KEY}/{encoded_url}",
            params={"strictness": strictness},
        )
        resp.raise_for_status()
        return resp.json()


async def check_phone(phone: str, country: str = "US") -> dict:
    """Prueft Telefonnummer auf Gueltigkeit und Fraud-Risiko."""
    if not IPQS_KEY:
        return {"error": "IPQS_API_KEY not set. Get a free key at ipqualityscore.com"}

    import urllib.parse
    encoded_phone = urllib.parse.quote(phone, safe="")

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{BASE_URL}/phone/{IPQS_KEY}/{encoded_phone}",
            params={"country[]": country},
        )
        resp.raise_for_status()
        return resp.json()
