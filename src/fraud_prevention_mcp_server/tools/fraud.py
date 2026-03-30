"""
Fraud Prevention Tools — Kernlogik.

Nutzt IPQualityScore und HaveIBeenPwned fuer Echtzeit-Betrugs-Analyse.
"""

import asyncio
from datetime import datetime, timezone

from fraud_prevention_mcp_server.clients.hibp import check_email_breaches
from fraud_prevention_mcp_server.clients.ipqs import (
    check_email,
    check_ip,
    check_phone,
    check_url,
)


def check_ip_reputation(ip_address: str, strictness: int = 1) -> dict:
    """IP-Adresse auf Fraud, Proxy, VPN und Tor pruefen."""
    try:
        result = asyncio.run(check_ip(ip_address, strictness))

        if "error" in result:
            return result

        # Risiko-Level berechnen
        fraud_score = result.get("fraud_score", 0)
        risk_level = _score_to_risk(fraud_score)

        return {
            "ip": ip_address,
            "fraud_score": fraud_score,
            "risk_level": risk_level,
            "is_proxy": result.get("proxy", False),
            "is_vpn": result.get("vpn", False),
            "is_tor": result.get("tor", False),
            "is_bot": result.get("bot_status", False),
            "country_code": result.get("country_code"),
            "city": result.get("city"),
            "isp": result.get("ISP"),
            "connection_type": result.get("connection_type"),
            "recent_abuse": result.get("recent_abuse", False),
            "recommendation": _ip_recommendation(result),
            "raw": result,
        }
    except Exception as e:
        return {"error": str(e), "ip": ip_address}


def check_email_risk(email: str, strictness: int = 1) -> dict:
    """E-Mail-Adresse auf Fraud, Disposable-Dienste und Aktivitaet pruefen."""
    try:
        result = asyncio.run(check_email(email, strictness))

        if "error" in result:
            return result

        fraud_score = result.get("fraud_score", 0)
        risk_level = _score_to_risk(fraud_score)

        return {
            "email": email,
            "fraud_score": fraud_score,
            "risk_level": risk_level,
            "valid": result.get("valid", False),
            "disposable": result.get("disposable", False),
            "spam_trap": result.get("spam_trap_score", 0) > 0.5,
            "recent_abuse": result.get("recent_abuse", False),
            "deliverability": result.get("deliverability"),
            "domain_age_days": result.get("domain_age", {}).get("human"),
            "first_seen": result.get("first_seen", {}).get("human"),
            "leaked": result.get("leaked", False),
            "recommendation": _email_recommendation(result),
            "raw": result,
        }
    except Exception as e:
        return {"error": str(e), "email": email}


def check_url_safety(url: str, strictness: int = 1) -> dict:
    """URL auf Phishing, Malware und Spam pruefen."""
    try:
        result = asyncio.run(check_url(url, strictness))

        if "error" in result:
            return result

        risk_score = result.get("risk_score", 0)
        risk_level = _score_to_risk(risk_score)

        return {
            "url": url,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "unsafe": result.get("unsafe", False),
            "phishing": result.get("phishing", False),
            "malware": result.get("malware", False),
            "spam": result.get("spamming", False),
            "domain": result.get("domain"),
            "ip_address": result.get("ip_address"),
            "country_code": result.get("country_code"),
            "category": result.get("category"),
            "recommendation": _url_recommendation(result),
            "raw": result,
        }
    except Exception as e:
        return {"error": str(e), "url": url}


def check_phone_risk(phone: str, country: str = "US") -> dict:
    """Telefonnummer auf Gueltigkeit, VoIP und Fraud-Risiko pruefen."""
    try:
        result = asyncio.run(check_phone(phone, country))

        if "error" in result:
            return result

        fraud_score = result.get("fraud_score", 0)
        risk_level = _score_to_risk(fraud_score)

        return {
            "phone": phone,
            "fraud_score": fraud_score,
            "risk_level": risk_level,
            "valid": result.get("valid", False),
            "active": result.get("active", False),
            "line_type": result.get("line_type"),
            "is_voip": result.get("VOIP", False),
            "is_prepaid": result.get("prepaid", False),
            "risky": result.get("risky", False),
            "recent_abuse": result.get("recent_abuse", False),
            "carrier": result.get("carrier"),
            "country": result.get("country"),
            "region": result.get("region"),
            "recommendation": _phone_recommendation(result),
            "raw": result,
        }
    except Exception as e:
        return {"error": str(e), "phone": phone}


def check_breach_exposure(email: str) -> dict:
    """Prueft ob eine E-Mail-Adresse in bekannten Datenpannen exponiert wurde."""
    try:
        result = asyncio.run(check_email_breaches(email))

        if "warning" in result or "error" in result:
            return result

        # Risiko-Einstufung basierend auf Breach-Anzahl
        breach_count = result.get("breach_count", 0)
        if breach_count == 0:
            risk_level = "low"
            summary = "Email not found in any known data breaches."
        elif breach_count <= 2:
            risk_level = "medium"
            summary = f"Email found in {breach_count} known data breach(es). Consider changing passwords."
        elif breach_count <= 5:
            risk_level = "high"
            summary = f"Email found in {breach_count} known data breaches. High risk — change passwords and enable 2FA."
        else:
            risk_level = "critical"
            summary = f"Email found in {breach_count} known data breaches. Critical exposure — immediate action required."

        # Datenkategorien aus allen Breaches sammeln
        all_data_classes = set()
        for b in result.get("breaches", []):
            all_data_classes.update(b.get("data_classes", []))

        has_passwords = "Passwords" in all_data_classes
        has_credit_cards = "Credit cards" in all_data_classes

        return {
            "email": email,
            "found_in_breaches": result.get("found_in_breaches", False),
            "breach_count": breach_count,
            "risk_level": risk_level,
            "has_password_exposure": has_passwords,
            "has_credit_card_exposure": has_credit_cards,
            "exposed_data_types": sorted(all_data_classes),
            "summary": summary,
            "breaches": result.get("breaches", []),
        }
    except Exception as e:
        return {"error": str(e), "email": email}


def calculate_composite_risk(
    ip: str = "",
    email: str = "",
    phone: str = "",
    url: str = "",
) -> dict:
    """
    Kombinierter Fraud-Risk-Score aus mehreren Signalen.

    Analysiert IP, E-Mail, Telefon und URL gleichzeitig und gibt
    einen konsolidierten Risiko-Score und Handlungsempfehlung.
    """
    if not any([ip, email, phone, url]):
        return {"error": "Provide at least one of: ip, email, phone, url"}

    signals = {}
    total_score = 0
    signal_count = 0

    # IP-Check
    if ip:
        ip_result = check_ip_reputation(ip)
        if "error" not in ip_result:
            signals["ip"] = {
                "value": ip,
                "fraud_score": ip_result.get("fraud_score", 0),
                "risk_level": ip_result.get("risk_level"),
                "flags": [
                    flag
                    for flag in ["is_proxy", "is_vpn", "is_tor", "is_bot", "recent_abuse"]
                    if ip_result.get(flag)
                ],
            }
            total_score += ip_result.get("fraud_score", 0)
            signal_count += 1

    # E-Mail-Check
    if email:
        email_result = check_email_risk(email)
        if "error" not in email_result:
            signals["email"] = {
                "value": email,
                "fraud_score": email_result.get("fraud_score", 0),
                "risk_level": email_result.get("risk_level"),
                "flags": [
                    flag
                    for flag in ["disposable", "spam_trap", "recent_abuse", "leaked"]
                    if email_result.get(flag)
                ],
            }
            total_score += email_result.get("fraud_score", 0)
            signal_count += 1

    # Telefon-Check
    if phone:
        phone_result = check_phone_risk(phone)
        if "error" not in phone_result:
            signals["phone"] = {
                "value": phone,
                "fraud_score": phone_result.get("fraud_score", 0),
                "risk_level": phone_result.get("risk_level"),
                "flags": [
                    flag
                    for flag in ["is_voip", "is_prepaid", "risky", "recent_abuse"]
                    if phone_result.get(flag)
                ],
            }
            total_score += phone_result.get("fraud_score", 0)
            signal_count += 1

    # URL-Check
    if url:
        url_result = check_url_safety(url)
        if "error" not in url_result:
            signals["url"] = {
                "value": url,
                "risk_score": url_result.get("risk_score", 0),
                "risk_level": url_result.get("risk_level"),
                "flags": [
                    flag
                    for flag in ["unsafe", "phishing", "malware", "spam"]
                    if url_result.get(flag)
                ],
            }
            total_score += url_result.get("risk_score", 0)
            signal_count += 1

    if signal_count == 0:
        return {"error": "All checks failed. Check API keys."}

    # Durchschnittlicher Composite-Score
    composite_score = round(total_score / signal_count, 1)
    composite_risk = _score_to_risk(composite_score)

    # Alle Flags sammeln
    all_flags = []
    for sig in signals.values():
        all_flags.extend(sig.get("flags", []))

    # Entscheidung
    if composite_score >= 85 or len(all_flags) >= 3:
        decision = "BLOCK"
        action = "High fraud risk detected. Block this transaction/user."
    elif composite_score >= 60 or len(all_flags) >= 2:
        decision = "REVIEW"
        action = "Elevated risk. Manual review or additional verification recommended."
    elif composite_score >= 30:
        decision = "MONITOR"
        action = "Moderate risk. Allow but monitor for suspicious patterns."
    else:
        decision = "ALLOW"
        action = "Low risk. No significant fraud indicators detected."

    return {
        "composite_risk_score": composite_score,
        "composite_risk_level": composite_risk,
        "decision": decision,
        "action": action,
        "signal_count": signal_count,
        "active_flags": list(set(all_flags)),
        "signals": signals,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def get_fraud_prevention_info() -> dict:
    """Gibt Informationen ueber den Server, verfuegbare Tools und API-Key-Setup zurueck."""
    import os

    ipqs_configured = bool(os.getenv("IPQS_API_KEY"))
    hibp_configured = bool(os.getenv("HIBP_API_KEY"))

    return {
        "server": "fraud-prevention-mcp-server",
        "version": "0.1.0",
        "description": "Open-source MCP server for fraud prevention using free APIs",
        "tools": [
            "check_ip_reputation — IP fraud, proxy, VPN, Tor detection",
            "check_email_risk — Email fraud score, disposable, spam trap",
            "check_url_safety — URL phishing, malware, spam detection",
            "check_phone_risk — Phone validation, VoIP, fraud score",
            "check_breach_exposure — HaveIBeenPwned breach check",
            "calculate_composite_risk — Multi-signal combined risk score",
        ],
        "api_keys_configured": {
            "IPQS_API_KEY": ipqs_configured,
            "HIBP_API_KEY": hibp_configured,
        },
        "setup": {
            "ipqualityscore": "Free key at https://www.ipqualityscore.com/create-account (5000 req/month)",
            "haveibeenpwned": "Key at https://haveibeenpwned.com/API/Key",
        },
        "data_sources": ["IPQualityScore", "HaveIBeenPwned"],
    }


# --- Hilfsfunktionen ---

def _score_to_risk(score: float) -> str:
    """Konvertiert einen numerischen Score (0-100) in ein Risiko-Level."""
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _ip_recommendation(data: dict) -> str:
    """Gibt eine Empfehlung basierend auf den IP-Daten zurueck."""
    score = data.get("fraud_score", 0)
    flags = []
    if data.get("proxy"):
        flags.append("proxy")
    if data.get("vpn"):
        flags.append("VPN")
    if data.get("tor"):
        flags.append("Tor")
    if data.get("bot_status"):
        flags.append("bot")

    if score >= 85 or "Tor" in flags:
        return "BLOCK — High fraud risk."
    if score >= 60 or flags:
        return f"REVIEW — Suspicious: {', '.join(flags) if flags else 'elevated score'}."
    return "ALLOW — No significant fraud indicators."


def _email_recommendation(data: dict) -> str:
    """Gibt eine Empfehlung basierend auf den E-Mail-Daten zurueck."""
    if not data.get("valid"):
        return "REJECT — Invalid email address."
    if data.get("disposable"):
        return "BLOCK — Disposable email service detected."
    if data.get("fraud_score", 0) >= 75:
        return "BLOCK — High fraud score."
    if data.get("spam_trap_score", 0) > 0.5:
        return "REVIEW — Potential spam trap."
    return "ALLOW — Email appears legitimate."


def _url_recommendation(data: dict) -> str:
    """Gibt eine Empfehlung basierend auf den URL-Daten zurueck."""
    if data.get("phishing"):
        return "BLOCK — Phishing site detected."
    if data.get("malware"):
        return "BLOCK — Malware distribution site."
    if data.get("unsafe"):
        return "BLOCK — Unsafe URL."
    if data.get("risk_score", 0) >= 75:
        return "BLOCK — High risk score."
    return "ALLOW — URL appears safe."


def _phone_recommendation(data: dict) -> str:
    """Gibt eine Empfehlung basierend auf den Telefon-Daten zurueck."""
    if not data.get("valid"):
        return "REJECT — Invalid phone number."
    if data.get("fraud_score", 0) >= 85:
        return "BLOCK — High fraud score."
    if data.get("VOIP") and data.get("risky"):
        return "REVIEW — Risky VoIP number."
    return "ALLOW — Phone appears legitimate."
