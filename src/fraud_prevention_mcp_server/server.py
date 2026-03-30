"""
Fraud Prevention MCP Server.

Open-source MCP-Server fuer Betrugs-Praevention via freie APIs.
Nutzt IPQualityScore (IP, E-Mail, URL, Telefon) und HaveIBeenPwned (Breach-Check).
"""

from mcp.server.fastmcp import FastMCP

from fraud_prevention_mcp_server.tools.fraud import (
    calculate_composite_risk,
    check_breach_exposure,
    check_email_risk,
    check_ip_reputation,
    check_phone_risk,
    check_url_safety,
    get_fraud_prevention_info,
)

# MCP-Server initialisieren
mcp = FastMCP(
    "fraud-prevention-mcp-server",
    instructions=(
        "Open-source MCP server for fraud prevention. "
        "Provides IP reputation, email risk scoring, URL safety, phone validation, "
        "data breach exposure checks, and composite multi-signal risk analysis. "
        "Uses IPQualityScore (free API key required) and HaveIBeenPwned. "
        "Tools: check_ip_reputation, check_email_risk, check_url_safety, "
        "check_phone_risk, check_breach_exposure, calculate_composite_risk, get_fraud_prevention_info."
    ),
)


@mcp.tool()
def tool_check_ip_reputation(ip_address: str, strictness: int = 1) -> dict:
    """
    Check an IP address for fraud risk, proxy, VPN, Tor and bot activity.

    Returns fraud score (0-100), risk level, and flags for proxy/VPN/Tor/bot.
    Requires IPQS_API_KEY env var (free at ipqualityscore.com).

    Args:
        ip_address: IPv4 or IPv6 address to check
        strictness: Detection strictness 0 (lenient) to 3 (strict), default 1
    """
    return check_ip_reputation(ip_address, strictness)


@mcp.tool()
def tool_check_email_risk(email: str, strictness: int = 1) -> dict:
    """
    Check an email address for fraud risk, disposable services and spam traps.

    Returns fraud score, validity, disposable flag, spam trap detection, and deliverability.
    Requires IPQS_API_KEY env var (free at ipqualityscore.com).

    Args:
        email: Email address to validate and check
        strictness: Detection strictness 0-3, default 1
    """
    return check_email_risk(email, strictness)


@mcp.tool()
def tool_check_url_safety(url: str, strictness: int = 1) -> dict:
    """
    Check a URL for phishing, malware, spam and other threats.

    Returns risk score, safety flags (phishing/malware/spam), and domain info.
    Requires IPQS_API_KEY env var (free at ipqualityscore.com).

    Args:
        url: Full URL to check (include https://)
        strictness: Detection strictness 0-3, default 1
    """
    return check_url_safety(url, strictness)


@mcp.tool()
def tool_check_phone_risk(phone: str, country: str = "US") -> dict:
    """
    Validate a phone number and check for fraud risk, VoIP and prepaid indicators.

    Returns validity, line type, carrier, VoIP flag, and fraud score.
    Requires IPQS_API_KEY env var (free at ipqualityscore.com).

    Args:
        phone: Phone number in E.164 format (e.g. +14155552671) or local format
        country: ISO country code for local numbers (default: US)
    """
    return check_phone_risk(phone, country)


@mcp.tool()
def tool_check_breach_exposure(email: str) -> dict:
    """
    Check if an email address has been exposed in known data breaches (HaveIBeenPwned).

    Returns breach count, risk level, exposed data types, and breach details.
    Requires HIBP_API_KEY env var (get key at haveibeenpwned.com/API/Key).

    Args:
        email: Email address to check for breach exposure
    """
    return check_breach_exposure(email)


@mcp.tool()
def tool_calculate_composite_risk(
    ip: str = "",
    email: str = "",
    phone: str = "",
    url: str = "",
) -> dict:
    """
    Calculate a combined fraud risk score from multiple signals (IP, email, phone, URL).

    Analyzes all provided signals and returns a composite risk score with
    ALLOW / MONITOR / REVIEW / BLOCK decision. Provide at least one signal.
    Requires IPQS_API_KEY env var.

    Args:
        ip: IP address to check (optional)
        email: Email address to check (optional)
        phone: Phone number to check (optional)
        url: URL to check (optional)
    """
    return calculate_composite_risk(ip=ip, email=email, phone=phone, url=url)


@mcp.tool()
def tool_get_fraud_prevention_info() -> dict:
    """
    Get information about this server, available tools and API key setup instructions.

    Returns tool list, API key configuration status, and links to get free API keys.
    """
    return get_fraud_prevention_info()


def main():
    """Startet den MCP-Server ueber stdio-Transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
