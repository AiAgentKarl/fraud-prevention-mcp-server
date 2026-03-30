# fraud-prevention-mcp-server

Open-source MCP server for AI-powered fraud prevention. Detects fraudulent IPs, emails, URLs and phone numbers using free APIs — a fully free alternative to proprietary solutions.

## Features

- **IP Reputation** — Detect proxies, VPNs, Tor exit nodes, bots and abusive IPs
- **Email Risk** — Disposable emails, spam traps, fraud scoring, deliverability
- **URL Safety** — Phishing, malware, spam URL detection
- **Phone Validation** — VoIP detection, line type, fraud scoring
- **Breach Exposure** — HaveIBeenPwned integration for data breach lookups
- **Composite Risk Score** — Multi-signal ALLOW/MONITOR/REVIEW/BLOCK decision

## Tools

| Tool | Description |
|------|-------------|
| `check_ip_reputation` | IP fraud score, proxy/VPN/Tor/bot flags |
| `check_email_risk` | Email validation, disposable, spam trap, fraud score |
| `check_url_safety` | Phishing, malware, spam URL detection |
| `check_phone_risk` | Phone validity, VoIP, fraud score |
| `check_breach_exposure` | Data breach exposure via HaveIBeenPwned |
| `calculate_composite_risk` | Combined multi-signal risk analysis |
| `get_fraud_prevention_info` | Server info and API key setup guide |

## Data Sources

- **[IPQualityScore](https://www.ipqualityscore.com)** — Free tier: 5,000 requests/month. Get free key at [ipqualityscore.com/create-account](https://www.ipqualityscore.com/create-account)
- **[HaveIBeenPwned](https://haveibeenpwned.com)** — Breach database. Get key at [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key)

## Installation

```bash
pip install fraud-prevention-mcp-server
```

## Configuration

Set your free API keys as environment variables:

```bash
export IPQS_API_KEY=your_ipqualityscore_key
export HIBP_API_KEY=your_haveibeenpwned_key
```

## Claude Desktop Integration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "fraud-prevention": {
      "command": "fraud-prevention-mcp-server",
      "env": {
        "IPQS_API_KEY": "your_key_here",
        "HIBP_API_KEY": "your_key_here"
      }
    }
  }
}
```

## Example Usage

```
check_ip_reputation("192.168.1.1")
→ { fraud_score: 15, risk_level: "low", is_proxy: false, is_vpn: false, ... }

check_email_risk("test@tempmail.com")
→ { fraud_score: 85, risk_level: "critical", disposable: true, recommendation: "BLOCK" }

check_breach_exposure("user@example.com")
→ { breach_count: 3, risk_level: "high", has_password_exposure: true, ... }

calculate_composite_risk(ip="1.2.3.4", email="user@example.com")
→ { composite_risk_score: 45, decision: "REVIEW", action: "Manual review recommended" }
```

## Risk Levels

| Score | Level | Recommendation |
|-------|-------|----------------|
| 0–29 | Low | ALLOW |
| 30–59 | Medium | MONITOR |
| 60–84 | High | REVIEW |
| 85–100 | Critical | BLOCK |

## Why This Server?

- **Free** — Uses only free-tier APIs, no enterprise contracts needed
- **Open Source** — MIT license, fully auditable
- **Multi-Signal** — Combines IP, email, URL and phone signals
- **Actionable** — Returns ALLOW/MONITOR/REVIEW/BLOCK decisions

## License

MIT
