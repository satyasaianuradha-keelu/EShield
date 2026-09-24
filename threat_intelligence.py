import os
import requests

VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

def get_ip_intelligence(ip_address):
    if not ip_address or ip_address == "N/A":
        return {"error": "Invalid IP address provided."}

    # Demo intelligence cache
    if ip_address == "185.220.101.5":
        return {
            "type": "IP Intelligence",
            "query": ip_address,
            "reputation": "MALICIOUS",
            "risk_score": 95,
            "country": "Germany",
            "city": "Munich",
            "isp": "Tor Exit Node Network",
            "asn": "AS208323",
            "blacklists_flagged": "14 / 88 security vendors",
            "categories": ["Tor Proxy", "Phishing Host", "Spam Relay"],
            "source": "ThreatIntel Synthetic Cache"
        }
    elif ip_address == "193.109.112.44":
        return {
            "type": "IP Intelligence",
            "query": ip_address,
            "reputation": "SUSPICIOUS",
            "risk_score": 72,
            "country": "Netherlands",
            "city": "Amsterdam",
            "isp": "Verio Europe VPS",
            "asn": "AS1103",
            "blacklists_flagged": "6 / 88 security vendors",
            "categories": ["Bulletproof VPS", "Unverified Mail Relay"],
            "source": "ThreatIntel Synthetic Cache"
        }

    return {
        "type": "IP Intelligence",
        "query": ip_address,
        "reputation": "UNCHECKED",
        "risk_score": 0,
        "country": "External",
        "city": "External",
        "isp": "Intelligence unavailable — external lookup required.",
        "asn": "N/A",
        "blacklists_flagged": "0 / 88",
        "categories": ["External Lookup Required"],
        "source": "No API key configured (VT_API_KEY or ABUSEIPDB_API_KEY needed in .env)"
    }

def get_domain_intelligence(domain_name):
    if not domain_name:
        return {"error": "Invalid domain name."}

    if "mail-auth-verify.xyz" in domain_name or "paypal-verification" in domain_name:
        return {
            "type": "Domain Intelligence",
            "query": domain_name,
            "reputation": "MALICIOUS",
            "risk_score": 96,
            "registrar": "NameCheap CheapTLDs Inc.",
            "created_date": "2026-09-21 (2 days old)",
            "expiration_date": "2027-09-21",
            "dnssec": "Disabled",
            "threat_category": "Phishing / Credential Harvester",
            "source": "ThreatIntel Synthetic Cache"
        }
    elif "executive-mail.org" in domain_name:
        return {
            "type": "Domain Intelligence",
            "query": domain_name,
            "reputation": "SUSPICIOUS",
            "risk_score": 75,
            "registrar": "Tucows Domains Inc.",
            "created_date": "2026-08-14 (1 month old)",
            "expiration_date": "2027-08-14",
            "dnssec": "Disabled",
            "threat_category": "Lookalike Domain / BEC",
            "source": "ThreatIntel Synthetic Cache"
        }

    return {
        "type": "Domain Intelligence",
        "query": domain_name,
        "reputation": "UNCHECKED",
        "risk_score": 0,
        "registrar": "Intelligence unavailable — external lookup required.",
        "created_date": "Unknown",
        "expiration_date": "Unknown",
        "dnssec": "Unknown",
        "threat_category": "External Lookup Required",
        "source": "No API key configured"
    }

def get_url_intelligence(url_str):
    if not url_str:
        return {"error": "Invalid URL."}

    if "paypal-verification-security-portal" in url_str:
        return {
            "type": "URL Intelligence",
            "query": url_str,
            "reputation": "MALICIOUS",
            "risk_score": 98,
            "target_brand": "PayPal",
            "redirects": ["http://paypal-verification-security-portal.com.xyz/login/verify.php -> http://185.220.101.5/harvest.php"],
            "ssl_valid": False,
            "threat_classification": "Active Credential Harvesting Form",
            "source": "ThreatIntel Synthetic Cache"
        }

    return {
        "type": "URL Intelligence",
        "query": url_str,
        "reputation": "UNCHECKED",
        "risk_score": 0,
        "target_brand": "Unknown",
        "redirects": ["Intelligence unavailable — external lookup required."],
        "ssl_valid": False,
        "threat_classification": "External Lookup Required",
        "source": "No API key configured"
    }
