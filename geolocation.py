import ipaddress
import requests

IP_DISCLAIMER = "IP geolocation represents approximate network infrastructure location and does not identify the attacker's exact physical location."

# Pre-cached fallback IP database for hackathon demonstration
MOCK_IP_GEO_DATABASE = {
    "185.220.101.5": {
        "ip": "185.220.101.5",
        "country": "Germany",
        "country_code": "DE",
        "region": "Bavaria",
        "city": "Munich",
        "latitude": 48.1371,
        "longitude": 11.5754,
        "isp": "Tor Exit Node Network / Host Europe",
        "asn": "AS208323",
        "reputation_score": "High Risk (Tor / Malicious Relay)"
        ,"source": "DEMO / SAMPLE GEOLOCATION CACHE"
    },
    "193.109.112.44": {
        "ip": "193.109.112.44",
        "country": "Netherlands",
        "country_code": "NL",
        "region": "North Holland",
        "city": "Amsterdam",
        "latitude": 52.3676,
        "longitude": 4.9041,
        "isp": "Verio Europe VPS Services",
        "asn": "AS1103",
        "reputation_score": "Suspicious (Bulletproof VPS)"
        ,"source": "DEMO / SAMPLE GEOLOCATION CACHE"
    },
    "194.26.29.11": {
        "ip": "194.26.29.11",
        "country": "Czechia",
        "country_code": "CZ",
        "region": "Prague",
        "city": "Prague",
        "latitude": 50.0755,
        "longitude": 14.4378,
        "isp": "Czech Telecom Transit",
        "asn": "AS28725",
        "reputation_score": "Neutral"
        ,"source": "DEMO / SAMPLE GEOLOCATION CACHE"
    }
}

def is_private_ip(ip_str):
    if not ip_str or ip_str in ["N/A", "Unknown", "127.0.0.1", "localhost"]:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
    except ValueError:
        return True

def get_ip_geolocation(ip_address):
    if not ip_address or is_private_ip(ip_address):
        return {
            "ip": ip_address or "Internal",
            "country": "Internal Network",
            "country_code": "INT",
            "region": "Private LAN",
            "city": "Local Subnet",
            "latitude": 0.0,
            "longitude": 0.0,
            "isp": "Internal Mail Infrastructure",
            "asn": "N/A (Private)",
            "is_private": True,
            "reputation_score": "Trusted Local",
            "source": "LOCAL NETWORK METADATA",
            "disclaimer": IP_DISCLAIMER
        }

    # Check pre-cached mock DB first for instant fast response during hackathon
    if ip_address in MOCK_IP_GEO_DATABASE:
        res = MOCK_IP_GEO_DATABASE[ip_address].copy()
        res["is_private"] = False
        res["disclaimer"] = IP_DISCLAIMER
        return res

    # Try live lookup via ip-api.com with 2s timeout
    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,as,query"
        resp = requests.get(url, timeout=2.0)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'success':
                return {
                    "ip": ip_address,
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "UN"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "latitude": data.get("lat", 0.0),
                    "longitude": data.get("lon", 0.0),
                    "isp": data.get("isp", "Unknown ISP"),
                    "asn": data.get("as", "N/A"),
                    "is_private": False,
                    "reputation_score": "External IP",
                    "source": "LIVE LOOKUP: ip-api.com",
                    "disclaimer": IP_DISCLAIMER
                }
    except Exception:
        pass

    # Fallback default when external lookup is unavailable
    return {
        "ip": ip_address,
        "country": "External Location",
        "country_code": "EXT",
        "region": "Remote Region",
        "city": "Unknown City",
        "latitude": 30.0,
        "longitude": 10.0,
        "isp": "Intelligence unavailable — external lookup required.",
        "asn": "External Lookup Required",
        "is_private": False,
        "reputation_score": "Unknown",
        "source": "UNKNOWN - EXTERNAL LOOKUP UNAVAILABLE",
        "disclaimer": IP_DISCLAIMER
    }
