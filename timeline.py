from services.geolocation import get_ip_geolocation

def build_forensic_timeline(received_hops):
    if not received_hops:
        return []

    timeline_events = []
    
    for idx, hop in enumerate(received_hops, start=1):
        ip_addr = hop.get("ip_address", "N/A")
        geo_info = get_ip_geolocation(ip_addr)
        
        server_from = hop.get("server_from", "Unknown")
        server_by = hop.get("server_by", "Mail Gateway")
        timestamp_str = hop.get("timestamp_str", "N/A")
        
        flags = []
        if geo_info.get("reputation_score") and "Tor" in geo_info.get("reputation_score"):
            flags.append("High Risk: Tor Proxy IP")
        if geo_info.get("reputation_score") and "Suspicious" in geo_info.get("reputation_score"):
            flags.append("Suspicious VPS Relay")
        if idx == 1:
            flags.append("Originating Mail Server")
        elif idx == len(received_hops):
            flags.append("Destination Mail Gateway")

        timeline_events.append({
            "hop_index": idx,
            "server_from": server_from,
            "server_by": server_by,
            "ip_address": ip_addr,
            "location": f"{geo_info.get('city')}, {geo_info.get('country')}",
            "isp": geo_info.get('isp'),
            "timestamp_str": timestamp_str,
            "delay_sec": (idx - 1) * 3,  # Synthesize 3s latency per hop if timestamp delta is unparseable
            "flags": flags,
            "raw_header": hop.get("raw_header", "")
        })

    return timeline_events

def build_forensic_investigation_workflow(case_id="ST-1024", timestamp_str="Recent", threat_type="Phishing"):
    return [
        {"step": 1, "title": "Email received", "desc": "Inbound message ingested into SOC gateway sandbox", "icon": "bi-envelope-download"},
        {"step": 2, "title": "Header extracted", "desc": "Parsed RFC822 headers, From/Reply-To addresses, and received hops", "icon": "bi-code-square"},
        {"step": 3, "title": "Indicators identified", "desc": "Extracted IP addresses, domain names, target URLs, and attachments", "icon": "bi-search"},
        {"step": 4, "title": "AI analysis completed", "desc": "Heuristic & NLP threat engine computed risk score and confidence metrics", "icon": "bi-cpu-fill"},
        {"step": 5, "title": "Threat detected", "desc": f"Classified threat type as '{threat_type.upper()}' with risk indicators", "icon": "bi-exclamation-triangle-fill"},
        {"step": 6, "title": "Alert generated", "desc": "Triggered high-priority SOC alert in analyst queue", "icon": "bi-bell-fill"},
        {"step": 7, "title": "Forensic case created", "desc": f"Opened official case #{case_id} for correlation and PDF reporting", "icon": "bi-folder-check"}
    ]

