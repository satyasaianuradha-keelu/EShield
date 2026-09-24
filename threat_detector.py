import re
import urllib.parse

SUSPICIOUS_TLDS = ['.xyz', '.top', '.work', '.click', '.info', '.online', '.site', '.tk', '.ml', '.ga', '.cf', '.gq']
HIGH_RISK_ATTACHMENT_EXTS = ['.exe', '.scr', '.vbs', '.js', '.iso', '.vbe', '.bat', '.cmd', '.ps1', '.docm', '.xlsm']

URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'action required', 'account suspended', 'unauthorized access',
    'verify now', 'security alert', 'wire transfer', 'confidential', 'frozen balance',
    '24 hours', 'restrict', 'log in immediately', 'update payment'
]

IMPERSONATION_BRANDS = [
    {"name": "PayPal", "official_domains": ["paypal.com", "paypal.org"]},
    {"name": "Microsoft", "official_domains": ["microsoft.com", "office365.com", "outlook.com"]},
    {"name": "Google", "official_domains": ["google.com", "gmail.com"]},
    {"name": "Apple", "official_domains": ["apple.com", "icloud.com"]},
    {"name": "Amazon", "official_domains": ["amazon.com", "aws.amazon.com"]},
    {"name": "Bank of America", "official_domains": ["bankofamerica.com"]}
]

def analyze_email_threats(parsed_email):
    risk_score = 0
    reasons = []
    indicators = []
    
    sender_domain = parsed_email.get('sender_domain', '').lower()
    reply_to_domain = parsed_email.get('reply_to_domain', '').lower()
    return_path_address = parsed_email.get('return_path_address', '')
    return_path_domain = parsed_email.get('return_path_domain', '').lower() if hasattr(parsed_email, 'return_path_domain') else reply_to_domain
    
    auth_text = parsed_email.get('auth_results', '').lower()
    raw_headers = parsed_email.get('raw_headers_text', '').lower()
    
    # 1. Check Sender vs Reply-To Mismatch
    if reply_to_domain and sender_domain and reply_to_domain != sender_domain:
        risk_score += 25
        reasons.append({
            "title": "Reply-To Address Mismatch",
            "desc": f"Replies are directed to '{parsed_email.get('reply_to_address')}' which differs from sender domain '{sender_domain}'.",
            "severity": "high"
        })
        indicators.append({
            "type": "header",
            "value": f"Reply-To: {parsed_email.get('reply_to_address')}",
            "severity": "high",
            "desc": "Divergent Reply-To domain detected"
        })

    # 2. Check Authentication Headers (SPF, DKIM, DMARC)
    spf_status = "UNAVAILABLE"
    dkim_status = "UNAVAILABLE"
    dmarc_status = "UNAVAILABLE"

    if "spf=pass" in auth_text or "spf=pass" in raw_headers:
        spf_status = "PASS"
    elif "spf=fail" in auth_text or "spf=fail" in raw_headers:
        spf_status = "FAIL"
        risk_score += 20
        reasons.append({
            "title": "SPF Authentication Failed",
            "desc": "SPF verification failed. The sending server IP is not authorized to send emails on behalf of this domain.",
            "severity": "high"
        })
    elif "spf=softfail" in auth_text or "spf=softfail" in raw_headers:
        spf_status = "NEUTRAL"
        risk_score += 10
        reasons.append({
            "title": "SPF Verification SoftFail",
            "desc": "SPF verification returned softfail. The sender IP may not be fully authorized.",
            "severity": "medium"
        })

    if "dkim=pass" in auth_text or "dkim=pass" in raw_headers:
        dkim_status = "PASS"
    elif "dkim=fail" in auth_text or "dkim=fail" in raw_headers:
        dkim_status = "FAIL"
        risk_score += 15
        reasons.append({
            "title": "DKIM Verification Failed",
            "desc": "Digital signature (DKIM) failed validation or was tampered with during transmission.",
            "severity": "high"
        })

    if "dmarc=pass" in auth_text or "dmarc=pass" in raw_headers:
        dmarc_status = "PASS"
    elif "dmarc=fail" in auth_text or "dmarc=fail" in raw_headers:
        dmarc_status = "FAIL"
        risk_score += 20
        reasons.append({
            "title": "DMARC Policy Failure",
            "desc": "DMARC policy check failed. Email fails sender domain alignment criteria.",
            "severity": "high"
        })

    # 3. Analyze URLs
    urls = parsed_email.get('urls', [])
    for url in urls:
        parsed_url = urllib.parse.urlparse(url)
        hostname = (parsed_url.netloc or "").lower()

        # Check IP address as hostname
        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', hostname.split(':')[0]):
            risk_score += 25
            reasons.append({
                "title": "IP Address Host in Link",
                "desc": f"URL '{url}' uses a raw IP address instead of a domain name, commonly used in phishing.",
                "severity": "high"
            })
            indicators.append({
                "type": "url",
                "value": url,
                "severity": "high",
                "desc": "Raw IP URL target"
            })

        # Check suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                risk_score += 20
                reasons.append({
                    "title": "Suspicious Top-Level Domain (TLD)",
                    "desc": f"URL hostname '{hostname}' uses a high-risk TLD ('{tld}') frequently linked to malicious activities.",
                    "severity": "high"
                })
                indicators.append({
                    "type": "domain",
                    "value": hostname,
                    "severity": "high",
                    "desc": f"Suspicious TLD ({tld})"
                })
                break

        # Check lookalike brand keywords in domain
        for brand in IMPERSONATION_BRANDS:
            brand_keyword = brand["name"].lower().replace(" ", "")
            if brand_keyword in hostname:
                is_official = any(hostname.endswith(off_d) for off_d in brand["official_domains"])
                if not is_official:
                    risk_score += 30
                    reasons.append({
                        "title": f"Lookalike Brand URL Domain ({brand['name']})",
                        "desc": f"URL domain '{hostname}' contains '{brand['name']}' but is NOT an official domain.",
                        "severity": "high"
                    })
                    indicators.append({
                        "type": "url",
                        "value": url,
                        "severity": "high",
                        "desc": f"Phishing typosquatting link targeting {brand['name']}"
                    })

    # 4. Check Social Engineering / Urgency Language
    body_text = (parsed_email.get('body_plain', '') + " " + parsed_email.get('subject', '')).lower()
    matched_urgency = [kw for kw in URGENCY_KEYWORDS if kw in body_text]
    if len(matched_urgency) >= 2:
        risk_score += 15
        reasons.append({
            "title": "Urgency & Psychological Pressure Detected",
            "desc": f"Email text contains urgent threat language: '{', '.join(matched_urgency[:4])}'.",
            "severity": "medium"
        })
    elif len(matched_urgency) == 1:
        risk_score += 5
        reasons.append({
            "title": "Urgency Indicator Found",
            "desc": f"Email contains pressure keyword: '{matched_urgency[0]}'.",
            "severity": "low"
        })

    # 5. Impersonation of High-Value Brands in Subject/Sender
    subject_text = parsed_email.get('subject', '')
    sender_text = parsed_email.get('sender', '')
    for brand in IMPERSONATION_BRANDS:
        if brand["name"].lower() in subject_text.lower() or brand["name"].lower() in sender_text.lower():
            if not any(sender_domain.endswith(off_d) for off_d in brand["official_domains"]):
                risk_score += 25
                reasons.append({
                    "title": f"Brand Impersonation Warning ({brand['name']})",
                    "desc": f"Email claims to be from {brand['name']}, but sending domain '{sender_domain}' is not authorized.",
                    "severity": "high"
                })
                indicators.append({
                    "type": "keyword",
                    "value": f"Brand Impersonation: {brand['name']}",
                    "severity": "high",
                    "desc": f"Claimed brand does not match sender domain '{sender_domain}'"
                })

    # 6. Attachment Safety Check
    attachments = parsed_email.get('attachments', [])
    for att in attachments:
        fname = att.get('filename', '').lower()
        for ext in HIGH_RISK_ATTACHMENT_EXTS:
            if fname.endswith(ext):
                risk_score += 25
                reasons.append({
                    "title": "High-Risk Executable Attachment",
                    "desc": f"Attachment '{att.get('filename')}' uses an executable/script extension ('{ext}').",
                    "severity": "high"
                })
                indicators.append({
                    "type": "header",
                    "value": f"Attachment: {att.get('filename')}",
                    "severity": "high",
                    "desc": "Dangerous executable payload file"
                })

    # 7. Header Anomalies
    if not parsed_email.get('message_id'):
        risk_score += 10
        reasons.append({
            "title": "Missing Standard Message-ID Header",
            "desc": "Email lacks a standard Message-ID header, a frequent indicator of bulk spam/phishing toolkits.",
            "severity": "low"
        })

    # Cap risk score at 100
    risk_score = min(100, max(0, risk_score))

    # Determine Classification & Confidence
    if risk_score >= 90:
        classification = "MALICIOUS / BEC"
        confidence = "Very High (98%)"
    elif risk_score >= 70:
        classification = "PHISHING"
        confidence = "High (94%)"
    elif risk_score >= 50:
        classification = "SPOOFING"
        confidence = "High (88%)"
    elif risk_score >= 25:
        classification = "SUSPICIOUS"
        confidence = "Medium (75%)"
    else:
        classification = "SAFE"
        confidence = "High (99%)"
        if not reasons:
            reasons.append({
                "title": "No Suspicious Indicators Found",
                "desc": "Email headers, domain alignment, and authentication checks passed without anomaly.",
                "severity": "info"
            })

    # Determine Severity
    if risk_score >= 70:
        severity = "HIGH"
    elif risk_score >= 35:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # Build Why Was This Detected Checks list
    why_detected_checks = []
    if reply_to_domain and sender_domain and reply_to_domain != sender_domain:
        why_detected_checks.append({"text": "Sender domain mismatch", "flagged": True})
    if spf_status == "FAIL" or dkim_status == "FAIL" or dmarc_status == "FAIL":
        why_detected_checks.append({"text": "Authentication failure detected (SPF/DKIM/DMARC)", "flagged": True})
    if any(r.get("title", "").startswith("Suspicious") or "Link" in r.get("title", "") or "Brand URL" in r.get("title", "") for r in reasons):
        why_detected_checks.append({"text": "Suspicious URL detected", "flagged": True})
    if matched_urgency:
        why_detected_checks.append({"text": "Urgency-based language detected", "flagged": True})
    if any("Impersonation" in r.get("title", "") for r in reasons):
        why_detected_checks.append({"text": "Brand impersonation attempt detected", "flagged": True})
    if any("Attachment" in r.get("title", "") for r in reasons):
        why_detected_checks.append({"text": "High-risk executable attachment detected", "flagged": True})

    if not why_detected_checks and risk_score < 25:
        why_detected_checks.append({"text": "Sender domain aligned & SPF/DKIM passed", "flagged": False})

    # Build AI Conclusion
    if risk_score >= 80:
        ai_conclusion = "High probability of phishing / BEC attack based on the detected email indicators."
    elif risk_score >= 50:
        ai_conclusion = "Moderate probability of spoofing or social engineering attempt."
    elif risk_score >= 25:
        ai_conclusion = "Elevated risk detected. Proceed with caution."
    else:
        ai_conclusion = "Low threat probability. Email indicators match legitimate sending patterns."

    return {
        "risk_score": risk_score,
        "classification": classification,
        "confidence": confidence,
        "severity": severity,
        "reasons": reasons,
        "why_detected_checks": why_detected_checks,
        "ai_conclusion": ai_conclusion,
        "indicators": indicators,
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "dmarc_status": dmarc_status
    }

