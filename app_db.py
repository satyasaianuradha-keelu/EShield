import sqlite3
import os
import json
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(__file__), 'app.db')
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), 'schema.sql')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db_connection()
    with open(SCHEMA_PATH, 'r', encoding='utf-8') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()

def seed_demo_data_if_empty():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM cases")
    count = cursor.fetchone()[0]
    
    if count > 0:
        conn.close()
        return

    print("Seeding initial demo cases into database...")

    # Demo Case 1: Urgent PayPal Phishing (ST-1024)
    case_1_id = "ST-1024"
    cursor.execute("""
        INSERT INTO emails (case_id, message_id, subject, sender, recipient, reply_to, return_path, date_str, body_plain, raw_headers)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_1_id,
        "<202609230912.paypalsecurity@mail-auth-verify.xyz>",
        "URGENT: Your PayPal Account Security Notice - Action Required Immediately",
        "PayPal Security Alert <service-update@mail-auth-verify.xyz>",
        "security-target@company.org",
        "support-collector@hackerserver.info",
        "bounce-handler@mail-auth-verify.xyz",
        "Wed, 23 Sep 2026 09:12:00 +0000",
        "Dear Customer,\n\nWe detected unauthorized login attempts on your account from IP address 185.220.101.5. To avoid permanent suspension, verify your account credentials immediately by clicking below:\n\nhttp://paypal-verification-security-portal.com.xyz/login/verify.php\n\nFailure to verify within 24 hours will result in permanent account restriction.\n\nPayPal Security Team",
        "Received: from mail-auth-verify.xyz (mail-auth-verify.xyz [185.220.101.5]) by mx.company.org with ESMTP id p1024; Wed, 23 Sep 2026 09:12:05 +0000\nAuthentication-Results: mx.company.org; spf=fail (sender IP 185.220.101.5); dkim=fail; dmarc=fail action=none header.from=paypal.com"
    ))
    email_1_row_id = cursor.lastrowid

    reasons_1 = [
        {"title": "Sender Domain Mismatch", "desc": "Claimed organization (PayPal) does not match actual sending domain (mail-auth-verify.xyz)."},
        {"title": "SPF Authentication Failed", "desc": "SPF verification failed. The IP 185.220.101.5 is not authorized by paypal.com."},
        {"title": "DKIM Verification Failed", "desc": "Digital signature verification failed or was tampered with."},
        {"title": "Suspicious URL Target", "desc": "Embedded URL points to suspicious lookalike domain (paypal-verification-security-portal.com.xyz)."},
        {"title": "Reply-To Address Divergence", "desc": "Reply-To address (support-collector@hackerserver.info) differs suspicious from sender address."},
        {"title": "High Urgency & Threat Language", "desc": "Email contains strong pressure tactics ('permanent restriction within 24 hours')."}
    ]

    cursor.execute("""
        INSERT INTO analysis_results (email_id, case_id, classification, risk_score, confidence, summary_json, reasons_json, spf_status, dkim_status, dmarc_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        email_1_row_id,
        case_1_id,
        "PHISHING",
        92,
        "High (96%)",
        json.dumps({"threat_type": "Credential Harvesting Phishing", "recommendation": "Do not click links. Block domain across network gateway."}),
        json.dumps(reasons_1),
        "FAIL", "FAIL", "FAIL"
    ))

    cursor.execute("""
        INSERT INTO cases (case_number, email_id, subject, sender, classification, risk_score, status, priority)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_1_id,
        email_1_row_id,
        "URGENT: Your PayPal Account Security Notice - Action Required Immediately",
        "PayPal Security Alert <service-update@mail-auth-verify.xyz>",
        "PHISHING",
        92,
        "Open",
        "High"
    ))

    cursor.execute("""
        INSERT INTO alerts (case_id, severity, message)
        VALUES (?, ?, ?)
    """, (case_1_id, "high", "Critical Phishing Threat detected targeting security-target@company.org"))

    # Indicators for ST-1024
    indicators_1 = [
        ("ip", "185.220.101.5", "high", "Known Tor Exit Node / Phishing Mail Relay IP"),
        ("domain", "mail-auth-verify.xyz", "high", "Newly registered suspicious TLD domain"),
        ("url", "http://paypal-verification-security-portal.com.xyz/login/verify.php", "high", "Credential harvesting link"),
        ("header", "Reply-To: support-collector@hackerserver.info", "high", "Data exfiltration destination")
    ]
    for itype, val, sev, desc in indicators_1:
        cursor.execute("INSERT INTO indicators (case_id, indicator_type, value, severity, description) VALUES (?, ?, ?, ?, ?)",
                       (case_1_id, itype, val, sev, desc))

    # Timeline events for ST-1024
    timeline_1 = [
        (1, "Originating Host (185.220.101.5)", "mail-auth-verify.xyz", "185.220.101.5", "09:12:00 UTC", 0, "Originating Node - High Risk IP"),
        (2, "mail-auth-verify.xyz", "relay-relay.server-host.net", "194.26.29.11", "09:12:03 UTC", 3, "Relay Hop"),
        (3, "relay-relay.server-host.net", "mx.company.org", "10.0.4.15", "09:12:05 UTC", 2, "Border Gateway - SPF Fail Triggered")
    ]
    for idx, sfrom, sby, ip, tstr, delay, flag in timeline_1:
        cursor.execute("INSERT INTO timeline_events (case_id, hop_index, server_from, server_by, ip_address, timestamp_str, delay_sec, flag) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                       (case_1_id, idx, sfrom, sby, ip, tstr, delay, flag))

    cursor.execute("""
        INSERT INTO analyst_notes (case_id, author, note_text)
        VALUES (?, ?, ?)
    """, (case_1_id, "Senior SOC Analyst", "Initial automated threat correlation confirms high-confidence phishing campaign. Domain registered 2 days ago. Block rule dispatched to firewall."))


    # Demo Case 2: BEC / Executive Impersonation (ST-1025)
    case_2_id = "ST-1025"
    cursor.execute("""
        INSERT INTO emails (case_id, message_id, subject, sender, recipient, reply_to, return_path, date_str, body_plain, raw_headers)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_2_id,
        "<202609230830.ceo-request@executive-mail.org>",
        "Urgent Wire Transfer Request - Confidential Acquisition",
        "CEO Office <ceo.johnson@executive-mail.org>",
        "finance-director@company.org",
        "private-johnson@consultant-group-exec.com",
        "bounce@executive-mail.org",
        "Wed, 23 Sep 2026 08:30:00 +0000",
        "Hi Alex,\n\nI am currently in an executive meeting and cannot take calls. We are finalizing a confidential acquisition today. Please process an wire transfer of $48,500 to our external advisor account immediately.\n\nReply directly to this email for routing instructions.\n\nBest regards,\nRobert Johnson\nCEO, Company Inc.",
        "Received: from executive-mail.org (193.109.112.44) by mx.company.org with ESMTP; Wed, 23 Sep 2026 08:30:05 +0000\nAuthentication-Results: mx.company.org; spf=softfail; dkim=none; dmarc=fail"
    ))
    email_2_row_id = cursor.lastrowid

    reasons_2 = [
        {"title": "Executive Brand Impersonation (BEC)", "desc": "Email purports to be CEO Robert Johnson requesting wire transfer."},
        {"title": "Reply-To Address Divergence", "desc": "Replies directed to external unverified domain (consultant-group-exec.com)."},
        {"title": "DMARC Policy Failure", "desc": "DMARC authentication failed for claimed executive domain."},
        {"title": "Wire Transfer & Financial Pressure", "desc": "Contains high-risk financial transfer instructions with secrecy constraints."}
    ]

    cursor.execute("""
        INSERT INTO analysis_results (email_id, case_id, classification, risk_score, confidence, summary_json, reasons_json, spf_status, dkim_status, dmarc_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        email_2_row_id,
        case_2_id,
        "SPOOFING",
        78,
        "High (91%)",
        json.dumps({"threat_type": "Business Email Compromise (BEC)", "recommendation": "Verify request out-of-band via phone before processing financial transaction."}),
        json.dumps(reasons_2),
        "NEUTRAL", "UNAVAILABLE", "FAIL"
    ))

    cursor.execute("""
        INSERT INTO cases (case_number, email_id, subject, sender, classification, risk_score, status, priority)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_2_id,
        email_2_row_id,
        "Urgent Wire Transfer Request - Confidential Acquisition",
        "CEO Office <ceo.johnson@executive-mail.org>",
        "SPOOFING",
        78,
        "Under Investigation",
        "High"
    ))

    cursor.execute("""
        INSERT INTO alerts (case_id, severity, message)
        VALUES (?, ?, ?)
    """, (case_2_id, "medium", "Potential Executive Impersonation / BEC attempt detected targeting Finance"))

    # Demo Case 3: Safe Email (ST-1026)
    case_3_id = "ST-1026"
    cursor.execute("""
        INSERT INTO emails (case_id, message_id, subject, sender, recipient, reply_to, return_path, date_str, body_plain, raw_headers)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_3_id,
        "<202609230715.notifications@company.org>",
        "Weekly Engineering Team Sprint Update & Standup Notes",
        "DevOps Automation <devops@company.org>",
        "all-engineers@company.org",
        "devops@company.org",
        "devops@company.org",
        "Wed, 23 Sep 2026 07:15:00 +0000",
        "Team,\n\nHere is the summary of sprint goals for this week:\n- Frontend SOC UI polish\n- Threat Intelligence API adapter validation\n- ReportLab PDF formatting\n\nSee full board at internal wiki.\n\nDevOps Team",
        "Received: from mail.company.org (10.0.1.10) by mx.company.org; Wed, 23 Sep 2026 07:15:00 +0000\nAuthentication-Results: mx.company.org; spf=pass; dkim=pass; dmarc=pass"
    ))
    email_3_row_id = cursor.lastrowid

    reasons_3 = [
        {"title": "Internal Domain Matched", "desc": "Sender matches verified internal domain company.org."},
        {"title": "SPF & DKIM Passed", "desc": "Authentication mechanisms successfully validated."}
    ]

    cursor.execute("""
        INSERT INTO analysis_results (email_id, case_id, classification, risk_score, confidence, summary_json, reasons_json, spf_status, dkim_status, dmarc_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        email_3_row_id,
        case_3_id,
        "SAFE",
        5,
        "High (99%)",
        json.dumps({"threat_type": "Legitimate Internal Communication", "recommendation": "No action required."}),
        json.dumps(reasons_3),
        "PASS", "PASS", "PASS"
    ))

    cursor.execute("""
        INSERT INTO cases (case_number, email_id, subject, sender, classification, risk_score, status, priority)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_3_id,
        email_3_row_id,
        "Weekly Engineering Team Sprint Update & Standup Notes",
        "DevOps Automation <devops@company.org>",
        "SAFE",
        5,
        "Resolved",
        "Low"
    ))

    conn.commit()
    conn.close()
    print("Database demo data successfully seeded.")

if __name__ == '__main__':
    init_db()
    seed_demo_data_if_empty()
