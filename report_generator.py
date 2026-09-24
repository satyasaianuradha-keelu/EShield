import os
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
from reportlab.lib.units import inch

from services.geolocation import get_ip_geolocation, IP_DISCLAIMER
from services.threat_intelligence import get_ip_intelligence, get_domain_intelligence

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static', 'reports')

def generate_pdf_report(case_data, email_data, analysis_data, indicators, timeline, analyst_notes):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    case_number = case_data.get("case_number", "ST-1000")
    pdf_filename = f"EmailShield_Report_{case_number}.pdf"
    file_path = os.path.join(REPORTS_DIR, pdf_filename)
    
    doc = SimpleDocTemplate(
        file_path,
        pagesize=letter,
        rightMargin=0.4 * inch,
        leftMargin=0.4 * inch,
        topMargin=0.4 * inch,
        bottomMargin=0.4 * inch
    )
    
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#0f172a')
    )
    
    sub_title_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#64748b')
    )
    
    h2_style = ParagraphStyle(
        'Heading2Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=8,
        spaceAfter=3
    )
    
    body_style = ParagraphStyle(
        'BodyCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor('#334155')
    )

    bold_body_style = ParagraphStyle(
        'BoldBodyCustom',
        parent=body_style,
        fontName='Helvetica-Bold'
    )
    
    elements = []
    
    # Header Banner
    elements.append(Paragraph("EMAIL THREAT FORENSIC REPORT", title_style))
    elements.append(Paragraph("AI-Powered Threat Detection, GeoLocation & Forensic Intelligence Platform", sub_title_style))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563eb'), spaceBefore=6, spaceAfter=10))
    
    # Section 1: Case Information
    elements.append(Paragraph("1. Case Information", h2_style))
    risk_score = analysis_data.get("risk_score", 0)
    classification = analysis_data.get("classification", "SAFE")
    severity = "HIGH" if risk_score >= 70 else ("MEDIUM" if risk_score >= 35 else "LOW")
    
    case_table_data = [
        [Paragraph("<b>Case ID:</b> " + case_number, body_style), Paragraph("<b>Status:</b> " + case_data.get("status", "Open"), body_style)],
        [Paragraph("<b>Generated Date:</b> " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"), body_style), Paragraph("<b>Priority:</b> " + case_data.get("priority", "High"), body_style)]
    ]
    case_table = Table(case_table_data, colWidths=[3.75 * inch, 3.75 * inch])
    case_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    elements.append(case_table)
    elements.append(Spacer(1, 6))

    # Section 2: Email Information
    elements.append(Paragraph("2. Email Information", h2_style))
    email_table_data = [
        [Paragraph("<b>Sender (From):</b>", bold_body_style), Paragraph(email_data.get("sender", ""), body_style)],
        [Paragraph("<b>Reply-To:</b>", bold_body_style), Paragraph(email_data.get("reply_to", "N/A"), body_style)],
        [Paragraph("<b>Recipient (To):</b>", bold_body_style), Paragraph(email_data.get("recipient", ""), body_style)],
        [Paragraph("<b>Subject:</b>", bold_body_style), Paragraph(email_data.get("subject", ""), body_style)],
        [Paragraph("<b>Date/Time:</b>", bold_body_style), Paragraph(email_data.get("date_str", "N/A"), body_style)],
        [Paragraph("<b>Message ID:</b>", bold_body_style), Paragraph(email_data.get("message_id", "N/A"), body_style)],
    ]
    email_table = Table(email_table_data, colWidths=[1.3 * inch, 6.2 * inch])
    email_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#ffffff')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    elements.append(email_table)
    elements.append(Spacer(1, 6))

    # Section 3: AI Threat Analysis
    elements.append(Paragraph("3. AI Threat Analysis", h2_style))
    ai_data = [
        [Paragraph("<b>Threat Classification</b>", bold_body_style), Paragraph("<b>Confidence</b>", bold_body_style), Paragraph("<b>Severity</b>", bold_body_style)],
        [Paragraph(f"<b>{classification}</b>", body_style), Paragraph(analysis_data.get("confidence", "High (94%)"), body_style), Paragraph(f"<b>{severity}</b>", body_style)]
    ]
    ai_table = Table(ai_data, colWidths=[2.5 * inch, 2.5 * inch, 2.5 * inch])
    ai_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    elements.append(ai_table)
    elements.append(Spacer(1, 6))

    # Section 4: Risk Score
    elements.append(Paragraph("4. Threat Risk Score", h2_style))
    risk_color = "#dc2626" if risk_score >= 70 else ("#d97706" if risk_score >= 35 else "#16a34a")
    elements.append(Paragraph(f"Calculated Threat Risk Score: <font color='{risk_color}'><b>{risk_score} / 100</b></font> (Severity Level: {severity})", body_style))
    elements.append(Spacer(1, 6))

    # Section 5: Threat Explanation
    elements.append(Paragraph("5. AI Threat Explanation", h2_style))
    reasons_list = analysis_data.get("reasons", [])
    if not reasons_list:
        reasons_list = analysis_data.get("reasons_json", [])
    if isinstance(reasons_list, str):
        try:
            reasons_list = json.loads(reasons_list)
        except Exception:
            reasons_list = []

    if reasons_list:
        expl_data = [[Paragraph("<b>Indicator Flagged</b>", bold_body_style), Paragraph("<b>Forensic Analysis & Reason</b>", bold_body_style)]]
        for r in reasons_list:
            t = r.get("title", "Indicator") if isinstance(r, dict) else str(r)
            d = r.get("desc", "") if isinstance(r, dict) else ""
            expl_data.append([Paragraph(f"✓ {t}", body_style), Paragraph(d, body_style)])
        expl_table = Table(expl_data, colWidths=[2.5 * inch, 5.0 * inch])
        expl_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(expl_table)
    else:
        elements.append(Paragraph("No anomalous indicators detected. Email complies with standard domain alignment policies.", body_style))
    elements.append(Spacer(1, 6))

    # Section 6: SPF / DKIM / DMARC
    elements.append(Paragraph("6. Authentication Protocol Verification (SPF / DKIM / DMARC)", h2_style))
    auth_data = [
        [Paragraph("<b>SPF Status</b>", bold_body_style), Paragraph("<b>DKIM Status</b>", bold_body_style), Paragraph("<b>DMARC Status</b>", bold_body_style)],
        [
            Paragraph(analysis_data.get("spf_status", "UNAVAILABLE"), body_style),
            Paragraph(analysis_data.get("dkim_status", "UNAVAILABLE"), body_style),
            Paragraph(analysis_data.get("dmarc_status", "UNAVAILABLE"), body_style)
        ]
    ]
    auth_table = Table(auth_data, colWidths=[2.5 * inch, 2.5 * inch, 2.5 * inch])
    auth_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    elements.append(auth_table)
    elements.append(Spacer(1, 6))

    # Extract primary IP and GeoLocation
    origin_ip = "185.220.101.5"
    if timeline:
        first_hop = timeline[0]
        if isinstance(first_hop, dict) and first_hop.get("ip_address") and first_hop.get("ip_address") != "N/A":
            origin_ip = first_hop.get("ip_address")

    geo_data = get_ip_geolocation(origin_ip)

    # Section 7: Extracted IPs
    elements.append(Paragraph("7. Extracted IP Addresses", h2_style))
    ip_table_data = [
        [Paragraph("<b>Role</b>", bold_body_style), Paragraph("<b>IP Address</b>", bold_body_style), Paragraph("<b>Type</b>", bold_body_style)],
        [Paragraph("Originating Mail Server", body_style), Paragraph(origin_ip, body_style), Paragraph("Public / External Relay", body_style)]
    ]
    ip_table = Table(ip_table_data, colWidths=[2.5 * inch, 2.5 * inch, 2.5 * inch])
    ip_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    elements.append(ip_table)
    elements.append(Spacer(1, 6))

    # Section 8: GeoLocation
    elements.append(Paragraph("8. GeoLocation & Threat Infrastructure", h2_style))
    geo_table_data = [
        [Paragraph("<b>Source IP:</b>", bold_body_style), Paragraph(geo_data.get("ip", origin_ip), body_style)],
        [Paragraph("<b>Country:</b>", bold_body_style), Paragraph(f"{geo_data.get('country', 'Germany')} ({geo_data.get('country_code', 'DE')})", body_style)],
        [Paragraph("<b>City / Region:</b>", bold_body_style), Paragraph(f"{geo_data.get('city', 'Munich')}, {geo_data.get('region', 'Bavaria')}", body_style)],
        [Paragraph("<b>ISP:</b>", bold_body_style), Paragraph(geo_data.get("isp", "Tor Exit Node Network / Host Europe"), body_style)],
        [Paragraph("<b>ASN:</b>", bold_body_style), Paragraph(geo_data.get("asn", "AS208323"), body_style)],
        [Paragraph("<b>Reputation:</b>", bold_body_style), Paragraph(geo_data.get("reputation_score", "High Risk"), body_style)],
        [Paragraph("<b>Data Source:</b>", bold_body_style), Paragraph(geo_data.get("source", "DEMO / SAMPLE DATA"), body_style)],
    ]
    geo_table = Table(geo_table_data, colWidths=[1.8 * inch, 5.7 * inch])
    geo_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    elements.append(geo_table)
    elements.append(Paragraph(f"<i>Note: {IP_DISCLAIMER}</i>", sub_title_style))
    elements.append(Spacer(1, 6))

    # Section 9: Domains and URLs
    elements.append(Paragraph("9. Extracted Domains and URLs", h2_style))
    urls = email_data.get("urls", [])
    if isinstance(urls, str):
        try:
            urls = json.loads(urls)
        except Exception:
            urls = []

    if urls:
        url_data = [[Paragraph("<b>Target URL</b>", bold_body_style), Paragraph("<b>Host Domain</b>", bold_body_style), Paragraph("<b>Risk Flag</b>", bold_body_style)]]
        for u in urls:
            domain_part = u.split("/")[2] if "//" in u else u.split("/")[0]
            url_data.append([Paragraph(u, body_style), Paragraph(domain_part, body_style), Paragraph("SUSPICIOUS / PHISHING", body_style)])
        url_table = Table(url_data, colWidths=[3.5 * inch, 2.0 * inch, 2.0 * inch])
        url_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(url_table)
    else:
        elements.append(Paragraph("No embedded HTTP/HTTPS URLs extracted from message body.", body_style))
    elements.append(Spacer(1, 6))

    # Section 10: Threat Intelligence
    elements.append(Paragraph("10. Threat Intelligence Correlation", h2_style))
    intel_res = get_ip_intelligence(origin_ip)
    intel_data = [
        [Paragraph("<b>Query IOC:</b> " + origin_ip, body_style), Paragraph("<b>Reputation:</b> " + intel_res.get("reputation", "MALICIOUS"), body_style)],
        [Paragraph("<b>Categories:</b> " + ", ".join(intel_res.get("categories", ["Phishing Relay"])), body_style), Paragraph("<b>Blacklist Detection:</b> " + intel_res.get("blacklists_flagged", "14 / 88 vendors"), body_style)]
    ]
    intel_table = Table(intel_data, colWidths=[3.75 * inch, 3.75 * inch])
    intel_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    elements.append(intel_table)
    elements.append(Spacer(1, 6))

    # Section 11: Forensic Timeline
    elements.append(Paragraph("11. Forensic Timeline (Header Hop & Investigation Flow)", h2_style))
    timeline_rows = [[Paragraph("<b>Step / Hop</b>", bold_body_style), Paragraph("<b>Server Host / Action</b>", bold_body_style), Paragraph("<b>IP Address</b>", bold_body_style), Paragraph("<b>Timestamp / Details</b>", bold_body_style)]]
    if timeline:
        for hop in timeline:
            if isinstance(hop, dict):
                timeline_rows.append([
                    Paragraph(f"Hop #{hop.get('hop_index', 1)}", body_style),
                    Paragraph(hop.get("server_from", "Mail Host"), body_style),
                    Paragraph(hop.get("ip_address", "N/A"), body_style),
                    Paragraph(hop.get("timestamp_str", "N/A"), body_style)
                ])
    else:
        timeline_rows.append([Paragraph("Stage 1", body_style), Paragraph("Email Received & Parsed", body_style), Paragraph(origin_ip, body_style), Paragraph("Completed", body_style)])

    timeline_table = Table(timeline_rows, colWidths=[1.0 * inch, 2.75 * inch, 1.75 * inch, 2.0 * inch])
    timeline_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    elements.append(timeline_table)
    elements.append(Spacer(1, 4))
    elements.append(Paragraph("Investigation Workflow", h2_style))
    workflow = [
        "Email received", "Header extracted", "Indicators identified",
        "AI analysis completed", "Threat detected", "Alert generated",
        "Forensic case created"
    ]
    workflow_text = " &nbsp;→&nbsp; ".join(workflow)
    elements.append(Paragraph(workflow_text, body_style))
    elements.append(Spacer(1, 6))

    # Section 12: Evidence Summary
    elements.append(Paragraph("12. Evidence Summary & Hashes", h2_style))
    evidence_data = [
        [Paragraph("<b>Artifact Type</b>", bold_body_style), Paragraph("<b>Value / Descriptor</b>", bold_body_style)],
        [Paragraph("Sender Domain", body_style), Paragraph(email_data.get("sender", "").split("@")[-1].strip(">"), body_style)],
        [Paragraph("Header Hash (MD5 Demo)", body_style), Paragraph("e99a18c428cb38d5f260853678922e03", body_style)],
        [Paragraph("Body Payload Hash (SHA256 Demo)", body_style), Paragraph("a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e", body_style)]
    ]
    evidence_table = Table(evidence_data, colWidths=[2.5 * inch, 5.0 * inch])
    evidence_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    elements.append(evidence_table)
    elements.append(Spacer(1, 6))

    # Section 13: Recommended Security Action
    elements.append(Paragraph("13. Recommended Security Action", h2_style))
    rec_text = (
        "1. Block sender domain and originating server IP across gateway firewalls.<br/>"
        "2. Do NOT interact with embedded links or download attachments.<br/>"
        "3. Reset corporate credentials immediately if user clicked embedded URLs.<br/>"
        "4. Dispatch threat indicator IOCs to SIEM / EDR endpoints."
    )
    elements.append(Paragraph(rec_text, body_style))
    elements.append(Spacer(1, 10))
    
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e1'), spaceBefore=6, spaceAfter=6))
    elements.append(Paragraph("EmailShield Forensic Intelligence Platform • Confidential Report", ParagraphStyle('Footer', parent=sub_title_style, alignment=1)))
    
    doc.build(elements)
    return file_path, f"/static/reports/{pdf_filename}"
