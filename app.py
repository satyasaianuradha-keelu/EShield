import os
import json
import random
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, flash

from database.app_db import get_db_connection, init_db, seed_demo_data_if_empty
from services.email_parser import parse_raw_email, extract_domain
from services.threat_detector import analyze_email_threats
from services.geolocation import get_ip_geolocation
from services.threat_intelligence import get_ip_intelligence, get_domain_intelligence, get_url_intelligence
from services.timeline import build_forensic_timeline, build_forensic_investigation_workflow
from services.report_generator import generate_pdf_report

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "emailshield_hackathon_secret_key_2026")

# Register custom Jinja filters
@app.template_filter('from_json')
def from_json_filter(value):
    if not value:
        return []
    try:
        return json.loads(value)
    except Exception:
        return []

@app.template_filter('extract_domain')
def extract_domain_filter(value):
    return extract_domain(value)

# Initialize and seed database on boot
with app.app_context():
    init_db()
    seed_demo_data_if_empty()

# Helper function to generate unique Case Numbers
def generate_case_number():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM cases")
    count = cursor.fetchone()[0]
    conn.close()
    return f"ST-{1024 + count}"

def build_indicator_records(parsed, analysis):
    """Combine parser-derived network indicators with analyzer findings."""
    records = list(analysis.get('indicators', []))
    known = {(item.get('type'), item.get('value')) for item in records}

    for ip_address in parsed.get('ips', []):
        item = ('ip', ip_address)
        if item not in known:
            records.append({
                'type': 'ip',
                'value': ip_address,
                'severity': 'info',
                'desc': 'IP address extracted from email headers or body'
            })
            known.add(item)

    for url in parsed.get('urls', []):
        domain = extract_domain(url)
        for indicator_type, value, description in [
            ('url', url, 'URL extracted from email content'),
            ('domain', domain, 'Domain extracted from URL')
        ]:
            if value and (indicator_type, value) not in known:
                records.append({
                    'type': indicator_type,
                    'value': value,
                    'severity': 'info',
                    'desc': description
                })
                known.add((indicator_type, value))

    sender_domain = parsed.get('sender_domain')
    if sender_domain and ('domain', sender_domain) not in known:
        records.append({
            'type': 'domain',
            'value': sender_domain,
            'severity': 'info',
            'desc': 'Sender domain extracted from From header'
        })
    return records

# ==============================================================================
# Page Routes
# ==============================================================================

@app.route('/')
def index():
    return render_template('index.html', active_page='home')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', active_page='dashboard')

@app.route('/check')
def check_email():
    return render_template('check_email.html', active_page='check_email')

@app.route('/upload', methods=['POST'])
def upload_email():
    if 'email_file' not in request.files:
        flash("No file part provided.")
        return redirect(url_for('check_email'))
    
    file = request.files['email_file']
    if file.filename == '':
        flash("No file selected.")
        return redirect(url_for('check_email'))

    if not file.filename.lower().endswith('.eml'):
        flash("Only .eml files are supported.")
        return redirect(url_for('check_email'))

    try:
        raw_bytes = file.read()
        return process_and_save_email(raw_bytes)
    except Exception as e:
        flash(f"Error parsing email: {str(e)}")
        return redirect(url_for('check_email'))

@app.route('/paste', methods=['POST'])
def paste_email():
    raw_text = request.form.get('email_raw', '')
    if not raw_text.strip():
        flash("Please paste email text content.")
        return redirect(url_for('check_email'))

    try:
        return process_and_save_email(raw_text)
    except Exception as e:
        flash(f"Error processing email content: {str(e)}")
        return redirect(url_for('check_email'))

def process_and_save_email(raw_content):
    parsed = parse_raw_email(raw_content)
    analysis = analyze_email_threats(parsed)
    case_number = generate_case_number()

    conn = get_db_connection()
    cursor = conn.cursor()

    # Save Email
    cursor.execute("""
        INSERT INTO emails (case_id, message_id, subject, sender, recipient, reply_to, return_path, date_str, body_plain, body_html, raw_headers)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_number,
        parsed.get('message_id'),
        parsed.get('subject'),
        parsed.get('sender'),
        parsed.get('recipient'),
        parsed.get('reply_to'),
        parsed.get('return_path'),
        parsed.get('date_str'),
        parsed.get('body_plain'),
        parsed.get('body_html'),
        parsed.get('raw_headers_text')
    ))
    email_id = cursor.lastrowid

    # Save Analysis Result
    cursor.execute("""
        INSERT INTO analysis_results (email_id, case_id, classification, risk_score, confidence, summary_json, reasons_json, spf_status, dkim_status, dmarc_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        email_id,
        case_number,
        analysis['classification'],
        analysis['risk_score'],
        analysis['confidence'],
        json.dumps({"recommendation": "Review evidence indicators"}),
        json.dumps(analysis['reasons']),
        analysis['spf_status'],
        analysis['dkim_status'],
        analysis['dmarc_status']
    ))

    # Save Case
    priority = "High" if analysis['risk_score'] >= 70 else ("Medium" if analysis['risk_score'] >= 35 else "Low")
    cursor.execute("""
        INSERT INTO cases (case_number, email_id, subject, sender, classification, risk_score, status, priority)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_number,
        email_id,
        parsed.get('subject'),
        parsed.get('sender'),
        analysis['classification'],
        analysis['risk_score'],
        "Open",
        priority
    ))

    for indicator in build_indicator_records(parsed, analysis):
        cursor.execute(
            "INSERT INTO indicators (case_id, indicator_type, value, severity, description) VALUES (?, ?, ?, ?, ?)",
            (case_number, indicator['type'], indicator['value'], indicator['severity'], indicator['desc'])
        )

    # Create Alert if high or medium risk
    if analysis['risk_score'] >= 35:
        severity = "high" if analysis['risk_score'] >= 70 else "medium"
        cursor.execute("""
            INSERT INTO alerts (case_id, severity, message)
            VALUES (?, ?, ?)
        """, (case_number, severity, f"Threat detected in email: '{parsed.get('subject')}'"))

    conn.commit()
    conn.close()

    return redirect(url_for('analysis_result', case_number=case_number))

@app.route('/geolocation')
def geolocation_page():
    conn = get_db_connection()
    case_list = conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
    
    selected_case_id = request.args.get('case_id')
    if not selected_case_id and case_list:
        selected_case_id = case_list[0]['case_number']
        
    case = None
    email = None
    analysis = None
    geo_info = None
    
    if selected_case_id:
        case = conn.execute("SELECT * FROM cases WHERE case_number = ?", (selected_case_id,)).fetchone()
        email = conn.execute("SELECT * FROM emails WHERE case_id = ?", (selected_case_id,)).fetchone()
        analysis = conn.execute("SELECT * FROM analysis_results WHERE case_id = ?", (selected_case_id,)).fetchone()
        
    conn.close()

    origin_ip = "185.220.101.5"
    if email and email['raw_headers']:
        parsed = parse_raw_email(email['raw_headers'])
        if parsed.get('received_hops'):
            origin_ip = parsed['received_hops'][0].get('ip_address', '185.220.101.5')

    geo_info = get_ip_geolocation(origin_ip)
    domain_name = extract_domain(email['sender'] if email else "mail-auth-verify.xyz")
    url_target = "Not available in analyzed message"
    if email:
        parsed_tmp = parse_raw_email((email['raw_headers'] or "") + "\n" + (email['body_plain'] or ""))
        if parsed_tmp.get('urls'):
            url_target = parsed_tmp['urls'][0]

    return render_template(
        'geolocation.html',
        active_page='geolocation',
        cases=case_list,
        selected_case=case,
        email=email,
        analysis=analysis,
        geo_info=geo_info,
        origin_ip=origin_ip,
        domain_name=domain_name,
        url_target=url_target
    )

@app.route('/result/<case_number>')
def analysis_result(case_number):
    conn = get_db_connection()
    case = conn.execute("SELECT * FROM cases WHERE case_number = ?", (case_number,)).fetchone()
    if not case:
        conn.close()
        flash("Case not found.")
        return redirect(url_for('dashboard'))

    email = conn.execute("SELECT * FROM emails WHERE case_id = ?", (case_number,)).fetchone()
    analysis = conn.execute("SELECT * FROM analysis_results WHERE case_id = ?", (case_number,)).fetchone()
    conn.close()

    parsed = parse_raw_email(email['raw_headers'] or "")
    fresh_analysis = analyze_email_threats(parsed)

    origin_ip = "185.220.101.5"
    if parsed.get('received_hops'):
        origin_ip = parsed['received_hops'][0].get('ip_address', '185.220.101.5')
    geo_info = get_ip_geolocation(origin_ip)

    return render_template(
        'analysis_result.html',
        case=case,
        email=email,
        analysis=analysis,
        fresh_analysis=fresh_analysis,
        geo_info=geo_info,
        active_page='check_email'
    )

@app.route('/investigation/<case_number>')
def investigation(case_number):
    conn = get_db_connection()
    case = conn.execute("SELECT * FROM cases WHERE case_number = ?", (case_number,)).fetchone()
    if not case:
        conn.close()
        flash("Case not found.")
        return redirect(url_for('dashboard'))

    email = conn.execute("SELECT * FROM emails WHERE case_id = ?", (case_number,)).fetchone()
    analysis = conn.execute("SELECT * FROM analysis_results WHERE case_id = ?", (case_number,)).fetchone()
    indicators = conn.execute("SELECT * FROM indicators WHERE case_id = ?", (case_number,)).fetchall()
    notes = conn.execute("SELECT * FROM analyst_notes WHERE case_id = ? ORDER BY created_at DESC", (case_number,)).fetchall()
    conn.close()

    # Reconstruct timeline & AI threat analysis
    parsed = parse_raw_email(email['raw_headers'] or "")
    timeline = build_forensic_timeline(parsed.get('received_hops', []))
    fresh_analysis = analyze_email_threats(parsed)
    workflow_steps = build_forensic_investigation_workflow(case_number, case['created_at'], fresh_analysis['classification'])
    indicator_records = build_indicator_records(parsed, fresh_analysis)

    origin_ip = "185.220.101.5"
    if parsed.get('received_hops'):
        origin_ip = parsed['received_hops'][0].get('ip_address', '185.220.101.5')
    geo_info = get_ip_geolocation(origin_ip)
    ip_intelligence = get_ip_intelligence(origin_ip)
    domain_name = extract_domain(parsed.get('sender', ''))
    domain_intelligence = get_domain_intelligence(domain_name)
    url_targets = parsed.get('urls', [])
    url_intelligence = get_url_intelligence(url_targets[0]) if url_targets else None

    return render_template(
        'investigation.html',
        case=case,
        email=email,
        analysis=analysis,
        fresh_analysis=fresh_analysis,
        indicators=indicators,
        notes=notes,
        timeline=timeline,
        workflow_steps=workflow_steps,
        geo_info=geo_info,
        indicator_records=indicator_records,
        ip_intelligence=ip_intelligence,
        domain_intelligence=domain_intelligence,
        url_intelligence=url_intelligence,
        active_page='cases'
    )


@app.route('/monitor')
def monitor():
    conn = get_db_connection()
    cases = conn.execute("SELECT * FROM cases ORDER BY created_at DESC LIMIT 10").fetchall()
    conn.close()
    return render_template('monitor.html', initial_cases=cases, active_page='monitor')

@app.route('/alerts')
def alerts():
    conn = get_db_connection()
    alert_list = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template('alerts.html', alerts=alert_list, active_page='alerts')

@app.route('/cases')
def cases():
    conn = get_db_connection()
    case_list = conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template('cases.html', cases=case_list, active_page='cases')

@app.route('/reports')
def reports():
    conn = get_db_connection()
    case_list = conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template('reports.html', cases=case_list, active_page='reports')

@app.route('/intelligence')
def intelligence_page():
    return render_template('intelligence.html', active_page='intelligence')

@app.route('/help')
def help_page():
    return render_template('help.html', active_page='help')

@app.route('/cases/<case_number>/notes', methods=['POST'])
def add_note(case_number):
    note_text = request.form.get('note_text', '').strip()
    if note_text:
        conn = get_db_connection()
        conn.execute("INSERT INTO analyst_notes (case_id, author, note_text) VALUES (?, ?, ?)",
                     (case_number, "Analyst Persona", note_text))
        conn.commit()
        conn.close()
    return redirect(url_for('investigation', case_number=case_number))

@app.route('/reports/download/<case_number>')
def download_report(case_number):
    conn = get_db_connection()
    case = conn.execute("SELECT * FROM cases WHERE case_number = ?", (case_number,)).fetchone()
    email = conn.execute("SELECT * FROM emails WHERE case_id = ?", (case_number,)).fetchone()
    analysis = conn.execute("SELECT * FROM analysis_results WHERE case_id = ?", (case_number,)).fetchone()
    indicators = conn.execute("SELECT * FROM indicators WHERE case_id = ?", (case_number,)).fetchall()
    notes = conn.execute("SELECT * FROM analyst_notes WHERE case_id = ?", (case_number,)).fetchall()
    conn.close()

    if not case:
        flash("Case not found.")
        return redirect(url_for('reports'))

    parsed = parse_raw_email(email['raw_headers'] or "")
    timeline = build_forensic_timeline(parsed.get('received_hops', []))
    email_dict = dict(email)
    email_dict['urls'] = parsed.get('urls', [])
    email_dict['ips'] = parsed.get('ips', [])

    pdf_file_path, rel_path = generate_pdf_report(dict(case), email_dict, dict(analysis), [dict(i) for i in indicators], timeline, [dict(n) for n in notes])
    return send_file(pdf_file_path, as_attachment=True, download_name=f"EmailShield_Report_{case_number}.pdf")

# ==============================================================================
# API Endpoints
# ==============================================================================

@app.route('/api/dashboard/stats')
def api_dashboard_stats():
    conn = get_db_connection()
    total_analyzed = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    threats_detected = conn.execute("SELECT COUNT(*) FROM cases WHERE risk_score >= 35").fetchone()[0]
    high_risk_cases = conn.execute("SELECT COUNT(*) FROM cases WHERE risk_score >= 70").fetchone()[0]

    safe_count = conn.execute("SELECT COUNT(*) FROM cases WHERE classification = 'SAFE'").fetchone()[0]
    suspicious_count = conn.execute("SELECT COUNT(*) FROM cases WHERE classification = 'SUSPICIOUS'").fetchone()[0]
    high_risk_count = conn.execute("SELECT COUNT(*) FROM cases WHERE classification in ('PHISHING', 'SPOOFING')").fetchone()[0]
    malicious_count = conn.execute("SELECT COUNT(*) FROM cases WHERE classification = 'MALICIOUS / BEC'").fetchone()[0]

    recent_cases_rows = conn.execute("SELECT * FROM cases ORDER BY created_at DESC LIMIT 6").fetchall()
    conn.close()

    recent_cases = [dict(r) for r in recent_cases_rows]

    return jsonify({
        "total_analyzed": total_analyzed,
        "threats_detected": threats_detected,
        "high_risk_cases": high_risk_cases,
        "last_24h": total_analyzed,
        "threat_breakdown": {
            "safe": safe_count,
            "suspicious": suspicious_count,
            "high_risk": high_risk_count,
            "malicious": malicious_count
        },
        "recent_cases": recent_cases
    })

@app.route('/api/samples/<sample_type>')
def api_sample_email(sample_type):
    sample_dir = os.path.join(os.path.dirname(__file__), 'sample_emails')
    file_map = {
        'phishing': 'phishing.eml',
        'suspicious': 'suspicious.eml',
        'safe': 'safe.eml'
    }
    fname = file_map.get(sample_type, 'phishing.eml')
    fpath = os.path.join(sample_dir, fname)

    if os.path.exists(fpath):
        with open(fpath, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({"sample_type": sample_type, "raw_content": content})
    return jsonify({"error": "Sample file not found."}), 404

@app.route('/api/monitor/trigger', methods=['POST'])
def api_monitor_trigger():
    # Pick a random sample email to simulate live inbound mail arrival
    sample_type = random.choice(['phishing', 'suspicious', 'safe'])
    sample_dir = os.path.join(os.path.dirname(__file__), 'sample_emails')
    fpath = os.path.join(sample_dir, f"{sample_type}.eml")

    if not os.path.exists(fpath):
        return jsonify({"error": "Sample file missing."}), 500

    with open(fpath, 'r', encoding='utf-8') as f:
        raw_content = f.read()

    parsed = parse_raw_email(raw_content)
    analysis = analyze_email_threats(parsed)
    case_number = generate_case_number()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO emails (case_id, message_id, subject, sender, recipient, reply_to, return_path, date_str, body_plain, raw_headers)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_number, parsed.get('message_id'), parsed.get('subject'), parsed.get('sender'),
        parsed.get('recipient'), parsed.get('reply_to'), parsed.get('return_path'),
        parsed.get('date_str'), parsed.get('body_plain'), parsed.get('raw_headers_text')
    ))
    email_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO analysis_results (email_id, case_id, classification, risk_score, confidence, summary_json, reasons_json, spf_status, dkim_status, dmarc_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        email_id, case_number, analysis['classification'], analysis['risk_score'],
        analysis['confidence'], json.dumps({"recommendation": "Monitor stream alert"}),
        json.dumps(analysis['reasons']), analysis['spf_status'], analysis['dkim_status'], analysis['dmarc_status']
    ))

    cursor.execute("""
        INSERT INTO cases (case_number, email_id, subject, sender, classification, risk_score, status, priority)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_number, email_id, parsed.get('subject'), parsed.get('sender'),
        analysis['classification'], analysis['risk_score'], "Open", "High"
    ))

    for indicator in build_indicator_records(parsed, analysis):
        cursor.execute(
            "INSERT INTO indicators (case_id, indicator_type, value, severity, description) VALUES (?, ?, ?, ?, ?)",
            (case_number, indicator['type'], indicator['value'], indicator['severity'], indicator['desc'])
        )

    if analysis['risk_score'] >= 35:
        cursor.execute("INSERT INTO alerts (case_id, severity, message) VALUES (?, ?, ?)",
                       (case_number, "high" if analysis['risk_score'] >= 70 else "medium", f"Inbound monitor alert: {parsed.get('subject')}"))

    conn.commit()
    conn.close()

    return jsonify({
        "case_number": case_number,
        "subject": parsed.get('subject'),
        "sender": parsed.get('sender'),
        "classification": analysis['classification'],
        "risk_score": analysis['risk_score']
    })

@app.route('/api/intelligence/lookup', methods=['POST'])
def api_intelligence_lookup():
    data = request.json or {}
    qtype = data.get('type', 'ip')
    query = data.get('query', '').strip()

    if not query:
        return jsonify({"error": "No query string provided."}), 400

    if qtype == 'ip':
        res = get_ip_intelligence(query)
    elif qtype == 'domain':
        res = get_domain_intelligence(query)
    elif qtype == 'url':
        res = get_url_intelligence(query)
    else:
        res = {"error": "Invalid lookup type."}

    return jsonify(res)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
