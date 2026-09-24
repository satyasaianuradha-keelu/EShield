-- EmailShield Database Schema

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    role TEXT DEFAULT 'analyst',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT UNIQUE NOT NULL,
    message_id TEXT,
    subject TEXT,
    sender TEXT,
    recipient TEXT,
    reply_to TEXT,
    return_path TEXT,
    date_str TEXT,
    body_plain TEXT,
    body_html TEXT,
    raw_headers TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS analysis_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id INTEGER NOT NULL,
    case_id TEXT NOT NULL,
    classification TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    confidence TEXT NOT NULL,
    summary_json TEXT,
    reasons_json TEXT,
    spf_status TEXT,
    dkim_status TEXT,
    dmarc_status TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(email_id) REFERENCES emails(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    indicator_type TEXT NOT NULL, -- 'ip', 'domain', 'url', 'header', 'keyword'
    value TEXT NOT NULL,
    severity TEXT NOT NULL, -- 'high', 'medium', 'low', 'info'
    description TEXT
);

CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_number TEXT UNIQUE NOT NULL, -- e.g. ST-1024
    email_id INTEGER NOT NULL,
    subject TEXT,
    sender TEXT,
    classification TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    status TEXT DEFAULT 'Open', -- 'Open', 'Under Investigation', 'Resolved'
    priority TEXT DEFAULT 'High', -- 'High', 'Medium', 'Low'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(email_id) REFERENCES emails(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    severity TEXT NOT NULL, -- 'high', 'medium', 'low'
    message TEXT NOT NULL,
    is_read INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS timeline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    hop_index INTEGER NOT NULL,
    server_from TEXT,
    server_by TEXT,
    ip_address TEXT,
    timestamp_str TEXT,
    delay_sec INTEGER DEFAULT 0,
    flag TEXT
);

CREATE TABLE IF NOT EXISTS analyst_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    author TEXT DEFAULT 'Analyst',
    note_text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
