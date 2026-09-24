import email
from email.header import decode_header
import re
import urllib.parse
import ipaddress

MAX_EMAIL_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB limit

def safe_decode_header(header_str):
    if not header_str:
        return ""
    decoded_parts = []
    try:
        for text, encoding in decode_header(header_str):
            if isinstance(text, bytes):
                try:
                    decoded_parts.append(text.decode(encoding or 'utf-8', errors='replace'))
                except Exception:
                    decoded_parts.append(text.decode('latin-1', errors='replace'))
            else:
                decoded_parts.append(str(text))
        return "".join(decoded_parts)
    except Exception:
        return str(header_str)

def extract_email_address(raw_str):
    if not raw_str:
        return ""
    match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', raw_str)
    return match.group(0) if match else raw_str.strip()

def extract_domain(email_or_url):
    if not email_or_url:
        return ""
    if "@" in email_or_url:
        return email_or_url.split("@")[-1].strip(">").strip()
    try:
        parsed = urllib.parse.urlparse(email_or_url)
        netloc = parsed.netloc or parsed.path
        return netloc.split(":")[0].strip()
    except Exception:
        return ""

def extract_ips(text):
    if not text:
        return []
    # Match IPv4 addresses
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    candidates = re.findall(ip_pattern, text)
    valid_ips = []
    for candidate in candidates:
        try:
            ip_obj = ipaddress.ip_address(candidate)
            valid_ips.append(str(ip_obj))
        except ValueError:
            pass
    return list(dict.fromkeys(valid_ips)) # Remove duplicates preserving order

def extract_urls(text):
    if not text:
        return []
    # Regex to extract HTTP/HTTPS URLs
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    matches = re.findall(url_pattern, text)
    cleaned_urls = []
    for url in matches:
        cleaned = url.rstrip('.,;)!]>"\'')
        cleaned_urls.append(cleaned)
    return list(dict.fromkeys(cleaned_urls))

def parse_received_headers(msg):
    received_headers = msg.get_all('Received', [])
    hops = []
    
    # Process headers in reverse chronological order
    for idx, raw_header in enumerate(reversed(received_headers), start=1):
        header_text = " ".join(raw_header.split())
        
        # Extract server_from
        from_match = re.search(r'from\s+([^\s]+(?:\s+\([^)]+\))?)', header_text, re.IGNORECASE)
        server_from = from_match.group(1) if from_match else "Unknown Host"
        
        # Extract server_by
        by_match = re.search(r'by\s+([^\s]+)', header_text, re.IGNORECASE)
        server_by = by_match.group(1) if by_match else "Mail Gateway"
        
        # Extract IP
        ips = extract_ips(header_text)
        hop_ip = ips[0] if ips else "N/A"
        
        # Extract Timestamp
        time_match = re.search(r';\s*(.+)$', header_text)
        timestamp_str = time_match.group(1).strip() if time_match else "N/A"
        
        hops.append({
            "hop_index": idx,
            "server_from": server_from,
            "server_by": server_by,
            "ip_address": hop_ip,
            "timestamp_str": timestamp_str,
            "raw_header": header_text
        })
        
    return hops

def parse_raw_email(raw_content):
    if isinstance(raw_content, str):
        if len(raw_content.encode('utf-8')) > MAX_EMAIL_SIZE_BYTES:
            raise ValueError("Email content exceeds size limit of 5MB.")
        msg = email.message_from_string(raw_content)
    elif isinstance(raw_content, bytes):
        if len(raw_content) > MAX_EMAIL_SIZE_BYTES:
            raise ValueError("Email content exceeds size limit of 5MB.")
        msg = email.message_from_bytes(raw_content)
    else:
        raise ValueError("Invalid email format provided.")

    subject = safe_decode_header(msg.get('Subject', 'No Subject'))
    sender = safe_decode_header(msg.get('From', ''))
    recipient = safe_decode_header(msg.get('To', ''))
    reply_to = safe_decode_header(msg.get('Reply-To', ''))
    return_path = safe_decode_header(msg.get('Return-Path', ''))
    date_str = safe_decode_header(msg.get('Date', ''))
    message_id = safe_decode_header(msg.get('Message-ID', ''))
    auth_results = safe_decode_header(msg.get('Authentication-Results', ''))

    # Extract Body
    body_plain = ""
    body_html = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if "attachment" in content_disposition:
                filename = safe_decode_header(part.get_filename() or "unnamed_attachment")
                attachments.append({
                    "filename": filename,
                    "content_type": content_type,
                    "size_bytes": len(part.get_payload(decode=True) or b"")
                })
            else:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        text = payload.decode(charset, errors='replace')
                        if content_type == "text/plain" and not body_plain:
                            body_plain = text
                        elif content_type == "text/html" and not body_html:
                            body_html = text
                except Exception:
                    pass
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or 'utf-8'
            body_plain = payload.decode(charset, errors='replace')

    combined_text = (body_plain + "\n" + body_html).strip()
    urls = extract_urls(combined_text)
    ips = extract_ips(combined_text + "\n" + str(msg.items()))
    received_hops = parse_received_headers(msg)

    # Collect raw headers text
    headers_dict = {}
    for key, val in msg.items():
        headers_dict[key] = safe_decode_header(val)

    return {
        "subject": subject,
        "sender": sender,
        "sender_address": extract_email_address(sender),
        "sender_domain": extract_domain(extract_email_address(sender)),
        "recipient": recipient,
        "recipient_address": extract_email_address(recipient),
        "reply_to": reply_to,
        "reply_to_address": extract_email_address(reply_to),
        "reply_to_domain": extract_domain(extract_email_address(reply_to)),
        "return_path": return_path,
        "return_path_address": extract_email_address(return_path),
        "date_str": date_str,
        "message_id": message_id,
        "auth_results": auth_results,
        "body_plain": body_plain,
        "body_html": body_html,
        "urls": urls,
        "ips": ips,
        "attachments": attachments,
        "received_hops": received_hops,
        "raw_headers_dict": headers_dict,
        "raw_headers_text": "\n".join([f"{k}: {v}" for k, v in msg.items()])
    }
