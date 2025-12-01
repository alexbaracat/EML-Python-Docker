from flask import Flask, request, render_template, send_from_directory, jsonify
from email.parser import BytesParser
from email.policy import default as default_policy
from email.mime.text import MIMEText
import os
import re
from html import escape

app = Flask(__name__, template_folder='templates', static_folder='static')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ALLOWED_EXTENSIONS = {'eml'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def decode_quoted_printable(text):
    """Decode quoted-printable encoded text."""
    # Remove soft line breaks
    text = re.sub(r'=\r?\n', '', text)
    # Decode hex sequences
    def hex_decode(match):
        try:
            return chr(int(match.group(1), 16))
        except:
            return match.group(0)
    text = re.sub(r'=([0-9A-F]{2})', hex_decode, text, flags=re.IGNORECASE)
    return text

def extract_body(msg):
    """Extract text or HTML body from email message."""
    body = ""
    is_html = False
    
    content_type = msg.get("content-type", "").lower()
    is_html = "text/html" in content_type
    
    if msg.is_multipart():
        # Try to find the best part (HTML if available, otherwise plain text)
        for part in msg.walk():
            part_type = part.get_content_type()
            
            if part_type == "text/html":
                body = part.get_content()
                is_html = True
                break
            elif part_type == "text/plain" and not body:
                body = part.get_content()
                is_html = False
    else:
        body = msg.get_content()
    
    # Decode quoted-printable if needed
    content_transfer_encoding = msg.get("content-transfer-encoding", "").lower()
    if "quoted-printable" in content_transfer_encoding and body:
        body = decode_quoted_printable(body)
    
    return body, is_html

def parse_email(content):
    """Parse email content and extract headers and body."""
    try:
        msg = BytesParser(policy=default_policy).parsebytes(content)
        
        # Key headers to display prominently
        key_header_names = ["from", "to", "cc", "bcc", "subject", "date", "message-id", "content-type"]
        key_headers = {}
        other_headers = {}
        
        # Extract all headers
        for header_name in msg.keys():
            header_value = msg.get(header_name)
            if header_value:
                header_display_name = header_name.replace('-', ' ').title()
                
                if header_name.lower() in key_header_names:
                    key_headers[header_display_name] = str(header_value)
                else:
                    other_headers[header_display_name] = str(header_value)
        
        # Extract body
        body, is_html = extract_body(msg)
        
        # Find attachments (save to static/attachments)
        attachments = []
        attachments_dir = os.path.join(BASE_DIR, 'static', 'attachments')
        os.makedirs(attachments_dir, exist_ok=True)

        for part in msg.walk():
            # skip multi-part containers
            if part.is_multipart():
                continue

            content_disposition = part.get_content_disposition() or ''
            filename = part.get_filename()
            if content_disposition.lower() == 'attachment' or filename:
                payload = part.get_payload(decode=True) or b''
                safe_name = filename or 'attachment'
                # make unique filename
                uniq = str(abs(hash((safe_name, len(payload), os.urandom(8)))))
                save_name = f"{uniq}_{safe_name}"
                save_path = os.path.join(attachments_dir, save_name)
                try:
                    with open(save_path, 'wb') as f:
                        f.write(payload)
                    attachments.append({
                        'filename': safe_name,
                        'url': f"/static/attachments/{save_name}",
                        'size': len(payload),
                        'content_type': part.get_content_type()
                    })
                except Exception:
                    # ignore saving errors but still report filename
                    attachments.append({
                        'filename': safe_name,
                        'url': None,
                        'size': len(payload),
                        'content_type': part.get_content_type()
                    })

        # Escape HTML for display in raw code tab
        raw_content = content.decode('utf-8', errors='ignore')

        # include headers under `headers` for template compatibility
        headers_combined = {**key_headers, **other_headers}

        return {
            "key_headers": key_headers,
            "other_headers": other_headers,
            "headers": headers_combined,
            "body": escape(body) if not is_html else body,
            "body_rendered": body,
            "is_html": is_html,
            "raw_content": raw_content,
            "attachments": attachments
        }
    except Exception as e:
        return {"error": str(e)}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload-api", methods=["POST"])
def upload_api():
    """API endpoint that returns JSON data instead of HTML."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"})
    
    file = request.files["file"]
    
    if file.filename == "":
        return jsonify({"error": "No file selected"})
    
    if not allowed_file(file.filename):
        return jsonify({"error": "Please upload a .eml file"})
    
    try:
        content = file.read()
        result = parse_email(content)
        
        if "error" in result:
            return jsonify({"error": f"Error parsing email: {result['error']}"})
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": f"Error: {str(e)}"})

@app.route("/upload", methods=["POST"])
def upload_email():
    """Legacy endpoint for backward compatibility."""
    if "file" not in request.files:
        return render_template("index.html", error="No file uploaded")
    
    file = request.files["file"]
    
    if file.filename == "":
        return render_template("index.html", error="No file selected")
    
    if not allowed_file(file.filename):
        return render_template("index.html", error="Please upload a .eml file")
    
    try:
        content = file.read()
        result = parse_email(content)
        
        if "error" in result:
            return render_template("index.html", error=f"Error parsing email: {result['error']}")
        
        return render_template("index.html", result=result)
    
    except Exception as e:
        return render_template("index.html", error=f"Error: {str(e)}")

@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(os.path.join(BASE_DIR, "static"), filename)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)