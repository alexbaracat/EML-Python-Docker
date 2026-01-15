import os
import io
import zipfile
import hashlib
from datetime import datetime
from urllib.parse import urlparse
from email.parser import BytesParser
from email.policy import default as default_policy
from email.utils import parseaddr

from flask import (
    Flask, request, render_template, redirect,
    url_for, flash, send_file, abort
)
...
EMAILS_SCANNED = 0
SUSPICIOUS_FLAGGED = 0  # high risk emails

# In-memory attachment store (for download links)
ATTACH_STORE = {}

from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    logout_user, login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")

# SQLite DB
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "eml_inspector.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = "login"

# OAuth (Google placeholder)
oauth = OAuth(app)
app.config["GOOGLE_CLIENT_ID"] = os.environ.get("GOOGLE_CLIENT_ID", "")
app.config["GOOGLE_CLIENT_SECRET"] = os.environ.get("GOOGLE_CLIENT_SECRET", "")

if app.config["GOOGLE_CLIENT_ID"] and app.config["GOOGLE_CLIENT_SECRET"]:
    oauth.register(
        name="google",
        client_id=app.config["GOOGLE_CLIENT_ID"],
        client_secret=app.config["GOOGLE_CLIENT_SECRET"],
        access_token_url="https://oauth2.googleapis.com/token",
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        api_base_url="https://openidconnect.googleapis.com/v1/",
        client_kwargs={
            "scope": "openid email profile"
        },
        authorize_params={
            "access_type": "offline",
            "prompt": "consent"
        }
    )


# ---------- MODELS ----------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(50), default="local")  # local, google, apple
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Simple in-memory counters just for the UI (not persistent)
EMAILS_SCANNED = 0
SUSPICIOUS_FLAGGED = 0  # high risk emails


# ---------- HELPER FUNCTIONS ----------

HIGH_RISK_EXTS = {
    ".exe", ".js", ".vbs", ".scr", ".bat", ".cmd", ".ps1",
    ".lnk", ".hta", ".jar", ".msi", ".html", ".htm"
}
MEDIUM_RISK_EXTS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".docm", ".xlsm", ".pptm", ".zip", ".rar"
}
SUSPICIOUS_TLDS = {".ru", ".cn", ".su", ".xyz", ".top", ".club", ".info"}
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd"
}


def classify_attachment(filename: str, content: bytes):
    """Return dict with type, risk label, hashes, etc."""
    name = filename or "attachment.bin"
    lower = name.lower()
    ext = ""
    if "." in lower:
        ext = lower[lower.rfind("."):]

    # classify by extension
    if ext in HIGH_RISK_EXTS:
        risk_level = "High"
        risk_label = "High-risk file type"
    elif ext in MEDIUM_RISK_EXTS:
        risk_level = "Medium"
        risk_label = "Potentially risky document"
    else:
        risk_level = "Low"
        risk_label = "Common file type"

    if ext in {".pdf"}:
        file_type = "PDF document"
    elif ext in {".doc", ".docx", ".docm"}:
        file_type = "Word document"
    elif ext in {".xls", ".xlsx", ".xlsm"}:
        file_type = "Excel spreadsheet"
    elif ext in {".ppt", ".pptx", ".pptm"}:
        file_type = "PowerPoint"
    elif ext in {".zip", ".rar"}:
        file_type = "Archive"
    elif ext in {".png", ".jpg", ".jpeg", ".gif"}:
        file_type = "Image"
    else:
        file_type = ext[1:].upper() + " file" if ext else "Binary file"

    # hashes for forensics
    data = content or b""
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    vt_url = f"https://www.virustotal.com/gui/file/{sha256}"

    return {
        "filename": name,
        "ext": ext,
        "file_type": file_type,
        "risk_level": risk_level,
        "risk_label": risk_label,
        "size": len(data),
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "vt_url": vt_url,
    }


def extract_links_from_body(body: str, is_html: bool):
    """Very simple URL extraction from text/HTML."""
    import re

    links = []

    # http(s) URLs in plain text
    url_pattern = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)
    for match in url_pattern.finditer(body):
        url = match.group(0)
        links.append(url)

    # Deduplicate
    unique = []
    seen = set()
    for url in links:
        if url not in seen:
            seen.add(url)
            unique.append(url)

    indicators = []
    for url in unique:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
        except Exception:
            domain = ""
        tld = ""
        if "." in domain:
            tld = "." + domain.split(".")[-1]
        is_shortener = domain in SHORTENER_DOMAINS
        is_suspicious_tld = tld in SUSPICIOUS_TLDS
        indicators.append({
            "url": url,
            "domain": domain,
            "tld": tld,
            "is_shortener": is_shortener,
            "is_suspicious_tld": is_suspicious_tld,
        })
    return indicators


def parse_auth_results(headers: dict):
    """Parse SPF/DKIM/DMARC from Authentication-Results header, if present."""
    auth_header = headers.get("Authentication-Results", "") or headers.get("Authentication-Results-Original", "")
    auth_lower = auth_header.lower()

    def _extract(mech):
        if f"{mech}=pass" in auth_lower:
            return "pass"
        if f"{mech}=fail" in auth_lower:
            return "fail"
        if f"{mech}=softfail" in auth_lower:
            return "softfail"
        if f"{mech}=neutral" in auth_lower:
            return "neutral"
        if f"{mech}=none" in auth_lower:
            return "none"
        return "unknown"

    if not auth_header:
        return {"spf": "missing", "dkim": "missing", "dmarc": "missing"}

    return {
        "spf": _extract("spf"),
        "dkim": _extract("dkim"),
        "dmarc": _extract("dmarc"),
    }


def build_header_summary(headers: dict):
    raw_from = headers.get("From", "")
    name, email_addr = parseaddr(raw_from)
    reply_to = headers.get("Reply-To", "")
    return_path = headers.get("Return-Path", "")
    subject = headers.get("Subject", "")
    date = headers.get("Date", "")

    auth = parse_auth_results(headers)

    return {
        "from_raw": raw_from,
        "from_name": name,
        "from_email": email_addr,
        "reply_to": reply_to,
        "return_path": return_path,
        "subject": subject,
        "date": date,
        "auth": auth,
    }


def compute_risk_score(header_summary, attachments, link_indicators):
    score = 0
    reasons = []

    # From / Reply-To domain mismatch
    def domain_of(addr):
        if "@" in addr:
            return addr.split("@")[-1].lower().strip(">")
        return ""

    from_domain = domain_of(header_summary["from_email"])
    reply_domain = domain_of(header_summary["reply_to"]) if header_summary["reply_to"] else ""
    if reply_domain and reply_domain != from_domain:
        score += 15
        reasons.append(f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}).")

    # Auth results
    auth = header_summary["auth"]
    for mech in ("spf", "dkim", "dmarc"):
        val = auth.get(mech, "missing")
        if val in ("fail", "softfail"):
            score += 15
            reasons.append(f"{mech.upper()} status: {val}.")
        elif val in ("missing", "unknown", "none"):
            score += 5
            reasons.append(f"{mech.upper()} is missing or not clearly passing.")

    # Attachments
    for a in attachments:
        if a["risk_level"] == "High":
            score += 25
            reasons.append(f"High-risk attachment: {a['filename']} ({a['file_type']}).")
        elif a["risk_level"] == "Medium":
            score += 10
            reasons.append(f"Potentially risky attachment: {a['filename']} ({a['file_type']}).")

    # Links
    for link in link_indicators:
        if link["is_shortener"]:
            score += 8
            reasons.append(f"URL uses shortener domain: {link['domain']}.")
        if link["is_suspicious_tld"]:
            score += 8
            reasons.append(f"URL uses suspicious TLD: {link['tld']} in {link['domain']}.")

    # Normalize-ish
    if score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    # Deduplicate reasons
    unique_reasons = []
    seen = set()
    for r in reasons:
        if r not in seen:
            seen.add(r)
            unique_reasons.append(r)

    return score, level, unique_reasons


def parse_eml_bytes(content: bytes):
    """Parse a single EML and return a dict with all info + risk analysis."""
    msg = BytesParser(policy=default_policy).parsebytes(content)
    headers = dict(msg.items())

    # Attachments + insights
    attachments = []
    attachments_raw = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename()
            payload = part.get_payload(decode=True) or b""
            info = classify_attachment(filename, payload)
            attachments.append(info)
            attachments_raw.append({
                "filename": filename or "attachment.bin",
                "content": payload
            })

    # Body (prefer HTML)
    body = ""
    is_html = False
    body_rendered = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/html":
                body = part.get_payload(decode=True).decode(
                    part.get_content_charset() or "utf-8",
                    errors="ignore"
                )
                is_html = True
                body_rendered = body
                break
            elif ctype == "text/plain" and not body:
                body = part.get_payload(decode=True).decode(
                    part.get_content_charset() or "utf-8",
                    errors="ignore"
                )
    else:
        ctype = msg.get_content_type()
        if ctype == "text/html":
            body = msg.get_payload(decode=True).decode(
                msg.get_content_charset() or "utf-8",
                errors="ignore"
            )
            is_html = True
            body_rendered = body
        else:
            body = msg.get_payload(decode=True).decode(
                msg.get_content_charset() or "utf-8",
                errors="ignore"
            )

    header_summary = build_header_summary(headers)
    link_indicators = extract_links_from_body(body or "", is_html=is_html)
    risk_score, risk_level, risk_reasons = compute_risk_score(
        header_summary, attachments, link_indicators
    )

    result = {
        "headers": headers,
        "header_summary": header_summary,
        "attachments": attachments,
        "attachments_raw": attachments_raw,  # <--- raw bytes here
        "is_html": is_html,
        "body": body,
        "body_rendered": body_rendered if is_html else None,
        "raw_content": content.decode("utf-8", errors="ignore"),
        "links": link_indicators,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_reasons": risk_reasons,
    }
    return result
    """Parse a single EML and return a dict with all info + risk analysis."""
    msg = BytesParser(policy=default_policy).parsebytes(content)
    headers = dict(msg.items())

    # Attachments + insights
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename()
            payload = part.get_payload(decode=True) or b""
            info = classify_attachment(filename, payload)
            attachments.append(info)

    # Body (prefer HTML)
    body = ""
    is_html = False
    body_rendered = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/html":
                body = part.get_payload(decode=True).decode(
                    part.get_content_charset() or "utf-8",
                    errors="ignore"
                )
                is_html = True
                body_rendered = body
                break
            elif ctype == "text/plain" and not body:
                body = part.get_payload(decode=True).decode(
                    part.get_content_charset() or "utf-8",
                    errors="ignore"
                )
    else:
        ctype = msg.get_content_type()
        if ctype == "text/html":
            body = msg.get_payload(decode=True).decode(
                msg.get_content_charset() or "utf-8",
                errors="ignore"
            )
            is_html = True
            body_rendered = body
        else:
            body = msg.get_payload(decode=True).decode(
                msg.get_content_charset() or "utf-8",
                errors="ignore"
            )

    header_summary = build_header_summary(headers)
    link_indicators = extract_links_from_body(body or "", is_html=is_html)
    risk_score, risk_level, risk_reasons = compute_risk_score(
        header_summary, attachments, link_indicators
    )

    result = {
        "headers": headers,
        "header_summary": header_summary,
        "attachments": attachments,
        "is_html": is_html,
        "body": body,
        "body_rendered": body_rendered if is_html else None,
        "raw_content": content.decode("utf-8", errors="ignore"),
        "links": link_indicators,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_reasons": risk_reasons,
    }
    return result


# ---------- ROUTES ----------

@app.route("/", methods=["GET"])
def index():
    """
    Main page. If ?auth=login or ?auth=signup is present,
    we use it to decide which mode the auth modal opens in.
    """
    auth_mode = request.args.get("auth")  # "login", "signup", or None
    use_google = bool(app.config.get("GOOGLE_CLIENT_ID") and app.config.get("GOOGLE_CLIENT_SECRET"))

    return render_template(
        "index.html",
        result=None,
        batch_results=None,
        emails_scanned=EMAILS_SCANNED,
        users_signed_up=User.query.count(),
        suspicious_flagged=SUSPICIOUS_FLAGGED,
        auth_mode=auth_mode,
        use_google=use_google,
    )


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    global EMAILS_SCANNED, SUSPICIOUS_FLAGGED

    file = request.files.get("file")
    if not file or file.filename == "":
        flash("No file selected", "error")
        return redirect(url_for("index"))

    filename = file.filename
    content = file.read()

    use_google = bool(app.config.get("GOOGLE_CLIENT_ID") and app.config.get("GOOGLE_CLIENT_SECRET"))

    # ZIP batch mode
    if filename.lower().endswith(".zip"):
        batch_rows = []
        try:
            zf = zipfile.ZipFile(io.BytesIO(content))
        except Exception as e:
            flash(f"Failed to read ZIP file: {e}", "error")
            return redirect(url_for("index"))

        count_in_zip = 0
        for info in zf.infolist():
            if info.is_dir():
                continue
            if not info.filename.lower().endswith(".eml"):
                continue
            try:
                eml_bytes = zf.read(info)
                parsed = parse_eml_bytes(eml_bytes)
                count_in_zip += 1
                EMAILS_SCANNED += 1
                if parsed["risk_level"] == "High":
                    SUSPICIOUS_FLAGGED += 1

                header_summary = parsed["header_summary"]
                batch_rows.append({
                    "file_name": info.filename,
                    "subject": header_summary.get("subject", ""),
                    "from_email": header_summary.get("from_email", ""),
                    "risk_level": parsed["risk_level"],
                    "risk_score": parsed["risk_score"],
                    "attachments_count": len(parsed["attachments"]),
                })
            except Exception:
                batch_rows.append({
                    "file_name": info.filename,
                    "subject": "[Failed to parse]",
                    "from_email": "",
                    "risk_level": "N/A",
                    "risk_score": 0,
                    "attachments_count": 0,
                })
        if count_in_zip == 0:
            flash("ZIP file contained no .eml files.", "error")

        return render_template(
            "index.html",
            result=None,
            batch_results=batch_rows,
            emails_scanned=EMAILS_SCANNED,
            users_signed_up=User.query.count(),
            suspicious_flagged=SUSPICIOUS_FLAGGED,
            auth_mode=None,
            use_google=use_google,
        )

    # Single EML
    try:
        parsed = parse_eml_bytes(content)
    except Exception as e:
        flash(f"Failed to parse email: {e}", "error")
        return redirect(url_for("index"))

    EMAILS_SCANNED += 1
    if parsed["risk_level"] == "High":
        SUSPICIOUS_FLAGGED += 1

    # stash attachments in in-memory store so we can download them later
    req_id = os.urandom(8).hex()
    ATTACH_STORE[req_id] = {
        "created_at": datetime.utcnow(),
        "attachments": parsed.get("attachments_raw", [])
    }
    parsed.pop("attachments_raw", None)
    parsed["request_id"] = req_id

    return render_template(
        "index.html",
        result=parsed,
        batch_results=None,
        emails_scanned=EMAILS_SCANNED,
        users_signed_up=User.query.count(),
        suspicious_flagged=SUSPICIOUS_FLAGGED,
        auth_mode=None,
        use_google=use_google,
    )
@app.route("/download_attachment/<req_id>/<int:index>")
@login_required
def download_attachment(req_id, index):
  store = ATTACH_STORE.get(req_id)
  if not store:
      abort(404)
  attachments = store.get("attachments", [])
  if index < 0 or index >= len(attachments):
      abort(404)

  att = attachments[index]
  data = att.get("content") or b""
  filename = att.get("filename") or f"attachment-{index+1}.bin"

  return send_file(
      io.BytesIO(data),
      as_attachment=True,
      download_name=filename,
      mimetype="application/octet-stream"
  )


@app.route("/download_attachments/<req_id>")
@login_required
def download_attachments(req_id):
  store = ATTACH_STORE.get(req_id)
  if not store:
      abort(404)
  attachments = store.get("attachments", [])
  if not attachments:
      abort(404)

  buf = io.BytesIO()
  with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
      for idx, att in enumerate(attachments):
          filename = att.get("filename") or f"attachment-{idx+1}.bin"
          data = att.get("content") or b""
          zf.writestr(filename, data)
  buf.seek(0)

  return send_file(
      buf,
      as_attachment=True,
      download_name="attachments.zip",
      mimetype="application/zip"
  )
# ---------- LOCAL AUTH (email/password) ----------

@app.route("/signup", methods=["GET", "POST"])
def signup():
    """
    Email/password signup.
    GET: redirect to main page with modal in signup mode.
    POST: create user, log in, redirect to main page.
    """
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Email and password are required.", "error")
            return redirect(url_for("index", auth="signup"))

        existing = User.query.filter_by(email=email).first()
        if existing:
            flash("An account with that email already exists.", "error")
            return redirect(url_for("index", auth="signup"))

        user = User(email=email, provider="local")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        login_user(user, remember=True)
        return redirect(url_for("index"))

    return redirect(url_for("index", auth="signup"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Email/password login.
    GET: redirect to main page with modal in login mode.
    POST: authenticate, log in, redirect to main page.
    """
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash("Invalid email or password.", "error")
            return redirect(url_for("index", auth="login"))

        login_user(user, remember=True)
        return redirect(url_for("index"))

    return redirect(url_for("index", auth="login"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


# ---------- DEV BYPASS LOGIN (TEMPORARY FOR TESTING) ----------

@app.route("/dev-login")
def dev_login():
    """Temporary helper to log in as a test user without password."""
    dev_email = "dev@local.test"
    user = User.query.filter_by(email=dev_email).first()
    if not user:
        user = User(email=dev_email, provider="local")
        user.set_password(os.urandom(8).hex())
        db.session.add(user)
        db.session.commit()
    login_user(user, remember=True)
    flash("Dev login enabled (temporary bypass).", "info")
    return redirect(url_for("index"))


# ---------- GOOGLE OAUTH ----------

@app.route("/auth/google")
def auth_google():
    if "google" not in oauth._clients:
        flash("Google login is not configured.", "error")
        return redirect(url_for("index", auth="login"))

    redirect_uri = url_for("auth_google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def auth_google_callback():
    if "google" not in oauth._clients:
        flash("Google login is not configured.", "error")
        return redirect(url_for("index", auth="login"))

    token = oauth.google.authorize_access_token()
    userinfo = oauth.google.get("userinfo").json()

    email = userinfo.get("email", "").lower()
    if not email:
        flash("Google login failed: no email provided.", "error")
        return redirect(url_for("index", auth="login"))

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, provider="google")
        db.session.add(user)
        db.session.commit()

    login_user(user, remember=True)
    return redirect(url_for("index"))


# ---------- APPLE OAUTH (placeholder) ----------

@app.route("/auth/apple")
def auth_apple():
    flash("Sign in with Apple is not fully configured yet.", "info")
    return redirect(url_for("index", auth="login"))


@app.route("/auth/apple/callback")
def auth_apple_callback():
    flash("Apple callback placeholder.", "info")
    return redirect(url_for("index", auth="login"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=8000, debug=True)