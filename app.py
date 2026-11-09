"""
DevGuardians - Data Leak Checker
منصة فحص تسريب البيانات وإرشادات الأمان الرقمي
"""
import hashlib
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import quote

import requests
from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # python-dotenv اختياري
    pass

# ----------------------------------------------------------------- الإعدادات
DB_PATH = os.environ.get("DB_PATH", "database.db")
HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "").strip()
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "").strip()
USER_AGENT = "DevGuardians-LeakChecker"
HTTP_TIMEOUT = 8

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # الطلبات هنا صغيرة جدًا

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

# بيانات الوضع التجريبي (Demo) - ليست نتائج حقيقية
DEMO_LEAKED = {
    "admin@devguardians.com",
    "test.leak@example.com",
    "account-exists@hibp-integration-tests.com",
}
DEMO_BREACH = {
    "Name": "DemoBreach",
    "Title": "تسريب تجريبي (Demo)",
    "BreachDate": "2020-01-01",
    "DataClasses": ["Email addresses", "Passwords"],
}


# ------------------------------------------------------------- قاعدة البيانات
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                masked_email TEXT NOT NULL,
                is_leaked INTEGER NOT NULL,
                breach_count INTEGER NOT NULL,
                mode TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


init_db()


# ----------------------------------------------------------------- أدوات مساعدة
def mask_email(email: str) -> str:
    """ab***@gmail.com"""
    local, _, domain = email.partition("@")
    return f"{local[:2]}***@{domain}"


def valid_email(email: str) -> bool:
    return bool(email) and len(email) <= 254 and bool(EMAIL_RE.match(email))


# ------------------------------------------------------------------- CSRF
def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def verify_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "رمز الحماية (CSRF) غير صالح. أعد تحميل الصفحة وحاول مرة أخرى.")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


# -------------------------------------------------------- فحص كلمة المرور (حقيقي)
def check_password_pwned(password: str) -> int:
    """
    يستخدم Pwned Passwords API بآلية k-anonymity:
    يُرسَل أول 5 أحرف فقط من تجزئة SHA-1، وكلمة المرور نفسها لا تغادر الخادم.
    يرجع عدد مرات ظهورها في التسريبات (0 = لم تظهر).
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    resp = requests.get(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"Add-Padding": "true", "User-Agent": USER_AGENT},
        timeout=HTTP_TIMEOUT,
    )
    resp.raise_for_status()
    for line in resp.text.splitlines():
        tail, _, count = line.partition(":")
        if tail.strip() == suffix:
            return int(count.strip() or 0)
    return 0


# ----------------------------------------------------------- فحص الإيميل
def check_email_leaks(email: str):
    """
    يرجع (mode, breaches)
    mode = "live" عند وجود مفتاح HIBP، وإلا "demo".
    """
    if not HIBP_API_KEY:
        if email in DEMO_LEAKED:
            return "demo", [DEMO_BREACH]
        return "demo", []

    resp = requests.get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='')}",
        params={"truncateResponse": "false"},
        headers={"hibp-api-key": HIBP_API_KEY, "User-Agent": USER_AGENT},
        timeout=HTTP_TIMEOUT,
    )
    if resp.status_code == 404:  # غير موجود في أي تسريب
        return "live", []
    resp.raise_for_status()
    return "live", resp.json()


# ----------------------------------------------------------------- المسارات
@app.route("/")
def home():
    return render_template("index.html", live=bool(HIBP_API_KEY))


@app.route("/check-password", methods=["POST"])
def check_password():
    password = request.form.get("password", "")
    if not password or len(password) > 256:
        flash("أدخل كلمة مرور (حتى 256 حرفًا).", "warning")
        return redirect(url_for("home"))
    try:
        count = check_password_pwned(password)
    except requests.RequestException:
        flash("تعذّر الاتصال بخدمة الفحص. تأكد من الإنترنت وحاول لاحقًا.", "danger")
        return redirect(url_for("home"))
    # لا نخزّن كلمة المرور ولا نسجّل أي أثر لها
    return render_template("result.html", kind="password", count=count)


@app.route("/check-email", methods=["POST"])
def check_email():
    email = (request.form.get("email") or "").strip().lower()
    save = request.form.get("save_history") == "on"

    if not valid_email(email):
        flash("صيغة البريد الإلكتروني غير صحيحة.", "warning")
        return redirect(url_for("home"))

    try:
        mode, breaches = check_email_leaks(email)
    except requests.HTTPError as e:
        code = e.response.status_code if e.response is not None else 0
        msg = {
            401: "مفتاح HIBP غير صالح. راجع إعدادات HIBP_API_KEY.",
            429: "تجاوزت حد الطلبات. انتظر قليلًا ثم حاول مرة أخرى.",
        }.get(code, "حدث خطأ من خدمة الفحص. حاول لاحقًا.")
        flash(msg, "danger")
        return redirect(url_for("home"))
    except requests.RequestException:
        flash("تعذّر الاتصال بخدمة الفحص. تأكد من الإنترنت وحاول لاحقًا.", "danger")
        return redirect(url_for("home"))

    # لا نخزّن شيئًا إلا بموافقة المستخدم، ونخزّن النسخة المقنّعة فقط
    if save:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO scan_log (masked_email, is_leaked, breach_count, mode, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (mask_email(email), int(bool(breaches)), len(breaches), mode,
                 datetime.now(timezone.utc).isoformat(timespec="seconds")),
            )

    return render_template(
        "result.html", kind="email", email=mask_email(email),
        breaches=breaches, mode=mode, saved=save,
    )


# ------------------------------------------------- لوحة السجلات (محمية بكلمة مرور)
def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    if not ADMIN_PASSWORD_HASH:
        return render_template("login.html", disabled=True)
    if request.method == "POST":
        if check_password_hash(ADMIN_PASSWORD_HASH, request.form.get("password", "")):
            session.clear()
            session["is_admin"] = True
            return redirect(url_for("view_records"))
        flash("كلمة المرور غير صحيحة.", "danger")
    return render_template("login.html", disabled=False)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/records")
@admin_required
def view_records():
    with get_db() as conn:
        records = conn.execute(
            "SELECT id, masked_email, is_leaked, breach_count, mode, created_at"
            " FROM scan_log ORDER BY id DESC LIMIT 200"
        ).fetchall()
    return render_template("records.html", records=records)


if __name__ == "__main__":
    # لا تفعّل debug إلا محليًا: set FLASK_DEBUG=1
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
