"""
DevGuardians - Data Leak Checker
منصة فحص تسريب البيانات وإرشادات الأمان الرقمي
"""
import hashlib
import ipaddress
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import quote, urlparse

import phonenumbers
import requests
from phonenumbers import carrier, geocoder
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
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
USER_AGENT = "DevGuardians-LeakChecker"
HTTP_TIMEOUT = 8

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # أقصى حجم للملف المفحوص

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
    return render_template("index.html", live=bool(HIBP_API_KEY), vt=bool(VT_API_KEY))


@app.route("/check-password", methods=["POST"])
def check_password():
    password = request.form.get("password", "")
    if not password or len(password) > 256:
        flash("اكتب كلمة المرور (حتى 256 حرفًا).", "warning")
        return redirect(url_for("home"))
    try:
        count = check_password_pwned(password)
    except requests.RequestException:
        flash("ما قدرنا نتصل بخدمة الفحص. تأكد من الإنترنت وحاول مرة ثانية.", "danger")
        return redirect(url_for("home"))
    # لا نخزّن كلمة المرور ولا نسجّل أي أثر لها
    return render_template("result.html", kind="password", count=count)


@app.route("/check-email", methods=["POST"])
def check_email():
    email = (request.form.get("email") or "").strip().lower()
    save = request.form.get("save_history") == "on"

    if not valid_email(email):
        flash("الإيميل غير صحيح. تأكد من كتابته.", "warning")
        return redirect(url_for("home"))

    try:
        mode, breaches = check_email_leaks(email)
    except requests.HTTPError as e:
        code = e.response.status_code if e.response is not None else 0
        msg = {
            401: "مفتاح الخدمة غير صحيح. راجع HIBP_API_KEY في ملف .env.",
            429: "أرسلت طلبات كثيرة. انتظر قليلًا ثم حاول مرة ثانية.",
        }.get(code, "حصل خطأ في خدمة الفحص. حاول لاحقًا.")
        flash(msg, "danger")
        return redirect(url_for("home"))
    except requests.RequestException:
        flash("ما قدرنا نتصل بخدمة الفحص. تأكد من الإنترنت وحاول مرة ثانية.", "danger")
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


# --------------------------------------------------------------- فحص الرابط
# فحص محلي بالقواعد فقط. لا نفتح الرابط ولا نرسل أي طلب إليه.
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly", "rb.gy"}
RISKY_TLDS = {"zip", "mov", "xyz", "top", "click", "tk", "ml", "ga", "cf", "gq", "work"}
BAIT_WORDS = ("login", "verify", "update", "secure", "account", "bank", "password", "wallet", "gift")


def analyze_url(raw: str):
    url = raw.strip()
    if not url or len(url) > 2048 or any(c.isspace() for c in url):
        return None
    has_scheme = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url)
    parsed = urlparse(url if has_scheme else "https://" + url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    host = parsed.hostname.lower()
    reasons = []
    if parsed.scheme == "http":
        reasons.append((1, "الرابط غير مشفّر (HTTP)"))
    try:
        ipaddress.ip_address(host)
        reasons.append((2, "الرابط يستخدم رقم IP بدل اسم موقع"))
    except ValueError:
        pass
    if parsed.username:
        reasons.append((2, "فيه علامة @ وقد تخفي الوجهة الحقيقية"))
    if "xn--" in host:
        reasons.append((2, "اسم الموقع بحروف مموّهة قد تقلّد موقعًا معروفًا"))
    if host in SHORTENERS:
        reasons.append((1, "رابط مختصر يخفي الوجهة الحقيقية"))
    if host.rsplit(".", 1)[-1] in RISKY_TLDS:
        reasons.append((1, "امتداد الموقع شائع في الاحتيال"))
    if host.count(".") >= 4:
        reasons.append((1, "فيه نطاقات فرعية كثيرة"))
    if len(url) > 100:
        reasons.append((1, "الرابط طويل بشكل غير عادي"))
    if any(w in url.lower() for w in BAIT_WORDS):
        reasons.append((1, "فيه كلمات يستخدمها المحتالون مثل login أو verify"))
    score = sum(points for points, _ in reasons)
    level = "safe" if score == 0 else "warn" if score <= 2 else "danger"
    return {"host": host, "level": level, "reasons": [t for _, t in reasons]}


# ------------------------------------------------------------ فحص رقم الهاتف
PT = phonenumbers.PhoneNumberType
PHONE_TYPES = {
    PT.MOBILE: "جوال", PT.FIXED_LINE: "خط ثابت", PT.FIXED_LINE_OR_MOBILE: "ثابت أو جوال",
    PT.TOLL_FREE: "رقم مجاني", PT.PREMIUM_RATE: "رقم برسوم مرتفعة",
    PT.VOIP: "رقم إنترنت (VoIP)", PT.PERSONAL_NUMBER: "رقم شخصي",
}


def analyze_phone(raw: str):
    """يرجع dict، أو "need_plus"، أو None إذا تعذّر قراءة الرقم."""
    raw = raw.strip()
    if not raw.startswith("+"):
        return "need_plus"
    try:
        num = phonenumbers.parse(raw, None)
    except phonenumbers.NumberParseException:
        return None
    valid = phonenumbers.is_valid_number(num)
    info = {"valid": valid,
            "formatted": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}
    if valid:
        country = geocoder.country_name_for_number(num, "ar") or geocoder.country_name_for_number(num, "en")
        place = geocoder.description_for_valid_number(num, "ar")
        info.update(
            country=country,
            place=place if place and place != country else "",
            carrier=carrier.name_for_number(num, "ar"),
            ptype=PHONE_TYPES.get(phonenumbers.number_type(num), "غير محدد"),
            voip=phonenumbers.number_type(num) == PT.VOIP,
        )
    return info


# ----------------------------------------------------------------- فحص الملف
RISKY_EXT = {"exe", "scr", "bat", "cmd", "js", "vbs", "ps1", "msi", "jar", "apk", "lnk", "dll", "hta", "iso"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "zip"}


def vt_lookup(sha256: str):
    """يرجع (الحالة، الإحصائيات). الحالات: unknown / found / error"""
    try:
        resp = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                            headers={"x-apikey": VT_API_KEY, "User-Agent": USER_AGENT},
                            timeout=HTTP_TIMEOUT)
    except requests.RequestException:
        return "error", None
    if resp.status_code == 404:
        return "unknown", None
    if resp.status_code != 200:
        return "error", None
    try:
        return "found", resp.json()["data"]["attributes"]["last_analysis_stats"]
    except (KeyError, ValueError):
        return "error", None


@app.errorhandler(413)
def too_large(_):
    flash("الملف كبير. الحد الأقصى 25 ميغابايت.", "warning")
    return redirect(url_for("home"))


@app.route("/check-link", methods=["POST"])
def check_link():
    result = analyze_url(request.form.get("url", ""))
    if result is None:
        flash("اكتب رابطًا صحيحًا مثل https://example.com", "warning")
        return redirect(url_for("home"))
    return render_template("result.html", kind="link", **result)


@app.route("/check-phone", methods=["POST"])
def check_phone():
    info = analyze_phone(request.form.get("phone", ""))
    if info == "need_plus":
        flash("ابدأ الرقم بعلامة + ورمز الدولة، مثل +966501234567", "warning")
        return redirect(url_for("home"))
    if info is None:
        flash("لم نستطع قراءة الرقم. تأكد من كتابته بشكل صحيح.", "warning")
        return redirect(url_for("home"))
    return render_template("result.html", kind="phone", **info)


@app.route("/check-file", methods=["POST"])
def check_file():
    f = request.files.get("file")
    if not f or not f.filename:
        flash("اختر ملفًا أولًا.", "warning")
        return redirect(url_for("home"))
    digest, size = hashlib.sha256(), 0
    for chunk in iter(lambda: f.stream.read(65536), b""):  # لا نحفظ الملف أبدًا
        digest.update(chunk)
        size += len(chunk)
    sha256 = digest.hexdigest()
    parts = os.path.basename(f.filename).lower().split(".")
    ext = parts[-1] if len(parts) > 1 else ""
    warnings = []
    if ext in RISKY_EXT:
        warnings.append("هذا ملف تنفيذي أو سكربت. لا تفتحه إلا إذا كنت واثقًا من مصدره.")
        if len(parts) > 2 and parts[-2] in DOC_EXT:
            warnings.append("اسمه يخدع بامتداد مزدوج مثل file.pdf.exe، وهذه حيلة معروفة.")
    status, stats = vt_lookup(sha256) if VT_API_KEY else ("nokey", None)
    return render_template("result.html", kind="file", filename=os.path.basename(f.filename),
                           size_kb=round(size / 1024, 1), sha256=sha256, warnings=warnings,
                           vt_status=status, stats=stats)


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
