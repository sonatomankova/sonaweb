import json
import os
import re
import secrets
import uuid
from functools import wraps
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
# DATA_DIR/UPLOAD_DIR sú nastaviteľné cez premenné prostredia, aby sa dali
# nasmerovať na trvalý disk na hostingu (lokálne ostávajú pôvodné priečinky).
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR / "data")))
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", str(BASE_DIR / "static" / "uploads")))
SITE_FILE = DATA_DIR / "site.json"
ADMIN_FILE = DATA_DIR / "admin.json"
SECRET_FILE = DATA_DIR / "secret.key"

DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Pri prvom spustení na prázdnom trvalom disku "zaseje" počiatočný obsah webu.
if not SITE_FILE.exists():
    _seed = BASE_DIR / "data" / "site.json"
    if _seed.exists() and _seed.resolve() != SITE_FILE.resolve():
        SITE_FILE.write_text(_seed.read_text(encoding="utf-8"), encoding="utf-8")

app = Flask(__name__)
app.jinja_env.globals["video_embed"] = lambda src: video_embed(src)


def get_secret_key():
    if SECRET_FILE.exists():
        return SECRET_FILE.read_text().strip()
    key = secrets.token_hex(32)
    SECRET_FILE.write_text(key)
    return key


app.secret_key = get_secret_key()

# Render (a naostro nastavené hostingy) nastavujú premennú RENDER — vtedy appka
# beží za HTTPS, tak session cookie zamkneme len na zabezpečené spojenie.
if os.environ.get("RENDER"):
    app.config["SESSION_COOKIE_SECURE"] = True


def load_site():
    with open(SITE_FILE, encoding="utf-8") as f:
        return json.load(f)


def save_site(data):
    with open(SITE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_admin():
    if not ADMIN_FILE.exists():
        password = secrets.token_urlsafe(9)
        admin = {"username": "sona", "password_hash": generate_password_hash(password, method="pbkdf2:sha256")}
        with open(ADMIN_FILE, "w", encoding="utf-8") as f:
            json.dump(admin, f, ensure_ascii=False, indent=2)
        print("=" * 60)
        print("Vytvorený prvý admin účet:")
        print("  meno:  sona")
        print(f"  heslo: {password}")
        print("(Zmeň si ho v Nastaveniach po prihlásení.)")
        print("=" * 60)
    with open(ADMIN_FILE, encoding="utf-8") as f:
        return json.load(f)


def save_admin(data):
    with open(ADMIN_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def phone_digits(phone, keep_plus=True):
    digits = "".join(re.findall(r"[\d+]", phone or ""))
    if not keep_plus:
        digits = digits.lstrip("+")
    return digits


def video_embed(src):
    """Rozpozná YouTube/Instagram odkaz a vráti embed; inak ide o priamy súbor videa."""
    s = (src or "").strip()
    m = re.search(r"(?:youtube\.com/(?:watch\?(?:[^#]*&)?v=|shorts/|embed/)|youtu\.be/)([A-Za-z0-9_-]{11})", s)
    if m:
        return {
            "kind": "iframe",
            "src": f"https://www.youtube.com/embed/{m.group(1)}",
            "thumb": f"https://img.youtube.com/vi/{m.group(1)}/hqdefault.jpg",
        }
    m = re.search(r"instagram\.com/(reels?|p|tv)/([A-Za-z0-9_-]+)", s)
    if m:
        kind = "reel" if m.group(1).startswith("reel") else m.group(1)
        return {"kind": "iframe", "src": f"https://www.instagram.com/{kind}/{m.group(2)}/embed"}
    return {"kind": "video", "src": s}


def today_sk():
    from datetime import date
    d = date.today()
    return f"{d.day}. {d.month}. {d.year}"


@app.context_processor
def inject_contact_helpers():
    site = load_site()
    return {
        "contact_tel": phone_digits(site["contact"]["phone"], keep_plus=True),
        "contact_wa": phone_digits(site["contact"]["phone"], keep_plus=False),
    }


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("admin_login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": get_csrf_token}


@app.before_request
def check_csrf():
    if request.method == "POST" and request.path.startswith("/admin/"):
        token = session.get("csrf_token", "")
        submitted = request.form.get("csrf_token", "")
        if not token or not secrets.compare_digest(token, submitted):
            abort(400, "Neplatný alebo vypršaný formulár, skús to znova.")


def save_upload(file_storage):
    """Uloží nahratý súbor do static/uploads a vráti jeho verejnú URL."""
    filename = secure_filename(file_storage.filename)
    ext = Path(filename).suffix
    unique_name = f"{uuid.uuid4().hex}{ext}"
    file_storage.save(UPLOAD_DIR / unique_name)
    return f"/static/uploads/{unique_name}"


# ---------- Verejný web ----------

@app.route("/")
def public_index():
    return render_template("index.html", site=load_site())


@app.route("/ocenenie.html")
def public_ocenenie():
    return render_template("ocenenie.html", site=load_site())


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(app.static_folder, "favicon.ico")


@app.route("/static/uploads/<path:filename>")
def uploaded_file(filename):
    # Nahraté súbory servírujeme z UPLOAD_DIR nezávisle od toho, či je to
    # priečinok vo vnútri appky (lokálne) alebo pripojený trvalý disk (hosting).
    return send_from_directory(UPLOAD_DIR, filename)


# ---------- Admin: prihlásenie ----------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        admin = load_admin()
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == admin["username"] and check_password_hash(admin["password_hash"], password):
            session["logged_in"] = True
            session["username"] = username
            return redirect(request.args.get("next") or url_for("admin_dashboard"))
        flash("Nesprávne meno alebo heslo.", "error")
    return render_template("admin_login.html")


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return redirect(url_for("public_index"))


@app.route("/admin/")
@login_required
def admin_dashboard():
    return redirect(url_for("admin_ponuky"))


# ---------- Admin: Ponuky ----------

@app.route("/admin/ponuky")
@login_required
def admin_ponuky():
    return render_template("admin_ponuky.html", site=load_site(), active="ponuky")


@app.route("/admin/ponuky/add", methods=["POST"])
@login_required
def admin_ponuky_add():
    site = load_site()
    img_url = request.form.get("img", "").strip()
    file = request.files.get("imgfile")
    if file and file.filename:
        img_url = save_upload(file)
    listing = {
        "href": request.form.get("href", "").strip(),
        "badge": request.form.get("badge", "Na predaj").strip(),
        "img": img_url,
        "alt": f"Fotka, {request.form.get('type', '').strip()}, {request.form.get('place', '').strip()}",
        "type": request.form.get("type", "").strip(),
        "place": request.form.get("place", "").strip(),
        "meta": request.form.get("meta", "").strip(),
    }
    site["listings"].append(listing)
    site["updated"] = f"Aktualizované: {today_sk()} · úplný a vždy aktuálny zoznam nájdete na bosen.sk"
    save_site(site)
    flash("Ponuka pridaná ✓", "ok")
    return redirect(url_for("admin_ponuky"))


@app.route("/admin/ponuky/<int:idx>/edit", methods=["POST"])
@login_required
def admin_ponuky_edit(idx):
    site = load_site()
    if idx < 0 or idx >= len(site["listings"]):
        abort(404)
    listing = site["listings"][idx]
    img_url = request.form.get("img", "").strip()
    file = request.files.get("imgfile")
    if file and file.filename:
        img_url = save_upload(file)
    elif not img_url:
        img_url = listing["img"]
    listing.update({
        "href": request.form.get("href", "").strip(),
        "badge": request.form.get("badge", "Na predaj").strip(),
        "img": img_url,
        "type": request.form.get("type", "").strip(),
        "place": request.form.get("place", "").strip(),
        "meta": request.form.get("meta", "").strip(),
    })
    site["updated"] = f"Aktualizované: {today_sk()} · úplný a vždy aktuálny zoznam nájdete na bosen.sk"
    save_site(site)
    flash("Ponuka uložená ✓", "ok")
    return redirect(url_for("admin_ponuky"))


@app.route("/admin/ponuky/<int:idx>/delete", methods=["POST"])
@login_required
def admin_ponuky_delete(idx):
    site = load_site()
    if 0 <= idx < len(site["listings"]):
        site["listings"].pop(idx)
        site["updated"] = f"Aktualizované: {today_sk()} · úplný a vždy aktuálny zoznam nájdete na bosen.sk"
        save_site(site)
        flash("Ponuka zmazaná ✓", "ok")
    return redirect(url_for("admin_ponuky"))


@app.route("/admin/ponuky/<int:idx>/move", methods=["POST"])
@login_required
def admin_ponuky_move(idx):
    site = load_site()
    direction = request.form.get("direction")
    listings = site["listings"]
    target = idx - 1 if direction == "up" else idx + 1
    if 0 <= idx < len(listings) and 0 <= target < len(listings):
        listings[idx], listings[target] = listings[target], listings[idx]
        save_site(site)
    return redirect(url_for("admin_ponuky"))


# ---------- Admin: Texty ----------

@app.route("/admin/texty", methods=["GET", "POST"])
@login_required
def admin_texty():
    site = load_site()
    if request.method == "POST":
        site["hero"]["kicker"] = request.form.get("kicker", "").strip()
        site["hero"]["text"] = request.form.get("hero_text", "").strip()
        site["contact"]["phone"] = request.form.get("phone", "").strip()
        site["contact"]["email"] = request.form.get("email", "").strip()
        site["contact"]["instagram"] = request.form.get("instagram", "").strip()
        site["contact"]["facebook"] = request.form.get("facebook", "").strip()
        save_site(site)
        flash("Texty uložené ✓", "ok")
        return redirect(url_for("admin_texty"))
    return render_template("admin_texty.html", site=site, active="texty")


VIDEO_EXTENSIONS = {".mp4", ".webm", ".mov", ".m4v"}


@app.route("/admin/texty/hero-bg", methods=["POST"])
@login_required
def admin_hero_bg():
    file = request.files.get("bg_file")
    if not file or not file.filename:
        flash("Nevybrala si žiadny súbor.", "error")
        return redirect(url_for("admin_texty"))
    site = load_site()
    ext = Path(secure_filename(file.filename)).suffix.lower()
    site["hero"]["bg_type"] = "video" if ext in VIDEO_EXTENSIONS else "image"
    site["hero"]["bg_src"] = save_upload(file)
    save_site(site)
    flash("Pozadie uložené ✓", "ok")
    return redirect(url_for("admin_texty"))


@app.route("/admin/texty/about/add", methods=["POST"])
@login_required
def admin_about_add():
    site = load_site()
    site["about"].append("")
    save_site(site)
    return redirect(url_for("admin_texty"))


@app.route("/admin/texty/about/<int:idx>/save", methods=["POST"])
@login_required
def admin_about_save(idx):
    site = load_site()
    if 0 <= idx < len(site["about"]):
        site["about"][idx] = request.form.get("text", "").strip()
        save_site(site)
        flash("Odstavec uložený ✓", "ok")
    return redirect(url_for("admin_texty"))


@app.route("/admin/texty/about/<int:idx>/delete", methods=["POST"])
@login_required
def admin_about_delete(idx):
    site = load_site()
    if 0 <= idx < len(site["about"]):
        site["about"].pop(idx)
        save_site(site)
    return redirect(url_for("admin_texty"))


@app.route("/admin/texty/about/<int:idx>/move", methods=["POST"])
@login_required
def admin_about_move(idx):
    site = load_site()
    direction = request.form.get("direction")
    about = site["about"]
    target = idx - 1 if direction == "up" else idx + 1
    if 0 <= idx < len(about) and 0 <= target < len(about):
        about[idx], about[target] = about[target], about[idx]
        save_site(site)
    return redirect(url_for("admin_texty"))


# ---------- Admin: Marketing videá ----------

@app.route("/admin/videa")
@login_required
def admin_videa():
    return render_template("admin_videa.html", site=load_site(), active="videa")


@app.route("/admin/videa/heading", methods=["POST"])
@login_required
def admin_videa_heading():
    site = load_site()
    site["marketing_heading"] = request.form.get("heading", "").strip()
    site["marketing_intro"] = request.form.get("intro", "").strip()
    save_site(site)
    flash("Nadpis a text uložené ✓", "ok")
    return redirect(url_for("admin_videa"))


@app.route("/admin/videa/add", methods=["POST"])
@login_required
def admin_videa_add():
    site = load_site()
    src = request.form.get("src", "").strip()
    file = request.files.get("videofile")
    if file and file.filename:
        src = save_upload(file)
    site["marketing_videos"].append({
        "title": request.form.get("title", "").strip(),
        "src": src,
    })
    save_site(site)
    flash("Video pridané ✓", "ok")
    return redirect(url_for("admin_videa"))


@app.route("/admin/videa/<int:idx>/edit", methods=["POST"])
@login_required
def admin_videa_edit(idx):
    site = load_site()
    if idx < 0 or idx >= len(site["marketing_videos"]):
        abort(404)
    video = site["marketing_videos"][idx]
    src = request.form.get("src", "").strip()
    file = request.files.get("videofile")
    if file and file.filename:
        src = save_upload(file)
    elif not src:
        src = video["src"]
    video.update({
        "title": request.form.get("title", "").strip(),
        "src": src,
    })
    save_site(site)
    flash("Video uložené ✓", "ok")
    return redirect(url_for("admin_videa"))


@app.route("/admin/videa/<int:idx>/delete", methods=["POST"])
@login_required
def admin_videa_delete(idx):
    site = load_site()
    if 0 <= idx < len(site["marketing_videos"]):
        site["marketing_videos"].pop(idx)
        save_site(site)
        flash("Video zmazané ✓", "ok")
    return redirect(url_for("admin_videa"))


@app.route("/admin/videa/<int:idx>/move", methods=["POST"])
@login_required
def admin_videa_move(idx):
    site = load_site()
    direction = request.form.get("direction")
    videos = site["marketing_videos"]
    target = idx - 1 if direction == "up" else idx + 1
    if 0 <= idx < len(videos) and 0 <= target < len(videos):
        videos[idx], videos[target] = videos[target], videos[idx]
        save_site(site)
    return redirect(url_for("admin_videa"))


# ---------- Admin: Recenzie ----------

@app.route("/admin/recenzie")
@login_required
def admin_recenzie():
    return render_template("admin_recenzie.html", site=load_site(), active="recenzie")


@app.route("/admin/recenzie/add", methods=["POST"])
@login_required
def admin_recenzie_add():
    site = load_site()
    site["reviews"].append({
        "avatar": request.form.get("avatar", "").strip(),
        "stars": int(request.form.get("stars", 5)),
        "text": request.form.get("text", "").strip(),
        "author": request.form.get("author", "").strip(),
    })
    save_site(site)
    flash("Recenzia pridaná ✓", "ok")
    return redirect(url_for("admin_recenzie"))


@app.route("/admin/recenzie/<int:idx>/edit", methods=["POST"])
@login_required
def admin_recenzie_edit(idx):
    site = load_site()
    if idx < 0 or idx >= len(site["reviews"]):
        abort(404)
    site["reviews"][idx] = {
        "avatar": request.form.get("avatar", "").strip(),
        "stars": int(request.form.get("stars", 5)),
        "text": request.form.get("text", "").strip(),
        "author": request.form.get("author", "").strip(),
    }
    save_site(site)
    flash("Recenzia uložená ✓", "ok")
    return redirect(url_for("admin_recenzie"))


@app.route("/admin/recenzie/<int:idx>/delete", methods=["POST"])
@login_required
def admin_recenzie_delete(idx):
    site = load_site()
    if 0 <= idx < len(site["reviews"]):
        site["reviews"].pop(idx)
        save_site(site)
        flash("Recenzia zmazaná ✓", "ok")
    return redirect(url_for("admin_recenzie"))


@app.route("/admin/recenzie/<int:idx>/move", methods=["POST"])
@login_required
def admin_recenzie_move(idx):
    site = load_site()
    direction = request.form.get("direction")
    reviews = site["reviews"]
    target = idx - 1 if direction == "up" else idx + 1
    if 0 <= idx < len(reviews) and 0 <= target < len(reviews):
        reviews[idx], reviews[target] = reviews[target], reviews[idx]
        save_site(site)
    return redirect(url_for("admin_recenzie"))


# ---------- Admin: Nastavenia ----------

@app.route("/admin/nastavenia", methods=["GET", "POST"])
@login_required
def admin_nastavenia():
    admin = load_admin()
    if request.method == "POST":
        current = request.form.get("current_password", "")
        if not check_password_hash(admin["password_hash"], current):
            flash("Aktuálne heslo nesedí.", "error")
            return redirect(url_for("admin_nastavenia"))
        new_username = request.form.get("username", "").strip()
        new_password = request.form.get("new_password", "").strip()
        if new_username:
            admin["username"] = new_username
        if new_password:
            admin["password_hash"] = generate_password_hash(new_password, method="pbkdf2:sha256")
        save_admin(admin)
        session["username"] = admin["username"]
        flash("Nastavenia uložené ✓", "ok")
        return redirect(url_for("admin_nastavenia"))
    return render_template("admin_nastavenia.html", admin=admin, active="nastavenia")


if __name__ == "__main__":
    load_admin()  # zabezpečí vytvorenie prvého účtu pri prvom spustení
    app.run(debug=True, port=5050, host="0.0.0.0")
