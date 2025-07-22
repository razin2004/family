import os
import re
import random
import string
from base64 import b64decode
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_mail import Mail, Message
import sqlite3
from datetime import timedelta
from flask import session
from flask import Flask, request
from flask_babel import Babel, _
from flask import Flask, render_template, jsonify, request
import sqlite3
import cloudinary
import cloudinary.uploader
import cloudinary.api
from flask import Flask, request, session
from flask_babel import Babel, _
from datetime import datetime
from werkzeug.security import check_password_hash

cloudinary.config(
    cloud_name="dxdy5tsju",
    api_key="623749966712191",
    api_secret="738I7WE3S60JYB5IH4eD4Lvrddg"
)

# SUPER ADMIN email
SUPER_ADMIN_EMAIL = "doctorbooksystem@gmail.com"


app = Flask(__name__)
app.secret_key = "your_secret_key"
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'
babel = Babel(app)



@babel.localeselector
def get_locale():
    lang = request.args.get('lang')
    if lang in ['en', 'ml']:
        session['lang'] = lang
        return lang
    return session.get('lang', 'en')

@app.before_request
def set_language():
    lang = request.args.get('lang')
    if lang in ['en', 'ml']:
        session['lang'] = lang

@app.route('/set_language/<lang_code>')
def set_language(lang_code):
    session['lang'] = lang_code
    return redirect(request.referrer or url_for('login'))

@app.context_processor
def inject_locale():
    return dict(get_locale=get_locale)



@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=15)

# Flask-Login setup
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Flask-Mail setup
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'doctorbooksystem@gmail.com'
app.config['MAIL_PASSWORD'] = 'wsjv lkjz dffv icwf'
app.config['MAIL_DEFAULT_SENDER'] = 'doctorbooksystem@gmail.com'
mail = Mail(app)





# # Ensure selfies folder exists
# if not os.path.exists("selfies"):
#     os.mkdir("selfies")

# # Serve selfies as static files
# @app.route("/selfies/<path:filename>")
# def selfies(filename):
#     return send_from_directory("selfies", filename)

# Helper: DB connection + create tables if missing
def get_db():
    conn = sqlite3.connect("family.db")
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            name TEXT,
            selfie_path TEXT,
            role TEXT,
            is_verified INTEGER,
            is_approved INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            otp_code TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS family_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            dob TEXT,
            gender TEXT,
            blood_group TEXT,
            job_or_education TEXT,
            selfie_path TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS relationships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id INTEGER,
            relation TEXT,
            related_to INTEGER
        )
    """)
    conn.commit()
    return conn

# User class
class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.email = row["email"]
        self.name = row["name"]
        self.role = row["role"]
        self.is_verified = row["is_verified"]
        self.is_approved = row["is_approved"]

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return User(user) if user else None

# Decorator to check allowed roles
from functools import wraps

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role not in roles:
                flash("Access denied.")
                return redirect(url_for("tree"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ---------------------
# Routes
# ---------------------

@app.route("/")
def home():
    return redirect(url_for("login"))


from flask import request, render_template, redirect, url_for, flash, session
from flask_login import login_user, current_user
from werkzeug.security import check_password_hash
from flask_babel import _  # for multilingual support
import random
import string

SUPER_ADMIN_EMAIL = "razinmuhammed1999@gmail.com"

@app.route("/login", methods=["GET", "POST"])
def login():
    db = get_db()
    otp_sent = False
    lang = session.get("lang", "en")

    # GET params
    email = request.args.get("email")
    otp_input = request.args.get("otp")
    username_input = request.args.get("username")
    action = request.args.get("action")

    if action == "send_otp" and email:
        otp_sent = True

    if request.method == "POST":
        action = request.form.get("action")
        email = request.form.get("email")
        otp_input = request.form.get("otp")
        username_input = request.form.get("username")
        password_input = request.form.get("password")

        if action == "send_otp":
            if not email:
                flash(_("Please enter your email."))
                return render_template("single_page.html", mode="login", lang=lang)

            user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

            if not user:
                # Auto-create unverified user
                role = "Admin" if email == SUPER_ADMIN_EMAIL else "Viewer"
                db.execute("INSERT INTO users (email, is_verified, is_approved, role) VALUES (?, 0, 0, ?)", (email, role))
                db.commit()

            # Generate OTP
            otp = ''.join(random.choices(string.digits, k=6))
            db.execute("DELETE FROM otps WHERE email=?", (email,))
            db.execute("INSERT INTO otps (email, otp_code) VALUES (?, ?)", (email, otp))
            db.commit()

            try:
                msg = Message("Your OTP Code", recipients=[email])
                msg.body = f"Your OTP is: {otp}"
                mail.send(msg)
                flash(_("OTP sent to your email."))
            except Exception as e:
                flash(_("Email error: ") + str(e))

            return render_template("single_page.html", mode="login", lang=lang, otp_sent=True, email=email)

        elif action == "login":
            # OTP Login
            if email and otp_input:
                otp_row = db.execute("SELECT * FROM otps WHERE email=? AND otp_code=?", (email, otp_input)).fetchone()
                if otp_row:
                    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
                    if user["email"] == SUPER_ADMIN_EMAIL:
                        db.execute("UPDATE users SET is_verified=1, is_approved=1 WHERE email=?", (email,))
                    else:
                        db.execute("UPDATE users SET is_verified=1 WHERE email=?", (email,))
                    db.commit()

                    if not user["name"]:
                        return redirect(url_for("first_profile", email=email))

                    if user["role"] == "Admin" and user["email"] == SUPER_ADMIN_EMAIL:
                        login_user(User(user), remember=True)
                        flash(_("Logged in as super admin."))
                        return redirect(url_for("dashboard", lang=lang))

                    elif user["is_approved"]:
                        login_user(User(user), remember=True)
                        flash(_("Login successful."))
                        return redirect(url_for("dashboard", lang=lang))
                    else:
                        return render_template("single_page.html", mode="pending", lang=lang)

                else:
                    flash(_("Invalid OTP."))
                    return render_template("single_page.html", mode="login", lang=lang, otp_sent=True, email=email)

            # Username/Password Login (Viewer only)
            elif username_input and password_input:
                user = db.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username_input,)).fetchone()
                if not user:
                    flash(_("Invalid username."))
                    return render_template("single_page.html", mode="login", lang=lang)

                if not check_password_hash(user["password"], password_input):
                    flash(_("Incorrect password."))
                    return render_template("single_page.html", mode="login", lang=lang, username=username_input)

                if user["role"] == "Viewer":
                    login_user(User(user), remember=True)
                    flash(_("Login successful."))
                    return redirect(url_for("dashboard", lang=lang))
                else:
                    flash(_("Only viewer accounts can use username login."))

        else:
            flash(_("Missing login credentials."))

    return render_template("single_page.html", mode="login", lang=lang, otp_sent=otp_sent, email=email, username=username_input,user=current_user)


@app.route('/manage_viewers')
@login_required
def manage_viewers():
    if current_user.email != 'razinmuhammed1999@gmail.com':
        return redirect(url_for('dashboard'))

    conn = sqlite3.connect('family.db')
    c = conn.cursor()
    c.execute("SELECT * FROM login_users")
    rows = c.fetchall()
    conn.close()

    viewer_accounts = [
        {
            'id': row[0],
            'username': row[1],
            'password': row[2],
            'created_by': row[3],
            'role': row[4],
            'created_at': row[5]  # Make sure this column exists
        } for row in rows
    ]

    return render_template("manage_viewers.html", viewer_accounts=viewer_accounts)



@app.route("/create_viewer_user", methods=["GET", "POST"])
@login_required
def create_viewer_user():
    if current_user.role != "Admin":
        flash("Only admin can create users.")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("Username and password required.")
        else:
            db = get_db()
            existing = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if existing:
                flash("Username already exists.")
            else:
                db.execute("INSERT INTO users (username, password, role, is_verified, is_approved) VALUES (?, ?, 'Viewer', 1, 1)",
                           (username, password))
                db.commit()
                flash("Viewer user created successfully.")

    return render_template("single_page.html")

@app.route("/verify_otp/<email>", methods=["GET", "POST"])
def verify_otp(email):
    db = get_db()
    if request.method == "POST":
        otp_input = request.form.get("otp")
        if not otp_input:
            flash("Enter the OTP.")
            return render_template("single_page.html", mode="verify_otp", email=email,
      
   
    user=current_user)

        otp_row = db.execute(
            "SELECT * FROM otps WHERE email=? AND otp_code=?",
            (email, otp_input)
        ).fetchone()

        if otp_row:
            user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

            if user["email"] == SUPER_ADMIN_EMAIL:
                db.execute(
                    "UPDATE users SET is_verified=1, is_approved=1 WHERE email=?",
                    (email,)
                )
                db.commit()
                user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

            db.execute("UPDATE users SET is_verified=1 WHERE email=?", (email,))
            db.commit()

            if not user["name"]:
                return redirect(url_for("first_profile", email=email))

            if user["role"] == "Admin" and user["email"] == SUPER_ADMIN_EMAIL:
                login_user(User(user), remember=True)
                flash("Logged in as super admin.")
                return redirect(url_for("dashboard"))
            elif user["is_approved"]:
                login_user(User(user), remember=True)
                flash("Login successful.")
                return redirect(url_for("dashboard"))
            else:
                return render_template("single_page.html", mode="pending",
      
   
    user=current_user)
        else:
            flash("Invalid OTP.")
            return render_template("single_page.html", mode="verify_otp", email=email,
      
   
    user=current_user)

    return render_template("single_page.html", mode="verify_otp", email=email,
      
    
    user=current_user)

@app.route("/first_profile/<email>", methods=["GET", "POST"])
def first_profile(email):
    db = get_db()
    if request.method == "POST":
        name = request.form.get("name")
        selfie_data = request.form.get("selfie")

        if not name or not selfie_data:
            flash("All fields required.")
            return render_template("single_page.html", mode="first_profile", email=email,
      
    
    user=current_user)

        import io
        from base64 import b64decode

        img_str = re.search(r'base64,(.*)', selfie_data).group(1)
        img_bytes = b64decode(img_str)

# Use BytesIO stream for Cloudinary upload
        img_stream = io.BytesIO(img_bytes)
        result = cloudinary.uploader.upload(img_stream, resource_type="image")
        filepath = result.get("secure_url")


        db.execute(
            "UPDATE users SET name=?, selfie_path=? WHERE email=?",
            (name, filepath, email)
        )
        db.commit()

        try:
            msg = Message(
                "New Family Portal Registration",
                recipients=[SUPER_ADMIN_EMAIL]
            )
            msg.body = f"New user registered:\nName: {name}\nEmail: {email}\nApprove via admin panel."
            with open(filepath, "rb") as f:
                msg.attach("selfie.png", "image/png", f.read())
            mail.send(msg)
        except Exception as e:
            flash(f"Failed to notify admin: {e}")

        return render_template("single_page.html", mode="pending",
      
    
    user=current_user)

    return render_template("single_page.html", mode="first_profile", email=email,
      
    
    user=current_user)




import os
import re
import random
import string
from base64 import b64decode
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_mail import Mail, Message
import sqlite3
from datetime import timedelta
from flask import session
from flask import Flask, request
from flask_babel import Babel, _
from flask import Flask, render_template, jsonify, request
import sqlite3
import cloudinary
import cloudinary.uploader
import cloudinary.api
from flask import Flask, request, session
from flask_babel import Babel, _
from datetime import timedelta

cloudinary.config(
    cloud_name="dxdy5tsju",
    api_key="623749966712191",
    api_secret="738I7WE3S60JYB5IH4eD4Lvrddg"
)

# SUPER ADMIN email
SUPER_ADMIN_EMAIL = "doctorbooksystem@gmail.com"


app = Flask(__name__)
app.secret_key = "your_secret_key"
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'
babel = Babel(app)



@babel.localeselector
def get_locale():
    lang = request.args.get('lang')
    if lang in ['en', 'ml']:
        session['lang'] = lang
        return lang
    return session.get('lang', 'en')

@app.before_request
def set_language():
    lang = request.args.get('lang')
    if lang in ['en', 'ml']:
        session['lang'] = lang

@app.route('/set_language/<lang_code>')
def set_language(lang_code):
    session['lang'] = lang_code
    return redirect(request.referrer or url_for('login'))

@app.context_processor
def inject_locale():
    return dict(get_locale=get_locale)



@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=15)

# Flask-Login setup
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Flask-Mail setup
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'doctorbooksystem@gmail.com'
app.config['MAIL_PASSWORD'] = 'wsjv lkjz dffv icwf'
app.config['MAIL_DEFAULT_SENDER'] = 'doctorbooksystem@gmail.com'
mail = Mail(app)





# # Ensure selfies folder exists
# if not os.path.exists("selfies"):
#     os.mkdir("selfies")

# # Serve selfies as static files
# @app.route("/selfies/<path:filename>")
# def selfies(filename):
#     return send_from_directory("selfies", filename)

# Helper: DB connection + create tables if missing
def get_db():
    conn = sqlite3.connect("family.db")
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            name TEXT,
            selfie_path TEXT,
            role TEXT,
            is_verified INTEGER,
            is_approved INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            otp_code TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS family_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            dob TEXT,
            gender TEXT,
            blood_group TEXT,
            job_or_education TEXT,
            selfie_path TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS relationships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id INTEGER,
            relation TEXT,
            related_to INTEGER
        )
    """)
    conn.commit()
    return conn

# User class
class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.email = row["email"]
        self.name = row["name"]
        self.role = row["role"]
        self.is_verified = row["is_verified"]
        self.is_approved = row["is_approved"]

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return User(user) if user else None

# Decorator to check allowed roles
from functools import wraps

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role not in roles:
                flash("Access denied.")
                return redirect(url_for("tree"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ---------------------
# Routes
# ---------------------

@app.route("/")
def home():
    return redirect(url_for("login"))



@app.route("/login", methods=["GET", "POST"])
def login():
    db = get_db()
    otp_sent = False
    lang = session.get("lang", "en")

    # Pre-fill from query string if redirected via lang switch
    email = request.args.get("email") or None
    otp_input = request.args.get("otp") or None
    action = request.args.get("action") or None
    # Ensure otp_sent stays True when switching language after sending OTP
    if action == "send_otp" and email:
        otp_sent = True


    if request.method == "POST":
        email = request.form.get("email")
        otp_input = request.form.get("otp")
        action = request.form.get("action")

        if action == "send_otp":
            if not email:
                flash(_("Please enter your email."))
                return render_template("single_page.html", mode="login", lang=lang, user=current_user)

            user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

            if not user:
                role = "Admin" if email == SUPER_ADMIN_EMAIL else "Viewer"
                db.execute(
                    "INSERT INTO users (email, is_verified, is_approved, role) VALUES (?, 0, 0, ?)",
                    (email, role)
                )
                db.commit()

            otp = ''.join(random.choices(string.digits, k=6))
            db.execute("DELETE FROM otps WHERE email=?", (email,))
            db.execute("INSERT INTO otps (email, otp_code) VALUES (?, ?)", (email, otp))
            db.commit()

            try:
                msg = Message("Your OTP Code", recipients=[email])
                msg.body = f"Your OTP is: {otp}"
                mail.send(msg)
                flash(_("OTP sent to your email."))
            except Exception as e:
                flash(_("Email error: ") + str(e))
                return render_template("single_page.html", lang=lang, mode="login", user=current_user)

            otp_sent = True
            return render_template("single_page.html", lang=lang, mode="login", otp_sent=True, email=email, user=current_user)

        elif action == "login":
            if not otp_input:
                flash(_("Please enter the OTP."))
                return render_template("single_page.html", lang=lang, mode="login", otp_sent=True, email=email, user=current_user)

            otp_row = db.execute("SELECT * FROM otps WHERE email=? AND otp_code=?", (email, otp_input)).fetchone()

            if otp_row:
                user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

                if user["email"] == SUPER_ADMIN_EMAIL:
                    db.execute("UPDATE users SET is_verified=1, is_approved=1 WHERE email=?", (email,))
                    db.commit()

                db.execute("UPDATE users SET is_verified=1 WHERE email=?", (email,))
                db.commit()

                if not user["name"]:
                    return redirect(url_for("first_profile", email=email))

                if user["role"] == "Admin" and user["email"] == SUPER_ADMIN_EMAIL:
                    login_user(User(user), remember=True)
                    flash(_("Logged in as super admin."))
                    return redirect(url_for("dashboard", lang=lang))

                elif user["is_approved"]:
                    login_user(User(user), remember=True)
                    flash(_("Login successful."))
                    return redirect(url_for("dashboard", lang=lang))
                else:
                    return render_template("single_page.html", lang=lang, mode="pending", user=current_user)
            else:
                flash(_("Invalid OTP."))
                return render_template("single_page.html", lang=lang, mode="login", otp_sent=True, email=email, user=current_user)

    # Default GET render
    return render_template("single_page.html", lang=lang, mode="login", otp_sent=otp_sent, email=email, otp=otp_input, user=current_user)

@app.route("/verify_otp/<email>", methods=["GET", "POST"])
def verify_otp(email):
    db = get_db()
    if request.method == "POST":
        otp_input = request.form.get("otp")
        if not otp_input:
            flash("Enter the OTP.")
            return render_template("single_page.html", mode="verify_otp", email=email,
      
   
    user=current_user)

        otp_row = db.execute(
            "SELECT * FROM otps WHERE email=? AND otp_code=?",
            (email, otp_input)
        ).fetchone()

        if otp_row:
            user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

            if user["email"] == SUPER_ADMIN_EMAIL:
                db.execute(
                    "UPDATE users SET is_verified=1, is_approved=1 WHERE email=?",
                    (email,)
                )
                db.commit()
                user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

            db.execute("UPDATE users SET is_verified=1 WHERE email=?", (email,))
            db.commit()

            if not user["name"]:
                return redirect(url_for("first_profile", email=email))

            if user["role"] == "Admin" and user["email"] == SUPER_ADMIN_EMAIL:
                login_user(User(user), remember=True)
                flash("Logged in as super admin.")
                return redirect(url_for("dashboard"))
            elif user["is_approved"]:
                login_user(User(user), remember=True)
                flash("Login successful.")
                return redirect(url_for("dashboard"))
            else:
                return render_template("single_page.html", mode="pending",
      
   
    user=current_user)
        else:
            flash("Invalid OTP.")
            return render_template("single_page.html", mode="verify_otp", email=email,
      
   
    user=current_user)

    return render_template("single_page.html", mode="verify_otp", email=email,
      
    
    user=current_user)

@app.route("/first_profile/<email>", methods=["GET", "POST"])
def first_profile(email):
    db = get_db()
    if request.method == "POST":
        name = request.form.get("name")
        selfie_data = request.form.get("selfie")

        if not name or not selfie_data:
            flash("All fields required.")
            return render_template("single_page.html", mode="first_profile", email=email,
      
    
    user=current_user)

        import io
        from base64 import b64decode

        img_str = re.search(r'base64,(.*)', selfie_data).group(1)
        img_bytes = b64decode(img_str)

# Use BytesIO stream for Cloudinary upload
        img_stream = io.BytesIO(img_bytes)
        result = cloudinary.uploader.upload(img_stream, resource_type="image")
        filepath = result.get("secure_url")


        db.execute(
            "UPDATE users SET name=?, selfie_path=? WHERE email=?",
            (name, filepath, email)
        )
        db.commit()

        try:
            msg = Message(
                "New Family Portal Registration",
                recipients=[SUPER_ADMIN_EMAIL]
            )
            msg.body = f"New user registered:\nName: {name}\nEmail: {email}\nApprove via admin panel."
            with open(filepath, "rb") as f:
                msg.attach("selfie.png", "image/png", f.read())
            mail.send(msg)
        except Exception as e:
            flash(f"Failed to notify admin: {e}")

        return render_template("single_page.html", mode="pending",
      
    
    user=current_user)

    return render_template("single_page.html", mode="first_profile", email=email,
      
    
    user=current_user)


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()

    pending_count = 0
    if current_user.role == "Admin":
        pending_count = db.execute("""
            SELECT COUNT(*) as count
            FROM users
            WHERE is_approved = 0
              AND name IS NOT NULL
        """).fetchone()["count"]

    today = datetime.today().strftime('%m-%d')
    members = db.execute("""
        SELECT name, dob, selfie_path
        FROM family_members
        WHERE is_late = 0 AND dob IS NOT NULL
    """).fetchall()

    birthday_today = []
    for member in members:
        try:
            dob_obj = datetime.strptime(member["dob"], "%Y-%m-%d")
            if dob_obj.strftime('%m-%d') == today:
                # Calculate age
                today_full = datetime.today()
                age = today_full.year - dob_obj.year - ((today_full.month, today_full.day) < (dob_obj.month, dob_obj.day))
                birthday_today.append({
                    "name": member["name"],
                    "selfie_path": member["selfie_path"],
                    "age": age
                })
        except ValueError:
            continue

    return render_template(
        "single_page.html",
        mode="dashboard",
        user=current_user,
        pending_count=pending_count,
        birthday_today=birthday_today
    )

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.")
    return redirect(url_for("login"))

# ---------------------
# Family Tree
# ---------------------

from flask_login import current_user

@app.route("/tree")
@login_required
def tree():
    db = get_db()

    members = db.execute("SELECT * FROM family_members").fetchall()
    relationships = db.execute("SELECT * FROM relationships").fetchall()

    # Build a dict of members keyed by id
    members_dict = {m["id"]: dict(m) for m in members}

    # Add an is_spouse flag for each member
    for m in members_dict.values():
        m["is_spouse"] = False

    # Find all members who appear as spouses
    spouse_ids = set()
    for rel in relationships:
        if rel["relation"] in ("wife", "husband", "spouse"):
            spouse_ids.add(rel["member_id"])

    for spouse_id in spouse_ids:
        if spouse_id in members_dict:
            members_dict[spouse_id]["is_spouse"] = True

    # Initialize tree nodes
    tree = {}
    for member_id in members_dict:
        tree[member_id] = {
            "member": members_dict[member_id],
            "children": [],
            "spouse": []
        }

    # Populate relationships
    for rel in relationships:
        if rel["relation"] == "child":
            tree[rel["related_to"]]["children"].append(rel["member_id"])
        elif rel["relation"] in ("wife", "husband", "spouse"):
            tree[rel["related_to"]]["spouse"].append(rel["member_id"])

    # Pick a root (first member added)
    root_id = None
    if members:
        root_id = min(members_dict.keys())

    return render_template(
        "tree.html",
        tree=tree,
        root_id=root_id,
        mode="tree", 
        user=current_user
    )




@app.route("/tree/add", methods=["GET", "POST"])
@login_required
@role_required("Admin", "Contributor")
def add_member():
    relation = request.args.get("relation")
    related_to = request.args.get("related_to")

    db = get_db()
    default_gender = None

    if relation == "spouse" and related_to:
        # check spouse limit
        spouse_count = db.execute("""
            SELECT COUNT(*) as cnt
            FROM relationships
            WHERE related_to = ? AND relation = 'spouse'
        """, (related_to,)).fetchone()["cnt"]

        if spouse_count >= 4:
            flash("A member can have at most 4 spouses.")
            return redirect(url_for("tree"))

        related_member = db.execute(
            "SELECT gender FROM family_members WHERE id = ?",
            (related_to,)
        ).fetchone()
        if related_member["gender"] == "Male":
            default_gender = _("Female")
        elif related_member["gender"] == "Female":
            default_gender = _("Male")


    blood_groups = ["A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"]

    if request.method == "POST":
        name = request.form["name"]
        dob_unknown = request.form.get("dob_unknown")
        dob = request.form.get("dob") or None
        is_late = 1 if request.form.get("is_late") == "on" else 0

        if dob_unknown and not is_late:
            flash("Only late members can have Date of Birth marked as unknown.")
            return redirect(request.url)

        if dob_unknown:
            dob = None

        gender = request.form["gender"]
        job = request.form.get("job_or_education")
        blood_group = request.form.get("blood_group")
        nickname = request.form.get("nickname") or None

        # enforce spouse gender if applicable
        if relation == "spouse" and default_gender:
            gender = default_gender

        photo_file = request.files.get("photo")
        selfie_path = None
        if photo_file and photo_file.filename:
            result = cloudinary.uploader.upload(photo_file)
            selfie_path = result.get("secure_url")


        cur = db.execute("""
            INSERT INTO family_members
            (name, is_late, dob, gender, job_or_education, blood_group, selfie_path, nickname)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, is_late, dob, gender, job, blood_group, selfie_path, nickname))

        new_member_id = cur.lastrowid

        if relation and related_to:
            db.execute("""
                INSERT INTO relationships (member_id, relation, related_to)
                VALUES (?, ?, ?)
            """, (new_member_id, relation, related_to))

        db.commit()
        flash("Member added.")
        return redirect(url_for("tree"))

    return render_template(
        "member_form.html",
        mode="add",
        relation=relation,
        related_to=related_to,
        default_gender=default_gender,
        blood_groups=blood_groups
    )

@app.route("/tree/edit/<int:member_id>", methods=["GET", "POST"])
@login_required
def edit_member(member_id):
    if current_user.role not in ["Admin", "Contributor"]:
        flash("Access denied.")
        return redirect(url_for("tree"))

    db = get_db()
    member = db.execute(
        "SELECT * FROM family_members WHERE id=?", (member_id,)
    ).fetchone()

    if not member:
        flash("Member not found.")
        return redirect(url_for("tree"))

    # Convert to dict for easier use
    member = dict(member)

    # Ensure blood_group is not None
    if member["blood_group"] is None:
        member["blood_group"] = ""

    blood_groups = ["A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"]

    if request.method == "POST":
        name = request.form["name"]
        dob_unknown = request.form.get("dob_unknown")
        dob = request.form.get("dob") or None
        is_late = 1 if request.form.get("is_late") == "on" else 0

        if dob_unknown and not is_late:
            flash("Only late members can have Date of Birth marked as unknown.")
            return redirect(request.url)

        if dob_unknown:
            dob = None

        gender = request.form["gender"]
        job = request.form.get("job_or_education")
        blood_group = request.form.get("blood_group")
        nickname = request.form.get("nickname") or None

        # Handle uploaded image file
        photo_file = request.files.get("photo")
        selfie_path = member["selfie_path"]  # Keep existing if no new upload

        if photo_file and photo_file.filename:
                result = cloudinary.uploader.upload(photo_file)
                selfie_path = result.get("secure_url")


        # Update the existing member in DB
        db.execute("""
            UPDATE family_members
            SET name = ?,
                is_late = ?,
                dob = ?,
                gender = ?,
                job_or_education = ?,
                blood_group = ?,
                selfie_path = ?,
                nickname = ?
            WHERE id = ?
        """, (name, is_late, dob, gender, job, blood_group, selfie_path, nickname, member_id))

        db.commit()
        flash("Member updated successfully.")
        return redirect(url_for("tree"))

    return render_template(
        "member_form.html",
        mode="edit",
        member=member,
        blood_groups=blood_groups,
        default_gender=None
    )

@app.route("/tree/delete/<int:member_id>", methods=["POST"])
@login_required
@role_required("Admin")
def delete_member(member_id):
    db = get_db()
    db.execute("DELETE FROM relationships WHERE member_id=? OR related_to=?", (member_id, member_id))
    db.execute("DELETE FROM family_members WHERE id=?", (member_id,))
    db.commit()
    flash("Member deleted.")
    return redirect(url_for("tree"))

# Admin panel for user approvals
@app.route("/admin", methods=["GET", "POST"])
@login_required
@role_required("Admin")
def admin():
    db = get_db()

    if request.method == "POST":
        user_id = request.form.get("user_id")
        new_role = request.form.get("role")
        action = request.form.get("action")

        if not action:
            flash("No action specified.")
            return redirect(url_for("admin"))

        user_row = None
        if user_id:
            user_row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

        protected_email = "razinmuhammed1999@gmail.com"

        if action == "update_role":
            if user_row and user_row["email"] == protected_email:
                flash("This user’s role cannot be changed.")
            else:
                db.execute(
                    "UPDATE users SET role=? WHERE id=?",
                    (new_role, user_id)
                )
                db.commit()
                flash("User role updated.")

        elif action == "delete":
            if user_row and user_row["email"] == protected_email:
                flash("This user cannot be deleted.")
            else:
                db.execute("DELETE FROM users WHERE id=?", (user_id,))
                db.commit()
                flash("User deleted.")

        elif action == "approve":
            db.execute(
                "UPDATE users SET is_approved=1 WHERE id=?",
                (user_id,)
            )
            db.commit()
            flash("User approved.")
            return redirect(url_for("admin", filter="pending"))

    # <---- MAKE SURE THIS IS ALWAYS PRESENT:
    filter_value = request.args.get("filter", "all")

    if filter_value == "pending":
        users = db.execute("""
            SELECT * FROM users
            WHERE name IS NOT NULL AND is_approved = 0
            ORDER BY email
        """).fetchall()
    elif filter_value == "approved":
        users = db.execute("""
            SELECT * FROM users
            WHERE name IS NOT NULL AND is_approved = 1
            ORDER BY email
        """).fetchall()
    else:
        users = db.execute("""
            SELECT * FROM users
            WHERE name IS NOT NULL
            ORDER BY is_approved DESC, role, email
        """).fetchall()

    return render_template(
        "single_page.html",
        mode="admin",
        users=users,
        
        user=current_user
    )

@app.context_processor
def inject_filter_value():
    return {
        "current_filter": request.args.get("filter", "all")
    }




@app.route("/bloodgroup")
def bloodgroup_page():
 return render_template(
        "bloodgroup.html",
        user=current_user,
        mode="bloodgroup"
    )
@app.route("/api/bloodgroup", methods=["POST"])
def search_by_blood_group():
    data = request.get_json()
    blood_group = data.get("blood_group")

    if not blood_group:
        return jsonify({"members": []})

    conn = sqlite3.connect("family.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM family_members
        WHERE blood_group = ?
        AND is_late = 0
        ORDER BY date(dob) ASC
    """, (blood_group,))
    rows = cur.fetchall()
    conn.close()

    members = []
    for row in rows:
        members.append({
            "id": row["id"],
            "name": row["name"],
            "nickname": row["nickname"],
            "blood_group": row["blood_group"],
            "dob": row["dob"],
            "gender": row["gender"],
            "job_or_education": row["job_or_education"],
            "is_late": row["is_late"]
        })

    return jsonify({"members": members})
@app.route("/validate_dob_status", methods=["POST"])
def validate_dob_status():
    is_late = request.json.get("is_late", False)
    dob_unknown = request.json.get("dob_unknown", False)

    if dob_unknown and not is_late:
        return jsonify({"warning": "Please confirm if the person is deceased when DOB is unknown."})
    return jsonify({"warning": ""})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.")
    return redirect(url_for("login"))

# ---------------------
# Family Tree
# ---------------------

from flask_login import current_user

@app.route("/tree")
@login_required
def tree():
    db = get_db()

    members = db.execute("SELECT * FROM family_members").fetchall()
    relationships = db.execute("SELECT * FROM relationships").fetchall()

    # Build a dict of members keyed by id
    members_dict = {m["id"]: dict(m) for m in members}

    # Add an is_spouse flag for each member
    for m in members_dict.values():
        m["is_spouse"] = False

    # Find all members who appear as spouses
    spouse_ids = set()
    for rel in relationships:
        if rel["relation"] in ("wife", "husband", "spouse"):
            spouse_ids.add(rel["member_id"])

    for spouse_id in spouse_ids:
        if spouse_id in members_dict:
            members_dict[spouse_id]["is_spouse"] = True

    # Initialize tree nodes
    tree = {}
    for member_id in members_dict:
        tree[member_id] = {
            "member": members_dict[member_id],
            "children": [],
            "spouse": []
        }

    # Populate relationships
    for rel in relationships:
        if rel["relation"] == "child":
            tree[rel["related_to"]]["children"].append(rel["member_id"])
        elif rel["relation"] in ("wife", "husband", "spouse"):
            tree[rel["related_to"]]["spouse"].append(rel["member_id"])

    # Pick a root (first member added)
    root_id = None
    if members:
        root_id = min(members_dict.keys())

    return render_template(
        "tree.html",
        tree=tree,
        root_id=root_id,
        mode="tree", 
        user=current_user
    )




@app.route("/tree/add", methods=["GET", "POST"])
@login_required
@role_required("Admin", "Contributor")
def add_member():
    relation = request.args.get("relation")
    related_to = request.args.get("related_to")

    db = get_db()
    default_gender = None

    if relation == "spouse" and related_to:
        # check spouse limit
        spouse_count = db.execute("""
            SELECT COUNT(*) as cnt
            FROM relationships
            WHERE related_to = ? AND relation = 'spouse'
        """, (related_to,)).fetchone()["cnt"]

        if spouse_count >= 4:
            flash("A member can have at most 4 spouses.")
            return redirect(url_for("tree"))

        related_member = db.execute(
            "SELECT gender FROM family_members WHERE id = ?",
            (related_to,)
        ).fetchone()
        if related_member["gender"] == "Male":
            default_gender = _("Female")
        elif related_member["gender"] == "Female":
            default_gender = _("Male")


    blood_groups = ["A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"]

    if request.method == "POST":
        name = request.form["name"]
        dob_unknown = request.form.get("dob_unknown")
        dob = request.form.get("dob") or None
        is_late = 1 if request.form.get("is_late") == "on" else 0

        if dob_unknown and not is_late:
            flash("Only late members can have Date of Birth marked as unknown.")
            return redirect(request.url)

        if dob_unknown:
            dob = None

        gender = request.form["gender"]
        job = request.form.get("job_or_education")
        blood_group = request.form.get("blood_group")
        nickname = request.form.get("nickname") or None

        # enforce spouse gender if applicable
        if relation == "spouse" and default_gender:
            gender = default_gender

        photo_file = request.files.get("photo")
        selfie_path = None
        if photo_file and photo_file.filename:
            result = cloudinary.uploader.upload(photo_file)
            selfie_path = result.get("secure_url")


        cur = db.execute("""
            INSERT INTO family_members
            (name, is_late, dob, gender, job_or_education, blood_group, selfie_path, nickname)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, is_late, dob, gender, job, blood_group, selfie_path, nickname))

        new_member_id = cur.lastrowid

        if relation and related_to:
            db.execute("""
                INSERT INTO relationships (member_id, relation, related_to)
                VALUES (?, ?, ?)
            """, (new_member_id, relation, related_to))

        db.commit()
        flash("Member added.")
        return redirect(url_for("tree"))

    return render_template(
       
        "member_form.html",
        mode="add",
        relation=relation,
        related_to=related_to,
        default_gender=default_gender,
        blood_groups=blood_groups
    )

@app.route("/tree/edit/<int:member_id>", methods=["GET", "POST"])
@login_required
def edit_member(member_id):
    if current_user.role not in ["Admin", "Contributor"]:
        flash("Access denied.")
        return redirect(url_for("tree"))

    db = get_db()
    member = db.execute(
        "SELECT * FROM family_members WHERE id=?", (member_id,)
    ).fetchone()

    if not member:
        flash("Member not found.")
        return redirect(url_for("tree"))

    # Convert to dict for easier use
    member = dict(member)

    # Ensure blood_group is not None
    if member["blood_group"] is None:
        member["blood_group"] = ""

    blood_groups = ["A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"]

    if request.method == "POST":
        name = request.form["name"]
        dob_unknown = request.form.get("dob_unknown")
        dob = request.form.get("dob") or None
        is_late = 1 if request.form.get("is_late") == "on" else 0

        if dob_unknown and not is_late:
            flash("Only late members can have Date of Birth marked as unknown.")
            return redirect(request.url)

        if dob_unknown:
            dob = None

        gender = request.form["gender"]
        job = request.form.get("job_or_education")
        blood_group = request.form.get("blood_group")
        nickname = request.form.get("nickname") or None

        # Handle uploaded image file
        photo_file = request.files.get("photo")
        selfie_path = member["selfie_path"]  # Keep existing if no new upload

        if photo_file and photo_file.filename:
                result = cloudinary.uploader.upload(photo_file)
                selfie_path = result.get("secure_url")


        # Update the existing member in DB
        db.execute("""
            UPDATE family_members
            SET name = ?,
                is_late = ?,
                dob = ?,
                gender = ?,
                job_or_education = ?,
                blood_group = ?,
                selfie_path = ?,
                nickname = ?
            WHERE id = ?
        """, (name, is_late, dob, gender, job, blood_group, selfie_path, nickname, member_id))

        db.commit()
        flash("Member updated successfully.")
        return redirect(url_for("tree"))

    return render_template(
        "member_form.html",
        mode="edit",
        member=member,
        blood_groups=blood_groups,
        default_gender=None
    )

@app.route("/tree/delete/<int:member_id>", methods=["POST"])
@login_required
@role_required("Admin")
def delete_member(member_id):
    db = get_db()
    db.execute("DELETE FROM relationships WHERE member_id=? OR related_to=?", (member_id, member_id))
    db.execute("DELETE FROM family_members WHERE id=?", (member_id,))
    db.commit()
    flash("Member deleted.")
    return redirect(url_for("tree"))

# Admin panel for user approvals
@app.route("/admin", methods=["GET", "POST"])
@login_required
@role_required("Admin")
def admin():
    db = get_db()

    if request.method == "POST":
        user_id = request.form.get("user_id")
        new_role = request.form.get("role")
        action = request.form.get("action")

        if not action:
            flash("No action specified.")
            return redirect(url_for("admin"))

        user_row = None
        if user_id:
            user_row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

        protected_email = "razinmuhammed1999@gmail.com"

        if action == "update_role":
            if user_row and user_row["email"] == protected_email:
                flash("This user’s role cannot be changed.")
            else:
                db.execute(
                    "UPDATE users SET role=? WHERE id=?",
                    (new_role, user_id)
                )
                db.commit()
                flash("User role updated.")

        elif action == "delete":
            if user_row and user_row["email"] == protected_email:
                flash("This user cannot be deleted.")
            else:
                db.execute("DELETE FROM users WHERE id=?", (user_id,))
                db.commit()
                flash("User deleted.")

        elif action == "approve":
            db.execute(
                "UPDATE users SET is_approved=1 WHERE id=?",
                (user_id,)
            )
            db.commit()
            flash("User approved.")
            return redirect(url_for("admin", filter="pending"))

    # <---- MAKE SURE THIS IS ALWAYS PRESENT:
    filter_value = request.args.get("filter", "all")

    if filter_value == "pending":
        users = db.execute("""
            SELECT * FROM users
            WHERE name IS NOT NULL AND is_approved = 0
            ORDER BY email
        """).fetchall()
    elif filter_value == "approved":
        users = db.execute("""
            SELECT * FROM users
            WHERE name IS NOT NULL AND is_approved = 1
            ORDER BY email
        """).fetchall()
    else:
        users = db.execute("""
            SELECT * FROM users
            WHERE name IS NOT NULL
            ORDER BY is_approved DESC, role, email
        """).fetchall()

    return render_template(
        "single_page.html",
        mode="admin",
        users=users,
        
        user=current_user
    )

@app.context_processor
def inject_filter_value():
    return {
        "current_filter": request.args.get("filter", "all")
    }




@app.route("/bloodgroup")
def bloodgroup_page():
 return render_template(
        "bloodgroup.html",
        user=current_user,
        mode="bloodgroup"
    )
@app.route("/api/bloodgroup", methods=["POST"])
def search_by_blood_group():
    data = request.get_json()
    blood_group = data.get("blood_group")

    if not blood_group:
        return jsonify({"members": []})

    conn = sqlite3.connect("family.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM family_members
        WHERE blood_group = ?
        AND is_late = 0
        ORDER BY date(dob) ASC
    """, (blood_group,))
    rows = cur.fetchall()
    conn.close()

    members = []
    for row in rows:
        members.append({
            "id": row["id"],
            "name": row["name"],
            "nickname": row["nickname"],
            "blood_group": row["blood_group"],
            "dob": row["dob"],
            "gender": row["gender"],
            "job_or_education": row["job_or_education"],
            "is_late": row["is_late"]
        })

    return jsonify({"members": members})
@app.route("/validate_dob_status", methods=["POST"])
def validate_dob_status():
    is_late = request.json.get("is_late", False)
    dob_unknown = request.json.get("dob_unknown", False)

    if dob_unknown and not is_late:
        return jsonify({"warning": "Please confirm if the person is deceased when DOB is unknown."})
    return jsonify({"warning": ""})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

