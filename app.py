\
import os
from datetime import datetime, date
from dateutil import parser as dateparser

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, TextAreaField, HiddenField, SelectField, DateField
from wtforms.validators import DataRequired, Email, Length, NumberRange, Optional

# --------------------------
# App & DB setup
# --------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(BASE_DIR, "app.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-in-production")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", f"sqlite:///{db_path}")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Honor DATABASE_URL that may start with "postgres://" by converting to "postgresql://"
db_url = app.config["SQLALCHEMY_DATABASE_URI"]
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url


# --------------------------
# Models
# --------------------------

CATEGORIES = [
    ("implants", "Implants"),
    ("ortho", "Orthodontics"),
    ("resto_endo", "Restoration with Endo"),
    ("scaling", "Scaling"),
    ("veneers", "Veneers"),
    ("fake", "Fake/Unreal"),
]

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    region = db.Column(db.String(120), nullable=True)
    role = db.Column(db.String(20), default="employee")  # "employee" or "manager"
    password_hash = db.Column(db.String(255), nullable=False)
    is_active_user = db.Column(db.Boolean, default=True)

    leads = db.relationship("LeadEntry", backref="user", lazy=True)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

class LeadEntry(db.Model):
    __tablename__ = "lead_entries"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    entry_date = db.Column(db.Date, nullable=False, index=True)
    category = db.Column(db.String(50), nullable=False)  # one of CATEGORIES keys
    total = db.Column(db.Integer, nullable=False, default=0)
    reserved = db.Column(db.Integer, nullable=False, default=0)
    not_reserved = db.Column(db.Integer, nullable=False, default=0)
    fake_count = db.Column(db.Integer, nullable=False, default=0)  # used when category == fake
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# --------------------------
# Forms
# --------------------------

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign In")

class LeadDailyForm(FlaskForm):
    entry_date = DateField("Date", validators=[Optional()], default=date.today)
    implants_total = IntegerField("Implants - total", validators=[NumberRange(min=0)], default=0)
    implants_reserved = IntegerField("Implants - reserved", validators=[NumberRange(min=0)], default=0)
    implants_not_reserved = IntegerField("Implants - not reserved", validators=[NumberRange(min=0)], default=0)

    ortho_total = IntegerField("Ortho - total", validators=[NumberRange(min=0)], default=0)
    ortho_reserved = IntegerField("Ortho - reserved", validators=[NumberRange(min=0)], default=0)
    ortho_not_reserved = IntegerField("Ortho - not reserved", validators=[NumberRange(min=0)], default=0)

    resto_total = IntegerField("Resto+Endo - total", validators=[NumberRange(min=0)], default=0)
    resto_reserved = IntegerField("Resto+Endo - reserved", validators=[NumberRange(min=0)], default=0)
    resto_not_reserved = IntegerField("Resto+Endo - not reserved", validators=[NumberRange(min=0)], default=0)

    scaling_total = IntegerField("Scaling - total", validators=[NumberRange(min=0)], default=0)
    scaling_reserved = IntegerField("Scaling - reserved", validators=[NumberRange(min=0)], default=0)
    scaling_not_reserved = IntegerField("Scaling - not reserved", validators=[NumberRange(min=0)], default=0)

    veneers_total = IntegerField("Veneers - total", validators=[NumberRange(min=0)], default=0)
    veneers_reserved = IntegerField("Veneers - reserved", validators=[NumberRange(min=0)], default=0)
    veneers_not_reserved = IntegerField("Veneers - not reserved", validators=[NumberRange(min=0)], default=0)

    fake_count = IntegerField("Fake/Unreal - count", validators=[NumberRange(min=0)], default=0)

    notes = TextAreaField("Notes", validators=[Optional(), Length(max=2000)])
    submit = SubmitField("Submit Daily Report")

# --------------------------
# Auth
# --------------------------

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --------------------------
# Utility functions
# --------------------------

def ensure_admin_exists():
    # Create default admin if none exists
    if not User.query.filter_by(role="manager").first():
        admin_email = os.environ.get("ADMIN_EMAIL", "admin@example.com")
        admin_pw = os.environ.get("ADMIN_PASSWORD", "Admin123!")
        admin = User(email=admin_email, name="Admin", region="HQ", role="manager")
        admin.set_password(admin_pw)
        db.session.add(admin)
        db.session.commit()

def parse_date(s, default=None):
    if not s:
        return default
    try:
        return dateparser.parse(s).date()
    except Exception:
        return default

def category_labels():
    return dict(CATEGORIES)

def conversion(reserved, total):
    if total <= 0:
        return 0.0
    return (reserved / total) * 100.0

# --------------------------
# Routes
# --------------------------

@app.route("/")
def index():
    if current_user.is_authenticated:
        if current_user.role == "manager":
            return redirect(url_for("manager_dashboard"))
        else:
            return redirect(url_for("employee_dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.strip().lower()).first()
        if user and user.check_password(form.password.data) and user.is_active_user:
            login_user(user)
            flash("Welcome back!", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid credentials.", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Signed out.", "info")
    return redirect(url_for("login"))

# Employee lead submission
@app.route("/employee", methods=["GET", "POST"])
@login_required
def employee_dashboard():
    if current_user.role not in ("employee", "manager"):
        return redirect(url_for("login"))
    form = LeadDailyForm()
    if form.validate_on_submit():
        d = form.entry_date.data or date.today()

        rows = []
        def add_row(cat_key, total, reserved, not_reserved):
            if total < reserved + not_reserved:
                raise ValueError(f"For {cat_key}, reserved + not_reserved exceeds total.")
            rows.append(LeadEntry(
                user_id=current_user.id,
                entry_date=d,
                category=cat_key,
                total=total,
                reserved=reserved,
                not_reserved=not_reserved,
                fake_count=0,
                notes=form.notes.data.strip() if form.notes.data else None
            ))

        try:
            add_row("implants", form.implants_total.data, form.implants_reserved.data, form.implants_not_reserved.data)
            add_row("ortho", form.ortho_total.data, form.ortho_reserved.data, form.ortho_not_reserved.data)
            add_row("resto_endo", form.resto_total.data, form.resto_reserved.data, form.resto_not_reserved.data)
            add_row("scaling", form.scaling_total.data, form.scaling_reserved.data, form.scaling_not_reserved.data)
            add_row("veneers", form.veneers_total.data, form.veneers_reserved.data, form.veneers_not_reserved.data)

            fake_row = LeadEntry(
                user_id=current_user.id,
                entry_date=d,
                category="fake",
                total=0, reserved=0, not_reserved=0,
                fake_count=form.fake_count.data or 0,
                notes=form.notes.data.strip() if form.notes.data else None
            )
            rows.append(fake_row)

        except ValueError as e:
            flash(str(e), "danger")
            return render_template("employee_dashboard.html", form=form, labels=category_labels())

        for r in rows:
            db.session.add(r)
        db.session.commit()
        flash("Daily report submitted.", "success")
        return redirect(url_for("employee_dashboard"))
    # show last 7 entries summary for the user
    recent = (db.session.query(LeadEntry)
              .filter(LeadEntry.user_id == current_user.id)
              .order_by(LeadEntry.entry_date.desc(), LeadEntry.created_at.desc())
              .limit(50).all())
    return render_template("employee_dashboard.html", form=form, labels=category_labels(), recent=recent)

# Manager dashboard
@app.route("/manager")
@login_required
def manager_dashboard():
    if current_user.role != "manager":
        flash("Managers only.", "warning")
        return redirect(url_for("index"))

    start = parse_date(request.args.get("start"))
    end = parse_date(request.args.get("end"))
    q = db.session.query(LeadEntry)
    if start:
        q = q.filter(LeadEntry.entry_date >= start)
    if end:
        q = q.filter(LeadEntry.entry_date <= end)

    entries = q.all()

    # aggregate
    by_category = {k: {"total":0, "reserved":0, "not_reserved":0, "fake":0} for k,_ in CATEGORIES}
    by_user = {}
    total_leads_nonfake = 0
    total_reserved = 0
    total_fake = 0

    for e in entries:
        if e.category == "fake":
            by_category["fake"]["fake"] += e.fake_count
            total_fake += e.fake_count
        else:
            by_category[e.category]["total"] += e.total
            by_category[e.category]["reserved"] += e.reserved
            by_category[e.category]["not_reserved"] += e.not_reserved
            total_leads_nonfake += e.total
            total_reserved += e.reserved

        # per-user
        u = by_user.setdefault(e.user_id, {
            "name": e.user.name if e.user else f"User {e.user_id}",
            "region": e.user.region if e.user else "",
            "total": 0,
            "reserved": 0,
            "not_reserved": 0,
            "fake": 0
        })
        if e.category == "fake":
            u["fake"] += e.fake_count
        else:
            u["total"] += e.total
            u["reserved"] += e.reserved
            u["not_reserved"] += e.not_reserved

    overall_conv = conversion(total_reserved, total_leads_nonfake)

    # prepare simple structures for charts
    cat_labels = [label for key,label in CATEGORIES if key!="fake"]
    cat_totals = [by_category[key]["total"] for key,_ in CATEGORIES if key!="fake"]
    cat_reserved = [by_category[key]["reserved"] for key,_ in CATEGORIES if key!="fake"]
    cat_not_reserved = [by_category[key]["not_reserved"] for key,_ in CATEGORIES if key!="fake"]

    users_table = []
    for uid, v in by_user.items():
        users_table.append({
            "id": uid,
            "name": v["name"],
            "region": v["region"],
            "total": v["total"],
            "reserved": v["reserved"],
            "not_reserved": v["not_reserved"],
            "fake": v["fake"],
            "conversion": round(conversion(v["reserved"], v["total"]), 2) if v["total"] else 0.0
        })
    # sort by total desc
    users_table.sort(key=lambda x: x["total"], reverse=True)

    return render_template("manager_dashboard.html",
                           labels=category_labels(),
                           start=start, end=end,
                           cat_labels=cat_labels, cat_totals=cat_totals,
                           cat_reserved=cat_reserved, cat_not_reserved=cat_not_reserved,
                           users_table=users_table,
                           totals={"total": total_leads_nonfake, "reserved": total_reserved, "fake": total_fake, "conv": round(overall_conv,2)})

# Employee detail view (drill-down)
@app.route("/manager/employee/<int:user_id>")
@login_required
def employee_detail(user_id):
    if current_user.role != "manager":
        flash("Managers only.", "warning")
        return redirect(url_for("index"))

    start = parse_date(request.args.get("start"))
    end = parse_date(request.args.get("end"))

    q = db.session.query(LeadEntry).filter(LeadEntry.user_id == user_id)
    if start:
        q = q.filter(LeadEntry.entry_date >= start)
    if end:
        q = q.filter(LeadEntry.entry_date <= end)
    entries = q.all()

    by_category = {k: {"total":0, "reserved":0, "not_reserved":0, "fake":0} for k,_ in CATEGORIES}

    total_leads_nonfake = 0
    total_reserved = 0
    total_fake = 0

    for e in entries:
        if e.category == "fake":
            by_category["fake"]["fake"] += e.fake_count
            total_fake += e.fake_count
        else:
            by_category[e.category]["total"] += e.total
            by_category[e.category]["reserved"] += e.reserved
            by_category[e.category]["not_reserved"] += e.not_reserved
            total_leads_nonfake += e.total
            total_reserved += e.reserved

    cat_labels = [label for key,label in CATEGORIES if key!="fake"]
    cat_totals = [by_category[key]["total"] for key,_ in CATEGORIES if key!="fake"]
    cat_reserved = [by_category[key]["reserved"] for key,_ in CATEGORIES if key!="fake"]
    cat_not_reserved = [by_category[key]["not_reserved"] for key,_ in CATEGORIES if key!="fake"]

    user = User.query.get_or_404(user_id)
    return render_template("employee_detail.html",
                           user=user,
                           labels=category_labels(),
                           start=start, end=end,
                           cat_labels=cat_labels, cat_totals=cat_totals,
                           cat_reserved=cat_reserved, cat_not_reserved=cat_not_reserved,
                           totals={"total": total_leads_nonfake, "reserved": total_reserved, "fake": total_fake, "conv": round(conversion(total_reserved, total_leads_nonfake),2)})

# User management (basic)
@app.route("/manager/users", methods=["GET", "POST"])
@login_required
def manage_users():
    if current_user.role != "manager":
        flash("Managers only.", "warning")
        return redirect(url_for("index"))

    if request.method == "POST":
        # Add or update user
        action = request.form.get("action")
        if action == "add":
            email = request.form.get("email","").strip().lower()
            name = request.form.get("name","").strip()
            region = request.form.get("region","").strip()
            role = request.form.get("role","employee")
            password = request.form.get("password","").strip()
            if not (email and name and password):
                flash("Email, name, and password are required.", "danger")
            elif User.query.filter_by(email=email).first():
                flash("Email already exists.", "danger")
            else:
                u = User(email=email, name=name, region=region, role=role)
                u.set_password(password)
                db.session.add(u)
                db.session.commit()
                flash("User created.", "success")
        elif action == "reset":
            uid = int(request.form.get("user_id"))
            new_pw = request.form.get("new_password","").strip()
            u = User.query.get(uid)
            if u and new_pw:
                u.set_password(new_pw)
                db.session.commit()
                flash("Password reset.", "success")

    users = User.query.order_by(User.role.desc(), User.name.asc()).all()
    return render_template("manage_users.html", users=users)

# Export CSV for current filter
import csv
@app.route("/manager/export.csv")
@login_required
def export_csv():
    if current_user.role != "manager":
        flash("Managers only.", "warning")
        return redirect(url_for("index"))

    start = parse_date(request.args.get("start"))
    end = parse_date(request.args.get("end"))
    q = db.session.query(LeadEntry)
    if start:
        q = q.filter(LeadEntry.entry_date >= start)
    if end:
        q = q.filter(LeadEntry.entry_date <= end)
    entries = q.order_by(LeadEntry.entry_date.asc()).all()

    from io import StringIO, BytesIO
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(["Date","Employee","Region","Category","Total","Reserved","NotReserved","FakeCount","Notes"])
    for e in entries:
        writer.writerow([
            e.entry_date.isoformat(),
            e.user.name if e.user else e.user_id,
            e.user.region if e.user else "",
            e.category,
            e.total,
            e.reserved,
            e.not_reserved,
            e.fake_count,
            (e.notes or "").replace("\n"," ").strip()
        ])
    output = BytesIO()
    output.write(si.getvalue().encode("utf-8"))
    output.seek(0)
    fn = f"leads_{start or 'all'}_{end or 'all'}.csv"
    return send_file(output, mimetype="text/csv", as_attachment=True, download_name=fn)

# CLI command to init DB
@app.cli.command("init-db")
def init_db():
    db.create_all()
    ensure_admin_exists()
    print("Database initialized and default admin created if missing.")
    print("Default admin: admin@example.com / Admin123! (CHANGE THIS IN PRODUCTION)")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        ensure_admin_exists()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
