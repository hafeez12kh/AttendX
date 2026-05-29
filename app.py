from unittest import result

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    url_for,
    flash,
    Response,
    send_file,
    jsonify
)
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

import uuid
import csv
import random
import json
import os
import hashlib
import logging
import socket

from collections import defaultdict
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import aliased

from cryptography.fernet import Fernet
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from logging.handlers import TimedRotatingFileHandler

import qrcode
from io import BytesIO
from PIL import Image
import math

from backup_sqlite import backup_to_sqlite
from sqlalchemy import func
from ai_rules import get_suspicion_scores
from ai_utils import get_subject_predictions, get_student_predictions

app = Flask(__name__)

app.config["SECRET_KEY"] = "super_secret_key"

app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "mysql+mysqlconnector://hafeez:Hafeez94@localhost/attendance_db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

app.permanent_session_lifetime = timedelta(hours=2)


# mail configuration
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "hafeez12kh@gmail.com"
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")

mail = Mail(app)

serializer = URLSafeTimedSerializer(app.secret_key)


# dos protection
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri="memory://",
)

# logging setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

DOS_LOG_FILE = os.path.join(LOG_DIR, "dos_access.log")

dos_logger = logging.getLogger("dos")
dos_logger.setLevel(logging.INFO)
dos_logger.propagate = False

file_handler = TimedRotatingFileHandler(
    DOS_LOG_FILE, when="midnight", interval=1, backupCount=5, encoding="utf-8"
)

file_handler.setFormatter(
    logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
)

if not dos_logger.handlers:
    dos_logger.addHandler(file_handler)

# globalconstraints

TIMEOUT_IN_MINUTES = 20
ADMIN_IDLE_TIMEOUT = timedelta(minutes=30)
tolerance = 15

app.config["PROXY_RETENTION_DAYS"] = 7

# utility functions
def generate_captcha():
    a, b = random.randint(1, 9), random.randint(1, 9)
    return f"{a} + {b}", a + b


def render_message(msg, session_id=None):
    if session.get("role") in ["teacher", "hod"]:
        return render_template("message_simple.html", msg=msg, session_id=session_id)
    else:
        return render_template("message_simple.html", msg=msg)


def load_secure_users():
    key = "0ELGC3Wl2GJyMLSxgl26lH0RSEJV1fiFTql0VvLmMd4="
    base_dir = os.path.dirname(os.path.abspath(__file__))
    secret_path = os.path.join(base_dir, "secrets", "users.enc")

    fernet = Fernet(key.encode())

    with open(secret_path, "rb") as f:
        decrypted = fernet.decrypt(f.read())

    return json.loads(decrypted.decode())


def validate_admin_session():

    token = session.get("admin_token")

    if not token:
        return False

    admin_session = AdminSession.query.filter_by(token=token).first()

    if not admin_session:
        return False

    if datetime.now() - admin_session.last_activity > ADMIN_IDLE_TIMEOUT:
        db.session.delete(admin_session)
        db.session.commit()
        session.clear()
        return False

    admin_session.last_activity = datetime.now()
    db.session.commit()

    return True


def save_secure_users(data):

    key = "0ELGC3Wl2GJyMLSxgl26lH0RSEJV1fiFTql0VvLmMd4="

    base_dir = os.path.dirname(os.path.abspath(__file__))
    secret_path = os.path.join(base_dir, "secrets", "users.enc")

    fernet = Fernet(key.encode())

    encrypted = fernet.encrypt(json.dumps(data).encode())

    with open(secret_path, "wb") as f:
        f.write(encrypted)

def subnet_within_tolerance(teacher_ip, student_ip):

    try:

        t = list(map(int, teacher_ip.split(".")))
        s = list(map(int, student_ip.split(".")))

        print("Teacher Parsed:", t)
        print("Student Parsed:", s)

        # First 2 octets must match
        if t[0] != s[0] or t[1] != s[1]:
            print("Department mismatch")
            return False

        # Third octet tolerance
        diff = abs(t[2] - s[2])

        print("Third Octet Difference:", diff)

        if diff > 10:
            print("Outside classroom/router tolerance")
            return False

        print("WiFi validation passed")
        return True

    except Exception as e:
        print("Subnet Error:", e)
        return False


# database models
class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(100), unique=True)

    password_hash = db.Column(db.String(255))

    role = db.Column(db.String(20), index=True)

    is_active = db.Column(db.Boolean, default=True)

    classes = db.relationship("Class", backref="teacher")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class AdminSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True)
    last_activity = db.Column(db.DateTime)


class Program(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    code = db.Column(db.String(20), unique=True)

    name = db.Column(db.String(100))


class Class(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    code = db.Column(db.String(20), unique=True)

    name = db.Column(db.String(100))

    program_id = db.Column(db.Integer, db.ForeignKey("program.id"))

    program = db.relationship("Program", backref="subjects")

    teacher_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    has_practical = db.Column(db.Boolean, default=False)

    is_active = db.Column(db.Boolean, default=True)

from werkzeug.security import generate_password_hash, check_password_hash


class Student(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))

    roll = db.Column(db.String(20), unique=True)

    email = db.Column(db.String(120))

    password_hash = db.Column(db.String(255))

    program_id = db.Column(db.Integer, db.ForeignKey("program.id"))

    program = db.relationship("Program")


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class AttendanceSession(db.Model):
    id = db.Column(db.String(50), primary_key=True)

    class_id = db.Column(db.Integer)
    teacher_id = db.Column(db.Integer)  # ✅ ADD THIS

    date = db.Column(db.Date)
    expires_at = db.Column(db.DateTime)

    created_ip = db.Column(db.String(50))
    session_type = db.Column(db.String(20))

    is_closed = db.Column(db.Boolean, default=False)


class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    student_id = db.Column(db.Integer)
    class_id = db.Column(db.Integer)

    date = db.Column(db.Date)
    time = db.Column(db.Time)
    ip_address = db.Column(db.String(50)) 
    session_type = db.Column(db.String(20))

    session_id = db.Column(db.String(50))  # ✅ ADD THIS

    __table_args__ = (
        db.UniqueConstraint(
            "student_id",
            "session_id",  # ✅ CHANGE THIS
            name="unique_attendance_per_session",
        ),
    )


class SessionDevice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(50))
    device_id = db.Column(db.String(200))
    student_id = db.Column(db.Integer)
    __table_args__ = (db.UniqueConstraint("session_id", "device_id"),)


class ProxyAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(50))
    class_id = db.Column(db.Integer)
    original_student_id = db.Column(db.Integer)
    proxy_student_id = db.Column(db.Integer)
    device_id = db.Column(db.String(200))
    ip = db.Column(db.String(50))
    time = db.Column(db.DateTime, default=datetime.now)


class AttendanceOverride(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer)
    class_id = db.Column(db.Integer)
    date = db.Column(db.Date)
    action = db.Column(db.String(10))  # ADDED / REMOVED
    reason = db.Column(db.String(200))
    teacher_ip = db.Column(db.String(50))
    time = db.Column(db.DateTime, default=datetime.now)


# flask hooks
@app.before_request
def log_every_request():
    try:
        dos_logger.info(
            "IP=%s PATH=%s UA=%s",
            request.remote_addr,
            request.path,
            request.user_agent.string,
        )
    except:
        pass


@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache"
    return response

from ai_rules import get_suspicion_scores
# routes
# LOGIN (TEACHER ONLY)
@app.route("/", methods=["GET","POST"])
def login():

    if session.get("user_id"):

        role = session.get("role")

        if role == "hod":
            return redirect("/hod")

        elif role == "teacher":
            return redirect("/teacher")

        elif role == "student":
            return redirect("/student/dashboard")

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        captcha = request.form.get("captcha")

        # CAPTCHA
        try:
            if int(captcha) != session.get("captcha"):
                raise ValueError
        except:
            return render_message("Invalid CAPTCHA")

        # --------------------------
        # CHECK HOD / TEACHER
        # --------------------------
        user = User.query.filter_by(username=username, is_active=True).first()

        if user and user.check_password(password):

            session["user_id"] = user.id
            session["role"] = user.role
            session["username"] = user.username

            if user.role == "hod":
                return redirect("/hod")

            elif user.role == "teacher":
                return redirect("/teacher")

        # --------------------------
        # CHECK STUDENT LOGIN
        # --------------------------
        student = Student.query.filter_by(roll=username).first()

        if student and student.check_password(password):

            session["student_id"] = student.id
            session["role"] = "student"

            return redirect("/student/dashboard")

        return render_message("Invalid login")

    captcha_text, answer = generate_captcha()
    session["captcha"] = answer

    return render_template("login.html", captcha=captcha_text)



@app.route("/teacher/ai")
def teacher_ai():

    if session.get("role") != "teacher":
        return redirect("/")

    teacher_id = session.get("user_id")

    results = get_suspicion_scores(
    db,
    Attendance,
    Class,
    SessionDevice,
    Student,
    User,                # ✅ ADD THIS
    teacher_id=teacher_id,
    role="teacher"
)
    return render_template("teacher_ai.html", results=results)


@app.route("/hod/ai")
def hod_ai():

    if session.get("role") != "hod":
        return redirect("/")

    results = get_suspicion_scores(
        db,
        Attendance,
        Class,
        SessionDevice,
        Student,
        User,
        role="hod"
    )

    # -------------------------------
    # LOAD SUBJECTS / CLASSES
    # -------------------------------
    subjects = Class.query.order_by(Class.name).all()

    # -------------------------------
    # COUNTS
    # -------------------------------
    total = len(results)

    high = sum(1 for r in results if r["status"] == "High Risk")

    medium = sum(1 for r in results if r["status"] == "Medium Risk")

    safe = sum(1 for r in results if r["status"] == "Safe")

    insufficient = sum(
        1 for r in results
        if r["status"] == "Insufficient Data"
    )

    return render_template(
        "hod_ai.html",
        results=results,
        subjects=subjects,
        total=total,
        high=high,
        medium=medium,
        safe=safe,
        insufficient=insufficient
    )

@app.route("/teacher/prediction")
def teacher_prediction():

    if session.get("role") not in ["teacher", "hod"]:
        return redirect("/")

    role = session.get("role")
    user_id = session.get("user_id")

    # ✅ Get selected subject from dropdown
    selected_class_id = request.args.get("class_id")

    # ✅ Get class list for dropdown
    if role == "teacher":
        classes = Class.query.filter_by(teacher_id=user_id).all()
    else:  # HOD
        classes = Class.query.all()

    # ✅ 🔥 THIS IS WHERE YOUR CODE GOES
    data = get_subject_predictions(
        db, Attendance, Class, Student,
        teacher_id=user_id if role == "teacher" else None,
        class_id=selected_class_id
    )

    return render_template(
        "teacher_prediction.html",
        data=data,
        classes=classes,
        selected_class_id=selected_class_id, role=session.get("role") 
    )





@app.route("/student/prediction")
def student_prediction():

    if session.get("role") != "student":
        return redirect("/")

    student_id = session.get("student_id")

    if not student_id:
        print("❌ Session lost, redirecting to login")
        return redirect("/")   # ✅ prevents crash

    data = get_student_predictions(
        db, Attendance, Class, Student,
        student_id=student_id
    )

    return render_template("student_prediction.html", data=data)

# manage access for HOD to add teachers
@app.route("/teachers/manage", methods=["GET", "POST"])
def manage_teachers():

    if session.get("role") != "hod":
        return redirect("/")

    classes = Class.query.filter_by(is_active=True).all()

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        class_ids = request.form.getlist("class_ids")

        if not username or not password:
            return render_message("Username and password required")

        existing = User.query.filter_by(username=username).first()

        if existing:
            return render_message("Teacher already exists")

        teacher = User(username=username, role="teacher")

        teacher.set_password(password)

        db.session.add(teacher)
        db.session.commit()

        for cid in class_ids:
            cls = Class.query.get(int(cid))
            if cls:
                cls.teacher_id = teacher.id

        db.session.commit()

        return render_message("Teacher added successfully")

    teachers = User.query.filter_by(role="teacher").all()
    assigned = [c.id for c in classes if c.teacher_id]

    return render_template(
        "manage_teachers.html", teachers=teachers, classes=classes, assigned=assigned
    )


# edit teacher assignments


@app.route("/teachers/edit/<int:teacher_id>", methods=["GET", "POST"])
def edit_teacher(teacher_id):

    if session.get("role") != "hod":
        return redirect("/")

    teacher = User.query.get_or_404(teacher_id)

    classes = Class.query.filter_by(is_active=True).all()

    if request.method == "POST":

        new_classes = request.form.getlist("class_ids")

        # remove old assignments
        old_classes = Class.query.filter_by(teacher_id=teacher.id).all()

        for c in old_classes:
            c.teacher_id = None

        # assign new ones
        for cid in new_classes:
            cls = Class.query.get(int(cid))
            if cls:
                cls.teacher_id = teacher.id

        db.session.commit()

        return redirect("/teachers/manage")

    return render_template("edit_teacher.html", teacher=teacher, classes=classes)


# delete teacher


@app.route("/teachers/delete/<int:teacher_id>")
def delete_teacher(teacher_id):

    if session.get("role") != "hod":
        return redirect("/")

    teacher = User.query.get_or_404(teacher_id)

    if teacher.role != "teacher":
        return render_message("Invalid teacher")

    # remove teacher from subjects
    classes = Class.query.filter_by(teacher_id=teacher.id).all()

    for c in classes:
        c.teacher_id = None

    db.session.delete(teacher)
    db.session.commit()

    return redirect("/teachers/manage")

from werkzeug.security import generate_password_hash, check_password_hash

@app.route("/change-password", methods=["GET", "POST"])
def change_password():

    # ✅ allow both user and student
    if not session.get("user_id") and not session.get("student_id"):
        return redirect("/")

    if request.method == "POST":

        current_password = request.form["current_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        # ============================
        # 🔹 STUDENT
        # ============================
        if session.get("role") == "student":

            student = Student.query.get(session.get("student_id"))

            if not student or not student.check_password(current_password):
                flash("Current password is incorrect")
                return redirect(url_for("change_password"))

            if new_password != confirm_password:
                flash("New passwords do not match")
                return redirect(url_for("change_password"))

            student.set_password(new_password)

        # ============================
        # 🔹 TEACHER / HOD
        # ============================
        else:

            user = User.query.get(session.get("user_id"))

            if not user or not user.check_password(current_password):
                flash("Current password is incorrect")
                return redirect(url_for("change_password"))

            if new_password != confirm_password:
                flash("New passwords do not match")
                return redirect(url_for("change_password"))

            user.set_password(new_password)

        db.session.commit()
        session.clear()

        flash("Password updated successfully. Please login again.")
        return redirect(url_for("login"))

    return render_template("change_password.html")
# =========================
# LOGOUT
# =========================


@app.route("/logout")
def logout():

    # =========================
    # BACKUP ON LOGOUT
    # =========================
    try:
        models = [
            Student,
            Class,
            Attendance,
            AttendanceSession,
            SessionDevice,
            ProxyAttempt,
            AttendanceOverride,
        ]

        backup_to_sqlite(db, models)

    except Exception as e:
        app.logger.error(f"Backup on logout failed: {e}")

    # Clear login session
    session.clear()

    return redirect("/")


# Reset Login
@app.route("/FRAL", methods=["GET", "POST"])
def force_reset_admin_login():

    if request.method == "POST":
        secure = load_secure_users()
        pwd = request.form.get("admin_action_password")

        if pwd != secure.get("admin_action_password"):
            return render_message("Invalid admin password")

        # 🔥 DELETE ALL ADMIN SESSIONS
        AdminSession.query.delete()
        db.session.commit()

        return render_message("Admin login lock reset successfully")

    return render_template("reset_admin_login.html")


@app.before_request
def cleanup_expired_admin_sessions():
    expired = AdminSession.query.filter(
        AdminSession.last_activity < datetime.now() - ADMIN_IDLE_TIMEOUT
    ).all()

    for s in expired:
        db.session.delete(s)

    if expired:
        db.session.commit()


#---------------------------
   #student Dashboard
#---------------------------
from datetime import datetime

@app.route("/student/dashboard")
def student_dashboard():

    # -------------------------
    # ROLE CHECK
    # -------------------------
    if session.get("role") != "student":
        return redirect("/")

    student_id = session.get("student_id")

    student = Student.query.get(student_id)

    if not student:
        return redirect("/")

    now = datetime.now()
    today = now.date()

    # Get class
    program = Program.query.get(student.program_id)

    student_name = student.name   # or student.name if available
    class_name = program.name if program else "Unknown"


    # -------------------------
    # GET SUBJECTS OF PROGRAM
    # -------------------------
    subjects = Class.query.filter_by(
        program_id=student.program_id,
        is_active=True
    ).all()

    # -------------------------
    # ACTIVE SESSIONS
    # -------------------------
    active_sessions_raw = db.session.query(
        AttendanceSession.id,
        Class.code,
        Class.name,
        AttendanceSession.expires_at
    ).join(
        Class, AttendanceSession.class_id == Class.id
    ).outerjoin(
        Attendance,
        (Attendance.session_id == AttendanceSession.id) &
        (Attendance.student_id == student_id)
    ).filter(
    Class.program_id == student.program_id,
    AttendanceSession.expires_at > now,
    AttendanceSession.is_closed == False,
    Attendance.id == None
)
    active_sessions = []

    for s in active_sessions_raw:

        remaining = int((s.expires_at - now).total_seconds())

        minutes = remaining // 60
        seconds = remaining % 60

        active_sessions.append({
            "id": s.id,
            "code": s.code,
            "name": s.name,
            "expires_at": s.expires_at,
            "remaining": f"{minutes}:{seconds:02d}"
        })

    # -------------------------
    # TODAY ATTENDANCE
    # -------------------------
    today_attendance = db.session.query(
        Class.name,
        AttendanceSession.date,
        Attendance.id.label("present")
    ).join(
        AttendanceSession,
        AttendanceSession.class_id == Class.id
    ).outerjoin(
        Attendance,
        (Attendance.session_id == AttendanceSession.id) &
        (Attendance.student_id == student_id)
    ).filter(
        Class.program_id == student.program_id,
        AttendanceSession.date == today
    ).all()

    # -------------------------
    # PREVIOUS ATTENDANCE
    # -------------------------
    previous_attendance = db.session.query(
        Class.name,
        AttendanceSession.date,
        Attendance.id.label("present")
    ).join(
        AttendanceSession, AttendanceSession.class_id == Class.id
    ).outerjoin(
        Attendance,
        (Attendance.session_id == AttendanceSession.id) &
        (Attendance.student_id == student_id)
    ).filter(
    Class.program_id == student.program_id,
    AttendanceSession.date < today

    ).order_by(
        AttendanceSession.date.desc()
    ).limit(20).all()
        # -------------------------
    # TOTAL SESSIONS
    # -------------------------
    total_sessions = db.session.query(
        Class.id.label("class_id"),
        Class.name.label("subject"),
        db.func.count(AttendanceSession.id).label("total")
    ).join(
        AttendanceSession,
        AttendanceSession.class_id == Class.id
    ).filter(
    Class.program_id == student.program_id

    ).group_by(
        Class.id
    ).subquery()

    # -------------------------
    # PRESENT SESSIONS
    # -------------------------
    present_sessions = db.session.query(
        Class.id.label("class_id"),
        db.func.count(Attendance.id).label("present")
    ).join(
        AttendanceSession,
        Attendance.session_id == AttendanceSession.id
    ).join(
        Class,
        AttendanceSession.class_id == Class.id
    ).filter(
    Attendance.student_id == student_id,
    Class.program_id == student.program_id

    ).group_by(
        Class.id
    ).subquery()

    # -------------------------
    # MERGE BOTH
    # -------------------------
    attendance = db.session.query(
        total_sessions.c.subject,
        total_sessions.c.total,
        db.func.coalesce(present_sessions.c.present, 0).label("present")
    ).outerjoin(
        present_sessions,
        total_sessions.c.class_id == present_sessions.c.class_id
    ).all()

    subjects = []

    for row in attendance:

        percent = 0

        if row.total > 0:
            percent = round((row.present / row.total) * 100, 2)

        subjects.append({
            "subject": row.subject,
            "present": row.present,
            "absent": row.total - row.present,
            "total": row.total,
            "percent": percent,
            "status": "Good" if percent >= 75 else "Low Attendance"
    
        })

    # -------------------------
    # RENDER DASHBOARD
    # -------------------------
    return render_template(
    "student_dashboard.html",
    student=student,
    student_name=student_name,
    class_name=class_name,
    active_sessions=active_sessions,
    today_attendance=today_attendance,
    previous_attendance=previous_attendance,
    subjects=subjects
)
# =========================
# TEACHER DASHBOARD
#
@app.route("/teacher")
def teacher_dashboard():

    if session.get("role") != "teacher":
        return redirect("/")

    teacher_id = session.get("user_id")
    today = datetime.today().date()
    teacher_name = session.get("username")

    # ================= TEACHER SUBJECTS =================
    classes = Class.query.filter_by(
        teacher_id=teacher_id,
        is_active=True
    ).all()

    total_classes = len(classes)

    # ================= PROGRAM IDS =================
    program_ids = list(set([c.program_id for c in classes]))

    # ================= TOTAL STUDENTS =================
    total_students = Student.query.filter(
        Student.program_id.in_(program_ids)
    ).count()

    # ================= PRESENT TODAY =================
    present_count = (
        db.session.query(db.func.count(db.distinct(Attendance.student_id)))
        .join(Class, Attendance.class_id == Class.id)
        .filter(
            Class.teacher_id == teacher_id,
            Attendance.date == today
        )
        .scalar()
    )

    absent_count = max(0, total_students - present_count)

    # ================= SUBJECT ATTENDANCE =================
    subject_stats = []

    for c in classes:

        total_records = Attendance.query.filter_by(
            class_id=c.id
        ).count()

        student_count = Student.query.filter_by(
            program_id=c.program_id
        ).count()

        percent = 0

        if student_count > 0:
            percent = round((total_records / student_count) * 100, 2)

        subject_stats.append({
            "subject": c.code,
            "percent": percent
        })

    # ================= RECENT SESSIONS =================
    recent_sessions = []

    sessions = (
        db.session.query(
            Attendance.session_id,
            Attendance.date,
            Attendance.class_id,
            db.func.count(db.distinct(Attendance.student_id)).label("present")
        )
        .join(Class, Attendance.class_id == Class.id)
        .filter(Class.teacher_id == teacher_id)
        .group_by(
            Attendance.session_id,
            Attendance.date,
            Attendance.class_id
        )
        .order_by(Attendance.date.desc())
        .limit(5)
        .all()
    )

    for s in sessions:

        class_obj = Class.query.get(s.class_id)

        total_students_class = Student.query.filter_by(
            program_id=class_obj.program_id
        ).count()

        absent = max(0, total_students_class - s.present)

        recent_sessions.append({
            "date": s.date,
            "class_name": f"{class_obj.code} - {class_obj.name}",
            "present": s.present,
            "absent": absent
        })

    # ================= TOTAL SESSIONS =================
    total_sessions = db.session.query(
        db.func.count(db.distinct(Attendance.session_id))
    ).join(
        Class, Attendance.class_id == Class.id
    ).filter(
        Class.teacher_id == teacher_id
    ).scalar()

    # ================= STUDENT PRESENT COUNT =================
    student_present = db.session.query(
        Student.roll,
        db.func.count(Attendance.id).label("present")
    ).join(
        Attendance, Student.id == Attendance.student_id
    ).join(
        Class, Attendance.class_id == Class.id
    ).filter(
        Class.teacher_id == teacher_id
    ).group_by(
        Student.id
    ).all()

    low_attendance_students = []

    for s in student_present:

        percent = (s.present / total_sessions) * 100 if total_sessions else 0

        if percent < 75:
            low_attendance_students.append({
                "roll": s.roll,
                "percentage": round(percent, 2)
            })

    # ================= MONTHLY TREND =================
    monthly_data = []

    for month in range(1, 6):
        count = Attendance.query.filter(
            db.extract("month", Attendance.date) == month
        ).count()

        monthly_data.append(count)

    monthly_labels = ["Jan", "Feb", "Mar", "Apr", "May"]



    
    # ================= RENDER =================
    return render_template(
        "teacher_dashboard.html",

        classes=classes,
       teacher_name=teacher_name,

        total_classes=total_classes,
        total_students=total_students,

        present_count=present_count,
        absent_count=absent_count,

        subject_stats=subject_stats,

        recent_sessions=recent_sessions,
        low_students=low_attendance_students,

        monthly_labels=monthly_labels,
        monthly_values=monthly_data
    )
# assign teacher to class
@app.route("/assign-teacher", methods=["POST"])
def assign_teacher():

    if session.get("role") != "hod":
        return render_message("Permission denied")

    teacher_id = request.form.get("teacher_id")
    class_id = request.form.get("class_id")

    if not teacher_id or not class_id:
        return render_message("Teacher or class missing")

    cls = Class.query.get(class_id)

    if not cls:
        return render_message("Invalid class")

    teacher = User.query.get(teacher_id)

    if not teacher or teacher.role != "teacher":
        return render_message("Invalid teacher")

    cls.teacher_id = teacher.id

    db.session.commit()

    return redirect("/hod")

#----------------
# HOD Dashboard
#----------------
from datetime import datetime

from datetime import datetime


@app.route("/hod")
def hod_dashboard():

    if session.get("role") != "hod":
        return redirect("/")

    classes = Class.query.filter_by(is_active=True).all()

    teachers = User.query.filter_by(role="teacher").count()

    students = Student.query.count()

    active_sessions = AttendanceSession.query.filter_by(is_closed=False).count()

    today = datetime.today().date()

    # -------------------------
    # TODAY ATTENDANCE
    # -------------------------
    present_today = Attendance.query.filter_by(date=today).count()

    absent_today = students - present_today
    if absent_today < 0:
        absent_today = 0

    attendance_percentage = 0
    if students > 0:
        attendance_percentage = round((present_today / students) * 100)

    # -------------------------
    # TODAY PROXY ATTEMPTS
    # -------------------------
    proxy_today = ProxyAttempt.query.filter(
        db.func.date(ProxyAttempt.time) == today
    ).count()

    # -------------------------
    # TEACHER WORKLOAD
    # -------------------------
    teacher_workload = []

    teacher_list = User.query.filter_by(role="teacher").all()

    for t in teacher_list:

        today_sessions = (
            db.session.query(AttendanceSession, Class)
            .join(Class, AttendanceSession.class_id == Class.id)
            .filter(
                AttendanceSession.teacher_id == t.id, AttendanceSession.date == today
            )
            .all()
        )

        subjects_today = []

        for s, c in today_sessions:
            subjects_today.append(f"{c.code} - {c.name}")

        teacher_workload.append({"teacher": t.username, "subjects": subjects_today})

    # -------------------------
    # RECENT SESSIONS
    # -------------------------
    recent_sessions = (
        db.session.query(AttendanceSession, Class)
        .join(Class, AttendanceSession.class_id == Class.id)
        .order_by(AttendanceSession.date.desc())
        .limit(5)
        .all()
    )

    return render_template(
        "hod_dashboard.html",
        classes=classes,
        teachers=teachers,
        students=students,
        active_sessions=active_sessions,
        attendance_percentage=attendance_percentage,
        present_today=present_today,
        absent_today=absent_today,
        proxy_today=proxy_today,
        teacher_workload=teacher_workload,
        recent_sessions=recent_sessions,
        now=datetime.now(),
    )

#search bar for teacher and hod to search student attendance by roll number#


@app.route("/search-student")
def search_student():

    try:

        keyword = request.args.get(
            "query",
            ""
        ).strip().lower()

        if keyword == "":
            return jsonify([])

        students = Student.query.all()

        result = []

        for s in students:

            # =========================
            # SEARCH
            # =========================
            if keyword in s.roll.lower():

                # =========================
                # PROGRAM
                # =========================
                program = Program.query.get(
                    s.program_id
                )

                # =========================
                # GET ATTENDANCE RECORDS
                # =========================
                attendances = Attendance.query.filter_by(
                    student_id=s.id
                ).all()

                subject_names = []

                for a in attendances:

                    cls = Class.query.get(a.class_id)

                    if cls and cls.name not in subject_names:

                        subject_names.append(
                            cls.name
                        )

                # =========================
                # ATTENDANCE %
                # =========================
                total_attendance = len(attendances)

                attendance_percent = min(
                    total_attendance * 5,
                    100
                )

                result.append({

                    "roll": s.roll,

                    "program":
                    program.name if program else "N/A",

                    "subjects":
                    subject_names if subject_names else [],

                    "attendance":
                    attendance_percent
                })

        return jsonify(result)

    except Exception as e:

        print("SEARCH ERROR:", e)

        return jsonify([])
    

@app.route("/check-students")
def check_students():

    students = Student.query.all()

    data = []

    for s in students:

        data.append({
            "id": s.id,
            "roll": s.roll,
            "class_id": s.class_id
        })

    return jsonify(data)
# START ATTENDANCE SESSION
# =========================
# =========================
@app.route("/start/<int:class_id>", methods=["GET", "POST"])
def start_session(class_id):

    if session.get("role") not in ["hod", "teacher"]:
        return redirect("/")

    teacher_id = session.get("user_id")

    # Verify teacher owns this subject
    cls = Class.query.filter_by(
        id=class_id, teacher_id=teacher_id, is_active=True
    ).first()

    if not cls:
        return render_message("Invalid or unauthorized subject")

    if request.method == "POST":

        session_type = request.form.get("session_type")

        # Prevent multiple THEORY sessions at the same time
        if session_type == "theory":

            active_session = AttendanceSession.query.filter(
                AttendanceSession.class_id == class_id,
                AttendanceSession.teacher_id == teacher_id,
                AttendanceSession.session_type == "theory",
                AttendanceSession.expires_at > datetime.now(),
            ).first()

            if active_session:
                return render_message("Theory session already active")

        # SESSION CREATION (for theory, lab, tutorial etc.)
        sid = str(uuid.uuid4())

        expires = datetime.now() + timedelta(minutes=TIMEOUT_IN_MINUTES)

        teacher_ip = request.remote_addr

        new_session = AttendanceSession(
            id=sid,
            class_id=class_id,
            teacher_id=teacher_id,
            date=datetime.today().date(),
            expires_at=expires,
            created_ip=teacher_ip,
            session_type=session_type,
        )

        db.session.add(new_session)
        db.session.commit()

        return render_template("session.html", session_id=sid, expires=expires)

    return render_template("start_session.html", cls=cls)


# =========================
# STUDENT ATTENDANCE PAGE
# =========================
@app.route("/mark-page/<session_id>")
def mark_page(session_id):
    # =========================
    # LOAD SESSION
    # =========================
    sess = db.session.get(AttendanceSession, session_id)

    if not sess or sess.expires_at < datetime.now() or sess.is_closed:
        return render_message("Session expired or closed by teacher!!!")

    cls = db.session.get(Class, sess.class_id)

    # =========================
    # SUBNET CHECK (DEPARTMENT WIFI)
    # Allow ±tolerance fluctuation on 3rd octet
    # =========================
   

    student_ip = request.remote_addr
    teacher_ip = sess.created_ip

    if not subnet_within_tolerance(teacher_ip, student_ip):
        return render_message(
            "<b>Attendance Marking Restricted!!!</b><br>"
            "You must be physically present in the department "
            "and connected to the departmental Wi-Fi."
        )

    session["dept_wifi_ok"] = True

    # =========================
    # CAPTCHA
    # =========================
    captcha_text, answer = generate_captcha()
    session["student_captcha"] = answer

    # =========================
    # TIME REMAINING
    # =========================
    remaining_seconds = int((sess.expires_at - datetime.now()).total_seconds())
    print("Teacher IP:", teacher_ip)
    print("Student IP:", student_ip)

    student_ip = request.remote_addr
    teacher_ip = sess.created_ip
    if remaining_seconds <= 0:
        return render_message("Session expired")

    # =========================
    # RENDER PAGE
    # =========================
    return render_template(
        "mark.html",
        session_id=session_id,
        remaining=remaining_seconds,
        captcha=captcha_text,
        class_code=cls.code,
        class_name=cls.name,
        session_type=sess.session_type,
    )


# =========================
# MARK ATTENDANCE (POST)
# =========================
from sqlalchemy.exc import IntegrityError
from datetime import datetime
import hashlib


@app.route("/mark", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def mark_attendance():

    roll = request.form.get("roll", "").strip()
    password = request.form.get("password", "")
    session_id = request.form.get("session_id", "")
    student_ip = request.remote_addr

    if request.method == "GET":
        return render_template("mark.html")

    # =========================
    # CAPTCHA CHECK
    # =========================
    captcha_input = request.form.get("captcha", "").strip()
    expected_captcha = session.pop("student_captcha", None)

    try:
        if expected_captcha is None or int(captcha_input) != expected_captcha:
            raise ValueError
    except:
        return render_message("Invalid CAPTCHA. Please reload and try again.")

    # =========================
    # AUTHENTICATE STUDENT
    # =========================
    student = Student.query.filter_by(roll=roll).first()

    if not student or not student.check_password(password):
        return render_message("Invalid student credentials")

    # =========================
    # VALIDATE SESSION
    # =========================
    sess = db.session.get(AttendanceSession, session_id)

    if not sess or sess.expires_at < datetime.now() or sess.is_closed:
        return render_message("Session expired")
    cls = Class.query.get(sess.class_id)

    if student.program_id != cls.program_id:
        return render_message("Wrong class")

    # =========================
    # WIFI NETWORK CHECK
    # =========================
    teacher_ip = sess.created_ip

    print("Teacher IP:", teacher_ip)
    print("Student IP:", student_ip)

    if not subnet_within_tolerance(teacher_ip, student_ip):
        return render_message("You must connect to department WiFi.")

    # =========================
    # DEVICE FINGERPRINT
    # =========================
    browser_fp = request.form.get("fingerprint", "").strip()

    if not browser_fp:
        return render_message("Page not fully loaded. Please reload.")

    device_id = hashlib.sha256(
        (student_ip + "|" + browser_fp).encode("utf-8", errors="ignore")
    ).hexdigest()

    # =========================
    # SAVE ATTENDANCE
    # =========================
    try:

        existing_device = SessionDevice.query.filter_by(
            session_id=session_id, device_id=device_id
        ).first()

        if existing_device:

            if existing_device.student_id == student.id:
                return render_message("Attendance already marked")

            db.session.add(
                ProxyAttempt(
                    session_id=session_id,
                    class_id=sess.class_id,
                    original_student_id=existing_device.student_id,
                    proxy_student_id=student.id,
                    device_id=device_id,
                    ip=student_ip,
                )
            )

            db.session.commit()

            return render_message(
                "😄 <b>Proxy attempt detected!</b><br>"
                "This device already marked attendance."
            )

        already_marked = Attendance.query.filter_by(
            student_id=student.id, session_id=session_id
        ).first()

        if already_marked:
            return render_message("Attendance already marked")

        db.session.add(
            SessionDevice(
                session_id=session_id, device_id=device_id, student_id=student.id
            )
        )

        db.session.add(
            Attendance(
                student_id=student.id,
                class_id=sess.class_id,
                date=datetime.today().date(),
                time=datetime.now().time(),
                session_type=sess.session_type,
                session_id=session_id,
                ip_address=student_ip   # 👈 ADD THIS LINE
            )
)

        db.session.commit()

    except IntegrityError:
        db.session.rollback()
        return render_message("Attendance already marked")

    return render_message("Attendance updated successfully", session_id=session_id)


# student forget password


@app.route("/student_reset_password", methods=["GET", "POST"])
def student_reset_password():

    if request.method == "POST":
        roll = request.form.get("roll")
        new_password = request.form.get("new_password")

        student = Student.query.filter_by(roll=roll).first()

        if not student:
            return render_message("Invalid roll number")

        if len(new_password) < 6:
            return render_message("Password must be at least 6 characters")

        student.set_password(new_password)
        db.session.commit()

        return render_message("Password updated successfully. Please login again.")

    return render_template("student_reset_password.html")


# =========================
# IMPORT STUDENTS (CSV)
# =========================
@app.route("/import", methods=["GET", "POST"])
def import_students():

    # 🔐 Login validation
    if session.get("role") != "hod":
        return redirect("/")

    # 🚫 Teachers cannot import students
    if session.get("role") == "teacher":
        return render_message("Only HOD can import students")

    if request.method == "POST":

        # -------------------------
        # ADMIN ACTION PASSWORD
        # -------------------------
        admin_action_password = request.form.get("admin_action_password", "").strip()
        secure = load_secure_users()

        if admin_action_password != secure.get("admin_action_password"):
            return render_message("Invalid admin action password")

        # -------------------------
        # FILE VALIDATION
        # -------------------------
        file = request.files.get("file")

        if not file or file.filename == "":
            return render_message("No file selected")

        try:
            rows = csv.DictReader(file.stream.read().decode("utf-8").splitlines())
        except Exception:
            return render_message("Invalid CSV file")

        imported = 0
        updated = 0
        skipped = 0
        errors = []

        # -------------------------
        # IMPORT LOGIC
        # -------------------------
        with db.session.no_autoflush:

            for idx, r in enumerate(rows, start=1):

                try:

                    name = r.get("name", "").strip()

                    roll = r.get("roll", "").strip()

                    password = r.get("password", "").strip()

                    email = r.get("email", "").strip().lower()

                    program_code = r.get("program_code", "")

                    program_code = program_code.replace("–", "-").replace("—", "-")
                    program_code = program_code.strip().upper()
                    # -------------------------
                    # BASIC VALIDATION
                    # -------------------------
                    if not name or not roll or not password or not email or not program_code:
                        errors.append(f"Row {idx}: missing required fields")
                        skipped += 1
                        continue

                    # -------------------------
                    # CHECK CLASS
                    # -------------------------
                    program = Program.query.filter_by(code=program_code).first()

                    if not program:
                        errors.append(f"{roll}: unknown program code '{program_code}'")
                        skipped += 1
                        continue

                    # -------------------------
                    # CHECK EXISTING STUDENT
                    # -------------------------
                    existing_student = Student.query.filter_by(roll=roll).first()

                    if existing_student:

                        existing_student.name = name

                        existing_student.program_id = program.id

                        existing_student.email = email

                        existing_student.set_password(password)

                        updated += 1
                        continue

                    # -------------------------
                    # ADD NEW STUDENT
                    # -------------------------
                    student = Student(

                            name=name,

                            roll=roll,

                            email=email,

                            program_id=program.id
                        )

                    student.set_password(password)

                    db.session.add(student)

                    imported += 1

                except Exception as e:

                    errors.append(f"Row {idx}: {str(e)}")
                    skipped += 1

        # -------------------------
        # COMMIT
        # -------------------------
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return render_message(f"Import failed: {str(e)}")

        # -------------------------
        # RESULT MESSAGE
        # -------------------------
        message = (
                f"Students import completed.<br><br>"

                f"✅ New Students Imported: {imported}<br>"

                f"🔄 Existing Students Updated: {updated}<br>"

                f"⚠️ Skipped: {skipped}"
            )

        if errors:
            message += "<br><br><b>Errors:</b><br>" + "<br>".join(errors[:20])

            if len(errors) > 20:
                message += "<br>... more errors omitted"

        return render_message(message)

    return render_template("import.html")


# =========================
# VIEW STUDENTS (CLASS-WISE)
# =========================


@app.route("/students")
def view_students():

    if session.get("role") not in ["hod", "teacher"]:
        return redirect("/")

    role = session.get("role")
    user_id = session.get("user_id")

    # HOD → all classes
   # HOD → only active classes
    if role == "hod":
        classes = Class.query.filter_by(is_active=True)\
            .order_by(Class.code)\
            .all()
    # Teacher → only their classes
    else:
        classes = (
            Class.query.filter_by(is_active=True, teacher_id=user_id)
            .order_by(Class.code)
            .all()
        )

    selected_class_id = request.args.get("class_id")

    students = []
    selected_class = None

    if selected_class_id:
        selected_class = db.session.get(Class, int(selected_class_id))

        if not selected_class:
            return render_message("Invalid class selected")

        # SECURITY: teacher cannot open other teacher classes
        if role == "teacher" and selected_class.teacher_id != user_id:
            return render_message("Access denied")

        students = (
    Student.query.filter_by(program_id=selected_class.program_id)
    .order_by(Student.roll)
    .all()
)
    return render_template(
        "students.html",
        classes=classes,
        students=students,
        selected_class=selected_class,
    )



#studnet view for teacher and hod to view student attendance details

@app.route("/student/view/<int:student_id>")
def teacher_view_student(student_id):

    if session.get("role") not in ["hod", "teacher"]:
        return redirect("/")

    student = Student.query.get_or_404(student_id)

    today = datetime.today().date()

    # -------------------------
    # ACTIVE SESSIONS
    # -------------------------
    active_sessions = db.session.query(
    AttendanceSession
    ).join(
        Attendance,
        Attendance.session_id == AttendanceSession.id
    ).filter(
        Attendance.student_id == student.id,
        AttendanceSession.date == today
    ).all()

    # -------------------------
    # TODAY ATTENDANCE
    # -------------------------
    today_attendance = db.session.query(
        Class.name,
        AttendanceSession.date,
        Attendance.id.label("present")
    ).join(
        AttendanceSession,
        AttendanceSession.class_id == Class.id
    ).outerjoin(
        Attendance,
        (Attendance.session_id == AttendanceSession.id) &
        (Attendance.student_id == student.id)
   ).filter(
    Attendance.student_id == student.id,
    AttendanceSession.date == today
    ).all()

    # -------------------------
    # PREVIOUS ATTENDANCE
    # -------------------------
    previous_attendance = db.session.query(
        Class.name,
        AttendanceSession.date,
        Attendance.id.label("present")
    ).join(
        AttendanceSession,
        AttendanceSession.class_id == Class.id
    ).outerjoin(
        Attendance,
        (Attendance.session_id == AttendanceSession.id) &
        (Attendance.student_id == student.id)
   ).filter(
    Attendance.student_id == student.id,
    AttendanceSession.date < today

    ).order_by(
        AttendanceSession.date.desc()
    ).limit(20).all()

    # -------------------------
    # SUBJECT ANALYTICS
    # -------------------------
    total_sessions = db.session.query(
    Class.id.label("class_id"),
    Class.name.label("subject"),
    db.func.count(AttendanceSession.id).label("total")
    ).join(
        AttendanceSession,
        AttendanceSession.class_id == Class.id
    ).join(
        Attendance,
        Attendance.session_id == AttendanceSession.id
    ).filter(
        Attendance.student_id == student.id
    ).group_by(
        Class.id
    ).subquery()

    present_sessions = db.session.query(
        Class.id.label("class_id"),
        db.func.count(Attendance.id).label("present")
    ).join(
        AttendanceSession,
        Attendance.session_id == AttendanceSession.id
    ).join(
        Class,
        AttendanceSession.class_id == Class.id
    ).filter(
        Attendance.student_id == student.id
    ).group_by(
        Class.id
    ).subquery()

    attendance = db.session.query(
        total_sessions.c.subject,
        total_sessions.c.total,
        db.func.coalesce(
            present_sessions.c.present,
            0
        ).label("present")
    ).outerjoin(
        present_sessions,
        total_sessions.c.class_id ==
        present_sessions.c.class_id
    ).all()

    subjects = []

    for row in attendance:

        percent = 0

        if row.total > 0:
            percent = round(
                (row.present / row.total) * 100,
                2
            )

        subjects.append({
            "subject": row.subject,
            "present": row.present,
            "absent": row.total - row.present,
            "total": row.total,
            "percent": percent,
            "status":
                "Good"
                if percent >= 75
                else "Low Attendance"
        })
    
    return render_template(
        "student_dashboard.html",

        student=student,

        student_name=student.name,

        class_name=student.program.code,

        active_sessions=active_sessions,

        today_attendance=today_attendance,

        previous_attendance=previous_attendance,

        subjects=subjects,

        view_mode=True
    )

@app.route("/student/forgot_password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        roll = request.form.get("roll")
        student = Student.query.filter_by(roll=roll).first()

        if not student or not student.email:
            return render_message("If account exists, reset link sent.")

        token = serializer.dumps(student.email, salt="password-reset")

        reset_url = url_for("reset_password", token=token, _external=True)

        msg = Message(
            "Password Reset - Attendance System",
            sender=app.config["MAIL_USERNAME"],
            recipients=[student.email],
        )

        msg.body = f"""
Click the link below to reset your password:

{reset_url}

This link expires in 10 minutes.
"""

        mail.send(msg)

        return render_message("Reset link sent to your email.")

    return render_template("student_forgot_password.html")


@app.route("/student/reset/<token>", methods=["GET", "POST"])
def reset_password(token):

    try:
        email = serializer.loads(
            token, salt="password-reset", max_age=900  # 15 minutes
        )
    except:
        return render_message("Invalid or expired link.")

    student = Student.query.filter_by(email=email).first()

    if request.method == "POST":
        new_password = request.form.get("new_password")

        if len(new_password) < 6:
            return render_message("Password must be at least 6 characters")

        student.set_password(new_password)
        db.session.commit()

        return render_message("Password updated successfully.")

    return render_template("reset_password.html")


# =========================
# TODAY'S ATTENDANCE
# =========================

from collections import defaultdict


@app.route("/attendance/today")
def today_attendance():

    if session.get("role") not in ["hod", "teacher"]:
        return redirect("/")

    today = datetime.today().date()
    selected_class = request.args.get("class_code")
    selected_type = request.args.get("session_type")

    role = session.get("role")
    user_id = session.get("user_id")

    # load all classes for dropdown
    all_classes = Class.query.filter_by(is_active=True).order_by(Class.code).all()
    query = (
       db.session.query(
            Class.code,
            Class.name,
            Attendance.session_id,
            Student.roll,
            Attendance.time,
            Attendance.session_type,

        )
        .join(Attendance, Attendance.student_id == Student.id)
        .join(Class, Attendance.class_id == Class.id)
        .join(AttendanceSession, Attendance.session_id == AttendanceSession.id)
        .filter(Attendance.date == today)
    )
    # =========================
    # TEACHER FILTER
    # =========================
    if role == "teacher":
        query = query.filter(AttendanceSession.teacher_id == user_id)

    # =========================
    # OPTIONAL FILTERS
    # =========================
    if selected_class:
        query = query.filter(Class.code == selected_class)

    if selected_type:
        query = query.filter(Attendance.session_type == selected_type)

    records = query.order_by(
        Class.code, Attendance.session_type, Attendance.session_id, Student.roll
    ).all()

    # =========================
    # GROUP RESULTS
    # =========================
    grouped = defaultdict(lambda: {"records": [], "first_time": None})

    for code, subject_name, session_id, roll, time, stype in records:

        display_name = f"{code} - {subject_name}"

        key = (display_name, stype, session_id)     

        grouped[key]["records"].append({"roll": roll, "time": time})

        if grouped[key]["first_time"] is None or time < grouped[key]["first_time"]:
            grouped[key]["first_time"] = time

    return render_template(
        "today_attendance.html",
        grouped=grouped,
        classes=all_classes,
        selected_class=selected_class,
        selected_type=selected_type,
        today=today,
    )


# =========================
# EXPORT RANGE (PIVOT FORMAT)
@app.route("/export/range", methods=["GET", "POST"])
def export_range():

    if session.get("role") not in ["hod", "teacher"]:
        return redirect("/")

    role = session.get("role")
    user_id = session.get("user_id")

    # ================= LOAD CLASSES =================
    if role == "hod":
        classes = Class.query.filter_by(is_active=True).order_by(Class.code).all()
    else:
        classes = Class.query.filter_by(
            teacher_id=user_id,
            is_active=True
        ).order_by(Class.code).all()

    # ================= GET REQUEST =================
    if request.method == "GET":

        class_id = request.args.get("class_code")

        selected_class = None

        if class_id:
                selected_class = Class.query.get(int(class_id))

        return render_template(
                "export_range.html",
                classes=classes,
                selected_class=selected_class
            )

    # ================= FORM DATA =================
    class_id = request.form.get("class_code")
    session_type = request.form.get("session_type")
    start_date_raw = request.form.get("start_date")
    end_date_raw = request.form.get("end_date")
    action = request.form.get("action")

    if not class_id or not start_date_raw or not end_date_raw:
        return render_template(
            "export_range.html",
            classes=classes,
            selected_class=None
        )

    class_id = int(class_id)

    # ================= SECURITY =================
    if role == "teacher":
        check = Class.query.filter_by(id=class_id, teacher_id=user_id).first()
        if not check:
            return render_message("You cannot export another teacher's subject")

    # ================= LOAD CLASS =================
    cls = Class.query.filter_by(id=class_id, is_active=True).first()

    if not cls:
        return render_message("Invalid subject")

    # ================= DATE PARSE =================
    start_date = datetime.strptime(start_date_raw, "%Y-%m-%d").date()
    end_date = datetime.strptime(end_date_raw, "%Y-%m-%d").date()

    # ================= DATE RANGE =================
    dates = []
    d = start_date
    while d <= end_date:
        dates.append(d)
        d += timedelta(days=1)

    # ================= STUDENTS =================
    students = Student.query.filter_by(
        program_id=cls.program_id
    ).order_by(Student.roll).all()

    # ================= ATTENDANCE RECORDS =================
    records = Attendance.query.filter(
        Attendance.class_id == class_id,
        Attendance.session_type == session_type,
        Attendance.date.between(start_date, end_date)
    ).all()

    present = {(r.student_id, r.date) for r in records}

    # Remove empty days
    dates = [d for d in dates if any((s.id, d) in present for s in students)]

    total_days = len(dates)

    # ================= EXPORT =================
    if action == "export":

        export_format = request.form.get("format", "csv")

        # ---------- CSV ----------
        if export_format == "csv":

            def generate():

                yield ",".join(
                    ["Roll"] + [str(d) for d in dates] + ["Total", "Percentage"]
                ) + "\n"

                for s in students:

                    present_count = 0
                    row = [s.roll]

                    for d in dates:

                        if (s.id, d) in present:
                            row.append("P")
                            present_count += 1
                        else:
                            row.append("")

                    percent = round((present_count / total_days) * 100, 2) if total_days else 0

                    row += [str(present_count), f"{percent}%"]

                    yield ",".join(row) + "\n"

            return Response(
                generate(),
                mimetype="text/csv",
                headers={
                    "Content-Disposition":
                    f"attachment; filename=attendance_{cls.code}.csv"
                }
            )

        # ---------- PDF ----------
        if export_format == "pdf":

            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet
            from io import BytesIO

            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer)

            styles = getSampleStyleSheet()
            elements = []

            elements.append(
                Paragraph(
                    f"Attendance Report - {cls.code} ({session_type})",
                    styles["Heading2"]
                )
            )

            elements.append(Spacer(1, 20))

            table_data = [["Roll"] + [str(d) for d in dates] + ["Total", "%"]]

            for s in students:

                present_count = 0
                row = [s.roll]

                for d in dates:

                    if (s.id, d) in present:
                        row.append("P")
                        present_count += 1
                    else:
                        row.append("")

                percent = round((present_count / total_days) * 100, 2) if total_days else 0

                row += [present_count, f"{percent}%"]

                table_data.append(row)

            table = Table(table_data, repeatRows=1)

            table.setStyle(TableStyle([
                ("GRID", (0,0), (-1,-1), 0.5, colors.black),
                ("BACKGROUND", (0,0), (-1,0), colors.grey),
                ("TEXTCOLOR", (0,0), (-1,0), colors.whitesmoke),
                ("ALIGN", (1,1), (-1,-1), "CENTER")
            ]))

            elements.append(table)

            doc.build(elements)

            buffer.seek(0)

            return Response(
                buffer.getvalue(),
                mimetype="application/pdf",
                headers={
                    "Content-Disposition":
                    f"attachment; filename=attendance_{cls.code}.pdf"
                }
            )

    # ================= PREVIEW =================
    preview = []

    for s in students:

        marks = []
        present_count = 0

        for d in dates:

            if (s.id, d) in present:
                marks.append("P")
                present_count += 1
            else:
                marks.append("")

        percent = round((present_count / total_days) * 100, 2) if total_days else 0

        preview.append({
            "roll": s.roll,
            "marks": marks,
            "total_present": present_count,
            "percentage": percent
        })

    return render_template(
        "export_range.html",
        classes=classes,
        preview=preview,
        dates=dates,
        selected_class=cls,
        session_type=session_type,
        start_date=start_date,
        end_date=end_date
    )





from sqlalchemy.orm import aliased

@app.route("/proxy-attempts")
def proxy_attempts():

    if not session.get("user_id"):
        return redirect("/")

    role = session.get("role")
    teacher_id = session.get("user_id")

    OriginalStudent = aliased(Student)
    ProxyStudent = aliased(Student)

    query = (
        db.session.query(
            ProxyAttempt,
            Class.name,
            OriginalStudent.roll.label("original_roll"),
            ProxyStudent.roll.label("proxy_roll")
        )
        .join(Class, ProxyAttempt.class_id == Class.id)
        .join(OriginalStudent, ProxyAttempt.original_student_id == OriginalStudent.id)
        .join(ProxyStudent, ProxyAttempt.proxy_student_id == ProxyStudent.id)
    )

    # Apply filter only for teacher
    if role == "teacher":
        query = query.filter(Class.teacher_id == teacher_id)

    attempts = query.order_by(ProxyAttempt.time.desc()).all()

    return render_template("proxy_attempts.html", attempts=attempts)
@app.route("/active-sessions")
def active_sessions():

    if not session.get("user_id"):
        return redirect("/")

    now = datetime.now()

    query = (
        db.session.query(AttendanceSession, Class)
        .join(Class, AttendanceSession.class_id == Class.id)
        .filter(
            AttendanceSession.expires_at >= now, AttendanceSession.is_closed == False
        )
    )

    if session.get("role") == "teacher":
        teacher_id = session.get("user_id")
        query = query.filter(Class.teacher_id == teacher_id)

    sessions = query.order_by(AttendanceSession.expires_at).all()

    return render_template("active_sessions.html", sessions=sessions, now=now)


@app.route("/end-session/<session_id>", methods=["POST"])
def end_session(session_id):

    if session.get("role") not in ["hod", "teacher"]:
        return redirect("/")

    sess = db.session.get(AttendanceSession, session_id)

    if not sess:
        return redirect("/active-sessions")

    sess.is_closed = True
    db.session.commit()

    return redirect("/active-sessions")


from sqlalchemy.orm import aliased



import qrcode
from io import BytesIO
from flask import send_file
from PIL import Image


@app.route("/qr/<session_id>")
def qr_code(session_id):
    url = f"http://{request.host}/mark-page/{session_id}"

    qr = qrcode.QRCode(
        version=2,  # smaller version
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=6,  # 🔴 controls size (try 3–5)
        border=2,
    )

    qr.add_data(url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    return send_file(buf, mimetype="image/png")



@app.route("/attendance/edit", methods=["GET", "POST"])
def edit_attendance():

    # 🔐 Access control
    if session.get("role") not in ["hod", "teacher"]:
        return redirect("/")

    role = session.get("role")
    user_id = session.get("user_id")

    # ================= LOAD CLASSES =================
    if role == "hod":
        classes = Class.query.order_by(Class.code).all()
    else:
        classes = Class.query.filter_by(
            teacher_id=user_id
        ).order_by(Class.code).all()

    # ================= DEFAULT VALUES =================
    selected_class = None
    session_type = None

    # ================= HANDLE POST =================
    if request.method == "POST":

        class_id = request.form.get("class_id")
        date_str = request.form.get("date")
        session_type = request.form.get("session_type")

        # ✅ Always load selected class
        if class_id:
            selected_class = Class.query.get(int(class_id))

        # 🔐 Teacher restriction
        if class_id and role == "teacher":
            cls_check = Class.query.filter_by(
                id=int(class_id),
                teacher_id=user_id
            ).first()

            if not cls_check:
                return render_message("You cannot edit another teacher's subject")

        # ================= LOAD ATTENDANCE =================
        if class_id and date_str and session_type:

            date = datetime.strptime(date_str, "%Y-%m-%d").date()

            sessions = AttendanceSession.query.filter_by(
                class_id=int(class_id),
                date=date,
                session_type=session_type
            ).order_by(AttendanceSession.expires_at).all()

            students = Student.query.filter_by(
                program_id=selected_class.program_id
            ).order_by(Student.roll).all()

            selected_session_id = request.form.get("session_id")

            if not selected_session_id and sessions:
                selected_session_id = sessions[0].id

            present = set()

            if selected_session_id:
                present = {
                    a.student_id
                    for a in Attendance.query.filter_by(
                        session_id=selected_session_id
                    ).all()
                }

            return render_template(
                "edit_attendance.html",
                students=students,
                present=present,
                class_id=class_id,
                date=date,
                session_type=session_type,
                classes=classes,
                sessions=sessions,
                selected_session_id=selected_session_id,
                timedelta=timedelta,
                selected_class=selected_class   # ✅ IMPORTANT
            )

    # ================= DEFAULT PAGE =================
    return render_template(
        "edit_attendance_select.html",
        classes=classes,
        selected_class=selected_class,   # ✅ IMPORTANT
        selected_type=session_type       # ✅ IMPORTANT
    )


@app.route("/attendance/update", methods=["POST"])
def update_attendance():
    print("SESSION:", session)
    if session.get("role") not in ["hod", "teacher"]:
        return redirect("/")

    teacher_password = request.form.get("teacher_password")

    user = User.query.get(session.get("user_id"))

    if not user or not user.check_password(teacher_password):
        return render_message("Invalid password")

    class_id = int(request.form.get("class_id"))
    date = datetime.strptime(request.form.get("date"), "%Y-%m-%d").date()
    session_type = request.form.get("session_type")
    session_id = request.form.get("session_id")
    reason = request.form.get("reason")

    if not session_id:
        return render_message("No session selected")

    session_id = session_id

    cls = Class.query.get(class_id)

    students = Student.query.filter_by(
        program_id=cls.program_id
    ).all()

    existing = {
        a.student_id: a for a in Attendance.query.filter_by(session_id=session_id).all()
    }

    for s in students:

        checked = f"present_{s.id}" in request.form

        if checked and s.id not in existing:

            db.session.add(
                Attendance(
                    student_id=s.id,
                    class_id=class_id,
                    date=date,
                    time=datetime.now().time(),
                    session_type=session_type,
                    session_id=session_id,
                )
            )

            db.session.add(
                AttendanceOverride(
                    student_id=s.id,
                    class_id=class_id,
                    date=date,
                    action="ADDED",
                    reason=reason,
                    teacher_ip=request.remote_addr,
                )
            )

        if not checked and s.id in existing:

            db.session.delete(existing[s.id])

            db.session.add(
                AttendanceOverride(
                    student_id=s.id,
                    class_id=class_id,
                    date=date,
                    action="REMOVED",
                    reason=reason,
                    teacher_ip=request.remote_addr,
                )
            )

    db.session.commit()

    return render_message("Attendance updated successfully")
#student profile edit
@app.route("/student/edit_profile", methods=["GET", "POST"])
def edit_profile():

    # Login check
    if session.get("role") != "student":
        return redirect("/")

    student_id = session.get("student_id")

    # Get student
    student = Student.query.get(student_id)

    if not student:
        return redirect("/")

    # UPDATE
    if request.method == "POST":

        student.name = request.form.get("name")
        student.email = request.form.get("email")

        db.session.commit()

        flash("Profile updated successfully")

        return redirect("/student/dashboard")

    return render_template(
        "edit_profile.html",
        student=student
    )

#------------------------
# Class management (HOD only)
#------------------------
@app.route("/programs/manage", methods=["GET","POST"])
def manage_programs():

    if session.get("role") != "hod":
        return redirect("/")

    if request.method == "POST":

        action = request.form.get("action")

        code = request.form.get("code","").strip().upper()
        name = request.form.get("name","").strip()
        program_id = request.form.get("program_id")

        # --------------------
        # ADD PROGRAM
        # --------------------
        if action == "add":

            existing = Program.query.filter_by(code=code).first()

            if existing:
                return render_message("Program already exists")

            db.session.add(
                Program(code=code, name=name)
            )

            db.session.commit()

            return redirect("/programs/manage")


        # --------------------
        # UPDATE PROGRAM
        # --------------------
        if action == "update":

            program = Program.query.get(int(program_id))

            if not program:
                return render_message("Program not found")

            program.code = code
            program.name = name

            db.session.commit()

            return redirect("/programs/manage")


        # --------------------
        # DELETE PROGRAM
        # --------------------
        if action == "delete":

            program = Program.query.get(int(program_id))

            if not program:
                return render_message("Program not found")

            subject_exists = Class.query.filter_by(
                program_id=program.id
            ).first()

            if subject_exists:
                return render_message(
                    "Cannot delete program with subjects"
                )

            db.session.delete(program)
            db.session.commit()

            return redirect("/programs/manage")

    # GET request
    programs = Program.query.order_by(Program.code).all()

    return render_template(
        "manage_programs.html",
        programs=programs
    )
@app.route("/subjects/manage", methods=["GET", "POST"])
def manage_subjects():
    if session.get("role") != "hod":
        return redirect("/")

    secure = load_secure_users()

    if request.method == "POST":
        action = request.form.get("action")
        action_password = request.form.get("admin_action_password")

        # 🔐 VERIFY ACTION PASSWORD
        if action_password != secure.get("admin_action_password"):
            return render_message("Invalid admin action password")

        # ➕ ADD SUBJECT
        if action == "add":
            # 🔴 EXACT FIX STARTS HERE
            code = request.form.get("code", "")
            name = request.form.get("name", "")
            program_code = request.form.get("program_code", "").strip().upper()
            has_practical = request.form.get("has_practical") == "yes"

            # 🔒 HARD NORMALIZATION (CRITICAL)
            code = code.strip().upper()
            name = name.strip()

            if not code or not name:
                return render_message("Subject code and name are required")

            existing = Class.query.filter_by(code=code).first()
            program = Program.query.filter_by(code=program_code).first()

            if not program:
                return render_message("Invalid program code")
            if existing:
                    if not existing.is_active:
                        existing.is_active = True
                        existing.name = name
                        existing.program_id = program.id
                        existing.has_practical = has_practical
                        db.session.commit()
                        return render_message("Subject reactivated successfully")
                    else:
                       return render_message("Subject code already exists")

            # ➕ ADD NEW SUBJECT
            db.session.add(
                Class(
                    code=code,
                    name=name,
                    program_id=program.id,
                    has_practical=has_practical,
                    is_active=True
                )
      )
            db.session.commit()

            return render_message("Subject added successfully")

        # 🚫 DEACTIVATE SUBJECT
        if action == "deactivate":
            class_id = int(request.form.get("class_id", 0))
            cls = Class.query.filter_by(id=class_id, is_active=True).first()
            if not cls:
                return render_message("Invalid or already inactive subject")

            cls.is_active = False
            db.session.commit()
            return render_message("Subject deactivated successfully")

        # ♻️ REACTIVATE SUBJECT
        if action == "reactivate":
            class_id = int(request.form.get("class_id", 0))
            cls = Class.query.filter_by(id=class_id, is_active=False).first()
            if not cls:
                return render_message("Invalid or already active subject")

            cls.is_active = True
            db.session.commit()
            return render_message("Subject reactivated successfully")

        # ❌ PERMANENT DELETE SUBJECT (ONLY IF INACTIVE)
        if action == "delete":
            class_id = int(request.form.get("class_id", 0))

            cls = Class.query.filter_by(id=class_id, is_active=False).first()
            if not cls:
                return render_message(
                    "Only inactive subjects can be permanently deleted"
                )

            # 🔒 Prevent deletion if attendance exists
            session_exists = AttendanceSession.query.filter_by(class_id=class_id).first()

            if session_exists:
                return render_message(
                    "Cannot delete subject because attendance records exist"
                )

            # 🔴 Delete subject
            db.session.delete(cls)
            db.session.commit()

            return render_message("Subject permanently deleted.")
        return render_message("Invalid action")

    # ===== GET =====
    active_classes = Class.query.filter_by(is_active=True)\
        .join(Program)\
        .order_by(Program.code, Class.code)\
        .all()
    inactive_classes = Class.query.filter_by(is_active=False)\
        .join(Program)\
        .order_by(Program.code, Class.code)\
        .all()
    programs = Program.query.order_by(Program.code).all()

    return render_template(
        "manage_subjects.html",
        active_classes=active_classes,
        inactive_classes=inactive_classes,
        programs=programs
    )
@app.route("/server-time")
def server_time():
    return {"time": datetime.now().strftime("%d-%m-%Y %H:%M")}


import socket



def print_startup_banner(port=5000):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"

    print(" * Running on all addresses (0.0.0.0)")
    print(f" * Running on http://127.0.0.1:{port}")
    print(f" * Running on http://{local_ip}:{port}")



# =========================
# INIT
# =========================
from waitress import serve

def initialize_app():
    print_startup_banner(5000)

    with app.app_context():
        db.create_all()

        if not User.query.filter_by(role="hod").first():
            hod = User(username="hod", role="hod")
            hod.set_password("9400")

            db.session.add(hod)
            db.session.commit()

if __name__ == "__main__":
    initialize_app()
    
  
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
        threaded=True
    )