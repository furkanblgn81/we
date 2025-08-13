# app.py
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, abort
from functools import wraps
import pymysql
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
import re
import logging

# Basit logging (console)
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = "key"  # production: daha uzun/gizli yap

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

MAX_SIZE_MEMBER = 500 * 1024 * 1024  # 500 MB
MAX_SIZE_GUEST = 5 * 1024 * 1024     # 5 MB

MAIL_SERVER = "smtp.gmail.com"
MAIL_PORT = 587
MAIL_USERNAME = "furkannbilgin82@gmail.com"
MAIL_PASSWORD = "baixextgzodivtuc"  # production: ortam değişkeni kullan

# --- DB Bağlantısı: admin kullanıcı ---
def get_db():
    return pymysql.connect(
        host="127.0.0.1",   # veya localhost
        user="admin",
        password="1234",
        database="kullanici_db",
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor
    )


# --- Decorator ---
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'username' not in session:
                flash("Giriş yapmalısınız.")
                return redirect(url_for('home'))
            if role and session.get('role') != role:
                flash("Yetkiniz yok.")
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated
    return decorator

# --- Email doğrulama ---
def is_valid_email(email):
    regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(regex, email) is not None

# --- Anasayfa ---
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('upload_file'))
    return render_template('login.html')

# --- Kayıt ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        role = 'user'

        if not is_valid_email(email):
            flash("Geçerli bir email adresi giriniz.")
            return redirect(url_for('register'))

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE username=%s OR email=%s", (username, email))
        if cur.fetchone():
            flash("Bu kullanıcı adı veya email zaten kayıtlı.")
            cur.close()
            db.close()
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        cur.execute("INSERT INTO users (username, email, password, role, created_at) VALUES (%s, %s, %s, %s, NOW())",
                    (username, email, hashed_password, role))
        db.commit()
        cur.close()
        db.close()
        flash("Kayıt başarılı, giriş yapabilirsiniz.")
        return redirect(url_for('home'))

    return render_template('register.html')

# --- Login ---
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    log.debug(f"Login attempt: username/email={username}, password length={len(password)}")

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username=%s OR email=%s", (username, username))
    user = cur.fetchone()
    cur.close()
    db.close()

    log.debug(f"User found: {user}")

    if not user:
        flash("Kullanıcı bulunamadı.")
        return redirect(url_for('home'))

    try:
        ok = check_password_hash(user['password'], password)
    except Exception as e:
        log.exception("Password check error")
        ok = False

    log.debug(f"Password check result: {ok}")

    if ok:
        session['username'] = user['username']
        session['role'] = user['role']
        session['user_id'] = user['id']
        flash(f"Hoşgeldin, {user['username']}!")

        if user['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('upload_file'))
    else:
        flash("Hatalı kullanıcı adı veya şifre!")
        return redirect(url_for('home'))

# --- Logout ---
@app.route('/logout')
def logout():
    session.clear()
    flash("Çıkış yapıldı.")
    return redirect(url_for('home'))

# --- Admin Dashboard ---
@app.route('/admin/dashboard')
@login_required(role='admin')
def admin_dashboard():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, username, email, role, created_at FROM users ORDER BY id ASC")
    users = cur.fetchall()
    cur.close()
    db.close()
    return render_template('admin_dashboard.html', users=users)

# --- Upload ---
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    user_id = session.get('user_id')
    guest_email = None

    if request.method == 'GET':
        return render_template('upload.html', username=session.get('username'),
                               max_size_member=MAX_SIZE_MEMBER // (1024*1024),
                               max_size_guest=MAX_SIZE_GUEST // (1024*1024))

    # Upload kodunu buraya ekle
    return "Upload endpoint placeholder (kodun burada çalışmalı)"

# --- Yardımcı Fonksiyon ---
def get_user_email(user_id):
    if not user_id:
        return None
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT email FROM users WHERE id=%s", (user_id,))
    user = cur.fetchone()
    cur.close()
    db.close()
    return user['email'] if user else None

# --- Uygulamayı çalıştır ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
