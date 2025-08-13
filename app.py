from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify
from functools import wraps
import pymysql
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import re
import logging

# --- Logging ---
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

# --- Flask app ---
app = Flask(__name__)
app.secret_key = "key"  # production ortamında değiştir

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

MAX_SIZE_MEMBER = 500 * 1024 * 1024  # 500 MB
MAX_SIZE_GUEST = 5 * 1024 * 1024     # 5 MB

# --- DB bağlantısı ---
def get_db():
    return pymysql.connect(
        host="138.68.68.5",
        user="admin",
        password="1234",
        database="kullanici_db",
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor
    )

# --- Login kontrolü ---
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

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username=%s OR email=%s", (username, username))
    user = cur.fetchone()
    cur.close()
    db.close()

    if not user:
        flash("Kullanıcı bulunamadı.")
        return redirect(url_for('home'))

    try:
        ok = check_password_hash(user['password'], password)
    except:
        ok = False

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

# --- Admin Files ---
@app.route('/admin/files')
@login_required(role='admin')
def admin_files():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM files ORDER BY id DESC")
    files = cur.fetchall()
    cur.close()
    db.close()
    return render_template('admin_files.html', files=files, get_download_logs=get_download_logs)

# --- Download Logları ---
def get_download_logs(file_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM download_logs WHERE file_id=%s ORDER BY download_time DESC", (file_id,))
    logs = cur.fetchall()
    cur.close()
    db.close()
    return logs

# --- Download Confirm / Onay Sayfası ---
@app.route('/download_confirm/<stored_filename>')
def download_confirm(stored_filename):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT original_filename FROM files WHERE stored_filename=%s", (stored_filename,))
    result = cur.fetchone()
    cur.close()
    db.close()

    if not result:
        return "Dosya bulunamadı.", 404

    original_filename = result['original_filename']
    return render_template('download_confirm.html', stored_filename=stored_filename, original_filename=original_filename)

# --- Gerçek Download ---
@app.route('/download_file/<stored_filename>')
def download_file_final(stored_filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], stored_filename, as_attachment=True)

# --- Upload + Kuyruğa ekleme ---
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    user_id = session.get('user_id')
    is_guest = user_id is None

    if request.method == 'POST':
        receiver_email = request.form.get('receiver_email')
        message = request.form.get('message', '')
        file = request.files.get('file')
        valid_days = int(request.form.get('valid_days', 7))

        if not file:
            flash("Dosya seçmelisiniz.")
            return redirect(request.url)

        max_size = MAX_SIZE_GUEST if is_guest else MAX_SIZE_MEMBER
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        if size > max_size:
            flash(f"Dosya boyutu sınırı aşıldı. Maksimum {max_size // (1024*1024)} MB")
            return redirect(request.url)

        guest_email = None
        if is_guest:
            guest_email = request.form.get('guest_email')
            if not guest_email or not is_valid_email(guest_email):
                flash("Geçerli bir e-posta adresi giriniz.")
                return redirect(request.url)

        filename = secure_filename(file.filename)
        stored_name = f"{uuid.uuid4().hex}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], stored_name))

        db = get_db()
        cur = db.cursor()
        cur.execute("""
            INSERT INTO files (stored_filename, original_filename, receiver_email, uploaded_by, guest_email, upload_date, max_download_time)
            VALUES (%s, %s, %s, %s, %s, NOW(), DATE_ADD(NOW(), INTERVAL %s DAY))
        """, (
            stored_name,
            filename,
            receiver_email,
            None if is_guest else user_id,
            guest_email,
            valid_days
        ))

        # Kuyruğa ekle
        download_link = url_for('download_confirm', stored_filename=stored_name, _external=True)
        email_body = f"Merhaba,\n\nSize bir dosya gönderildi: {filename}\nMesaj: {message}\nİndirmek için: {download_link}"

        cur.execute("""
            INSERT INTO email_queue (to_email, subject, body, status, created_at)
            VALUES (%s, %s, %s, 'pending', NOW())
        """, (
            receiver_email,
            "Dosya Paylaşım Bildirimi",
            email_body
        ))

        db.commit()
        cur.close()
        db.close()

        flash("Dosya başarıyla yüklendi ve kuyruğa eklendi.")
        return redirect(url_for('home'))

    return render_template('upload.html', username=session.get('username'),
                           max_size_member=MAX_SIZE_MEMBER // (1024*1024),
                           max_size_guest=MAX_SIZE_GUEST // (1024*1024))

# --- API: Bekleyen mailler ---
@app.route('/api/get_pending_emails', methods=['GET'])
def get_pending_emails():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM email_queue WHERE status='pending' LIMIT 10")
    emails = cur.fetchall()
    cur.close()
    db.close()
    return jsonify(emails)

# --- API: Maili gönderildi olarak işaretle ---
@app.route('/api/mark_email_sent', methods=['POST'])
def mark_email_sent():
    data = request.get_json()
    email_id = data.get('id')

    if not email_id:
        return jsonify({'status': 'error', 'message': 'id parametresi eksik'}), 400

    db = get_db()
    cur = db.cursor()
    cur.execute(
        "UPDATE email_queue SET status='sent', sent_at=NOW() WHERE id=%s",
        (email_id,)
    )
    db.commit()
    cur.close()
    db.close()
    return jsonify({'status': 'ok'})

# --- Uygulamayı çalıştır ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
