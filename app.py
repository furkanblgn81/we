from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from functools import wraps
import pymysql
import os
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = "FURKAN_SECRET"

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Boyut limitleri
MAX_SIZE_MEMBER = 500 * 1024 * 1024  # 500 MB
MAX_SIZE_GUEST = 5 * 1024 * 1024     # 5 MB

# Mail ayarları
MAIL_SERVER = "smtp.gmail.com"
MAIL_PORT = 587
MAIL_USERNAME = "furkannbilgin82@gmail.com"
MAIL_PASSWORD = "cfwbswwmrlglpotl"  # uygulama şifresi

# ------------------- DB bağlantısı -------------------
def get_db():
    return pymysql.connect(
        host="localhost",
        user="root",
        password="1234",
        database="kullanici_db",
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor
    )

# ------------------- Login kontrol -------------------
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

# ------------------- ROUTES -------------------

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE username=%s OR email=%s", (username, email))
        if cur.fetchone():
            flash("Bu kullanıcı adı veya email zaten kayıtlı.")
            return redirect(url_for('register'))

        cur.execute("INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)",
                    (username, email, password, role))
        db.commit()
        cur.close()
        flash("Kayıt başarılı, giriş yapabilirsiniz.")
        return redirect(url_for('home'))

    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username=%s AND password=%s", (username, password))
    user = cur.fetchone()
    cur.close()

    if user:
        session['username'] = user['username']
        session['role'] = user['role']
        session['user_id'] = user['id']
        return redirect(url_for('upload_file'))
    else:
        flash("Hatalı kullanıcı adı veya şifre!")
        return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Çıkış yapıldı.")
    return redirect(url_for('home'))

@app.route('/admin/dashboard')
@login_required(role='admin')
def admin_dashboard():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users ORDER BY id ASC")
    users = cur.fetchall()
    cur.close()
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/files')
@login_required(role='admin')
def admin_files():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT f.id, f.original_filename, f.receiver_email, f.upload_date, f.max_download_time,
               u.username AS registered_user, f.guest_email
        FROM uploaded_files f
        LEFT JOIN users u ON f.uploader_id = u.id
        ORDER BY f.upload_date DESC
    """)
    files = cur.fetchall()
    cur.close()
    return render_template('admin_files.html', files=files)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    user_id = session.get('user_id')
    guest_email = None

    if request.method == 'GET':
        return render_template('upload.html')

    file = request.files.get('file')
    receiver_email = request.form.get('receiver_email')
    message = request.form.get('message')
    valid_days = int(request.form.get('valid_days', 7))

    # Misafir ise kendi emailini zorunlu kıl
    if not user_id:
        guest_email = request.form.get('guest_email')
        if not guest_email:
            flash("Misafir olarak yüklerken e-posta adresinizi giriniz.")
            return redirect(url_for('upload_file'))

    if not file or file.filename == '':
        flash("Dosya seçilmedi.")
        return redirect(url_for('upload_file'))

    # Boyut kontrolü
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)

    limit = MAX_SIZE_MEMBER if user_id else MAX_SIZE_GUEST
    if size > limit:
        if not user_id:
            flash("Misafir olarak yalnızca 5 MB'a kadar dosya gönderebilirsiniz. Daha büyük dosyalar için giriş yapın.")
        else:
            flash(f"Dosya boyutu izin verilen sınırı aşıyor ({limit // (1024*1024)} MB).")
        return redirect(url_for('upload_file'))

    # Kaydetme
    original_name = secure_filename(file.filename)
    unique_name = str(uuid.uuid4()) + "_" + original_name
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
    file.save(save_path)

    valid_until = datetime.utcnow() + timedelta(days=valid_days)
    token = str(uuid.uuid4())

    db = get_db()
    cur = db.cursor()
    cur.execute("""
        INSERT INTO uploaded_files 
        (uploader_id, guest_email, original_filename, saved_filename, upload_date, max_download_time, token, receiver_email, message)
        VALUES (%s, %s, %s, %s, NOW(), %s, %s, %s, %s)
    """, (user_id, guest_email, original_name, unique_name, valid_until, token, receiver_email, message))
    file_id = cur.lastrowid
    db.commit()
    cur.close()

    # Mail gönder
    send_download_email(receiver_email, file_id, token, message, valid_days)

    flash("Dosya yüklendi ve mail gönderildi.")
    return redirect(url_for('upload_file'))

@app.route('/download/<int:file_id>')
def download_file(file_id):
    token = request.args.get('token')
    if not token:
        return "Geçersiz istek", 400

    downloader_email = request.args.get('email', 'Bilinmiyor')

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM uploaded_files WHERE id=%s AND token=%s", (file_id, token))
    file = cur.fetchone()

    if not file:
        return "Geçersiz veya süresi dolmuş link", 403

    if file['max_download_time'] < datetime.utcnow():
        return "İndirme süresi dolmuş", 403

    # Log kaydı
    cur.execute("INSERT INTO file_download_logs (file_id, downloader_email, download_time) VALUES (%s, %s, NOW())",
                (file_id, downloader_email))
    db.commit()

    # Bildirim gönder
    owner_email = file['guest_email'] if file['guest_email'] else get_user_email(file['uploader_id'])
    if owner_email:
        send_download_notification(owner_email, file['original_filename'], downloader_email)

    cur.close()
    return send_from_directory(app.config['UPLOAD_FOLDER'], file['saved_filename'], as_attachment=True)

# ------------------- Yardımcılar -------------------

def get_user_email(user_id):
    if not user_id:
        return None
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT email FROM users WHERE id=%s", (user_id,))
    user = cur.fetchone()
    cur.close()
    return user['email'] if user else None

def send_download_email(receiver, file_id, token, message, days):
    link = f"http://<SUNUCU_IP_ADRESİ>:5000/download/{file_id}?token={token}&email={receiver}"
    body = f"""
Merhaba,

Size bir dosya gönderildi. {days} gün içinde indirebilirsiniz:

{link}

Mesaj: {message or '(Mesaj yok)'}
"""
    send_email(receiver, "Dosya İndirme Linki", body)

def send_download_notification(receiver, filename, downloader_email):
    body = f"""
'{filename}' adlı dosyanız {downloader_email} tarafından indirildi.
"""
    send_email(receiver, "Dosya İndirildi", body)

def send_email(to, subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = MAIL_USERNAME
    msg['To'] = to

    try:
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
            server.starttls()
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print("Mail gönderilemedi:", e)

@app.context_processor
def utility_processor():
    def get_download_logs(file_id):
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT downloader_email, download_time FROM file_download_logs WHERE file_id=%s ORDER BY download_time DESC", (file_id,))
        logs = cur.fetchall()
        cur.close()
        return logs
    return dict(get_download_logs=get_download_logs)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
