import time
import requests
import smtplib
from email.mime.text import MIMEText

API_BASE_URL = "https://furkanbilgin.com.tr/"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "furkannbilgin82@gmail.com"
SMTP_PASSWORD = "qrqftdwrjnbghnwl"

def send_email(to_email, subject, body):
    msg = MIMEText(body)
    msg['From'] = SMTP_USER
    msg['To'] = to_email
    msg['Subject'] = subject

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, to_email, msg.as_string())

def fetch_pending_emails():
    try:
        resp = requests.get(f"{API_BASE_URL}/api/get_pending_emails", timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        print("API isteği hatası:", e)
    return []

def mark_as_sent(email_id):
    try:
        resp = requests.post(
            f"{API_BASE_URL}/api/mark_email_sent",
            json={"id": email_id},
            timeout=10
        )
        return resp.status_code == 200
    except Exception as e:
        print("Mark as sent hatası:", e)
    return False

if __name__ == "__main__":
    print("Agent başlatıldı. E-posta kuyruğu dinleniyor...")
    while True:
        emails = fetch_pending_emails()
        if emails:
            print(f"{len(emails)} bekleyen e-posta bulundu.")
            for email in emails:
                try:
                    send_email(email['to_email'], email['subject'], email['body'])
                    mark_as_sent(email['id'])
                    print(f"{email['to_email']} adresine gönderildi.")
                except Exception as e:
                    print(f"{email['to_email']} gönderim hatası:", e)
        else:
            print("Bekleyen e-posta yok.")

        time.sleep(30)  # 30 saniyede bir kontrol et
