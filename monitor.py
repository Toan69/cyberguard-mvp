import os
import smtplib
import socket
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import dns.resolver
from supabase import create_client

# Hämta miljövariabler/nycklar från GitHub Secrets
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
EMAIL_SENDER = os.environ.get("EMAIL_SENDER")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")

def check_ssl(domain_name):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain_name, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain_name) as ssock:
                return True
    except Exception:
        return False

def check_dns_security(domain_name):
    score = 100
    try:
        answers = dns.resolver.resolve(domain_name, 'TXT')
        if not any("v=spf1" in rdata.to_text() for rdata in answers):
            score -= 25
    except Exception:
        score -= 25

    try:
        dns.resolver.resolve(f"_dmarc.{domain_name}", 'TXT')
    except Exception:
        score -= 30

    if not check_ssl(domain_name):
        score -= 35

    return max(score, 0)

def send_alert(to_email, domain_name, new_score, old_score):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = to_email
        msg['Subject'] = f"⚠️ Säkerhetsuppdatering för {domain_name} — CyberGuard AI"
        
        body = f"""Hej!

Detta är en automatisk veckorapport från CyberGuard AI.

Vi har kört en ny övervakningsskanning på {domain_name}.
• Tidigare säkerhetspoäng: {old_score}/100
• Nuvarande säkerhetspoäng: {new_score}/100

Om din poäng har sjunkit rekommenderar vi att du ser över dina DNS- och SSL-inställningar.

Med vänliga hälsningar,
CyberGuard AI"""

        msg.attach(MIMEText(body, 'plain'))
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"Larm skickat till {to_email} för {domain_name}")
    except Exception as e:
        print(f"Fel vid mailutskick: {e}")

def run_monitoring():
    if not SUPABASE_URL or not SUPABASE_KEY:
        print("Supabase-nycklar saknas!")
        return

    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    res = supabase.table("subscriptions").select("*").eq("status", "active").execute()
    
    for sub in res.data:
        domain = sub["domain"]
        email = sub["email"]
        old_score = sub.get("last_score", 0)
        
        current_score = check_dns_security(domain)
        print(f"Skannar {domain}: Ny poäng {current_score} (Tidigare: {old_score})")

        # Uppdatera ny poäng i databasen
        supabase.table("subscriptions").update({"last_score": current_score}).eq("id", sub["id"]).execute()

        # Skicka mejl om poängen förändrats eller är låg
        if current_score != old_score or current_score < 80:
            send_alert(email, domain, current_score, old_score)

if __name__ == "__main__":
    run_monitoring()
