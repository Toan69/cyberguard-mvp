import streamlit as st
import dns.resolver
import socket
import ssl
import time
import csv
import os
import re
import pandas as pd
from urllib.parse import urlparse
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
import io
from groq import Groq
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Ladda API-nyckel från .env
load_dotenv()

# --- SIDKONFIGURATION ---
st.set_page_config(
    page_title="CyberGuard AI | Säkerhetsanalys för Småföretag",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# --- DESIGN / CSS ---
st.markdown("""
<style>
    .stApp {
        background: linear-gradient(180deg, #0a0e1a 0%, #0d1220 100%);
    }
    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, 'Segoe UI', sans-serif;
    }
    .cg-hero {
        text-align: center;
        padding: 2.5rem 1rem 1.5rem 1rem;
    }
    .cg-hero h1 {
        font-size: 2.6rem;
        font-weight: 800;
        background: linear-gradient(90deg, #4f9dff, #7ee0d0);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.3rem;
    }
    .cg-hero p {
        color: #8a93a6;
        font-size: 1.05rem;
    }
    .cg-card {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 16px;
        padding: 1.4rem 1.6rem;
        margin-bottom: 1.2rem;
        box-shadow: 0 4px 20px rgba(0,0,0,0.25);
    }
    .cg-status {
        display: flex;
        align-items: center;
        gap: 0.6rem;
        padding: 0.9rem 1.1rem;
        border-radius: 12px;
        width: 100%;
        margin-bottom: 0.7rem;
        font-weight: 600;
        font-size: 0.98rem;
    }
    .cg-status-ok {
        background: rgba(34,197,94,0.12);
        border: 1px solid rgba(34,197,94,0.35);
        color: #4ade80;
    }
    .cg-status-warn {
        background: rgba(234,179,8,0.12);
        border: 1px solid rgba(234,179,8,0.35);
        color: #facc15;
    }
    .cg-status-bad {
        background: rgba(239,68,68,0.12);
        border: 1px solid rgba(239,68,68,0.35);
        color: #f87171;
    }
    .cg-status small {
        display: block;
        font-weight: 400;
        opacity: 0.75;
        font-size: 0.82rem;
        margin-top: 0.15rem;
    }
    .cg-score-wrap {
        display: flex;
        align-items: center;
        gap: 1.6rem;
        padding: 0.4rem 0;
    }
    .cg-score-num {
        font-size: 3.2rem;
        font-weight: 800;
        line-height: 1;
        white-space: nowrap;
    }
    .cg-score-bar-bg {
        flex: 1;
        height: 14px;
        background: rgba(255,255,255,0.08);
        border-radius: 999px;
        overflow: hidden;
    }
    .cg-score-bar-fill {
        height: 100%;
        border-radius: 999px;
        transition: width 0.6s ease;
    }
    .stButton > button, .stFormSubmitButton > button {
        background: linear-gradient(90deg, #ff4b5c, #ff7a4f) !important;
        color: white !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 0.7rem 1.4rem !important;
        font-weight: 700 !important;
        box-shadow: 0 4px 14px rgba(255,75,92,0.35) !important;
        transition: transform 0.15s ease, box-shadow 0.15s ease !important;
    }
    .stButton > button:hover, .stFormSubmitButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(255,75,92,0.5) !important;
    }
    .stTextInput > div > div > input {
        background: rgba(255,255,255,0.04) !important;
        border: 1px solid rgba(255,255,255,0.12) !important;
        border-radius: 10px !important;
        color: white !important;
    }
    .cg-trust {
        text-align: center;
        color: #6b7280;
        font-size: 0.85rem;
        padding: 0.5rem 0 1.5rem 0;
        border-bottom: 1px solid rgba(255,255,255,0.06);
        margin-bottom: 1.5rem;
    }
    .cg-step-num {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 28px;
        height: 28px;
        border-radius: 50%;
        background: rgba(79,157,255,0.15);
        color: #4f9dff;
        font-weight: 700;
        margin-bottom: 0.4rem;
    }
</style>
""", unsafe_allow_html=True)

# --- DESIGN-HJÄLPFUNKTIONER ---
def render_status_row(label, level, detail_text):
    """level: 'ok', 'warn' eller 'bad'"""
    icons = {"ok": "✅", "warn": "⚠️", "bad": "❌"}
    st.markdown(f"""
    <div class="cg-status cg-status-{level}">
        <div style="font-size:1.2rem;">{icons[level]}</div>
        <div><strong>{label}</strong><small>{detail_text}</small></div>
    </div>
    """, unsafe_allow_html=True)

def render_score_gauge(score):
    if score >= 80:
        color = "#4ade80"
    elif score >= 50:
        color = "#facc15"
    else:
        color = "#f87171"

    st.markdown(f"""
    <div class="cg-card">
        <div class="cg-score-wrap">
            <div class="cg-score-num" style="color:{color}">{score}<span style="font-size:1.2rem; opacity:0.6;">/100</span></div>
            <div class="cg-score-bar-bg">
                <div class="cg-score-bar-fill" style="width:{score}%; background:{color};"></div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

# --- E-POSTVALIDERING ---
def is_valid_email(email_addr):
    """
    Kontrollerar både format (regex) och att domänen faktiskt
    har en mailserver (MX-post). Fångar t.ex. 'asdf@asdf' eller
    'namn@paahittad-domän.se'.
    """
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(pattern, email_addr.strip()):
        return False, "E-postadressen har fel format. Ange t.ex. namn@företag.se"

    domain_part = email_addr.strip().split("@")[1]
    try:
        dns.resolver.resolve(domain_part, 'MX')
        return True, ""
    except Exception:
        return False, f"Domänen '{domain_part}' kan inte ta emot e-post. Kontrollera att adressen är korrekt stavad."

# --- E-POSTMALL (HTML) ---
def build_html_email(domain_name, score, scan_results, ai_summary):
    if score >= 80:
        score_color = "#22c55e"
    elif score >= 50:
        score_color = "#eab308"
    else:
        score_color = "#ef4444"

    rows_html = ""
    for test, status in scan_results.items():
        if status.startswith("✅"):
            badge_color = "#22c55e"
            badge_bg = "#dcfce7"
        elif status.startswith("⚠️"):
            badge_color = "#b45309"
            badge_bg = "#fef3c7"
        else:
            badge_color = "#dc2626"
            badge_bg = "#fee2e2"
        detail = status.split(" ", 1)[1] if " " in status else status
        rows_html += f"""
        <tr>
            <td style="padding:10px 14px; border-bottom:1px solid #e2e8f0; font-size:14px; color:#0f172a; font-weight:600;">{test}</td>
            <td style="padding:10px 14px; border-bottom:1px solid #e2e8f0; font-size:13px;">
                <span style="background:{badge_bg}; color:{badge_color}; padding:4px 10px; border-radius:999px; font-weight:600;">{detail}</span>
            </td>
        </tr>
        """

    ai_summary_html = ai_summary.replace("\n", "<br>")

    html = f"""
    <html>
    <body style="margin:0; padding:0; background-color:#0d1220; font-family:'Segoe UI', Arial, sans-serif;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#0d1220; padding:30px 0;">
            <tr>
                <td align="center">
                    <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff; border-radius:16px; overflow:hidden;">
                        <tr>
                            <td style="background:linear-gradient(90deg, #1e3a8a, #0f172a); padding:32px 30px; text-align:center;">
                                <div style="font-size:28px; margin-bottom:6px;">🛡️</div>
                                <div style="font-size:22px; font-weight:800; color:#ffffff;">CyberGuard AI</div>
                                <div style="font-size:13px; color:#93c5fd; margin-top:4px;">Säkerhetsrapport för {domain_name}</div>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding:30px;">
                                <p style="font-size:15px; color:#334155; margin:0 0 20px 0;">Hej!<br>Tack för att du körde en säkerhetsanalys på CyberGuard AI. Här är resultatet för <strong>{domain_name}</strong>.</p>

                                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc; border-radius:12px; padding:20px; margin-bottom:24px;">
                                    <tr>
                                        <td style="text-align:center;">
                                            <div style="font-size:42px; font-weight:800; color:{score_color};">{score}<span style="font-size:16px; color:#94a3b8;">/100</span></div>
                                            <div style="font-size:13px; color:#64748b; margin-top:4px;">Säkerhetspoäng</div>
                                        </td>
                                    </tr>
                                </table>

                                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e2e8f0; border-radius:10px; overflow:hidden; margin-bottom:24px;">
                                    {rows_html}
                                </table>

                                <div style="background:#eff6ff; border-left:4px solid #3b82f6; border-radius:8px; padding:18px 20px; margin-bottom:26px;">
                                    <div style="font-size:14px; font-weight:700; color:#1e3a8a; margin-bottom:8px;">🧠 AI-Analys & Rådgivning</div>
                                    <div style="font-size:14px; color:#334155; line-height:1.6;">{ai_summary_html}</div>
                                </div>

                                <p style="font-size:13px; color:#94a3b8; text-align:center; margin:0;">Med vänliga hälsningar,<br><strong style="color:#334155;">CyberGuard AI</strong></p>
                            </td>
                        </tr>
                        <tr>
                            <td style="background:#f1f5f9; padding:16px 30px; text-align:center;">
                                <div style="font-size:11px; color:#94a3b8;">Detta mail skickades eftersom du begärde en säkerhetsanalys via CyberGuard AI.</div>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    return html

# --- E-POSTFUNKTION ---
def send_email_report(to_email, domain_name, score, scan_results, ai_summary):
    try:
        sender_email = st.secrets["EMAIL_SENDER"]
        sender_password = st.secrets["EMAIL_PASSWORD"]

        msg = MIMEMultipart("alternative")
        msg['From'] = sender_email
        msg['To'] = to_email
        msg['Subject'] = f"Säkerhetsrapport för {domain_name} — CyberGuard AI"

        # Textversion (fallback för klienter som inte visar HTML)
        plain_body = f"Hej!\n\nTack för att du körde en säkerhetsanalys på CyberGuard AI.\n\nSäkerhetspoäng för {domain_name}: {score}/100\n\nAI-analys:\n{ai_summary}\n\nMed vänliga hälsningar,\nCyberGuard AI"
        msg.attach(MIMEText(plain_body, 'plain'))

        # HTML-version
        html_body = build_html_email(domain_name, score, scan_results, ai_summary)
        msg.attach(MIMEText(html_body, 'html'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        st.error(f"E-postfel: {e}")
        return False

# --- PDF-GENERERING ---
def create_pdf(domain_name, score, scan_results, missing_items, ai_text):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )
    story = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontSize=22,
        leading=26,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=12
    )
    story.append(Paragraph("🛡️ CyberGuard AI — Säkerhetsrapport", title_style))
    story.append(Spacer(1, 10))

    normal_style = ParagraphStyle('NormalStyle', parent=styles['Normal'], fontSize=10, leading=14, textColor=colors.HexColor('#334155'))
    story.append(Paragraph(f"<b>Analyserad domän:</b> {domain_name}", normal_style))
    story.append(Paragraph(f"<b>Säkerhetspoäng:</b> {score} / 100", normal_style))
    story.append(Paragraph(f"<b>Datum:</b> {time.strftime('%Y-%m-%d')}", normal_style))
    story.append(Spacer(1, 15))

    data = [["Säkerhetskontroll", "Status"]]
    for k, v in scan_results.items():
        data.append([k, v])
    
    t = Table(data, colWidths=[240, 240])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#F1F5F9')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#0F172A')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 8),
        ('TOPPADDING', (0,0), (-1,0), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
    ]))
    story.append(t)
    story.append(Spacer(1, 20))

    story.append(Paragraph("<b>AI-Analys & Åtgärdsförslag:</b>", styles['Heading2']))
    story.append(Spacer(1, 8))
    clean_ai_text = ai_text.replace('*', '').replace('#', '')
    story.append(Paragraph(clean_ai_text, normal_style))

    doc.build(story)
    buffer.seek(0)
    return buffer

# --- SIDOMENY (ADMIN) ---
st.sidebar.title("🔐 Adminpanel")
admin_password = st.sidebar.text_input("Lösenord:", type="password")

# OBS: Lägg till ADMIN_PASSWORD i Streamlit Cloud → Settings → Secrets.
# Tills du gjort det används "admin123" som reserv (byt ASAP, se not nedan).
correct_admin_password = st.secrets.get("ADMIN_PASSWORD", "admin123")

if admin_password and admin_password == correct_admin_password:
    st.sidebar.success("Inloggad som Admin")
    st.title("⚙️ Admin Dashboard")
    
    api_key_status = "✅ Laddad" if os.getenv("GROQ_API_KEY") or "GROQ_API_KEY" in st.secrets else "❌ Saknas"
    st.write(f"**Groq API-nyckel:** {api_key_status}")

    st.divider()
    st.subheader("📊 Insamlade Leads")
    
    if os.path.exists('leads.csv'):
        df = pd.read_csv('leads.csv')
        st.dataframe(df, use_container_width=True)
        
        with open("leads.csv", "rb") as file:
            st.download_button(
                label="📥 Ladda ner alla leads (CSV)",
                data=file,
                file_name="cyberguard_leads.csv",
                mime="text/csv"
            )
    else:
        st.info("Inga leads har sparats ännu.")
    
    st.stop()

# --- HUVUDAPP (HERO SEKTION) ---
st.markdown("""
<div class="cg-hero">
    <h1>🛡️ CyberGuard AI</h1>
    <p>Autonom säkerhetsanalys för småföretag</p>
</div>
<div class="cg-trust">
    🔒 Ingen data delas med tredje part &nbsp;•&nbsp; Analys på under 10 sekunder &nbsp;•&nbsp; 100% gratis
</div>
""", unsafe_allow_html=True)

st.markdown("##### 🔍 Testa ditt företags digitala skydd")
st.caption("Ange din domän nedan för att identifiera brister i e-postskydd och SSL-kryptering på under 10 sekunder.")

domain = st.text_input("Företagsdomän:", placeholder="t.ex. dittforetag.se eller google.com")

def clean_domain_input(url_string):
    url_string = url_string.strip()
    if not url_string.startswith(('http://', 'https://')):
        url_string = 'http://' + url_string
    parsed = urlparse(url_string)
    host = parsed.netloc or parsed.path
    if host.startswith("www."):
        host = host[4:]
    return host.split('/')[0]

def check_ssl(domain_name):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain_name, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain_name) as ssock:
                return True, "✅ SSL-certifikat aktivt och giltigt"
    except Exception:
        return False, "❌ Saknar eller har ogiltigt SSL-certifikat"

def check_dns_security(domain_name):
    results = {}
    score = 100
    missing_items = []
    
    # SPF
    try:
        answers = dns.resolver.resolve(domain_name, 'TXT')
        spf_found = any("v=spf1" in rdata.to_text() for rdata in answers)
        if spf_found:
            results["SPF (Mailskydd)"] = "✅ Konfigurerat"
        else:
            results["SPF (Mailskydd)"] = "⚠️ Saknas"
            score -= 25
            missing_items.append("SPF")
    except Exception:
        results["SPF (Mailskydd)"] = "⚠️ Saknas"
        score -= 25
        missing_items.append("SPF")

    # DMARC
    try:
        dns.resolver.resolve(f"_dmarc.{domain_name}", 'TXT')
        results["DMARC (Anti-phishing)"] = "✅ Konfigurerat"
    except Exception:
        results["DMARC (Anti-phishing)"] = "❌ Saknas (Risk för mail-kapning)"
        score -= 30
        missing_items.append("DMARC")

    # SSL
    ssl_ok, ssl_msg = check_ssl(domain_name)
    results["HTTPS / Kryptering"] = ssl_msg
    if not ssl_ok:
        score -= 35
        missing_items.append("SSL/HTTPS")

    return results, max(score, 0), missing_items

def generate_ai_analysis(domain_name, score, missing):
    api_key = os.getenv("GROQ_API_KEY") or st.secrets.get("GROQ_API_KEY")
    if api_key:
        try:
            client = Groq(api_key=api_key)
            prompt = f"Du är en cybersäkerhetsexpert på CyberGuard AI. Analysera domänen {domain_name}. Poäng: {score}/100. Saknade skydd: {', '.join(missing) if missing else 'Inga'}. Skriv en unik, kort, professionell och pedagogisk sammanfattning för en småföretagare på svenska. Förklara vad bristerna innebär och vad de bör göra."
            
            chat_completion = client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model="llama-3.3-70b-versatile",
            )
            return chat_completion.choices[0].message.content
        except Exception as e:
            st.error(f"API Fel: {e}")

    # Fallback
    if score == 100:
        return f"Domänen {domain_name} visar utmärkt grundläggande säkerhet. Alla primära DNS- och krypteringsskydd är aktiverade, vilket minskar risken för spoofing och avlyssning avsevärt."
    
    issues_str = ", ".join(missing) if missing else "okända brister"
    return f"Vi har identifierat svagheter i inställningarna för {domain_name} gällande {issues_str}. Utan dessa skydd kan obehöriga skicka bluffmail i ditt företags namn (phishing) samt fånga upp känslig information. Rekommendation: Konfigurera korrekt TXT-poster i DNS-hanteraren samt säkerställ giltigt SSL-certifikat."

def save_lead(domain_name, email_addr):
    file_exists = os.path.isfile('leads.csv')
    with open('leads.csv', mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(['Domän', 'E-post', 'Datum'])
        writer.writerow([domain_name, email_addr, time.strftime("%Y-%m-%d %H:%M:%S")])

# KNAPP FÖR SKANNING
if st.button("Kör Gratis Säkerhetsanalys →", use_container_width=True, type="primary"):
    if domain:
        clean_domain = clean_domain_input(domain)
        
        with st.spinner(f"Skannar {clean_domain} och genererar AI-analys..."):
            time.sleep(1)
            scan_results, final_score, missing_items = check_dns_security(clean_domain)
            ai_text = generate_ai_analysis(clean_domain, final_score, missing_items)
            
            st.session_state['last_domain'] = clean_domain
            st.session_state['scan_results'] = scan_results
            st.session_state['final_score'] = final_score
            st.session_state['missing_items'] = missing_items
            st.session_state['ai_text'] = ai_text
    else:
        st.warning("Vänligen ange en giltig domän först.")

# VISNING AV RESULTAT
if 'scan_results' in st.session_state:
    clean_domain = st.session_state['last_domain']
    scan_results = st.session_state['scan_results']
    final_score = st.session_state['final_score']
    missing_items = st.session_state['missing_items']
    ai_text = st.session_state['ai_text']

    st.write("---")
    st.markdown(f"### 📊 Analysresultat för `{clean_domain}`")

    # Poäng-gauge (visuell mätare istället för text-banner)
    render_score_gauge(final_score)

    # Detaljerad status per kontroll (status-badges istället för punktlista)
    st.markdown("#### Detektionsöversikt")

    for test, status in scan_results.items():
        if status.startswith("✅"):
            level = "ok"
        elif status.startswith("⚠️"):
            level = "warn"
        else:
            level = "bad"
        detail = status.split(" ", 1)[1] if " " in status else status
        render_status_row(test, level, detail)

    st.write("")
    st.markdown("#### 🧠 AI-Analys & Rådgivning")
    st.markdown(f'<div class="cg-card">{ai_text}</div>', unsafe_allow_html=True)

    # Ladda ner PDF
    pdf_buffer = create_pdf(clean_domain, final_score, scan_results, missing_items, ai_text)
    st.download_button(
        label="📄 Ladda ner fullständig PDF-Rapport",
        data=pdf_buffer,
        file_name=f"CyberGuard_Rapport_{clean_domain}.pdf",
        mime="application/pdf",
        use_container_width=True
    )

    # Lead capture
    if final_score < 100:
        st.write("---")
        st.subheader("📬 Behöver du hjälp att åtgärda bristerna?")
        st.write("Fyll i din e-postadress så skickar vi en kostnadsfri åtgärdsplan och förslag på hur vi kan hjälpa dig konfigurera skydden.")
        
        col1, col2 = st.columns([3, 1])
        with col1:
            email = st.text_input("Din e-postadress:", label_visibility="collapsed", placeholder="namn@foretag.se")
        with col2:
            if st.button("Skicka ➔", use_container_width=True):
                if email:
                    valid, error_msg = is_valid_email(email)
                    if valid:
                        save_lead(clean_domain, email)
                        if send_email_report(email, clean_domain, final_score, scan_results, ai_text):
                            st.success("Tack! Rapporten skickas nu till din e-post.")
                        else:
                            st.warning("E-postadressen är giltig, men mailet kunde inte skickas just nu. Kontrollera e-postinställningarna i Secrets.")
                    else:
                        st.error(f"⚠️ {error_msg}")
                else:
                    st.warning("Ange e-post.")

# --- INFORMATION OCH FÖRTROENDE (VISAS NÄR MAN INTE SKANNAT) ---
if 'scan_results' not in st.session_state:
    st.write("---")
    st.markdown("### ⚡ Hur det fungerar")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown('<div class="cg-step-num">1</div>', unsafe_allow_html=True)
        st.markdown("**Automatisk skanning**")
        st.caption("Vi kontrollerar din domäns offentliga DNS-poster för SPF, DMARC samt HTTPS-kryptering.")
    with col2:
        st.markdown('<div class="cg-step-num">2</div>', unsafe_allow_html=True)
        st.markdown("**AI-Analys**")
        st.caption("Vår AI utvärderar resultaten och förklarar konsekvenserna i klartext anpassat för företagare.")
    with col3:
        st.markdown('<div class="cg-step-num">3</div>', unsafe_allow_html=True)
        st.markdown("**Åtgärdsrapport**")
        st.caption("Du får en skräddarsydd PDF-rapport med konkreta instruktioner för att täppa till luckorna.")

    st.write("---")
    st.markdown("### ❓ Vanliga frågor")
    
    with st.expander("Vad är SPF och varför behöver mitt företag det?"):
        st.write("SPF (Sender Policy Framework) anger vilka e-postservrar som har tillåtelse att skicka mail å ditt företags vägnar. Utan SPF kan bedragare lätt förfalska mail och låtsas vara du.")
        
    with st.expander("Vad innebär DMARC?"):
        st.write("DMARC hjälper e-postmottagare att avgöra vad de ska göra med mail som misslyckas med SPF- eller DKIM-kontroller. Det förhindrar phishing och mail-kapning i ditt varumärkes namn.")
        
    with st.expander("Varför räcker det inte bara med en vanlig hemsida?"):
        st.write("Även om din hemsida ser bra ut kan saknade DNS-skydd göra att dina affärsmail hamnar i kunders skräppost eller att kriminella skickar bluffsändningar i ditt namn.")
