import streamlit as st
import dns.resolver
import socket
import ssl
import time
import csv
import os
import pandas as pd
from urllib.parse import urlparse
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
import io
from groq import Groq
from dotenv import load_dotenv

# Ladda API-nyckel från .env
load_dotenv()

# --- SIDKONFIGURATION ---
st.set_page_config(
    page_title="CyberGuard AI | Säkerhetsanalys för Småföretag",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)

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

    # Titel och Header
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

    # Resultat-tabell
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

    # AI Analys
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

if admin_password == "admin123":
    st.sidebar.success("Inloggad som Admin")
    st.title("⚙️ Admin Dashboard")
    
    api_key_status = "✅ Laddad från .env" if os.getenv("GROQ_API_KEY") else "❌ Saknas i .env"
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
st.markdown("<h1 style='text-align: center;'>🛡️ CyberGuard AI</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; font-size: 1.2rem; color: #64748B;'>Autonom Säkerhetsanalys för Småföretag</p>", unsafe_allow_html=True)
st.write("---")

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
    api_key = os.getenv("GROQ_API_KEY")
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
    
    # Poäng-banner
    if final_score >= 80:
        st.success(f"**Säkerhetspoäng: {final_score} / 100** — Bra grundskydd!")
    elif final_score >= 50:
        st.warning(f"**Säkerhetspoäng: {final_score} / 100** — Åtgärder rekommenderas.")
    else:
        st.error(f"**Säkerhetspoäng: {final_score} / 100** — Kritiska säkerhetsbrister upptäckta!")

    # Detaljerad lista
    st.markdown("#### Detektionsöversikt")
    for test, status in scan_results.items():
        st.write(f"• **{test}:** {status}")

    st.write("")
    st.markdown("#### 🧠 AI-Analys & Rådgivning")
    st.info(ai_text)

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
                if email and "@" in email:
                    save_lead(clean_domain, email)
                    st.success("Tack! Vi återkommer inom kort.")
                else:
                    st.warning("Ange e-post.")

# --- INFORMATION OCH FÖRTROENDE (VISAS NÄR MAN INTE SKANNAT) ---
if 'scan_results' not in st.session_state:
    st.write("---")
    st.markdown("### ⚡ Hur det fungerar")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("**1. Automatisk skanning**")
        st.caption("Vi kontrollerar din domäns offentliga DNS-poster för SPF, DMARC samt HTTPS-kryptering.")
    with col2:
        st.markdown("**2. AI-Analys**")
        st.caption("Vår AI utvärderar resultaten och förklarar konsekvenserna i klartext anpassat för företagare.")
    with col3:
        st.markdown("**3. Åtgärdsrapport**")
        st.caption("Du får en skräddarsydd PDF-rapport med konkreta instruktioner för att täppa till luckorna.")

    st.write("---")
    st.markdown("### ❓ Vanliga frågor")
    
    with st.expander("Vad är SPF och varför behöver mitt företag det?"):
        st.write("SPF (Sender Policy Framework) anger vilka e-postservrar som har tillåtelse att skicka mail å ditt företags vägnar. Utan SPF kan bedragare lätt förfalska mail och låtsas vara du.")
        
    with st.expander("Vad innebär DMARC?"):
        st.write("DMARC hjälper e-postmottagare att avgöra vad de ska göra med mail som misslyckas med SPF- eller DKIM-kontroller. Det förhindrar phishing och mail-kapning i ditt varumärkes namn.")
        
    with st.expander("Varför räcker det inte bara med en vanlig hemsida?"):
        st.write("Även om din hemsida ser bra ut kan saknade DNS-skydd göra att dina affärsmail hamnar i kunders skräppost eller att kriminella skickar bluffsändningar i ditt namn.")