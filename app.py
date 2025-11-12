import os
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, render_template 
from flask_cors import CORS 
from datetime import datetime
import whois 
import re 

# ----------------------------------------------------
# 💡 إعدادات Flask لـ Vercel (البنية القياسية):
# ----------------------------------------------------
# Vercel يبحث تلقائيًا عن مجلد 'templates' في الجذر.
app = Flask(__name__) 
CORS(app) 
# ----------------------------------------------------


# --- وظيفة فحص سمعة IP (القاعدة 7) ---
def check_ip_reputation(domain):
    reputation_points = 0
    try:
        api_url = f"https://api.hackertarget.com/reverseiplookup/?q={domain}"
        response = requests.get(api_url, timeout=3)
        host_count = len(response.text.split('\n'))
        if host_count > 10:
            reputation_points += 2
    except Exception:
        reputation_points += 0 
    return reputation_points

# --- وظيفة تحليل الرابط الرئيسية (7 قواعد + فحص المحتوى) ---
def analyze_url(url):
    points = 0
    content_warnings = [] 

    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
    except ValueError:
        return 10, content_warnings

    # ----------------------------------------------------
    # القواعد الهيكلية (تحليل الرابط)
    # ----------------------------------------------------
    if len(url) > 70: points += 1
    
    suspicious_keywords = ['login', 'verify', 'update', 'security', 'account', 'paypal', 'bank']
    for keyword in suspicious_keywords:
        if keyword in domain:
            points += 2
            break
            
    if parsed_url.scheme == 'http': points += 3 
    if '@' in url: points += 5 
    if domain.count('.') > 3: points += 1 

    # فحص عُمر النطاق (Whois)
    try:
        w = whois.whois(domain)
        today = datetime.now().date()
        creation_date = w.creation_date
        
        if isinstance(creation_date, list): creation_date = creation_date[0]
            
        if creation_date:
            age_in_days = (today - creation_date.date()).days
            if age_in_days < 90: points += 4 
            elif age_in_days < 180: points += 2 
    except Exception: 
        points += 1 

    points += check_ip_reputation(domain)

    # ----------------------------------------------------
    # 💡 قواعد تحليل محتوى الصفحة (Content Analysis)
    # ----------------------------------------------------
    try:
        response = requests.get(url, timeout=5) 
        response.raise_for_status() 
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 1. فحص النماذج الحساسة (نموذج إدخال بيانات الاعتماد)
        password_fields = soup.find_all('input', {'type': 'password'})
        if password_fields and ('login' in url.lower() or 'signin' in url.lower()):
            content_warnings.append("نموذج إدخال بيانات اعتماد (كلمة مرور).")
            points += 3 
            
        # 2. فحص العناصر المخفية (Iframe / عنصر HTML)
        hidden_elements = soup.find_all(lambda tag: tag.has_attr('style') and ('display:none' in tag['style'] or 'visibility:hidden' in tag['style']))
        if hidden_elements:
            content_warnings.append(f"تم العثور على {len(hidden_elements)} عنصر HTML/Iframe مخفي (قد يُستخدم للسرقة).")
            points += 2
            
        # 3. فحص إعادة التوجيه الفورية (JavaScript Redirect)
        if re.search(r'window\.location|document\.location|header\s*\(\s*["\']location', response.text, re.IGNORECASE):
            content_warnings.append("إعادة توجيه فورية (قد يكون لصفحة احتيال).")
            points += 2
            
    except requests.exceptions.RequestException:
        content_warnings.append("فشل في جلب محتوى الصفحة.")
        points += 1
    except Exception:
        content_warnings.append("خطأ غير متوقع أثناء تحليل المحتوى.")
        points += 1 

    return points, content_warnings 

# 💡 المسار الرئيسي لصفحة الويب:
@app.route('/')
def index():
    return render_template('index.html')


# واجهة الـ API
@app.route('/check_link', methods=['POST'])
def check_link():
    data = request.get_json()
    link = data.get('link')

    if not link:
        return jsonify({"error": "الرجاء إرسال حقل 'link' في صيغة JSON"}), 400

    score, warnings = analyze_url(link)
    
    if score >= 8:
        result = "🔴 خطر جسيم (خطر احتيال مؤكد)"
        certainty = "High"
    elif score >= 4:
        result = "🟡 مشتبه به (يحتوي على عناصر مريبة)"
        certainty = "Medium"
    else:
        result = "🟢 آمن نسبياً"
        certainty = "Low"

    return jsonify({
        "link": link,
        "score": score,
        "certainty": certainty,
        "result": result,
        "warnings": warnings 
    })
