import os
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, render_template 
from flask_cors import CORS 
from datetime import datetime
import whois # ✅ تم إبقاء الاستدعاء هنا مع معالجة الخطأ لاحقًا

# ----------------------------------------------------
# 💡 إعدادات Flask لـ Vercel (الأبسط):
# ----------------------------------------------------
# Vercel يبحث تلقائيًا عن مجلد 'templates' في الجذر.
app = Flask(__name__) 
CORS(app) 
# ----------------------------------------------------


# --- وظيفة فحص سمعة IP (القاعدة 7) ---
def check_ip_reputation(domain):
    reputation_points = 0
    try:
        # استخدام API خارجي بسيط للتحقق من سمعة الـ IP
        api_url = f"https://api.hackertarget.com/reverseiplookup/?q={domain}"
        response = requests.get(api_url, timeout=3)
        # إذا كان هناك عدد كبير من المواقع على نفس الـ IP، فهذا يشير للشك
        host_count = len(response.text.split('\n'))
        if host_count > 10:
            reputation_points += 2
    except Exception:
        reputation_points += 0 
    return reputation_points

# --- وظيفة تحليل الرابط الرئيسية (7 قواعد) ---
def analyze_url(url):
    points = 0
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
    except ValueError:
        # إذا كان الرابط غير صالح تمامًا، نعتبره مشبوهاً جداً
        return 10 

    # القواعد 1-5 (هيكلية الرابط)
    if len(url) > 70: points += 1
    
    suspicious_keywords = ['login', 'verify', 'update', 'security', 'account', 'paypal', 'bank']
    for keyword in suspicious_keywords:
        if keyword in domain:
            points += 2
            break
            
    if parsed_url.scheme == 'http': points += 3 # استخدام HTTP بدلاً من HTTPS
    if '@' in url: points += 5 #
