import os
import time  # لإضافة متغير الوقت لحل مشكلة الكاش
from flask import Flask, request, jsonify, render_template
from validators import url  # للتحقق الاحترافي من الروابط
import requests
import json
import re # ✅ تم إضافة مكتبة التعبيرات العادية لتطبيق القواعد

app = Flask(__name__)

# --- تعريف الـ 20 قاعدة أمنية (Security Rules) ---
# كل قاعدة هي دالة Lambda يتم تطبيقها على الرابط المدخل.
SECURITY_RULES = [
    # 1. استخدام اختصار URL (موقع إخفاء)
    lambda link: any(service in link.lower() for service in ["bit.ly", "goo.gl", "tinyurl", "ow.ly", "cutt.ly", "is.gd"]),
    # 2. وجود رقم IP بدلاً من اسم نطاق (قد يشير إلى خادم مؤقت)
    lambda link: bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', link)),
    # 3. وجود رموز @ في الرابط (تستخدم أحياناً لخداع المتصفح بشأن الوجهة الحقيقية)
    lambda link: '@' in link,
    # 4. طول الرابط مريب (أطول من 80 حرفاً)
    lambda link: len(link) > 80,
    # 5. وجود كلمات شائعة للخداع (مثل gift, prize, free)
    lambda link: any(word in link.lower() for word in ['gift', 'prize', 'free', 'win', 'claim', 'discount']),
    # 6. عدم استخدام HTTPS (أخطر المخالفات)
    lambda link: link.lower().startswith('http://'),
    # 7. استخدام منافذ غير قياسية في الرابط (قد يشير إلى خدمة غير تقليدية)
    lambda link: bool(re.search(r':\d{4,}', link)), # منفذ بأربعة أرقام أو أكثر
    # 8. محاولة تمرير معلمات (parameters) ضخمة
    lambda link: link.count('=') > 5,
    # 9. وجود أكثر من نطاق فرعي واحد (كثرة النطاقات الفرعية العميقة)
    lambda link: link.count('.') > 3,
    # 10. انتهاء النطاق بمواقع غير شائعة (قد تشير إلى مواقع تم إنشاؤها حديثاً لغرض معين)
    lambda link: link.lower().endswith(('.cf', '.tk', '.ga', '.ml', '.xyz')),
    # 11. استخدام كلمة "secure" أو "safe" كجزء من الرابط (محاولة إيهام المستخدم بالأمان)
    lambda link: any(word in link.lower() for word in ['secure', 'safe', 'trust', 'login', 'verify']) and 'https' not in link.lower(),
    # 12. تكرار النطاق الفرعي (subdomain repetition) مثل google.google.com
    lambda link: len(link.split('.')) > 2 and link.split('.')[0].lower() == link.split('.')[-2].lower(),
    # 13. استخدام نطاق بأرقام (قد يشير إلى تلاعب)
    lambda link: any(char.isdigit() for char in link.split('.')[1]) and link.count('.') >= 1,
    # 14. وجود سلسلة طويلة من الأرقام في مسار الملف (قد تشير إلى ملفات تم تحميلها بشكل عشوائي)
    lambda link: bool(re.search(r'/\d{8,}/', link)),
    # 15. وجود أحرف كبيرة وصغيرة بشكل عشوائي (يستخدم لتفادي فلاتر)
    lambda link: len(link) > 30 and link != link.lower() and link != link.upper(),
    # 16. استخدام رمز الـ hash (#) كعلامة (قد يستخدم لتمرير بيانات غير مرئية للتحليل)
    lambda link: '#' in link,
    # 17. وجود كلمة 'admin' أو 'upload' في الرابط
    lambda link: any(word in link.lower() for word in ['admin', 'upload', 'config']),
    # 18. الرابط ينتهي بملف تنفيذي مشبوه
    lambda link: link.lower().endswith(('.exe', '.bat', '.cmd', '.scr')),
    # 19. محاولة إيهام باستخدام بروتوكول داخل المسار (مثلاً: https://google.com/http:/malware.com)
    lambda link: link.count('http') > 1,
    # 20. مطابقة اسم النطاق لأحد المواقع المعروفة ولكن به حرف مفقود أو زائد (Typosquatting)
    lambda link: any(re.search(rf'f[ae]ceb?ook|go0gle|appple', link.lower()))
]


# --- دالة التحليل الأمني (منطق العمل المُحدث) ---
def perform_security_scan(link):
    
    suspicious_points = 0
    detected_warnings = 0
    page_content_warning = "جاري الاتصال والتحليل..."
    
    # 1. فحص الاتصال بالرابط
    try:
        # وقت استجابة أطول قليلاً للروابط المشبوهة
        response = requests.get(link, timeout=10, allow_redirects=True) 
        status_code = response.status_code
        
        if status_code != 200:
            suspicious_points += 5
            detected_warnings += 1
            page_content_warning = f"تحذير: حالة الاستجابة غير ناجحة. الرمز: {status_code}"
        else:
            page_content_warning = "تم جلب محتوى الصفحة بنجاح."
            
    except requests.exceptions.RequestException:
        suspicious_points += 10
        detected_warnings += 1
        page_content_warning = "خطأ حاد في الاتصال بالرابط أو حدوث مهلة (Timeout)."
        status_code = 0
        
    # 2. تطبيق الـ 20 قاعدة أمنية
    violated_rules = []
    for i, rule in enumerate(SECURITY_RULES):
        try:
            if rule(link):
                suspicious_points += 2 # كل قاعدة تخترق تزيد نقطتين
                detected_warnings += 1
                violated_rules.append(f"القاعدة {i+1} تم اختراقها.")
        except Exception as e:
            # لتجنب توقف البرنامج بسبب خطأ غير متوقع في قاعدة معينة
            print(f"Error applying rule {i+1}: {e}") 
            pass

    # 3. تحديد مستوى الخطورة بناءً على النقاط
    risk_score = "Low"
    result_message = "آمن نسبيًا: لم يتم اكتشاف مخاطر واضحة."

    if suspicious_points > 25:
        risk_score = "Critical"
        result_message = "خطير! يحتوي على عدد كبير من نقاط الضعف والمخالفات الأمنية."
    elif suspicious_points > 15:
        risk_score = "High"
        result_message = "مرتفع: تم اكتشاف مخالفات هيكلية وسلوكية في الرابط."
    elif suspicious_points > 5:
        risk_score = "Medium"
        result_message = "متوسط: يحتوي على بعض العناصر المشبوهة. استخدم بحذر."
    
    # 4. إعادة النتيجة
    return {
        "status": "success" if suspicious_points <= 5 else "warning" if suspicious_points <= 15 else "error",
        "message": f"تحليل مكتمل. تم تطبيق {len(SECURITY_RULES)} قاعدة فحص.",
        "link": link,
        "result_message": result_message,
        "risk_score": risk_score,
        "suspicious_points": suspicious_points,
        "detected_warnings": detected_warnings,
        "page_content_warning": page_content_warning,
        "violated_rules": violated_rules 
    }

# --- نقطة النهاية الرئيسية (حل مشكلة الكاش) ---
@app.route('/', methods=['GET'])
def index():
    # إضافة متغير الوقت لإجبار المتصفح على تحميل نسخة جديدة في كل مرة
    cache_buster = int(time.time()) 
    return render_template('index.html', cache_buster=cache_buster)


# --- نقطة النهاية للتحليل ---
@app.route('/analyze', methods=['POST'])
def analyze_link():
    
    try:
        data = request.get_json()
        link_to_analyze = data.get('link')
    except Exception:
        return jsonify({
            "status": "critical_error",
            "message": "خطأ في معالجة بيانات الطلب (JSON).",
            "error_code": 400
        }), 400

    # 1. التحقق من أن الحقل ليس فارغاً
    if not link_to_analyze or link_to_analyze.strip() == "":
        return jsonify({
            "status": "validation_error",
            "message": "❌ فشل التحقق: الرجاء إدخال رابط. حقل الرابط لا يمكن أن يكون فارغاً.",
            "error_code": 400
        }), 400

    # 2. التحقق من صيغة الرابط (إضافة بروتوكول افتراضي إذا لم يكن موجوداً)
    if not link_to_analyze.lower().startswith(('http://', 'https://')):
        link_to_analyze = 'https://' + link_to_analyze
    
    # تحقق احترافي إضافي
    try:
        if url(link_to_analyze) is not True:
             return jsonify({
                "status": "validation_error",
                "message": "❌ الإدخال غير صحيح. الرجاء إدخال رابط حقيقي وصالح بصيغة URL.",
                "error_code": 400
            }), 400
    except ImportError:
         pass


    # 3. المتابعة إلى منطق التحليل
    analysis_result = perform_security_scan(link_to_analyze) 
    
    return jsonify(analysis_result), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
