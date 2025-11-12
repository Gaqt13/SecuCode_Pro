import os
import time  # لإضافة متغير الوقت لحل مشكلة الكاش
from flask import Flask, request, jsonify, render_template
from validators import url  # للتحقق الاحترافي من الروابط
import requests
import json

app = Flask(__name__)

# --- دالة التحليل الأمني (منطق العمل) ---
# يجب أن تحتوي على منطقك الأصلي، وهنا مثال للحقول التي يجب إعادتها
def perform_security_scan(link):
    """
    يقوم بإجراء تحليل أمني وهمي للرابط ويعيد نتائج منظمة.
    """
    try:
        # محاولة الاتصال بالرابط لتأكيد وجوده (مثال - يمكن إزالة هذا في تطبيق حقيقي معقد)
        response = requests.get(link, timeout=5, allow_redirects=True) 
        
        # مثال لمنطق تحليل وهمي
        if "google.com" in link or "microsoft.com" in link:
            return {
                "status": "success",
                "message": "تحليل مكتمل.",
                "link": link,
                "result_message": "آمن: تم التحقق من المصدر.",
                "risk_score": "Low",
                "suspicious_points": 0,
                "detected_warnings": 0,
                "page_content_warning": "تم جلب محتوى الصفحة بنجاح."
            }

        elif response.status_code == 200:
            return {
                "status": "warning",
                "message": "تحليل مكتمل.",
                "link": link,
                "result_message": "غير مؤكد: قد يحتوي على نقاط ضعف.",
                "risk_score": "Medium",
                "suspicious_points": 5,
                "detected_warnings": 2,
                "page_content_warning": "تم جلب محتوى الصفحة بنجاح. راجع النقاط المشبوهة."
            }
        else:
            return {
                "status": "critical_warning",
                "message": "تحذير حرج: الرابط موجود لكن حالة الاستجابة غير عادية.",
                "link": link,
                "result_message": "غير مؤكد.",
                "risk_score": "High",
                "suspicious_points": 8,
                "detected_warnings": 3,
                "page_content_warning": f"فشل في جلب محتوى الصفحة. رمز الحالة: {response.status_code}"
            }
            
    except requests.exceptions.RequestException:
        return {
            "status": "error",
            "message": "خطأ في الاتصال بالرابط.",
            "link": link,
            "result_message": "غير قابل للوصول.",
            "risk_score": "Critical",
            "suspicious_points": 10,
            "detected_warnings": 5,
            "page_content_warning": "فشل حاد في الاتصال بالرابط أو حدوث مهلة (Timeout)."
        }

# --- نقطة النهاية الرئيسية (حل مشكلة الكاش) ---
@app.route('/', methods=['GET'])
def index():
    # إضافة متغير الوقت لإجبار المتصفح على تحميل نسخة جديدة في كل مرة
    cache_buster = int(time.time()) 
    return render_template('index.html', cache_buster=cache_buster)


# --- نقطة النهاية للتحليل (بمنطق التحقق الثابت) ---
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

    # 2. التحقق من صيغة الرابط
    # نستخدم هنا منطقًا أبسط للتحقق من أن الرابط يبدأ بـ http/https
    # لأن مكتبة 'validators' قد لا تكون متوفرة دائماً في البيئة التجريبية
    if not link_to_analyze.lower().startswith(('http://', 'https://')):
        link_to_analyze = 'https://' + link_to_analyze
    
    # تحقق احترافي إضافي (يجب أن يتم تثبيت المكتبة محليا: pip install validators)
    try:
        if url(link_to_analyze) is not True:
             return jsonify({
                "status": "validation_error",
                "message": "❌ الإدخال غير صحيح. الرجاء إدخال رابط حقيقي وصالح بصيغة URL.",
                "error_code": 400
            }), 400
    except ImportError:
         # تجاوز التحقق الاحترافي إذا لم يتم تثبيت المكتبة
         pass


    # 3. المتابعة إلى منطق التحليل
    analysis_result = perform_security_scan(link_to_analyze) 
    
    return jsonify(analysis_result), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

