import os
from flask import Flask, request, jsonify, render_template
from validators import url  # استيراد دالة التحقق
import requests
import json

app = Flask(__name__)

# --- دالة التحليل الأمني (افتراضية) ---
# يجب عليك استبدال هذا المنطق بالمنطق الحقيقي لمشروعك (SecuCode)
def perform_security_scan(link):
    """
    تقوم بتنفيذ عملية الفحص الأمني الحقيقية على الرابط.
    هذه الدالة يجب أن تُحدَّث للتعامل مع أخطاء الاتصال/Timeout بشكل سليم.
    """
    try:
        # محاولة الاتصال بالرابط لتأكيد وجوده (اختياري، يمكنك استخدام منطقك الخاص)
        response = requests.get(link, timeout=5, allow_redirects=True) 
        
        # مثال لمنطق بسيط جداً للنتائج:
        if response.status_code == 200:
            # مثال لتقرير تفصيلي
            return {
                "status": "success",
                "message": "تحليل مكتمل.",
                "link": link,
                "result_message": "آمن نسبيًا.",
                "risk_score": "Low",
                "suspicious_points": 2,
                "detected_warnings": 1,
                "page_content_warning": "تحذير: تم جلب محتوى الصفحة بنجاح."
            }
        else:
            return {
                "status": "warning",
                "message": "تحذير: الرابط موجود لكن حالة الاستجابة غير عادية.",
                "link": link,
                "result_message": "غير مؤكد.",
                "risk_score": "Medium",
                "suspicious_points": 5,
                "detected_warnings": 2,
                "page_content_warning": f"فشل في جلب محتوى الصفحة. رمز الحالة: {response.status_code}"
            }
            
    except requests.exceptions.RequestException as e:
        # التعامل مع أخطاء الاتصال، Timeout، أو الروابط غير القابلة للوصول
        return {
            "status": "error",
            "message": "خطأ في الاتصال بالرابط.",
            "link": link,
            "result_message": "غير قابل للوصول.",
            "risk_score": "High", # نرفع درجة الخطورة إذا لم نتمكن من الوصول
            "suspicious_points": 10,
            "detected_warnings": 3,
            "page_content_warning": "فشل حاد في الاتصال بالرابط أو حدوث مهلة (Timeout)."
        }

# --- نقطة النهاية الرئيسية (عرض الصفحة) ---
@app.route('/', methods=['GET'])
def index():
    # افترض أن ملف الواجهة الأمامية هو index.html داخل مجلد templates
    return render_template('index.html')


# --- نقطة النهاية للتحليل (تطبيق التحقق الاحترافي) ---
@app.route('/analyze', methods=['POST'])
def analyze_link():
    """
    نقطة النهاية لمعالجة طلب فحص الرابط مع التحقق الاحترافي.
    """
    
    # 1. استلام الرابط من الطلب
    try:
        data = request.get_json()
        link_to_analyze = data.get('link')
    except Exception:
        # خطأ في صيغة JSON
        return jsonify({
            "status": "critical_error",
            "message": "خطأ في معالجة بيانات الطلب (JSON).",
            "error_code": 400
        }), 400

    # 2. التحقق من وجود الرابط (الرابط فارغ)
    if not link_to_analyze or link_to_analyze.strip() == "":
        return jsonify({
            "status": "validation_error",
            "message": "❌ فشل التحقق: الرجاء إدخال رابط. حقل الرابط لا يمكن أن يكون فارغاً.",
            "error_code": 400
        }), 400

    # 3. التحقق الاحترافي من صيغة الرابط (باستخدام مكتبة validators)
    if url(link_to_analyze) is not True:
        # إرجاع استجابة خطأ HTTP 400 (Bad Request)
        return jsonify({
            "status": "validation_error",
            "message": "❌ فشل التحقق: الإدخال غير صحيح. الرجاء إدخال رابط حقيقي وصالح بصيغة URL (مثل: https://example.com).",
            "error_code": 400
        }), 400

    # 4. المتابعة إلى منطق التحليل
    analysis_result = perform_security_scan(link_to_analyze) 
    
    return jsonify(analysis_result), 200

# تشغيل التطبيق محلياً (لا يتم استخدامه في Vercel عادةً)
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
