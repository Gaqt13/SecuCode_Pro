import os
from flask import Flask, request, jsonify, render_template
from validators import url  # المكتبة الضرورية للتحقق من الروابط
import requests
import json

app = Flask(__name__)

# --- دالة التحليل الأمني (يجب أن تحتوي على منطقك الأصلي) ---
def perform_security_scan(link):
    """
    تقوم بتنفيذ عملية الفحص الأمني الحقيقية على الرابط.
    هذا هو المنطق الذي يعيد النتيجة الأصلية لمشروعك.
    """
    try:
        # مثال بسيط (يمكنك استبداله بمنطقك الأصلي)
        response = requests.get(link, timeout=5, allow_redirects=True) 
        
        if response.status_code == 200:
            return {
                "status": "success",
                "message": "تحليل مكتمل.",
                "link": link,
                "result_message": "آمن نسبيًا.",
                "risk_score": "Low",
                "suspicious_points": 2,
                "detected_warnings": 1,
                "page_content_warning": "تم جلب محتوى الصفحة بنجاح."
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
            
    except requests.exceptions.RequestException:
        # التعامل مع أخطاء الاتصال
        return {
            "status": "error",
            "message": "خطأ في الاتصال بالرابط.",
            "link": link,
            "result_message": "غير قابل للوصول.",
            "risk_score": "High",
            "suspicious_points": 10,
            "detected_warnings": 3,
            "page_content_warning": "فشل حاد في الاتصال بالرابط أو حدوث مهلة (Timeout)."
        }

# --- نقطة النهاية الرئيسية (عرض الصفحة) ---
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


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

    # 2. التحقق من صيغة الرابط (لحل مشكلة إعطاء نتيجة للحروف العشوائية)
    if url(link_to_analyze) is not True:
        return jsonify({
            "status": "validation_error",
            "message": "❌ الإدخال غير صحيح. الرجاء إدخال رابط حقيقي وصالح بصيغة URL.",
            "error_code": 400
        }), 400

    # 3. المتابعة إلى منطق التحليل
    analysis_result = perform_security_scan(link_to_analyze) 
    
    return jsonify(analysis_result), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
