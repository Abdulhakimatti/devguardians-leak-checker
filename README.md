# 🛡️ DevGuardians - Data Leak Checker & Digital Security Advisor
> **منصة فحص تسريب البيانات وإرشادات الأمان الرقمي**

مشروع تخرج - تخصص تطوير البرمجيات وتقنية المعلومات - فريق **حراس التطوير (DevGuardians)**.

---

## 🎯 نبذة عن المشروع
منصة ويب تفحص كلمات المرور والبريد الإلكتروني مقابل تسريبات معروفة، وتعرض للمستخدم خطوات عملية لحماية حساباته.

## ✅ الميزات المنفّذة
| الميزة | كيف تعمل |
|---|---|
| فحص كلمة المرور | Pwned Passwords API بآلية k-anonymity: يُرسل أول 5 أحرف فقط من SHA-1، وكلمة المرور لا تُخزَّن ولا تُسجَّل. |
| فحص البريد الإلكتروني | Have I Been Pwned API عند ضبط `HIBP_API_KEY`، وإلا **وضع تجريبي** واضح للمستخدم (بيانات عرض فقط). |
| الخصوصية | لا يُحفظ أي فحص إلا بموافقة المستخدم، ويُحفظ البريد مقنّعًا (`ab***@gmail.com`). |
| فحص الرابط | فحص محلي بالقواعد (HTTP، رقم IP، حروف مموّهة، اختصار...). لا يفتح الرابط، وهو مؤشر وليس ضمانًا. |
| فحص رقم الهاتف | مكتبة `phonenumbers`: صحة الرقم، الدولة، النوع. يعرض مكان تسجيل الرقم وليس مكان صاحبه. |
| فحص الملف | يحسب SHA-256 دون حفظ الملف، ويبحث عن البصمة في VirusTotal عند ضبط `VIRUSTOTAL_API_KEY`. |
| لوحة السجلات `/records` | محمية بكلمة مرور مشرف مخزّنة كتجزئة (Werkzeug scrypt). |
| حماية التطبيق | رمز CSRF للنماذج، التحقق من صيغة المدخلات، استعلامات SQL مُعلَّمة، ترويسات أمان، تعطيل `debug` افتراضيًا. |

## 🚧 تطوير مستقبلي (غير منفّذ حاليًا)
- حسابات مستخدمين وتنبيهات بريدية (SMTP) عند اكتشاف تسريب جديد.
- الانتقال من SQLite إلى PostgreSQL.
- تحديد معدل الطلبات (Rate Limiting).

## 🚀 التقنيات
* **Backend:** Python + Flask
* **Database:** SQLite
* **Frontend:** HTML5, CSS3, Bootstrap 5 (RTL)
* **Version Control:** Git & GitHub

## ⚙️ التشغيل محليًا
```bash
python -m venv venv
venv\Scripts\activate          # على Windows  (على Linux/Mac: source venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env         # على Linux/Mac: cp .env.example .env
python app.py
```

### إعداد كلمة مرور المشرف
ولّد التجزئة:
```bash
python -c "from werkzeug.security import generate_password_hash as g; print(g(input('Password: ')))"
```
ضعها في `.env` بين علامتي اقتباس مفردة:
```
ADMIN_PASSWORD_HASH='scrypt:32768:8:1$...'
```
ثم افتح `/login`. بدون هذه القيمة تبقى لوحة السجلات معطّلة.

### فحص البريد الحقيقي (اختياري)
احصل على مفتاح من [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) (يتطلب اشتراكًا) وضعه في `HIBP_API_KEY`.

## 📂 هيكل المشروع
```text
devguardians-leak-checker/
├── app.py              # التطبيق الرئيسي
├── requirements.txt    # مكتبات بايثون
├── .env.example        # نموذج الإعدادات (انسخه إلى .env)
├── .gitignore
├── templates/          # base, index, result, login, records
└── README.md
```

## 👥 فريق العمل
* **طالب تطوير المشروع:** عبدالحكيم (Abdulhakim)
* **الرقم التدريبي:** 445231502
* **الجهة الأكاديمية:** الكلية التقنية (TVTC) - تخصص تطوير البرمجيات وتقنية المعلومات
