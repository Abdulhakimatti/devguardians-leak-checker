from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_email():
    email = request.form.get('email')
    
    # محاكاة لفحص البريد (يمكننا لاحقاً ربطها بقاعدة بيانات أو API حقيقي)
    # للأغراض التجريبية: سنعتبر إيميلات معينة أو نفترض النتيجة
    is_leaked = "test" in email.lower() or "admin" in email.lower()
    
    return render_template('result.html', email=email, is_leaked=is_leaked)

if __name__ == '__main__':
    app.run(debug=True)