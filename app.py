
from flask import Flask, render_template, request
import sqlite3

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS leaks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            is_leaked INTEGER NOT NULL
        )
    ''')
    sample_data = [
        ("admin@devguardians.com", 1),
        ("test.leak@example.com", 1),
        ("mnmapex@gmail.com", 0)
    ]
    for email, is_leaked in sample_data:
        try:
            cursor.execute("INSERT INTO leaks (email, is_leaked) VALUES (?, ?)", (email, is_leaked))
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_email():
    email = request.form.get('email').strip().lower()
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT is_leaked FROM leaks WHERE email = ?", (email,))
    row = cursor.fetchone()
    
    if row:
        is_leaked = bool(row[0])
    else:
        is_leaked = "test" in email or "admin" in email
        cursor.execute("INSERT INTO leaks (email, is_leaked) VALUES (?, ?)", (email, int(is_leaked)))
        conn.commit()
        
    conn.close()
    return render_template('result.html', email=email, is_leaked=is_leaked)

# مسار جديد لعرض قاعدة البيانات للجنة المناقشة
@app.route('/records')
def view_records():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, is_leaked FROM leaks")
    records = cursor.fetchall()
    conn.close()
    return render_template('records.html', records=records)

if __name__ == '__main__':
    app.run(debug=True)