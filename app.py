from flask import Flask, render_template, request, redirect, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash  # For password hashing

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Insecure! For demonstration only.

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('budget.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS transactions
                 (id INTEGER PRIMARY KEY, user_id INTEGER, description TEXT, amount REAL)''')
    conn.commit()
    conn.close()

# Home page
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('index.html')

# Registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)  # Hash the password
        conn = sqlite3.connect('budget.db')
        c = conn.cursor()
        # Check if username already exists
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        if c.fetchone():
            return "Username already exists!"
        # Insert new user
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()
        return redirect('/login')
    return render_template('register.html')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('budget.db')
        c = conn.cursor()
        # Fetch user from database
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):  # Verify hashed password
            session['user_id'] = user[0]
            return redirect('/')
        else:
            return "Invalid credentials!"
    return render_template('login.html')

# Add transaction
@app.route('/add', methods=['POST'])
def add_transaction():
    if 'user_id' not in session:
        return redirect('/login')
    description = request.form['description']
    amount = float(request.form['amount'])
    user_id = session['user_id']
    conn = sqlite3.connect('budget.db')
    c = conn.cursor()
    # Use parameterized queries to prevent SQL injection
    c.execute("INSERT INTO transactions (user_id, description, amount) VALUES (?, ?, ?)", (user_id, description, amount))
    conn.commit()
    conn.close()
    return redirect('/')

# Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/login')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)  # Debug mode is insecure for production!