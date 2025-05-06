from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import re
import hashlib
import os
import nltk
from nltk import pos_tag, word_tokenize
from command_injection_detector import detect_command_injection

# Download required NLTK packages if not already downloaded
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('taggers/averaged_perceptron_tagger')
except LookupError:
    nltk.download('punkt')
    nltk.download('averaged_perceptron_tagger')

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database connection
def connect_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database
def init_db():
    conn = connect_db()
    with open('schema.sql', 'r') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()

# Initialize database if it doesn't exist
if not os.path.exists('database.db'):
    init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Clean and validate input with POS tagging for command injection
        if detect_command_injection(username):
            flash('Potential command injection detected in username field!', 'danger')
            return render_template('login.html')
            
        if detect_command_injection(password):
            flash('Potential command injection detected in password field!', 'danger')
            return render_template('login.html')
        
        # Hash password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Connect to database and check credentials
        conn = connect_db()
        cursor = conn.cursor()
        
        # Use parameterized queries to prevent SQL injection
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password_hash))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Clean and validate input with POS tagging for command injection
        if detect_command_injection(username):
            flash('Potential command injection detected in username field!', 'danger')
            return render_template('register.html')
            
        if detect_command_injection(password):
            flash('Potential command injection detected in password field!', 'danger')
            return render_template('register.html')
        
        # Validate username format
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            flash('Username can only contain letters, numbers, and underscores.', 'danger')
            return render_template('register.html')
        
        # Hash password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Connect to database
        conn = connect_db()
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            conn.close()
            flash('Username already exists', 'danger')
            return render_template('register.html')
        
        # Add new user
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                      (username, password_hash))
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        # Connect to database
        conn = connect_db()
        cursor = conn.cursor()
        
        # Get user data
        cursor.execute("SELECT * FROM users WHERE username = ?", (session['username'],))
        user = cursor.fetchone()
        
        # Get user's posts
        cursor.execute("SELECT * FROM posts WHERE user_id = ?", (user['id'],))
        posts = cursor.fetchall()
        
        conn.close()
        
        return render_template('dashboard.html', user=user, posts=posts)
    
    return redirect(url_for('login'))

@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    results = []
    if request.method == 'POST':
        search_term = request.form['search']
        
        # Clean and validate search input with POS tagging for command injection
        if detect_command_injection(search_term):
            flash('Potential command injection detected in search field!', 'danger')
            return render_template('search.html', results=results)
        
        # Connect to database
        conn = connect_db()
        cursor = conn.cursor()
        
        # Search using parameterized query
        cursor.execute("SELECT * FROM posts WHERE title LIKE ? OR content LIKE ?", 
                     ('%' + search_term + '%', '%' + search_term + '%'))
        results = cursor.fetchall()
        conn.close()
    
    return render_template('search.html', results=results)

@app.route('/post', methods=['GET', 'POST'])
def post():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        # Clean and validate input with POS tagging for command injection
        if detect_command_injection(title):
            flash('Potential command injection detected in title field!', 'danger')
            return render_template('post.html')
            
        if detect_command_injection(content):
            flash('Potential command injection detected in content field!', 'danger')
            return render_template('post.html')
        
        # Connect to database
        conn = connect_db()
        cursor = conn.cursor()
        
        # Get user id
        cursor.execute("SELECT id FROM users WHERE username = ?", (session['username'],))
        user = cursor.fetchone()
        
        # Add new post
        cursor.execute("INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)",
                     (title, content, user['id']))
        conn.commit()
        conn.close()
        
        flash('Post added successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('post.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)