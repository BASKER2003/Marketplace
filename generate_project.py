"""
Bootstrap script for Community Marketplace - Module 1 (Base + Authentication)

This single-file helper will:
- Create a Flask app (app.py content) and write it to disk
- Create required folders (templates/, static/, instance/)
- Populate templates for base, index, and auth pages
- Create a simple SQLite database and user table via SQLAlchemy

USAGE:
1. Save this file and run it with Python 3.10+ in your project root.
2. It will create an `app.py` file and templates; then you can run `python app.py` to start the dev server.

Note: This is a generator script to help you scaffold Module 1 quickly. You can inspect the generated files and modify them.
"""

from pathlib import Path
import textwrap
import os

ROOT = Path('.').resolve()
TEMPLATES = ROOT / 'templates'
STATIC = ROOT / 'static'
INSTANCE = ROOT / 'instance'

TEMPLATES.mkdir(exist_ok=True)
(TEMPLATES / 'auth').mkdir(exist_ok=True)
(TEMPLATES / 'dashboard').mkdir(exist_ok=True)
STATIC.mkdir(exist_ok=True)
(STATIC / 'css').mkdir(exist_ok=True)
(STATIC / 'js').mkdir(exist_ok=True)
INSTANCE.mkdir(exist_ok=True)

app_py = textwrap.dedent(r"""
from flask import Flask, render_template, redirect, url_for, request, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import sqlite3
from pathlib import Path

DB_PATH = Path('instance') / 'marketplace.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize DB if missing
if not DB_PATH.exists():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            employee_id TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT,
            department TEXT,
            phone TEXT,
            profile_picture TEXT,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT
        );
    ''')
    # Insert a demo admin
    import hashlib
    pw = generate_password_hash('adminpass')
    c.execute('''INSERT INTO users (full_name, employee_id, email, password_hash, is_admin, created_at)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              ('Demo Admin', 'ADMIN001', 'admin@example.com', pw, 1, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

app = Flask(__name__)
app.secret_key = 'dev-secret-key'  # CHANGE in production

# ------------------- Routes -------------------
@app.route('/')
def index():
    return render_template('index.html')

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        employee_id = request.form.get('employee_id')
        email = request.form.get('email')
        password = request.form.get('password')
        if not (full_name and employee_id and email and password):
            flash('Please fill all required fields', 'danger')
            return redirect(url_for('register'))
        conn = get_db_connection()
        c = conn.cursor()
        # Check uniqueness
        c.execute('SELECT id FROM users WHERE email = ? OR employee_id = ?', (email, employee_id))
        if c.fetchone():
            flash('Email or Employee ID already exists', 'danger')
            conn.close()
            return redirect(url_for('register'))
        pw_hash = generate_password_hash(password)
        c.execute('INSERT INTO users (full_name, employee_id, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)',
                  (full_name, employee_id, email, pw_hash, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        flash('Account created. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('auth/register.html')

# Login (two options)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        mode = request.form.get('mode')
        if mode == 'sso':
            # Simulated SSO: accept employee_id or email
            identifier = request.form.get('identifier')
            conn = get_db_connection()
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE employee_id = ? OR email = ?', (identifier, identifier))
            row = c.fetchone()
            if row:
                # login success
                session['user_id'] = row['id']
                session['full_name'] = row['full_name']
                flash('Logged in via SSO (simulated)', 'success')
                conn.close()
                return redirect(url_for('dashboard'))
            else:
                flash('User not found. Please register.', 'warning')
                conn.close()
                return redirect(url_for('register'))
        else:
            # email/password login
            email = request.form.get('email')
            password = request.form.get('password')
            conn = get_db_connection()
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE email = ?', (email,))
            row = c.fetchone()
            conn.close()
            if row and row['password_hash'] and check_password_hash(row['password_hash'], password):
                session['user_id'] = row['id']
                session['full_name'] = row['full_name']
                flash('Logged in successfully', 'success')
                return redirect(url_for('dashboard'))
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))
    return render_template('auth/login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('index'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        row = c.fetchone()
        conn.close()
        if row:
            # For demo, redirect to reset with a fake token
            flash('Password reset link (simulated) - opening reset page', 'info')
            return redirect(url_for('reset_password', token='demo-token', _external=False))
        flash('If the email exists, a reset link has been sent (simulated).', 'info')
        return redirect(url_for('login'))
    return render_template('auth/forgot_password.html')

@app.route('/reset-password')
def reset_password():
    # token is simulated
    return render_template('auth/reset_password.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('user_id'):
        flash('Please login to access dashboard', 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard/user_dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)
""")

# Templates content
base_html = textwrap.dedent(r"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Community Marketplace</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <div class="container-fluid">
        <a class="navbar-brand" href="{{ url_for('index') }}">Community Marketplace</a>
        <div class="collapse navbar-collapse">
          <ul class="navbar-nav ms-auto">
            {% if session.get('user_id') %}
            <li class="nav-item"><a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a></li>
            <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">Logout</a></li>
            {% else %}
            <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">Login</a></li>
            <li class="nav-item"><a class="nav-link" href="{{ url_for('register') }}">Register</a></li>
            {% endif %}
          </ul>
        </div>
      </div>
    </nav>

    <div class="container mt-4">
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for category, msg in messages %}
            <div class="alert alert-{{ category }}">{{ msg }}</div>
          {% endfor %}
        {% endif %}
      {% endwith %}

      {% block content %}{% endblock %}
    </div>

    <footer class="footer mt-auto py-3 bg-light">
      <div class="container text-center">
        <span class="text-muted">&copy; Company - Community Marketplace</span>
      </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
""")

index_html = textwrap.dedent(r"""
{% extends 'base.html' %}
{% block content %}
  <div class="jumbotron py-5 text-center">
    <h1 class="display-5">Welcome to the Employee Community Marketplace</h1>
    <p class="lead">Buy, sell, or give away items safely within the organization.</p>
    <p>
      <a class="btn btn-primary btn-lg" href="{{ url_for('login') }}" role="button">Login</a>
      <a class="btn btn-outline-secondary btn-lg" href="{{ url_for('register') }}" role="button">Register</a>
    </p>
  </div>

  <div class="row mt-4">
    <div class="col-md-4">
      <h4>Post Items Easily</h4>
      <p>Create listings quickly with photos and descriptions.</p>
    </div>
    <div class="col-md-4">
      <h4>Browse & Search</h4>
      <p>Find items using search and filters.</p>
    </div>
    <div class="col-md-4">
      <h4>Safe & Moderated</h4>
      <p>Report posts and our admins will review them.</p>
    </div>
  </div>
{% endblock %}
""")

login_html = textwrap.dedent(r"""
{% extends 'base.html' %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-6">
    <div class="card">
      <div class="card-body">
        <h5 class="card-title">Login</h5>

        <!-- SSO -->
        <form method="post" class="mb-3">
          <input type="hidden" name="mode" value="sso">
          <div class="mb-3">
            <label class="form-label">Employee ID or Email (SSO)</label>
            <input class="form-control" name="identifier" placeholder="e.g. EMP001 or you@company.com">
          </div>
          <button class="btn btn-primary" type="submit">Login with Corporate SSO (Simulated)</button>
        </form>

        <hr>

        <!-- Email/password -->
        <form method="post">
          <input type="hidden" name="mode" value="password">
          <div class="mb-3">
            <label class="form-label">Email</label>
            <input class="form-control" name="email" type="email">
          </div>
          <div class="mb-3">
            <label class="form-label">Password</label>
            <input class="form-control" name="password" type="password">
          </div>
          <div class="d-flex justify-content-between">
            <a href="{{ url_for('forgot_password') }}">Forgot password?</a>
            <button class="btn btn-success" type="submit">Login</button>
          </div>
        </form>

      </div>
    </div>
  </div>
</div>
{% endblock %}
""")

register_html = textwrap.dedent(r"""
{% extends 'base.html' %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-6">
    <div class="card">
      <div class="card-body">
        <h5 class="card-title">Register</h5>
        <form method="post">
          <div class="mb-3">
            <label class="form-label">Full name</label>
            <input class="form-control" name="full_name">
          </div>
          <div class="mb-3">
            <label class="form-label">Employee ID</label>
            <input class="form-control" name="employee_id">
          </div>
          <div class="mb-3">
            <label class="form-label">Email</label>
            <input class="form-control" name="email" type="email">
          </div>
          <div class="mb-3">
            <label class="form-label">Password</label>
            <input class="form-control" name="password" type="password">
          </div>
          <button class="btn btn-primary" type="submit">Create Account</button>
        </form>
      </div>
    </div>
  </div>
</div>
{% endblock %}
""")

forgot_html = textwrap.dedent(r"""
{% extends 'base.html' %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-6">
    <div class="card">
      <div class="card-body">
        <h5 class="card-title">Forgot Password</h5>
        <form method="post">
          <div class="mb-3">
            <label class="form-label">Email</label>
            <input class="form-control" name="email" type="email">
          </div>
          <button class="btn btn-primary" type="submit">Send Reset Link (Simulated)</button>
        </form>
      </div>
    </div>
  </div>
</div>
{% endblock %}
""")

reset_html = textwrap.dedent(r"""
{% extends 'base.html' %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-6">
    <div class="card">
      <div class="card-body">
        <h5 class="card-title">Reset Password (Simulated)</h5>
        <form method="post" action="#">
          <div class="mb-3">
            <label class="form-label">New Password</label>
            <input class="form-control" name="new_password" type="password">
          </div>
          <div class="mb-3">
            <label class="form-label">Confirm Password</label>
            <input class="form-control" name="confirm_password" type="password">
          </div>
          <button class="btn btn-primary" type="submit">Save Password</button>
        </form>
      </div>
    </div>
  </div>
</div>
{% endblock %}
""")

dashboard_html = textwrap.dedent(r"""
{% extends 'base.html' %}
{% block content %}
  <h3>Welcome, {{ session.get('full_name') }}</h3>
  <p>This is your dashboard (Module 1 placeholder). Your listings and inquiries will appear here.</p>
{% endblock %}
""")



# ------------------ Templates ------------------
base_html = textwrap.dedent(r"""
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Community Marketplace</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
      body.dark-mode { background-color: #121212; color: #f8f9fa; }
      .card.dark-mode { background-color: #1e1e1e; color: #f8f9fa; }
      .navbar.dark-mode { background-color: #1e1e1e !important; }
      a { text-decoration: none; }
    </style>
  </head>
  <body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light" id="navbar">
      <div class="container-fluid">
        <a class="navbar-brand" href="{{ url_for('index') }}">Community Marketplace</a>
        <button class="btn btn-sm btn-outline-secondary ms-auto" onclick="toggleDarkMode()" id="theme-btn">Dark Mode</button>
        <div class="collapse navbar-collapse">
          <ul class="navbar-nav ms-auto">
            {% if session.get('user_id') %}
            <li class="nav-item"><a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a></li>
            <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">Logout</a></li>
            {% else %}
            <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">Login</a></li>
            <li class="nav-item"><a class="nav-link" href="{{ url_for('register') }}">Register</a></li>
            {% endif %}
          </ul>
        </div>
      </div>
    </nav>

    <div class="container mt-4">
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for category, msg in messages %}
            <div class="alert alert-{{ category }}">{{ msg }}</div>
          {% endfor %}
        {% endif %}
      {% endwith %}
      {% block content %}{% endblock %}
    </div>

    <footer class="footer mt-auto py-3 bg-light">
      <div class="container text-center">
        <span class="text-muted">&copy; Company - Community Marketplace</span>
      </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
      function toggleDarkMode() {
        document.body.classList.toggle('dark-mode');
        document.querySelectorAll('.card').forEach(c => c.classList.toggle('dark-mode'));
        document.getElementById('navbar').classList.toggle('dark-mode');
      }
    </script>
  </body>
</html>
""")

login_html = textwrap.dedent(r"""
{% extends 'base.html' %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-6">
    <div class="card p-3">
      <h5 class="card-title">Login</h5>
      <div class="btn-group mb-3 w-100" role="group">
        <button class="btn btn-outline-primary w-50" onclick="toggleLogin('sso')">SSO Login</button>
        <button class="btn btn-outline-secondary w-50" onclick="toggleLogin('password')">Password Login</button>
      </div>
      <form id="form-sso" method="post" style="display:none;">
        <input type="hidden" name="mode" value="sso">
        <input class="form-control mb-3" name="identifier" placeholder="EMP001 or user@sandbox.com" required>
        <button class="btn btn-primary w-100" type="submit">Login with SSO</button>
      </form>
      <form id="form-password" method="post" style="display:none;">
        <input type="hidden" name="mode" value="password">
        <input class="form-control mb-3" name="email" type="email" required pattern="^[^@]+@sandbox\.com$" placeholder="name@sandbox.com">
        <input class="form-control mb-3" name="password" type="password" required placeholder="Password">
        <button class="btn btn-success w-100" type="submit">Login</button>
      </form>
    </div>
  </div>
</div>
<script>
function toggleLogin(type){
  document.getElementById('form-sso').style.display = type==='sso'?'block':'none';
  document.getElementById('form-password').style.display = type==='password'?'block':'none';
}
</script>
{% endblock %}
""")

register_html = textwrap.dedent(r"""
{% extends 'base.html' %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-6">
    <div class="card p-3">
      <h5 class="card-title">Register</h5>
      <form method="post">
        <input class="form-control mb-3" name="full_name" placeholder="Full Name" required>
        <input class="form-control mb-3" name="employee_id" placeholder="Employee ID" required>
        <input class="form-control mb-3" name="email" type="email" placeholder="name@sandbox.com" required pattern="^[^@]+@sandbox\.com$">
        <input class="form-control mb-3" name="password" type="password" placeholder="Password (min 6 chars)" required minlength="6">
        <button class="btn btn-primary w-100" type="submit">Create Account</button>
      </form>
    </div>
  </div>
</div>
{% endblock %}
""")

# Write files
(ROOT / 'app.py').write_text(app_py, encoding='utf-8')
(TEMPLATES / 'base.html').write_text(base_html, encoding='utf-8')
(TEMPLATES / 'index.html').write_text(index_html, encoding='utf-8')
(TEMPLATES / 'auth' / 'login.html').write_text(login_html, encoding='utf-8')
(TEMPLATES / 'auth' / 'register.html').write_text(register_html, encoding='utf-8')
(TEMPLATES / 'auth' / 'forgot_password.html').write_text(forgot_html, encoding='utf-8')
(TEMPLATES / 'auth' / 'reset_password.html').write_text(reset_html, encoding='utf-8')
(TEMPLATES / 'dashboard' / 'user_dashboard.html').write_text(dashboard_html, encoding='utf-8')

print('Scaffold created:')
print(' - app.py')
print(' - templates/ (auth/, dashboard/)')
print(' - instance/marketplace.db created (with demo admin)')
print('Updated scaffold with dark mode, SSO toggle, email validation.')
print('\nRun the app: python app.py')
