from flask import Flask, jsonify, render_template, redirect, send_from_directory, url_for, request, flash, session
from flask_login import current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, time
from functools import wraps
import sqlite3
from pathlib import Path
import os

DB_PATH = Path('instance') / 'marketplace.db'
UPLOAD_FOLDER = 'static/uploads/items'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

CHAT_UPLOAD_FOLDER = os.path.join('static', 'uploads', 'chat')
os.makedirs(CHAT_UPLOAD_FOLDER, exist_ok=True)
ALLOWED_IMAGE_EXT = {'png', 'jpg', 'jpeg', 'gif'}

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
    # Demo admin
    pw = generate_password_hash('adminpass')
    c.execute('''INSERT INTO users (full_name, employee_id, email, password_hash, is_admin, created_at)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              ('Demo Admin', 'ADMIN001', 'admin@sandbox.com', pw, 1, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

conn = sqlite3.connect(DB_PATH, check_same_thread=False)
c = conn.cursor()

# Items table
c.execute('''
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL,
    currency TEXT NOT NULL,        -- EUR, INR, GBP
    thumbnail TEXT,
    status TEXT DEFAULT 'active',  -- active / expired
    expires_at TEXT NOT NULL,
    created_at TEXT,
    updated_at TEXT,
    FOREIGN KEY(owner_id) REFERENCES users(id)
);
''')

# Item Images table (max 5 per item)
c.execute('''
CREATE TABLE IF NOT EXISTS item_images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    FOREIGN KEY(item_id) REFERENCES items(id)
);
''')

# Wishlist table (many-to-many between users and items)
c.execute('''
CREATE TABLE IF NOT EXISTS wishlist (
    user_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, item_id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(item_id) REFERENCES items(id)
);
''')

# Item reports table
c.execute('''
CREATE TABLE IF NOT EXISTS item_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    reporter_id INTEGER NOT NULL,
    reason TEXT,
    created_at TEXT,
    FOREIGN KEY(item_id) REFERENCES items(id),
    FOREIGN KEY(reporter_id) REFERENCES users(id)
);
''')

# Chat tables (put near other CREATE TABLE calls)
c.execute('''
CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_a INTEGER NOT NULL,
    user_b INTEGER NOT NULL,
    created_at TEXT,
    UNIQUE(user_a, user_b)
);
''')

c.execute('''
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    body TEXT,
    created_at TEXT,
    is_read INTEGER DEFAULT 0,
    FOREIGN KEY(conversation_id) REFERENCES conversations(id),
    FOREIGN KEY(sender_id) REFERENCES users(id)
);
''')

c.execute('''
CREATE TABLE IF NOT EXISTS chat_attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    FOREIGN KEY(message_id) REFERENCES messages(id)
);
''')

# typing status table (simple)
c.execute('''
CREATE TABLE IF NOT EXISTS typing_status (
    conversation_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    last_typing_at REAL,
    PRIMARY KEY (conversation_id, user_id)
);
''')



conn.commit()
conn.close()


app = Flask(__name__)
app.secret_key = 'dev-secret-key'

# ------------------- Routes -------------------
@app.route('/')
def index():
    return render_template('index.html')

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
        if not email.endswith('@sandbox.com'):
            flash('Use company email ending with @sandbox.com', 'danger')
            return redirect(url_for('register'))

        conn = get_db_connection()
        c = conn.cursor()
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        mode = request.form.get('mode')
        if mode == 'sso':
            identifier = request.form.get('identifier')
            conn = get_db_connection()
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE employee_id = ? OR email = ?', (identifier, identifier))
            row = c.fetchone()
            conn.close()
            if row:
                session['user_id'] = row['id']
                session['full_name'] = row['full_name']
                session['is_admin'] = False
                flash('Logged in via SSO', 'success')
                return redirect(url_for('dashboard'))
            flash('User not found. Please register.', 'warning')
            return redirect(url_for('register'))
        else:
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
            flash('Password reset link (simulated)', 'info')
            return redirect(url_for('reset_password', token='demo-token'))
        flash('If the email exists, a reset link has been sent (simulated).', 'info')
        return redirect(url_for('login'))
    return render_template('auth/forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    return render_template('auth/reset_password.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('user_id'):
        flash('Please login', 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard/user_dashboard.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        flash('Your message has been submitted (simulated).', 'success')
        return redirect(url_for('index'))
    return render_template('contact.html')


# Profile page & update routes (already explained previously)
@app.route('/profile')
def profile():
    if not session.get('user_id'):
        flash('Please login', 'warning')
        return redirect(url_for('login'))
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    return render_template('profile.html', user=user)

@app.route('/update-profile', methods=['POST'])
def update_profile():
    if not session.get('user_id'):
        flash('Please login', 'warning')
        return redirect(url_for('login'))
    full_name = request.form.get('full_name')
    department = request.form.get('department')
    phone = request.form.get('phone')
    profile_picture = request.files.get('profile_picture')
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    pic_filename = user['profile_picture']
    if profile_picture:
        filename = f"profile_{session['user_id']}_{profile_picture.filename}"
        profile_picture.save(f"static/uploads/profile/{filename}")
        pic_filename = filename
    conn.execute('UPDATE users SET full_name=?, department=?, phone=?, profile_picture=? WHERE id=?',
                 (full_name, department, phone, pic_filename, session['user_id']))
    conn.commit()
    conn.close()
    session['full_name'] = full_name
    flash('Profile updated successfully', 'success')
    return redirect(url_for('profile'))

@app.route('/update-password', methods=['POST'])
def update_password():
    if not session.get('user_id'):
        flash('Please login', 'warning')
        return redirect(url_for('login'))
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    if new_password != confirm_password:
        flash('Passwords do not match', 'danger')
        return redirect(url_for('profile'))
    conn = get_db_connection()
    pw_hash = generate_password_hash(new_password)
    conn.execute('UPDATE users SET password_hash=? WHERE id=?', (pw_hash, session['user_id']))
    conn.commit()
    conn.close()
    flash('Password updated successfully', 'success')
    return redirect(url_for('profile'))


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/add_item', methods=['GET', 'POST'])
def add_item():
    if not session.get('user_id'):
        flash('Please login first.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    c = conn.cursor()

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        posted_date = request.form['posted_date']
        # Category handling
        category = request.form['category']
        if category == 'other':
            category = request.form.get('custom_category') or 'Other'

        # Price handling
        if request.form.get('price') == '':
            price = 0.0
        else:
            price = float(request.form['price'])
        if 'freeCheckbox' in request.form:
            price = 0.0

        currency = request.form['currency']

        # Expiry logic
        expiry_option = request.form.get('expiry_option')
        custom_days = request.form.get('custom_days')
        from datetime import datetime, timedelta
        if expiry_option == 'custom' and custom_days:
            days = max(1, min(100, int(custom_days)))  # ensure 1-100
        else:
            days = int(expiry_option)
        expires_at = (datetime.utcnow() + timedelta(days=days)).isoformat()

        # Handle images
        files = request.files.getlist('images[]')
        thumbnail = None
        image_files = []

        for i, file in enumerate(files[:5]):  # max 5 images
            if file and allowed_file(file.filename):
                filename = f"{datetime.utcnow().timestamp()}_{secure_filename(file.filename)}"
                file.save(os.path.join(UPLOAD_FOLDER, filename))
                image_files.append(filename)
                if i == 0:
                    thumbnail = filename

        # Insert item
        c.execute('''
            INSERT INTO items (owner_id, title, description, category, price, currency, thumbnail, expires_at, created_at, posted_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], title, description, category, price, currency, thumbnail, expires_at, datetime.utcnow().isoformat(), posted_date))
        item_id = c.lastrowid

        # Insert images
        for img in image_files:
            c.execute('INSERT INTO item_images (item_id, filename) VALUES (?, ?)', (item_id, img))

        conn.commit()
        conn.close()

        flash('Item added successfully!', 'success')
        return redirect(url_for('dashboard'))

    # Currencies & expiry options
    currencies = ['EUR', 'INR', 'GBP']
    expiry_options = [7, 15, 30, 60, 'custom']  # in days
    categories = ['Electronics', 'Furniture', 'Books', 'Clothing']  # example categories

    return render_template('dashboard/add_item.html', currencies=currencies, expiry_options=expiry_options, categories=categories)

# ------------------- Additional Routes -------------------

# Helper decorator for login check


def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please login first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap

# ----- My Listings -----
@app.route('/my_listings')
@login_required
def my_listings():
    if not session.get('user_id'):
        flash("Please log in.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()

    items = conn.execute("""
        SELECT * FROM items 
        WHERE owner_id=? 
        ORDER BY posted_date DESC
    """, (session['user_id'],)).fetchall()

    full_items = []

    from datetime import datetime, date

    for item in items:

        # Load image filenames
        images = conn.execute(
            "SELECT filename FROM item_images WHERE item_id=?",
            (item['id'],)
        ).fetchall()

        img_list = [img['filename'] for img in images]

        # Parse ISO timestamps safely
        raw_posted = item['posted_date']
        raw_expires = item['expires_at']

        try:
            posted_date = datetime.strptime(raw_posted, "%Y-%m-%dT%H:%M:%S.%f").date()
        except:
            posted_date = datetime.strptime(raw_posted.split("T")[0], "%Y-%m-%d").date()

        try:
            expires_date = datetime.strptime(raw_expires, "%Y-%m-%dT%H:%M:%S.%f").date()
        except:
            expires_date = datetime.strptime(raw_expires.split("T")[0], "%Y-%m-%d").date()

        today = date.today()

        # Determine status
        if posted_date > today:
            status = "scheduled"        # future post
        elif expires_date < today:
            status = "expired"
        else:
            status = "active"

        full_items.append({
            **dict(item),
            "images": img_list,
            "posted_date_clean": posted_date.strftime("%Y-%m-%d"),
            "expires_at_clean": expires_date.strftime("%Y-%m-%d"),
            "status": status
        })

    conn.close()

    return render_template("dashboard/my_listings.html", items=full_items)

# ----- Edit Item -----
@app.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    if not session.get('user_id'):
        flash("Please log in.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    item = conn.execute(
        "SELECT * FROM items WHERE id=? AND owner_id=?",
        (item_id, session['user_id'])
    ).fetchone()

    if not item:
        flash("Item not found.", "danger")
        return redirect(url_for('my_listings'))

    images = conn.execute(
        "SELECT id, filename FROM item_images WHERE item_id=?",
        (item_id,)
    ).fetchall()

    from datetime import datetime

    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        price = request.form.get('price', 0)
        currency = request.form.get('currency', '').strip()
        posted_date_str = request.form['posted_date']
        expiry_date_str = request.form.get('expires_at')

        # Handle "Free" checkbox
        if request.form.get('is_free'):
            price_val = 0
            currency = ''
        else:
            try:
                price_val = float(price)
            except:
                price_val = 0

        # Dates
        try:
            posted_date = datetime.strptime(posted_date_str, "%Y-%m-%d").date()
        except:
            posted_date = datetime.today()

        try:
            expires_date = datetime.strptime(expiry_date_str, "%Y-%m-%d").date()
        except:
            # fallback: keep current expiry
            expires_date = datetime.strptime(item['expires_at'].split("T")[0], "%Y-%m-%d").date()

        # Update item
        conn.execute("""
            UPDATE items SET title=?, description=?, price=?, currency=?, posted_date=?, expires_at=?
            WHERE id=?
        """, (title, description, price_val, currency, posted_date.isoformat(), expires_date.isoformat(), item_id))

        # Delete selected images
        delete_ids = request.form.getlist('delete_images')
        for img_id in delete_ids:
            img_data = conn.execute("SELECT filename FROM item_images WHERE id=?", (img_id,)).fetchone()
            if img_data:
                path = os.path.join('static', 'uploads', 'items', img_data['filename'])
                if os.path.exists(path):
                    os.remove(path)
                conn.execute("DELETE FROM item_images WHERE id=?", (img_id,))

        # Add new images
        new_files = request.files.getlist('new_images')
        current_count = len(images) - len(delete_ids)
        for f in new_files:
            if f and current_count < 5:
                filename = secure_filename(f.filename)
                save_path = os.path.join('static', 'uploads', 'items', filename)
                f.save(save_path)
                conn.execute("INSERT INTO item_images (item_id, filename) VALUES (?, ?)", (item_id, filename))
                current_count += 1

        conn.commit()
        conn.close()
        flash("Item updated successfully!", "success")
        return redirect(url_for('my_listings'))

    conn.close()
    return render_template("dashboard/edit_item.html", item=item, images=images)


@app.route('/delete_item/<int:item_id>')
@login_required
def delete_item(item_id):
    if not session.get('user_id'):
        flash("Please log in first.", "warning")
        return redirect(url_for('login'))

    conn = get_db_connection()

    # Delete images from DB
    imgs = conn.execute("""
        SELECT filename FROM item_images WHERE item_id=?
    """, (item_id,)).fetchall()

    for img in imgs:
        try:
            os.remove(os.path.join('static/uploads/items', img['filename']))
        except:
            pass

    conn.execute("DELETE FROM item_images WHERE item_id=?", (item_id,))
    conn.execute("DELETE FROM items WHERE id=? AND owner_id=?", (item_id, session['user_id']))
    conn.commit()
    conn.close()

    flash("Item deleted successfully.", "success")
    return redirect(url_for('my_listings'))


# ----- Marketplace -----
@app.route('/marketplace')
@login_required
def marketplace():
    conn = get_db_connection()

    # --- Pagination settings ---
    page = int(request.args.get("page", 1))
    per_page = 9
    offset = (page - 1) * per_page

    # Count total items
    total_items = conn.execute("SELECT COUNT(*) FROM items").fetchone()[0]
    total_pages = (total_items + per_page - 1) // per_page

    # Fetch items
    rows = conn.execute("""
        SELECT * FROM items 
        ORDER BY posted_date DESC 
        LIMIT ? OFFSET ?
    """, (per_page, offset)).fetchall()

    items = []
    from datetime import datetime, date

    def safe_date(value):
        """Safely convert DB date or return None."""
        if not value:
            return None
        try:
            return datetime.fromisoformat(value).date()
        except:
            try:
                return datetime.strptime(value[:10], "%Y-%m-%d").date()
            except:
                return None

    today = date.today()

    for row in rows:
        images = conn.execute("SELECT filename FROM item_images WHERE item_id=?", 
                              (row['id'],)).fetchall()
        image_list = [i['filename'] for i in images]

        posted = safe_date(row['posted_date'])
        exp = safe_date(row['expires_at'])

        # --- Determine status ---
        if posted and posted > today:
            status = "scheduled"
        elif exp and exp < today:
            status = "expired"
        else:
            status = "active"

        # ---- CHECK IF USER WISHLISTED THIS ITEM ----
        wished = conn.execute(
            "SELECT 1 FROM wishlist WHERE user_id=? AND item_id=?",
            (session['user_id'], row['id'])
        ).fetchone() is not None

        items.append({
            **dict(row),
            "images": image_list,
            "status": status,
            "posted_clean": posted.strftime("%Y-%m-%d") if posted else "N/A",
            "expires_clean": exp.strftime("%Y-%m-%d") if exp else "N/A",
            "wished": wished
        })

    # USER ITEMS
    user_items = []
    if session.get("user_id"):
        user_rows = conn.execute("""
            SELECT * FROM items WHERE owner_id=? ORDER BY posted_date DESC
        """, (session['user_id'],)).fetchall()

        for row in user_rows:
            imgs = conn.execute("SELECT filename FROM item_images WHERE item_id=?", 
                                (row['id'],)).fetchall()
            user_items.append({
                **dict(row),
                "images": [i['filename'] for i in imgs]
            })

    conn.close()

    return render_template(
        "dashboard/marketplace.html",
        items=items,
        user_items=user_items,
        page=page,
        total_pages=total_pages
    )


# ----- My Inquiries (placeholder) -----
@app.route('/my_inquiries')
@login_required
def my_inquiries():
    # For now, this is a placeholder. You can later implement messages/inquiry table.
    return render_template('dashboard/my_inquiries.html')


@app.route('/wishlist')
@login_required
def wishlist():
    user_id = session.get('user_id')
    conn = get_db_connection()

    rows = conn.execute('''
        SELECT items.* 
        FROM items
        JOIN wishlist ON items.id = wishlist.item_id
        WHERE wishlist.user_id = ?
        ORDER BY items.posted_date DESC
    ''', (user_id,)).fetchall()

    wishlist_items = []

    for row in rows:
        images = conn.execute(
            "SELECT filename FROM item_images WHERE item_id=?",
            (row['id'],)
        ).fetchall()

        wishlist_items.append({
            **dict(row),
            "images": [i['filename'] for i in images],
            "posted_clean": row['posted_date'][:10] if row['posted_date'] else "N/A"
        })

    conn.close()

    return render_template(
        'dashboard/wishlist.html',
        wishlist_items=wishlist_items     # IMPORTANT!!
    )

@app.route('/wishlist_add')
@login_required
def wishlist_add():
    item_id = request.args.get('item_id', type=int)
    if not item_id:
        flash("Invalid item.", "danger")
        return redirect(url_for('marketplace'))

    user_id = session.get('user_id')
    conn = get_db_connection()
    # check if already exists
    exists = conn.execute("SELECT 1 FROM wishlist WHERE user_id=? AND item_id=?", (user_id, item_id)).fetchone()
    if not exists:
        conn.execute("INSERT INTO wishlist(user_id, item_id) VALUES (?, ?)", (user_id, item_id))
        conn.commit()
        flash("Item added to your wishlist!", "success")
    else:
        flash("Item already in your wishlist.", "info")
    conn.close()
    return redirect(request.referrer or url_for('marketplace'))

@app.route('/wishlist_remove')
@login_required
def wishlist_remove():
    item_id = request.args.get('item_id', type=int)
    if not item_id:
        flash("Invalid item.", "danger")
        return redirect(url_for('marketplace'))

    user_id = session.get('user_id')
    conn = get_db_connection()
    conn.execute("DELETE FROM wishlist WHERE user_id=? AND item_id=?", (user_id, item_id))
    conn.commit()
    conn.close()
    flash("Item removed from your wishlist.", "success")
    return redirect(request.referrer or url_for('marketplace'))

@app.route('/wishlist_toggle', methods=['POST'])
@login_required
def wishlist_toggle():
    user_id = session.get('user_id')
    item_id = request.form.get('item_id', type=int)

    conn = get_db_connection()
    exists = conn.execute(
        "SELECT 1 FROM wishlist WHERE user_id=? AND item_id=?",
        (user_id, item_id)
    ).fetchone()

    if exists:
        # remove
        conn.execute(
            "DELETE FROM wishlist WHERE user_id=? AND item_id=?",
            (user_id, item_id)
        )
        conn.commit()
        conn.close()
        return {"status": "removed"}
    else:
        # add
        conn.execute(
            "INSERT INTO wishlist (user_id, item_id) VALUES (?, ?)",
            (user_id, item_id)
        )
        conn.commit()
        conn.close()
        return {"status": "added"}


# Open Report Page
@app.route('/item/<int:item_id>/report')
@login_required
def report_page(item_id):
    conn = get_db_connection()
    item = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
    conn.close()

    if not item:
        flash("Item not found!", "danger")
        return redirect(url_for('home'))

    return render_template('dashboard/report_item.html', item=item)


# Submit Report
@app.route('/report_item', methods=['POST'])
@login_required
def report_item():
    item_id = request.form.get("item_id")
    reason = request.form.get("reason")

    conn = get_db_connection()
    conn.execute("""
        INSERT INTO item_reports (item_id, reporter_id, reason, created_at)
        VALUES (?, ?, ?, ?)
    """, (item_id, session['user_id'], reason, datetime.utcnow().isoformat()))

    conn.commit()
    conn.close()

    flash("Report submitted to admin!", "success")
    return redirect(url_for('marketplace'))


@app.route('/contact_seller')
@login_required
def contact_seller():
    # For now, this is a placeholder. You can later implement messages/inquiry table.
    return render_template('dashboard/my_inquiries.html')


def allowed_chat_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_IMAGE_EXT

def get_or_create_conversation(conn, user1, user2):
    a, b = min(user1, user2), max(user1, user2)
    row = conn.execute("SELECT * FROM conversations WHERE user_a=? AND user_b=?", (a,b)).fetchone()
    if row:
        return row['id']
    now = datetime.utcnow().isoformat()
    cur = conn.cursor()
    cur.execute("INSERT INTO conversations (user_a, user_b, created_at) VALUES (?, ?, ?)", (a,b,now))
    conn.commit()
    return cur.lastrowid

# Inbox UI
@app.route('/chats')
@login_required
def chats_inbox():
    uid = session['user_id']
    conn = get_db_connection()
    # find conversations where user is either side
    rows = conn.execute("""
        SELECT c.id,
               CASE WHEN c.user_a = ? THEN c.user_b ELSE c.user_a END as other_id,
               u.full_name as other_name,
               u.profile_picture,
               (SELECT body FROM messages m WHERE m.conversation_id = c.id ORDER BY m.created_at DESC LIMIT 1) as last_message,
               (SELECT created_at FROM messages m WHERE m.conversation_id = c.id ORDER BY m.created_at DESC LIMIT 1) as last_at,
               (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id AND m.is_read = 0 AND m.sender_id != ?) as unread_count
        FROM conversations c
        JOIN users u ON u.id = (CASE WHEN c.user_a = ? THEN c.user_b ELSE c.user_a END)
        WHERE c.user_a = ? OR c.user_b = ?
        ORDER BY last_at DESC
    """, (uid, uid, uid, uid, uid)).fetchall()

    # convert to list
    convs = [dict(r) for r in rows]
    conn.close()
    return render_template('chat/inbox.html', conversations=convs)

# Chat view UI
@app.route('/chat/<int:conversation_id>')
@login_required
def chat_view(conversation_id):
    uid = session['user_id']
    conn = get_db_connection()
    # verify user belongs to conversation
    conv = conn.execute("SELECT * FROM conversations WHERE id = ?", (conversation_id,)).fetchone()
    if not conv:
        conn.close()
        flash("Conversation not found", "danger")
        return redirect(url_for('chats_inbox'))
    if uid not in (conv['user_a'], conv['user_b']):
        conn.close()
        flash("Not allowed", "danger")
        return redirect(url_for('chats_inbox'))

    other_id = conv['user_b'] if conv['user_a'] == uid else conv['user_a']
    other = conn.execute("SELECT id, full_name, profile_picture FROM users WHERE id=?", (other_id,)).fetchone()

    # load recent messages (limit 100)
    msgs = conn.execute("""
        SELECT m.*, u.full_name as sender_name
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        WHERE m.conversation_id = ?
        ORDER BY m.created_at ASC
        LIMIT 200
    """, (conversation_id,)).fetchall()

    # attach images for each message
    messages = []
    for m in msgs:
        attachments = conn.execute("SELECT filename FROM chat_attachments WHERE message_id=?", (m['id'],)).fetchall()
        messages.append({**dict(m), "attachments":[a['filename'] for a in attachments]})

    # mark messages as read where sender != me
    conn.execute("UPDATE messages SET is_read=1 WHERE conversation_id=? AND sender_id<>? AND is_read=0", (conversation_id, uid))
    conn.commit()
    conn.close()

    return render_template('chat/chat_view.html', conversation_id=conversation_id, other=other, messages=messages)

# API: list chats (json) - optional for dynamic inbox
@app.route('/api/chats')
@login_required
def api_chats():
    uid = session['user_id']
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT c.id,
               CASE WHEN c.user_a = ? THEN c.user_b ELSE c.user_a END as other_id,
               u.full_name as other_name,
               (SELECT body FROM messages m WHERE m.conversation_id = c.id ORDER BY m.created_at DESC LIMIT 1) as last_message,
               (SELECT created_at FROM messages m WHERE m.conversation_id = c.id ORDER BY m.created_at DESC LIMIT 1) as last_at,
               (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id AND m.is_read = 0 AND m.sender_id != ?) as unread_count
        FROM conversations c
        JOIN users u ON u.id = (CASE WHEN c.user_a = ? THEN c.user_b ELSE c.user_a END)
        WHERE c.user_a = ? OR c.user_b = ?
        ORDER BY last_at DESC
    """, (uid, uid, uid, uid, uid)).fetchall()
    convs = [dict(r) for r in rows]
    conn.close()
    return jsonify(convs)

# API: get messages since timestamp (polling)
@app.route('/api/messages/<int:conversation_id>')
@login_required
def api_messages(conversation_id):
    since = request.args.get('since')  # ISO timestamp or empty
    uid = session['user_id']
    conn = get_db_connection()
    # permission check
    conv = conn.execute("SELECT * FROM conversations WHERE id=?", (conversation_id,)).fetchone()
    if not conv or uid not in (conv['user_a'], conv['user_b']):
        conn.close()
        return jsonify({"error":"not allowed"}), 403

    if since:
        rows = conn.execute("""
            SELECT m.*, u.full_name as sender_name
            FROM messages m JOIN users u ON u.id = m.sender_id
            WHERE m.conversation_id=? AND m.created_at > ?
            ORDER BY m.created_at ASC
        """, (conversation_id, since)).fetchall()
    else:
        rows = conn.execute("""
            SELECT m.*, u.full_name as sender_name
            FROM messages m JOIN users u ON u.id = m.sender_id
            WHERE m.conversation_id=?
            ORDER BY m.created_at ASC
            LIMIT 200
        """, (conversation_id,)).fetchall()

    messages = []
    for m in rows:
        attachments = conn.execute("SELECT filename FROM chat_attachments WHERE message_id=?", (m['id'],)).fetchall()
        messages.append({**dict(m), "attachments":[a['filename'] for a in attachments]})

    # Optionally mark incoming msgs as read if the current user is not the sender
    conn.execute("UPDATE messages SET is_read=1 WHERE conversation_id=? AND sender_id<>? AND is_read=0", (conversation_id, uid))
    conn.commit()
    conn.close()
    return jsonify(messages)

# API: send message (text + optional image)
@app.route('/api/send_message', methods=['POST'])
@login_required
def api_send_message():
    uid = session['user_id']
    conversation_id = int(request.form.get('conversation_id') or 0)
    body = request.form.get('body', '').strip()
    file = request.files.get('image')

    if not conversation_id:
        # maybe user passed other_user_id to start convo
        other = request.form.get('other_user_id', type=int)
        if not other:
            return jsonify({"error":"missing conversation or other_user_id"}), 400
        conn = get_db_connection()
        conversation_id = get_or_create_conversation(conn, uid, other)
        conn.close()

    conn = get_db_connection()
    # permission check
    conv = conn.execute("SELECT * FROM conversations WHERE id=?", (conversation_id,)).fetchone()
    if not conv or uid not in (conv['user_a'], conv['user_b']):
        conn.close()
        return jsonify({"error":"not allowed"}), 403

    now = datetime.utcnow().isoformat()
    cur = conn.cursor()
    cur.execute("INSERT INTO messages (conversation_id, sender_id, body, created_at, is_read) VALUES (?, ?, ?, ?, 0)",
                (conversation_id, uid, body, now))
    msg_id = cur.lastrowid

    # handle file
    if file and allowed_chat_file(file.filename):
        fname = secure_filename(f"{int(time.time()*1000)}_{file.filename}")
        save_path = os.path.join(CHAT_UPLOAD_FOLDER, fname)
        file.save(save_path)
        cur.execute("INSERT INTO chat_attachments (message_id, filename) VALUES (?, ?)", (msg_id, fname))

    conn.commit()
    conn.close()
    return jsonify({"status":"ok", "message_id": msg_id, "created_at": now})

# API: toggle typing (POST to set last typing timestamp)
@app.route('/api/typing', methods=['POST'])
@login_required
def api_typing():
    conversation_id = request.form.get('conversation_id', type=int)
    uid = session['user_id']
    if not conversation_id:
        return jsonify({"error":"missing conversation_id"}), 400
    conn = get_db_connection()
    now_ts = time.time()
    conn.execute("""
        INSERT INTO typing_status (conversation_id, user_id, last_typing_at)
        VALUES (?, ?, ?)
        ON CONFLICT(conversation_id, user_id) DO UPDATE SET last_typing_at=excluded.last_typing_at
    """, (conversation_id, uid, now_ts))
    conn.commit()
    conn.close()
    return jsonify({"status":"ok"})

# API: get typing status for a conversation (who typed recently)
@app.route('/api/typing_status/<int:conversation_id>')
@login_required
def api_typing_status(conversation_id):
    uid = session['user_id']
    conn = get_db_connection()
    rows = conn.execute("SELECT user_id, last_typing_at FROM typing_status WHERE conversation_id=?", (conversation_id,)).fetchall()
    others_typing = []
    now_ts = time.time()
    for r in rows:
        if r['user_id'] == uid: 
            continue
        if r['last_typing_at'] and (now_ts - float(r['last_typing_at']) < 6):  # show typing for 6s after last send
            others_typing.append(r['user_id'])
    conn.close()
    return jsonify({"typing_user_ids": others_typing})

# Serve uploaded chat images (optional)
@app.route('/uploads/chat/<path:filename>')
def chat_upload(filename):
    return send_from_directory(CHAT_UPLOAD_FOLDER, filename)

@app.route('/start_chat')
@login_required
def start_chat():
    other_user_id = request.args.get('other_user_id', type=int)
    if not other_user_id:
        flash("Invalid user", "danger")
        return redirect(url_for('chats_inbox'))

    uid = session['user_id']
    conn = get_db_connection()
    conv_id = get_or_create_conversation(conn, uid, other_user_id)
    conn.close()
    
    # redirect directly to the chat view
    return redirect(url_for('chat_view', conversation_id=conv_id))


from datetime import datetime, timedelta
import random
import string

# -----------------------------
# ADMIN LOGIN (EMAIL INPUT PAGE)
# -----------------------------

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email'].strip()

        conn = get_db_connection()
        admin = conn.execute(
            "SELECT * FROM users WHERE email = ? AND is_admin = 1",
            (email,)
        ).fetchone()

        if not admin:
            flash("Admin account not found!", "danger")
            conn.close()
            return redirect(url_for('admin_login'))

        # Generate OTP
        otp = ''.join(random.choices(string.digits, k=6))
        expires = datetime.utcnow() + timedelta(minutes=5)

        conn.execute(
            "UPDATE users SET otp_code = ?, otp_expires_at = ? WHERE id = ?",
            (otp, expires.isoformat(), admin['id'])
        )
        conn.commit()
        conn.close()

        # Store email
        session['admin_email'] = email

        # 🔥 Pass OTP directly via session for simulation
        session['simulated_admin_otp'] = otp

        return redirect(url_for('admin_verify_otp'))

    return render_template("admin/admin_login.html")


@app.route('/admin/verify-otp', methods=['GET', 'POST'])
def admin_verify_otp():
    if 'admin_email' not in session:
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        entered_otp = request.form['otp']

        conn = get_db_connection()
        admin = conn.execute(
            "SELECT * FROM users WHERE email = ?", 
            (session['admin_email'],)
        ).fetchone()

        if not admin:
            flash("Invalid session!", "danger")
            conn.close()
            return redirect(url_for('admin_login'))

        # Check OTP & expiry
        db_otp = admin['otp_code']
        exp = admin['otp_expires_at']

        if not db_otp or not exp:
            flash("OTP not generated!", "danger")
            conn.close()
            return redirect(url_for('admin_login'))

        if datetime.utcnow() > datetime.fromisoformat(exp):
            flash("OTP expired! Try again.", "warning")
            conn.close()
            return redirect(url_for('admin_login'))

        if entered_otp != db_otp:
            flash("Incorrect OTP!", "danger")
            conn.close()
            return redirect(url_for('admin_verify_otp'))

        # OTP correct → login
        session['admin_id'] = admin['id']
        session['user_id'] = admin['id']
        session['is_admin'] = True
        # Clear OTP
        conn.execute(
            "UPDATE users SET otp_code=NULL, otp_expires_at=NULL WHERE id=?",
            (admin['id'],)
        )
        conn.commit()
        conn.close()

        flash("Admin login successful!", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template("admin/admin_verify_otp.html")


@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))

    return render_template('admin/admin_dashboard.html')

# Admin: List Users
@app.route('/admin/users')
def admin_users():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))

    current_admin_id = session['user_id']

    conn = get_db_connection()
    users = conn.execute('''
        SELECT id, full_name, email, employee_id, is_admin, created_at, department 
        FROM users 
        WHERE id != ?
        ORDER BY created_at DESC
    ''', (current_admin_id,)).fetchall()
    conn.close()

    return render_template('admin/users.html', users=users)


# Admin: Add User (GET + POST)
@app.route('/admin/users/add', methods=['GET','POST'])
def admin_add_user():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        employee_id = request.form['employee_id']
        password = request.form['password']
        is_admin = 1 if request.form.get('is_admin') == 'on' else 0

        pw_hash = generate_password_hash(password)

        conn = get_db_connection()
        conn.execute('INSERT INTO users (full_name,email,employee_id,password_hash,is_admin,created_at) VALUES (?,?,?,?,?,?)',
                     (full_name,email,employee_id,pw_hash,is_admin,datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()

        flash('User added successfully', 'success')
        return redirect(url_for('admin_users'))

    return render_template('admin/add_user.html')

# Admin: Edit User (GET + POST)
@app.route('/admin/users/edit/<int:user_id>', methods=['GET','POST'])
def admin_edit_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()

    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin_users'))

    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        employee_id = request.form['employee_id']
        is_admin = 1 if request.form.get('is_admin') == 'on' else 0

        conn.execute('UPDATE users SET full_name=?, email=?, employee_id=?, is_admin=? WHERE id=?',
                     (full_name,email,employee_id,is_admin,user_id))
        conn.commit()
        conn.close()
        flash('User updated successfully', 'success')
        return redirect(url_for('admin_users'))

    conn.close()
    return render_template('admin/edit_user.html', user=user)

# Admin: Delete User
@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id=?', (user_id,))
    conn.commit()
    conn.close()
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin_users'))


# Admin: Manage Items
@app.route('/admin/items')
def admin_items():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))

    search = request.args.get("search", "").strip()
    category = request.args.get("category", "").strip()
    selected_status = request.args.get("status", "").strip()

    conn = get_db_connection()

    # Fetch items + owner details
    query = """
        SELECT items.*, users.full_name AS owner_name, users.email AS owner_email
        FROM items
        JOIN users ON items.owner_id = users.id
        WHERE 1 = 1
    """
    params = []

    # Search filter
    if search:
        query += """
            AND (
                items.title LIKE ? OR
                items.description LIKE ? OR
                users.full_name LIKE ? OR
                users.email LIKE ?
            )
        """
        params += [f"%{search}%", f"%{search}%", f"%{search}%", f"%{search}%"]

    # Category filter
    if category:
        query += " AND items.category = ?"
        params.append(category)

    query += " ORDER BY items.created_at DESC"

    items = conn.execute(query, params).fetchall()

    # -----------------------------
    # LOAD ALL IMAGES FOR EACH ITEM
    # -----------------------------
    all_images = conn.execute("""
        SELECT item_id, filename
        FROM item_images
        ORDER BY id ASC
    """).fetchall()

    img_map = {}
    for img in all_images:
        img_map.setdefault(img["item_id"], []).append(img["filename"])

    # -----------------------------
    # COMPUTE STATUS + ATTACH IMAGES
    # -----------------------------
    updated_items = []
    now = datetime.utcnow()

    for i in items:
        posted = datetime.fromisoformat(i['created_at'])
        expires = datetime.fromisoformat(i['expires_at'])

        # Compute status
        if posted > now:
            computed_status = "scheduled"
        elif expires < now:
            computed_status = "expired"
        else:
            computed_status = "active"

        row = dict(i)
        row['computed_status'] = computed_status

        # Attach all images
        row['images'] = img_map.get(i['id'], [])

        # Always include thumbnail as fallback
        if not row['images']:
            row['images'] = [row['thumbnail']]

        updated_items.append(row)

    # Status filter AFTER computing status
    if selected_status:
        updated_items = [i for i in updated_items if i['computed_status'] == selected_status]

    categories = conn.execute("SELECT DISTINCT category FROM items").fetchall()
    conn.close()

    return render_template(
        'admin/items.html',
        items=updated_items,
        categories=categories,
        search=search,
        selected_category=category,
        selected_status=selected_status
    )


# Admin Delete Item
@app.route('/admin/items/<int:item_id>/delete', methods=['POST'])
def admin_delete_item(item_id):
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    conn.execute("DELETE FROM item_images WHERE item_id = ?", (item_id,))
    conn.execute("DELETE FROM items WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()

    flash("Item deleted successfully!", "success")
    return redirect(url_for('admin_items'))

@app.route('/admin/reports')
def admin_reports():
    if not session.get('is_admin'):
        return redirect(url_for("admin_login"))

    conn = get_db_connection()

    reports = conn.execute("""
        SELECT r.*, 
               u.full_name AS reporter_name,
               u.email AS reporter_email,
               i.title AS item_title
        FROM item_reports r
        JOIN users u ON r.reporter_id = u.id
        JOIN items i ON r.item_id = i.id
        ORDER BY r.created_at DESC
    """).fetchall()

    conn.close()

    return render_template("admin/reports.html", reports=reports)



if __name__ == '__main__':
    app.run(debug=True)
