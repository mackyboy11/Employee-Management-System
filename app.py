from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import re
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///company.db')

# Security Settings
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False') == 'True'
app.config['SESSION_COOKIE_HTTPONLY'] = os.getenv('SESSION_COOKIE_HTTPONLY', 'True') == 'True'
app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# --- MODELS (Database Structure) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    position = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    salary = db.Column(db.Float, nullable=False)

# --- PASSWORD MODULE (Logic) ---
def set_password(password):
    return generate_password_hash(password)

def verify_password(stored_hash, password):
    return check_password_hash(stored_hash, password)

def validate_password_strength(password):
    """
    Validate password strength requirements:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is strong"

def sanitize_input(user_input):
    """Sanitize user input to prevent XSS attacks"""
    if not isinstance(user_input, str):
        return user_input
    # Remove potentially dangerous characters
    return secure_filename(user_input) if len(user_input) <= 100 else user_input[:100]

# --- ROUTES ---
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    employees = Employee.query.all()
    return render_template('employees.html', employees=employees)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        
        user = User.query.filter_by(username=username).first()
        if user and verify_password(user.password, password):
            session['user_id'] = user.id
            session.permanent = True
            flash('✓ Login successful!', 'success')
            return redirect(url_for('index'))
        flash('❌ Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate username
        if len(username) < 3:
            flash('Username must be at least 3 characters long', 'danger')
        elif not re.match(r'^[a-zA-Z0-9_]+$', username):
            flash('Username can only contain letters, numbers, and underscores', 'danger')
        else:
            # Check if user already exists
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('❌ Username already exists', 'danger')
            elif password != confirm_password:
                flash('❌ Passwords do not match', 'danger')
            else:
                # Validate password strength
                is_valid, message = validate_password_strength(password)
                if not is_valid:
                    flash(f'❌ {message}', 'danger')
                else:
                    new_user = User(username=username, password=set_password(password))
                    db.session.add(new_user)
                    db.session.commit()
                    flash('✓ Account created successfully! Please login.', 'success')
                    return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('✓ You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/add_employee', methods=['POST'])
def add_employee():
    new_emp = Employee(
        full_name=request.form['name'],
        position=request.form['position'],
        email=request.form['email'],
        salary=request.form['salary']
    )
    db.session.add(new_emp)
    db.session.commit()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Generates the DB structure
        # Create a default admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin_user = User(username='admin', password=set_password('password123'))
            db.session.add(admin_user)
            db.session.commit()
            print("✓ Default admin user created: username='admin', password='password123'")
    app.run(debug=True)