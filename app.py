from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///company.db'
db = SQLAlchemy(app)

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

# --- ROUTES ---
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    employees = Employee.query.all()
    return render_template('employees.html', employees=employees)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and verify_password(user.password, request.form['password']):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        flash('Invalid Credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists')
        elif password != confirm_password:
            flash('Passwords do not match')
        elif len(password) < 4:
            flash('Password must be at least 4 characters')
        else:
            new_user = User(username=username, password=set_password(password))
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Please login.')
            return redirect(url_for('login'))
    return render_template('register.html')

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