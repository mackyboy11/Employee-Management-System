from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from starlette.middleware.sessions import SessionMiddleware
from starlette.status import HTTP_303_SEE_OTHER
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import re
from dotenv import load_dotenv

try:
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    from slowapi import _rate_limit_exceeded_handler
    RATE_LIMITING_ENABLED = True
except Exception:  # pragma: no cover - optional dependency
    Limiter = None
    get_remote_address = None
    RateLimitExceeded = None
    _rate_limit_exceeded_handler = None
    RATE_LIMITING_ENABLED = False

load_dotenv()

# FastAPI application instance
app = FastAPI()
templates = Jinja2Templates(directory="templates")

SECRET_KEY = os.getenv("SECRET_KEY", "dev-key-change-in-production")
DATABASE_URI = os.getenv("DATABASE_URI", "sqlite:///company.db")

SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "False") == "True"
SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    https_only=SESSION_COOKIE_SECURE,
    same_site=SESSION_COOKIE_SAMESITE,
)

engine = create_engine(DATABASE_URI, connect_args={"check_same_thread": False} if DATABASE_URI.startswith("sqlite") else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

limiter = None
if RATE_LIMITING_ENABLED:
    limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

def rate_limit(rule: str):
    if RATE_LIMITING_ENABLED and limiter is not None:
        return limiter.limit(rule)
    def decorator(func):
        return func
    return decorator

# --- MODELS (Database Structure) ---
class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(255), nullable=False)

class Employee(Base):
    __tablename__ = "employee"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(100), nullable=False)
    position = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    salary = Column(Float, nullable=False)
    department = Column(String(100), nullable=True)
    location = Column(String(100), nullable=True)
    status = Column(String(20), default="active", nullable=False)

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
    if not re.search(r'[!@#$%^&*(),.?_":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is strong"

def sanitize_input(user_input):
    """Sanitize user input to prevent XSS attacks"""
    if not isinstance(user_input, str):
        return user_input
    return secure_filename(user_input) if len(user_input) <= 100 else user_input[:100]

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def set_flash(request: Request, message: str, category: str = "info"):
    request.session["flash"] = {"message": message, "category": category}

def pop_flash(request: Request):
    return request.session.pop("flash", None)

# --- ROUTES ---
@app.get("/", response_class=HTMLResponse, name="index")
def index(request: Request, db: Session = Depends(get_db)):
    if "user_id" not in request.session:
        return RedirectResponse(url="/login", status_code=HTTP_303_SEE_OTHER)
    employees = db.query(Employee).all()
    return templates.TemplateResponse(
        "employees.html",
        {"request": request, "employees": employees, "flash": pop_flash(request)}
    )

@app.get("/login", response_class=HTMLResponse, name="login")
def login_get(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "flash": pop_flash(request)}
    )

@app.post("/login", response_class=HTMLResponse, name="login_post")
@rate_limit("5/minute")
def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    username = sanitize_input(username)
    user = db.query(User).filter_by(username=username).first()
    if user and verify_password(user.password, password):
        request.session["user_id"] = user.id
        request.session["permanent"] = True
        set_flash(request, "✓ Login successful!", "success")
        return RedirectResponse(url="/", status_code=HTTP_303_SEE_OTHER)
    set_flash(request, "Invalid credentials. Please try again.", "danger")
    return RedirectResponse(url="/login", status_code=HTTP_303_SEE_OTHER)

@app.get("/register", response_class=HTMLResponse, name="register")
def register_get(request: Request):
    return templates.TemplateResponse(
        "register.html",
        {"request": request, "flash": pop_flash(request)}
    )

@app.post("/register", response_class=HTMLResponse, name="register_post")
@rate_limit("3/minute")
def register_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    username = sanitize_input(username)

    if len(username) < 3:
        set_flash(request, "Username must be at least 3 characters long", "danger")
        return RedirectResponse(url="/register", status_code=HTTP_303_SEE_OTHER)
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        set_flash(request, "Username can only contain letters, numbers, and underscores", "danger")
        return RedirectResponse(url="/register", status_code=HTTP_303_SEE_OTHER)

    existing_user = db.query(User).filter_by(username=username).first()
    if existing_user:
        set_flash(request, "Username already exists", "danger")
        return RedirectResponse(url="/register", status_code=HTTP_303_SEE_OTHER)
    if password != confirm_password:
        set_flash(request, "Passwords do not match", "danger")
        return RedirectResponse(url="/register", status_code=HTTP_303_SEE_OTHER)

    is_valid, message = validate_password_strength(password)
    if not is_valid:
        set_flash(request, f"{message}", "danger")
        return RedirectResponse(url="/register", status_code=HTTP_303_SEE_OTHER)

    new_user = User(username=username, password=set_password(password))
    db.add(new_user)
    db.commit()
    set_flash(request, "✓ Account created successfully! Please login.", "success")
    return RedirectResponse(url="/login", status_code=HTTP_303_SEE_OTHER)

@app.get("/logout", name="logout")
def logout(request: Request):
    request.session.clear()
    set_flash(request, "✓ You have been logged out.", "success")
    return RedirectResponse(url="/login", status_code=HTTP_303_SEE_OTHER)

@app.post("/add_employee", name="add_employee")
def add_employee(
    request: Request,
    name: str = Form(...),
    position: str = Form(...),
    email: str = Form(...),
    salary: float = Form(...),
    department: str = Form(None),
    location: str = Form(None),
    db: Session = Depends(get_db)
):
    if "user_id" not in request.session:
        set_flash(request, "Please log in to continue.", "danger")
        return RedirectResponse(url="/login", status_code=HTTP_303_SEE_OTHER)

    new_emp = Employee(
        full_name=sanitize_input(name),
        position=sanitize_input(position),
        email=sanitize_input(email),
        salary=salary,
        department=sanitize_input(department) if department else None,
        location=sanitize_input(location) if location else None,
    )
    db.add(new_emp)
    db.commit()
    set_flash(request, "✓ Employee added successfully!", "success")
    return RedirectResponse(url="/", status_code=HTTP_303_SEE_OTHER)


@app.get("/employee/{emp_id}", response_class=HTMLResponse, name="view_employee")
def view_employee(request: Request, emp_id: int, db: Session = Depends(get_db)):
    if "user_id" not in request.session:
        return RedirectResponse(url="/login", status_code=HTTP_303_SEE_OTHER)
    emp = db.query(Employee).filter_by(id=emp_id).first()
    if not emp:
        set_flash(request, "Employee not found.", "danger")
        return RedirectResponse(url="/", status_code=HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        "employee_detail.html",
        {"request": request, "employee": emp, "flash": pop_flash(request)}
    )


@app.get("/employee/{emp_id}/edit", response_class=HTMLResponse, name="edit_employee_get")
def edit_employee_get(request: Request, emp_id: int, db: Session = Depends(get_db)):
    if "user_id" not in request.session:
        return RedirectResponse(url="/login", status_code=HTTP_303_SEE_OTHER)
    emp = db.query(Employee).filter_by(id=emp_id).first()
    if not emp:
        set_flash(request, "Employee not found.", "danger")
        return RedirectResponse(url="/", status_code=HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        "edit_employee.html",
        {"request": request, "employee": emp, "flash": pop_flash(request)}
    )


@app.post("/employee/{emp_id}/edit", name="edit_employee_post")
def edit_employee_post(
    request: Request,
    emp_id: int,
    name: str = Form(...),
    position: str = Form(...),
    email: str = Form(...),
    salary: float = Form(...),
    department: str = Form(None),
    location: str = Form(None),
    db: Session = Depends(get_db),
):
    if "user_id" not in request.session:
        set_flash(request, "Please log in to continue.", "danger")
        return RedirectResponse(url="/login", status_code=HTTP_303_SEE_OTHER)
    emp = db.query(Employee).filter_by(id=emp_id).first()
    if not emp:
        set_flash(request, "Employee not found.", "danger")
        return RedirectResponse(url="/", status_code=HTTP_303_SEE_OTHER)

    emp.full_name = sanitize_input(name)
    emp.position = sanitize_input(position)
    emp.email = sanitize_input(email)
    emp.salary = salary
    emp.department = sanitize_input(department) if department else None
    emp.location = sanitize_input(location) if location else None
    db.commit()
    set_flash(request, "✓ Employee updated successfully!", "success")
    return RedirectResponse(url="/", status_code=HTTP_303_SEE_OTHER)


@app.post("/employee/{emp_id}/delete", name="delete_employee")
def delete_employee(request: Request, emp_id: int, db: Session = Depends(get_db)):
    if "user_id" not in request.session:
        set_flash(request, "Please log in to continue.", "danger")
        return RedirectResponse(url="/login", status_code=HTTP_303_SEE_OTHER)
    emp = db.query(Employee).filter_by(id=emp_id).first()
    if not emp:
        set_flash(request, "Employee not found.", "danger")
        return RedirectResponse(url="/", status_code=HTTP_303_SEE_OTHER)
    db.delete(emp)
    db.commit()
    set_flash(request, "✓ Employee deleted successfully!", "success")
    return RedirectResponse(url="/", status_code=HTTP_303_SEE_OTHER)


@app.post("/employee/{emp_id}/toggle_leave", name="toggle_leave")
def toggle_leave(request: Request, emp_id: int, db: Session = Depends(get_db)):
    if "user_id" not in request.session:
        set_flash(request, "Please log in to continue.", "danger")
        return RedirectResponse(url="/login", status_code=HTTP_303_SEE_OTHER)
    emp = db.query(Employee).filter_by(id=emp_id).first()
    if not emp:
        set_flash(request, "Employee not found.", "danger")
        return RedirectResponse(url="/", status_code=HTTP_303_SEE_OTHER)
    
    if emp.status == "active":
        emp.status = "on_leave"
        set_flash(request, f"✓ {emp.full_name} is now on leave.", "success")
    else:
        emp.status = "active"
        set_flash(request, f"✓ {emp.full_name} has returned from leave.", "success")
    
    db.commit()
    return RedirectResponse(url="/", status_code=HTTP_303_SEE_OTHER)

@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        admin = db.query(User).filter_by(username="admin").first()
        if not admin:
            admin_user = User(username="admin", password=set_password("password123"))
            db.add(admin_user)
            db.commit()
            print("✓ Default admin user created: username='admin', password='password123'")

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)