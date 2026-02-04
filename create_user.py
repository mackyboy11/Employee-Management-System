from app import app, db, User, set_password

with app.app_context():
    # Create tables first if they don't exist
    db.create_all()
    
    # Check if user already exists
    username = input("Enter username: ")
    password = input("Enter password: ")
    
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        print(f"❌ User '{username}' already exists!")
    else:
        # Create new user
        new_user = User(username=username, password=set_password(password))
        db.session.add(new_user)
        db.session.commit()
        print(f"✓ User '{username}' created successfully!")
        print(f"You can now login with username: {username}")
