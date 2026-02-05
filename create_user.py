from app import SessionLocal, engine, Base, User, set_password

def main():
    Base.metadata.create_all(bind=engine)

    username = input("Enter username: ")
    password = input("Enter password: ")

    with SessionLocal() as db:
        existing_user = db.query(User).filter_by(username=username).first()
        if existing_user:
            print(f" User '{username}' already exists!")
            return

        new_user = User(username=username, password=set_password(password))
        db.add(new_user)
        db.commit()
        print(f"✓ User '{username}' created successfully!")
        print(f"You can now login with username: {username}")

if __name__ == "__main__":
    main()
