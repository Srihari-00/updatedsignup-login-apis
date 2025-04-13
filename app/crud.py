# app/crud.py

from sqlalchemy.orm import Session
from .models import User


# ✅ Fetch user by email (email is case-insensitive)
def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email.lower()).first()


# ✅ Create a new user with lowercase email
def create_user(db: Session, username: str, email: str, hashed_password: str):
    user = User(
        username=username,
        email=email.lower(),
        password=hashed_password
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
