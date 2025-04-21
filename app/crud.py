from sqlalchemy.orm import Session
from .models import UserDetail, UserRole
from datetime import datetime
from app.utils import hash_password, verify_password, normalize_email
from fastapi import HTTPException
import datetime


# Fetch user by email (email is case-insensitive)
def get_user_by_email(db: Session, email: str):
    return db.query(UserDetail).filter(UserDetail.email == email.lower()).first()


def get_user_by_username(db: Session, username: str):
    return db.query(UserDetail).filter(UserDetail.username == username).first()


# Create a new user with lowercase email

def create_user(db: Session, username: str, email: str, password: str):
    # Hash the password before storing it
    hashed_password = hash_password(password)
    # Insert user data into the database
    user = UserDetail(
        username=username,
        email=email,
        password=hashed_password  # Store the hashed password
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def update_user_password(db: Session, user, new_hashed_password: str):
    user.password = new_hashed_password
    db.commit()
    db.refresh(user)


def get_user_by_id(db: Session, user_id: int):
    return db.query(UserDetail).filter(UserDetail.id == user_id).first()


def update_user_details(db: Session, user_id: int, updates: dict):
    user = get_user_by_id(db, user_id)
    if not user:
        return None
    for key, value in updates.items():
        setattr(user, key, value)
    user.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(user)
    return user
