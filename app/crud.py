from sqlalchemy.orm import Session
from . import models, utils
import datetime


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def create_user(db: Session, username: str, email: str, password: str):
    hashed_password = utils.get_password_hash(password)
    new_user = models.User(username=username, email=email,
                           password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


def create_otp(db: Session, email: str, otp: str, purpose: str):
    new_otp = models.OTP(email=email, otp=otp, purpose=purpose)
    db.add(new_otp)
    db.commit()


def verify_otp(db: Session, email: str, otp: str, purpose: str):
    stored_otp = db.query(models.OTP).filter_by(
        email=email, purpose=purpose).order_by(models.OTP.created_at.desc()).first()
    if stored_otp and stored_otp.otp == otp and (datetime.datetime.utcnow() - stored_otp.created_at).seconds < 600:
        return True
    return False


def change_user_password(db: Session, user_id: int, new_password: str):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user:
        user.password = utils.get_password_hash(new_password)
        db.commit()
        return True
    return False
