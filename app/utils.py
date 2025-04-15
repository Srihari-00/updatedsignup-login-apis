import re
from passlib.context import CryptContext
import random
import smtplib
from email.message import EmailMessage
import os
from typing import Dict
import time

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Temporary in-memory store for OTPs
otp_store: Dict[str, Dict[str, any]] = {}  # email: {otp: ..., expiry: ...}

# ----------------- PASSWORD ---------------------


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def is_strong_password(password: str) -> bool:
    if len(password) < 8 or len(password) > 15:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

# ----------------- EMAIL ---------------------


def normalize_email(email: str) -> str:
    return email.strip().lower()


def is_valid_email(email: str) -> bool:
    return re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", email) is not None


def send_email_otp(email: str, otp: str):
    email = normalize_email(email)
    EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

    msg = EmailMessage()
    msg.set_content(f"Your OTP for verification is: {otp}")
    msg["Subject"] = "Your OTP Verification Code - Testing RR"
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)

# ----------------- OTP ---------------------


def generate_otp():
    return str(random.randint(100000, 999999))


def store_otp(email: str, otp: str, ttl_seconds: int = 300):
    email = normalize_email(email)
    otp_store[email] = {
        "otp": otp,
        "expiry": time.time() + ttl_seconds
    }


def verify_otp(email: str, otp: str):
    email = normalize_email(email)
    if email in otp_store:
        record = otp_store[email]
        if time.time() < record["expiry"] and record["otp"] == otp:
            del otp_store[email]
            return True
    return False

# ----------------- RESPONSE ---------------------


def custom_response(response: str, response_code: int, response_message: str, data: dict = {}):
    return {
        "response": response,
        "response_code": response_code,
        "response_message": response_message,
        "data": data
    }
