# app/utils.py

import os
import smtplib
import random
from email.message import EmailMessage
import time
import re
from passlib.context import CryptContext
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.requests import Request
from typing import Dict, Tuple, Any


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Temporary in-memory store for OTPs
otp_store: Dict[str, Dict[str, Any]] = {}  # email: {otp: ..., expiry: ...}

# Password regex
PASSWORD_REGEX = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,15}$"


# ----------------- Email Utils ---------------------

def normalize_email(email: str) -> str:
    return email.strip().lower()


def is_valid_email(email: str) -> bool:
    return re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", email) is not None


def send_email_otp(email: str, otp: str):
    email = normalize_email(email)
    EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        raise EnvironmentError("Email credentials not configured properly.")

    msg = EmailMessage()
    msg.set_content(f"Your OTP for verification is: {otp}")
    msg["Subject"] = "Your OTP Verification Code - Testing RR"
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)


# ----------------- OTP Handling ---------------------

def generate_otp() -> str:
    return str(random.randint(100000, 999999))


def store_otp(email: str, otp: str, ttl_seconds: int = 300):
    email = normalize_email(email)
    hashed_otp = pwd_context.hash(otp)
    otp_store[email] = {
        "otp": hashed_otp,
        "expiry": time.time() + ttl_seconds
    }


def get_stored_otp(email):
    return otp_store.get(email)


def verify_otp(email: str, otp: str) -> bool:
    email = normalize_email(email)
    if email in otp_store:
        record = otp_store[email]
        if time.time() < record["expiry"] and pwd_context.verify(otp, record["otp"]):
            del otp_store[email]
            return True
    return False


# ----------------- Password Utils ---------------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def is_strong_password(password: str) -> bool:
    return bool(re.match(PASSWORD_REGEX, password))


def validate_password_rules(password: str) -> Tuple[bool, list]:
    """
    Validates password strength and returns a tuple:
    (is_valid: bool, errors: list of rule violations)
    """
    errors = []

    if len(password) < 8 or len(password) > 15:
        errors.append("Password must be 8-15 characters long.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r"\d", password):
        errors.append("Password must contain at least one digit.")
    if not re.search(r"[@$!%*?&]", password):
        errors.append(
            "Password must contain at least one special character (@$!%*?&).")

    return len(errors) == 0, errors


# ----------------- Response Utils ---------------------

def custom_response(response: str, response_code: int, response_message: str, data=None):
    return JSONResponse(
        status_code=response_code,
        content={
            "response": response,
            "response_code": response_code,
            "response_message": response_message,
            "data": data or {}
        }
    )


# ----------------- Email Validation ---------------------

def validate_email(email: str) -> Tuple[bool, str]:
    email = normalize_email(email)
    if '@' not in email or '.' not in email.split('@')[-1]:
        return False, "Invalid email format."

    if not is_valid_email(email):
        return False, "Email does not match the expected pattern."

    return True, ""


def handle_email_validation_error(error_detail: dict):
    error_location = error_detail.get("loc", [])
    error_message = error_detail.get("msg", "")
    input_value = error_detail.get("input", "")

    response_code = 422
    response_message = f"Error in {error_location[-1]}: {error_message}. Input: '{input_value}'"

    return custom_response(
        response="error",
        response_code=response_code,
        response_message=response_message,
        data={"error_detail": error_detail}
    )


# ----------------- Global Validation Handler ---------------------

async def validation_exception_handler(request: Request, exc: RequestValidationError):
    error = exc.errors()[0]  # Get first error detail
    location = error.get("loc", ["body"])
    message = error.get("msg", "")
    input_value = error.get("input", "")

    response_message = f"Error in {location[-1]}: {message}. Input: '{input_value}'"
    return custom_response(
        response="error",
        response_code=422,
        response_message=response_message,
        data={"error_detail": error}
    )
