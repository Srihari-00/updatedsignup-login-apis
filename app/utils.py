# app/utils.py

import re
from passlib.context import CryptContext
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.requests import Request

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def is_strong_password(password: str) -> bool:
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,15}$"
    return bool(re.match(pattern, password))


def validate_password_rules(password: str):
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


def custom_response(response: str, response_code: int, response_message: str, data=None):
    return JSONResponse(
        status_code=response_code,
        content={
            "response": response,
            "response_code": response_code,
            "response_message": response_message,
            "data": data if data else {}
        }
    )


def validate_email(email: str):
    """Validates an email string format and returns a tuple of (is_valid: bool, message: str)"""
    try:
        if '@' not in email:
            return False, "An email address must have an @-sign."

        local_part, domain_part = email.split('@', 1)
        if not domain_part or '.' not in domain_part:
            return False, "An email address must have a valid domain."

        if not re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", email):
            return False, "Invalid email format."

        return True, ""
    except Exception as e:
        return False, f"Email validation error: {str(e)}"


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


# ✅ Add this for globally handling all validation errors
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
