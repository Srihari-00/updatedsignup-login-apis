from fastapi import Depends
from sqlalchemy.orm import Session
from . import schemas, crud, utils
from .database import SessionLocal


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def signup_user(request: schemas.SignupRequest, db: Session):
    email = request.email.lower()

    is_valid_email, email_error = utils.validate_email(email)
    if not is_valid_email:
        return utils.custom_response("error", 422, email_error)

    if crud.get_user_by_email(db, email):
        return utils.custom_response("error", 409, "Email already registered. Please login.")

    is_valid_pw, password_errors = utils.validate_password_rules(
        request.password)
    if not is_valid_pw:
        return utils.custom_response(
            "error",
            400,
            "Password validation failed. See 'data' for more info.",
            {"password_errors": password_errors}
        )

    hashed_pw = utils.hash_password(request.password)
    user = crud.create_user(db, request.username, email, hashed_pw)

    return utils.custom_response(
        "success", 200, "User successfully registered",
        {
            "user_id": user.id,
            "username": user.username,
            "user_email": user.email
        }
    )


def login_user(request: schemas.LoginRequest, db: Session):
    email = request.email.lower()
    user = crud.get_user_by_email(db, email)

    if not user:
        return utils.custom_response("error", 404, "Email not registered. Please signup.")

    if not utils.verify_password(request.password, user.password):
        return utils.custom_response("error", 401, "Invalid password. Please try again.")

    return utils.custom_response(
        "success", 200, "Successfully logged in",
        {
            "user_id": user.id,
            "username": user.username,
            "user_email": user.email
        }
    )


def change_password(request: schemas.ChangePasswordRequest, db: Session):
    email = request.email.lower()
    user = crud.get_user_by_email(db, email)

    if not user:
        return utils.custom_response(
            "error",
            404,
            "Email not found. Please check if the email is correct and registered.",
            data={"field": "email", "error": "User with this email does not exist."}
        )

    # User identity mismatch
    if user.id != request.user_id or user.username != request.username:
        return utils.custom_response(
            "error",
            403,
            "User identity (username) mismatch. Please check your user details.",
            data={"field": "user_identity",
                  "error": "User identity does not match."}
        )

    # Incorrect old password
    if not utils.verify_password(request.old_password, user.password):
        return utils.custom_response(
            "error",
            401,
            "Incorrect old password. Please try again.",
            data={"field": "old_password",
                  "error": "The old password you entered is incorrect."}
        )

    # New password and confirm password mismatch
    if request.new_password != request.confirm_password:
        return utils.custom_response(
            "error",
            400,
            "New password and confirm password do not match. Please ensure they are identical.",
            data={"field": "confirm_password",
                  "error": "Passwords do not match."}
        )

    # Validate new password strength
    is_valid_pw, password_errors = utils.validate_password_rules(
        request.new_password)
    if not is_valid_pw:
        return utils.custom_response(
            "error",
            400,
            "New password validation failed. See 'data' for more information.",
            {"password_errors": password_errors}
        )

    # Update password
    user.password = utils.hash_password(request.new_password)
    db.commit()

    return utils.custom_response(
        "success", 200, "Password changed successfully.",
        {
            "user_id": user.id,
            "username": user.username,
            "user_email": user.email
        }
    )
