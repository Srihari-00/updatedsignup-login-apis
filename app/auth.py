from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from .database import SessionLocal
from . import schemas, models, utils, crud

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ------------------ SIGNUP ------------------


@router.post("/signup", response_model=schemas.StandardResponse)
def signup_user(request: schemas.SignupRequest, db: Session = Depends(get_db)):
    normalized_email = utils.normalize_email(request.email)

    if not utils.is_valid_email(normalized_email):
        return utils.custom_response("error", 400, "Invalid email format. Please enter a valid email like example@domain.com")

    if not utils.is_strong_password(request.password):
        return utils.custom_response("error", 400, "Password must be 8–15 characters, with upper/lowercase and special characters")

    if crud.get_user_by_email(db, normalized_email):
        return utils.custom_response("error", 400, "Email already registered")

    otp = utils.generate_otp()
    utils.store_otp(normalized_email, otp)
    utils.send_email_otp(normalized_email, otp)

    return utils.custom_response("OTP sent", 200, "OTP sent to email for verification")


@router.post("/verify-otp-signup", response_model=schemas.StandardResponse)
def verify_signup_otp(request: schemas.VerifyOtpSignupRequest, db: Session = Depends(get_db)):
    normalized_email = utils.normalize_email(request.email)

    if utils.verify_otp(normalized_email, request.otp):
        user = crud.create_user(db, request.username,
                                normalized_email, request.password)
        return utils.custom_response("Signup successful", 200, "User created successfully", {
            "user_id": user.id,
            "username": user.username,
            "user_email": user.email
        })

    return utils.custom_response("error", 400, "Invalid or expired OTP")

# ------------------ LOGIN ------------------


@router.post("/login", response_model=schemas.StandardResponse)
def login_user(request: schemas.LoginRequest, db: Session = Depends(get_db)):
    normalized_email = utils.normalize_email(request.email)

    if not utils.is_valid_email(normalized_email):
        return utils.custom_response("error", 400, "Invalid email format")

    user = crud.get_user_by_email(db, normalized_email)
    if not user:
        return utils.custom_response("error", 400, "Email not registered")

    if not utils.verify_password(request.password, user.password):
        return utils.custom_response("error", 400, "Incorrect password")

    otp = utils.generate_otp()
    utils.store_otp(normalized_email, otp)
    utils.send_email_otp(normalized_email, otp)

    return utils.custom_response("OTP sent", 200, "OTP sent to email for verification", {
        "user_id": user.id,
        "username": user.username,
        "user_email": user.email
    })


@router.post("/verify-login-otp", response_model=schemas.StandardResponse)
def verify_login_otp(request: schemas.VerifyLoginOtpRequest, db: Session = Depends(get_db)):
    if utils.verify_otp(request.email, request.otp):
        user = crud.get_user_by_email(db, request.email)
        if user:
            return utils.custom_response(
                response="success",
                response_code=200,
                response_message="Successfully logged into the account",
                data={
                    "user_id": user.id,
                    "username": user.username,
                    "user_email": user.email
                }
            )
        return utils.custom_response(
            response="error",
            response_code=404,
            response_message="User not found after OTP verification",
            data={}
        )

    return utils.custom_response(
        response="error",
        response_code=400,
        response_message="Invalid or expired OTP",
        data={}
    )

# ------------------ CHANGE PASSWORD ------------------


@router.post("/change-password", response_model=schemas.StandardResponse)
def change_password(request: schemas.ChangePasswordRequest, db: Session = Depends(get_db)):
    normalized_email = utils.normalize_email(request.email)
    user = crud.get_user_by_email(db, normalized_email)

    if not user or user.id != request.user_id or user.username != request.username:
        return utils.custom_response("error", 400, "User not found")

    if not utils.verify_password(request.old_password, user.password):
        return utils.custom_response("error", 400, "Old password is incorrect")

    if request.new_password != request.confirm_password:
        return utils.custom_response("error", 400, "New passwords do not match")

    if not utils.is_strong_password(request.new_password):
        return utils.custom_response("error", 400, "New password does not meet security requirements")

    crud.change_user_password(db, request.user_id, request.new_password)

    return utils.custom_response("Password changed", 200, "Password updated successfully", {
        "user_id": user.id,
        "username": user.username,
        "user_email": user.email
    })
