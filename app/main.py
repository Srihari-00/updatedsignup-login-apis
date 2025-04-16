from fastapi import FastAPI, Depends
from . import auth
from .database import engine
from .models import Base
from app import schemas
from app.schemas import SignupRequest, LoginRequest, ChangePasswordRequest, VerifyOtpSignupRequest
from .auth import get_db
from sqlalchemy.orm import Session
from . import crud, utils
app = FastAPI()
Base.metadata.create_all(bind=engine)


# signup route
# This endpoint allows users to sign up by providing their username, email, and password.
@app.post("/signup")
def signup(request: SignupRequest, db: Session = Depends(get_db)):
    return auth.signup_user(request, db)

# Verify signup OTP
# This endpoint verifies the OTP sent to the user's email during signup.


@app.post("/verify-signup-otp")
def verify_signup_otp(request: VerifyOtpSignupRequest, db: Session = Depends(get_db)):
    return auth.verify_signup_otp(request, db)

# Resend Signup OTP
# This endpoint allows users to request a new OTP for signup verification.


@app.post("/resend-signup-otp")
def resend_signup_otp(email: str, db: Session = Depends(get_db)):
    return auth.resend_signup_otp(email, db)
# Login route

# This endpoint allows users to log in by providing their email and password.
# If the credentials are valid, it sends an OTP to the user's email for verification.
# It requires the user to provide their email and password.
# The OTP is used to verify the user's identity before granting access to the system.


@app.post("/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    return auth.login_user(request, db)


# Verify Login OTP endpoint
# This endpoint verifies the OTP sent to the user's email during login.
# If the OTP is valid, it returns a success response.
# It requires the user to provide their email and OTP.
@app.post("/verify-login-otp")
def verify_login_otp(request: schemas.VerifyLoginOtpRequest, db: Session = Depends(get_db)):
    # Now `request` will automatically contain the email and otp fields
    return auth.verify_login_otp(request, db)


# change Password
# This endpoint allows users to change their password after verifying their old password.
# It requires the user to provide their user ID, username, email, old password, new password, and confirm password.
@app.post("/change-password")
def change_password(request: ChangePasswordRequest, db: Session = Depends(get_db)):
    return auth.change_password(request, db)

# Forgot Password
# This endpoint is used to initiate the password reset process by sending a reset OTP to the user's email.


@app.post("/forgot-password")
def reset_password(request: schemas.ResetPasswordRequest, db: Session = Depends(get_db)):
    return auth.reset_password(request, db)

# Verify Reset Password OTP
# This endpoint verifies the OTP sent to the user's email for resetting the password.
# If the OTP is valid, it allows the user to set a new password.


@app.post("/verify-reset-password-otp")
def verify_reset_password_otp(request: schemas.VerifyResetPasswordOTPRequest, db: Session = Depends(get_db)):
    return auth.verify_reset_password_otp(request, db)
