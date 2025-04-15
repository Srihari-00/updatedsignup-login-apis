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
@app.post("/signup")
def signup(request: SignupRequest, db: Session = Depends(get_db)):
    return auth.signup_user(request, db)

# Verify signup OTP


@app.post("/verify-signup-otp")
def verify_signup_otp(request: VerifyOtpSignupRequest, db: Session = Depends(get_db)):
    return auth.verify_signup_otp(request, db)

# Resend Signup OTP


@app.post("/resend-signup-otp")
def resend_signup_otp(email: str, db: Session = Depends(get_db)):
    return auth.resend_signup_otp(email, db)
# Login route


@app.post("/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    return auth.login_user(request, db)


# Verify Login OTP endpoint
@app.post("/verify-login-otp")
def verify_login_otp(request: schemas.VerifyLoginOtpRequest, db: Session = Depends(get_db)):
    # Now `request` will automatically contain the email and otp fields
    return auth.verify_login_otp(request, db)


# change Password
@app.post("/change-password")
def change_password(request: ChangePasswordRequest, db: Session = Depends(get_db)):
    return auth.change_password(request, db)
