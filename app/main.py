from fastapi import FastAPI, Depends
from . import auth
from .database import engine
from .models import Base
from .schemas import SignupRequest, LoginRequest, ChangePasswordRequest, VerifyOtpSignupRequest
from .auth import get_db
from sqlalchemy.orm import Session

app = FastAPI()
Base.metadata.create_all(bind=engine)


@app.post("/signup")
def signup(request: SignupRequest, db: Session = Depends(get_db)):
    return auth.signup_user(request, db)


@app.post("/verify-signup-otp")
def verify_signup_otp(request: VerifyOtpSignupRequest, db: Session = Depends(get_db)):
    return auth.verify_signup_otp(request, db)


@app.post("/resend-signup-otp")
def resend_signup_otp(email: str, db: Session = Depends(get_db)):
    otp = auth.utils.generate_otp()
    auth.utils.store_otp(email, otp)
    auth.utils.send_email_otp(email, otp)
    return auth.utils.custom_response(
        response="OTP resent",
        response_code=200,
        response_message="OTP resent to email for verification",
        data={}
    )


@app.post("/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    return auth.login_user(request, db)


@app.post("/verify-login-otp")  # Placeholder if needed later
def verify_login_otp(email: str, otp: str, db: Session = Depends(get_db)):
    return {"message": "This endpoint can be implemented similarly"}


@app.post("/change-password")
def change_password(request: ChangePasswordRequest, db: Session = Depends(get_db)):
    return auth.change_password(request, db)
