from fastapi import FastAPI, Depends, Request
from . import auth
from .database import engine
from .models import Base
from .schemas import SignupRequest, LoginRequest, ChangePasswordRequest, ResetPasswordRequest, VerifyOtpSignupRequest, UpdateUserDetailsRequest
from .auth import get_db
from sqlalchemy.orm import Session
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

app = FastAPI()
Base.metadata.create_all(bind=engine)


# @app.post("/signup")
# def signup(request: SignupRequest, db: Session = Depends(get_db)):
#     return auth.signup_user(request, db)

@app.post("/signup")
def signup(request: SignupRequest, db: Session = Depends(get_db)):
    return auth.signup_user(request, db)

# Verify signup OTP
# This endpoint verifies the OTP sent to the user's email during signup.


@app.post("/verify-signup-otp")
def verify_signup_otp(request: VerifyOtpSignupRequest, db: Session = Depends(get_db)):
    return auth.verify_signup_otp(request, db)


@app.post("/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    return auth.login_user(request, db)


@app.post("/forgot-password")
def forgot_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    return auth.reset_password(request, db)


@app.post("/change-password")
def change_password(request: ChangePasswordRequest, db: Session = Depends(get_db)):
    return auth.change_password(request, db)


@app.put("/update-user-details")
def update_user_details(request: UpdateUserDetailsRequest, db: Session = Depends(get_db)):
    return auth.update_user_details(request=request, db=db)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = {}
    for err in exc.errors():
        loc = err.get("loc")[-1]
        msg = err.get("msg")
        errors[loc] = msg

    return JSONResponse(
        status_code=422,
        content={
            "response": "error",
            "response_code": 422,
            "response_message": "Validation Error",
            "data": errors
        }
    )
