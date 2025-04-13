from fastapi import FastAPI, Depends
from . import auth
from .database import engine
from .models import Base
from .schemas import SignupRequest, LoginRequest, ChangePasswordRequest
from .auth import get_db
from sqlalchemy.orm import Session

app = FastAPI()
Base.metadata.create_all(bind=engine)


@app.post("/signup")
def signup(request: SignupRequest, db: Session = Depends(get_db)):
    return auth.signup_user(request, db)


@app.post("/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    return auth.login_user(request, db)


@app.post("/change-password")
def change_password(request: ChangePasswordRequest, db: Session = Depends(get_db)):
    return auth.change_password(request, db)
