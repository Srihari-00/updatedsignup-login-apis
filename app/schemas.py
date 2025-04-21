from typing import Optional
from pydantic import BaseModel, EmailStr, Field
import datetime


class SignupRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str


class VerifyOtpSignupRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str
    otp: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ChangePasswordRequest(BaseModel):
    user_id: int
    username: str
    email: EmailStr
    old_password: str
    new_password: str
    confirm_password: str


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    new_password: str
    confirm_password: str


class UserResponse(BaseModel):
    user_id: int
    username: str
    email: str
    first_name: Optional[str]
    middle_name: Optional[str]
    last_name: Optional[str]
    gender: Optional[str]
    date_of_birth: Optional[datetime.date]
    mobile: Optional[str]
    city: Optional[str]
    state: Optional[str]
    country: Optional[str]
    role_id: Optional[int]  # ✅ Accepts null (None) values

    class Config:
        from_attributes = True  # ✅ Updated for Pydantic v2


class UpdateUserDetailsRequest(BaseModel):
    user_id: int
    first_name: Optional[str]
    middle_name: Optional[str]
    last_name: Optional[str]
    gender: Optional[str]
    date_of_birth: Optional[datetime.date]
    mobile: Optional[str]
    city: Optional[str]
    state: Optional[str]
    country: Optional[str]

    class Config:
        from_attributes = True  # ✅ Corrected for Pydantic v2


class StandardResponse(BaseModel):
    response: str
    response_code: int
    response_message: str
    data: Optional[UserResponse] = None
