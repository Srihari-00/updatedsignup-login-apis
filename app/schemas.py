from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Union, Dict, Any


class SignupRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class ChangePasswordRequest(BaseModel):
    user_id: int
    username: str
    email: str
    old_password: str
    new_password: str
    confirm_password: str


class UserResponse(BaseModel):
    user_id: int
    username: str
    user_email: str


class StandardResponse(BaseModel):
    response: str
    response_code: int
    response_message: str
    data: Optional[Union[UserResponse, Dict[str, Any]]] = None


class VerifyOtpSignupRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str
    otp: str


class VerifyLoginOtpRequest(BaseModel):
    email: EmailStr
    otp: str


class ResetPasswordRequest(BaseModel):
    email: EmailStr


class VerifyResetPasswordOTPRequest(BaseModel):
    email: EmailStr
    otp: str
    new_password: str
    confirm_password: str
