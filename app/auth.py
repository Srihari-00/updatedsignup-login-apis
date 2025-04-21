from fastapi import Depends, APIRouter, HTTPException
from sqlalchemy.orm import Session
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy import text
from . import schemas, crud, utils
from .schemas import VerifyOtpSignupRequest
from .models import UserDetail as User
from .utils import hash_password, get_stored_otp, verify_otp
from .database import SessionLocal

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/signup", response_model=schemas.StandardResponse)
def signup_user(request: schemas.SignupRequest, db: Session = Depends(get_db)):
    normalized_email = utils.normalize_email(request.email)

    # Check if email is already registered
    if crud.get_user_by_email(db, normalized_email):
        return utils.custom_response(
            response="error",
            response_code=400,
            response_message="The email you provided is already associated with an account."
        )

    # Check for valid email format
    if not utils.is_valid_email(normalized_email):
        return utils.custom_response(
            response="error",
            response_code=400,
            response_message="Please enter a valid email like example@domain.com"
        )

    # Check for strong password
    if not utils.is_strong_password(request.password):
        return utils.custom_response(
            response="error",
            response_code=400,
            response_message="Password must be 8–15 characters long and include uppercase, lowercase, numbers, and special characters."
        )

    # Check if username is already taken
    if crud.get_user_by_username(db, request.username):
        return utils.custom_response(
            response="error",
            response_code=400,
            response_message=f"The username '{request.username}' is already in use. Please choose a different username."
        )

    # Generate and send OTP
    otp = utils.generate_otp()
    utils.store_otp(normalized_email, otp)
    utils.send_email_otp(normalized_email, otp)

    return utils.custom_response(
        response="success",
        response_code=200,
        response_message="An OTP has been sent to your registered email. Please verify it to complete your registration."
    )


@router.post("/verify-signup-otp")
def verify_signup_otp(request: VerifyOtpSignupRequest, db: Session = Depends(get_db)):
    normalized_email = utils.normalize_email(request.email)

    print(f"Email: {normalized_email}")
    print(f"Entered OTP: {request.otp}")
    print(f"Stored OTP: {get_stored_otp(normalized_email)}")

    # Validate OTP using normalized email
    if not verify_otp(normalized_email, request.otp):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    # Check if user already exists using normalized email
    existing_user = db.query(User).filter(
        User.email == normalized_email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_password = hash_password(request.password)

    user = User(
        username=request.username,
        email=normalized_email,  # Store lowercase email in DB
        password=hashed_password,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "message": "Signup successful. Please update your profile via /update-details.",
        "user_id": user.id,
        "email": user.email
    }


@router.post("/reset-password", response_model=schemas.StandardResponse)
def reset_password(request: schemas.ResetPasswordRequest, db: Session = Depends(get_db)):
    email = request.email.lower()
    is_valid_email, email_message = utils.validate_email(email)
    if not is_valid_email:
        return utils.custom_response(
            "error", 400, "Invalid email format", {
                "description": email_message}
        )

    user = crud.get_user_by_email(db, email)
    if not user:
        return utils.custom_response("error", 404, "User not found", {"description": f"No user found with email: {email}"})

    if request.new_password != request.confirm_password:
        return utils.custom_response("error", 400, "Passwords do not match", {"description": "New password and confirm password must match."})

    is_valid, errors = utils.validate_password_rules(request.new_password)
    if not is_valid:
        return utils.custom_response("error", 400, "Weak password", {"description": " ".join(errors)})

    hashed_password = utils.hash_password(request.new_password)
    crud.update_user_password(db, user, hashed_password)

    return utils.custom_response("success", 200, "Password reset successful", {"description": f"Password for user {email} has been reset successfully."})


@router.post("/login", response_model=schemas.StandardResponse)
def login_user(request: schemas.LoginRequest, db: Session = Depends(get_db)):
    email = utils.normalize_email(request.email)
    user = crud.get_user_by_email(db, email)

    if not user:
        return utils.custom_response("error", 404, "Email not registered. Please signup.")

    if not utils.verify_password(request.password, user.password):
        return utils.custom_response("error", 401, "Invalid password. Please try again.")

    return utils.custom_response("success", 200, "Successfully logged in", {
        "user_id": user.id,
        "username": user.username,
        "user_email": user.email
    })


@router.post("/change-password", response_model=schemas.StandardResponse)
def change_password(request: schemas.ChangePasswordRequest, db: Session = Depends(get_db)):
    email = utils.normalize_email(request.email)
    user = crud.get_user_by_email(db, email)

    if not user:
        return utils.custom_response("error", 404, "Email not found. Please check if the email is correct and registered.",
                                     {"field": "email", "error": "User with this email does not exist."})

    if user.id != request.user_id or user.username != request.username:
        return utils.custom_response("error", 403, "User identity (username) mismatch. Please check your user details.",
                                     {"field": "user_identity", "error": "User identity does not match."})

    if not utils.verify_password(request.old_password, user.password):
        return utils.custom_response("error", 401, "Incorrect old password. Please try again.",
                                     {"field": "old_password", "error": "The old password you entered is incorrect."})

    if request.new_password != request.confirm_password:
        return utils.custom_response("error", 400, "New password and confirm password do not match. Please ensure they are identical.",
                                     {"field": "confirm_password", "error": "Passwords do not match."})

    is_valid_pw, password_errors = utils.validate_password_rules(
        request.new_password)
    if not is_valid_pw:
        return utils.custom_response("error", 400, "New password validation failed. See 'data' for more information.",
                                     {"password_errors": password_errors})

    user.password = utils.hash_password(request.new_password)
    db.commit()

    return utils.custom_response("success", 200, "Password changed successfully.", {
        "user_id": user.id,
        "username": user.username,
        "user_email": user.email
    })


@router.put("/update-user-details", response_model=schemas.StandardResponse)
def update_user_details(request: schemas.UpdateUserDetailsRequest, db: Session = Depends(get_db)):
    try:
        # Fetch the user by ID
        user = db.query(User).filter(
            User.id == request.user_id).first()

        if not user:
            return schemas.StandardResponse(
                response="error",
                response_code=404,
                response_message="User not found",
                data=None
            )

        # Update each field from the request if it is not None
        for field, value in request.dict(exclude_unset=True).items():
            if field != "user_id" and value is not None and hasattr(user, field):
                setattr(user, field, value)

        db.commit()
        db.refresh(user)

        user_response = schemas.UserResponse(
            user_id=user.id,
            username=user.username,
            email=user.email,
            first_name=user.first_name,
            middle_name=user.middle_name,
            last_name=user.last_name,
            gender=user.gender,
            date_of_birth=user.date_of_birth,
            mobile=user.mobile,
            city=user.city,
            state=user.state,
            country=user.country,
            role_id=user.role_id
        )

        return schemas.StandardResponse(
            response="success",
            response_code=200,
            response_message="User details updated successfully",
            data=user_response
        )

    except IntegrityError as e:
        db.rollback()
        return JSONResponse(
            status_code=400,
            content=schemas.StandardResponse(
                response="error",
                response_code=400,
                response_message="Integrity error occurred: " +
                str(e.__cause__),
                data=None
            ).dict()
        )

    except SQLAlchemyError as e:
        db.rollback()
        return JSONResponse(
            status_code=500,
            content=schemas.StandardResponse(
                response="error",
                response_code=500,
                response_message="Database error: " + str(e.__cause__),
                data=None
            ).dict()
        )

    except Exception as e:
        db.rollback()
        return JSONResponse(
            status_code=500,
            content=schemas.StandardResponse(
                response="error",
                response_code=500,
                response_message="Internal server error: " + str(e),
                data=None
            ).dict()
        )
