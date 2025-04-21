from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from .database import Base
import datetime


# class User(Base):
#     __tablename__ = "users"

#     id = Column(Integer, primary_key=True, index=True)
#     username = Column(String, index=True)
#     email = Column(String, unique=True, index=True)
#     password = Column(String)
#     created_at = Column(DateTime, default=datetime.datetime.utcnow)

class UserRole(Base):
    __tablename__ = "user_roles"

    role_id = Column(Integer, primary_key=True, index=True)
    role_code = Column(String, nullable=False)
    role_name = Column(String, nullable=False)
    active_flag = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow,
                        onupdate=datetime.datetime.utcnow)

    # Reverse relationship to access all users with this role
    users = relationship("UserDetail", back_populates="role")


class UserDetail(Base):
    __tablename__ = "users_details"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    first_name = Column(String, nullable=True)
    middle_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    gender = Column(String, nullable=True)
    date_of_birth = Column(DateTime, nullable=True)
    email = Column(String, unique=True, index=True, nullable=True)
    mobile = Column(String, unique=True, nullable=True)
    password = Column(String, nullable=False)

    # Foreign key relationship with UserRole
    role_id = Column(Integer, ForeignKey("user_roles.role_id"), nullable=True)
    role = relationship("UserRole", back_populates="users")

    city = Column(String, nullable=True)
    state = Column(String, nullable=True)
    country = Column(String, nullable=True)

    active_flag = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow,
                        onupdate=datetime.datetime.utcnow)
    created_by = Column(String, nullable=True)
    updated_by = Column(String, nullable=True)
