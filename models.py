from database import engine
from sqlalchemy import Column, ForeignKey, Integer, Boolean, String
from sqlmodel import SQLModel, Field, Relationship
from typing import List, Optional
from datetime import datetime, timezone, timedelta
import uuid
from sqlalchemy.types import Text, JSON
import sqlalchemy
from enum import Enum


def generate_otp_code() -> str:
    # Generates a short UUID string; adjust as needed for OTP length requirements
    return str(uuid.uuid4().int)[:5]  # Generates a 6-digit numeric code from UUID


class Institution(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True, index=True)
    name: str = Field(default=None)

    user: Optional["User"] = Relationship(back_populates="institution")

class OTP(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True, index=True)
    otp_code: str = Field(default_factory=generate_otp_code, max_length=6, index=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expired_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=10))


    is_used: bool = Field(default=False)

    # Foreign key relationship to User
    user_id: int = Field(foreign_key="user.id")
    user: Optional["User"] = Relationship(back_populates="otps")


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True, index=True)
    full_name: str = Field(default=None, nullable=True)
    email:str = Field(unique=True)
    phone_number: str = Field(default=None, nullable=True)
    hashed_password: str = Field(nullable=True)
    role: str 
    int_id: int = Field(foreign_key="institution.id")
    institution: list[Institution] = Relationship(back_populates="user")
    otps: list[OTP] = Relationship(back_populates="user")
    activated: bool = Field(default=False)


class Subject(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True, index=True)
    name: str = Field(default=None, nullable=True)


    topics: List["Topic"] = Relationship(back_populates="subject", sa_relationship_kwargs={"cascade": "all, delete-orphan"})




class ActivationPin(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True, index=True)
    code: str = Field(max_length=15, unique=True)
    used: bool = Field(default=False)


class Topic(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True, index=True)
    title: str = Field(nullable=False)
    description: Optional[str] = Field(nullable=True)
    content: str = Field(default=None, sa_column=Column(Text))
    free: bool = Field(default=False)
    subject_id: int = Field(default=None, foreign_key="subject.id")

    subject: Subject = Relationship(back_populates="topics")
    questions: List["Question"] = Relationship(back_populates="topic")




class Question(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    year: str = Field(max_length=5)
    question_text: str = Field(default=None, sa_column=Column(Text))
    a: str 
    b: str 
    c: str 
    d: str =Field(nullable=True)
    e: str = Field(nullable=True)
    correct_answer: str  # This will store the letter (A, B, C, D, E)
    topic_id: int = Field(foreign_key="topic.id")

    topic: Topic = Relationship(back_populates="questions")



class PasswordRequest(SQLModel):
    email: str


    class Config:
        json_schema_extra = {
            "example": {
                
                "email": "johndoe@example.com"
            }
        }


class OTPVerify(SQLModel):
    otp_code: str
    email: str
    new_password: str


    class Config:
        json_schema_extra = {
            "example": {
                
                "otp_code": "873734",
                "email": "elint@gm.com",
                "new_password": "okon"
            }
        }

class CreateUserRequest(SQLModel):
    email: str 
    full_name: str
    institution_id: str
    password: str
    phone_number: str
    role: str

    class Config:
        #orm_mode = False
        json_schema_extra = {
            "example": {
                "email": "johndoe@example.com",
                "full_name": "John Doe",
                "institution_id": "8",
                "phone_number": "09838333",
                "password": "your_secure_password",
                "role": "student"

            }
        }



def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

