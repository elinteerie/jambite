from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy.orm import Session
from database import get_db
from models import User, PasswordRequest, OTP, OTPVerify, CreateUserRequest, Institution, ActivationPin
from passlib.context import CryptContext
from typing import Annotated, Optional
from sqlalchemy import or_
import os
from fastapi import BackgroundTasks
from jose import JWTError, jwt
from dotenv import load_dotenv
from mail_setup import send_custom_email
from datetime import datetime, timezone, timedelta
import json
from sqlmodel import select
load_dotenv()
from sqlalchemy.ext.asyncio import AsyncSession, AsyncEngine

SECRET_KEY = os.getenv('SECRET_KEY')
print(SECRET_KEY)
ALGORITHM = os.getenv('ALGORITHM')
print(ALGORITHM)
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI =os.getenv('GOOGLE_REDIRECT_URI')



router = APIRouter(prefix='/auth',tags=['Authentication'])

#Encrypt Password
bcrypt_context = CryptContext(schemes=['argon2', 'bcrypt'], default='argon2', deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')
db_dependency = Annotated[AsyncSession, Depends(get_db)]


#Authenticate Users
def authenticate_user(username_or_email: str, password: str, db: db_dependency):
    #user = db.query(User).filter(User.email == username_or_email).first()

    statement = select(User).where(User.email == username_or_email)
    result = db.execute(statement)
    result = result.scalars().first()
    user = result
    #print("user:",user)

    if not user:
        return False
    
    
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return user

#Create a JWT
def create_access_token(email: str, user_id: int, role: str, expires_delta: timedelta ):
    encode = {"sub": email, "id": user_id, "role": role}  
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)
    

#Decode a JWT
async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        user_role: str = payload.get('role')

        if username is None or user_id is None:
            raise HTTPException(status_code=401, detail="Could Not Valid Credential")
        return {
            'username': username, "id": user_id, "user_role": user_role
        }
    except JWTError:
        raise HTTPException(status_code=401, detail="Could Not Valid Credential")
        



class Token(BaseModel):
    access_token: str
    token_type: str
    expires: str


@router.post('/', status_code=status.HTTP_201_CREATED)
async def create_user(user_request: CreateUserRequest, db: db_dependency, background_tasks: BackgroundTasks):
    
    """
    For Creating of Users, You will have to use the get level and get department urls to get the IDs of
    of the Level and Department which users will use to select their level and select their department.
    - level: /auth/get-levels
    - depts: /auth/get-depts

    - info: Immediately a User is created, they are logined 
    """

    result = select(User).where(User.email == user_request.email)
    existing_user = db.execute(result)
    existing_user = existing_user.scalars().first()
    
    """db.query(User).filter(User.email == user_request.email).first()"""
    if existing_user:
        raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"User with this email {user_request.email}  already exists."
    )
    

    
    
    create_user = User(
        email = user_request.email,
        full_name = user_request.full_name,
        role = "student",
        int_id= user_request.institution_id,
        hashed_password = bcrypt_context.hash(user_request.password),
        is_active = True
        )
    
    
    db.add(create_user)
    db.commit()
    db.refresh(create_user)

    background_tasks.add_task(
        send_custom_email,
        user_request.email,
        "FUTO STUDY APP",
        "Welcome Mail",
        "Welcome to FUTO Study APP"
    )

    user = authenticate_user(user_request.email, user_request.password, db)

    token = create_access_token(user.email, user.id, user.role, timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES)))


    return {
        'message': "User Created",
        'access_token': token,
        'token_type': "bearer",
        "token_expires": f'{ACCESS_TOKEN_EXPIRE_MINUTES}'
        
    }
    
    

@router.post('/token', response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):


    statement = select(User).where(User.email == form_data.username)
    result = db.execute(statement)
    result = result.scalars().first()
    user = result


    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=401, detail="Could Not Valid Credential")
        
    
    token = create_access_token(user.email, user.id, user.role, timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES)))
    
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires": f'{ACCESS_TOKEN_EXPIRE_MINUTES}'
    }
    


@router.get('/get-instituions', status_code=status.HTTP_200_OK)
async def get_all_levels(db: db_dependency):
    levels = db.query(Institution).all()

    return {
        "message": "Institutions Available",
        "levels": levels
    }







@router.post('/passw-reset-request', status_code=status.HTTP_200_OK)
async def request_otp(user_request: PasswordRequest, db: db_dependency, background_tasks: BackgroundTasks):

    user = db.query(User).filter(User.email == user_request.email).first()
    print(user)

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")


    
    user_otp_create = OTP(user_id=user.id)
    db.add(user_otp_create)

    db.commit()
    db.refresh(user_otp_create)


    background_tasks.add_task(
        send_custom_email,
        user_request.email,
        "FUTO STUDY APP",
        "Password Reset",
        f" This Code last for just 10 minutes {user_otp_create.otp_code}"
    )

    
    return {
        "message": "OTP created and sent",
        "otp_code": user_otp_create.otp_code  # For testing only; remove in production
    }



def is_otp_expired(otp: OTP) -> bool:
    """Check if the OTP is expired based on a 10-minute expiration from the creation time."""
    # Ensure created_at is timezone-aware; assume UTC if naive
    if otp.expired_at.tzinfo is None:
        created_at_utc = otp.expired_at.replace(tzinfo=timezone.utc)
    else:
        created_at_utc = otp.expired_at
    
    # Define the expiration time 10 minutes after created_at
    expiration_time = created_at_utc 
    print(expiration_time)
    print(datetime.now(timezone.utc))
    return datetime.now(timezone.utc) > expiration_time


@router.post('/passw-reset-confirm', status_code=status.HTTP_200_OK)
async def otp_verify(otp_request: OTPVerify, db: db_dependency):

    user = db.query(User).filter(User.email == otp_request.email).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    otp = db.query(OTP).filter(OTP.user_id == user.id, OTP.otp_code ==otp_request.otp_code).order_by(OTP.created_at.desc()).first()
    

    if not otp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OTP not found")
    

    if is_otp_expired(otp):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP has expired")
    

    
    
    

    if otp.is_used:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP has being used")

    hashed_password = bcrypt_context.hash(otp_request.new_password)

    user.hashed_password = hashed_password
    db.add(user)
    otp.is_used = True
    db.add(otp)
    db.commit()




    return {
        "message": "User Password Changed. Action performed."
    }



