from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy.orm import Session
from database import get_db
from .auth import get_current_user
from models import User, Topic, Subject
from passlib.context import CryptContext
from typing import Annotated, Optional
from sqlalchemy import or_
import os
import json
from sqlmodel import select

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


router = APIRouter(prefix='/notes',tags=['Notes'])


@router.get('/all-subjects', status_code=status.HTTP_200_OK)
async def get_all_subjects(user: user_dependency, db: db_dependency):
    """
    When you do the get request, you will get Courses grouped by the year and 
    then first and second semesters respectively.
    """


    if not user:
        raise HTTPException(status_code=401, detail="Not Authenticated")
    
    user_info = db.query(User).filter(User.id == user.get('id')).first()

    
    

    subject_statment = select(Subject)
    subjects = db.exec(subject_statment).all()

   

    if not subjects:
        raise HTTPException(status_code=404, detail="No courses found")
    

    return subjects



@router.get('/course-topic', status_code=status.HTTP_200_OK)
async def get_subject_topic(user: user_dependency, db: db_dependency, subject_id:int):
    """
    When you do the get request, you will get Courses grouped by the year and 
    then first and second semesters respectively.
    """


    if not user:
        raise HTTPException(status_code=401, detail="Not Authenticated")
    
    user_info = db.query(User).filter(User.id == user.get('id')).first()

    
    

    topics_statment = select(Topic).where(Topic.subject_id==subject_id)
    subjects = db.exec(topics_statment).all()

   

    if not subjects:
        raise HTTPException(status_code=404, detail="No Topic found")
    

    return [{"id": topic.id, "title": topic.title, "free": topic.free} for topic in subjects]



@router.get('/topic-content', status_code=status.HTTP_200_OK)
async def topic_content_details(user: user_dependency, db: db_dependency, topic_id:int):
    """
    When you do the get request, you will get Courses grouped by the year and 
    then first and second semesters respectively.
    """


    if not user:
        raise HTTPException(status_code=401, detail="Not Authenticated")
    
    user_info = db.query(User).filter(User.id == user.get('id')).first()

    
    

    topics_statment = select(Topic).where(Topic.id==topic_id)
    topic = db.exec(topics_statment).first()

   

    if not topic:
        raise HTTPException(status_code=404, detail="No Topic found")
    

    if not user_info.activated and not topic.free:

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={
            "status":"Not Activated",
            "message": "Please contact vendor to get activated"
        })

    

    return {
        "topic_content": topic
        
    }

