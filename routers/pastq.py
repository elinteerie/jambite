from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy.orm import Session
from database import get_db
from .auth import get_current_user
from models import User, Topic, Subject, Question
from passlib.context import CryptContext
from typing import Annotated, Optional

from sqlmodel import select

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


router = APIRouter(prefix='/pq',tags=['PQ'])





@router.get('/get-a-question', status_code=status.HTTP_200_OK, response_model=Question)
async def get_a_question(q_id: int, user: user_dependency, db: db_dependency):


    if not user:
        raise HTTPException(status_code=401, detail="Not Authenticated")
    
    question = db.query(Question).filter(Question.id == q_id).first()

    if not question:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No Question Founds")

    return question


@router.get('/question-by-topic', status_code=status.HTTP_200_OK)
async def question_by_topic(topic_id: int, user: user_dependency, db: db_dependency):

    if not user:
        raise HTTPException(status_code=401, detail="Not Authenticated")
    
    user_info = db.query(User).filter(User.id == user.get('id')).first()

    topic_stmt = select(Topic).where(Topic.id==topic_id)
    topic = db.execute(topic_stmt).scalars().first()


    

    question = db.query(Question).filter(Question.topic_id == topic_id).limit(15).all()
    activated = user_info.activated

    if not activated and not topic.free:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={
            "status":"Not Activated",
            "message": "Please contact vendor to get activated"
        })

    return question



@router.get('/question-by-subject', status_code=status.HTTP_200_OK)
async def question_by_topic(subject_id: int, user: user_dependency, db: db_dependency):

    if not user:
        raise HTTPException(status_code=401, detail="Not Authenticated")
    
    user_info = db.query(User).filter(User.id == user.get('id')).first()

    statement = (
        select(Question)
        .join(Topic)
        .where(Topic.subject_id == subject_id)
    )

    

    questions = db.exec(statement).all()
    activated = user_info.activated

    if not activated:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={
            "status":"Not Activated",
            "message": "Please contact vendor to get activated"
        })

    return questions