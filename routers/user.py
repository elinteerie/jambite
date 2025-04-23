from fastapi import APIRouter, Depends, HTTPException, status, Path, Request
from typing import Annotated, List
from database import get_db
from sqlalchemy.orm import Session
from .auth import get_current_user
from models import User,  ActivationPin
from typing import Optional
from datetime import datetime, timezone, timedelta
from typing import Dict
from sqlmodel import select



router = APIRouter(prefix='/user',tags=['Users'])

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]



@router.get('/info',status_code=status.HTTP_200_OK)
async def user_info(user: user_dependency, db: db_dependency):

    if not user:
        raise HTTPException(status_code=401, detail="Not Authenticated")
    

    user_model = db.query(User).filter(User.id == user.get('id')).first()

    return user_model



@router.patch('/activate-app',status_code=status.HTTP_200_OK)
async def activate_app(pin: str, user: user_dependency, db: db_dependency):
    """
    Pin is Level Activatiom Sensititive
    """

    if not user:
        raise HTTPException(status_code=401, detail="Not Authenticated")
    

    pin_statement = select(ActivationPin).where(ActivationPin.code==pin)
    pin = db.exec(pin_statement).first()

    # Check if the pin exists
    if not pin:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pin not found or does not exist")


    if pin.used:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Pin has been used by another subscriber")
    

    user_model = db.query(User).filter(User.id == user.get('id')).first()

    user_model.activated = True
    pin.used = True
    db.commit()

    return True