#from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.ext.asyncio import AsyncSession, AsyncEngine
from sqlalchemy.engine import create_engine
from sqlmodel import Session, create_engine
#from sqlalchemy.ext.declarative import declarative_base
import os
from dotenv import load_dotenv
load_dotenv()

from sqlalchemy.orm import sessionmaker




#DATABASE_URL = os.getenv('DATABASE_URL')
DB_URL = os.getenv('DB_URL')
#print(DATABASE_URL)
connect_arg= {"check_same_thread": False}

#engine = create_engine(DATABASE_URL)
engine = create_engine(DB_URL, connect_args=connect_arg, echo=True, future=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    with Session(engine) as session:
        yield session




"""async def get_db():
    async with AsyncSessionLocal() as session:
        yield session"""
