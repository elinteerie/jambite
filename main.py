from fastapi import FastAPI
from database import engine, get_db
import models
import routers
from models import Institution, Subject, Topic, User, ActivationPin, CutOff, Question
from routers import auth, notes, user, pastq
from contextlib import asynccontextmanager
from models import create_db_and_tables
from fastapi import Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqladmin.authentication import AuthenticationBackend
from starlette.requests import Request
from starlette.responses import RedirectResponse
#from sqladmin import Admin, ModelView
from typing import Annotated
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware
from routers.auth import authenticate_user
from sqlmodel import select, Session
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker
from fastapi.staticfiles import StaticFiles
from sqladmin import Admin, ModelView
#from starlette_admin.auth import AdminConfig, AdminUser, AuthProvider
#from starlette_admin.exceptions import FormValidationError, LoginFailed
#from starlette.responses import Response
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware









users_list = [
    {
        "username": "admin ",
        "password": "password",
        "role": "can_edit"
    },
    {
        "username": "sirangle",
        "password": "admin",
        "role": "can_not_edit"
    },

    {"username": "akazamarz",
     "password": "thepassakas",
     "role": "can_not_edit"}
]




origins = [
    "http://localhost",        # Allow requests from localhost
    "http://localhost:3000",  # Allow requests from frontend (React, etc.)
    "https://yourdomain.com", # Add your production domain
    "http://127.0.0.1",
    
]


class AdminAuth(AuthenticationBackend):
    async def login(self, request: Request):
        form = await request.form()
        username, password = form["username"], form["password"]

        for user in users_list:
        
            if username ==user["username"] and password == user["password"]:

        
                request.session.update({"token": "UUID", "role": user["role"]})
                

        return True

    async def logout(self, request: Request) -> bool:
        # Usually you'd want to just clear the session
        request.session.clear()
        return True

    async def authenticate(self, request: Request) -> bool:
        token = request.session.get("token")

        if not token:
            return False

        # Check the token in depth
        return True





@asynccontextmanager
async def lifespan(app: FastAPI):
    # Code to run on startup
    print("db created ")
    create_db_and_tables()
    print("db updated")
    yield  # Your application runs during this yield

app = FastAPI(lifespan=lifespan, title="JAMBITE", version="1.0")
#admin = Admin(app, engine)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins          # Origins allowed to access your app
    allow_credentials=True,          # Allow cookies
    allow_methods=["*"],             # Allow all HTTP methods
    allow_headers=["*"],             # Allow all headers
)


app.mount("/static", StaticFiles(directory="uploads"), name="uploads")
SECRET = "1234567890"
"""admin = Admin(engine, title="FUTOSTUDY: Admin Panel", 
              auth_provider=UsernameAndPasswordProvider(),
              middlewares=[Middleware(SessionMiddleware, secret_key=SECRET)],
              )"""







app.include_router(auth.router)
app.include_router(notes.router)
app.include_router(user.router)
app.include_router(pastq.router)
#app.include_router(header.router)
#app.include_router(lecture.router)
#app.include_router(pq.router)
#app.include_router(study_clique.router)



#authentication_backend = AdminAuth(secret_key="88trrrr")
#admin = Admin(app=app, engine=engine, authentication_backend=authentication_backend)
admin = Admin(app=app, engine=engine)


def check_oga_admin(request: Request)-> bool:
    role = request.session.get("role")

    if role:
        if not role =="can_edit":
            print("No role found in the session.")
            return False
        else:
            print(f"The role in the session is: {role}")

            return True
    
class UserAdmin(ModelView, model=User):
    column_list = "__all__"

class InstitutionAdmin(ModelView, model=Institution):
    column_list = "__all__"

class SubjectAdmin(ModelView, model=Subject):
    column_list = "__all__"

class TopictAdmin(ModelView, model=Topic):
    column_list = "__all__"


class ActivationAdmin(ModelView, model=ActivationPin):
    column_list = "__all__"

class CutOffAdmin(ModelView, model=CutOff):
    column_list = "__all__"


class QuestiojnAdmin(ModelView, model=Question):
    column_list = "__all__"


admin.add_view(UserAdmin)
admin.add_view(InstitutionAdmin)
admin.add_view(SubjectAdmin)
admin.add_view(TopictAdmin)
admin.add_view(ActivationAdmin)
admin.add_view(CutOffAdmin)
admin.add_view(QuestiojnAdmin)

