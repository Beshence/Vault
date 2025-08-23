from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_versionizer import api_version
from pydantic import BaseModel
from starlette import status

from app.core.auth import log_in_user_via_credentials, \
    ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token, get_user_from_username, register_user_with_credentials, Token
from app.core.db import SessionDep

auth_router = APIRouter(prefix="/auth", tags=["Auth"])


class UserCreate(BaseModel):
    username: str
    password: str

@api_version(1, 0)
@auth_router.post("/register")
async def register(user_create: UserCreate, session: SessionDep) -> Token:
    if await get_user_from_username(session, user_create.username) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this username already exists"
        )
    user = await register_user_with_credentials(session, user_create.username, user_create.password)

    # TODO: make sessions, not tokens

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")





@api_version(1, 0)
@auth_router.post("/login")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: SessionDep) -> Token:
    user = await log_in_user_via_credentials(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # TODO: make sessions, not tokens

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")