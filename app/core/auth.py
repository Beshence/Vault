import os
import uuid
from datetime import timedelta, datetime, timezone
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jwt import InvalidTokenError
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from sqlmodel import select, SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession
from starlette import status

from app.core.db import SessionDep
from app.models.user import User

JWT_SECRET_KEY = None
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

password_hash = PasswordHash([Argon2Hasher()])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


def get_jwt_secret_key() -> str:
    global JWT_SECRET_KEY
    if JWT_SECRET_KEY is None:
        if not os.path.isfile("data/JWT_SECRET_KEY"):
            with open("data/JWT_SECRET_KEY", "w") as f:
                f.write(os.urandom(512).hex())
        JWT_SECRET_KEY = open("data/JWT_SECRET_KEY").read().strip()
    return JWT_SECRET_KEY


class Token(SQLModel):
    access_token: str
    token_type: str


class TokenData(SQLModel):
    username: str | None = None


def verify_password(plain_password, hashed_password):
    # TODO: verify_and_update
    return password_hash.verify(plain_password, hashed_password)


def get_password_hash(password):
    return password_hash.hash(password)


async def get_user_from_username(session: AsyncSession, username: str) -> User:
    user = (await session.scalar(select(User).where(User.username == username)))
    return user


async def get_user_from_id(session: AsyncSession, user_id: str) -> User:
    user = (await session.scalar(select(User).where(User.id == uuid.UUID(user_id))))
    return user


async def register_user_with_credentials(session: AsyncSession, username: str, password: str) -> User:
    if await get_user_from_username(session, username) is not None:
        raise Exception(f"User {username} already exists")
    user = User(
        id=uuid.uuid4(),
        username=username,
        password=get_password_hash(password),
        is_active=True,
        # TODO: change fast login secret
        fast_login_secret="123"
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user

async def log_in_user_via_credentials(session: AsyncSession, username: str, password: str) -> User | None:
    user = await get_user_from_username(session, username)
    if not user:
        return None
    if not verify_password(password, user.password):
        return None
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, get_jwt_secret_key(), algorithm=JWT_ALGORITHM)
    return encoded_jwt


async def get_current_user(session: SessionDep, token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, get_jwt_secret_key(), algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        token_data = TokenData(username=user_id)
    except InvalidTokenError:
        raise credentials_exception
    user = await get_user_from_id(session, token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
