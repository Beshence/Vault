from typing import Optional

from fastapi import APIRouter, Request, Depends
from fastapi_users import schemas
from fastapi_versionizer import api_version
from pydantic import BaseModel

from app.api.user import user_router
from app.entities.user.manager import fastapi_users, auth_backend, current_user
from app.entities.user.model import User
from app.entities.user.schema import UserRead, UserCreate

api_router = APIRouter()

api_router.include_router(
    fastapi_users.get_auth_router(auth_backend),
    prefix="/auth",
    tags=["Auth"]
)

api_router.include_router(
    fastapi_users.get_register_router(UserRead, UserCreate),
    prefix="/auth",
    tags=["Auth"],
)
"""api_router.include_router(
    fastapi_users.get_reset_password_router(),
    prefix="/auth",
    tags=["Auth"],
)"""
api_router.include_router(user_router)


class Ping(BaseModel):
    ping: str = "pong"
    latest_api_version: str = "v0.0"
    me: UserRead | None

@api_version(1, 0)
@api_router.get('/ping', tags=['Common'])
def ping(request: Request, me: Optional[User] = Depends(current_user(optional=True))) -> Ping:
    return Ping(
        ping="pong",
        latest_api_version=request.app.state.latest_api_version,
        me=schemas.model_validate(UserRead, me) if me else None
    )