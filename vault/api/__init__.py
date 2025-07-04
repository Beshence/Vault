from typing import Optional

from fastapi import APIRouter, Request, Depends
from fastapi_versionizer import api_version
from pydantic import BaseModel

from vault.entities.user.manager import fastapi_users, auth_backend, current_user
from vault.entities.user.model import User
from vault.entities.user.schema import UserRead, UserCreate, UserUpdate

api_router = APIRouter(
    prefix='',
)

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
api_router.include_router(
    fastapi_users.get_users_router(UserRead, UserUpdate),
    prefix="/user",
    tags=["Users"],
)

"""@api_version(1, 0)
@api_router.get("/authenticated-route")
async def authenticated_route(user: User = Depends(current_active_user)):
    return {"message": f"Hello {user.email}!"}"""


class PingV1_0(BaseModel):
    ping: str = "pong"
    latest_api_version: str = "v0.0"
    username: str | None = "admin"

@api_version(1, 0)
@api_router.get('/ping', tags=['Common'])
def ping(request: Request, user: Optional[User] = Depends(current_user(optional=True))) -> PingV1_0:
    return PingV1_0(
        ping="pong",
        latest_api_version=request.app.state.latest_api_version,
        username=user.username if user else None
    )