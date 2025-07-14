from fastapi import APIRouter

from app.api.user.repo import repo_router
from app.entities.user.manager import fastapi_users
from app.entities.user.schema import UserRead, UserUpdate

user_router = APIRouter(prefix="/user")
user_router.include_router(fastapi_users.get_users_router(UserRead, UserUpdate), tags=["Users"])
user_router.include_router(repo_router)