from uuid import UUID

from fastapi import APIRouter, Depends
from fastapi_users import schemas

from app.entities.user.manager import current_user
from app.entities.user.model import User
from app.entities.user.schema import UserRead

repo_router = APIRouter(prefix="/{user_id}/repo")

@repo_router.get("/{repo_id}", tags=["Repositories"])
async def get_user_repo(user_id: UUID, repo_id: UUID, me: User = Depends(current_user())):
    return {"user_id": user_id, "repo_id": repo_id, "me": schemas.model_validate(UserRead, me)}