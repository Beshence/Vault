import uuid
from typing import Optional, Generic

from fastapi_users import models
from fastapi_users.schemas import model_dump, PYDANTIC_V2
from pydantic import BaseModel, ConfigDict


class UserModel(BaseModel):
    def create_update_dict(self):
        return model_dump(
            self,
            exclude_unset=True,
            exclude={
                "id",
                "is_superuser",
                "is_active"
            },
        )

    def create_update_dict_superuser(self):
        return model_dump(self, exclude_unset=True, exclude={"id"})

class UserRead(UserModel, Generic[models.ID]):
    id: uuid.UUID
    username: str
    is_active: bool = True
    is_superuser: bool = False

    if PYDANTIC_V2:  # pragma: no cover
        model_config = ConfigDict(from_attributes=True)  # type: ignore
    else:  # pragma: no cover
        class Config:
            orm_mode = True


class UserCreate(UserModel):
    username: str
    password: str
    #is_active: Optional[bool] = True
    #is_superuser: Optional[bool] = False


class UserUpdate(UserModel):
    username: Optional[str] = None
    password: Optional[str] = None
    #is_active: Optional[bool] = None
    #is_superuser: Optional[bool] = None