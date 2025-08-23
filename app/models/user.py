import uuid

from sqlmodel import SQLModel, Field

class UserBase(SQLModel):
    id: uuid.UUID = Field(primary_key=True, nullable=False, index=True)
    username: str = Field(nullable=False, unique=True, index=True)
    is_active: bool = Field(nullable=False)

class User(UserBase, table=True):
    __tablename__ = "BVUsers"

    password: str | None = Field(nullable=True)
    fast_login_secret: str = Field(nullable=False)

class UserPublic(UserBase):
    pass
