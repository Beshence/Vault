from sqlmodel import SQLModel, Field, String, UUID


class UserBase(SQLModel):
    id: UUID = Field(primary_key=True, nullable=False, index=True)
    username: str = Field(nullable=False, unique=True, index=True)
    is_active: bool = Field(nullable=False)

class User(UserBase, table=True):
    password: str | None = Field(nullable=True)
    fast_login_secret: String = Field(nullable=False)

class UserPublic(UserBase):
    pass
