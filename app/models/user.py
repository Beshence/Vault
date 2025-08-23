from sqlmodel import SQLModel, Field, String, UUID


class UserBase(SQLModel):
    id: UUID = Field(primary_key=True, nullable=False, index=True)

class User(UserBase, table=True):
    fast_login_secret: String = Field(nullable=False)
    is_active: bool = Field(nullable=False)

class UserPublic(UserBase):
    pass