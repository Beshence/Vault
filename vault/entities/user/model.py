import uuid
from datetime import datetime

from fastapi_users_db_sqlalchemy import UUID_ID, GUID
from fastapi_users_db_sqlalchemy.generics import TIMESTAMPAware, now_utc
from sqlalchemy import Column, String, Boolean, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from vault.core.db import Base


class User(Base):
    __tablename__ = "Users"

    id: Mapped[UUID_ID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)
    username = Column(String(length=320), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(length=1024), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)



class AccessToken(Base):
    __tablename__ = "AccessTokens"

    user_id: Mapped[GUID] = mapped_column(GUID, ForeignKey("Users.id", ondelete="cascade"), nullable=False)
    token: Mapped[str] = mapped_column(String(length=43), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMPAware(timezone=True), index=True, nullable=False, default=now_utc)