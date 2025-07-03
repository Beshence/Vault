import uuid
from typing import Optional, Any, Generic, TYPE_CHECKING, TypeVar, Protocol, Union

import jwt
from fastapi import Depends, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_users import FastAPIUsers, UUIDIDMixin, models, exceptions
from fastapi_users.authentication import (
    AuthenticationBackend,
    BearerTransport
)
from fastapi_users.authentication.strategy import AccessTokenDatabase, DatabaseStrategy
from fastapi_users.jwt import SecretType, generate_jwt, decode_jwt
from fastapi_users.manager import RESET_PASSWORD_TOKEN_AUDIENCE, VERIFY_USER_TOKEN_AUDIENCE
from fastapi_users.models import OAP
from fastapi_users.password import PasswordHelperProtocol, PasswordHelper
from fastapi_users_db_sqlalchemy import UUID_ID, GUID
from fastapi_users_db_sqlalchemy.access_token import SQLAlchemyAccessTokenDatabase
from sqlalchemy import select, String, Integer, func, Select, ForeignKey
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column
from starlette.responses import Response

from vault.core.db import get_async_session
from vault.entities.user.model import User, AccessToken
from vault.entities.user.schema import UserCreate, UserUpdate, UserRead

# TODO: move every change (email -> username) and (verified -> None) to separate library

SECRET = "SECRET"

ID = TypeVar("ID")


class UserProtocol(Protocol[ID]):
    """User protocol that ORM model should follow."""

    id: ID
    username: str
    hashed_password: str
    is_active: bool
    is_superuser: bool


UP = TypeVar("UP", bound=UserProtocol)


class SQLAlchemyBaseOAuthAccountTable(Generic[ID]):
    """Base SQLAlchemy OAuth account table definition."""

    __tablename__ = "oauth_account"

    if TYPE_CHECKING:  # pragma: no cover
        id: UUID_ID
        user_id: UUID_ID
        oauth_name: str
        access_token: str
        expires_at: Optional[int]
        refresh_token: Optional[str]
        account_id: str
        account_username: str
    else:
        id: Mapped[UUID_ID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)
        user_id = mapped_column(GUID, ForeignKey("Users.id", ondelete="cascade"), nullable=False)
        oauth_name: Mapped[str] = mapped_column(
            String(length=100), index=True, nullable=False
        )
        access_token: Mapped[str] = mapped_column(String(length=1024), nullable=False)
        expires_at: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
        refresh_token: Mapped[Optional[str]] = mapped_column(
            String(length=1024), nullable=True
        )
        account_id: Mapped[str] = mapped_column(
            String(length=320), index=True, nullable=False
        )
        account_username: Mapped[str] = mapped_column(String(length=320), nullable=False)


class UserDatabase(Generic[UP, ID]):
    """
    Database.

    :param session: SQLAlchemy session instance.
    :param user_table: SQLAlchemy user model.
    :param oauth_account_table: Optional SQLAlchemy OAuth accounts model.
    """

    session: AsyncSession
    user_table: type[UP]
    oauth_account_table: Optional[type[SQLAlchemyBaseOAuthAccountTable]]

    def __init__(
            self,
            session: AsyncSession,
            user_table: type[UP],
            oauth_account_table: Optional[type[SQLAlchemyBaseOAuthAccountTable]] = None,
    ):
        self.session = session
        self.user_table = user_table
        self.oauth_account_table = oauth_account_table

    async def get(self, id: ID) -> Optional[UP]:
        statement = select(self.user_table).where(self.user_table.id == id)
        return await self._get_user(statement)

    async def get_by_username(self, username: str) -> Optional[UP]:
        statement = select(self.user_table).where(
            func.lower(self.user_table.username) == func.lower(username)
        )
        return await self._get_user(statement)

    async def get_by_oauth_account(self, oauth: str, account_id: str) -> Optional[UP]:
        if self.oauth_account_table is None:
            raise NotImplementedError()

        statement = (
            select(self.user_table)
            .join(self.oauth_account_table)
            .where(self.oauth_account_table.oauth_name == oauth)  # type: ignore
            .where(self.oauth_account_table.account_id == account_id)  # type: ignore
        )
        return await self._get_user(statement)

    async def create(self, create_dict: dict[str, Any]) -> UP:
        user = self.user_table(**create_dict)
        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)
        return user

    async def update(self, user: UP, update_dict: dict[str, Any]) -> UP:
        for key, value in update_dict.items():
            setattr(user, key, value)
        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)
        return user

    async def delete(self, user: UP) -> None:
        await self.session.delete(user)
        await self.session.commit()

    async def add_oauth_account(self, user: UP, create_dict: dict[str, Any]) -> UP:
        if self.oauth_account_table is None:
            raise NotImplementedError()

        await self.session.refresh(user)
        oauth_account = self.oauth_account_table(**create_dict)
        self.session.add(oauth_account)
        user.oauth_accounts.append(oauth_account)  # type: ignore
        self.session.add(user)

        await self.session.commit()

        return user

    async def update_oauth_account(
            self, user: UP, oauth_account: OAP, update_dict: dict[str, Any]
    ) -> UP:
        if self.oauth_account_table is None:
            raise NotImplementedError()

        for key, value in update_dict.items():
            setattr(oauth_account, key, value)
        self.session.add(oauth_account)
        await self.session.commit()

        return user

    async def _get_user(self, statement: Select) -> Optional[UP]:
        results = await self.session.execute(statement)
        return results.unique().scalar_one_or_none()


async def get_user_db(session: AsyncSession = Depends(get_async_session)):
    yield UserDatabase(session, User)


async def get_access_token_db(session: AsyncSession = Depends(get_async_session)):
    yield SQLAlchemyAccessTokenDatabase(session, AccessToken)


class UserManager(UUIDIDMixin, Generic[models.UP, models.ID]):
    """
    User management logic.

    :attribute reset_password_token_secret: Secret to encode reset password token.
    :attribute reset_password_token_lifetime_seconds: Lifetime of reset password token.
    :attribute reset_password_token_audience: JWT audience of reset password token.
    :attribute verification_token_secret: Secret to encode verification token.
    :attribute verification_token_lifetime_seconds: Lifetime of verification token.
    :attribute verification_token_audience: JWT audience of verification token.

    :param user_db: Database adapter instance.
    """

    reset_password_token_secret: SecretType = SECRET
    reset_password_token_lifetime_seconds: int = 3600
    reset_password_token_audience: str = RESET_PASSWORD_TOKEN_AUDIENCE

    verification_token_secret: SecretType
    verification_token_lifetime_seconds: int = 3600
    verification_token_audience: str = VERIFY_USER_TOKEN_AUDIENCE

    user_db: UserDatabase[UP, ID]
    password_helper: PasswordHelperProtocol

    def __init__(
            self,
            user_db: UserDatabase[UP, ID],
            password_helper: Optional[PasswordHelperProtocol] = None,
    ):
        self.user_db = user_db
        if password_helper is None:
            self.password_helper = PasswordHelper()
        else:
            self.password_helper = password_helper  # pragma: no cover


    async def get(self, id: models.ID) -> models.UP:
        """
        Get a user by id.

        :param id: Id. of the user to retrieve.
        :raises UserNotExists: The user does not exist.
        :return: A user.
        """
        user = await self.user_db.get(id)

        if user is None:
            raise exceptions.UserNotExists()

        return user

    async def get_by_username(self, username: str) -> models.UP:
        """
        Get a user by username.

        :param username: Username of the user to retrieve.
        :raises UserNotExists: The user does not exist.
        :return: A user.
        """
        user = await self.user_db.get_by_username(username)

        if user is None:
            raise exceptions.UserNotExists()

        return user

    async def get_by_oauth_account(self, oauth: str, account_id: str) -> models.UP:
        """
        Get a user by OAuth account.

        :param oauth: Name of the OAuth client.
        :param account_id: Id. of the account on the external OAuth service.
        :raises UserNotExists: The user does not exist.
        :return: A user.
        """
        user = await self.user_db.get_by_oauth_account(oauth, account_id)

        if user is None:
            raise exceptions.UserNotExists()

        return user

    async def create(
            self,
            user_create: UserCreate,
            safe: bool = False,
            request: Optional[Request] = None,
    ) -> models.UP:
        """
        Create a user in database.

        Triggers the on_after_register handler on success.

        :param user_create: The UserCreate model to create.
        :param safe: If True, sensitive values like is_superuser or is_verified
        will be ignored during the creation, defaults to False.
        :param request: Optional FastAPI request that
        triggered the operation, defaults to None.
        :raises UserAlreadyExists: A user already exists with the same username.
        :return: A new user.
        """
        await self.validate_password(user_create.password, user_create)

        existing_user = await self.user_db.get_by_username(user_create.username)
        if existing_user is not None:
            raise exceptions.UserAlreadyExists()

        user_dict = (
            user_create.create_update_dict()
            if safe
            else user_create.create_update_dict_superuser()
        )
        password = user_dict.pop("password")
        user_dict["hashed_password"] = self.password_helper.hash(password)

        created_user = await self.user_db.create(user_dict)

        await self.on_after_register(created_user, request)

        return created_user

    async def oauth_callback(
            self: "UserManager[models.UOAP, models.ID]",
            oauth_name: str,
            access_token: str,
            account_id: str,
            account_username: str,
            expires_at: Optional[int] = None,
            refresh_token: Optional[str] = None,
            request: Optional[Request] = None,
            *,
            associate_by_username: bool = False,
            is_verified_by_default: bool = False,
    ) -> models.UOAP:
        """
        Handle the callback after a successful OAuth authentication.

        If the user already exists with this OAuth account, the token is updated.

        If a user with the same username already exists and `associate_by_username` is True,
        the OAuth account is associated to this user.
        Otherwise, the `UserNotExists` exception is raised.

        If the user does not exist, it is created and the on_after_register handler
        is triggered.

        :param oauth_name: Name of the OAuth client.
        :param access_token: Valid access token for the service provider.
        :param account_id: models.ID of the user on the service provider.
        :param account_username: Username of the user on the service provider.
        :param expires_at: Optional timestamp at which the access token expires.
        :param refresh_token: Optional refresh token to get a
        fresh access token from the service provider.
        :param request: Optional FastAPI request that
        triggered the operation, defaults to None
        :param associate_by_username: If True, any existing user with the same
        username will be associated to this user. Defaults to False.
        :param is_verified_by_default: If True, the `is_verified` flag will be
        set to `True` on newly created user.
        Defaults to False.
        :return: A user.
        """
        oauth_account_dict = {
            "oauth_name": oauth_name,
            "access_token": access_token,
            "account_id": account_id,
            "account_username": account_username,
            "expires_at": expires_at,
            "refresh_token": refresh_token,
        }

        try:
            user = await self.get_by_oauth_account(oauth_name, account_id)
        except exceptions.UserNotExists:
            try:
                # Associate account
                user = await self.get_by_username(account_username)
                if not associate_by_username:
                    raise exceptions.UserAlreadyExists()
                user = await self.user_db.add_oauth_account(user, oauth_account_dict)
            except exceptions.UserNotExists:
                # Create account
                password = self.password_helper.generate()
                user_dict = {
                    "username": account_username,
                    "hashed_password": self.password_helper.hash(password),
                    "is_verified": is_verified_by_default,
                }
                user = await self.user_db.create(user_dict)
                user = await self.user_db.add_oauth_account(user, oauth_account_dict)
                await self.on_after_register(user, request)
        else:
            # Update oauth
            for existing_oauth_account in user.oauth_accounts:
                if (
                        existing_oauth_account.account_id == account_id
                        and existing_oauth_account.oauth_name == oauth_name
                ):
                    user = await self.user_db.update_oauth_account(
                        user, existing_oauth_account, oauth_account_dict
                    )

        return user

    async def oauth_associate_callback(
            self: "UserManager[models.UOAP, models.ID]",
            user: models.UOAP,
            oauth_name: str,
            access_token: str,
            account_id: str,
            account_username: str,
            expires_at: Optional[int] = None,
            refresh_token: Optional[str] = None,
            request: Optional[Request] = None,
    ) -> models.UOAP:
        """
        Handle the callback after a successful OAuth association.

        We add this new OAuth account to the given user.

        :param oauth_name: Name of the OAuth client.
        :param access_token: Valid access token for the service provider.
        :param account_id: models.ID of the user on the service provider.
        :param account_username: Username of the user on the service provider.
        :param expires_at: Optional timestamp at which the access token expires.
        :param refresh_token: Optional refresh token to get a
        fresh access token from the service provider.
        :param request: Optional FastAPI request that
        triggered the operation, defaults to None
        :return: A user.
        """
        oauth_account_dict = {
            "oauth_name": oauth_name,
            "access_token": access_token,
            "account_id": account_id,
            "account_username": account_username,
            "expires_at": expires_at,
            "refresh_token": refresh_token,
        }

        user = await self.user_db.add_oauth_account(user, oauth_account_dict)

        await self.on_after_update(user, {}, request)

        return user

    """async def request_verify(
        self, user: models.UP, request: Optional[Request] = None
    ) -> None:"""
    """"""    """
        Start a verification request.

        Triggers the on_after_request_verify handler on success.

        :param user: The user to verify.
        :param request: Optional FastAPI request that
        triggered the operation, defaults to None.
        :raises UserInactive: The user is inactive.
        :raises UserAlreadyVerified: The user is already verified.
        """
    """"""    """if not user.is_active:
            raise exceptions.UserInactive()
        if user.is_verified:
            raise exceptions.UserAlreadyVerified()

        token_data = {
            "sub": str(user.id),
            "username": user.username,
            "aud": self.verification_token_audience,
        }
        token = generate_jwt(
            token_data,
            self.verification_token_secret,
            self.verification_token_lifetime_seconds,
        )
        await self.on_after_request_verify(user, token, request)"""

    """async def verify(self, token: str, request: Optional[Request] = None) -> models.UP:"""
    """"""    """
        Validate a verification request.

        Changes the is_verified flag of the user to True.

        Triggers the on_after_verify handler on success.

        :param token: The verification token generated by request_verify.
        :param request: Optional FastAPI request that
        triggered the operation, defaults to None.
        :raises InvalidVerifyToken: The token is invalid or expired.
        :raises UserAlreadyVerified: The user is already verified.
        :return: The verified user.
        """
    """    try:
            data = decode_jwt(
                token,
                self.verification_token_secret,
                [self.verification_token_audience],
            )
        except jwt.PyJWTError:
            raise exceptions.InvalidVerifyToken()

        try:
            user_id = data["sub"]
            username = data["username"]
        except KeyError:
            raise exceptions.InvalidVerifyToken()

        try:
            user = await self.get_by_username(username)
        except exceptions.UserNotExists:
            raise exceptions.InvalidVerifyToken()

        try:
            parsed_id = self.parse_id(user_id)
        except exceptions.InvalidID:
            raise exceptions.InvalidVerifyToken()

        if parsed_id != user.id:
            raise exceptions.InvalidVerifyToken()

        if user.is_verified:
            raise exceptions.UserAlreadyVerified()

        verified_user = await self._update(user, {"is_verified": True})

        await self.on_after_verify(verified_user, request)

        return verified_user"""

    async def forgot_password(
            self, user: models.UP, request: Optional[Request] = None
    ) -> None:
        """
        Start a forgot password request.

        Triggers the on_after_forgot_password handler on success.

        :param user: The user that forgot its password.
        :param request: Optional FastAPI request that
        triggered the operation, defaults to None.
        :raises UserInactive: The user is inactive.
        """
        if not user.is_active:
            raise exceptions.UserInactive()

        token_data = {
            "sub": str(user.id),
            "password_fgpt": self.password_helper.hash(user.hashed_password),
            "aud": self.reset_password_token_audience,
        }
        token = generate_jwt(
            token_data,
            self.reset_password_token_secret,
            self.reset_password_token_lifetime_seconds,
        )
        await self.on_after_forgot_password(user, token, request)

    async def reset_password(
            self, token: str, password: str, request: Optional[Request] = None
    ) -> models.UP:
        """
        Reset the password of a user.

        Triggers the on_after_reset_password handler on success.

        :param self:
        :param token: The token generated by forgot_password.
        :param password: The new password to set.
        :param request: Optional FastAPI request that
        triggered the operation, defaults to None.
        :raises InvalidResetPasswordToken: The token is invalid or expired.
        :raises UserInactive: The user is inactive.
        :raises InvalidPasswordException: The password is invalid.
        :return: The user with updated password.
        """
        try:
            data = decode_jwt(
                token,
                self.reset_password_token_secret,
                [self.reset_password_token_audience],
            )
        except jwt.PyJWTError:
            raise exceptions.InvalidResetPasswordToken()

        try:
            user_id = data["sub"]
            password_fingerprint = data["password_fgpt"]
        except KeyError:
            raise exceptions.InvalidResetPasswordToken()

        try:
            parsed_id = self.parse_id(user_id)
        except exceptions.InvalidID:
            raise exceptions.InvalidResetPasswordToken()

        user = await self.get(parsed_id)

        valid_password_fingerprint, _ = self.password_helper.verify_and_update(
            user.hashed_password, password_fingerprint
        )
        if not valid_password_fingerprint:
            raise exceptions.InvalidResetPasswordToken()

        if not user.is_active:
            raise exceptions.UserInactive()

        updated_user = await self._update(user, {"password": password})

        await self.on_after_reset_password(user, request)

        return updated_user

    async def update(
            self,
            user_update: UserUpdate,
            user: models.UP,
            safe: bool = False,
            request: Optional[Request] = None,
    ) -> models.UP:
        """
        Update a user.

        Triggers the on_after_update handler on success

        :param user_update: The UserUpdate model containing
        the changes to apply to the user.
        :param user: The current user to update.
        :param safe: If True, sensitive values like is_superuser or is_verified
        will be ignored during the update, defaults to False
        :param request: Optional FastAPI request that
        triggered the operation, defaults to None.
        :return: The updated user.
        """
        if safe:
            updated_user_data = user_update.create_update_dict()
        else:
            updated_user_data = user_update.create_update_dict_superuser()
        updated_user = await self._update(user, updated_user_data)
        await self.on_after_update(updated_user, updated_user_data, request)
        return updated_user

    async def delete(
            self,
            user: models.UP,
            request: Optional[Request] = None,
    ) -> None:
        """
        Delete a user.

        :param user: The user to delete.
        :param request: Optional FastAPI request that
        triggered the operation, defaults to None.
        """
        await self.on_before_delete(user, request)
        await self.user_db.delete(user)
        await self.on_after_delete(user, request)

    async def validate_password(
            self, password: str, user: Union[UserCreate, UserRead]
    ) -> None:
        """
        Validate a password.

        *You should overload this method to add your own validation logic.*

        :param password: The password to validate.
        :param user: The user associated to this password.
        :raises InvalidPasswordException: The password is invalid.
        :return: None if the password is valid.
        """
        return  # pragma: no cover

    async def on_after_register(
            self, user: models.UP, request: Optional[Request] = None
    ) -> None:
        """
        Perform logic after successful user registration.

        *You should overload this method to add your own logic.*

        :param user: The registered user
        :param request: Optional FastAPI request that
        triggered the operation, defaults to None.
        """
        return  # pragma: no cover

    async def on_after_update(
            self,
            user: models.UP,
            update_dict: dict[str, Any],
            request: Optional[Request] = None,
    ) -> None:
        """
        Perform logic after successful user update.

        *You should overload this method to add your own logic.*

        :param user: The updated user
        :param update_dict: Dictionary with the updated user fields.
        :param request: Optional FastAPI request that
        triggered the operation, defaults to None.
        """
        return  # pragma: no cover

    async def on_after_request_verify(
            self, user: models.UP, token: str, request: Optional[Request] = None
    ) -> None:
        """
        Perform logic after successful verification request.

        *You should overload this method to add your own logic.*

        :param user: The user to verify.
        :param token: The verification token.
        :param request: Optional FastAPI request that
        triggered the operation, defaults to None.
        """
        return  # pragma: no cover

    async def on_after_verify(
            self, user: models.UP, request: Optional[Request] = None
    ) -> None:
        """
        Perform logic after successful user verification.

        *You should overload this method to add your own logic.*

        :param user: The verified user.
        :param request: Optional FastAPI request that
        triggered the operation, defaults to None.
        """
        return  # pragma: no cover

    async def on_after_forgot_password(
        self, user: User, token: str, request: Optional[Request] = None
    ):
        print(f"User {user.id} has forgot their password. Reset token: {token}")

    async def on_after_reset_password(
            self, user: models.UP, request: Optional[Request] = None
    ) -> None:
        """
        Perform logic after successful password reset.

        *You should overload this method to add your own logic.*

        :param user: The user that reset its password.
        :param request: Optional FastAPI request that
        triggered the operation, defaults to None.
        """
        return  # pragma: no cover

    async def on_after_login(
            self,
            user: models.UP,
            request: Optional[Request] = None,
            response: Optional[Response] = None,
    ) -> None:
        """
        Perform logic after user login.

        *You should overload this method to add your own logic.*

        :param user: The user that is logging in
        :param request: Optional FastAPI request
        :param response: Optional response built by the transport.
        Defaults to None
        """
        return  # pragma: no cover

    async def on_before_delete(
            self, user: models.UP, request: Optional[Request] = None
    ) -> None:
        """
        Perform logic before user delete.

        *You should overload this method to add your own logic.*

        :param user: The user to be deleted
        :param request: Optional FastAPI request that
        triggered the operation, defaults to None.
        """
        return  # pragma: no cover

    async def on_after_delete(
            self, user: models.UP, request: Optional[Request] = None
    ) -> None:
        """
        Perform logic before user delete.

        *You should overload this method to add your own logic.*

        :param user: The user to be deleted
        :param request: Optional FastAPI request that
        triggered the operation, defaults to None.
        """
        return  # pragma: no cover

    async def authenticate(
            self, credentials: OAuth2PasswordRequestForm
    ) -> Optional[models.UP]:
        """
        Authenticate and return a user following a username and a password.

        Will automatically upgrade password hash if necessary.

        :param credentials: The user credentials.
        """
        try:
            user = await self.get_by_username(credentials.username)
        except exceptions.UserNotExists:
            # Run the hasher to mitigate timing attack
            # Inspired from Django: https://code.djangoproject.com/ticket/20760
            self.password_helper.hash(credentials.password)
            return None

        verified, updated_password_hash = self.password_helper.verify_and_update(
            credentials.password, user.hashed_password
        )
        if not verified:
            return None
        # Update password hash to a more robust one if needed
        if updated_password_hash is not None:
            await self.user_db.update(user, {"hashed_password": updated_password_hash})

        return user

    async def _update(self, user: UP, update_dict: dict[str, Any]) -> models.UP:
        validated_update_dict = {}
        for field, value in update_dict.items():
            if field == "username" and value != user.username:
                try:
                    await self.get_by_username(value)
                    raise exceptions.UserAlreadyExists()
                except exceptions.UserNotExists:
                    validated_update_dict["username"] = value
                    validated_update_dict["is_verified"] = False
            elif field == "password" and value is not None:
                await self.validate_password(value, user)
                validated_update_dict["hashed_password"] = self.password_helper.hash(
                    value
                )
            else:
                validated_update_dict[field] = value
        return await self.user_db.update(user, validated_update_dict)


async def get_user_manager(user_db: UserDatabase = Depends(get_user_db)):
    yield UserManager(user_db)


bearer_transport = BearerTransport(tokenUrl="/api/latest/auth/login")


def get_database_strategy(
        access_token_db: AccessTokenDatabase[AccessToken] = Depends(get_access_token_db),
) -> DatabaseStrategy:
    return DatabaseStrategy(access_token_db, lifetime_seconds=3600)


auth_backend = AuthenticationBackend(
    name="jwt",
    transport=bearer_transport,
    get_strategy=get_database_strategy,
)

fastapi_users = FastAPIUsers[User, uuid.UUID](get_user_manager, [auth_backend])

current_active_user = fastapi_users.current_user(active=True)
