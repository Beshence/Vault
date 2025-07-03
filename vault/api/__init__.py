from fastapi import APIRouter
from fastapi_versionizer import api_version

from vault.api.auth import auth_router

api_router = APIRouter(
    prefix='',
)

@api_version(1, 0)
@api_router.get('/ping', tags=['Common'])
def ping() -> dict:
    return {"ping": "pong"}


api_router.include_router(auth_router)