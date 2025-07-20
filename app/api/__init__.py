from fastapi import APIRouter, Request
from fastapi_versionizer import api_version
from pydantic import BaseModel

from app.api.user import user_router

api_router = APIRouter()
api_router.include_router(user_router)


class Ping(BaseModel):
    ping: str = "pong"
    latest_api_version: str = "v0.0"

@api_version(1, 0)
@api_router.get('/ping', tags=['Common'])
async def ping(request: Request) -> Ping:
    return Ping(
        ping="pong",
        latest_api_version=request.app.state.latest_api_version
    )