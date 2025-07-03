from fastapi import APIRouter
from fastapi_versionizer import api_version

auth_router = APIRouter(
    prefix='/auth',
    tags=['Auth']
)

@api_version(1, 0)
@auth_router.post('/login')
def login() -> dict:
    return {"hello": "world"}