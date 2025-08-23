from contextlib import asynccontextmanager

from fastapi import FastAPI

from fastapi_versionizer.versionizer import Versionizer
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request

from app.api import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield

app = FastAPI(
    root_path='',
    title='Beshence Vault',
    redoc_url=None,
    description='Beshence Vault',
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

api_versions = Versionizer(
    app=app,
    default_version=(1, 0),
    prefix_format='/api/v{major}.{minor}',
    semantic_version_format='{major}.{minor}',
    latest_prefix='/api/latest',
    sort_routes=True,
    include_main_docs=False,
    include_main_openapi_route=False
).versionize()

app.state.versions = ["v"+".".join(map(str, api_version)) for api_version in api_versions]

@app.get('/.well-known/beshence/vault', tags=['Common'])
async def well_known(request: Request):
    return {
        "api": {
            "base_url": None,
            "path": "/api",
            "versions": request.app.state.versions
        }
    }