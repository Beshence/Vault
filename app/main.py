from contextlib import asynccontextmanager

from fastapi import FastAPI

from fastapi_versionizer.versionizer import Versionizer

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

app.state.latest_api_version = "v"+".".join(map(str, api_versions[-1]))