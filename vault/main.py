import uvicorn
from fastapi import FastAPI, APIRouter
from fastapi_versionizer import api_version

from fastapi_versionizer.versionizer import Versionizer

from vault.api import api_router

app = FastAPI(
    root_path='/api',
    title='Beshence Vault',
    docs_url='/docs',
    redoc_url=None,
    description='Beshence Vault'
)

app.include_router(api_router)

versions = Versionizer(
    app=app,
    prefix_format='/v{major}.{minor}',
    semantic_version_format='{major}.{minor}',
    latest_prefix='/latest',
    sort_routes=True
).versionize()