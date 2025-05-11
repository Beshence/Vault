from fastapi import FastAPI

from vault.api import build_router_for_version
from vault.misc import get_versions

# Перечень версий:

app = FastAPI(title="Main API", docs_url=None, redoc_url=None)

for version in get_versions():
    subapp = FastAPI(
        title=f"API {version}",
        docs_url="/docs",
        openapi_url="/openapi.json"
    )
    router = build_router_for_version(version)
    subapp.include_router(router)
    app.mount(f"/api/{version}", subapp)