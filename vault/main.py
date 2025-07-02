from fastapi import FastAPI

from vault.api import build_router_for_version
from vault.misc import get_versions

app = FastAPI(title="Main API", docs_url="/docs", redoc_url=None)

for version in get_versions(with_latest=True):
    subapp = FastAPI(
        title=f"API {version}",
        docs_url="/docs",
        redoc_url=None,
        openapi_url="/openapi.json"
    )
    router = build_router_for_version(version)
    subapp.include_router(router)
    app.mount(f"/api/{version}", subapp)