from fastapi import FastAPI
from vault.api.loader import build_router_for_version

versions = ["v1.0", "v1.1", "v1.2"]

app = FastAPI(title="Main API", docs_url=None, redoc_url=None)

for version in versions:
    # для каждой версии — свой FastAPI с /docs
    subapp = FastAPI(
        title=f"API {version}",
        docs_url="/docs",
        openapi_url="/openapi.json"
        #servers=[{"url": f"/api/{version}"}]
    )
    router = build_router_for_version(version)
    subapp.include_router(router)
    app.mount(f"/api/{version}", subapp)