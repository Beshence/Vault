from fastapi import FastAPI, APIRouter
from fastapi.routing import APIRoute


class VersionedAPI:
    def __init__(self, version_map: dict[str, APIRouter]):
        self.apps = {}
        self.routers = version_map

    def build(self, main_app: FastAPI):
        sorted_versions = sorted(self.routers.keys())
        prev_router = None
        for version in sorted_versions:
            router = self.routers[version]
            if prev_router:
                self.clone_routes(prev_router, router)
            app = FastAPI(title=f"API {version}", docs_url="/docs", openapi_url="/openapi.json")
            app.include_router(router)
            main_app.mount(f"/api/{version}", app)
            prev_router = router

    @staticmethod
    def clone_routes(from_router, to_router):
        for route in from_router.routes:
            if isinstance(route, APIRoute):
                if not any(
                        r.path == route.path and set(r.methods) & set(route.methods)
                        for r in to_router.routes
                ):
                    to_router.routes.append(route)
