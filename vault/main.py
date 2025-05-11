"""from fastapi import FastAPI, HTTPException

from vault.misc import VersionedAPI

versioned_api = VersionedAPI()

v1_0 = versioned_api.create_version("v1.0")
v1_1 = versioned_api.create_version("v1.1")
v1_2 = versioned_api.create_version("v1.2")
v1_3 = versioned_api.create_version("v1.3")

@v1_0.get("/get_user")
def get_user():
    return {"user": "from v1.0"}

@v1_1.post("/create_user")
def create_user_v1_1():
    return {"status": "created in v1.1"}

@v1_2.post("/create_user")
def create_user_v1_2():
    return {"status": "created in v1.2, improved"}

@v1_3.get("/get_user", include_in_schema=False)
def get_user_v1_3():
    raise HTTPException(status_code=410, detail="Этот эндпоинт удалён в v1.3")

vault = FastAPI(title="Main API", docs_url=None, redoc_url=None)
versioned_api.mount_versions(vault)"""

from fastapi import FastAPI

from vault.api import get_versions_map
from vault.misc import VersionedAPI

app = FastAPI(title="Main", docs_url=None, redoc_url=None)

versioned_api = VersionedAPI(get_versions_map())
versioned_api.build(app)