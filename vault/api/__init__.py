from .v1_0.routes import router as v1_0_router
from .v1_1.routes import router as v1_1_router
from .v1_2.routes import router as v1_2_router
from .v1_3.routes import router as v1_3_router

version_map = {
    "v1.0": v1_0_router,
    "v1.1": v1_1_router,
    "v1.2": v1_2_router,
    "v1.3": v1_3_router
}